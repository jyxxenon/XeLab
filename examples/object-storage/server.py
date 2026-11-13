"""Versioned object storage served through the XeLab workload RPCs."""

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import errno
from functools import wraps
import os
from pathlib import Path
import re
import sqlite3
from threading import Condition
import time
import uuid

import grpc
from xelab.v1 import capability_pb2 as cap
from xelab.v1 import capability_pb2_grpc as capability
from xelab.v1 import common_pb2 as common
from xelab.v1 import lifecycle_pb2 as life
from xelab.v1 import lifecycle_pb2_grpc as lifecycle
from xelab.v1 import migration_pb2 as mig
from xelab.v1 import migration_pb2_grpc as migration

from model import (
    Call, MAX_INTEGER, StoreError, canonical_json, canonical_uuid, conflict, digest,
    integer, invalid, request_fields,
)
from store import Limits, SCHEMA, Store
from transport import HostBlobs, TlsFiles, Work, abort, require_kernel, strict_json
from volume import mounted_capacity, observe_format


_VOLUME = Path("/data/objects")
_MANIFEST = Path("/xelab/plugin.json")
_LISTENER = "0.0.0.0:7000"
_DELEGATION = re.compile(r"[A-Za-z0-9_-]{43}")
_CALLS = {
    "data.object.put": "put",
    "data.object.list": "list",
    "data.object.stat": "stat",
    "data.object.export": "export",
    "data.object.delete": "delete",
    "data.object.usage.get": "usage",
}
_HOST_ERRORS = {
    grpc.StatusCode.PERMISSION_DENIED: "PERMISSION_DENIED",
    grpc.StatusCode.NOT_FOUND: "RESOURCE_NOT_FOUND",
    grpc.StatusCode.RESOURCE_EXHAUSTED: "RESOURCE_EXHAUSTED",
    grpc.StatusCode.DEADLINE_EXCEEDED: "DEADLINE_EXCEEDED",
    grpc.StatusCode.CANCELLED: "CANCELED",
    grpc.StatusCode.UNAVAILABLE: "UNAVAILABLE",
}
_TERMINAL_FAILURE_VERSION = 1
_BUSINESS_REJECTIONS = frozenset({
    "INVALID_ARGUMENT", "PERMISSION_DENIED", "RESOURCE_NOT_FOUND",
    "STATE_CONFLICT", "RESOURCE_EXHAUSTED",
})


def kernel_rpc(method):
    @wraps(method)
    def handle(self, request, context):
        require_kernel(context)
        try:
            return method(self, request, context)
        except StoreError as error:
            abort(context, error)
        except grpc.FutureCancelledError:
            abort(context, StoreError("CANCELED", "Host Blob operation canceled"))
        except grpc.RpcError as error:
            code = _HOST_ERRORS.get(error.code(), "INTERNAL")
            abort(context, StoreError(code, "Host Blob operation failed"))
        except OSError as error:
            code = "RESOURCE_EXHAUSTED" if error.errno in (errno.ENOSPC, errno.EDQUOT) else "INTERNAL"
            abort(context, StoreError(code, "Object volume operation failed"))
        except sqlite3.Error as error:
            code = "RESOURCE_EXHAUSTED" if getattr(error, "sqlite_errorcode", 0) == sqlite3.SQLITE_FULL else "INTERNAL"
            abort(context, StoreError(code, "Object metadata operation failed"))
        except Exception:
            abort(context, StoreError("INTERNAL", "Object storage operation failed"))
    return handle


class ObjectStorage(
    lifecycle.PluginLifecycleServicer,
    capability.CapabilityServiceServicer,
    migration.DataMigrationServicer,
):
    def __init__(
        self, manifest, volume, deployment, instance, generation, host,
        *, schema=SCHEMA, inspect_mount=mounted_capacity,
    ):
        self.raw_manifest = manifest.read_bytes()
        self.manifest = strict_json(self.raw_manifest, 1024 * 1024)
        self.manifest_digest = digest(self.raw_manifest)
        self.volume = volume.absolute()
        self.schema = schema
        self.deployment = canonical_uuid(deployment)
        self.instance = canonical_uuid(instance)
        self.generation = integer(generation, 1, MAX_INTEGER)
        self.host = host
        self.inspect_mount = inspect_mount
        self.contracts = {c["contract"]["name"]: c for c in self.manifest["capabilities"]}
        if (
            self.manifest["plugin_id"] != "org.xelab.object-storage"
            or self.manifest["data_schema_version"] != "1"
            or self.contracts.keys() != _CALLS.keys()
            or len(self.manifest["capabilities"]) != len(_CALLS)
        ):
            raise invalid("Object storage manifest has a different profile")
        concurrency = self.manifest["concurrency"]
        self.active_limit = integer(concurrency["max_active_requests"], 1, 4)
        self.queue_limit = integer(concurrency["max_queue_requests"], 0, 32)
        self.queue_timeout = integer(concurrency["queue_timeout_ms"], 0, 5000) / 1000
        self.minimum_volume = self.manifest["volumes"][0]["minimum_bytes"]
        self.changed = Condition()
        self.active = 0
        self.calls = {}
        self.waiting = deque()
        self.store = None
        self.config_digest = None
        self.initializing = False
        self.draining = False

    def _config(self, raw):
        value = strict_json(raw, 1024 * 1024)
        schema = self.manifest["config_schema"]
        request_fields(value, tuple(schema["required"]))
        for name, rule in schema["properties"].items():
            if "const" in rule:
                expected = rule["const"]
                if type(expected) is int:
                    value[name] = integer(value[name], expected, expected)
                elif value[name] != expected:
                    raise invalid("Object storage configuration differs from its signed profile")
            if rule.get("type") == "integer":
                value[name] = integer(value[name], rule["minimum"], rule["maximum"])
        return Limits(
            quota_bytes=value["default_user_quota_bytes"],
            max_objects=value["default_user_max_objects"],
            storage_budget_bytes=value["deployment_storage_budget_bytes"],
            idempotency_ttl_seconds=value["idempotency_ttl_seconds"],
            cursor_ttl_seconds=value["list_cursor_ttl_seconds"],
        )

    def _capacity(self, writable):
        capacity = self.inspect_mount(self.volume, writable)
        if capacity < self.minimum_volume:
            raise conflict("Mounted volume is smaller than the signed object volume")
        return capacity

    @kernel_rpc
    def Describe(self, request, context):
        Work(request.context, context, 30)
        return life.DescribeResponse(manifest_json=self.raw_manifest, manifest_digest=self.manifest_digest)

    @kernel_rpc
    def Initialize(self, request, context):
        work = Work(request.context, context, 30)
        if (
            request.deployment_id != self.deployment or request.instance_id != self.instance
            or request.generation != self.generation or digest(request.config_json) != request.config_digest
        ):
            raise conflict("Initialize identity or configuration digest differs")
        limits = self._config(request.config_json)
        with self.changed:
            if self.draining or self.initializing:
                raise conflict("Object storage lifecycle is busy")
            if self.store is not None:
                if self.config_digest != request.config_digest:
                    raise conflict("Object storage configuration needs a new generation")
                return life.InitializeResponse(observed_generation=self.generation, initialized=True)
            self.initializing = True
        opened = None
        try:
            if limits.storage_budget_bytes > self._capacity(True):
                raise conflict("Object storage budget exceeds the mounted volume")
            work.check()
            scope = f"{self.deployment}:{self.generation}"
            opened = Store(self.volume, scope, limits, schema=self.schema)
            with self.changed:
                work.check()
                if self.draining:
                    raise conflict("Object storage is draining")
                self.store, opened = opened, None
                self.config_digest = request.config_digest
            return life.InitializeResponse(observed_generation=self.generation, initialized=True)
        finally:
            if opened is not None:
                opened.close()
            with self.changed:
                self.initializing = False
                self.changed.notify_all()

    @kernel_rpc
    def GetHealth(self, request, context):
        Work(request.context, context, 30)
        with self.changed:
            ready = self.store is not None and not self.draining
        return life.HealthResponse(
            alive=True, observed_generation=self.generation,
            capabilities=[
                life.CapabilityHealth(contract=common.ContractRef(**c["contract"]), ready=ready)
                for c in self.contracts.values()
            ],
        )

    def _drain(self, work, grace_ms, *, cancel):
        until = time.monotonic() + min(work.remaining(), grace_ms / 1000)
        with self.changed:
            self.draining = True
            calls = [entry[1] for entry in self.calls.values()] if cancel else []
            self.changed.notify_all()
        for pending in calls:
            pending.cancel()
        with self.changed:
            while self.calls or self.initializing:
                left = until - time.monotonic()
                if left <= 0:
                    break
                self.changed.wait(min(left, 0.05))
                work.check()
            return life.DrainResponse(
                accepting_requests=False, active_calls=self.active,
                drained=not self.calls and not self.initializing,
            )

    @kernel_rpc
    def Drain(self, request, context):
        return self._drain(Work(request.context, context, 30), request.grace_ms, cancel=False)

    @kernel_rpc
    def Shutdown(self, request, context):
        self._drain(Work(request.context, context, 30), request.grace_ms, cancel=True)
        return common.Ack(request_id=request.context.request_id, accepted=True)

    def _subject(self, rpc):
        if not _DELEGATION.fullmatch(rpc.delegation_token):
            raise StoreError("PERMISSION_DENIED", "Current Call delegation required")
        if rpc.actor_instance_id and rpc.actor_instance_id != self.instance:
            raise StoreError("PERMISSION_DENIED", "Call belongs to another workload")
        return canonical_uuid(rpc.subject_id)

    @contextmanager
    def _admit(self, call_id, subject, work):
        with self.changed:
            if self.store is None or self.draining:
                raise StoreError("UNAVAILABLE", "Object storage is not accepting Calls")
            if call_id in self.calls:
                raise conflict("Call is already in flight")
            if len(self.calls) >= self.active_limit + self.queue_limit:
                raise StoreError("RESOURCE_EXHAUSTED", "Object storage queue is full")
            self.calls[call_id] = (subject, work)
            self.waiting.append(call_id)
            self.changed.notify_all()
        acquired = False
        try:
            queue_until = time.monotonic() + min(work.remaining(), self.queue_timeout)
            with self.changed:
                while True:
                    work.check()
                    if self.draining:
                        raise StoreError("UNAVAILABLE", "Object storage is draining")
                    if self.waiting[0] == call_id and self.active < self.active_limit:
                        self.waiting.popleft()
                        self.active += 1
                        acquired = True
                        break
                    left = queue_until - time.monotonic()
                    if left <= 0:
                        raise StoreError("RESOURCE_EXHAUSTED", "Object storage queue wait expired")
                    self.changed.wait(min(left, 0.05))
            yield self.store
        finally:
            with self.changed:
                del self.calls[call_id]
                if acquired:
                    self.active -= 1
                else:
                    self.waiting.remove(call_id)
                self.changed.notify_all()

    def _invoke(self, store, name, subject, request, value, work):
        if name in ("stat", "list", "usage"):
            return getattr(store, name)(subject, value)
        call = Call(subject, request.call_id, request.context.idempotency_key)
        if name == "put":
            return store.put(call, value, lambda blob: self.host.read(request.context, work, blob), work.check)
        if name == "export":
            return store.export(
                call, value,
                lambda metadata, frames: self.host.write(request.context, work, metadata, frames),
                work.check,
            )
        return store.delete(call, value, work.check)

    @staticmethod
    def _result(call_id, result, maximum):
        output = canonical_json(result)
        if len(output) > maximum:
            raise StoreError("INTERNAL", "Object storage output exceeds its signed contract")
        return cap.InvokeResponse(call_id=call_id, output_json=output, output_digest=digest(output))

    @kernel_rpc
    def Invoke(self, request, context):
        work = Work(request.context, context, 300)
        subject = self._subject(request.context)
        call_id = canonical_uuid(request.call_id)
        contract = self.contracts.get(request.contract.name)
        if (
            contract is None or request.contract != common.ContractRef(**contract["contract"])
            or request.binding_id or digest(request.input_json) != request.input_digest
        ):
            raise invalid("Call contract or input digest differs")
        value = strict_json(request.input_json, contract["maximum_input_bytes"])
        with self._admit(call_id, subject, work) as store:
            operation = _CALLS[request.contract.name]
            try:
                result = self._invoke(store, operation, subject, request, value, work)
            except StoreError as error:
                # Copying and exporting can have work to unwind. Only the
                # store can confirm completion for those operations.
                if (request.terminal_failure_version != _TERMINAL_FAILURE_VERSION
                        or error.code not in _BUSINESS_REJECTIONS
                        or (operation in ("put", "export") and not error.completed)):
                    raise
                work.check()
                return cap.InvokeResponse(
                    call_id=call_id,
                    terminal_failure=cap.InvokeFailure(
                        version=_TERMINAL_FAILURE_VERSION,
                        contract=request.contract,
                        code=error.code,
                    ),
                )
            return self._result(call_id, result, contract["maximum_output_bytes"])

    @kernel_rpc
    def InvokeStream(self, request, context):
        raise StoreError("UNIMPLEMENTED", "Object storage capabilities are unary")

    @kernel_rpc
    def Cancel(self, request, context):
        Work(request.context, context, 2)
        call_id = canonical_uuid(request.call_id)
        with self.changed:
            pending = self.calls.get(call_id)
        if pending:
            if request.context.subject_id and request.context.subject_id != pending[0]:
                raise StoreError("PERMISSION_DENIED", "Call belongs to another subject")
            pending[1].cancel()
        return common.Ack(request_id=request.context.request_id, accepted=True)

    @kernel_rpc
    def QueryResult(self, request, context):
        work = Work(request.context, context, 2)
        subject = self._subject(request.context)
        if request.idempotency_key != request.context.idempotency_key:
            raise invalid("Result key differs from its context")
        identity = Call(subject, request.call_id, request.idempotency_key)
        with self.changed:
            store = self.store
        if store is None:
            raise StoreError("UNAVAILABLE", "Object storage has not initialized")
        state, output = store.query_result(identity)
        work.check()
        if state == "succeeded":
            return cap.QueryResultResponse(
                state=common.EXECUTION_STATE_SUCCEEDED,
                completed=self._result(request.call_id, output, 16 * 1024 * 1024),
            )
        return cap.QueryResultResponse(
            state=common.EXECUTION_STATE_RUNNING if state == "running" else common.EXECUTION_STATE_UNKNOWN,
        )

    def _operation(self, rpc, phase):
        operation, colon, requested = rpc.idempotency_key.partition(":")
        if not colon or requested != phase or uuid.UUID(canonical_uuid(operation)).int == 0:
            raise invalid("Invalid format operation")
        canonical_uuid(rpc.subject_id)
        return operation

    def _plan(self, operation, source):
        plan_digest = digest(canonical_json([
            "xelab-object-storage-format-v1", operation, self.deployment, self.manifest_digest, source, "1",
        ]))
        plan_id = str(uuid.uuid5(uuid.UUID(operation), plan_digest))
        return mig.MigrationPlan(
            plan_id=plan_id, plan_digest=plan_digest, requires_exclusive_write=source == "none",
            backward_read_compatible=source == "1", reversible=source == "1",
        )

    @kernel_rpc
    def Plan(self, request, context):
        work = Work(request.context, context, 10)
        operation = self._operation(request.context, "plan")
        if request.deployment_id != self.deployment or request.target_schema != "1":
            raise conflict("Unsupported deployment or object format target")
        self._capacity(False)
        source = observe_format(self.volume, work.check)
        if source != request.source_schema:
            raise conflict("Object volume does not match the requested source format")
        return self._plan(operation, source)

    @kernel_rpc
    def Apply(self, request, context):
        raise StoreError("UNIMPLEMENTED", "Object storage has no format conversion")

    @kernel_rpc
    def Verify(self, request, context):
        work = Work(request.context, context, 60)
        operation = self._operation(request.context, "verify")
        integer(request.volume_fence, 1, MAX_INTEGER)
        if request.plan_id not in {self._plan(operation, source).plan_id for source in ("none", "1")}:
            raise conflict("Verify does not match the object format plan")
        self._capacity(False)
        observed = observe_format(self.volume, work.check, verify=True)
        if observed != "1":
            raise conflict("Object volume format was not initialized")
        return mig.MigrationResult(plan_id=request.plan_id, succeeded=True, observed_schema=observed)

    def close(self):
        if self.store is not None:
            self.store.close()


def server_for(service, executor):
    server = grpc.server(
        executor, maximum_concurrent_rpcs=service.active_limit + service.queue_limit + 4,
        options=(("grpc.max_receive_message_length", 4 * 1024 * 1024 + 65536),),
    )
    lifecycle.add_PluginLifecycleServicer_to_server(service, server)
    capability.add_CapabilityServiceServicer_to_server(service, server)
    migration.add_DataMigrationServicer_to_server(service, server)
    return server


def main():
    tls = TlsFiles(*(Path(os.environ[key]) for key in (
        "XELAB_TLS_CERT_PATH", "XELAB_TLS_KEY_PATH", "XELAB_TLS_CA_PATH",
    )))
    instance = os.environ["XELAB_INSTANCE_ID"]
    host = HostBlobs(os.environ["XELAB_HOST_RPC_ENDPOINT"], tls, instance)
    service = ObjectStorage(
        _MANIFEST, _VOLUME, os.environ["XELAB_DEPLOYMENT_ID"], instance,
        int(os.environ["XELAB_GENERATION"]), host, schema=Path("/opt/plugin/storage.sql"),
    )
    if (
        os.environ["XELAB_PLUGIN_ID"] != service.manifest["plugin_id"]
        or os.environ["XELAB_PLUGIN_VERSION"] != service.manifest["version"]
        or os.environ["XELAB_PLUGIN_RPC_LISTEN"] != _LISTENER
    ):
        raise conflict("Injected object storage identity differs")
    try:
        with ThreadPoolExecutor(max_workers=service.active_limit + service.queue_limit + 4) as executor:
            server = server_for(service, executor)
            if not server.add_secure_port(_LISTENER, tls.listener()):
                raise RuntimeError("Cannot bind the object storage workload listener")
            server.start()
            try:
                server.wait_for_termination()
            finally:
                server.stop(0).wait()
    finally:
        service.close()


if __name__ == "__main__":
    main()
