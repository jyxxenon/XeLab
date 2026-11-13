"""Actual mTLS and Proto transport with an isolated kernel/Blob fixture."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Lock
import time
import unittest
from unittest.mock import patch
import uuid

import grpc
from xelab.v1 import capability_pb2 as cap
from xelab.v1 import capability_pb2_grpc as capability
from xelab.v1 import common_pb2 as common
from xelab.v1 import host_pb2 as host
from xelab.v1 import host_pb2_grpc as host_service
from xelab.v1 import lifecycle_pb2 as life
from xelab.v1 import lifecycle_pb2_grpc as lifecycle
from xelab.v1 import migration_pb2 as mig
from xelab.v1 import migration_pb2_grpc as migration

from model import MAX_CHUNK_BYTES, StoreError, canonical_json, digest
from server import ObjectStorage, server_for
from transport import HostBlobs, TlsFiles
from volume import mounted_capacity


SPEC = Path(__file__).resolve().parent / "../../docs/preset-plugins/object-storage"
MANIFEST = Path(os.environ.get("XELAB_OBJECT_TEST_MANIFEST", SPEC / "manifest.json"))
CONFIG = Path(os.environ.get("XELAB_OBJECT_TEST_CONFIG", SPEC / "defaults.json"))
SCHEMA = Path(os.environ.get("XELAB_OBJECT_TEST_SCHEMA", SPEC / "storage.sql"))


def identifier():
    return str(uuid.uuid4())


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=8)


def leaf(root, label, dns, uri):
    key, cert = root / f"{label}.key", root / f"{label}.crt"
    request, extensions = root / f"{label}.csr", root / f"{label}.ext"
    openssl("req", "-new", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-subj", f"/CN={dns}", "-keyout", key, "-out", request)
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        f"extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:{dns},URI:{uri}\n",
        encoding="utf-8",
    )
    openssl("x509", "-req", "-CA", root / "ca.crt", "-CAkey", root / "ca.key",
            "-set_serial", uuid.uuid4().int, "-days", 1, "-in", request, "-extfile",
            extensions, "-out", cert)
    return TlsFiles(cert, key, root / "ca.crt")


class BlobFixture(host_service.HostServiceServicer):
    def __init__(self, instance_uri):
        self.instance_uri = instance_uri.encode()
        self.instance = instance_uri.split("/")[4]
        self.sources = {}
        self.outputs = {}
        self.grants = {}
        self.read_started = Event()
        self.read_ended = Event()
        self.release_read = Event()
        self.pause_read = False
        self.drop_export_reply = False
        self.write_count = 0
        self.lock = Lock()

    def allow(self, token, subject, actions):
        with self.lock:
            self.grants[token] = (subject, frozenset(actions))

    def authorize(self, rpc, context, action):
        identities = context.auth_context().get("x509_subject_alternative_name", ())
        with self.lock:
            grant = self.grants.get(rpc.delegation_token)
        if (
            self.instance_uri not in identities or rpc.actor_instance_id != self.instance
            or not grant or rpc.subject_id != grant[0] or action not in grant[1]
            or rpc.deadline_unix_ms <= time.time_ns() // 1_000_000
        ):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "Blob fixture denied")

    def ReadBlob(self, request, context):
        self.authorize(request.context, context, "read")
        source = self.sources.get(request.blob_id)
        if source is None or source[0] != request.context.subject_id:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "Blob fixture denied")
        self.read_started.set()
        try:
            if self.pause_read:
                while context.is_active() and not self.release_read.wait(0.02):
                    pass
            if not context.is_active():
                return
            data = source[1]
            for offset in range(0, len(data), MAX_CHUNK_BYTES):
                yield host.BlobChunk(offset=offset, data=data[offset:offset + MAX_CHUNK_BYTES])
        finally:
            self.read_ended.set()

    def WriteBlob(self, requests, context):
        header = next(requests).header
        self.authorize(header.context, context, "write")
        if not header.context.idempotency_key.startswith("sha256:"):
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Missing bounded fixture transport key")
        data = bytearray()
        for request in requests:
            if (
                not request.HasField("data") or request.data.offset != len(data)
                or not 0 < len(request.data.data) <= MAX_CHUNK_BYTES
            ):
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Malformed fixture frames")
            data.extend(request.data.data)
        self.authorize(header.context, context, "write")
        if len(data) != header.size_bytes or digest(data) != header.digest:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Fixture digest mismatch")
        blob = identifier()
        with self.lock:
            self.outputs[blob] = (header.context.subject_id, bytes(data))
            self.write_count += 1
        if self.drop_export_reply:
            context.abort(grpc.StatusCode.UNAVAILABLE, "Fixture lost its reply after publication")
        return host.BlobReference(blob_id=blob, size_bytes=len(data), digest=header.digest)


class ObjectRpc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        root = Path(directory.name)
        openssl("req", "-new", "-x509", "-nodes", "-newkey", "ec", "-pkeyopt",
                "ec_paramgen_curve:P-256", "-keyout", root / "ca.key", "-out", root / "ca.crt",
                "-days", 1, "-subj", "/CN=object-test-ca", "-addext",
                "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        cls.instance = identifier()
        cls.generation = 7
        cls.instance_name = f"i-{cls.instance}-{cls.generation}.xelab.local"
        cls.instance_uri = f"spiffe://xelab.local/instance/{cls.instance}/generation/{cls.generation}"
        cls.plugin_tls = leaf(root, "plugin", cls.instance_name, cls.instance_uri)
        cls.kernel_tls = leaf(root, "kernel", "kernel.xelab.local", "spiffe://xelab.local/kernel")
        cls.other_tls = leaf(root, "other", "other.xelab.local", "spiffe://xelab.local/workload/other")

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.volume = self.data_volume()
        self.manifest_path = MANIFEST
        self.deployment, self.owner, self.other = identifier(), identifier(), identifier()
        self.config = canonical_json(json.loads(CONFIG.read_bytes()))
        self.fixture = BlobFixture(self.instance_uri)
        self.mount_checks = []
        self.mount_bytes = 20 * 1024 * 1024 * 1024
        self.host_address = self.host_server(self.kernel_tls)
        self.addCleanup(self.stop_plugin)
        self.server = None
        self.start_plugin()

    def data_volume(self):
        volume = self.root / "volume"
        volume.mkdir()
        return volume

    def host_server(self, tls):
        executor = ThreadPoolExecutor(max_workers=6)
        self.addCleanup(executor.shutdown)
        server = grpc.server(executor)
        host_service.add_HostServiceServicer_to_server(self.fixture, server)
        port = server.add_secure_port("127.0.0.1:0", tls.listener())
        self.assertNotEqual(port, 0)
        server.start()
        self.addCleanup(lambda: server.stop(0).wait())
        return f"https://127.0.0.1:{port}"

    def inspect_mount(self, path, writable):
        self.assertEqual(path, self.volume)
        self.mount_checks.append(writable)
        return self.mount_bytes

    def start_plugin(self):
        outgoing = HostBlobs(self.host_address, self.plugin_tls, self.instance)
        self.service = ObjectStorage(
            self.manifest_path, self.volume, self.deployment, self.instance, self.generation,
            outgoing, schema=SCHEMA, inspect_mount=self.inspect_mount,
        )
        self.executor = ThreadPoolExecutor(max_workers=self.service.active_limit + self.service.queue_limit + 4)
        self.server = server_for(self.service, self.executor)
        port = self.server.add_secure_port("127.0.0.1:0", self.plugin_tls.listener())
        self.assertNotEqual(port, 0)
        self.server.start()
        self.connect_plugin(f"127.0.0.1:{port}")

    def connect_plugin(self, address):
        self.address = address
        self.contract_refs = {
            entry["contract"]["name"]: entry["contract"]
            for entry in json.loads(self.manifest_path.read_bytes())["capabilities"]
        }
        self.channel = self.client_channel(self.kernel_tls)
        self.lifecycle = lifecycle.PluginLifecycleStub(self.channel)
        self.capability = capability.CapabilityServiceStub(self.channel)
        self.migration = migration.DataMigrationStub(self.channel)

    def stop_plugin(self):
        if self.server is not None:
            self.channel.close()
            self.server.stop(0).wait()
            self.executor.shutdown()
            self.service.close()
            self.server = None

    def client_channel(self, tls):
        return grpc.secure_channel(
            self.address, tls.client(),
            options=(("grpc.ssl_target_name_override", self.instance_name), ("grpc.enable_http_proxy", 0)),
        )

    def context(self, subject=None, key="", actions=(), milliseconds=10000):
        token = ""
        if subject is not None:
            token = secrets.token_urlsafe(32)
            self.fixture.allow(token, subject, actions)
        return common.RpcContext(
            request_id=identifier(), subject_id=subject or "", idempotency_key=key,
            delegation_token=token, deadline_unix_ms=time.time_ns() // 1_000_000 + milliseconds,
        )

    def initialize(self, **overrides):
        fields = dict(
            context=self.context(), deployment_id=self.deployment, instance_id=self.instance,
            generation=self.generation, config_json=self.config, config_digest=digest(self.config),
            approval_revision=1,
        )
        fields.update(overrides)
        return life.InitializeRequest(**fields)

    def invoke(self, name, body, subject=None, key="", actions=(), milliseconds=10000):
        raw = canonical_json(body)
        return cap.InvokeRequest(
            context=self.context(subject or self.owner, key, actions, milliseconds),
            call_id=identifier(), contract=common.ContractRef(**self.contract_refs[name]),
            input_json=raw, input_digest=digest(raw),
        )

    def put(self, key, data, subject=None):
        subject = subject or self.owner
        blob = identifier()
        self.fixture.sources[blob] = (subject, data)
        return self.invoke("data.object.put", {
            "key": key, "blob_id": blob, "size_bytes": len(data), "digest": digest(data),
            "content_type": "application/octet-stream", "mode": "create",
        }, subject=subject, key=identifier(), actions=("read",))

    def refused(self, method, request, status, detail=None):
        with self.assertRaises(grpc.RpcError) as error:
            method(request, timeout=5)
        self.assertEqual(error.exception.code(), status, error.exception.details())
        if detail:
            trailers = dict(error.exception.trailing_metadata())
            self.assertEqual(common.ErrorDetail.FromString(trailers["xelab-error-bin"]).code, detail)

    def output(self, request):
        reply = self.capability.Invoke(request, timeout=5)
        self.assertEqual(reply.call_id, request.call_id)
        self.assertEqual(reply.output_digest, digest(reply.output_json))
        return json.loads(reply.output_json)

    def test_six_signed_operations_and_durable_result_over_mtls(self):
        description = self.lifecycle.Describe(life.DescribeRequest(context=self.context()), timeout=5)
        self.assertEqual(description.manifest_json, MANIFEST.read_bytes())
        self.assertEqual(description.manifest_digest, digest(description.manifest_json))
        health = self.lifecycle.GetHealth(life.HealthRequest(context=self.context()), timeout=5)
        self.assertTrue(health.alive)
        self.assertFalse(any(entry.ready for entry in health.capabilities))
        data = b"x" * MAX_CHUNK_BYTES + b"second frame"
        request = self.put("reports/q1", data)
        self.refused(self.capability.Invoke, request, grpc.StatusCode.UNAVAILABLE)
        initialized = self.lifecycle.Initialize(self.initialize(), timeout=5)
        self.assertEqual((initialized.initialized, initialized.observed_generation), (True, 7))
        ready = self.lifecycle.GetHealth(life.HealthRequest(context=self.context()), timeout=5)
        self.assertEqual(len(ready.capabilities), 6)
        self.assertTrue(all(entry.ready for entry in ready.capabilities))
        created = self.output(request)
        self.assertEqual(created["object"]["owner_id"], self.owner)
        self.assertEqual(created["object"]["digest"], digest(data))
        self.assertEqual(self.output(self.invoke("data.object.stat", {"key":"reports/q1"})), created)
        self.assertEqual(
            self.output(self.invoke("data.object.list", {"prefix":"reports/"}))["items"],
            [created["object"]],
        )
        self.assertEqual(self.output(self.invoke("data.object.usage.get", {}))["logical_bytes"], len(data))
        self.refused(self.capability.Invoke, self.invoke("data.object.stat", {"key":"reports/q1"}, self.other),
                     grpc.StatusCode.NOT_FOUND)
        wrong_source = self.put("reports/denied", b"owner secret")
        denied = self.invoke("data.object.put", json.loads(wrong_source.input_json), self.other,
                             key=identifier(), actions=("read",))
        self.refused(self.capability.Invoke, denied, grpc.StatusCode.PERMISSION_DENIED)
        target = {"key":"reports/q1", "expected_revision":1}
        export = self.invoke("data.object.export", target, key="导出", actions=("write",))
        result = self.output(export)
        self.assertEqual(self.fixture.outputs[result["blob_id"]], (self.owner, data))
        self.assertEqual(self.output(self.invoke("data.object.delete", target, key="delete"))["deleted_revision"], 2)
        self.stop_plugin()
        self.start_plugin()
        self.lifecycle.Initialize(self.initialize(), timeout=5)
        query = cap.QueryResultRequest(
            context=self.context(self.owner, export.context.idempotency_key),
            call_id=export.call_id, idempotency_key=export.context.idempotency_key,
        )
        settled = self.capability.QueryResult(query, timeout=5)
        self.assertEqual(settled.state, common.EXECUTION_STATE_SUCCEEDED)
        self.assertEqual(json.loads(settled.completed.output_json), result)
        query.context.CopyFrom(self.context(self.other, export.context.idempotency_key))
        self.assertEqual(self.capability.QueryResult(query, timeout=5).state, common.EXECUTION_STATE_UNKNOWN)
        self.assertEqual(self.fixture.write_count, 1)

    def test_peer_identity_and_signed_envelope(self):
        with self.client_channel(self.other_tls) as foreign:
            self.refused(lifecycle.PluginLifecycleStub(foreign).Describe,
                         life.DescribeRequest(context=self.context()), grpc.StatusCode.PERMISSION_DENIED)
        self.refused(self.lifecycle.Initialize, self.initialize(generation=8), grpc.StatusCode.FAILED_PRECONDITION)
        self.refused(self.lifecycle.Initialize, self.initialize(config_digest=digest(b"{}")),
                     grpc.StatusCode.FAILED_PRECONDITION)
        self.mount_bytes -= 1
        self.refused(self.lifecycle.Initialize, self.initialize(), grpc.StatusCode.FAILED_PRECONDITION)
        self.assertEqual(list(self.volume.iterdir()), [])
        self.mount_bytes += 1
        self.lifecycle.Initialize(self.initialize(), timeout=5)
        request = self.invoke("data.object.stat", {"key":"missing","owner_id":self.other})
        self.refused(self.capability.Invoke, request, grpc.StatusCode.INVALID_ARGUMENT)
        request.context.actor_instance_id = identifier()
        self.refused(self.capability.Invoke, request, grpc.StatusCode.PERMISSION_DENIED)
        request.context.actor_instance_id = ""
        request.contract.schema_digest = digest(b"another schema")
        self.refused(self.capability.Invoke, request, grpc.StatusCode.INVALID_ARGUMENT)
        request.context.delegation_token = ""
        self.refused(self.capability.Invoke, request, grpc.StatusCode.PERMISSION_DENIED)
        with self.assertRaises(StoreError):
            mounted_capacity(self.volume, True)

    def test_host_tls_rejects_same_ca_wrong_server_name(self):
        self.stop_plugin()
        self.host_address = self.host_server(self.other_tls)
        self.start_plugin()
        self.lifecycle.Initialize(self.initialize(), timeout=5)
        self.refused(self.capability.Invoke, self.put("wrong-peer", b"data"), grpc.StatusCode.UNAVAILABLE)
        self.assertFalse(self.fixture.read_started.is_set())
        self.assertEqual(self.output(self.invoke("data.object.list", {}))["items"], [])

    def test_cancel_propagates_to_the_active_host_read(self):
        self.lifecycle.Initialize(self.initialize(), timeout=5)
        self.fixture.pause_read = True
        request = self.put("canceled", b"data")
        request.terminal_failure_version = 1
        future = self.capability.Invoke.future(request, timeout=6)
        self.addCleanup(future.cancel)
        self.assertTrue(self.fixture.read_started.wait(4))
        cancel = cap.CancelCallRequest(context=self.context(self.other), call_id=request.call_id)
        self.refused(self.capability.Cancel, cancel, grpc.StatusCode.PERMISSION_DENIED)
        self.assertFalse(self.fixture.read_ended.is_set())
        cancel.context.CopyFrom(self.context(self.owner))
        self.assertTrue(self.capability.Cancel(cancel, timeout=4).accepted)
        with self.assertRaises(grpc.RpcError) as canceled:
            future.result(timeout=4)
        self.assertEqual(canceled.exception.code(), grpc.StatusCode.CANCELLED)
        self.assertTrue(self.fixture.read_ended.wait(4))
        self.assertEqual(self.output(self.invoke("data.object.usage.get", {}))["reserved_bytes"], 0)
        self.assertEqual(self.output(self.invoke("data.object.list", {}))["items"], [])

    def test_export_reply_loss_preserves_unknown_and_prevents_resend(self):
        self.lifecycle.Initialize(self.initialize(), timeout=5)
        self.output(self.put("exported", b"content"))
        self.fixture.drop_export_reply = True
        request = self.invoke("data.object.export", {"key":"exported","expected_revision":1},
                              key="stable", actions=("write",))
        request.terminal_failure_version = 1
        self.refused(self.capability.Invoke, request, grpc.StatusCode.UNKNOWN, "OUTCOME_UNKNOWN")
        self.fixture.drop_export_reply = False
        request.call_id = identifier()
        self.refused(self.capability.Invoke, request, grpc.StatusCode.UNKNOWN, "OUTCOME_UNKNOWN")
        self.assertEqual(self.fixture.write_count, 1)

    def test_negotiated_business_failure_has_the_original_call_and_contract(self):
        self.lifecycle.Initialize(self.initialize(), timeout=5)
        request = self.invoke("data.object.stat", {"key": "missing"})
        self.refused(self.capability.Invoke, request, grpc.StatusCode.NOT_FOUND, "RESOURCE_NOT_FOUND")
        request.terminal_failure_version = 1
        reply = self.capability.Invoke(request, timeout=5)
        self.assertEqual(reply.call_id, request.call_id)
        self.assertEqual(reply.terminal_failure, cap.InvokeFailure(
            version=1, contract=request.contract, code="RESOURCE_NOT_FOUND",
        ))
        self.assertEqual((reply.output_json, reply.output_digest), (b"", ""))

        self.output(self.put("saved", b"content"))
        stale = self.put("saved", b"new")
        stale.terminal_failure_version = 1
        reply = self.capability.Invoke(stale, timeout=5)
        self.assertEqual(reply.call_id, stale.call_id)
        self.assertEqual(reply.terminal_failure, cap.InvokeFailure(
            version=1, contract=stale.contract, code="STATE_CONFLICT",
        ))
        stale.call_id = identifier()
        with patch.object(self.service.store, "_discard_put", side_effect=OSError("cleanup failed")):
            self.refused(self.capability.Invoke, stale, grpc.StatusCode.FAILED_PRECONDITION, "STATE_CONFLICT")

    def test_bounded_queue_and_drain(self):
        self.stop_plugin()
        manifest = json.loads(MANIFEST.read_bytes())
        manifest["concurrency"].update(max_active_requests=1, max_queue_requests=1)
        self.manifest_path = self.root / "queue-manifest.json"
        self.manifest_path.write_bytes(canonical_json(manifest))
        self.start_plugin()
        self.lifecycle.Initialize(self.initialize(), timeout=5)
        self.fixture.pause_read = True
        active = self.capability.Invoke.future(self.put("active", b"abc"), timeout=8)
        self.addCleanup(active.cancel)
        self.assertTrue(self.fixture.read_started.wait(4))
        queued = self.capability.Invoke.future(self.put("queued", b"abc"), timeout=8)
        self.addCleanup(queued.cancel)
        with self.service.changed:
            self.assertTrue(self.service.changed.wait_for(lambda: len(self.service.calls) == 2, timeout=3))
        self.refused(self.capability.Invoke, self.put("too-many", b"abc"), grpc.StatusCode.RESOURCE_EXHAUSTED)
        first = self.lifecycle.Drain(life.DrainRequest(context=self.context(), grace_ms=0), timeout=4)
        self.assertEqual((first.accepting_requests, first.active_calls, first.drained), (False, 1, False))
        with self.assertRaises(grpc.RpcError) as rejected:
            queued.result(timeout=4)
        self.assertEqual(rejected.exception.code(), grpc.StatusCode.UNAVAILABLE)
        self.fixture.release_read.set()
        active.result(timeout=4)
        final = self.lifecycle.Drain(life.DrainRequest(context=self.context(), grace_ms=1000), timeout=4)
        self.assertEqual((final.active_calls, final.drained), (0, True))

    def test_plan_and_verify_check_read_only_content_after_reopen(self):
        operation = identifier()
        plan_request = mig.PlanMigrationRequest(
            context=self.context(self.owner, operation + ":plan"), deployment_id=self.deployment,
            source_schema="none", target_schema="1",
        )
        plan = self.migration.Plan(plan_request, timeout=5)
        self.assertTrue(plan.requires_exclusive_write)
        self.assertEqual(self.migration.Plan(plan_request, timeout=5), plan)
        verify = mig.VerifyMigrationRequest(
            context=self.context(self.owner, operation + ":verify"),
            plan_id=plan.plan_id, volume_fence=1,
        )
        self.refused(self.migration.Verify, verify, grpc.StatusCode.FAILED_PRECONDITION)
        self.assertEqual(list(self.volume.iterdir()), [])
        self.lifecycle.Initialize(self.initialize(), timeout=5)
        self.output(self.put("saved", b"actual data"))
        self.stop_plugin()
        self.start_plugin()
        before = {p.relative_to(self.volume): p.read_bytes() for p in self.volume.rglob("*") if p.is_file()}
        observed = self.migration.Verify(verify, timeout=5)
        self.assertEqual((observed.succeeded, observed.observed_schema), (True, "1"))
        self.assertEqual({p.relative_to(self.volume): p.read_bytes()
                          for p in self.volume.rglob("*") if p.is_file()}, before)
        self.assertEqual(self.mount_checks, [False, False, False, True, False])
        wrong = mig.VerifyMigrationRequest(
            context=self.context(self.owner, identifier() + ":verify"),
            plan_id=plan.plan_id, volume_fence=1,
        )
        self.refused(self.migration.Verify, wrong, grpc.StatusCode.FAILED_PRECONDITION)
        file, = self.volume.glob("users/*/content/*.blob")
        file.write_bytes(b"other bytes")
        self.refused(self.migration.Verify, verify, grpc.StatusCode.FAILED_PRECONDITION)

    def test_verify_reads_committed_wal_without_creating_sidecars(self):
        operation = identifier()
        plan = self.migration.Plan(mig.PlanMigrationRequest(
            context=self.context(self.owner, operation + ":plan"), deployment_id=self.deployment,
            source_schema="none", target_schema="1",
        ), timeout=5)
        self.lifecycle.Initialize(self.initialize(), timeout=5)
        self.stop_plugin()
        verify = mig.VerifyMigrationRequest(
            context=self.context(self.owner, operation + ":verify"), plan_id=plan.plan_id, volume_fence=1,
        )
        # A frozen WAL is part of the durable format. A read path that silently
        # ignored it would accept the stale checkpoint rather than reject this state.
        with closing(sqlite3.connect(self.volume / "objects.sqlite3")) as conn:
            conn.execute("PRAGMA wal_autocheckpoint=0")
            conn.execute("UPDATE os_metadata SET value=? WHERE key='cursor_key'", ("b" * 64,))
            conn.commit()
            wal = self.volume / "objects.sqlite3-wal"
            self.assertGreater(wal.stat().st_size, 0)
            self.start_plugin()
            previous = wal.read_bytes()
            self.assertTrue(self.migration.Verify(verify, timeout=5).succeeded)
            self.assertEqual(wal.read_bytes(), previous)
            conn.execute("UPDATE os_metadata SET value='2' WHERE key='data_schema_version'")
            conn.commit()
            self.refused(self.migration.Verify, verify, grpc.StatusCode.FAILED_PRECONDITION)
