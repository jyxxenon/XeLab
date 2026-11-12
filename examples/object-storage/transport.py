"""Kernel peer authentication and delegated, bounded HostService calls."""

from contextlib import contextmanager
from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
from threading import Event, Lock
import time
from urllib.parse import urlsplit

import grpc
from xelab.v1 import common_pb2 as common
from xelab.v1 import host_pb2 as host
from xelab.v1 import host_pb2_grpc as host_service

from model import StoreError, canonical_uuid, digest, invalid


KERNEL_URI = b"spiffe://xelab.local/kernel"
KERNEL_NAME = "kernel.xelab.local"
_ERROR_CODES = {
    "INVALID_ARGUMENT": grpc.StatusCode.INVALID_ARGUMENT,
    "PERMISSION_DENIED": grpc.StatusCode.PERMISSION_DENIED,
    "RESOURCE_NOT_FOUND": grpc.StatusCode.NOT_FOUND,
    "STATE_CONFLICT": grpc.StatusCode.FAILED_PRECONDITION,
    "RESOURCE_EXHAUSTED": grpc.StatusCode.RESOURCE_EXHAUSTED,
    "DEADLINE_EXCEEDED": grpc.StatusCode.DEADLINE_EXCEEDED,
    "CANCELED": grpc.StatusCode.CANCELLED,
    "UNAVAILABLE": grpc.StatusCode.UNAVAILABLE,
    "OUTCOME_UNKNOWN": grpc.StatusCode.UNKNOWN,
    "UNIMPLEMENTED": grpc.StatusCode.UNIMPLEMENTED,
}


def abort(context, error):
    detail = common.ErrorDetail(code=error.code, message=str(error))
    context.set_trailing_metadata((("xelab-error-bin", detail.SerializeToString()),))
    context.abort(_ERROR_CODES.get(error.code, grpc.StatusCode.INTERNAL), str(error))


def require_kernel(context):
    identities = context.auth_context().get("x509_subject_alternative_name", ())
    if KERNEL_URI not in identities:
        abort(context, StoreError("PERMISSION_DENIED", "Kernel workload identity required"))


def strict_json(raw, maximum):
    if not 0 < len(raw) <= maximum:
        raise invalid("JSON exceeds its byte limit")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise invalid("Duplicate JSON member")
            result[key] = value
        return result

    def nonfinite(_):
        raise invalid("Nonfinite JSON number")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=nonfinite)
    except (ValueError, RecursionError):
        raise invalid("Malformed JSON document") from None


class Work:
    def __init__(self, rpc, context, cap):
        canonical_uuid(rpc.request_id)
        declared = (rpc.deadline_unix_ms - time.time_ns() // 1_000_000) / 1000
        wire = context.time_remaining()
        self.deadline = time.monotonic() + min(cap, declared, cap if wire is None else wire)
        self.cancelled = Event()
        self.lock = Lock()
        self.outbound = None
        if not context.add_callback(self.cancel):
            self.cancel()
        self.check()

    def check(self):
        if time.monotonic() >= self.deadline:
            raise StoreError("DEADLINE_EXCEEDED", "Object storage deadline expired")
        if self.cancelled.is_set():
            raise StoreError("CANCELED", "Object storage operation canceled")

    def remaining(self):
        self.check()
        return max(self.deadline - time.monotonic(), 0.0)

    def cancel(self):
        self.cancelled.set()
        with self.lock:
            outbound = self.outbound
        if outbound is not None:
            outbound.cancel()

    @contextmanager
    def bind(self, call):
        with self.lock:
            self.outbound = call
        try:
            self.check()
            yield
        finally:
            with self.lock:
                self.outbound = None
            call.cancel()


@dataclass(frozen=True, slots=True)
class TlsFiles:
    cert: Path
    key: Path
    ca: Path

    def listener(self):
        key = self.key.read_bytes()
        ca = self.ca.read_bytes()
        last = None
        lock = Lock()

        def refresh():
            nonlocal last
            with lock:
                cert = self.cert.read_bytes()
                if cert == last:
                    return None
                config = grpc.ssl_server_certificate_configuration(
                    ((key, cert),), root_certificates=ca,
                )
                last = cert
                return config

        return grpc.dynamic_ssl_server_credentials(
            refresh(), refresh, require_client_authentication=True,
        )

    def client(self):
        return grpc.ssl_channel_credentials(
            self.ca.read_bytes(), self.key.read_bytes(), self.cert.read_bytes(),
        )


def host_address(value):
    try:
        url = urlsplit(value)
        address = ipaddress.ip_address(url.hostname)
        if (
            url.scheme == "https" and url.netloc
            and not url.username and url.password is None
            and not url.path and not url.query and not url.fragment
            and not address.is_unspecified and not address.is_multicast
            and url.port is not None and 1 <= url.port <= 65535
        ):
            return f"[{address}]:{url.port}" if address.version == 6 else f"{address}:{url.port}"
    except ValueError:
        pass
    raise invalid("Invalid configured HostService address")


class HostBlobs:
    def __init__(self, endpoint, tls, instance):
        self.address = host_address(endpoint)
        self.tls = tls
        self.instance = instance

    @contextmanager
    def stub(self):
        with grpc.secure_channel(
            self.address, self.tls.client(),
            options=(("grpc.ssl_target_name_override", KERNEL_NAME),
                     ("grpc.enable_http_proxy", 0),
                     ("grpc.max_receive_message_length", 1024 * 1024)),
        ) as channel:
            yield host_service.HostServiceStub(channel)

    def context(self, rpc, work):
        forwarded = common.RpcContext()
        forwarded.CopyFrom(rpc)
        forwarded.actor_instance_id = self.instance
        forwarded.deadline_unix_ms = min(
            rpc.deadline_unix_ms, time.time_ns() // 1_000_000 + int(work.remaining() * 1000),
        )
        return forwarded

    def read(self, rpc, work, blob):
        request = host.ReadBlobRequest(context=self.context(rpc, work), blob_id=blob)
        with self.stub() as stub:
            call = stub.ReadBlob(request, timeout=work.remaining())
            with work.bind(call):
                for chunk in call:
                    work.check()
                    yield chunk.offset, chunk.data

    def write(self, rpc, work, metadata, frames):
        forwarded = self.context(rpc, work)
        # The HostService ledger is keyed by Call and an ASCII transport key.
        # Preserve the original key in the plugin's durable business ledger.
        forwarded.idempotency_key = digest(rpc.idempotency_key.encode("utf-8"))

        def body():
            yield host.WriteBlobRequest(header=host.WriteBlobHeader(
                context=forwarded, content_type=metadata["content_type"],
                size_bytes=metadata["size_bytes"], digest=metadata["digest"],
            ))
            for offset, data in frames:
                work.check()
                yield host.WriteBlobRequest(data=host.BlobChunk(offset=offset, data=data))

        with self.stub() as stub:
            call = stub.WriteBlob.future(body(), timeout=work.remaining())
            with work.bind(call):
                reference = call.result()
        return {"blob_id": reference.blob_id, "size_bytes": reference.size_bytes,
                "digest": reference.digest}
