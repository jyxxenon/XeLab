#!/usr/bin/python3
"""Independent HTTP plugin with the existing generated PluginLifecycle RPC."""
import concurrent.futures
import hashlib
import json
import os
import pathlib
import threading
import time
import uuid

import grpc
from xelab.v1 import common_pb2 as common
from xelab.v1 import lifecycle_pb2 as life
from xelab.v1 import lifecycle_pb2_grpc as lifecycle
from xelab.v1 import capability_pb2 as cap
from xelab.v1 import capability_pb2_grpc as capability

from http_server import HOLD_RECEIPT, KernelHTTPServer, State, encoded, unique_object, invalid_constant, bounded_integer


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require_kernel(context):
    identities = context.auth_context().get("x509_subject_alternative_name", ())
    if b"spiffe://xelab.local/kernel" not in identities:
        context.abort(grpc.StatusCode.PERMISSION_DENIED, "Kernel identity required")


class Lifecycle(lifecycle.PluginLifecycleServicer):
    def __init__(self, state, manifest_path="/xelab/plugin.json"):
        self.state = state
        self.raw = pathlib.Path(manifest_path).read_bytes()
        self.manifest = json.loads(self.raw)
        self.generation = int(os.environ["XELAB_GENERATION"])

    def Describe(self, request, context):
        require_kernel(context)
        return life.DescribeResponse(manifest_json=self.raw, manifest_digest=digest(self.raw))

    def Initialize(self, request, context):
        require_kernel(context)
        config = json.loads(request.config_json)
        hold_receipt = (bool(self.manifest["capabilities"]) and isinstance(config, dict)
                        and config.keys() == {"test_hold_receipt"} and config["test_hold_receipt"] is True)
        if (request.instance_id != os.environ["XELAB_INSTANCE_ID"]
                or request.deployment_id != os.environ["XELAB_DEPLOYMENT_ID"]
                or request.generation != self.generation
                or digest(request.config_json) != request.config_digest
                or (config != {} and not hold_receipt)):
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Identity or config differs")
        self.state.initialize(HOLD_RECEIPT if hold_receipt else None)
        return life.InitializeResponse(observed_generation=self.generation, initialized=True)

    def GetHealth(self, request, context):
        require_kernel(context)
        return life.HealthResponse(alive=True, observed_generation=self.generation,
            capabilities=[life.CapabilityHealth(contract=common.ContractRef(**spec["contract"]), ready=self.state.ready())
                          for spec in self.manifest["capabilities"]])

    def Drain(self, request, context):
        require_kernel(context)
        active = self.state.drain()
        return life.DrainResponse(accepting_requests=False, active_calls=active, drained=active == 0)

    def Shutdown(self, request, context):
        require_kernel(context)
        self.state.drain()
        return common.Ack(request_id=request.context.request_id, accepted=True)


class EchoCapability(capability.CapabilityServiceServicer):
    """Optional real RPC adapter sharing HTTP's physical application slots."""
    def __init__(self, state, spec):
        self.state = state
        self.contract = common.ContractRef(**spec["contract"])
        self.results = {}
        self.canceled = set()

    def Invoke(self, request, context):
        require_kernel(context)
        try:
            if (request.contract != self.contract or digest(request.input_json) != request.input_digest
                    or len(request.input_json) > 8192 or not request.context.delegation_token
                    or request.context.deadline_unix_ms <= int(time.time() * 1000)
                    or str(uuid.UUID(request.call_id)) != request.call_id):
                raise ValueError("Invalid admitted call")
            value = json.loads(request.input_json.decode(), object_pairs_hook=unique_object, parse_constant=invalid_constant)
            if (not isinstance(value, dict) or set(value) != {"message", "delay_ms"}
                    or not isinstance(value["message"], str) or len(value["message"]) > 1024):
                raise ValueError("Input differs from signed contract")
            value["delay_ms"] = bounded_integer(value["delay_ms"], 0, 5000)
        except (ValueError, UnicodeError):
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid RPC request")
        with self.state.business() as acquired:
            if not acquired:
                context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "Shared physical instance slots exhausted")
            end = time.monotonic() + value["delay_ms"] / 1000
            while time.monotonic() < end:
                if (not context.is_active() or request.call_id in self.canceled or not self.state.ready()
                        or request.context.deadline_unix_ms <= int(time.time() * 1000)):
                    context.abort(grpc.StatusCode.CANCELLED, "Call stopped")
                time.sleep(min(0.02, max(0, end - time.monotonic())))
            output = encoded({"message": value["message"]})
            response = cap.InvokeResponse(call_id=request.call_id, output_json=output, output_digest=digest(output))
            with self.state.lock:
                if len(self.results) >= 1024:
                    self.results.clear()
                self.results[request.call_id] = response
            return response

    def InvokeStream(self, request, context):
        require_kernel(context)
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "This capability declares no streaming schema")

    def Cancel(self, request, context):
        require_kernel(context)
        with self.state.lock:
            if len(self.canceled) >= 1024:
                self.canceled.clear()
            self.canceled.add(request.call_id)
        return common.Ack(request_id=request.context.request_id, accepted=True)

    def QueryResult(self, request, context):
        require_kernel(context)
        with self.state.lock:
            result = self.results.get(request.call_id)
        return (cap.QueryResultResponse(state=common.EXECUTION_STATE_SUCCEEDED, completed=result) if result
                else cap.QueryResultResponse(state=common.EXECUTION_STATE_UNKNOWN))


def main():
    if os.environ.get("XELAB_HTTP_LISTEN", "0.0.0.0:8080") != "0.0.0.0:8080":
        raise ValueError("HTTP listener must use the fixed bootstrap binding")
    if os.environ.get("XELAB_PLUGIN_RPC_LISTEN", "0.0.0.0:7000") != "0.0.0.0:7000":
        raise ValueError("RPC listener must use the fixed bootstrap binding")
    state = State()
    cert_path = pathlib.Path(os.environ["XELAB_TLS_CERT_PATH"])
    identity = cert_path.parent
    if (pathlib.Path(os.environ["XELAB_TLS_KEY_PATH"]) != identity / "tls.key"
            or pathlib.Path(os.environ["XELAB_TLS_CA_PATH"]) != identity / "ca.crt"):
        raise ValueError("Workload identity paths differ")
    http = KernelHTTPServer(("0.0.0.0", 8080), state, identity)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    last = [None]

    def certificates():
        cert = cert_path.read_bytes()
        if cert == last[0]:
            return None
        config = grpc.ssl_server_certificate_configuration(
            (((identity / "tls.key").read_bytes(), cert),), root_certificates=(identity / "ca.crt").read_bytes())
        last[0] = cert
        return config

    credentials = grpc.dynamic_ssl_server_credentials(certificates(), certificates,
                                                      require_client_authentication=True)
    rpc = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=4),
                      options=[("grpc.max_receive_message_length", 1048576)])
    service = Lifecycle(state)
    lifecycle.add_PluginLifecycleServicer_to_server(service, rpc)
    if service.manifest["capabilities"]:
        capability.add_CapabilityServiceServicer_to_server(EchoCapability(state, service.manifest["capabilities"][0]), rpc)
    if not rpc.add_secure_port("0.0.0.0:7000", credentials):
        raise RuntimeError("Cannot bind plugin lifecycle listener")
    rpc.start()
    try:
        rpc.wait_for_termination()
    finally:
        state.drain()
        http.shutdown()
        http.server_close()


if __name__ == "__main__":
    main()
