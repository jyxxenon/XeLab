"""Real loopback mTLS tests; no kernel, OCI or external credentials required."""
import hashlib
import base64
import contextlib
import http.client
import json
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

import build_artifact
from http_server import BUSINESS_PATH, CREATED_PATH, DISCARD_PATH, EVENTS_PATH, HOLD_PATH, READ_PATH, STATIC_PATH, KernelHTTPServer, State


class ObservedAcceptSocket:
    """Observe real TCP acceptance without replacing TLS or HTTP handling."""
    def __init__(self, wrapped):
        self.wrapped = wrapped
        self.condition = threading.Condition()
        self.accepted = 0

    def accept(self):
        result = self.wrapped.accept()
        with self.condition:
            self.accepted += 1
            self.condition.notify_all()
        return result

    def wait_accepted(self, count):
        with self.condition:
            return self.condition.wait_for(lambda: self.accepted >= count, timeout=2)

    def __getattr__(self, name):
        return getattr(self.wrapped, name)


class ObservedKernelHTTPServer(KernelHTTPServer):
    def __init__(self, *args):
        self.worker_condition = threading.Condition()
        self.active_workers = 0
        self.handler_calls = 0
        super().__init__(*args)
        self.socket = ObservedAcceptSocket(self.socket)

    def process_request_thread(self, request, client_address):
        with self.worker_condition:
            self.active_workers += 1
            self.worker_condition.notify_all()
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.worker_condition:
                self.active_workers -= 1
                self.worker_condition.notify_all()

    def finish_request(self, request, client_address):
        with self.worker_condition:
            self.handler_calls += 1
        super().finish_request(request, client_address)

    def wait_workers(self, count, timeout=2):
        with self.worker_condition:
            return self.worker_condition.wait_for(lambda: self.active_workers == count, timeout=timeout)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="xelab-http-reference-")
        cls.root = pathlib.Path(cls.directory.name)

        def openssl(*args):
            subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        openssl("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", cls.root / "ca.key", "-out", cls.root / "ca.crt", "-subj", "/CN=Test Workload CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        for name, san, purpose in [
            ("server", "DNS:localhost,IP:127.0.0.1,URI:spiffe://xelab.local/instance/00000000-0000-4000-8000-000000000001/generation/1", "serverAuth"),
            ("kernel", "URI:spiffe://xelab.local/kernel", "clientAuth"),
            ("foreign", "URI:spiffe://xelab.local/instance/00000000-0000-4000-8000-000000000002/generation/1", "clientAuth"),
        ]:
            openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", cls.root / (name + ".key"),
                    "-out", cls.root / (name + ".csr"), "-subj", "/CN=" + name)
            extension = cls.root / (name + ".ext")
            extension.write_text("subjectAltName=" + san + "\nextendedKeyUsage=" + purpose + "\n")
            openssl("x509", "-req", "-in", cls.root / (name + ".csr"), "-CA", cls.root / "ca.crt", "-CAkey", cls.root / "ca.key",
                    "-CAcreateserial", "-out", cls.root / (name + ".crt"), "-days", "1", "-extfile", extension)
        # CI's Python predates strict-by-default verification; assert the PKI shape here.
        openssl("verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", cls.root / "ca.crt",
                cls.root / "server.crt")
        (cls.root / "tls.crt").write_bytes((cls.root / "server.crt").read_bytes())
        (cls.root / "tls.key").write_bytes((cls.root / "server.key").read_bytes())
        (cls.root / "untrusted.key").write_bytes((cls.root / "foreign.key").read_bytes())
        openssl("req", "-new", "-x509", "-key", cls.root / "untrusted.key", "-days", "1",
                "-out", cls.root / "untrusted.crt", "-subj", "/CN=Untrusted Kernel",
                "-addext", "subjectAltName=URI:spiffe://xelab.local/kernel",
                "-addext", "extendedKeyUsage=clientAuth")
        cls.state = State()
        cls.server = ObservedKernelHTTPServer(("127.0.0.1", 0), cls.state, cls.root)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.directory.cleanup()

    def setUp(self):
        self.state.initialize()

    def connection(self, identity="kernel"):
        context = ssl.create_default_context(cafile=self.root / "ca.crt")
        if identity:
            context.load_cert_chain(self.root / (identity + ".crt"), self.root / (identity + ".key"))
        return http.client.HTTPSConnection("localhost", self.server.server_address[1], context=context, timeout=2)

    def request(self, method="POST", path=BUSINESS_PATH, body=b'{"message":"hello"}', headers=None, identity="kernel"):
        prepared = {"Content-Type": "application/json", "X-Xelab-Delegation": "opaque-kernel-handle",
                    "X-Xelab-Subject": "00000000-0000-4000-8000-000000000001",
                    "X-Xelab-Call-ID": str(uuid.uuid4()), "X-Xelab-Deadline-Unix-Ms": str(int(time.time() * 1000) + 10000),
                    "X-Xelab-Idempotency-Key": base64.urlsafe_b64encode("component-test-business-key".encode()).rstrip(b"=").decode()}
        if headers is not None:
            prepared.update(headers)
        connection = self.connection(identity)
        try:
            connection.request(method, path, body=body, headers=prepared)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_declared_fixed_methods_bodyless_input_and_created_status(self):
        cases = [("GET", READ_PATH, b"", 200, {"message": "HTTP fixed read"}),
                 ("PUT", CREATED_PATH, b'{"message":"created"}', 201, {"message": "created"}),
                 ("PATCH", CREATED_PATH, b'{"message":"patched"}', 200, {"message": "patched"}),
                 ("DELETE", DISCARD_PATH, b"", 204, None),
                 ("HEAD", READ_PATH, b"", 200, None)]
        for method, path, body, expected, value in cases:
            with self.subTest(method=method):
                status, _, result = self.request(method=method, path=path, body=body)
                self.assertEqual(status, expected)
                self.assertEqual(json.loads(result) if result else None, value)
        self.assertEqual(self.request(method="GET", path=READ_PATH, body=b"unexpected")[0], 400)
        self.assertEqual(self.request(method="POST", path=READ_PATH)[0], 405)
        self.assertEqual(self.request(method="DELETE", path=BUSINESS_PATH, body=b"")[0], 405)
        self.assert_business_slots_released()

    def test_real_echo_and_strict_shape(self):
        status, headers, raw = self.request(body='{"message":"你好"}'.encode())
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), {"message": "你好"})
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn("Location", headers)
        self.assert_business_slots_released()
        for body in [b'{"message":"a","message":"b"}', b'{"message":NaN}', b'{"message":1}', b'{"message":"a","other":true}', b'{}', b'{"message":"\xff"}', br'{"message":"\ud800"}']:
            with self.subTest(body=body):
                self.assertEqual(self.request(body=body)[0], 400)
                self.assert_business_slots_released()

    def test_mtls_rejects_no_certificate_and_foreign_workload(self):
        for identity in [None, "foreign", "untrusted"]:
            with self.subTest(identity=identity):
                self.assert_all_connection_slots_released()
                before = self.server.handler_calls
                with self.assertRaises((ssl.SSLError, http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError)):
                    self.request(identity=identity)
                self.assert_all_connection_slots_released()
                self.assertEqual(self.server.handler_calls, before)
        self.assertEqual(self.request()[0], 200)

    def held_handshakes(self, count):
        connections = []
        try:
            for _ in range(count):
                connection = socket.create_connection(self.server.server_address, timeout=2)
                connections.append(connection)
                connection.sendall(b"\x16")
            return connections
        except BaseException:
            for connection in connections:
                connection.close()
            raise

    def assert_all_connection_slots_released(self):
        self.assertTrue(self.server.wait_workers(0))
        acquired = 0
        try:
            while acquired < 17 and self.server.connections.acquire(blocking=False):
                acquired += 1
            self.assertEqual(acquired, 16)
        finally:
            for _ in range(acquired):
                self.server.connections.release()

    def assert_business_slots_released(self):
        # The response can reach the peer before the handler leaves its
        # business context. Observe worker completion before checking slots.
        self.assertTrue(self.server.wait_workers(0), "HTTP workers did not finish")
        with self.state.lock:
            self.assertEqual(self.state.active, 0)
        acquired = 0
        try:
            while acquired < 4 and self.state.slots.acquire(blocking=False):
                acquired += 1
            self.assertEqual(acquired, 4)
        finally:
            for _ in range(acquired):
                self.state.slots.release()

    def test_slow_tls_handshakes_do_not_block_a_legal_static_request(self):
        accepted = self.server.socket.accepted
        stalled = self.held_handshakes(1)
        try:
            # Establish that TLS work started before placing the legal peer
            # behind a second incomplete handshake in the real listen queue.
            self.assertTrue(self.server.socket.wait_accepted(accepted + 1))
            stalled.extend(self.held_handshakes(1))
            self.assertEqual(self.request("GET", STATIC_PATH, b"")[0], 200)
            self.assertGreaterEqual(self.server.active_workers, 2)
        finally:
            for connection in stalled:
                connection.close()
        self.assert_all_connection_slots_released()

    def test_tcp_tls_and_http_share_the_16_connection_bound(self):
        self.assert_all_connection_slots_released()
        stalled = self.held_handshakes(16)
        try:
            self.assertTrue(self.server.wait_workers(16))
            self.assertFalse(self.server.connections.acquire(blocking=False))
            before = self.server.handler_calls
            with self.assertRaises((OSError, http.client.RemoteDisconnected)):
                self.request("GET", STATIC_PATH, b"")
            self.assertEqual(self.server.active_workers, 16)
            self.assertEqual(self.server.handler_calls, before)
        finally:
            for connection in stalled:
                connection.close()
        self.assert_all_connection_slots_released()
        self.assertEqual(self.request()[0], 200)

    def test_tls_handshake_timeout_releases_its_slot_without_http(self):
        self.assert_all_connection_slots_released()
        before = self.server.handler_calls
        stalled = self.held_handshakes(1)
        try:
            self.assertTrue(self.server.wait_workers(1))
            self.assertTrue(self.server.wait_workers(0, timeout=3))
            self.assertEqual(stalled[0].recv(1), b"")
            self.assertEqual(self.server.handler_calls, before)
        finally:
            stalled[0].close()
        self.assert_all_connection_slots_released()
        self.assertEqual(self.request()[0], 200)

    def test_worker_start_failure_closes_socket_and_releases_its_permit(self):
        self.assert_all_connection_slots_released()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            with socket.create_connection(listener.getsockname(), timeout=2) as peer:
                request, address = listener.accept()
                try:
                    with mock.patch("socketserver.threading.Thread.start", side_effect=RuntimeError("worker start failed")):
                        with self.assertRaises(RuntimeError):
                            self.server.process_request(request, address)
                    self.assertEqual(request.fileno(), -1)
                    self.assertEqual(peer.recv(1), b"")
                finally:
                    request.close()
        self.assert_all_connection_slots_released()
        self.assertEqual(self.request()[0], 200)

    def test_handler_failure_closes_socket_and_releases_its_permit(self):
        self.assert_all_connection_slots_released()
        with mock.patch.object(self.server, "finish_request", side_effect=RuntimeError("handler failed")):
            with mock.patch.object(self.server, "handle_error") as handle_error:
                with self.assertRaises((OSError, http.client.RemoteDisconnected)):
                    self.request("GET", STATIC_PATH, b"")
                self.assert_all_connection_slots_released()
                self.assertEqual(handle_error.call_count, 1)
        self.assertEqual(self.request()[0], 200)

    def test_new_connections_observe_rotated_workload_certificate(self):
        def peer_certificate():
            connection = self.connection()
            try:
                connection.connect()
                certificate = connection.sock.getpeercert(binary_form=True)
                connection.request("GET", STATIC_PATH)
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
                return certificate
            finally:
                connection.close()

        before = peer_certificate()
        replacement = self.root / "renewed.crt"
        subprocess.run(["openssl", "x509", "-req", "-in", str(self.root / "server.csr"),
                        "-CA", str(self.root / "ca.crt"), "-CAkey", str(self.root / "ca.key"),
                        "-set_serial", "123456789", "-out", str(replacement), "-days", "1",
                        "-extfile", str(self.root / "server.ext")],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        original = (self.root / "tls.crt").read_bytes()
        try:
            replacement.replace(self.root / "tls.crt")
            self.assertNotEqual(peer_certificate(), before)
        finally:
            (self.root / "tls.crt").write_bytes(original)
        self.assertEqual(peer_certificate(), before)
        self.assert_all_connection_slots_released()

    def test_static_get_head_and_conditional(self):
        status, headers, body = self.request("GET", STATIC_PATH, b"", {"X-Xelab-Delegation": "", "X-Xelab-Subject": ""})
        self.assertEqual(status, 200)
        self.assertEqual(body, self.server.static)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        status, head, body = self.request("HEAD", STATIC_PATH, b"")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(head["Content-Length"], str(len(self.server.static)))
        self.assertEqual(self.request("GET", STATIC_PATH, b"", {"If-None-Match": headers["ETag"]})[0], 304)
        self.assertEqual(self.request("GET", STATIC_PATH, b"", {"Range": "bytes=0-9"})[0], 400)

    def test_head_business_length_describes_get_representation(self):
        get_status, get_headers, get_body = self.request("GET", READ_PATH, b"")
        head_status, head_headers, head_body = self.request("HEAD", READ_PATH, b"")
        self.assertEqual((get_status, head_status), (200, 200))
        self.assertEqual(head_body, b"")
        self.assertGreater(len(get_body), 0)
        self.assertEqual(head_headers["Content-Length"], str(len(get_body)))
        self.assertEqual(head_headers["Content-Length"], get_headers["Content-Length"])
        self.assertEqual(head_headers["Connection"].lower(), "close")

    def test_no_content_response_has_no_content_length(self):
        status, headers, body = self.request("DELETE", DISCARD_PATH, b"")
        self.assertEqual(status, 204)
        self.assertEqual(body, b"")
        self.assertNotIn("Content-Length", headers)
        self.assertEqual(headers["Connection"].lower(), "close")

    def test_conditional_responses_retain_etag_without_misleading_length(self):
        status, headers, body = self.request("GET", STATIC_PATH, b"")
        self.assertEqual(status, 200)
        self.assertGreater(len(body), 0)
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                status, conditional, result = self.request(method, STATIC_PATH, b"", {"If-None-Match": headers["ETag"]})
                self.assertEqual(status, 304)
                self.assertEqual(result, b"")
                self.assertEqual(conditional.get("ETag"), headers["ETag"])
                self.assertNotIn("Content-Length", conditional)
                self.assertEqual(conditional["Connection"].lower(), "close")

    def test_sequential_client_requests_reconnect_after_explicit_close(self):
        connection = self.connection()
        before = self.server.socket.accepted
        try:
            connection.request("GET", STATIC_PATH)
            first = connection.getresponse()
            etag = first.getheader("ETag")
            self.assertEqual(first.status, 200)
            self.assertTrue(first.will_close)
            self.assertEqual(first.read(), self.server.static)
            connection.request("HEAD", STATIC_PATH)
            second = connection.getresponse()
            self.assertEqual(second.status, 200)
            self.assertTrue(second.will_close)
            self.assertEqual(second.read(), b"")
            connection.request("GET", STATIC_PATH, headers={"If-None-Match": etag})
            third = connection.getresponse()
            self.assertEqual(third.status, 304)
            self.assertTrue(third.will_close)
            self.assertEqual(third.read(), b"")
        finally:
            connection.close()
        self.assertEqual(self.server.socket.accepted - before, 3)

    def test_delegation_and_credential_leakage_refused(self):
        for headers, status in [
            ({"X-Xelab-Delegation": ""}, 403),
            ({"X-Xelab-Subject": "other-account"}, 403),
            ({"X-Xelab-Call-ID": "forged"}, 403),
            ({"X-Xelab-Deadline-Unix-Ms": "1"}, 403),
            ({"X-Xelab-Idempotency-Key": "not+canonical/base64="}, 403),
            ({"Authorization": "Bearer user-credential"}, 400),
            ({"Cookie": "__Host-xelab_session=user-cookie"}, 400),
            ({"Upgrade": "websocket"}, 400),
            ({"Transfer-Encoding": "chunked"}, 400),
            ({"X-User-ID": "external-identity"}, 400),
            ({"X-Forwarded-Host": "external-origin"}, 400),
            ({"Content-Type": "text/plain"}, 415),
        ]:
            with self.subTest(headers=headers):
                self.assertEqual(self.request(headers=headers)[0], status)

    def test_no_catch_all_or_path_normalization(self):
        for path in ["/plugins/org.xelab.http-echo/other", BUSINESS_PATH + "/other", STATIC_PATH + "/../plugin.json",
                     "/ui/org.xelab.http-echo/%2e%2e/plugin.json", "/ui/org.xelab.http-echo%2findex.html",
                     "//ui/org.xelab.http-echo/index.html", STATIC_PATH + "?path=/xelab/plugin.json",
                     "https://kernel.xelab.local/oauth/callback"]:
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path, b"")[0], 404)
        self.assertEqual(self.request("POST", STATIC_PATH)[0], 405)
        self.assertEqual(self.request("GET", BUSINESS_PATH, b"")[0], 405)

    def test_limits_and_lifecycle_release_slots(self):
        self.assertEqual(self.request(body=b"x" * 8193)[0], 413)
        for _ in range(4):
            self.assertTrue(self.state.slots.acquire(blocking=False))
        try:
            self.assertEqual(self.request()[0], 429)
        finally:
            for _ in range(4):
                self.state.slots.release()
        self.assertEqual(self.request()[0], 200)
        self.state.drain()
        self.assertEqual(self.request()[0], 503)
        self.assertEqual(self.request("GET", STATIC_PATH, b"")[0], 200)
        self.state.initialize()
        self.assertEqual(self.request()[0], 200)
        self.assert_business_slots_released()

    def test_duplicate_framing_and_delegation_headers(self):
        for header in ["Content-Length", "Content-Type", "X-Xelab-Subject", "X-Xelab-Delegation",
                       "X-Xelab-Call-ID", "X-Xelab-Deadline-Unix-Ms", "X-Xelab-Idempotency-Key"]:
            with self.subTest(header=header):
                connection = self.connection()
                try:
                    connection.putrequest("POST", BUSINESS_PATH)
                    for key, value in [("Content-Type", "application/json"), ("Content-Length", "19"),
                                       ("X-Xelab-Subject", "00000000-0000-4000-8000-000000000001"), ("X-Xelab-Delegation", "opaque"),
                                       ("X-Xelab-Call-ID", str(uuid.uuid4())), ("X-Xelab-Deadline-Unix-Ms", str(int(time.time() * 1000) + 10000)),
                                       ("X-Xelab-Idempotency-Key", "YnVzaW5lc3M")]:
                        connection.putheader(key, value)
                        if key == header:
                            connection.putheader(key, value)
                    connection.endheaders(b'{"message":"hello"}')
                    response = connection.getresponse()
                    self.assertIn(response.status, [400, 403])
                    response.read()
                finally:
                    connection.close()

    def test_real_delayed_operation_and_bounded_sse(self):
        status, _, raw = self.request(path=HOLD_PATH, body=b'{"message":"hold","delay_ms":20}')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), {"message": "hold"})
        call = str(uuid.uuid4())
        status, headers, raw = self.request(path=EVENTS_PATH,
            body=b'{"message":"event","items":2,"interval_ms":10}', headers={"X-Xelab-Call-ID": call})
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/event-stream")
        frames = []
        for raw_frame in raw.decode().strip().split("\n\n"):
            fields = dict(line.split(": ", 1) for line in raw_frame.splitlines())
            frame = json.loads(fields["data"])
            self.assertEqual(fields["id"], f"{call}:{frame['sequence']}")
            self.assertEqual(fields["event"], frame["kind"])
            frames.append(frame)
        self.assertEqual([frame["kind"] for frame in frames], ["accepted", "item", "item", "completed"])
        self.assertEqual([frame["sequence"] for frame in frames], [1, 2, 3, 4])
        self.assertEqual(frames[-1]["payload"]["output"], {"message": "event"})
        self.assertEqual(frames[-1]["payload"]["contract"]["name"], "org.xelab.http-echo.http")
        self.assertEqual(sum(frame["terminal"] for frame in frames), 1)
        self.assert_business_slots_released()

    def test_sse_deadline_is_a_terminal_frame_and_releases_the_slot(self):
        status, _, raw = self.request(path=EVENTS_PATH,
            body=b'{"message":"deadline","items":2,"interval_ms":1000}',
            headers={"X-Xelab-Deadline-Unix-Ms": str(int(time.time() * 1000) + 1000)})
        self.assertEqual(status, 200)
        self.assertIn(b'"kind":"accepted"', raw)
        self.assertIn(b'"kind":"canceled"', raw)
        self.assertIn(b'"reason":"deadline"', raw)
        self.assertNotIn(b'"kind":"completed"', raw)
        self.assert_business_slots_released()

    def test_terminal_sse_response_can_precede_server_slot_cleanup(self):
        cleanup_started = threading.Event()
        release_cleanup = threading.Event()
        original = self.state.business

        @contextlib.contextmanager
        def delayed_business():
            with original() as acquired:
                try:
                    yield acquired
                finally:
                    if acquired:
                        cleanup_started.set()
                        if not release_cleanup.wait(5):
                            raise TimeoutError("test cleanup gate timed out")

        with mock.patch.object(self.state, "business", delayed_business):
            try:
                status, _, raw = self.request(path=EVENTS_PATH,
                    body=b'{"message":"gate","items":0,"interval_ms":0}')
                self.assertEqual(status, 200)
                self.assertIn(b'"kind":"completed"', raw)
                self.assertTrue(cleanup_started.wait(2))
                with self.state.lock:
                    self.assertEqual(self.state.active, 1)
            finally:
                release_cleanup.set()
            self.assert_business_slots_released()

    def test_json_schema_integral_numbers_are_accepted_without_truncation(self):
        self.assertEqual(self.request(path=HOLD_PATH, body=b'{"message":"float","delay_ms":1.0}')[0], 200)
        status, _, raw = self.request(path=EVENTS_PATH, body=b'{"message":"float","items":2.0,"interval_ms":1.0}')
        self.assertEqual(status, 200)
        self.assertEqual(raw.count(b'"kind":"item"'), 2)
        for value in [b'true', b'false', b'1.5', b'-1', b'5001', b'1e999']:
            with self.subTest(value=value):
                self.assertEqual(self.request(path=HOLD_PATH, body=b'{"message":"bad number","delay_ms":' + value + b'}')[0], 400)
        self.assert_business_slots_released()


class ArtifactTests(unittest.TestCase):
    def test_raw_contract_binding_and_fixed_http_skill(self):
        with tempfile.TemporaryDirectory(prefix="xelab-http-artifact-") as directory:
            root = pathlib.Path(directory)
            manifest = build_artifact.build(root, "00000000-0000-4000-8000-000000000001")
            raw = (root / "xelab/http/openapi.json").read_bytes()
            self.assertEqual(raw, pathlib.Path(__file__).with_name("openapi.json").read_bytes())
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            self.assertEqual(manifest["routes"][0]["http_contract_digest"], digest)
            self.assertEqual(manifest["skills"][0]["target"]["http_contract_digest"], digest)
            operation = json.loads(raw)["paths"][BUSINESS_PATH]["post"]
            self.assertEqual(operation["x-permission"], manifest["routes"][0]["required_action"])
            self.assertEqual(operation["operationId"], manifest["skills"][0]["target"]["http_operation_id"])
            self.assertEqual(manifest["skills"][0]["input_schema"], operation["requestBody"]["content"]["application/json"]["schema"])

    def test_optional_rpc_contract_is_a_real_signed_package(self):
        with tempfile.TemporaryDirectory(prefix="xelab-http-mixed-") as directory:
            root = pathlib.Path(directory)
            manifest = build_artifact.build(root, "00000000-0000-4000-8000-000000000001",
                                            plugin_version="2.0.0", include_rpc=True)
            cap = manifest["capabilities"][0]
            self.assertEqual(cap["contract"]["name"], "org.xelab.http-echo.rpc")
            package = root / "xelab/contracts/org.xelab.http-echo.rpc/1.0.0"
            checks = []
            for name in ["input.schema.json", "output.schema.json", "stream.schema.json", "semantics.json"]:
                checks.append(f"{name} {hashlib.sha256((package / name).read_bytes()).hexdigest()}\n")
            self.assertEqual(cap["contract"]["schema_digest"], "sha256:" + hashlib.sha256("".join(checks).encode()).hexdigest())
            self.assertEqual(manifest["skills"][0]["version"], "2.0.0")
            raw = (root / "xelab/http/openapi.json").read_bytes()
            operation = json.loads(raw)["paths"][HOLD_PATH]["post"]
            hold = manifest["skills"][-1]
            self.assertEqual(hold["target"]["http_operation_id"], operation["operationId"])
            self.assertEqual(hold["target"]["http_contract_digest"], "sha256:" + hashlib.sha256(raw).hexdigest())
            self.assertEqual(hold["input_schema"], operation["requestBody"]["content"]["application/json"]["schema"])
            self.assertEqual(hold["output_schema"], operation["responses"]["200"]["content"]["application/json"]["schema"])


if __name__ == "__main__":
    unittest.main()
