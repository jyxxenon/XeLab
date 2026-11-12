"""Small real HTTP application behind the kernel's admitted mTLS proxy.

It does not authenticate users or interpret opaque delegation handles. The
kernel's authenticated workload identity is the only accepted HTTP peer.
"""
import contextlib
import base64
import datetime
import hashlib
import http.server
import json
import math
import os
import pathlib
import socket
import ssl
import tempfile
import threading
import time
import uuid


PLUGIN_ID = "org.xelab.http-echo"
BUSINESS_PATH = "/plugins/" + PLUGIN_ID + "/echo"
HOLD_PATH = "/plugins/" + PLUGIN_ID + "/hold"
HOLD_RECEIPT = pathlib.Path("/tmp/xelab-http-hold-receipt")
EVENTS_PATH = "/plugins/" + PLUGIN_ID + "/events"
READ_PATH = "/plugins/" + PLUGIN_ID + "/read"
CREATED_PATH = "/plugins/" + PLUGIN_ID + "/created"
DISCARD_PATH = "/plugins/" + PLUGIN_ID + "/discard"
STATIC_PATH = "/ui/" + PLUGIN_ID + "/index.html"
KERNEL_IDENTITY = "spiffe://xelab.local/kernel"
MAXIMUM_BODY_BYTES = 8192


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def invalid_constant(_):
    raise ValueError("Non-finite number")


def bounded_integer(value, minimum, maximum):
    # JSON Schema integer includes finite integral JSON numbers such as1.0.
    # bool is a distinct JSON type despite being an int subclass in Python.
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or (isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()))
            or not minimum <= value <= maximum):
        raise ValueError("Input integer differs from schema")
    return int(value)


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.initialized = False
        self.draining = False
        self.active = 0
        self.hold_receipt = None
        self.slots = threading.BoundedSemaphore(4)

    def ready(self):
        with self.lock:
            return self.initialized and not self.draining

    def initialize(self, hold_receipt=None):
        with self.lock:
            self.initialized = True
            self.draining = False
            self.hold_receipt = hold_receipt

    def record_hold(self, call_id):
        with self.lock:
            receipt = self.hold_receipt
        if receipt is not None:
            # Publish a single UUID to the opt-in test's private tmpfs.
            with tempfile.NamedTemporaryFile(dir=receipt.parent, delete=False) as pending:
                try:
                    pending.write(call_id.encode("ascii"))
                    pending.flush()
                    os.replace(pending.name, receipt)
                finally:
                    pathlib.Path(pending.name).unlink(missing_ok=True)

    def drain(self):
        with self.lock:
            self.draining = True
            return self.active

    @contextlib.contextmanager
    def business(self):
        acquired = self.slots.acquire(blocking=False)
        if acquired:
            with self.lock:
                if not self.initialized or self.draining:
                    self.slots.release()
                    acquired = False
                else:
                    self.active += 1
        try:
            yield acquired
        finally:
            if acquired:
                with self.lock:
                    self.active -= 1
                self.slots.release()


class KernelHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, state, identity, static_path=None):
        self.state = state
        self.connections = threading.BoundedSemaphore(16)
        self.identity = pathlib.Path(identity)
        self.static = pathlib.Path(static_path or pathlib.Path(__file__).with_name("index.html")).read_bytes()
        self.etag = '"sha256:' + hashlib.sha256(self.static).hexdigest() + '"'
        manifest = pathlib.Path("/xelab/plugin.json")
        self.plugin_version = json.loads(manifest.read_bytes())["version"] if manifest.exists() else "1.0.0"
        contract = pathlib.Path("/xelab/http/openapi.json")
        if not contract.exists():
            contract = pathlib.Path(__file__).with_name("openapi.json")
        self.http_contract_digest = "sha256:" + hashlib.sha256(contract.read_bytes()).hexdigest()
        self.instance = os.environ.get("XELAB_INSTANCE_ID", "00000000-0000-4000-8000-000000000001")
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            try:
                self.shutdown_request(request)
            finally:
                self.connections.release()
            raise

    def process_request_thread(self, request, client_address):
        connection = request
        try:
            try:
                # One permit covers TCP, TLS and HTTP. Slow handshakes cannot
                # hold the accept loop ahead of other bounded workers.
                connection.settimeout(2)
                # Fresh contexts observe atomically rotated workload leaves.
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.minimum_version = ssl.TLSVersion.TLSv1_2
                tls.verify_mode = ssl.CERT_REQUIRED
                tls.load_verify_locations(cafile=self.identity / "ca.crt")
                tls.load_cert_chain(self.identity / "tls.crt", self.identity / "tls.key")
                tls.set_alpn_protocols(["http/1.1"])
                connection = tls.wrap_socket(connection, server_side=True)
                identities = connection.getpeercert().get("subjectAltName", ())
                if ("URI", KERNEL_IDENTITY) not in identities:
                    raise ssl.SSLError("Kernel identity required")
                connection.settimeout(5)
            except (OSError, ValueError):
                return
            super().process_request_thread(connection, client_address)
        finally:
            # Pre-handler TLS failures also close. Standard HTTP cleanup may
            # already have closed the socket; the permit is released once.
            try:
                self.shutdown_request(connection)
            finally:
                self.connections.release()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "XeLabHTTPReference/1"
    sys_version = ""

    def log_message(self, *_):
        # Raw request paths, tokens, cookies and bodies never enter logs.
        pass

    def reply(self, status, body=b"", content_type="application/json", extra=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        # 204 forbids Content-Length; 304 may include it only if it describes
        # the selected 200 representation, so omit it for bodyless responses.
        if not (100 <= status < 200 or status in (204, 304)):
            self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD" and not (100 <= status < 200 or status in (204, 304)):
            self.wfile.write(body)
        self.close_connection = True

    def error(self, status, code):
        self.reply(status, encoded({"error": code}))

    def safe_request(self):
        # The application is deliberately literal; it never resolves a user path
        # against the filesystem or accepts an absolute target URL.
        # BaseHTTPRequestHandler itself collapses a leading //; compare against
        # the request line so that normalization cannot turn an undeclared
        # external spelling into a declared route.
        target = self.requestline.split(" ", 2)[1]
        if target != self.path or self.path not in (BUSINESS_PATH, HOLD_PATH, EVENTS_PATH, READ_PATH, CREATED_PATH, DISCARD_PATH, STATIC_PATH):
            self.error(404, "NOT_FOUND")
            return False
        if (self.headers.get("Upgrade") or self.headers.get("Transfer-Encoding")
                or self.headers.get("Authorization") or self.headers.get("Cookie")
                or any(self.headers.get(name) is not None for name in
                       ("X-User-ID", "X-Plugin-ID", "X-Account-ID", "Forwarded", "X-Forwarded-For",
                        "X-Forwarded-Host", "Last-Event-ID", "Sec-WebSocket-Key", "Sec-WebSocket-Version"))
                or len(self.headers.get_all("Content-Length", [])) > 1
                or len(self.headers.get_all("Content-Type", [])) > 1):
            self.error(400, "INVALID_REQUEST")
            return False
        return True

    def admitted_context(self):
        if not self.server.state.ready():
            self.error(503, "UNAVAILABLE")
            return None
        delegates = self.headers.get_all("X-Xelab-Delegation", [])
        subjects = self.headers.get_all("X-Xelab-Subject", [])
        call_ids = self.headers.get_all("X-Xelab-Call-ID", [])
        deadlines = self.headers.get_all("X-Xelab-Deadline-Unix-Ms", [])
        keys = self.headers.get_all("X-Xelab-Idempotency-Key", [])
        try:
            if len(delegates) != 1 or not 1 <= len(delegates[0]) <= 4096 or len(subjects) != 1:
                raise ValueError("Missing fixed delegation")
            if str(uuid.UUID(subjects[0])) != subjects[0]:
                raise ValueError("Invalid subject")
            if (len(call_ids) != 1 or str(uuid.UUID(call_ids[0])) != call_ids[0]
                    or len(deadlines) != 1 or not deadlines[0].isdigit()
                    or int(deadlines[0]) <= int(time.time() * 1000)
                    or len(keys) != 1 or len(keys[0]) > 684):
                raise ValueError("Invalid admitted call context")
            business_key = base64.b64decode(keys[0] + "=" * (-len(keys[0]) % 4), altchars=b"-_", validate=True)
            if (base64.urlsafe_b64encode(business_key).rstrip(b"=").decode() != keys[0]
                    or len(business_key.decode("utf-8")) > 128):
                raise ValueError("Invalid encoded business key")
        except (ValueError, AttributeError):
            self.error(403, "DELEGATION_REQUIRED")
            return None
        return call_ids[0], int(deadlines[0])

    def do_POST(self):
        if not self.safe_request():
            return
        allowed = (BUSINESS_PATH, HOLD_PATH, EVENTS_PATH) if self.command == "POST" else (CREATED_PATH,)
        if self.path not in allowed:
            self.error(405, "METHOD_NOT_ALLOWED")
            return
        if not self.server.state.ready():
            self.error(503, "UNAVAILABLE")
            return
        context = self.admitted_context()
        if context is None:
            return
        if self.headers.get_content_type() != "application/json":
            self.error(415, "UNSUPPORTED_MEDIA_TYPE")
            return
        try:
            size = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            self.error(400, "INVALID_REQUEST")
            return
        if size < 0:
            self.error(400, "INVALID_REQUEST")
            return
        if size > MAXIMUM_BODY_BYTES:
            self.error(413, "BODY_TOO_LARGE")
            return
        with self.server.state.business() as acquired:
            if not acquired:
                self.error(429 if self.server.state.ready() else 503, "UNAVAILABLE")
                return
            try:
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError("Truncated request")
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                                   parse_constant=invalid_constant)
                required = {"message"} if self.path in (BUSINESS_PATH, CREATED_PATH) else ({"message", "delay_ms"} if self.path == HOLD_PATH else {"message", "items", "interval_ms"})
                if (not isinstance(value, dict) or set(value) != required
                        or not isinstance(value.get("message"), str) or len(value["message"]) > 1024):
                    raise ValueError("Input differs from schema")
                bounds = {"delay_ms": (0, 5000)} if self.path == HOLD_PATH else ({"items": (0, 64), "interval_ms": (0, 1000)} if self.path == EVENTS_PATH else {})
                for name, (minimum, maximum) in bounds.items():
                    value[name] = bounded_integer(value[name], minimum, maximum)
                result = encoded({"message": value["message"]})
            except (ValueError, UnicodeError, socket.timeout):
                self.error(400, "INVALID_REQUEST")
                return
            if self.path == HOLD_PATH:
                try:
                    self.server.state.record_hold(context[0])
                except OSError:
                    self.error(503, "UNAVAILABLE")
                    return
            # Actual business work: parse and return exactly the submitted text.
            # Delegation and subject are never reflected in the response body.
            if self.path == EVENTS_PATH:
                self.events(value, context[0], context[1])
            elif self.wait(value.get("delay_ms", 0), context[1]):
                self.reply(201 if self.command == "PUT" else 200, result)

    def wait(self, milliseconds, deadline):
        end = time.monotonic() + milliseconds / 1000
        while time.monotonic() < end:
            if not self.server.state.ready() or int(time.time() * 1000) >= deadline:
                self.error(503, "UNAVAILABLE")
                return False
            time.sleep(min(0.02, max(0, end - time.monotonic())))
        return True

    def events(self, value, call_id, deadline):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        def send(sequence, kind, payload, terminal=False):
            event = {"call_id": call_id, "sequence": sequence, "kind": kind,
                     "payload": payload, "terminal": terminal}
            raw = b"event: " + kind.encode() + b"\nid: " + call_id.encode() + b":" + str(sequence).encode() + b"\ndata: " + encoded(event) + b"\n\n"
            # Explicit HTTP framing proves complete EOF independently of TLS
            # close_notify. A socket close cannot stand in for a terminal frame
            # and the final chunk, especially under rustls truncation checks.
            self.wfile.write(f"{len(raw):x}\r\n".encode() + raw + b"\r\n")
            if terminal:
                self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()

        try:
            send(1, "accepted", {})
            for index in range(value["items"]):
                # SSE has already committed its status; cancellation is a
                # terminal frame, never a second HTTP error response.
                end = time.monotonic() + value["interval_ms"] / 1000
                while time.monotonic() < end:
                    if int(time.time() * 1000) >= deadline or not self.server.state.ready():
                        send(index + 2, "canceled", {"reason": "deadline" if int(time.time() * 1000) >= deadline else "requested"}, True)
                        return
                    time.sleep(min(0.02, max(0, end - time.monotonic())))
                send(index + 2, "item", {"message": value["message"], "index": index})
            completed = {"call_id": call_id, "contract": {"name": PLUGIN_ID + ".http",
                "version": self.server.plugin_version, "schema_digest": self.server.http_contract_digest},
                "provider_instance_id": self.server.instance, "output": {"message": value["message"]},
                "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")}
            send(value["items"] + 2, "completed", completed, True)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            # Disconnect ends physical work and the shared application slot;
            # the kernel still owns durable outcome/fencing decisions.
            return

    def do_GET(self):
        if not self.safe_request():
            return
        if self.path == READ_PATH and self.command in ("GET", "HEAD"):
            self.bodyless_business(200, {"message": "HTTP fixed read"})
            return
        if self.path != STATIC_PATH:
            self.error(405, "METHOD_NOT_ALLOWED")
            return
        if self.headers.get("Range"):
            self.error(400, "INVALID_REQUEST")
            return
        if self.headers.get("Content-Length", "0") != "0":
            self.error(400, "INVALID_REQUEST")
            return
        if self.headers.get("If-None-Match") == self.server.etag:
            self.reply(304, content_type="text/html; charset=utf-8", extra=(("ETag", self.server.etag),))
            return
        self.reply(200, self.server.static, "text/html; charset=utf-8",
                   (("ETag", self.server.etag),
                    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")))

    do_HEAD = do_GET

    def bodyless_business(self, status, value=None):
        if self.admitted_context() is None:
            return
        if self.headers.get("Content-Length", "0") != "0":
            self.error(400, "INVALID_REQUEST")
            return
        with self.server.state.business() as acquired:
            if not acquired:
                self.error(429 if self.server.state.ready() else 503, "UNAVAILABLE")
                return
            # reply() suppresses the bytes for HEAD while retaining the GET
            # representation length in its response metadata.
            self.reply(status, b"" if status == 204 else encoded(value))

    def do_PUT(self):
        self.do_POST()

    def do_PATCH(self):
        self.do_POST()

    def do_DELETE(self):
        if not self.safe_request():
            return
        if self.path != DISCARD_PATH:
            self.error(405, "METHOD_NOT_ALLOWED")
            return
        self.bodyless_business(204)

    def unsupported(self):
        self.error(405, "METHOD_NOT_ALLOWED")

    do_OPTIONS = unsupported
    do_CONNECT = unsupported
    do_TRACE = unsupported
