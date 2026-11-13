#!/usr/bin/env python3
"""Real Chromium 151 / HTTP/2 TLS regression for the production WebUI reader.

This local component serves the unchanged production api.js over HTTP/2. It
does not start the kernel, emulate OAuth, or replace the signed-OCI Core/browser
gate in crates/kernel/tests/m3_ui.rs. Its local token provider and JSON service
are explicit fixture adapters; browser requests use native fetch, with no route
interception or fabricated browser response.

Run with XELAB_OAUTH_BROWSER_CHROMIUM pointing to the pinned Chromium 151 binary.
Missing tools, a different browser, or a failed request fail the component.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
import select
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid

from playwright.sync_api import sync_playwright

MAXIMUM = 16 * 1024 * 1024 + 65536
SKILL = "00000000-0000-4000-8000-000000000004"
FIXTURE_TOKEN = "local-http2-component-token"
API_PATH = pathlib.Path(__file__).resolve().parent / "public" / "api.js"

SERVER = r"""
const fs = require('node:fs'), http2 = require('node:http2');
const maximum = 16 * 1024 * 1024 + 65536;
const skill = '00000000-0000-4000-8000-000000000004';
let serial = 0, posts = 0, completed = 0, aborted = 0;
const cases = {};
const server = http2.createSecureServer({
  key: fs.readFileSync(process.argv[2]), cert: fs.readFileSync(process.argv[3]),
  allowHTTP1: false,
});
server.on('session', session => session.on('error', () => {}));
server.on('stream', (stream, headers) => {
  stream.on('error', () => {});
  stream.on('aborted', () => { aborted++; });
  const origin = 'https://shell.localhost:' + server.address().port;
  const cors = {
    'access-control-allow-origin': origin,
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'authorization,content-type,idempotency-key,accept',
    'cache-control': 'no-store',
  };
  if (headers[':method'] === 'OPTIONS') {
    stream.respond({':status': 204, ...cors}); stream.end(); return;
  }
  if (headers[':path'] === '/api.js') {
    stream.respond({':status': 200, 'content-type': 'text/javascript', ...cors});
    stream.end(fs.readFileSync(process.argv[4])); return;
  }
  if (headers[':path'] === '/stats') {
    stream.respond({':status': 200, 'content-type': 'application/json', ...cors});
    stream.end(JSON.stringify({posts, completed, aborted, cases})); return;
  }
  if (headers[':method'] !== 'POST') {
    stream.respond({':status': 200, 'content-type': 'text/html', ...cors});
    stream.end('<!doctype html><body><p>HTTP/2 TLS reader component.</p></body>');
    return;
  }
  const chunks = [];
  stream.on('data', chunk => chunks.push(chunk));
  stream.on('end', () => {
    let input;
    try { input = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { stream.respond({':status': 400, ...cors}); stream.end('{}'); return; }
    posts++; serial++;
    const message = input.input.message, kind = message.split(':')[0];
    const entry = cases[kind] ??= {posts: 0, chunks: 0, planned_bytes: 0};
    entry.posts++;
    const call = '00000000-0000-4000-8000-' + serial.toString(16).padStart(12, '0');
    let body = Buffer.from(JSON.stringify({
      skill_id: skill, skill_version: '1.0.0', definition_digest: 'sha256:' + 'a'.repeat(64),
      call: {
        call_id: call, skill_id: skill, skill_definition_digest: 'sha256:' + 'a'.repeat(64),
        contract: {name: 'org.xelab.http2.component.echo', version: '1.0.0', schema_digest: 'sha256:' + 'a'.repeat(64)},
        provider_instance_id: '00000000-0000-4000-8000-000000000005',
        output: {message}, completed_at: new Date().toISOString(),
      },
    }));
    let contentType = 'application/json', status = 200, length = true;
    if (['limit', 'unicode', 'plusone', 'declaredoversize'].includes(kind)) {
      const prefix = Buffer.from('{"message":"'), suffix = Buffer.from('"}');
      const size = ['limit', 'unicode'].includes(kind) ? maximum : maximum + 1;
      const wanted = size - prefix.length - suffix.length;
      const unit = kind === 'unicode' ? Buffer.from('汉🙂é') : Buffer.from('x');
      body = Buffer.concat([prefix, Buffer.alloc(Math.floor(wanted / unit.length) * unit.length, unit),
                            Buffer.alloc(wanted % unit.length, 120), suffix]);
      length = kind !== 'plusone';
    }
    if (kind === 'utf8') body = Buffer.from([123, 34, 120, 34, 58, 34, 255, 34, 125]);
    if (kind === 'badjson') body = Buffer.from('{"broken":');
    if (kind === 'wrongtype') contentType = 'text/plain';
    if (kind === 'empty204') { status = 204; body = Buffer.alloc(0); length = false; }
    entry.planned_bytes = body.length;
    const begin = () => {
      if (stream.destroyed) return;
      const response = {':status': status, 'content-type': contentType, ...cors};
      if (length) response['content-length'] = body.length;
      stream.respond(response);
      if (status === 204) { stream.end(); completed++; return; }
      if (kind === 'bodydeadline' || kind === 'bodycancel') {
        const split = Math.floor(body.length / 2);
        stream.write(body.subarray(0, split)); entry.chunks++;
        setTimeout(() => {
          if (!stream.destroyed) { stream.end(body.subarray(split)); entry.chunks++; completed++; }
        }, 350);
        return;
      }
      let offset = 0;
      const pump = () => {
        while (!stream.destroyed && offset < body.length) {
          const end = Math.min(offset + 32768, body.length);
          const chunk = body.subarray(offset, end); offset = end; entry.chunks++;
          if (!stream.write(chunk)) { stream.once('drain', pump); return; }
        }
        if (!stream.destroyed) { stream.end(); completed++; }
      };
      pump();
    };
    setTimeout(begin, ['headersdeadline', 'headerscancel'].includes(kind) ? 350 : 5);
  });
});
server.listen(0, '127.0.0.1', () => process.stdout.write(JSON.stringify({port: server.address().port}) + '\n'));
process.on('SIGTERM', () => { server.close(); setTimeout(() => process.exit(0), 100).unref(); });
"""

INVOKE = r"""
async config => {
  const {ApiClient, readJson} = await import('/api.js');
  const started = performance.now();
  let status = null;
  try {
    let value;
    if (config.primitive) {
      const response = await fetch(config.core + '/reader-fixture', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({input: {message: config.message}}),
        credentials: 'omit', signal: AbortSignal.timeout(10000),
      });
      status = response.status;
      value = await readJson(response);
    } else {
      const controller = new AbortController();
      const reason = config.customCancel ? 'local component view closed' : undefined;
      const options = {};
      if (config.cancel && !config.afterCancel && config.bodyCancel) {
        // A fixed cancel timer can beat the fixture's first body chunk on a
        // loaded runner; abort when the first chunk actually reaches the page.
        const native = globalThis.fetch.bind(globalThis);
        options.fetcher = async (...args) => {
          const response = await native(...args);
          const [probe, rest] = response.body.tee();
          (async () => {
            const reader = probe.getReader();
            try { await reader.read(); } catch { /* stream already aborted */ }
            reader.cancel().catch(() => {});
            controller.abort(reason);
          })();
          return new Response(rest, {status: response.status, statusText: response.statusText, headers: response.headers});
        };
      } else if (config.cancel && !config.afterCancel) {
        setTimeout(() => controller.abort(reason), 50);
      }
      const key = crypto.randomUUID();
      const api = new ApiClient(
        {core_origin: config.core, client_id: 'http2-browser-component'},
        {accessToken: async () => config.fixtureToken},
        options,
      );
      value = (await api.invoke('invokeSkill', {
        params: {skill_id: config.skill},
        body: {input: {message: config.message}, timeout_ms: config.deadline ? 100 : 10000, idempotency_key: key},
        idempotencyKey: key, signal: controller.signal,
        // The transport deadline cases exercise the explicit HTTP wait budget.
        waitBudgetMs: config.deadline ? 100 : undefined,
      })).data;
      status = 200;
      if (config.afterCancel) controller.abort();
    }
    document.body.dataset.actualSuccess = 'true';
    return {
      success: true, status, is_null: value === null,
      identity: value?.skill_id === config.skill && value?.call?.skill_id === config.skill,
      output: value?.call?.output?.message === config.message,
      bytes: value === null ? 0 : new TextEncoder().encode(JSON.stringify(value)).byteLength,
      elapsed_ms: performance.now() - started, call_id: value?.call?.call_id ?? null,
    };
  } catch (error) {
    return {
      success: false, status, elapsed_ms: performance.now() - started,
      error_type: /^[A-Za-z_][A-Za-z0-9_]{0,79}$/.test(error.name) ? error.name : 'Other',
      error_code: /^[A-Z_]{1,64}$/.test(error.code ?? '') ? error.code : null,
    };
  }
}
"""


def fixed_type(error):
    value = type(error).__name__
    return value if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", value) else "Other"


def network_bucket(value):
    text = str(value or "")
    for fragment, bucket in [
        ("ERR_ABORTED", "Aborted"), ("ERR_FAILED", "Failed"),
        ("ERR_CONNECTION_CLOSED", "ConnectionClosed"), ("ERR_CONNECTION_RESET", "ConnectionReset"),
        ("ERR_TIMED_OUT", "TimedOut"), ("ERR_HTTP2_PROTOCOL_ERROR", "Http2Protocol"),
    ]:
        if fragment in text:
            return bucket
    return "Other"


def canonical_uuid(value):
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


class Http2BrowserReader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.browser = cls.playwright = cls.server = cls.directory = None
        try:
            chrome = os.environ.get("XELAB_OAUTH_BROWSER_CHROMIUM")
            if not chrome or not pathlib.Path(chrome).is_file():
                raise RuntimeError("pinned_chromium_environment_required")
            if not shutil.which("node") or not shutil.which("openssl"):
                raise RuntimeError("node_and_openssl_required")
            cls.directory = tempfile.TemporaryDirectory(prefix="xelab-http2-browser-")
            root = pathlib.Path(cls.directory.name)
            os.chmod(root, 0o700)
            key, cert, script = root / "key.pem", root / "cert.pem", root / "server.cjs"
            script.write_text(SERVER)
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(key), "-out", str(cert), "-subj", "/CN=core.localhost",
                 "-addext", "subjectAltName=DNS:core.localhost,DNS:shell.localhost",
                 "-days", "1"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=10,
            )
            os.chmod(key, 0o600)
            public = subprocess.check_output(
                ["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"], timeout=5,
            )
            der = subprocess.check_output(
                ["openssl", "pkey", "-pubin", "-outform", "DER"], input=public, timeout=5,
            )
            pin = base64.b64encode(hashlib.sha256(der).digest()).decode()
            cls.server = subprocess.Popen(
                ["node", str(script), str(key), str(cert), str(API_PATH)],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
            if not select.select([cls.server.stdout], [], [], 10)[0]:
                raise RuntimeError("http2_fixture_start_timeout")
            port = json.loads(cls.server.stdout.readline())["port"]
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise RuntimeError("http2_fixture_port")
            cls.core, cls.shell = f"https://core.localhost:{port}", f"https://shell.localhost:{port}"
            cls.playwright = sync_playwright().start()
            cls.browser = cls.playwright.chromium.launch(
                executable_path=chrome, headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--no-proxy-server",
                      "--host-resolver-rules=MAP core.localhost 127.0.0.1,MAP shell.localhost 127.0.0.1",
                      "--ignore-certificate-errors-spki-list=" + pin],
            )
            if cls.browser.version.split(".")[0] != "151":
                raise RuntimeError("pinned_chromium_151_required")
            cls.api_sha256 = hashlib.sha256(API_PATH.read_bytes()).hexdigest()
        except Exception as error:
            cls.tearDownClass()
            raise RuntimeError("http2_component_setup:" + fixed_type(error)) from None

    @classmethod
    def tearDownClass(cls):
        errors = []
        if cls.browser:
            try:
                cls.browser.close()
            except Exception as error:
                errors.append(fixed_type(error))
        if cls.playwright:
            try:
                cls.playwright.stop()
            except Exception as error:
                errors.append(fixed_type(error))
        if cls.server:
            if cls.server.poll() is None:
                cls.server.terminate()
                try:
                    cls.server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    cls.server.kill()
                    cls.server.wait(timeout=3)
            if cls.server.stdout:
                cls.server.stdout.close()
        if cls.directory:
            cls.directory.cleanup()
        if errors:
            raise RuntimeError("http2_component_cleanup:" + ",".join(errors)) from None

    def setUp(self):
        self.context = self.browser.new_context()
        self.page = self.context.new_page()
        self.requests, self.active = {}, None

        def selected(request):
            return request.method == "POST" and request.url in (
                self.core + f"/api/platform/v1/skills/{SKILL}/calls", self.core + "/reader-fixture",
            )

        def request_seen(request):
            if selected(request) and self.active is not None:
                self.requests[request] = self.active
                self.active["request_ms"] = self.elapsed(self.active)

        def response_seen(response):
            if selected(response.request) and response.request in self.requests:
                self.requests[response.request]["response"] = response

        def finished(request):
            if selected(request) and request in self.requests:
                self.requests[request]["finished_ms"] = self.elapsed(self.requests[request])

        def failed(request):
            if selected(request) and request in self.requests:
                value = self.requests[request]
                value["failed_ms"] = self.elapsed(value)
                value["network_bucket"] = network_bucket(request.failure)

        self.context.on("request", request_seen)
        self.context.on("response", response_seen)
        self.context.on("requestfinished", finished)
        self.context.on("requestfailed", failed)
        try:
            self.page.goto(self.shell + "/", wait_until="domcontentloaded", timeout=10000)
            self.assertEqual(self.page.evaluate(
                'performance.getEntriesByType("navigation")[0].nextHopProtocol'), "h2")
            # Warm only the actual Core-origin TLS connection, using a native
            # GET body consumer. This is outside the selected POST counters.
            self.assertTrue(self.page.evaluate(
                "async core => {const response=await fetch(core+'/health',{credentials:'omit'});"
                "await response.arrayBuffer();return response.status===200;}", self.core))
        except Exception as error:
            self.context.close()
            raise AssertionError("http2_page_setup:" + fixed_type(error)) from None

    def tearDown(self):
        try:
            self.context.close()
        except Exception as error:
            raise AssertionError("http2_page_cleanup:" + fixed_type(error)) from None

    @staticmethod
    def elapsed(value):
        return round((time.monotonic() - value["started"]) * 1000, 3)

    def stats(self):
        try:
            return self.page.evaluate("async () => (await fetch('/stats')).json()")
        except Exception as error:
            raise AssertionError("http2_stats:" + fixed_type(error)) from None

    def invoke(self, kind, number=0, primitive=False, audit=False, custom_cancel=False):
        if self.server.poll() is not None:
            raise AssertionError("http2_fixture_process_ended")
        value = {"started": time.monotonic(), "request_ms": None, "finished_ms": None,
                 "failed_ms": None, "network_bucket": None, "response": None,
                 "json_verified": False, "body_error_type": None}
        self.active = value
        message = kind + ":" + str(number)
        try:
            ui = self.page.evaluate(INVOKE, {
                "core": self.core, "skill": SKILL, "message": message,
                "fixtureToken": FIXTURE_TOKEN, "primitive": primitive,
                "deadline": kind.endswith("deadline"), "cancel": kind.endswith("cancel"),
                "afterCancel": kind == "aftercancel",
                "bodyCancel": kind == "bodycancel",
                "customCancel": custom_cancel,
            })
            deadline = time.monotonic() + 3
            while value["finished_ms"] is None and value["failed_ms"] is None and time.monotonic() < deadline:
                self.page.evaluate("() => true")
            identifier = ui.pop("call_id", None)
            if audit and value["finished_ms"] is not None and value["response"] is not None:
                try:
                    actual = value["response"].json()
                    value["json_verified"] = (
                        actual.get("skill_id") == SKILL
                        and actual.get("call", {}).get("skill_id") == SKILL
                        and actual["call"]["call_id"] == identifier
                        and actual["call"]["output"] == {"message": message}
                    )
                except Exception as error:
                    value["body_error_type"] = fixed_type(error)
            value["ui"], value["identifier"] = ui, identifier
            return value
        except Exception as error:
            raise AssertionError("http2_actual_request:" + fixed_type(error)) from None

    def report(self, name, value):
        print("HTTP2_BROWSER_EVIDENCE " + json.dumps({
            "test": name, "browser": self.browser.version, "api_sha256": self.api_sha256,
            "adapter": "local_h2_tls_component_not_kernel_or_oci", **value,
        }, sort_keys=True), flush=True)

    def assert_successful_calls(self, kind, count):
        before = self.stats()["posts"]
        values = [self.invoke(kind, index, audit=True) for index in range(count)]
        identifiers = [value["identifier"] for value in values]
        counts = {
            "requested": count,
            "actual_posts": self.stats()["posts"] - before,
            "ui_successes": sum(bool(value["ui"]["success"] and value["ui"].get("identity")
                                     and value["ui"].get("output")) for value in values),
            "request_finished": sum(value["finished_ms"] is not None for value in values),
            "request_failed": sum(value["failed_ms"] is not None for value in values),
            "verified_json": sum(value["json_verified"] for value in values),
            "unique_call_ids": len(set(identifier for identifier in identifiers if identifier)),
            "canonical_call_ids": sum(canonical_uuid(identifier) for identifier in identifiers),
            "fixed_network_failures": {},
            "body_error_types": {},
        }
        for value in values:
            for field, key in [("network_bucket", "fixed_network_failures"), ("body_error_type", "body_error_types")]:
                if value[field]:
                    counts[key][value[field]] = counts[key].get(value[field], 0) + 1
        self.report(kind, counts)
        self.assertTrue(
            all(counts[key] == count for key in (
                "actual_posts", "ui_successes", "request_finished", "verified_json", "unique_call_ids", "canonical_call_ids"))
            and counts["request_failed"] == 0 and not counts["body_error_types"],
            "strict actual HTTP/2 call/body/lifecycle gate failed: " + json.dumps(counts, sort_keys=True),
        )

    def test_skill_calls_finish_with_verified_unique_bodies(self):
        self.assert_successful_calls("positive", 40)

    def test_completed_calls_survive_later_caller_abort(self):
        self.assert_successful_calls("aftercancel", 10)

    def test_exact_maximum_multichunk_bytes_and_unicode(self):
        for kind in ("limit", "unicode"):
            with self.subTest(case=kind):
                before = self.stats()["posts"]
                value = self.invoke(kind, primitive=True)
                case = self.stats()["cases"][kind]
                self.report(kind, {"success": value["ui"]["success"], "bytes": value["ui"].get("bytes"),
                                   "request_finished": value["finished_ms"] is not None,
                                   "fixed_network_failure": value["network_bucket"], "chunks": case["chunks"]})
                self.assertTrue(value["ui"]["success"] and value["ui"].get("bytes") == MAXIMUM)
                self.assertTrue(value["finished_ms"] is not None and value["failed_ms"] is None)
                self.assertTrue(case["planned_bytes"] == MAXIMUM and case["chunks"] > 1)
                self.assertEqual(self.stats()["posts"] - before, 1)

    def test_invalid_and_oversized_responses_are_rejected(self):
        cases = (("plusone", "PAYLOAD_TOO_LARGE"), ("declaredoversize", "PAYLOAD_TOO_LARGE"),
                 ("utf8", "INVALID_RESPONSE"), ("badjson", "INVALID_RESPONSE"),
                 ("wrongtype", "INVALID_RESPONSE"))
        for kind, expected in cases:
            with self.subTest(case=kind):
                before = self.stats()["posts"]
                value = self.invoke(kind, primitive=True)
                self.report(kind, {"success": value["ui"]["success"], "error_code": value["ui"].get("error_code"),
                                   "fixed_network_failure": value["network_bucket"]})
                self.assertFalse(value["ui"]["success"])
                self.assertEqual(value["ui"].get("error_code"), expected)
                self.assertEqual(self.stats()["posts"] - before, 1)

    def test_active_deadline_and_caller_cancellation(self):
        for kind, expected in (
            ("headersdeadline", "DEADLINE_EXCEEDED"), ("bodydeadline", "DEADLINE_EXCEEDED"),
            ("headerscancel", "CANCELED"), ("bodycancel", "CANCELED"),
        ):
            with self.subTest(case=kind):
                before = self.stats()["posts"]
                value = self.invoke(kind)
                response_seen = value["response"] is not None
                response_status = value["response"].status if response_seen else None
                case = self.stats()["cases"].get(kind, {})
                self.report(kind, {"success": value["ui"]["success"], "error_code": value["ui"].get("error_code"),
                                   "fixed_network_failure": value["network_bucket"],
                                   "response_seen": response_seen, "response_status": response_status,
                                   "actual_body_chunks": case.get("chunks", 0)})
                self.assertFalse(value["ui"]["success"])
                self.assertEqual(value["ui"].get("error_code"), expected)
                self.assertEqual(value["network_bucket"], "Aborted")
                self.assertTrue(value["failed_ms"] is not None)
                if kind.startswith("body"):
                    self.assertTrue(response_seen and response_status == 200 and case.get("chunks", 0) >= 1)
                else:
                    self.assertFalse(response_seen)
                    self.assertEqual(case.get("chunks", 0), 0)
                accepted = self.stats()["posts"] - before
                # A header-stage deadline/abort can win before Chromium sends the
                # HTTP/2 stream, so zero accepted POSTs is valid. Body-stage
                # cases already observed a response and must have one POST.
                # At most one accepted POST still proves there was no retry.
                if kind.startswith("body"):
                    self.assertEqual(accepted, 1)
                else:
                    self.assertIn(accepted, (0, 1))

    def test_custom_caller_cancellation_before_headers_and_during_body(self):
        for kind in ("headerscancel", "bodycancel"):
            with self.subTest(case=kind):
                before = self.stats()["posts"]
                value = self.invoke(kind, custom_cancel=True)
                self.assertFalse(value["ui"]["success"])
                self.assertEqual(value["ui"].get("error_code"), "CANCELED")
                self.assertEqual(value["network_bucket"], "Aborted")
                self.assertTrue(value["failed_ms"] is not None)
                self.assertEqual(value["response"] is not None, kind.startswith("body"))
                accepted = self.stats()["posts"] - before
                # A header-stage abort can win before Chromium sends the HTTP/2
                # stream. Body-stage cases already saw a response and must have
                # one accepted POST; both stages still reject a retry (>1).
                if kind.startswith("body"):
                    self.assertEqual(accepted, 1)
                else:
                    self.assertIn(accepted, (0, 1))

    def test_no_content_response_remains_null(self):
        value = self.invoke("empty204", primitive=True)
        # A 204 has no business body. Chromium can report an aborted Inspector
        # resource for this status; expose that fact separately, never relax
        # the strict 200 Skill body/lifecycle gate above.
        self.report("empty204", {"status": value["ui"].get("status"),
                               "returned_null": value["ui"].get("is_null"),
                               "fixed_network_failure": value["network_bucket"]})
        self.assertTrue(value["ui"]["success"] and value["ui"].get("is_null"))
        self.assertEqual(value["ui"].get("status"), 204)


if __name__ == "__main__":
    unittest.main()
