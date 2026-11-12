#!/usr/bin/env python3
"""Actual Chromium + official BridgeHost + separate-process mTLS echo component.

Core responses are an explicit bounded component adapter, not a kernel router.
The plugin's static and business responses come from its real HTTPS process.
"""
import argparse
import base64
import copy
import datetime
import hashlib
import http.client
import json
import os
import pathlib
import ssl
import subprocess
import sys
import time
import unittest
import uuid
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright
import build_artifact
import test_http

SHELL, CORE, PLUGIN = "https://shell.ui-reference.test", "https://core.ui-reference.test", "https://plugin.ui-reference.test"
SUBJECT, DEPLOYMENT, INSTALLATION, SKILL, INSTANCE = [str(uuid.UUID(int=value)) for value in range(1, 6)]
DIGEST = "sha256:" + "a" * 64
HOST_PUBLIC = None
TOKENS = {"accent":"#4F7CFF", "desktop":"#E9EEF7", "surface":"#FFFFFF", "text":"#18202C", "muted_text":"#526074", "border":"#CBD5E1", "danger":"#B42318", "radius_px":12, "blur_px":16, "panel_opacity":0.92, "font":"system"}


class IndependentPage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Disposable identities only. The helper also has a small unused local
        # server; every browser request below targets the separate child port.
        test_http.HTTPTests.setUpClass()
        cls.port_file = test_http.HTTPTests.root / "browser-component-port.json"
        cls.process = subprocess.Popen([sys.executable, str(pathlib.Path(__file__).with_name("component_server.py")), "--identity", str(test_http.HTTPTests.root), "--port-file", str(cls.port_file)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while not cls.port_file.exists() and cls.process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if not cls.port_file.exists():
            cls.process.terminate()
            cls.process.wait(timeout=5)
            test_http.HTTPTests.tearDownClass()
            raise RuntimeError("The independent mTLS component could not start")
        cls.port = json.loads(cls.port_file.read_text())["port"]
        cls.manifest = build_artifact.build(test_http.HTTPTests.root / "artifact", str(uuid.uuid4()))
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(executable_path=os.environ.get("XELAB_OAUTH_BROWSER_CHROMIUM", "/usr/bin/chromium"), headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.process.stderr.close()
        test_http.HTTPTests.tearDownClass()

    def setUp(self):
        self.context = self.browser.new_context()
        self.page = self.context.new_page()
        self.current = self.contribution("echo_window")
        self.calls, self.opened, self.errors, self.backend_messages = [], [], [], []
        self.revoked = False
        self.results = {}
        self.defer_echo = False
        self.deferred_echo = None
        self.defer_result_checks = False
        self.deferred_result_checks = []
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))
        self.page.route("**/*", self.route)

    def tearDown(self):
        self.assertEqual(self.errors, [])
        self.context.close()

    def contribution(self, identifier):
        spec = copy.deepcopy(next(value for value in self.manifest["ui"]["contributions"] if value["id"] == identifier))
        digest = "sha256:" + hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return {"deployment_id":DEPLOYMENT, "installation_id":INSTALLATION, "plugin_id":build_artifact.PLUGIN_ID, "manifest_digest":"sha256:"+"b"*64, "contribution_digest":digest, "spec":spec,
                "frame_url":PLUGIN+"/ui/"+build_artifact.PLUGIN_ID+spec["entry_path"], "frame_origin":PLUGIN, "availability":"ready", "reason_codes":[],
                "bindings":[{"alias":"echo", "skill_id":SKILL, "definition_digest":DIGEST, "modes":["call"]}]}

    def backend(self, path, method="GET", value=None):
        context = ssl.create_default_context(cafile=test_http.HTTPTests.root / "ca.crt")
        context.load_cert_chain(test_http.HTTPTests.root / "kernel.crt", test_http.HTTPTests.root / "kernel.key")
        connection = http.client.HTTPSConnection("localhost", self.port, context=context, timeout=5)
        headers = {}
        body = b""
        if value is not None:
            body = json.dumps(value).encode()
            headers = {"Content-Type":"application/json", "X-Xelab-Delegation":"explicit-component-adapter-handle", "X-Xelab-Subject":SUBJECT, "X-Xelab-Call-ID":str(uuid.uuid4()), "X-Xelab-Deadline-Unix-Ms":str(int(time.time()*1000)+10000), "X-Xelab-Idempotency-Key":base64.urlsafe_b64encode(b"component-intent").rstrip(b"=").decode()}
        try:
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            return response.status, {key.lower():value for key,value in response.getheaders()}, response.read()
        finally:
            connection.close()

    def route(self, route):
        request, parsed = route.request, urlparse(route.request.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin == SHELL:
            if parsed.path in ("/bridge.js", "/api.js"):
                route.fulfill(content_type="text/javascript", body=(HOST_PUBLIC / parsed.path[1:]).read_bytes())
            else:
                route.fulfill(content_type="text/html", body=f"""<!doctype html><main id=frames></main><script type=module>
import {{BridgeHost}} from '/bridge.js'; import {{ApiClient}} from '/api.js';
window.states=[]; window.opened=[]; window.deferOpen=false; window.rejectOpen=false; window.releaseOpen=null;
const api=new ApiClient({{core_origin:{json.dumps(CORE)},client_id:'component-only-client'}},{{accessToken:async()=> 'parent-only-component-token'}});
window.launch=async contribution=>{{const iframe=document.createElement('iframe');iframe.width=640;iframe.height=420;document.querySelector('#frames').append(iframe);
window.bridge=new BridgeHost({{iframe,api,contribution,subjectId:{json.dumps(SUBJECT)},isCurrent:()=>true,coreOrigin:{json.dumps(CORE)},theme:()=>({{theme_tokens:{json.dumps(TOKENS)},reduce_motion:false,reduce_transparency:false}}),onState:(...state)=>states.push(state),openWindow:async value=>{{opened.push(value);if(window.deferOpen)await new Promise((resolve,reject)=>window.releaseOpen=()=>window.rejectOpen?reject(new Error('synthetic open failure')):resolve());return crypto.randomUUID();}}}});await bridge.mount();}};
</script>""")
            return
        if origin == PLUGIN:
            status, headers, body = self.backend(parsed.path + ("?"+parsed.query if parsed.query else ""))
            headers = {key:value for key,value in headers.items() if key in ("content-type", "cache-control", "etag", "x-content-type-options", "referrer-policy")}
            headers["content-security-policy"] = f"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors {SHELL}"
            route.fulfill(status=status, headers=headers, body=body)
            return
        if origin != CORE:
            route.abort()
            return
        cors = {"access-control-allow-origin":SHELL, "access-control-allow-headers":"authorization,content-type,idempotency-key,if-match", "access-control-allow-methods":"GET,POST,OPTIONS", "access-control-expose-headers":"etag,x-request-id", "x-request-id":SUBJECT}
        if request.method == "OPTIONS":
            route.fulfill(status=204, headers=cors)
            return
        self.calls.append({"path":parsed.path, "method":request.method, "headers":request.all_headers(), "body":request.post_data})
        if self.revoked:
            route.fulfill(status=403, headers=cors, content_type="application/json", body=json.dumps({"error":{"code":"PERMISSION_DENIED", "message":"Component source revoked", "retryable":False, "violations":[], "retry_after_ms":None, "resource_id":None}}))
        elif "/ui/contributions/" in parsed.path:
            identifier = parsed.path.rsplit("/", 1)[1]
            value = self.current if identifier == self.current["spec"]["id"] else self.contribution(identifier)
            if self.defer_result_checks and any(call["path"].startswith("/api/platform/v1/calls/") for call in self.calls):
                self.deferred_result_checks.append((route, cors, value))
                return
            route.fulfill(headers=cors, content_type="application/json", body=json.dumps(value))
        elif request.method == "POST" and parsed.path == f"/api/platform/v1/skills/{SKILL}/calls":
            value = json.loads(request.post_data)
            status, _, raw = self.backend(f"/plugins/{build_artifact.PLUGIN_ID}/echo", "POST", value["input"])
            self.assertEqual(status, 200)
            output = json.loads(raw)
            self.backend_messages.append(output)
            result = {"skill_id":SKILL, "skill_version":"1.0.0", "definition_digest":DIGEST, "call":{"call_id":str(uuid.uuid4()), "contract":{"name":build_artifact.PLUGIN_ID+".echo", "version":"1.0.0", "schema_digest":DIGEST}, "provider_instance_id":INSTANCE, "skill_id":SKILL, "skill_definition_digest":DIGEST, "output":output, "completed_at":datetime.datetime.now(datetime.timezone.utc).isoformat()}}
            self.results[result["call"]["call_id"]] = result["call"]
            if self.defer_echo:
                self.deferred_echo = (route, cors, result)
                return
            route.fulfill(headers=cors, content_type="application/json", body=json.dumps(result))
        elif request.method == "GET" and parsed.path.startswith("/api/platform/v1/calls/") and parsed.path.rsplit("/",1)[1] in self.results:
            call = self.results[parsed.path.rsplit("/",1)[1]]
            route.fulfill(headers=cors, content_type="application/json", body=json.dumps({"call_id":call["call_id"],"state":"succeeded","result":call,"error":None}))
        else:
            route.fulfill(status=404, headers=cors, content_type="application/json", body='{"error":{"code":"RESOURCE_NOT_FOUND"}}')

    def launch(self):
        self.page.goto(SHELL+"/")
        self.page.wait_for_function("typeof launch === 'function'")
        with self.page.expect_event("framenavigated", predicate=lambda frame:frame.url.startswith(PLUGIN)) as navigation:
            self.page.evaluate("value=>launch(value)", self.current)
        self.page.wait_for_function("states.some(state=>state[0]==='active')")
        frame = navigation.value
        frame.wait_for_function("() => document.querySelector('#state').textContent.includes('ready') || document.querySelector('#state').textContent.includes('not granted')")
        return frame

    def test_real_frame_calls_real_independent_process_and_renders_text_only(self):
        frame = self.launch()
        self.assertTrue(frame.evaluate("(()=>{try{parent.document.body;return false}catch{return true}})()"))
        self.assertTrue(frame.evaluate("(()=>{try{parent.sessionStorage.length;return false}catch{return true}})()"))
        message = "Actual backend <img src=x onerror=alert(1)>"
        frame.locator("#message").fill(message)
        frame.locator("#call").click()
        frame.wait_for_function("() => document.querySelector('#skill-state').textContent==='Skill call completed.'")
        self.assertEqual(frame.locator("#result").inner_text(), message)
        self.assertEqual(frame.locator("img").count(), 0)
        self.assertEqual(frame.locator('#result-context').inner_text(), 'Submitted message: ' + json.dumps(message))
        self.assertEqual(frame.locator('#result-context img').count(), 0)
        self.assertEqual(self.backend_messages, [{"message":message}])
        post = next(value for value in self.calls if value["method"] == "POST")
        body = json.loads(post["body"])
        self.assertEqual(body["provider_deployment_id"], DEPLOYMENT)
        self.assertEqual(body["idempotency_key"], post["headers"]["idempotency-key"])
        self.assertNotIn("cookie", post["headers"])
        self.assertTrue(frame.evaluate("!document.body.textContent.includes('parent-only-component-token') && localStorage.length===0 && sessionStorage.length===0"))

    def test_echo_waits_for_current_result_checks_after_the_business_timeout_window(self):
        frame = self.launch()
        self.defer_echo = True
        self.defer_result_checks = True
        message = "Wait for the fixed Call and contribution proofs"
        frame.locator("#message").fill(message)
        frame.locator("#call").click()
        deadline = time.monotonic() + 5
        while self.deferred_echo is None and time.monotonic() < deadline:
            self.page.wait_for_timeout(10)
        self.assertIsNotNone(self.deferred_echo, "expected a submitted Skill Call")
        route, cors, result = self.deferred_echo
        self.assertEqual(json.loads(route.request.post_data)["timeout_ms"], 10000)
        proof_path = "/api/platform/v1/calls/" + result["call"]["call_id"]
        # Both operations fit within their own ten-second HTTP budgets. The
        # iframe has to wait for their combined time and the host's other checks.
        self.page.wait_for_timeout(4200)
        with self.page.expect_response(lambda response: response.url == CORE + proof_path and response.status == 200):
            route.fulfill(headers=cors, content_type="application/json", body=json.dumps(result))
        deadline = time.monotonic() + 5
        while not self.deferred_result_checks and time.monotonic() < deadline:
            self.page.wait_for_timeout(10)
        self.assertTrue(self.deferred_result_checks, "expected a contribution check after the Call proof")
        self.page.wait_for_timeout(6200)
        state = frame.locator("#skill-state").inner_text()
        output = frame.locator("#result").inner_text()
        self.defer_result_checks = False
        for pending, headers, contribution in self.deferred_result_checks:
            pending.fulfill(headers=headers, content_type="application/json", body=json.dumps(contribution))
        self.assertEqual(state, "Waiting for the actual Skill result…")
        self.assertEqual(output, "")
        frame.wait_for_function("() => document.querySelector('#skill-state').textContent === 'Skill call completed.'", timeout=5000)
        self.assertEqual(frame.locator("#result").inner_text(), message)
        self.assertEqual(self.backend_messages, [{"message": message}])
        self.assertEqual(sum(call["method"] == "POST" for call in self.calls), 1)
        self.assertEqual(sum(call["path"] == proof_path for call in self.calls), 1)

    def assert_edited_message_keeps_result_attributed_to_submitted_message(self):
        frame = self.launch()
        self.defer_echo = True
        frame.locator('#message').fill('first')
        frame.locator('#call').click()
        deadline = time.monotonic() + 5
        while self.deferred_echo is None and time.monotonic() < deadline:
            self.page.wait_for_timeout(10)
        self.assertIsNotNone(self.deferred_echo, 'expected the first request to reach the Core adapter')
        frame.locator('#message').fill('second')
        route, cors, result = self.deferred_echo
        self.defer_echo = False
        # Distinguish the Core adapter's returned output from the input so the
        # assertion cannot pass if the UI fabricates a local echo. The actual
        # separate-process echo received "first" above; this response mutation
        # is limited to the controlled adapter.
        result = copy.deepcopy(result)
        result['call']['output']['message'] = 'adapter-returned-result'
        self.results[result['call']['call_id']] = copy.deepcopy(result['call'])
        route.fulfill(headers=cors, content_type='application/json', body=json.dumps(result))
        frame.wait_for_function("() => document.querySelector('#skill-state').textContent === 'Skill call completed.'")
        self.assertEqual(frame.locator('#message').input_value(), 'second')
        self.assertEqual(frame.locator('#result').inner_text(), 'adapter-returned-result')
        self.assertEqual(frame.locator('#result-context').count(), 1)
        self.assertEqual(frame.locator('#result-context').inner_text(), 'Submitted message: "first"')
        self.assertEqual(self.backend_messages, [{'message':'first'}])

        frame.locator('#message').fill('third')
        self.assertEqual(frame.locator('#result').inner_text(), 'adapter-returned-result')
        self.assertEqual(frame.locator('#result-context').inner_text(), 'Submitted message: "first"')
        frame.locator('#message').fill('second')
        frame.locator('#call').click()
        frame.wait_for_function("() => document.querySelector('#skill-state').textContent === 'Skill call completed.'")
        self.assertEqual(frame.locator('#result').inner_text(), 'second')
        self.assertEqual(frame.locator('#result-context').inner_text(), 'Submitted message: "second"')

    def test_window_edited_message_keeps_result_attributed_to_submitted_message(self):
        self.assert_edited_message_keeps_result_attributed_to_submitted_message()

    def test_widget_edited_message_keeps_result_attributed_to_submitted_message(self):
        self.current = self.contribution('echo_widget')
        self.assert_edited_message_keeps_result_attributed_to_submitted_message()

    def test_failed_call_still_identifies_submitted_message(self):
        frame = self.launch()
        self.defer_echo = True
        frame.locator('#message').fill('first')
        frame.locator('#call').click()
        deadline = time.monotonic() + 5
        while self.deferred_echo is None and time.monotonic() < deadline:
            self.page.wait_for_timeout(10)
        self.assertIsNotNone(self.deferred_echo)
        frame.locator('#message').fill('second')
        route, cors, _ = self.deferred_echo
        route.fulfill(status=403, headers=cors, content_type='application/json', body=json.dumps({'error':{'code':'PERMISSION_DENIED','message':'denied','retryable':False,'violations':[],'retry_after_ms':None,'resource_id':None}}))
        frame.wait_for_function("() => document.querySelector('#skill-state').textContent.startsWith('BACKEND_ERROR:')")
        self.assertEqual(frame.locator('#result').inner_text(), '')
        self.assertEqual(frame.locator('#result-context').inner_text(), 'Submitted message: "first"')
        self.assertEqual(frame.locator('#message').input_value(), 'second')

    def test_closed_bridge_clears_context_and_keeps_closed_status(self):
        frame = self.launch()
        frame.evaluate("""() => {
          window.lateResponses = [];
          window.addEventListener('message', event => {
            if (event.data && event.data.type === 'response') window.lateResponses.push(event.data);
          });
        }""")
        self.defer_echo = True
        frame.locator('#message').fill('first')
        frame.locator('#call').click()
        deadline = time.monotonic() + 5
        while self.deferred_echo is None and time.monotonic() < deadline:
            self.page.wait_for_timeout(10)
        self.assertIsNotNone(self.deferred_echo)
        frame.evaluate("() => window.dispatchEvent(new Event('pagehide'))")
        frame.wait_for_function("() => document.querySelector('#state').textContent === 'Channel closed.'")
        self.assertEqual(frame.locator('#result-context').inner_text(), '')
        self.assertEqual(frame.locator('#result').inner_text(), '')
        self.assertEqual(frame.locator('#skill-state').inner_text(), '')
        self.assertTrue(frame.locator('#call').is_disabled())
        route, cors, result = self.deferred_echo
        route.fulfill(headers=cors, content_type='application/json', body=json.dumps(result))
        frame.wait_for_function("() => window.lateResponses.length === 1")
        self.assertEqual(frame.locator('#state').inner_text(), 'Channel closed.')
        self.assertEqual(frame.locator('#result-context').inner_text(), '')
        self.assertEqual(frame.locator('#skill-state').inner_text(), '')

    def test_widget_opens_only_the_same_deployment_window(self):
        self.current = self.contribution("echo_widget")
        frame = self.launch()
        frame.locator("#open-window").click()
        self.page.wait_for_function("opened.length===1")
        opened = self.page.evaluate("opened[0]")
        self.assertEqual(opened["deployment_id"], DEPLOYMENT)
        self.assertEqual(opened["spec"]["id"], "echo_window")
        self.assertEqual(len(self.backend_messages), 0)

    def test_widget_window_completion_does_not_erase_skill_failure(self):
        self.current = self.contribution('echo_widget')
        frame = self.launch()
        self.page.evaluate('window.deferOpen = true')
        frame.locator('#open-window').click()
        self.page.wait_for_function("() => typeof window.releaseOpen === 'function'")
        self.defer_echo = True
        frame.locator('#message').fill('submitted first')
        frame.locator('#call').click()
        deadline = time.monotonic() + 5
        while self.deferred_echo is None and time.monotonic() < deadline:
            self.page.wait_for_timeout(10)
        self.assertIsNotNone(self.deferred_echo)
        route, cors, _ = self.deferred_echo
        route.fulfill(status=403, headers=cors, content_type='application/json', body=json.dumps({'error':{'code':'PERMISSION_DENIED','message':'denied','retryable':False,'violations':[],'retry_after_ms':None,'resource_id':None}}))
        frame.wait_for_function("() => document.querySelector('#skill-state').textContent.startsWith('BACKEND_ERROR:')")
        self.page.evaluate('bridge.refresh()')
        frame.wait_for_function("() => document.querySelector('#state').textContent.startsWith('Widget refresh requested.')")
        self.assertTrue(frame.locator('#skill-state').inner_text().startswith('BACKEND_ERROR:'))
        self.page.evaluate('window.releaseOpen()')
        frame.wait_for_function("() => document.querySelector('#window-state').textContent.includes('host opened')")
        self.assertTrue(frame.locator('#skill-state').inner_text().startswith('BACKEND_ERROR:'), 'window success must not erase a Skill failure')
        self.assertEqual(frame.locator('#result-context').inner_text(), 'Submitted message: "submitted first"')
        self.assertEqual(frame.locator('#skill-state').get_attribute('role'), 'status')
        self.assertEqual(frame.locator('#window-state').get_attribute('role'), 'status')
        self.assertEqual(frame.locator('#result').get_attribute('aria-describedby'), 'result-context')

    def test_widget_skill_completion_does_not_erase_window_failure(self):
        self.current = self.contribution('echo_widget')
        frame = self.launch()
        self.page.evaluate('window.deferOpen = true; window.rejectOpen = true')
        frame.locator('#open-window').click()
        self.page.wait_for_function("() => typeof window.releaseOpen === 'function'")
        self.defer_echo = True
        frame.locator('#message').fill('submitted second')
        frame.locator('#call').click()
        deadline = time.monotonic() + 5
        while self.deferred_echo is None and time.monotonic() < deadline:
            self.page.wait_for_timeout(10)
        self.assertIsNotNone(self.deferred_echo)
        self.page.evaluate('window.releaseOpen()')
        frame.wait_for_function("() => document.querySelector('#window-state').textContent.startsWith('BINDING_UNAVAILABLE:')")
        window_failure = frame.locator('#window-state').inner_text()
        route, cors, result = self.deferred_echo
        route.fulfill(headers=cors, content_type='application/json', body=json.dumps(result))
        frame.wait_for_function("() => document.querySelector('#skill-state').textContent === 'Skill call completed.'")
        self.assertEqual(frame.locator('#window-state').inner_text(), window_failure)
        self.assertEqual(frame.locator('#result').inner_text(), 'submitted second')
        self.assertEqual(frame.locator('#result-context').inner_text(), 'Submitted message: "submitted second"')

    def test_widget_late_window_failure_does_not_erase_skill_success(self):
        self.current = self.contribution('echo_widget')
        frame = self.launch()
        self.page.evaluate('window.deferOpen = true; window.rejectOpen = true')
        frame.locator('#open-window').click()
        self.page.wait_for_function("() => typeof window.releaseOpen === 'function'")
        frame.locator('#message').fill('completed Skill')
        frame.locator('#call').click()
        frame.wait_for_function("() => document.querySelector('#skill-state').textContent === 'Skill call completed.'")
        self.page.evaluate('window.releaseOpen()')
        frame.wait_for_function("() => document.querySelector('#window-state').textContent.startsWith('BINDING_UNAVAILABLE:')")
        self.assertEqual(frame.locator('#skill-state').inner_text(), 'Skill call completed.')
        self.assertEqual(frame.locator('#result').inner_text(), 'completed Skill')

    def test_widget_late_skill_failure_does_not_erase_window_success(self):
        self.current = self.contribution('echo_widget')
        frame = self.launch()
        self.defer_echo = True
        frame.locator('#call').click()
        deadline = time.monotonic() + 5
        while self.deferred_echo is None and time.monotonic() < deadline:
            self.page.wait_for_timeout(10)
        self.assertIsNotNone(self.deferred_echo)
        frame.locator('#open-window').click()
        frame.wait_for_function("() => document.querySelector('#window-state').textContent.includes('host opened')")
        window_success = frame.locator('#window-state').inner_text()
        route, cors, _ = self.deferred_echo
        route.fulfill(status=403, headers=cors, content_type='application/json', body=json.dumps({'error':{'code':'PERMISSION_DENIED','message':'denied','retryable':False,'violations':[],'retry_after_ms':None,'resource_id':None}}))
        frame.wait_for_function("() => document.querySelector('#skill-state').textContent.startsWith('BACKEND_ERROR:')")
        self.assertEqual(frame.locator('#window-state').inner_text(), window_success)

    def test_widget_closed_bridge_keeps_closed_status_after_open_response(self):
        self.current = self.contribution('echo_widget')
        frame = self.launch()
        frame.evaluate("""() => {
          window.lateResponses = [];
          window.addEventListener('message', event => {
            if (event.data && event.data.type === 'response') window.lateResponses.push(event.data);
          });
        }""")
        self.page.evaluate('window.deferOpen = true')
        frame.locator('#open-window').click()
        self.page.wait_for_function("() => typeof window.releaseOpen === 'function'")
        frame.evaluate("() => window.dispatchEvent(new Event('pagehide'))")
        frame.wait_for_function("() => document.querySelector('#state').textContent === 'Channel closed.'")
        self.page.evaluate('window.releaseOpen()')
        frame.wait_for_function("() => window.lateResponses.length === 1")
        self.assertEqual(frame.locator('#state').inner_text(), 'Channel closed.')
        self.assertTrue(frame.locator('#open-window').is_disabled())
        self.assertEqual(frame.locator('#window-state').inner_text(), '')
        self.assertEqual(frame.locator('#skill-state').inner_text(), '')

    def test_missing_binding_and_source_revocation_do_not_produce_fake_results(self):
        self.current["bindings"] = []
        frame = self.launch()
        self.assertTrue(frame.locator("#call").is_disabled())
        self.assertEqual(frame.locator("#result").inner_text(), "")
        self.assertEqual(self.backend_messages, [])
        self.revoked = True
        self.page.wait_for_function("states.some(state=>state[0]==='closed')", timeout=8000)
        self.assertEqual(self.page.locator("iframe").count(), 0)

    def test_wrong_nonce_and_replayed_host_sequence_are_ignored(self):
        frame = self.launch()
        self.page.evaluate("""origin=>{const iframe=document.querySelector('iframe'),meta=Object.fromEntries(new URL(iframe.src).hash.slice(1).split('&').map(pair=>pair.split('=').map(decodeURIComponent)));for(const message of [{protocol:meta.protocol,view_id:meta.view_id,channel_nonce:'0'.repeat(64),seq:2,type:'event',event:'host.dispose',params:{reason:'logout'}},{protocol:meta.protocol,view_id:meta.view_id,channel_nonce:meta.channel_nonce,seq:1,type:'event',event:'host.dispose',params:{reason:'logout'}}])iframe.contentWindow.postMessage(message,origin); }""", PLUGIN)
        frame.locator("#message").fill("Still the valid channel")
        frame.locator("#call").click()
        frame.wait_for_function("() => document.querySelector('#skill-state').textContent==='Skill call completed.'")
        self.assertEqual(self.backend_messages, [{"message":"Still the valid channel"}])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--webui-public", type=pathlib.Path, required=True, help="The actual official WebUI public/ source directory")
    args, remaining = parser.parse_known_args()
    HOST_PUBLIC = args.webui_public.resolve()
    if not all((HOST_PUBLIC / name).is_file() for name in ("bridge.js", "api.js")):
        parser.error("The actual official BridgeHost/API modules are required")
    unittest.main(argv=[sys.argv[0], *remaining])
