#!/usr/bin/env python3
"""Real cross-origin Chromium frames with explicit core fixtures, not M3 E2E."""
import copy
import base64
import hashlib
import json
import os
import pathlib
import time
import unittest
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

PUBLIC = pathlib.Path(__file__).parent / "public"
REFERENCE_PUBLIC = pathlib.Path(__file__).resolve().parents[1] / "ui-reference" / "public"
SHELL, CORE, PLUGIN, ATTACKER = ("https://shell.example.test", "https://core.example.test",
                                 "https://plugin.example.test", "https://attacker.example.test")
SUBJECT = "00000000-0000-4000-8000-000000000001"
DEPLOYMENT = "00000000-0000-4000-8000-000000000002"
INSTALLATION = "00000000-0000-4000-8000-000000000003"
SKILL = "00000000-0000-4000-8000-000000000004"
DIGEST = "sha256:" + "a" * 64
THEME = {"theme_tokens": {"accent": "#4F7CFF", "desktop": "#E9EEF7", "surface": "#FFFFFF", "text": "#18202C", "muted_text": "#526074", "border": "#CBD5E1", "danger": "#B42318", "radius_px": 12, "blur_px": 16, "panel_opacity": 0.92, "font": "system"}, "reduce_motion": False, "reduce_transparency": False}


def contribution(identifier="main", kind="window"):
    spec = {"id": identifier, "kind": kind, "title": "Independent fixture", "description": "Bridge component fixture", "entry_path": "/index.html", "refresh_interval_seconds": 0,
            "skill_bindings": [{"alias": "echo", "name": "org.xelab.fixture.echo", "version": "1.0.0", "modes": ["call", "batch"]}]}
    if kind == "window":
        spec["window"] = {"width": 640, "height": 400, "min_width": 320, "min_height": 200, "max_width": 1024, "max_height": 800, "resizable": True}
    else:
        spec["widget"] = {"columns": 3, "rows": 2, "min_columns": 1, "min_rows": 1, "max_columns": 8, "max_rows": 8}
    spec_digest = "sha256:" + hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"deployment_id": DEPLOYMENT, "installation_id": INSTALLATION, "plugin_id": "org.xelab.fixture", "manifest_digest": "sha256:" + "b" * 64, "contribution_digest": spec_digest,
            "spec": spec, "frame_url": PLUGIN + "/ui/org.xelab.fixture/index.html", "frame_origin": PLUGIN, "availability": "ready", "reason_codes": [],
            "bindings": [{"alias": "echo", "skill_id": SKILL, "definition_digest": DIGEST, "modes": ["call", "batch"]}]}


def framing_query(identifier, client_id="bridge-component"):
    # Structural fixture only: real HMAC validation belongs to Core tests.
    selector = {"client_id": client_id, "contribution_id": identifier, "origin_index": 0}
    encoded = base64.urlsafe_b64encode(json.dumps(selector, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).rstrip(b"=").decode()
    return "?xelab_frame=v1." + encoded + "." + "A" * 43


FRAME = """<!doctype html><meta charset=utf-8><p>Independent test plugin</p><script>
const metadata=Object.fromEntries(new URLSearchParams(location.hash.slice(1)));
window.messages=[];window.sequence=0;window.responses=()=>messages.filter(m=>m.type==='response');
addEventListener('message',e=>{if(e.source!==parent||e.origin!==metadata.parent_origin)return;messages.push(e.data);if(e.data.event==='visibility.changed')document.documentElement.dataset.visible=String(e.data.params.visible);});
window.emit=(method,params,id,overrides={})=>parent.postMessage({protocol:metadata.protocol,view_id:metadata.view_id,channel_nonce:metadata.channel_nonce,seq:++sequence,type:'request',request_id:id,method,params,...overrides},metadata.parent_origin);
window.meta=metadata;
window.domBlocked=false;try{parent.document.body}catch{domBlocked=true}
window.storageBlocked=false;try{parent.sessionStorage.length}catch{storageBlocked=true}
parent.postMessage({protocol:metadata.protocol,view_id:metadata.view_id,channel_nonce:metadata.channel_nonce,seq:++sequence,type:'ready'},metadata.parent_origin);
</script>"""


class IsolatedBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(executable_path=os.environ.get("XELAB_OAUTH_BROWSER_CHROMIUM", "/usr/bin/chromium"), headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.context = self.browser.new_context()
        self.page = self.context.new_page()
        self.current = contribution()
        self.calls, self.pending, self.errors = [], [], []
        self.result_record = None
        self.deny_result = False
        self.hold = False
        self.denied = False
        self.reference_assets = False
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))
        self.page.route("**/*", self.route)

    def tearDown(self):
        self.assertEqual(self.errors, [])
        self.context.close()

    def route(self, route):
        request, url = route.request, urlparse(route.request.url)
        origin = f"{url.scheme}://{url.netloc}"
        if origin == SHELL:
            if url.path.endswith(".js"):
                file = PUBLIC / pathlib.Path(url.path).name
                route.fulfill(content_type="text/javascript", body=file.read_bytes())
            else:
                route.fulfill(content_type="text/html", body=f"""<!doctype html><div id=frames></div><script type=module>
import {{BridgeHost}} from '/bridge.js';import {{ApiClient}} from '/api.js';
window.currentSubject={json.dumps(SUBJECT)};window.states=[];window.opened=[];
const api=new ApiClient({{core_origin:{json.dumps(CORE)},client_id:'bridge-component'}},{{accessToken:async()=> 'component-token'}});
window.launch=async(contribution)=>{{let frame=document.createElement('iframe');frame.width=640;frame.height=400;document.querySelector('#frames').append(frame);
window.bridge=new BridgeHost({{iframe:frame,api,contribution,subjectId:{json.dumps(SUBJECT)},isCurrent:subject=>subject===currentSubject,coreOrigin:{json.dumps(CORE)},theme:()=>({json.dumps(THEME)}),onState:(state,reason)=>states.push([state,reason]),openWindow:async value=>{{opened.push(value);return crypto.randomUUID();}}}});await bridge.mount();return bridge.viewId;}};
</script>""")
            return
        if origin in (PLUGIN, ATTACKER):
            if origin == PLUGIN and self.reference_assets:
                file = pathlib.Path(url.path).name
                if file not in {"window.html", "app.js", "bridge.js", "styles.css"}:
                    route.fulfill(status=404, body="not found")
                    return
                types = {".html": "text/html", ".js": "text/javascript", ".css": "text/css"}
                route.fulfill(content_type=types[pathlib.Path(file).suffix], headers={"content-security-policy": f"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; frame-ancestors {SHELL}"}, body=(REFERENCE_PUBLIC / file).read_bytes())
                return
            route.fulfill(content_type="text/html", headers={"content-security-policy": f"default-src 'none'; script-src 'unsafe-inline'; connect-src 'none'; frame-ancestors {SHELL}"}, body=FRAME if origin == PLUGIN else "<!doctype html><p>Wrong-origin frame</p>")
            return
        if origin != CORE:
            route.abort()
            return
        headers = {"access-control-allow-origin": SHELL, "access-control-allow-headers": "authorization,content-type,idempotency-key,if-match", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-expose-headers": "etag,x-request-id", "x-request-id": SUBJECT}
        if request.method == "OPTIONS":
            route.fulfill(status=204, headers=headers)
            return
        self.calls.append({"method": request.method, "path": url.path, "body": request.post_data, "headers": request.all_headers()})
        if self.denied:
            route.fulfill(status=403, headers=headers, content_type="application/json", body=json.dumps({"error": {"code": "PERMISSION_DENIED", "message": "fixture authorization revoked", "retryable": False, "violations": [], "retry_after_ms": None, "resource_id": None}}))
        elif "/ui/contributions/" in url.path:
            data = copy.deepcopy(self.current)
            if url.path.endswith("/detail"):
                data["spec"]["id"] = "detail"
            route.fulfill(headers=headers, content_type="application/json", body=json.dumps(data))
        elif url.path == f"/api/platform/v1/skills/{SKILL}/calls" and request.method == "POST":
            if self.hold:
                self.pending.append((route, headers, json.loads(request.post_data)))
            else:
                self.result(route, headers, json.loads(request.post_data))
        elif url.path == f"/api/platform/v1/calls/{INSTALLATION}" and request.method == "GET":
            if self.deny_result:
                route.fulfill(status=403, headers=headers, content_type="application/json", body=json.dumps({"error": {"code": "PERMISSION_DENIED", "message": "original proof revoked", "retryable": False, "violations": [], "retry_after_ms": None, "resource_id": None}}))
            else:
                route.fulfill(headers=headers, content_type="application/json", body=json.dumps({"call_id": INSTALLATION, "state": "succeeded", "result": self.result_record, "error": None}))
        else:
            route.fulfill(status=404, headers=headers, content_type="application/json", body='{"error":{"code":"RESOURCE_NOT_FOUND"}}')

    def result(self, route, headers, body):
        self.result_record = {"call_id": INSTALLATION, "skill_id": SKILL, "skill_definition_digest": DIGEST, "output": body["input"]}
        route.fulfill(headers=headers, content_type="application/json", body=json.dumps({"skill_id": SKILL, "skill_version": "1.0.0", "definition_digest": DIGEST, "call": self.result_record}))

    def launch(self):
        self.page.goto(SHELL + "/")
        self.page.wait_for_function("typeof launch === 'function'")
        with self.page.expect_event("framenavigated", predicate=lambda frame: frame.url.startswith(PLUGIN)) as navigated:
            self.page.evaluate("value=>launch(value)", self.current)
        self.page.wait_for_function("states.some(item=>item[0]==='active')")
        frame = navigated.value
        frame.wait_for_function("()=>messages.some(message=>message.type==='host.init')")
        return frame

    def send(self, frame, method="skill.call", params=None, identifier=1, overrides=None):
        params = params if params is not None else {"binding_alias": "echo", "input": {"message": "iframe"}, "idempotency_key": "stable-intent"}
        frame.evaluate("args=>emit(args.method,args.params,args.id,args.overrides)", {"method": method, "params": params, "id": identifier, "overrides": overrides or {}})

    def responses(self, frame, count):
        frame.wait_for_function("count=>responses().length>=count", arg=count)
        return frame.evaluate("responses()")

    def posts(self):
        return [call for call in self.calls if call["method"] == "POST"]

    def test_fixed_framing_query_keeps_real_cross_origin_handshake_and_skill_call(self):
        query = framing_query(self.current["spec"]["id"])
        self.current["frame_url"] += query
        frame = self.launch()
        self.assertEqual(urlparse(frame.url).query, query.removeprefix("?"))
        self.assertEqual(frame.evaluate("meta.parent_origin"), SHELL)
        self.assertEqual(len(frame.evaluate("meta.channel_nonce")), 64)
        self.send(frame)
        self.assertTrue(self.responses(frame, 1)[0]["ok"])
        self.assertEqual(len(self.posts()), 1)

    def test_framing_query_rejects_ambiguous_encoding_unknown_fields_and_wrong_contribution(self):
        self.page.goto(SHELL + "/")
        self.page.wait_for_function("typeof launch === 'function'")
        selector = {"client_id": "bridge-component", "contribution_id": "main", "origin_index": 0}
        def encoded(raw):
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        def query(value=None, raw=None, mac="A" * 43):
            raw = raw if raw is not None else json.dumps(selector if value is None else value, sort_keys=True, separators=(",", ":")).encode()
            return "?xelab_frame=v1." + encoded(raw) + "." + mac
        valid = query()
        unicode_value = copy.deepcopy(self.current)
        unicode_value["frame_url"] += framing_query("main", "界" * 128)
        self.assertTrue(self.page.evaluate("""async value => {
          const {validateContribution}=await import('/bridge.js');
          return validateContribution(value,{parentOrigin:location.origin,coreOrigin:'https://core.example.test'}).spec.id==='main';
        }""", unicode_value))
        cases = {
            "unknown_query": "?url=arbitrary",
            "empty_query": "?",
            "duplicate_query": valid + "&xelab_frame=again",
            "extra_query": valid + "&other=1",
            "wrong_contribution": query({**selector, "contribution_id": "detail"}),
            "unknown_selector_field": query({**selector, "subject_id": SUBJECT}),
            "duplicate_selector_field": query(raw=b'{"client_id":"bridge-component","client_id":"bridge-component","contribution_id":"main","origin_index":0}'),
            "noncanonical_order": query(raw=b'{"origin_index":0,"contribution_id":"main","client_id":"bridge-component"}'),
            "noncanonical_whitespace": query(raw=json.dumps(selector, sort_keys=True).encode()),
            "invalid_utf8": query(raw=b"\xff"),
            "byte_order_mark": query(raw=b"\xef\xbb\xbf" + json.dumps(selector, sort_keys=True, separators=(",", ":")).encode()),
            "origin_string": query({**selector, "origin_index": "0"}),
            "origin_out_of_range": query({**selector, "origin_index": 8}),
            "noncanonical_number": query(raw=b'{"client_id":"bridge-component","contribution_id":"main","origin_index":0.0}'),
            "empty_client": query({**selector, "client_id": ""}),
            "oversize_client": query({**selector, "client_id": "x" * 129}),
            "client_control": query({**selector, "client_id": "client\nname"}),
            "client_unicode_control": query({**selector, "client_id": "client\u0085name"}),
            "wrong_version": valid.replace("=v1.", "=v2."),
            "selector_padding": valid.replace(".AAA", "=.AAA"),
            "percent_encoding": valid.replace("v1", "%761"),
            "plus_encoding": valid + "+",
            "short_mac": query(mac="A" * 42),
            "noncanonical_mac_bits": query(mac="A" * 42 + "B"),
            "oversize_selector": "?xelab_frame=v1." + "A" * 769 + "." + "A" * 43,
            "fragment": valid + "#unexpected",
        }
        for label, suffix in cases.items():
            with self.subTest(case=label):
                invalid = copy.deepcopy(self.current)
                invalid["frame_url"] += suffix
                code = self.page.evaluate("""async value => {
                  const {validateContribution}=await import('/bridge.js');
                  try {validateContribution(value,{parentOrigin:location.origin,coreOrigin:'https://core.example.test'});return 'accepted';}
                  catch(error){return error.bridge?.code??'unexpected_error';}
                }""", invalid)
                self.assertEqual(code, "PERMISSION_DENIED")
        self.assertEqual(self.page.locator("iframe").count(), 0)
        self.assertEqual(self.calls, [])

    def test_handshake_budget_begins_after_real_reference_document_load(self):
        self.reference_assets = True
        self.current["frame_url"] = PLUGIN + "/ui/org.xelab.fixture/window.html"
        self.current["spec"]["entry_path"] = "/window.html"
        self.current["spec"]["skill_bindings"][0]["modes"] = ["call"]
        self.current["bindings"][0]["modes"] = ["call"]
        pending_documents, pending_metadata = [], []
        gate = {"metadata": False}
        self.page.route(self.current["frame_url"], lambda route: pending_documents.append(route))
        def metadata(route):
            if gate["metadata"] and route.request.method != "OPTIONS":
                pending_metadata.append(route)
            else:
                self.route(route)
        self.page.route(CORE + "/api/platform/v1/ui/contributions/**", metadata)
        self.page.goto(SHELL + "/")
        self.page.wait_for_function("() => typeof launch === 'function'")
        self.page.evaluate("value => {window.mounting=launch(value).catch(error=>{window.mountingError=error.code;});}", self.current)
        deadline = time.monotonic() + 5
        while not pending_documents and time.monotonic() < deadline:
            self.page.wait_for_timeout(10)
        self.assertEqual(len(pending_documents), 1)
        # Deliberately hold a real browser document request for nine wall-clock
        # seconds, then require two more seconds of current Core proof.
        self.page.wait_for_timeout(9000)
        gate["metadata"] = True
        with self.page.expect_event("framenavigated", predicate=lambda frame: frame.url.startswith(PLUGIN)) as navigation:
            self.route(pending_documents[0])
        frame = navigation.value
        frame.wait_for_load_state("load")
        loaded = time.monotonic()
        frame.locator("#call").wait_for(state="visible")
        self.page.wait_for_timeout(2000)
        self.assertEqual(self.page.locator("#frames iframe").count(), 1, "The ten-second handshake budget starts after the target document loads")
        self.assertTrue(frame.locator("#call").is_disabled(), "Current authorization must still complete before host.init")
        self.assertGreater(len(pending_metadata), 0)
        gate["metadata"] = False
        for route in pending_metadata:
            self.route(route)
        frame.wait_for_function("() => document.querySelector('#call')?.disabled === false")
        self.page.wait_for_function("() => states.some(item=>item[0]==='active')")
        self.assertEqual(self.posts(), [])
        print({"component": "BridgeHost_real_reference_fixture_not_Core", "load_to_verified_active_ms": round((time.monotonic()-loaded)*1000)})

    def test_close_during_verification_does_not_resurrect_channel(self):
        pending = []
        def metadata(route):
            if route.request.method == "OPTIONS":
                self.route(route)
            else:
                pending.append(route)
        self.page.route(CORE + "/api/platform/v1/ui/contributions/**", metadata)
        self.page.goto(SHELL + "/")
        self.page.wait_for_function("() => typeof launch === 'function'")
        self.page.evaluate("value => {window.mounting=launch(value).catch(error=>{window.mountingError=error.code;});}", self.current)
        deadline = time.monotonic() + 5
        while not pending and time.monotonic() < deadline:
            self.page.wait_for_timeout(10)
        self.assertEqual(len(pending), 1)
        self.page.evaluate("() => bridge.close('close')")
        # Complete the intercepted server handler even though its client was
        # canceled, and prove a late valid proof cannot revive the closed view.
        for route in pending:
            route.fulfill(headers={"access-control-allow-origin": SHELL}, content_type="application/json", body=json.dumps(self.current))
        self.page.wait_for_function("() => window.mountingError !== undefined")
        self.assertEqual(self.page.locator("#frames iframe").count(), 0)
        self.assertFalse(self.page.evaluate("states.some(item=>item[0]==='active')"))
        self.assertEqual(self.posts(), [])

    def test_widget_visibility_is_not_implicit_refresh_without_shell_read_proof(self):
        self.current = contribution("summary", "widget")
        frame = self.launch()
        self.page.evaluate("bridge.setVisible(false); bridge.setVisible(true)")
        frame.locator('html[data-visible="true"]').wait_for(state="attached")
        self.assertEqual(frame.evaluate("messages.filter(message=>message.event==='widget.refresh').length"), 0)
        self.page.evaluate("bridge.refresh()")
        frame.wait_for_function("()=>messages.some(message=>message.event==='widget.refresh')")
        self.assertEqual(len(self.posts()), 0)

    def test_fixed_call_handshake_dom_isolation_and_stable_derived_key(self):
        frame = self.launch()
        self.assertTrue(frame.evaluate("domBlocked && storageBlocked"))
        init = frame.evaluate("messages.find(message=>message.type==='host.init')")
        self.assertEqual(init["seq"], 1)
        self.assertEqual(len(init["channel_nonce"]), 64)
        self.assertNotIn("component-token", json.dumps(init))
        self.assertEqual(init["params"]["bindings"][0]["skill_id"], SKILL)
        self.send(frame)
        response = self.responses(frame, 1)[0]
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["call"]["output"], {"message": "iframe"})
        post = self.posts()[0]
        expected = "ui-" + hashlib.sha256(json.dumps({"subject_id": SUBJECT, "installation_id": INSTALLATION, "deployment_id": DEPLOYMENT, "contribution_id": self.current["spec"]["id"], "contribution_digest": self.current["contribution_digest"], "method": "skill.call", "idempotency_key": "stable-intent"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(post["headers"]["idempotency-key"], expected)
        self.assertEqual(json.loads(post["body"])["idempotency_key"], expected)
        self.assertEqual(json.loads(post["body"])["provider_deployment_id"], DEPLOYMENT)
        self.assertEqual(post["path"], f"/api/platform/v1/skills/{SKILL}/calls")
        self.assertNotIn("cookie", post["headers"])
        self.assertTrue(frame.evaluate("""async origin=>{try{await fetch(origin+'/api/platform/v1/node');return false}catch{return true}}""", CORE))
        old_view = frame.evaluate("meta.view_id")
        self.page.evaluate("bridge.close('close')")
        frame = self.launch()
        self.assertNotEqual(frame.evaluate("meta.view_id"), old_view)
        self.send(frame)
        self.responses(frame, 1)
        self.assertEqual(self.posts()[-1]["headers"]["idempotency-key"], expected)
        self.current["deployment_id"] = "00000000-0000-4000-8000-000000000099"
        frame = self.launch()
        self.send(frame)
        self.responses(frame, 1)
        self.assertNotEqual(self.posts()[-1]["headers"]["idempotency-key"], expected)
        self.assertEqual(json.loads(self.posts()[-1]["body"])["provider_deployment_id"], self.current["deployment_id"])

    def test_alias_extra_fields_future_methods_and_same_deployment_window(self):
        frame = self.launch()
        self.send(frame, params={"binding_alias": "other", "input": {}, "idempotency_key": "x"})
        self.assertEqual(self.responses(frame, 1)[0]["error"]["code"], "BINDING_UNAVAILABLE")
        self.send(frame, params={"binding_alias": "echo", "input": {}, "idempotency_key": "x", "skill_id": SKILL}, identifier=2)
        self.assertEqual(self.responses(frame, 2)[1]["error"]["code"], "PROTOCOL_ERROR")
        self.send(frame, params={"binding_alias": "echo", "input": {}, "idempotency_key": "x", "provider_deployment_id": "00000000-0000-4000-8000-000000000099"}, identifier=3)
        self.assertEqual(self.responses(frame, 3)[2]["error"]["code"], "PROTOCOL_ERROR")
        self.send(frame, "batch.create", {"binding_alias": "echo", "request": {"run_as": "user"}, "idempotency_key": "x"}, 4)
        self.assertEqual(self.responses(frame, 4)[3]["error"]["code"], "METHOD_NOT_ALLOWED")
        self.send(frame, "window.open", {"contribution_id": "detail"}, 5)
        opened = self.responses(frame, 5)[4]
        self.assertTrue(opened["ok"])
        self.assertEqual(self.page.evaluate("opened[0].deployment_id"), DEPLOYMENT)
        self.send(frame, "window.open", {"contribution_id": "detail", "url": CORE + "/auth/ui/login"}, 6)
        self.assertEqual(self.responses(frame, 6)[5]["error"]["code"], "PROTOCOL_ERROR")
        self.assertEqual(self.posts(), [])

    def test_pending_dedup_conflict_sequence_source_and_four_call_cap(self):
        frame = self.launch()
        self.hold = True
        self.send(frame)
        self.page.wait_for_function("true")
        self.page.wait_for_timeout(100)
        self.send(frame)
        for identifier in (2, 3, 4):
            self.send(frame, identifier=identifier)
            self.page.wait_for_timeout(50)
        self.send(frame, identifier=5)
        result = self.responses(frame, 1)[0]
        self.assertEqual(result["error"]["code"], "RATE_LIMITED")
        self.assertEqual(len(self.pending), 4)
        for route, headers, body in self.pending:
            self.result(route, headers, body)
        self.pending.clear()
        self.responses(frame, 5)
        self.assertEqual(len(self.posts()), 4)
        self.send(frame, identifier=1)
        self.responses(frame, 6)
        self.assertEqual(len(self.posts()), 4)
        self.send(frame, params={"binding_alias": "echo", "input": {"changed": True}, "idempotency_key": "stable-intent"}, identifier=1)
        self.assertEqual(self.responses(frame, 7)[-1]["error"]["code"], "IDEMPOTENCY_CONFLICT")
        old_sequence = frame.evaluate("sequence")
        self.send(frame, identifier=6, overrides={"seq": old_sequence})
        self.send(frame, identifier=6, overrides={"channel_nonce": "0" * 64})
        metadata = frame.evaluate("meta")
        self.page.evaluate("""origin=>{const frame=document.createElement('iframe');frame.id='attacker';frame.src=origin;document.body.append(frame)}""", ATTACKER)
        attacker = self.page.frame_locator("#attacker")
        attacker.locator("p").wait_for()
        wrong = next(candidate for candidate in self.page.frames if candidate.url.startswith(ATTACKER))
        wrong.evaluate("metadata=>parent.postMessage({protocol:metadata.protocol,view_id:metadata.view_id,channel_nonce:metadata.channel_nonce,seq:999,type:'request',request_id:7,method:'skill.call',params:{binding_alias:'echo',input:{},idempotency_key:'x'}},metadata.parent_origin)", metadata)
        self.page.wait_for_timeout(150)
        self.assertEqual(len(frame.evaluate("responses()")), 7)
        self.assertEqual(len(self.posts()), 4)
        self.assertFalse(self.page.evaluate("states.some(item=>item[0]==='closed')"))
        self.hold = False
        self.send(frame, identifier=6)
        self.assertTrue(self.responses(frame, 8)[-1]["ok"])

    def test_revocation_upgrade_reload_and_logout_destroy_channels(self):
        frame = self.launch()
        self.denied = True
        self.send(frame)
        self.page.wait_for_function("states.some(item=>item[0]==='closed')")
        self.assertEqual(self.page.locator("#frames iframe").count(), 0)
        self.assertEqual(self.posts(), [])

        self.denied = False
        frame = self.launch()
        self.current["manifest_digest"] = "sha256:" + "d" * 64
        self.send(frame)
        self.page.wait_for_function("states.some(item=>item[0]==='closed'&&item[1]==='upgrade')")
        self.assertEqual(self.posts(), [])
        frame = self.launch()
        frame.evaluate("location.reload()")
        self.page.wait_for_function("states.some(item=>item[0]==='closed')")
        self.assertEqual(self.page.locator("#frames iframe").count(), 0)
        frame = self.launch()
        self.page.evaluate("currentSubject='00000000-0000-4000-8000-000000000099'")
        self.send(frame)
        self.page.wait_for_function("states.some(item=>item[0]==='closed')")
        self.assertEqual(self.page.locator("#frames iframe").count(), 0)
        self.assertEqual(self.posts(), [])

    def test_cached_result_requires_original_call_read_proof_without_reinvoke(self):
        frame = self.launch()
        self.send(frame)
        self.assertTrue(self.responses(frame, 1)[0]["ok"])
        self.assertEqual(len(self.posts()), 1)
        self.deny_result = True
        self.send(frame)
        self.page.wait_for_function("states.some(item=>item[0]==='closed')")
        self.assertEqual(len(self.posts()), 1, "a denied cached result never becomes a repeated business POST")
        self.assertEqual(self.page.locator("#frames iframe").count(), 0)

    def test_bridge_call_outlives_a_post_past_the_business_deadline(self):
        frame = self.launch()
        self.hold = True
        self.send(frame, params={"binding_alias": "echo", "input": {"message": "late kernel pipeline"}, "idempotency_key": "stable-intent", "timeout_ms": 10000})
        deadline = time.monotonic() + 5
        while not self.pending and time.monotonic() < deadline:
            self.page.wait_for_timeout(10)
        self.assertTrue(self.pending, "expected a held bridge Skill Call POST")
        route, headers, body = self.pending[0]
        self.assertEqual(body["timeout_ms"], 10000)
        # The kernel call pipeline legitimately answers inside one HTTP request
        # past the business deadline (#82); the shell must not abort the
        # forwarded call at body.timeout_ms while the frame waits for a result.
        self.page.wait_for_timeout(11000)
        self.assertEqual(frame.evaluate("responses().length"), 0)
        self.hold = False
        self.result(route, headers, body)
        response = self.responses(frame, 1)[0]
        self.assertTrue(response["ok"], "a POST past the business deadline still delivers the result")
        self.assertEqual(response["result"]["call"]["output"], {"message": "late kernel pipeline"})

    def test_per_view_rate_limit_rejects_the_121st_request(self):
        frame = self.launch()
        for identifier in range(1, 121):
            self.send(frame, "batch.get", {"binding_alias": "echo", "batch_id": INSTALLATION}, identifier)
            self.assertEqual(self.responses(frame, identifier)[-1]["error"]["code"], "METHOD_NOT_ALLOWED")
        self.send(frame, "batch.get", {"binding_alias": "echo", "batch_id": INSTALLATION}, 121)
        self.assertEqual(self.responses(frame, 121)[-1]["error"]["code"], "RATE_LIMITED")
        frame.evaluate("""()=>{let value={leaf:'x'};for(let i=0;i<30;i++)value={a:value,b:value};emit('skill.call',{binding_alias:'echo',input:value,idempotency_key:'rate-bound-dag'},122)}""")
        self.assertEqual(self.responses(frame, 122)[-1]["error"]["code"], "RATE_LIMITED")
        self.assertEqual(self.page.locator("#frames iframe").count(), 1, "rate denial precedes shared-tree expansion and leaves the valid channel intact")
        self.assertEqual(self.posts(), [])

    def test_shared_reference_expansion_and_large_messages_are_bounded(self):
        frame = self.launch()
        frame.evaluate("""()=>{let value={leaf:'x'};for(let i=0;i<30;i++)value={a:value,b:value};emit('skill.call',{binding_alias:'echo',input:value,idempotency_key:'dag'},1)}""")
        self.page.wait_for_function("states.some(item=>item[0]==='closed')", timeout=5000)
        self.assertEqual(self.page.evaluate("21*2"), 42)
        self.assertEqual(self.posts(), [])
        frame = self.launch()
        self.send(frame, params={"binding_alias": "echo", "input": "x" * 1048576, "idempotency_key": "large"})
        self.page.wait_for_function("states.some(item=>item[0]==='closed')", timeout=5000)
        self.assertEqual(self.posts(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
