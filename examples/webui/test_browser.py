#!/usr/bin/env python3
"""Real Chromium component tests; API fixtures are not core/OCI acceptance."""
import json
import os
import base64
import hashlib
import importlib.util
import pathlib
import time
import unittest
from urllib.parse import parse_qs, urlencode, urlparse

from playwright.sync_api import sync_playwright, TimeoutError as BrowserTimeoutError
from test_bridge import contribution, FRAME, PLUGIN

PUBLIC = pathlib.Path(__file__).parent / "public"
REFERENCE_PUBLIC = pathlib.Path(__file__).resolve().parents[1] / "ui-reference" / "public"
SHELL = "https://shell.example.test"
CORE = "https://core.example.test"
BASE = "/ui/org.xelab.webui/"
ACCOUNT = "00000000-0000-4000-8000-000000000001"
SKILL = "00000000-0000-4000-8000-000000000002"
DEPLOYMENT = "00000000-0000-4000-8000-000000000003"
NOW = "2026-11-04T00:00:00Z"
DRIVER_SPEC = importlib.util.spec_from_file_location("m3_ui_browser", pathlib.Path(__file__).resolve().parents[2] / "tools/m3-ui-browser.py")
DRIVER = importlib.util.module_from_spec(DRIVER_SPEC)
DRIVER_SPEC.loader.exec_module(DRIVER)


def preferences():
    return {"id": ACCOUNT, "owner_id": ACCOUNT, "revision": 1,
            "created_at": NOW, "updated_at": NOW,
            "spec": {"theme": {"mode": "system", "reduce_motion": False, "reduce_transparency": False},
                     "dock": {"position": "bottom", "auto_hide": False, "pinned": []},
                     "widgets": [], "restore_windows": True}}


class DesktopBrowser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(
            executable_path=os.environ.get("XELAB_OAUTH_BROWSER_CHROMIUM", "/usr/bin/chromium"), headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"])

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.context = self.browser.new_context(viewport={"width": 1280, "height": 900})
        self.page = self.context.new_page()
        self.calls = []
        self.saved = preferences()
        self.denied = set()
        self.contributions = {}
        self.call_result = None
        self.status_overrides = {}
        self.refresh_enabled = False
        self.hold_refresh = False
        self.pending_refresh = []
        self.abort_business = False
        self.errors = []
        self.expected_challenge = None
        self.hold_preferences = False
        self.pending_preferences = []
        self.hold_call = False
        self.pending_calls = []
        self.hold_mount_verify = False
        self.pending_mount_verify = []
        self.real_reference = False
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))
        self.page.route("**/*", self.route)

    def tearDown(self):
        self.assertEqual(self.errors, [], "browser JavaScript errors")
        self.context.close()

    def route(self, route):
        request = route.request
        url = urlparse(request.url)
        if f"{url.scheme}://{url.netloc}" == SHELL:
            file = url.path.removeprefix(BASE)
            if file in ("", "callback"):
                file = "index.html"
            if file == "runtime-config.js":
                route.fulfill(status=200, content_type="text/javascript", body="export const runtimeConfig=" + json.dumps({"core_origin": CORE, "client_id": "browser-component", "max_open_windows": 16}) + ";")
                return
            if file not in {"index.html", "app.js", "styles.css", "desktop.css", "components.css", "motion.css", "api.js", "oauth.js", "bridge.js", "wallpaper.svg"}:
                route.fulfill(status=404, body="not found")
                return
            types = {".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml"}
            route.fulfill(status=200, content_type=types[pathlib.Path(file).suffix], body=(PUBLIC / file).read_bytes())
            return
        if f"{url.scheme}://{url.netloc}" == PLUGIN:
            if self.real_reference:
                file = pathlib.Path(url.path).name
                if file not in {"window.html", "widget.html", "app.js", "bridge.js", "styles.css"}:
                    route.fulfill(status=404, body="not found")
                    return
                types = {".html": "text/html", ".css": "text/css", ".js": "text/javascript"}
                route.fulfill(content_type=types[pathlib.Path(file).suffix], headers={"content-security-policy": f"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; frame-ancestors {SHELL}"}, body=(REFERENCE_PUBLIC / file).read_bytes())
                return
            route.fulfill(status=200, content_type="text/html", headers={"content-security-policy": f"default-src 'none'; script-src 'unsafe-inline'; connect-src 'none'; frame-ancestors {SHELL}"}, body=FRAME)
            return
        if f"{url.scheme}://{url.netloc}" != CORE:
            route.abort()
            return
        headers = {"access-control-allow-origin": SHELL,
                   "access-control-allow-headers": "authorization,content-type,if-match,idempotency-key",
                   "access-control-allow-methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
                   "access-control-expose-headers": "etag,x-request-id",
                   "etag": '"rev-1"', "x-request-id": ACCOUNT}
        if request.method == "OPTIONS":
            route.fulfill(status=204, headers=headers)
            return
        if self.hold_preferences and request.method == "GET" and url.path.endswith("/me/ui-preferences"):
            self.pending_preferences.append(route)
            return
        if (self.hold_refresh and self.refresh_enabled and request.method == "POST" and url.path == "/oauth/token"
                and parse_qs(request.post_data or "", keep_blank_values=True) == {
                    "grant_type": ["refresh_token"], "client_id": ["browser-component"], "refresh_token": ["component-refresh"]}):
            self.pending_refresh.append(route)
            return
        if (self.hold_mount_verify and request.method == "GET" and url.path.endswith("/ui/contributions/" + self.contributions["main"]["deployment_id"] + "/main")
                and sum(call["path"] == url.path for call in self.calls) == 1):
            self.pending_mount_verify.append(route)
            return
        self.calls.append({"method": request.method, "path": url.path,
                           "headers": request.all_headers(), "body": request.post_data})
        hold = False
        status = 200
        if url.path == "/oauth/token":
            fields = parse_qs(request.post_data or "", keep_blank_values=True)
            if self.refresh_enabled and fields == {"grant_type": ["refresh_token"], "client_id": ["browser-component"], "refresh_token": ["component-refresh"]}:
                route.fulfill(status=200, headers=headers, content_type="application/json", body=json.dumps({"access_token": "component-rotated-access", "refresh_token": "component-rotated-refresh", "token_type": "Bearer", "expires_in": 900, "scope": "client:browser-component"}))
                return
            verifier = fields.get("code_verifier", [""])[0]
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            if (request.method != "POST" or set(fields) != {"grant_type", "client_id", "code", "redirect_uri", "code_verifier"}
                    or any(len(values) != 1 for values in fields.values())
                    or fields["grant_type"] != ["authorization_code"] or fields["client_id"] != ["browser-component"]
                    or fields["code"] != ["component-authorization-code"] or fields["redirect_uri"] != [SHELL + BASE + "callback"]
                    or not self.expected_challenge or challenge != self.expected_challenge):
                status, data = 400, {"error": "invalid_grant"}
            else:
                data = {"access_token": "component-exchanged-token", "token_type": "Bearer", "expires_in": 900,
                        "scope": "client:browser-component"}
        elif url.path in self.status_overrides:
            status, data = self.status_overrides[url.path], {"error": {"code": "INVALID_CREDENTIAL", "message": "fixture credential rejected", "retryable": False}}
        elif url.path in self.denied:
            status, data = 403, {"error": {"code": "PERMISSION_DENIED", "message": "fixture denied", "retryable": False}}
        elif url.path.endswith("/sessions"):
            data = {"items": [{"account_id": ACCOUNT, "status": "active"}], "next_cursor": None}
        elif url.path.endswith("/me/ui-preferences"):
            if request.method == "PUT":
                self.saved["spec"] = json.loads(request.post_data)
                self.saved["revision"] += 1
            headers["etag"] = f'"rev-{self.saved["revision"]}"'
            data = self.saved
        elif url.path == "/api/platform/v1/ui/contributions":
            data = {"items": list(self.contributions.values()), "next_cursor": None}
        elif "/ui/contributions/" in url.path and url.path.split("/")[-1] in self.contributions:
            data = self.contributions[url.path.split("/")[-1]]
        elif url.path.endswith("/skills"):
            data = {"items": [{"id": SKILL, "revision": 1, "enabled": True,
                              "definition_digest": "sha256:" + "a" * 64,
                              "availability": "ready", "reason_codes": [],
                              "definition": {"name": "component.echo", "version": "1.0.0"}}], "next_cursor": None}
        elif url.path.endswith(f"/skills/{SKILL}/calls"):
            if self.abort_business:
                route.abort("failed")
                return
            data = {"skill_id": SKILL, "skill_version": "1.0.0", "definition_digest": "sha256:" + "a" * 64,
                    "call": {"call_id": DEPLOYMENT, "contract": {"name": "component.echo", "version": "1.0.0",
                             "schema_digest": "sha256:" + "b" * 64}, "provider_instance_id": ACCOUNT,
                             "output": json.loads(request.post_data)["input"], "completed_at": NOW,
                             "skill_id": SKILL, "skill_definition_digest": "sha256:" + "a" * 64}}
            self.call_result = data["call"]
            hold = self.hold_call
        elif url.path == f"/api/platform/v1/calls/{DEPLOYMENT}":
            data = {"call_id": DEPLOYMENT, "state": "succeeded", "result": self.call_result, "error": None}
        elif url.path.endswith("/deployments"):
            data = {"items": [{"id": DEPLOYMENT, "revision": 1, "phase": "disabled", "conditions": [],
                              "spec": {"display_name": "fixture deployment", "enabled": False}}], "next_cursor": None}
        elif url.path == f"/api/platform/v1/deployments/{DEPLOYMENT}" and request.method == "PUT":
            body = json.loads(request.post_data)
            if set(body) != {"spec"}:
                status, data = 400, {"error": {"code": "INVALID_ARGUMENT", "message": "DeploymentPatch requires spec", "retryable": False}}
            else:
                status, data = 202, {"id": ACCOUNT, "state": "pending", "kind": "update_deployment"}
        elif url.path.endswith("/installations"):
            data = {"items": [{"id": ACCOUNT, "plugin_id": '<img src=x onerror="alert(1)">',
                              "version": "1.0.0", "state": "installed", "image_digest": "sha256:" + "b" * 64}], "next_cursor": None}
        elif url.path.endswith("/node"):
            data = {"fixture": "component-only", "state": "ready"}
        else:
            status, data = 503, {"error": {"code": "NOT_READY", "message": "component fixture has no implementation", "retryable": False}}
        if hold:
            self.pending_calls.append((route, headers, data))
            return
        route.fulfill(status=status, headers=headers, content_type="application/json", body=json.dumps(data))

    def open(self, authenticated=True, expires_ms=900000, refresh_token=None):
        if authenticated:
            self.context.add_init_script("""if (location.origin === 'https://shell.example.test') {
              sessionStorage.setItem('xelab.oauth:https://core.example.test:browser-component', JSON.stringify({
                core_origin:'https://core.example.test',client_id:'browser-component',
                access_token:'component-token',refresh_token:REFRESH_VALUE,expires_at:Date.now()+EXPIRY_VALUE,
                scope:'client:browser-component'}));
            }""".replace("REFRESH_VALUE", json.dumps(refresh_token)).replace("EXPIRY_VALUE", str(expires_ms)))
        self.page.goto(SHELL + BASE)
        self.page.locator(".dock button").first.wait_for()
        if authenticated:
            self.page.get_by_role("button", name="退出", exact=True).wait_for()
            self.page.wait_for_function("document.querySelector('#connection').textContent === '已连接核心'")

    def app(self, name):
        self.page.get_by_role("button", name=f"打开{name}", exact=True).click()
        window = self.page.locator(".window").last
        window.wait_for()
        return window

    def skill_body_audit(self):
        # Core here is an explicit routed component adapter. The same observer
        # runs against actual Core/OCI only in the separate acceptance driver.
        report = {"checks": {}, "http": {"actual_skill_successes": 0, "unique_skill_call_ids": 0, "skill_post_attempts": 0}}
        observed = {"observer_failure": False, "error_counts": {}, "active_request_observers": 0, "active_response_observers": 0}
        bodies = DRIVER.SkillBodyAudit(CORE, SKILL, report, observed)
        self.context.on("request", lambda request: bodies.request(request, "component"))
        self.context.on("response", bodies.response)
        self.context.on("requestfinished", bodies.finished)
        self.context.on("requestfailed", bodies.failed)
        return report, observed, bodies

    def test_unexpired_access_without_refresh_can_load_desktop_and_skills(self):
        self.page.set_default_timeout(3000)
        self.open(expires_ms=20000, refresh_token=None)
        skills = self.app("Skill")
        skills.get_by_text("component.echo", exact=True).wait_for()
        self.assertTrue(any(call["method"] == "GET" and call["path"].endswith("/skills")
                            for call in self.calls))
        self.assertFalse(any(call["path"] == "/oauth/token" for call in self.calls))

    def test_skill_json_is_queued_until_outer_pump_reads_actual_response(self):
        report, observed, bodies = self.skill_body_audit()
        self.open()
        skills = self.app("Skill")
        skills.get_by_role("button", name="调用测试", exact=True).click()
        editor = self.page.locator('.window[data-app="editor-invokeSkill"]')
        bodies.expect(1)
        editor.get_by_role("button", name="提交", exact=True).click()
        editor.locator("pre.result").wait_for()
        self.page.evaluate("() => true")
        # The application has read its response, and callbacks are idle. Our
        # independent body audit must still be queued rather than assume success.
        self.assertEqual(observed["active_response_observers"], 0)
        self.assertEqual(report["http"]["actual_skill_successes"], 0)
        self.assertEqual(len(bodies.queue), 1)
        self.assertTrue(bodies.queue[0]["finished"])
        DRIVER.wait_for_observers(self.page, observed, bodies)
        self.assertEqual(report["http"]["actual_skill_successes"], 1)
        self.assertEqual(report["http"]["unique_skill_call_ids"], 1)
        self.assertEqual(bodies.calls, [DEPLOYMENT])
        self.assertEqual(bodies.queue, [])
        self.assertFalse(observed["observer_failure"], observed["error_counts"])

    def test_duplicate_actual_routed_skill_body_is_fatal_with_safe_reason(self):
        # This is the component Core adapter, deliberately returning the same
        # Call UUID for two distinct browser POSTs. It is not real Core evidence.
        report, observed, bodies = self.skill_body_audit()
        self.open()
        expression = """async ({core,skill,key}) => {
          const response=await fetch(core+'/api/platform/v1/skills/'+skill+'/calls',{
            method:'POST',headers:{Authorization:'Bearer component-token','Content-Type':'application/json','Idempotency-Key':key},
            body:JSON.stringify({input:{message:key},idempotency_key:key})});
          await response.json(); return response.status;
        }"""
        bodies.expect(1)
        self.assertEqual(self.page.evaluate(expression, {"core": CORE, "skill": SKILL, "key": "first-component-intent"}), 200)
        DRIVER.wait_for_observers(self.page, observed, bodies)
        bodies.expect(2)
        self.assertEqual(self.page.evaluate(expression, {"core": CORE, "skill": SKILL, "key": "different-component-intent"}), 200)
        with self.assertRaises(DRIVER.CheckFailed):
            DRIVER.wait_for_observers(self.page, observed, bodies)
        self.assertTrue(observed["observer_failure"])
        self.assertTrue(observed["response_skill_body_failed"])
        self.assertEqual(observed["skill_body_reasons"], {"Duplicate": 1})
        diagnostic = observed["skill_body_failure_stats"][0]
        self.assertEqual(diagnostic["duplicate_index"], 0)
        self.assertEqual(diagnostic["context_label"], "component")
        self.assertEqual(diagnostic["expected_successes"], 2)
        self.assertTrue(diagnostic["finished"])
        self.assertTrue(diagnostic["echo_matches_request"])
        self.assertEqual(report["http"], {"actual_skill_successes": 1, "unique_skill_call_ids": 1, "skill_post_attempts": 2})
        self.assertEqual(report["body_observation"]["failed_requests"], 0)
        self.assertTrue(report["body_observation"]["all_requests_finished"])
        safe = json.dumps({"report": report, "observed": observed})
        for private in (SKILL, DEPLOYMENT, CORE, "first-component-intent", "different-component-intent", "component-token"):
            self.assertNotIn(private, safe)

    def test_actual_aborted_skill_request_is_fatal_with_fixed_network_category(self):
        # A real Chromium request aborted by this explicit component adapter;
        # no fake Request/Response object replaces the network event lifecycle.
        report, observed, bodies = self.skill_body_audit()
        self.abort_business = True
        self.open()
        self.page.route(CORE + f"/api/platform/v1/skills/{SKILL}/calls", lambda route: route.abort("aborted") if route.request.method == "POST" else self.route(route))
        bodies.expect(1)
        rejected = self.page.evaluate("""async ({core,skill}) => {
          try {await fetch(core+'/api/platform/v1/skills/'+skill+'/calls',{
            method:'POST',headers:{Authorization:'Bearer component-token','Content-Type':'application/json','Idempotency-Key':'aborted-component-intent'},
            body:JSON.stringify({input:{message:'private component message'}})});return false;}catch{return true;}
        }""", {"core": CORE, "skill": SKILL})
        self.assertTrue(rejected)
        with self.assertRaises(DRIVER.CheckFailed):
            DRIVER.wait_for_observers(self.page, observed, bodies)
        self.assertEqual(observed["skill_body_reasons"], {"SelectedRequestFailed": 1})
        failure = observed["skill_body_failure_stats"][0]
        self.assertEqual(failure["failure_category"], "net::ERR_ABORTED")
        self.assertFalse(failure["finished"])
        self.assertFalse(failure["read"])
        self.assertFalse(failure["body_verified"])
        self.assertEqual(report["http"], {"actual_skill_successes": 0, "unique_skill_call_ids": 0, "skill_post_attempts": 1})
        body = report["body_observation"]
        self.assertEqual(body["failed_requests"], 1)
        self.assertEqual(body["unfinished_requests"], 0)
        self.assertFalse(body["all_requests_finished"])
        lifecycle = body["request_lifecycle"][0]
        self.assertEqual(lifecycle["start_ms"], 0)
        self.assertIsNone(lifecycle["response_ms"])
        self.assertIsNone(lifecycle["finished_ms"])
        self.assertIsInstance(lifecycle["failed_ms"], int)
        self.assertTrue(0 <= lifecycle["failed_ms"] <= 300000)
        self.assertEqual(DRIVER.selected_failure_category('private unknown error '+CORE), 'OTHER')
        encoded = json.dumps({"report": report, "observed": observed})
        for private in (CORE, SKILL, 'private component message', 'aborted-component-intent', 'component-token'):
            self.assertNotIn(private, encoded)

    def test_management_editor_closes_only_after_real_json_body_audit(self):
        report, observed, bodies = self.skill_body_audit()
        self.open()
        skills = self.app("Skill")
        skills.get_by_role("button", name="调用测试", exact=True).click()
        editor = self.page.locator('.window[data-app="editor-invokeSkill"]')
        editor.get_by_label("请求 JSON", exact=True).fill(json.dumps({"input": {"message": "Must audit before editor abort"}, "idempotency_key": "component-close-audit"}))
        bodies.expect(1)
        editor.get_by_role("button", name="提交", exact=True).click()
        editor.get_by_text('"message": "Must audit before editor abort"', exact=False).wait_for()
        self.assertEqual(report["http"]["actual_skill_successes"], 0)
        DRIVER.close_windows(self.page, report, observed, bodies)
        self.assertEqual(self.page.locator(".window").count(), 0)
        self.assertTrue(report["checks"]["all_windows_close"])
        self.assertEqual(report["http"], {"actual_skill_successes": 1, "unique_skill_call_ids": 1, "skill_post_attempts": 1})
        self.assertEqual(report["body_observation"]["queued_bodies"], 0)
        self.assertEqual(report["body_observation"]["unfinished_requests"], 0)
        self.assertFalse(observed["observer_failure"], observed["error_counts"])

    def test_bootstrap_dependency_failure_reports_only_safe_stage_and_state(self):
        # Real routed HTTP responses, with a deliberate module dependency503.
        # This Core adapter component does not diagnose the real OCI failure.
        report = {"checks": {}}
        bootstrap = DRIVER.LoginBootstrapAudit(CORE, SHELL, PLUGIN, report)
        self.context.on("request", lambda request: bootstrap.request(request, "owner"))
        self.context.on("response", lambda response: bootstrap.response(response, "owner"))
        self.context.on("requestfinished", lambda request: bootstrap.terminal(request, "owner", False))
        self.context.on("requestfailed", lambda request: bootstrap.terminal(request, "owner", True))
        self.page.route(SHELL + BASE + "runtime-config.js", lambda route: route.fulfill(status=503, content_type="text/javascript", body=""))
        bootstrap.stage("owner", "root_navigation")
        self.assertEqual(self.page.goto(SHELL + BASE, wait_until="domcontentloaded").status, 200)
        bootstrap.snapshot(self.page, "owner", "root")
        bootstrap.stage("owner", "welcome_login_click")
        self.page.locator("#welcome-login").click()
        bootstrap.stage("owner", "account_wait")
        with self.assertRaises(BrowserTimeoutError) as failed:
            self.page.locator("#account").wait_for(timeout=100)
        bootstrap.failure(self.page, "owner", failed.exception)
        self.assertEqual(report["step"], "owner_account_wait")
        diagnostic = report["bootstrap"]["owner"]
        self.assertEqual(diagnostic["error_type"], "TimeoutError")
        asset = diagnostic["assets"]["runtime-config.js"]
        self.assertEqual(asset["status_counts"], {"503": 1})
        self.assertEqual(asset["finished"] + asset["failed"], 1)
        for snapshot in diagnostic["snapshots"].values():
            self.assertEqual(snapshot["origin_class"], "ui")
            self.assertFalse(snapshot["dock_populated"])
            self.assertFalse(snapshot["clock_nonempty"])
            self.assertTrue(snapshot["welcome_login_exists"])
            self.assertTrue(snapshot["welcome_login_visible"])
            self.assertTrue(snapshot["welcome_login_enabled"])
            self.assertFalse(snapshot["account_exists"])
        encoded = json.dumps(report)
        for private in (CORE, SHELL, PLUGIN, ACCOUNT, "component-token", "Timeout 100ms"):
            self.assertNotIn(private, encoded)

    def test_trusted_login_pkce_and_no_password(self):
        self.open(False)
        self.assertEqual(self.page.locator('input[type="password"]').count(), 0)
        self.page.get_by_role("button", name="前往可信登录 →", exact=True).click()
        self.page.wait_for_url(CORE + "/oauth/authorize?*")
        params = parse_qs(urlparse(self.page.url).query)
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(params["redirect_uri"], [SHELL + BASE + "callback"])
        self.assertEqual(len(params["state"][0]), 43)
        self.assertNotIn("client_secret", params)

    def test_callback_exchanges_native_browser_fetch_with_exact_pkce(self):
        self.open(False)
        self.page.get_by_role("button", name="前往可信登录 →", exact=True).click()
        self.page.wait_for_url(CORE + "/oauth/authorize?*")
        params = parse_qs(urlparse(self.page.url).query)
        self.expected_challenge = params["code_challenge"][0]
        self.page.goto(SHELL + BASE + "callback?" + urlencode({
            "code": "component-authorization-code", "state": params["state"][0]}))
        self.page.wait_for_function("document.querySelector('#connection').textContent === '已连接核心'")
        self.assertEqual(self.page.url, SHELL + BASE)
        exchanged = [call for call in self.calls if call["path"] == "/oauth/token"]
        self.assertEqual(len(exchanged), 1)
        self.assertNotIn("authorization", exchanged[0]["headers"])
        self.assertNotIn("cookie", exchanged[0]["headers"])
        self.assertEqual(exchanged[0]["headers"]["origin"], SHELL)
        self.assertEqual(self.page.evaluate("Object.keys(sessionStorage).filter(key=>key.endsWith(':pending')).length"), 0)
        self.assertNotIn("component-authorization-code", self.page.locator("body").text_content())

    def test_callback_wrong_state_never_exchanges_or_reads_private_api(self):
        self.open(False)
        self.page.get_by_role("button", name="前往可信登录 →", exact=True).click()
        self.page.wait_for_url(CORE + "/oauth/authorize?*")
        self.page.goto(SHELL + BASE + "callback?code=component-authorization-code&state=wrong-state")
        self.page.get_by_text("登录未完成：INVALID_STATE", exact=True).wait_for()
        self.assertEqual([(call["method"], call["path"]) for call in self.calls], [("GET", "/oauth/authorize")])
        self.assertEqual(self.page.evaluate("Object.keys(sessionStorage).filter(key=>key.startsWith('xelab.oauth:')).length"), 0)
        self.assertEqual(self.page.locator('input[type="password"]').count(), 0)

    def test_window_drag_resize_minimize_maximize_and_keyboard(self):
        self.open()
        window = self.app("系统状态")
        window.get_by_text('"component-only"', exact=False).wait_for()
        title = window.locator(".window-title")
        initial = window.bounding_box()
        box = title.bounding_box()
        self.page.mouse.move(box["x"] + box["width"] - 50, box["y"] + 20)
        self.page.mouse.down()
        self.page.mouse.move(box["x"] + box["width"] + 50, box["y"] + 90, steps=5)
        self.page.mouse.up()
        moved = window.bounding_box()
        self.assertGreater(moved["x"], initial["x"] + 40)
        handle = window.get_by_role("button", name="调整系统状态大小")
        handle.focus()
        self.page.keyboard.press("ArrowRight")
        self.assertGreater(window.bounding_box()["width"], moved["width"])
        title.focus()
        x = window.bounding_box()["x"]
        self.page.keyboard.press("Alt+ArrowLeft")
        self.assertLess(window.bounding_box()["x"], x)
        window.get_by_role("button", name="最大化或恢复系统状态").click()
        self.assertGreater(window.bounding_box()["width"], 1100)
        window.get_by_role("button", name="最大化或恢复系统状态").click()
        self.assertLess(window.bounding_box()["width"], 1000)
        window.get_by_role("button", name="最小化系统状态").click()
        self.assertFalse(window.is_visible())
        self.page.get_by_role("button", name="恢复系统状态", exact=True).click()
        self.assertTrue(window.is_visible())
        window.get_by_role("button", name="关闭系统状态").click()
        self.assertEqual(self.page.locator(".window").count(), 0)

    def test_delayed_preferences_do_not_restore_live_windows(self):
        self.hold_preferences = True
        self.saved["spec"]["theme"]["mode"] = "dark"
        self.open()
        window = self.app("插件中心")
        window.get_by_role("heading", name="fixture deployment", exact=True).wait_for()
        original = window.get_attribute("data-view-id")
        self.assertEqual(len(self.pending_preferences), 1)
        self.hold_preferences = False
        for route in self.pending_preferences:
            self.route(route)
        self.page.wait_for_function("() => document.documentElement.dataset.theme === 'dark'")
        self.assertEqual(self.page.locator('.window[data-app="plugins"]').count(), 1)
        self.assertEqual(window.get_attribute("data-view-id"), original)
        self.assertEqual(len([call for call in self.calls if call["path"].endswith("/installations")]), 1)

    def assert_old_preferences_do_not_change_disconnected_status(self, status):
        # The startup preferences read has no window-owned AbortSignal, so it
        # can finish after logout. Track body consumption instead of sleeping.
        self.context.add_init_script('''(() => {
          const original = Response.prototype.arrayBuffer;
          globalThis.__stalePreferencesDecoded = false;
          Response.prototype.arrayBuffer = async function(...args) {
            const bytes = await original.apply(this, args);
            if (new TextDecoder().decode(bytes).includes('stale-preferences-probe'))
              globalThis.__stalePreferencesDecoded = true;
            return bytes;
          };
        })()''')
        self.hold_preferences = True
        self.open()
        self.assertEqual(len(self.pending_preferences), 1)
        self.page.get_by_role("button", name="退出", exact=True).click()
        self.page.get_by_role("button", name="登录", exact=True).wait_for()
        self.assertEqual(self.page.locator('#connection').text_content(), '未连接')
        if status == 200:
            data = {**self.saved, "probe": "stale-preferences-probe"}
        else:
            data = {"error": {"code": "STALE_PREFERENCES", "message": "stale-preferences-probe"}}
        self.pending_preferences[0].fulfill(
            status=status, headers={"access-control-allow-origin": SHELL},
            content_type="application/json", body=json.dumps(data))
        self.page.wait_for_function("globalThis.__stalePreferencesDecoded === true")
        self.page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
        self.assertEqual(self.page.locator('#connection').text_content(), '未连接')
        self.assertTrue(self.page.get_by_role("button", name="登录", exact=True).is_visible())

    def test_old_success_after_logout_cannot_change_connection_status(self):
        self.assert_old_preferences_do_not_change_disconnected_status(200)

    def test_old_failure_after_logout_cannot_change_connection_status(self):
        self.assert_old_preferences_do_not_change_disconnected_status(503)

    def test_delayed_preferences_restore_previous_multiwindow_layout(self):
        self.hold_preferences = True
        self.saved["spec"]["theme"]["mode"] = "dark"
        key = f"xelab:windows:{CORE}:browser-component:{ACCOUNT}"
        saved = [{"app": "resources", "rect": {"x": 40 + index * 24, "y": 24 + index * 20, "width": 500, "height": 400}, "minimized": False, "maximized": False} for index in range(2)]
        saved.append(None)  # Invalid optional storage must not clear the session.
        self.context.add_init_script(f"if(location.origin === {json.dumps(SHELL)}) localStorage.setItem({json.dumps(key)}, {json.dumps(json.dumps(saved))});")
        self.open()
        self.assertEqual(self.page.locator(".window").count(), 0)
        self.assertEqual(len(self.pending_preferences), 1)
        self.hold_preferences = False
        for route in self.pending_preferences:
            self.route(route)
        self.page.wait_for_function("() => document.querySelectorAll('.window[data-app=resources]').length === 2")
        self.page.wait_for_function("() => document.querySelectorAll('.window[data-app=resources] pre.result').length === 2")
        self.assertEqual(self.page.locator('.window[data-app="resources"] pre.result').count(), 2)
        self.assertTrue(self.page.get_by_role("button", name="退出", exact=True).is_visible())

    def test_acceptance_closes_foreground_and_minimized_windows_through_controls(self):
        self.open()
        self.app("系统状态").get_by_text('"component-only"', exact=False).wait_for()
        self.app("设置")
        report = {"checks": {}}
        DRIVER.close_windows(self.page, report)
        self.assertEqual(self.page.locator(".window").count(), 0)
        for name in ("系统状态", "设置"):
            window = self.app(name)
            window.get_by_role("button", name="最小化" + name, exact=True).click()
        self.assertEqual(self.page.locator(".window:visible").count(), 0)
        DRIVER.close_windows(self.page, report)
        self.assertEqual(self.page.locator(".window").count(), 0)
        self.assertTrue(report["checks"]["all_windows_close"])

    def test_skill_fixed_uuid_real_request_shape_and_stable_manual_retry(self):
        self.open()
        skills = self.app("Skill")
        skills.get_by_text("component.echo", exact=True).wait_for()
        skills.get_by_role("button", name="调用测试", exact=True).click()
        editor = self.page.locator(".window").last
        editor.get_by_label("请求 JSON", exact=True).fill(json.dumps({"input": {"message": "actual browser fixture"}, "idempotency_key": "browser-business-key"}))
        editor.get_by_role("button", name="提交", exact=True).click()
        editor.get_by_text('"skill_version": "1.0.0"', exact=False).wait_for()
        editor.get_by_text('"message": "actual browser fixture"', exact=False).wait_for()
        editor.get_by_role("button", name="提交", exact=True).click()
        editor.get_by_text('"skill_version": "1.0.0"', exact=False).wait_for()
        calls = [call for call in self.calls if call["method"] == "POST"]
        self.assertEqual(len(calls), 2)
        self.assertEqual({call["path"] for call in calls}, {f"/api/platform/v1/skills/{SKILL}/calls"})
        self.assertEqual(calls[0]["headers"]["idempotency-key"], calls[1]["headers"]["idempotency-key"])
        self.assertEqual(calls[0]["body"], calls[1]["body"])
        self.assertNotIn("cookie", calls[0]["headers"])

    def test_theme_saved_preferences_reload_and_reduced_effects(self):
        self.open()
        settings = self.app("设置")
        settings.get_by_label("主题模式", exact=True).select_option("dark")
        settings.get_by_label("减少动画", exact=True).check()
        settings.get_by_label("减少透明度", exact=True).check()
        settings.get_by_role("button", name="保存到当前账户", exact=True).click()
        settings.get_by_text("已保存到核心，重新登录后仍可读取。", exact=True).wait_for()
        self.assertEqual(self.saved["spec"]["theme"]["mode"], "dark")
        self.assertTrue(self.saved["spec"]["theme"]["reduce_motion"])
        self.assertTrue(self.page.locator("html").evaluate("el => el.classList.contains('reduced-transparency')"))
        puts = [call for call in self.calls if call["method"] == "PUT"]
        self.assertEqual(puts[0]["headers"]["if-match"], '"rev-1"')
        self.page.reload()
        self.page.wait_for_function("document.documentElement.dataset.theme === 'dark'")
        self.assertEqual(self.page.locator("html").get_attribute("data-theme"), "dark")

    def test_disabled_deployment_configuration_uses_public_patch_shape(self):
        self.open()
        plugins = self.app("插件中心")
        plugins.get_by_role("button", name="配置", exact=True).click()
        editor = self.page.locator('.window[data-app="editor-updateDeployment"]')
        editor.get_by_text("先停用部署并等待实例排空", exact=False).wait_for()
        body = json.loads(editor.get_by_label("请求 JSON", exact=True).input_value())
        self.assertEqual(body, {"spec": {"display_name": "fixture deployment", "enabled": False}})
        body["spec"]["config"] = {"core_origin": CORE, "client_id": "browser-component"}
        editor.get_by_label("请求 JSON", exact=True).fill(json.dumps(body))
        editor.get_by_role("button", name="提交", exact=True).click()
        editor.get_by_text('"kind": "update_deployment"', exact=False).wait_for()
        writes = [call for call in self.calls if call["method"] == "PUT"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["path"], f"/api/platform/v1/deployments/{DEPLOYMENT}")
        self.assertEqual(json.loads(writes[0]["body"]), body)
        self.assertEqual(writes[0]["headers"]["if-match"], '"rev-1"')
        self.assertTrue(writes[0]["headers"]["idempotency-key"])

    def test_data_is_text_denied_unavailable_logout_and_mobile_controls(self):
        self.context.add_init_script('''(() => {
          const original = Response.prototype.arrayBuffer;
          globalThis.__preferencesDecoded = false;
          Response.prototype.arrayBuffer = async function(...args) {
            const bytes = await original.apply(this, args);
            if (new TextDecoder().decode(bytes).includes('"restore_windows": true'))
              globalThis.__preferencesDecoded = true;
            return bytes;
          };
        })()''')
        self.open()
        self.page.wait_for_function("globalThis.__preferencesDecoded === true")
        self.page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
        plugins = self.app("插件中心")
        plugins.get_by_text('<img src=x onerror="alert(1)">', exact=True).wait_for()
        self.assertEqual(plugins.locator("img").count(), 0)
        self.denied.add("/api/platform/v1/clients")
        self.page.get_by_role("button", name="打开应用启动器", exact=True).click()
        self.page.get_by_role("button", name="启动UI 客户端", exact=True).click()
        self.page.locator(".window").last.get_by_text("无权限", exact=True).wait_for()
        self.assertEqual(self.page.locator('#connection').text_content(), '当前请求无权限')
        self.page.get_by_role("button", name="打开应用启动器", exact=True).click()
        self.page.get_by_role("button", name="启动任务与知识库", exact=True).click()
        self.page.get_by_text("Batch / Workflow / 微插件 / 知识库尚不可用", exact=True).wait_for()
        self.assertTrue(DRIVER.future_features_unavailable(self.page.locator(".window").last))
        self.page.set_viewport_size({"width": 390, "height": 760})
        self.page.get_by_role("button", name="打开设置", exact=True).click()
        window = self.page.locator(".window").last
        close = window.get_by_role("button", name="关闭设置")
        box = close.bounding_box()
        self.assertGreaterEqual(box["x"], 0)
        self.assertLessEqual(box["x"] + box["width"], 390)
        self.assertLessEqual(self.page.evaluate("document.documentElement.scrollWidth"), 390)
        self.page.get_by_role("button", name="退出", exact=True).click()
        self.assertEqual(self.page.locator(".window").count(), 0)
        self.assertEqual(self.page.locator("#widgets").text_content(), "")
        self.assertEqual(self.page.evaluate("Object.keys(sessionStorage).filter(k=>k.startsWith('xelab.oauth:')).length"), 0)

    def test_resizing_updates_window_and_plugin_visibility(self):
        value = contribution("main", "window")
        value["bindings"][0]["skill_id"] = SKILL
        self.contributions["main"] = value
        self.open()
        self.page.get_by_role("button", name="打开应用启动器", exact=True).click()
        self.page.get_by_role("button", name="启动插件页面", exact=True).click()
        listing = self.page.locator('.window[data-app="contributions"]')
        with self.page.expect_event("framenavigated", predicate=lambda frame: frame.url.startswith(PLUGIN)) as navigated:
            listing.get_by_role("button", name="打开隔离窗口", exact=True).click()
        frame = navigated.value
        frame.wait_for_function("()=>messages.some(message=>message.type==='host.init')", polling=100, timeout=5000)
        listing.locator(".window-title").focus()
        listing.get_by_role("button", name="最小化插件页面", exact=True).click()
        settings = self.app("设置")
        plugin = self.page.locator('.window[data-app^="plugin:"]')
        self.assertFalse(plugin.is_hidden())
        self.page.set_viewport_size({"width": 390, "height": 760})
        frame.wait_for_function("()=>messages.some(m=>m.event==='visibility.changed'&&!m.params.visible)", polling=100, timeout=5000)
        self.assertTrue(plugin.is_hidden())
        self.assertFalse(settings.is_hidden())
        self.assertTrue(listing.is_hidden())
        self.assertEqual(settings.get_attribute("data-focused"), "true")
        self.page.get_by_role("button", name="打开应用启动器", exact=True).click()
        self.page.get_by_role("button", name="聚焦窗口2 Independent fixture · org.xelab.fixture", exact=True).click()
        frame.wait_for_function("()=>messages.filter(m=>m.event==='visibility.changed').at(-1)?.params.visible===true", polling=100, timeout=5000)
        self.assertFalse(plugin.is_hidden())
        self.assertTrue(settings.is_hidden())
        self.page.get_by_role("button", name="打开设置", exact=True).click()
        frame.wait_for_function("()=>messages.filter(m=>m.event==='visibility.changed').at(-1)?.params.visible===false", polling=100, timeout=5000)
        self.assertTrue(plugin.is_hidden())
        self.assertFalse(settings.is_hidden())
        self.page.set_viewport_size({"width": 1280, "height": 900})
        frame.wait_for_function("()=>messages.filter(m=>m.event==='visibility.changed').at(-1)?.params.visible===true", polling=100, timeout=5000)
        self.assertFalse(plugin.is_hidden())
        self.assertFalse(settings.is_hidden())
        self.assertTrue(listing.is_hidden())
        self.assertEqual(settings.get_attribute("data-focused"), "true")
        # Simulate document visibility on the real page; this does not claim
        # that the browser actually switched operating-system tabs.
        self.page.evaluate("""() => {
          Object.defineProperty(document, 'visibilityState', {configurable:true, get:()=> 'hidden'});
          document.dispatchEvent(new Event('visibilitychange'));
          window.__resizeCount = 0;
          window.addEventListener('resize', () => window.__resizeCount++);
        }""")
        frame.wait_for_function("()=>messages.filter(m=>m.event==='visibility.changed').at(-1)?.params.visible===false", polling=100, timeout=5000)
        self.page.set_viewport_size({"width": 390, "height": 760})
        self.page.wait_for_function("()=>window.__resizeCount >= 1", timeout=5000)
        self.page.set_viewport_size({"width": 1280, "height": 900})
        self.page.wait_for_function("()=>window.__resizeCount >= 2", timeout=5000)
        self.assertFalse(frame.evaluate("messages.filter(m=>m.event==='visibility.changed').at(-1).params.visible"))
        self.page.evaluate("""() => {
          delete document.visibilityState;
          document.dispatchEvent(new Event('visibilitychange'));
        }""")
        frame.wait_for_function("()=>messages.filter(m=>m.event==='visibility.changed').at(-1)?.params.visible===true", polling=100, timeout=5000)
        # Minimizing the focused window leaves its focused flag behind; a
        # subsequent narrow transition must keep the remaining window visible.
        settings.get_by_role("button", name="最小化设置", exact=True).click()
        self.page.set_viewport_size({"width": 390, "height": 760})
        self.page.wait_for_function("()=>document.querySelector('.window[data-app^=plugin]')?.dataset.focused==='true'", timeout=5000)
        self.assertFalse(plugin.is_hidden())
        self.assertTrue(settings.is_hidden())
        self.assertTrue(listing.is_hidden())
        self.assertEqual(plugin.get_attribute("data-focused"), "true")

    def test_hidden_window_remains_hidden_when_bridge_mount_finishes(self):
        value = contribution("main", "window")
        value["bindings"][0]["skill_id"] = SKILL
        self.contributions["main"] = value
        self.open()
        self.page.set_viewport_size({"width": 390, "height": 760})
        self.page.get_by_role("button", name="打开应用启动器", exact=True).click()
        self.page.get_by_role("button", name="启动插件页面", exact=True).click()
        listing = self.page.locator('.window[data-app="contributions"]')
        self.hold_mount_verify = True
        listing.get_by_role("button", name="打开隔离窗口", exact=True).click()
        for _ in range(100):
            if self.pending_mount_verify:
                break
            self.page.wait_for_timeout(10)
        self.assertEqual(len(self.pending_mount_verify), 1)
        self.app("设置")
        self.assertTrue(self.page.locator('.window[data-app^="plugin:"]').is_hidden())
        self.hold_mount_verify = False
        with self.page.expect_event("framenavigated", predicate=lambda frame: frame.url.startswith(PLUGIN)) as navigated:
            self.route(self.pending_mount_verify.pop())
        frame = navigated.value
        frame.wait_for_function("()=>messages.some(message=>message.type==='host.init')", polling=100, timeout=5000)
        self.assertFalse(frame.evaluate("messages.find(m=>m.type==='host.init').params.visible"))

    def test_actual_desktop_opens_fixed_window_and_widget_bridge(self):
        for identifier, kind in [("main", "window"), ("summary", "widget")]:
            value = contribution(identifier, kind)
            value["bindings"][0]["skill_id"] = SKILL
            self.contributions[identifier] = value
        self.open()
        self.page.get_by_role("button", name="打开应用启动器", exact=True).click()
        self.page.get_by_role("button", name="启动插件页面", exact=True).click()
        listing = self.page.locator('.window[data-app="contributions"]')
        with self.page.expect_event("framenavigated", predicate=lambda frame: frame.url.startswith(PLUGIN)) as navigated:
            listing.get_by_role("button", name="打开隔离窗口", exact=True).click()
        plugin_window = self.page.locator('.window[data-app^="plugin:"]')
        plugin_window.locator("iframe").wait_for()
        frame = navigated.value
        frame.wait_for_function("()=>messages.some(message=>message.type==='host.init')")
        frame.evaluate("emit('skill.call',{binding_alias:'echo',input:{message:'actual desktop frame'},idempotency_key:'window-intent'},1)")
        frame.wait_for_function("()=>responses().some(message=>message.ok===true)")
        self.assertEqual(frame.evaluate("responses()[0].result.call.output.message"), "actual desktop frame")
        plugin_window.get_by_role("button", name="最小化Independent fixture · org.xelab.fixture", exact=True).click()
        frame.locator('html[data-visible="false"]').wait_for(state="attached")
        self.page.get_by_role("button", name="恢复Independent fixture · org.xelab.fixture", exact=True).click()
        plugin_window.get_by_role("button", name="关闭Independent fixture · org.xelab.fixture", exact=True).click()
        self.assertEqual(self.page.locator('.window[data-app^="plugin:"]').count(), 0)
        with self.page.expect_event("framenavigated", predicate=lambda frame: frame.url.startswith(PLUGIN)) as navigated:
            listing.get_by_role("button", name="添加桌面组件", exact=True).click()
        self.page.locator("#widgets iframe").wait_for()
        listing.get_by_role("button", name="关闭插件页面", exact=True).click()
        widget = navigated.value
        widget.wait_for_function("()=>messages.some(message=>message.type==='host.init')")
        widget.evaluate("emit('skill.call',{binding_alias:'echo',input:{message:'actual desktop widget'},idempotency_key:'widget-intent'},1)")
        widget.wait_for_function("()=>responses().some(message=>message.ok===true)")
        self.assertEqual(widget.evaluate("responses()[0].result.call.output.message"), "actual desktop widget")
        self.assertEqual(len(self.saved["spec"]["widgets"]), 1)
        self.assertEqual(self.saved["spec"]["widgets"][0]["contribution"]["contribution_id"], "summary")
        self.page.locator('.widget-card').evaluate("element=>element.style.transform='translateY(3000px)'")
        widget.locator('html[data-visible="false"]').wait_for(state="attached")
        self.page.locator('.widget-card').evaluate("element=>element.style.transform=''")
        widget.locator('html[data-visible="true"]').wait_for(state="attached")
        self.assertEqual(widget.evaluate("messages.filter(message=>message.event==='widget.refresh').length"), 0)
        self.page.get_by_role("button", name="打开设置", exact=True).click()
        settings = self.page.locator('.window[data-app="settings"]')
        count = len([call for call in self.calls if call["method"] == "POST"])
        settings.get_by_label("主题模式", exact=True).select_option("dark")
        widget.wait_for_function("()=>messages.some(message=>message.event==='theme.changed')")
        self.assertEqual(len([call for call in self.calls if call["method"] == "POST"]), count)
        self.denied.add(f'/api/platform/v1/ui/contributions/{self.contributions["summary"]["deployment_id"]}/summary')
        widget.evaluate("emit('skill.call',{binding_alias:'echo',input:{message:'revoked'},idempotency_key:'revoked-intent'},2)")
        self.page.wait_for_function("document.querySelectorAll('#widgets iframe').length===0")
        self.assertEqual(len([call for call in self.calls if call["method"] == "POST"]), count)
        self.page.get_by_role("button", name="退出", exact=True).click()
        self.assertEqual(self.page.locator("#widgets").text_content(), "")

    def test_reference_window_open_settles_before_strict_network_audit_close(self):
        self.real_reference = True
        report, observed, bodies = self.skill_body_audit()
        counts = {"plugin_headers": 0}
        def audit(request):
            observed["active_request_observers"] += 1
            try:
                if f"{urlparse(request.url).scheme}://{urlparse(request.url).netloc}" == PLUGIN:
                    request.all_headers()
                    counts["plugin_headers"] += 1
            except Exception as error:
                DRIVER.record_observer_failure(observed, "request_headers", error)
            finally:
                observed["active_request_observers"] -= 1
        self.context.on("request", audit)
        for identifier, kind in [("echo_window", "window"), ("echo_widget", "widget")]:
            value = contribution(identifier, kind)
            value["plugin_id"] = "org.xelab.ui-reference"
            value["spec"]["title"] = "Reference echo" if kind == "window" else "Echo widget"
            value["spec"]["entry_path"] = "/window.html" if kind == "window" else "/widget.html"
            value["spec"]["skill_bindings"][0].update(name="org.xelab.ui-reference.echo", modes=["call"])
            value["bindings"][0].update(skill_id=SKILL, modes=["call"])
            value["frame_url"] = PLUGIN + "/ui/org.xelab.ui-reference" + value["spec"]["entry_path"]
            value["contribution_digest"] = "sha256:" + hashlib.sha256(json.dumps(value["spec"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            self.contributions[identifier] = value
        self.open()
        skills = self.app("Skill")
        skills.get_by_role("button", name="调用测试", exact=True).click()
        editor = self.page.locator('.window[data-app="editor-invokeSkill"]')
        editor.get_by_role("textbox", name="请求 JSON", exact=True).fill(json.dumps({"input": {"message": "Observed response before window abort"}, "idempotency_key": "component-observer-body"}))
        bodies.expect(1)
        editor.get_by_role("button", name="提交", exact=True).click()
        editor.locator("pre.result").wait_for()
        DRIVER.close_windows(self.page, report, observed, bodies)
        self.assertEqual(report["http"]["actual_skill_successes"], 1)
        self.page.get_by_role("button", name="打开应用启动器", exact=True).click()
        self.page.get_by_role("button", name="启动插件页面", exact=True).click()
        listing = self.page.locator('.window[data-app="contributions"]')
        with self.page.expect_event("framenavigated", predicate=lambda frame: frame.url.startswith(PLUGIN + "/ui/org.xelab.ui-reference/widget.html")) as mounted:
            listing.get_by_role("button", name="添加桌面组件", exact=True).click()
        widget = mounted.value
        widget.wait_for_function("() => document.querySelector('#call')?.disabled === false")
        listing.get_by_role("button", name="关闭插件页面", exact=True).click()
        with self.page.expect_event("framenavigated", predicate=lambda frame: frame.url.startswith(PLUGIN + "/ui/org.xelab.ui-reference/window.html")) as opened:
            widget.locator("#open-window").click()
        self.assertTrue(DRIVER.wait_for_widget_window(self.page, widget, opened.value, self.contributions["echo_window"]["deployment_id"]))
        source = PLUGIN + "/ui/org.xelab.ui-reference/widget.html#" + opened.value.url.split("#", 1)[1]
        with self.page.expect_event("framenavigated", predicate=lambda frame: frame.url == source) as navigated:
            self.page.evaluate("src => {const frame=document.createElement('iframe');frame.id='source-probe';frame.hidden=true;frame.src=src;document.body.append(frame);}", source)
        navigated.value.wait_for_load_state("load")
        self.assertTrue(navigated.value.locator("#call").is_disabled())
        self.page.locator("#source-probe").evaluate("element => element.remove()")
        DRIVER.wait_for_observers(self.page, observed, bodies)
        self.assertGreaterEqual(counts["plugin_headers"], 12)
        self.context.close()
        self.assertEqual(observed["active_request_observers"], 0)
        self.assertEqual(observed["active_response_observers"], 0)
        self.assertFalse(observed["observer_failure"], observed["error_counts"])
        print(json.dumps({"component": "desktop_reference_window_observer_not_core", "plugin_headers": counts["plugin_headers"], "skill_json": report["http"]["actual_skill_successes"], "unique_skill_call_ids": report["http"]["unique_skill_call_ids"], "active_requests": observed["active_request_observers"], "active_responses": observed["active_response_observers"], "observer_failure": observed["observer_failure"]}, sort_keys=True))

    def test_editor_invoke_skill_outlives_the_business_deadline(self):
        self.open()
        self.hold_call = True
        message = "editor waits for a settled Call"
        skills = self.app("Skill")
        skills.get_by_role("button", name="调用测试", exact=True).click()
        editor = self.page.locator('.window[data-app="editor-invokeSkill"]')
        editor.get_by_label("请求 JSON", exact=True).fill(json.dumps({
            "input": {"message": message},
            "idempotency_key": "editor-settlement-intent",
            "timeout_ms": 10000,
        }))
        editor.get_by_role("button", name="提交", exact=True).click()
        deadline = time.monotonic() + 5
        while not self.pending_calls and time.monotonic() < deadline:
            self.page.wait_for_timeout(10)
        self.assertEqual(len(self.pending_calls), 1, "expected a held editor Skill Call")
        route, headers, data = self.pending_calls[0]
        self.assertEqual(data["call"]["output"], {"message": message})
        self.page.wait_for_timeout(11000)
        self.assertNotIn("请求失败", editor.locator('[aria-live="polite"]').inner_text(),
                         "the editor must not abort a Call at its business deadline")
        route.fulfill(status=200, headers=headers, content_type="application/json", body=json.dumps(data))
        editor.locator("pre.result").wait_for()
        self.assertIn(message, editor.locator("pre.result").inner_text())
        self.assertEqual(len([call for call in self.calls
                              if call["method"] == "POST" and call["path"].endswith("/calls")]), 1)

    def test_mutating_401_never_refreshes_or_retries_business_request(self):
        self.open()
        self.status_overrides[f"/api/platform/v1/skills/{SKILL}/calls"] = 401
        skills = self.app("Skill")
        skills.get_by_role("button", name="调用测试", exact=True).click()
        editor = self.page.locator(".window").last
        editor.get_by_label("请求 JSON", exact=True).fill(json.dumps({"input": {"message": "once"}, "idempotency_key": "once"}))
        # Logout removes the editor and may abort the 401 response body. Keep
        # its outcome node to observe the submit handler after request() ends.
        editor.locator('[aria-live="polite"]').evaluate("element => { globalThis.__oldEditorOutcome = element; }")
        editor.get_by_role("button", name="提交", exact=True).click()
        self.page.get_by_role("button", name="登录", exact=True).wait_for()
        self.page.wait_for_function("globalThis.__oldEditorOutcome.querySelector('[data-kind=error], [data-kind=denied], [data-kind=unavailable]') !== null")
        self.assertEqual(self.page.locator('#connection').text_content(), '未连接')
        self.assertEqual(len([call for call in self.calls if call["method"] == "POST" and call["path"].endswith("/calls")]), 1)
        self.assertEqual(len([call for call in self.calls if call["path"] == "/oauth/token"]), 0)
        self.assertEqual(self.page.locator(".window").count(), 0)

    def test_unknown_mutation_editor_is_locked_after_preflight_credential_rotation(self):
        self.page.clock.install()
        self.refresh_enabled = True
        self.abort_business = True
        self.open(expires_ms=45000, refresh_token="component-refresh")
        skills = self.app("Skill")
        skills.get_by_role("button", name="调用测试", exact=True).click()
        editor = self.page.locator('.window[data-app="editor-invokeSkill"]')
        original_key = editor.locator('.code').text_content()
        editor.get_by_role("button", name="提交", exact=True).click()
        editor.get_by_text("请求失败", exact=True).wait_for()
        self.assertEqual(len([call for call in self.calls if call["method"] == "POST"]), 1)
        self.page.clock.fast_forward(16000)
        resources = self.app("系统状态")
        resources.get_by_text('"component-only"', exact=False).wait_for()
        editor.get_by_text("原请求已锁定", exact=True).wait_for()
        self.assertTrue(editor.get_by_role("button", name="提交", exact=True).is_disabled())
        self.assertEqual(len([call for call in self.calls if call["path"].endswith("/calls") and call["method"] == "POST"]), 1)
        self.assertEqual(len([call for call in self.calls if call["path"] == "/oauth/token"]), 1)
        self.assertEqual(editor.locator('.code').text_content(), original_key)
        self.assertTrue(self.page.get_by_role("button", name="退出", exact=True).is_visible())

    def test_expired_access_refresh_keeps_concurrent_desktop_views_available(self):
        self.page.clock.install()
        self.refresh_enabled = True
        self.open(expires_ms=45000, refresh_token="component-refresh")
        self.page.clock.fast_forward(46000)
        self.hold_refresh = True
        self.app("系统状态")
        resources = self.page.locator('.window[data-app="resources"]')
        self.page.wait_for_function("() => sessionStorage.getItem('xelab.oauth:https://core.example.test:browser-component') === null")
        self.assertEqual(len(self.pending_refresh), 1)
        try:
            self.app("Skill")
            skills = self.page.locator('.window[data-app="skills"]')
            self.assertEqual(skills.get_by_text("登录后继续", exact=True).count(), 0)
            self.assertTrue(self.page.get_by_role("button", name="退出", exact=True).is_visible())
        finally:
            self.hold_refresh = False
            for route in self.pending_refresh:
                self.route(route)
        resources.get_by_text('"component-only"', exact=False).wait_for()
        skills.get_by_text("component.echo", exact=True).wait_for()
        self.assertEqual(len([call for call in self.calls if call["path"] == "/oauth/token"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
