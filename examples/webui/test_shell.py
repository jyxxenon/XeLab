#!/usr/bin/env python3
"""Real Chromium shell interactions with explicit routed API adapters, not Core/OCI."""
import copy
import hashlib
import json
import unittest
from urllib.parse import parse_qs, urlparse

import test_browser as desktop
from test_bridge import contribution, framing_query


class ShellBrowser(unittest.TestCase):
    # Compose the existing fixture; inheriting it would run its test suite twice.
    @classmethod
    def setUpClass(cls):
        desktop.DesktopBrowser.setUpClass()

    @classmethod
    def tearDownClass(cls):
        desktop.DesktopBrowser.tearDownClass()

    def setUp(self):
        self.fixture = desktop.DesktopBrowser(methodName="runTest")
        self.fixture.setUp()
        self.page = self.fixture.page
        self.custom_calls = []
        self.fail_preferences = 0
        self.launcher_pages = None
        self.key_pages = None
        self.key_denied = False
        self.key_error = None
        self.account_action_error = None
        self.hold_account_ids = set()
        self.held_account_routes = {}
        self.fast_accounts = {}
        self.arm_hold_widget_after_put = False
        self.hold_widget_lookup = False
        self.held_widget_routes = []
        self.hold_installation = False
        self.held_installation_routes = []
        self.subject = desktop.ACCOUNT
        self.page.route("**/*", self.route)

    def tearDown(self):
        self.fixture.tearDown()

    def reply(self, route, data, status=200):
        route.fulfill(status=status, content_type="application/json", headers={
            "access-control-allow-origin": desktop.SHELL,
            "access-control-allow-headers": "authorization,content-type,if-match,idempotency-key",
            "access-control-allow-methods": "GET,PUT,OPTIONS",
            "access-control-expose-headers": "etag,x-request-id",
            "etag": '"rev-1"', "x-request-id": desktop.ACCOUNT,
        }, body=json.dumps(data))

    def route(self, route):
        request, url = route.request, urlparse(route.request.url)
        if f"{url.scheme}://{url.netloc}" != desktop.CORE or request.method == "OPTIONS":
            route.fallback()
            return
        if request.method == "PUT" and url.path.endswith("/me/ui-preferences"):
            self.custom_calls.append({"path": url.path, "body": request.post_data, "headers": request.all_headers()})
            if self.fail_preferences:
                self.fail_preferences -= 1
                self.reply(route, {"error": {"code": "UNAVAILABLE", "message": "explicit component outage"}}, 503)
                return
            if self.arm_hold_widget_after_put:
                self.arm_hold_widget_after_put = False
                self.hold_widget_lookup = True
        if self.hold_widget_lookup and request.method == "GET" and "/ui/contributions/" in url.path:
            self.held_widget_routes.append(route)
            return
        if self.hold_installation and url.path.startswith("/api/platform/v1/installations/"):
            self.held_installation_routes.append(route)
            return
        if self.account_action_error and url.path.endswith("/effective-permissions"):
            status, code, message = self.account_action_error
            self.reply(route, {"error": {"code": code, "message": message}}, status)
            return
        if url.path.startswith("/api/platform/v1/accounts/"):
            target_id = url.path.removeprefix("/api/platform/v1/accounts/")
            if "/" not in target_id:
                if target_id in self.hold_account_ids:
                    self.held_account_routes[target_id] = route
                    return
                if target_id in self.fast_accounts:
                    self.reply(route, self.fast_accounts[target_id])
                    return
        if url.path.endswith("/sessions") and self.subject != desktop.ACCOUNT:
            self.reply(route, {"items": [{"account_id": self.subject, "status": "active"}], "next_cursor": None})
            return
        if url.path == "/api/platform/v1/ui/contributions" and self.launcher_pages is not None:
            cursor = parse_qs(url.query).get("cursor", [None])[0]
            self.reply(route, self.launcher_pages[cursor])
            return
        if url.path == f"/api/platform/v1/accounts/{desktop.ACCOUNT}":
            self.reply(route, {"id": desktop.ACCOUNT, "display_name": "Component account", "status": "active"})
            return
        if url.path.endswith("/api-keys") or "/api-keys/" in url.path:
            self.custom_calls.append({"path": url.path, "method": request.method, "headers": request.all_headers()})
            value = {"id": desktop.DEPLOYMENT, "owner_id": desktop.ACCOUNT, "revision": 1,
                     "name": "Read-only monitor", "prefix": "xk_safe", "status": "active",
                     "issuer_credential_id": desktop.ACCOUNT, "created_at": desktop.NOW,
                     "updated_at": desktop.NOW, "last_used_at": None,
                     "inheritance": {"mode": "all_snapshot", "secret": "DO-NOT-RENDER-NESTED-SECRET"},
                     "secret": "DO-NOT-RENDER-ISSUANCE-SECRET", "verification_digest": "DO-NOT-RENDER-DIGEST"}
            if self.key_error:
                status, code, message = self.key_error
                self.reply(route, {"error": {"code": code, "message": message}}, status)
            elif self.key_denied:
                self.reply(route, {"error": {"code": "PERMISSION_DENIED", "message": "component ceiling denied"}}, 403)
            elif self.key_pages is not None:
                cursor = parse_qs(url.query).get("cursor", [None])[0]
                self.reply(route, self.key_pages[cursor])
            else:
                self.reply(route, {"items": [value], "next_cursor": None} if url.path.endswith("/api-keys") else value)
            return
        route.fallback()

    def window_contribution(self, identifier="main"):
        value = contribution(identifier)
        value["spec"]["title"] = "Pinned echo " + identifier
        self.fixture.contributions[identifier] = value
        return value

    def open_launcher(self):
        self.page.get_by_role("button", name="打开应用启动器", exact=True).click()

    def pin_from_launcher(self, value):
        self.open_launcher()
        self.page.locator("#app-search").fill(value["spec"]["title"])
        self.page.get_by_role("button", name="固定 " + value["spec"]["title"], exact=True).click()
        self.page.get_by_role("button", name="取消固定 " + value["spec"]["title"], exact=True).last.wait_for()
        self.page.locator("#launcher-close").click()
        self.page.get_by_role("button", name="打开固定贡献 " + value["spec"]["title"], exact=True).wait_for()

    def reference_widget(self):
        self.fixture.real_reference = True
        for identifier, kind in [("echo_window", "window"), ("echo_widget", "widget")]:
            value = contribution(identifier, kind)
            value["plugin_id"] = "org.xelab.ui-reference"
            value["spec"].update(title="Reference echo" if kind == "window" else "Echo widget", entry_path="/window.html" if kind == "window" else "/widget.html", refresh_interval_seconds=0)
            value["spec"]["skill_bindings"][0].update(name="org.xelab.ui-reference.echo", modes=["call"])
            value["bindings"][0].update(skill_id=desktop.SKILL, modes=["call"])
            value["frame_url"] = desktop.PLUGIN + "/ui/org.xelab.ui-reference" + value["spec"]["entry_path"]
            value["contribution_digest"] = "sha256:" + hashlib.sha256(json.dumps(value["spec"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            self.fixture.contributions[identifier] = value
        self.fixture.open()
        self.open_launcher()
        self.page.get_by_role("button", name="启动插件页面", exact=True).click()
        listing = self.page.locator('.window[data-app="contributions"]')
        with self.page.expect_event("framenavigated", predicate=lambda frame: frame.url.startswith(desktop.PLUGIN + "/ui/org.xelab.ui-reference/widget.html")) as mounted:
            listing.get_by_role("button", name="添加桌面组件", exact=True).click()
        widget = mounted.value
        widget.wait_for_function("() => document.querySelector('#call')?.disabled === false")
        listing.get_by_role("button", name="关闭插件页面", exact=True).click()
        widget.evaluate("""() => {window.__windowResponses=[];const m=Object.fromEntries(new URLSearchParams(location.hash.slice(1)));addEventListener('message',event=>{const value=event.data;if(event.source===parent&&event.origin===m.parent_origin&&value?.protocol===m.protocol&&value?.view_id===m.view_id&&value?.channel_nonce===m.channel_nonce&&value.type==='response'&&value.method==='window.open')window.__windowResponses.push({ok:value.ok,at:performance.now(),view_valid:/^[a-f0-9-]{36}$/i.test(value.result?.view_id||'')});});}""")
        return widget

    def test_reference_window_open_avoids_redundant_lookup_with_original_ten_second_deadline(self):
        # Actual app/Host/reference code; only Core HTTP is a routed adapter.
        # Individual legal metadata reads take 3s, never exceeding their 10s
        # budget. The old serial duplicate caused a valid response after 12s.
        self.page.add_init_script("""(() => {const original=window.fetch.bind(window);window.__windowProbe={delay:0,start:0,requests:[]};window.fetch=async(input,options)=>{const url=new URL(typeof input==='string'?input:input.url||String(input),location.href),p=window.__windowProbe;if(p.delay&&url.pathname.startsWith('/api/platform/v1/ui/contributions/')){const row={kind:url.pathname.endsWith('/echo_widget')?'widget':'window',before_window:!document.querySelector('#windows section.window[data-app$=":echo_window"]'),start:Math.round(performance.now()-p.start)};p.requests.push(row);await new Promise(resolve=>setTimeout(resolve,p.delay));const response=await original(input,options);row.end=Math.round(performance.now()-p.start);row.status=response.status;return response;}return original(input,options);};})();""")
        widget = self.reference_widget()
        widget.evaluate("() => {window.__windowStarted=performance.now();}")
        self.page.evaluate("() => {window.__windowProbe.start=performance.now();window.__windowProbe.delay=3000;}")
        with self.page.expect_event("framenavigated", timeout=25000, predicate=lambda frame: frame.url.startswith(desktop.PLUGIN + "/ui/org.xelab.ui-reference/window.html")) as opened:
            widget.locator("#open-window").click()
        widget.get_by_text("The host opened this deployment’s echo window.", exact=True).wait_for(timeout=25000)
        opened.value.wait_for_function("() => document.querySelector('#call')?.disabled === false")
        response = widget.evaluate("() => window.__windowResponses.map(row=>({...row,at:Math.round(row.at-window.__windowStarted)}))")
        self.assertEqual(len(response), 1)
        self.assertTrue(response[0]["ok"] and response[0]["view_valid"])
        self.assertLess(response[0]["at"], 10000, "The existing reference deadline remains unchanged")
        metadata = self.page.evaluate("() => window.__windowProbe.requests")
        before = [row for row in metadata if row["kind"] == "window" and row["before_window"]]
        self.assertEqual(len(before), 1, "Bridge's checked target must not be fetched twice before opening")
        self.assertGreaterEqual(sum(row["kind"] == "window" and not row["before_window"] for row in metadata), 2, "Target mount and handshake still check current authority")
        self.assertTrue(all(row.get("status", 200) == 200 for row in metadata))
        report = {}
        audit = desktop.DRIVER.WindowOpenAudit(desktop.CORE, desktop.DEPLOYMENT, report)
        audit.start()
        audit.snapshot(widget)
        safe = report["window_open_observation"]["widget_snapshot"]
        self.assertEqual(safe["state_class"], "window_open_succeeded")
        # The driver must continue to classify old signed images and must not
        # place arbitrary plugin text in diagnostic reports.
        widget.evaluate("""() => {
          document.querySelector('#window-state').textContent='Waiting for the host to open the window…';
          document.querySelector('#skill-state').textContent='Skill call completed.';
        }""")
        audit.snapshot(widget)
        self.assertEqual(report['window_open_observation']['widget_snapshot']['state_class'], 'previous_skill_completed')
        desktop.DRIVER.wait_for_reference_skill(widget)
        widget.evaluate("""() => {
          document.querySelector('#window-state').textContent='BINDING_UNAVAILABLE: PRIVATE_DIAGNOSTIC_MARKER';
        }""")
        audit.snapshot(widget)
        self.assertEqual(report['window_open_observation']['widget_snapshot']['state_class'], 'BINDING_UNAVAILABLE')
        self.assertNotIn('PRIVATE_DIAGNOSTIC_MARKER', json.dumps(report))
        widget.evaluate("""() => {
          document.querySelector('#window-state').remove();
          document.querySelector('#skill-state').remove();
          document.querySelector('#state').textContent='Skill call completed.';
        }""")
        desktop.DRIVER.wait_for_reference_skill(widget)
        audit.snapshot(widget)
        self.assertEqual(report['window_open_observation']['widget_snapshot']['state_class'], 'previous_skill_completed')
        widget.evaluate("() => {document.querySelector('#state').textContent='The host opened this deployment’s echo window.';}")
        audit.snapshot(widget)
        self.assertEqual(report['window_open_observation']['widget_snapshot']['state_class'], 'window_open_succeeded')
        audit.end()
        print(json.dumps({"component": "actual_window_bridge_core_adapter", "metadata_delay_ms": 3000, "window_response_ms": response[0]["at"], "pre_open_target_lookups": len(before), "target_ready": True}, sort_keys=True))

    def test_closed_widget_cannot_create_late_window_across_reference_digest_await(self):
        widget = self.reference_widget()
        self.page.evaluate("""() => {const original=crypto.subtle.digest.bind(crypto.subtle);window.__hashWaiting=false;window.__hashFinished=false;crypto.subtle.digest=async(algorithm,value)=>{const input=new TextDecoder().decode(value);if(input.startsWith('[')&&input.includes('\"alias\"')){window.__hashWaiting=true;await new Promise(resolve=>{window.__releaseHash=resolve;});}const result=await original(algorithm,value);if(window.__hashWaiting)window.__hashFinished=true;return result;};}""")
        widget.locator("#open-window").click()
        self.page.wait_for_function("() => window.__hashWaiting")
        # Remove the actual source widget while the account stays logged in;
        # sessionEpoch alone cannot protect this asynchronous boundary.
        self.page.locator("#widgets .widget-card").get_by_role("button", name="移除", exact=True).click()
        self.page.wait_for_function("() => document.querySelectorAll('#widgets .widget-card').length === 0")
        self.page.get_by_role("button", name="退出", exact=True).wait_for()
        self.page.evaluate("() => window.__releaseHash()")
        self.page.wait_for_function("() => window.__hashFinished")
        self.page.evaluate("() => Promise.resolve()")
        self.assertEqual(self.page.locator('#windows section.window[data-app$=":echo_window"]').count(), 0)
        self.assertFalse(any(call["method"] == "POST" for call in self.fixture.calls))

    def test_window_open_keeps_current_target_permission_and_fixed_deployment_checks(self):
        widget = self.reference_widget()
        target = self.fixture.contributions["echo_window"]
        path = f"/api/platform/v1/ui/contributions/{target['deployment_id']}/echo_window"
        self.fixture.denied.add(path)
        widget.locator("#open-window").click()
        widget.wait_for_function("() => window.__windowResponses.length === 1")
        self.assertFalse(widget.evaluate("() => window.__windowResponses[0].ok"))
        self.assertEqual(self.page.locator('#windows section.window[data-app$=":echo_window"]').count(), 0)
        self.fixture.denied.remove(path)
        target["deployment_id"] = "00000000-0000-4000-8000-000000000099"
        widget.locator("#open-window").click()
        widget.wait_for_function("() => window.__windowResponses.length === 2")
        self.assertFalse(widget.evaluate("() => window.__windowResponses[1].ok"))
        self.assertEqual(self.page.locator('#windows section.window[data-app$=":echo_window"]').count(), 0)

    def test_target_mount_rechecks_permission_before_loading_business_page(self):
        widget = self.reference_widget()
        target = self.fixture.contributions["echo_window"]
        target_requests, target_navigations = [], []
        self.page.on("framenavigated", lambda frame: target_navigations.append(True) if frame.url.startswith(target["frame_url"]) else None)

        def metadata(route):
            target_requests.append(True)
            if len(target_requests) == 1:
                route.fallback()
            else:
                self.reply(route, {"error": {"code": "PERMISSION_DENIED", "message": "component mount proof denied", "retryable": False}}, 403)

        self.page.route(desktop.CORE + f"/api/platform/v1/ui/contributions/{target['deployment_id']}/echo_window", metadata)
        widget.locator("#open-window").click()
        window = self.page.locator('#windows section.window[data-app$=":echo_window"]')
        window.get_by_role("heading", name="无权限", exact=True).wait_for()
        self.assertEqual(len(target_requests), 2, "The checked target is independently reauthorized at mount")
        self.assertEqual(window.locator("iframe").count(), 0)
        self.assertEqual(target_navigations, [], "No target business document loads after the current mount proof is denied")

    def test_launcher_search_pages_and_pin_open_unpin_fixed_contribution(self):
        first, second = self.window_contribution(), self.window_contribution("second")
        self.launcher_pages = {None: {"items": [first], "next_cursor": "component-next"},
                               "component-next": {"items": [second], "next_cursor": None}}
        self.fixture.open()
        self.open_launcher()
        self.page.get_by_role("button", name="加载更多贡献", exact=True).click()
        self.page.locator("#app-search").fill(second["spec"]["title"])
        self.page.get_by_role("button", name="固定 " + second["spec"]["title"], exact=True).click()
        self.page.get_by_role("button", name="取消固定 " + second["spec"]["title"], exact=True).last.wait_for()
        self.assertEqual(self.fixture.saved["spec"]["dock"]["pinned"], [{"deployment_id": second["deployment_id"], "contribution_id": "second"}])
        self.assertNotIn("digest", json.dumps(self.fixture.saved["spec"]["dock"]["pinned"]))
        self.page.locator("#launcher-close").click()
        self.page.get_by_role("button", name="打开固定贡献 " + second["spec"]["title"], exact=True).click()
        window = self.page.locator('.window[data-app="plugin:' + second["deployment_id"] + ':second"]')
        expected_src = second["frame_url"] + "#protocol=xelab.ui%2F1"
        # The mount verifies current permissions asynchronously after creating
        # the iframe. Wait for the authorized target under the same timeout.
        frame = window.locator("iframe[src^=" + json.dumps(expected_src) + "]")
        frame.wait_for()
        self.assertEqual(frame.get_attribute("sandbox"), "allow-scripts allow-same-origin")
        self.assertTrue(frame.get_attribute("src").startswith(expected_src))
        self.page.get_by_role("button", name="取消固定 " + second["spec"]["title"], exact=True).click()
        self.page.wait_for_function("() => !document.querySelector('.dock-pin')")
        self.assertEqual(self.fixture.saved["spec"]["dock"]["pinned"], [])
        self.assertEqual(len(self.custom_calls), 2)
        self.assertEqual(self.custom_calls[0]["headers"]["if-match"], '"rev-1"')
        self.assertEqual(self.custom_calls[1]["headers"]["if-match"], '"rev-2"')
        self.assertNotEqual(self.custom_calls[0]["headers"]["idempotency-key"], self.custom_calls[1]["headers"]["idempotency-key"])

    def test_closed_launcher_cannot_open_window_after_reopening(self):
        value = self.window_contribution()
        self.fixture.open()
        self.open_launcher()
        launcher = self.page.locator("#launcher")
        launch = launcher.get_by_role("button", name="启动贡献 " + value["spec"]["title"], exact=True)
        original_button = launch.element_handle()
        self.hold_widget_lookup = True
        original_button.click()
        for _ in range(250):
            if self.held_widget_routes:
                break
            self.page.wait_for_timeout(20)
        self.assertEqual(len(self.held_widget_routes), 1)
        self.assertTrue(original_button.is_disabled())

        self.page.keyboard.press("Escape")
        launcher.wait_for(state="hidden")
        active = self.fixture.app("系统状态")
        active.get_by_text('"component-only"', exact=False).wait_for()
        self.open_launcher()
        search = launcher.locator("#app-search")
        search.fill("settings")
        self.hold_widget_lookup = False
        self.held_widget_routes.pop().fallback()
        # The detached button is re-enabled when its old handler has returned.
        self.page.wait_for_function("button => !button.disabled", arg=original_button)
        self.assertEqual(self.page.locator('.window[data-app^="plugin:"]').count(), 0)
        self.assertTrue(launcher.is_visible())
        self.assertEqual(search.input_value(), "settings")
        self.assertTrue(search.evaluate("element => element === document.activeElement"))
        self.assertEqual(self.page.locator("#toast").inner_text(), "")

        search.fill(value["spec"]["title"])
        launch.click()
        launcher.wait_for(state="hidden")
        window = self.page.locator('.window[data-app^="plugin:"]')
        window.locator("iframe[src]").wait_for()
        self.assertEqual(window.count(), 1)
        self.assertTrue(window.locator(".window-title").evaluate("element => element === document.activeElement"))

    def test_closed_launcher_cannot_submit_widget_after_preference_read(self):
        value = contribution("late_widget", "widget")
        self.fixture.contributions["late_widget"] = value
        self.fixture.open()
        self.open_launcher()
        launcher = self.page.locator("#launcher")
        launch = launcher.get_by_role("button", name="启动贡献 " + value["spec"]["title"], exact=True)
        original_button = launch.element_handle()
        self.fixture.hold_preferences = True
        original_button.click()
        for _ in range(250):
            if self.fixture.pending_preferences:
                break
            self.page.wait_for_timeout(20)
        self.assertEqual(len(self.fixture.pending_preferences), 1)
        self.assertTrue(original_button.is_disabled())

        self.page.get_by_role("button", name="关闭启动器", exact=True).click()
        launcher.wait_for(state="hidden")
        self.open_launcher()
        self.fixture.hold_preferences = False
        self.fixture.route(self.fixture.pending_preferences.pop())
        self.page.wait_for_function("button => !button.disabled", arg=original_button)
        self.assertEqual(self.fixture.saved["spec"]["widgets"], [])
        self.assertEqual(self.custom_calls, [])
        self.assertTrue(launcher.is_visible())
        self.assertEqual(self.page.locator("#widgets iframe").count(), 0)
        self.assertEqual(self.page.locator("#toast").inner_text(), "")

        # An explicit new launch can submit once. Let its already-sent write
        # finish after closing the dialog, without dismissing the next opening.
        pending_writes = []

        def hold_write(route):
            if route.request.method == "PUT":
                pending_writes.append(route)
            else:
                route.fallback()

        self.page.route(desktop.CORE + "/api/platform/v1/me/ui-preferences", hold_write)
        retry_button = launch.element_handle()
        retry_button.click()
        for _ in range(250):
            if pending_writes:
                break
            self.page.wait_for_timeout(20)
        self.assertEqual(len(pending_writes), 1)
        self.assertTrue(retry_button.is_disabled())
        self.page.get_by_role("button", name="关闭启动器", exact=True).click()
        launcher.wait_for(state="hidden")
        self.open_launcher()
        pending_writes.pop().fallback()
        self.page.wait_for_function("button => !button.disabled", arg=retry_button)
        self.assertTrue(launcher.is_visible())
        self.assertEqual(len(self.custom_calls), 1)
        widgets = self.fixture.saved["spec"]["widgets"]
        self.assertEqual([widget["contribution"]["contribution_id"] for widget in widgets], ["late_widget"])
        self.page.locator("#widgets iframe[src]").wait_for()

    def test_closed_launcher_cannot_send_widget_after_credential_refresh(self):
        value = contribution("late_refresh", "widget")
        self.fixture.contributions["late_refresh"] = value
        self.page.clock.set_fixed_time("2026-11-01T12:00:00Z")
        self.fixture.refresh_enabled = True
        self.fixture.open(expires_ms=45000, refresh_token="component-refresh")
        self.open_launcher()
        launcher = self.page.locator("#launcher")
        launch = launcher.get_by_role("button", name="启动贡献 " + value["spec"]["title"], exact=True)
        original_button = launch.element_handle()
        self.fixture.hold_preferences = True
        original_button.click()
        for _ in range(250):
            if self.fixture.pending_preferences:
                break
            self.page.wait_for_timeout(20)
        self.assertEqual(len(self.fixture.pending_preferences), 1)
        self.assertTrue(original_button.is_disabled())

        # The preflight already holds a response, but the PUT now needs a
        # credential refresh before ApiClient can start the request.
        self.page.clock.set_fixed_time("2026-11-01T12:00:16Z")
        self.fixture.hold_preferences = False
        self.fixture.hold_refresh = True
        self.fixture.route(self.fixture.pending_preferences.pop())
        for _ in range(250):
            if self.fixture.pending_refresh:
                break
            self.page.wait_for_timeout(20)
        self.assertEqual(len(self.fixture.pending_refresh), 1)
        self.page.keyboard.press("Escape")
        launcher.wait_for(state="hidden")
        self.open_launcher()
        self.fixture.hold_refresh = False
        self.fixture.route(self.fixture.pending_refresh.pop())
        self.page.wait_for_function("button => !button.disabled", arg=original_button)
        self.assertEqual(len(self.custom_calls), 0)
        self.assertEqual(self.fixture.saved["spec"]["widgets"], [])
        self.assertTrue(launcher.is_visible())
        self.assertTrue(self.page.get_by_role("button", name="退出", exact=True).is_visible())
        launch.click()
        launcher.wait_for(state="hidden")
        self.assertEqual(len(self.custom_calls), 1)
        widgets = self.fixture.saved["spec"]["widgets"]
        self.assertEqual([widget["contribution"]["contribution_id"] for widget in widgets], ["late_refresh"])

    def test_pinned_digest_change_cannot_silently_open_new_version(self):
        value = self.window_contribution()
        self.fixture.open()
        self.pin_from_launcher(value)
        self.fixture.contributions["main"]["contribution_digest"] = "sha256:" + "e" * 64
        self.page.get_by_role("button", name="打开固定贡献 " + value["spec"]["title"], exact=True).click()
        self.page.locator("#toast").get_by_text("贡献或权限已改变", exact=False).wait_for()
        self.assertEqual(self.page.locator(".bridge-frame").count(), 0)
        self.assertTrue(self.page.get_by_role("button", name="打开固定贡献 " + value["spec"]["title"], exact=True).is_disabled())
        self.assertEqual(len(self.custom_calls), 1)

    def test_pinned_denied_can_be_removed_without_loading_iframe(self):
        value = self.window_contribution()
        self.fixture.saved["spec"]["dock"]["pinned"] = [{"deployment_id": value["deployment_id"], "contribution_id": "main"}]
        self.fixture.open()
        self.fixture.denied.add(f'/api/platform/v1/ui/contributions/{value["deployment_id"]}/main')
        self.page.reload()
        self.page.wait_for_function("document.querySelector('#connection').textContent === '当前请求无权限'")
        self.assertTrue(self.page.get_by_role("button", name="打开固定贡献 main", exact=True).is_disabled())
        self.page.get_by_role("button", name="取消固定 main", exact=True).click()
        self.page.wait_for_function("() => !document.querySelector('.dock-pin')")
        self.assertEqual(self.fixture.saved["spec"]["dock"]["pinned"], [])
        self.assertEqual(self.page.locator(".bridge-frame").count(), 0)

    def widget(self):
        value = contribution("widget", "widget")
        value["spec"]["title"] = "Layout widget"
        value["spec"]["widget"].update(min_columns=2, max_columns=4, min_rows=2, max_rows=3)
        self.fixture.contributions["widget"] = value
        placement = {"instance_id": desktop.ACCOUNT, "contribution": {"deployment_id": value["deployment_id"], "contribution_id": "widget"},
                     "column": 0, "row": 0, "columns": 3, "rows": 2}
        self.fixture.saved["spec"]["widgets"] = [placement]
        return value, copy.deepcopy(placement)

    def layout_window(self):
        self.page.get_by_role("button", name="调整组件布局 Layout widget", exact=True).click()
        return self.page.locator('.window[data-app^="widget-layout:"]')

    def restore_record(self, value):
        bindings = [{"alias": item["alias"], "skill_id": item["skill_id"], "definition_digest": item["definition_digest"],
                     "modes": sorted(item["modes"])} for item in sorted(value["bindings"], key=lambda item: item["alias"])]
        return {"app": "contribution", "contribution": {
            "deployment_id": value["deployment_id"], "contribution_id": value["spec"]["id"],
            "installation_id": value["installation_id"], "manifest_digest": value["manifest_digest"],
            "contribution_digest": value["contribution_digest"],
            "bindings_digest": "sha256:" + hashlib.sha256(json.dumps(bindings, separators=(",", ":")).encode()).hexdigest()},
            "rect": {"x": 100, "y": 80, "width": 600, "height": 360}, "minimized": False, "maximized": False}

    def seed_restore(self, value, account=desktop.ACCOUNT):
        key = f"xelab:windows:{desktop.CORE}:browser-component:{account}"
        stored = json.dumps([self.restore_record(value)])
        self.fixture.context.add_init_script(f"if(location.origin === {json.dumps(desktop.SHELL)}) localStorage.setItem({json.dumps(key)}, {json.dumps(stored)});")
        return key

    def test_contribution_restore_uses_new_channel_and_never_stores_business_or_credentials(self):
        value = self.window_contribution()
        value["frame_url"] += framing_query("main", "browser-component")
        self.fixture.open()
        skills = self.fixture.app("Skill")
        skills.get_by_role("button", name="调用测试", exact=True).click()
        editor = self.page.locator(".window").last
        editor.get_by_label("请求 JSON", exact=True).fill(json.dumps({"input": {"private": "BUSINESS-RESULT-NOT-LAYOUT"}, "idempotency_key": "private-business-intent"}))
        editor.get_by_role("button", name="提交", exact=True).click()
        editor.get_by_text('"private": "BUSINESS-RESULT-NOT-LAYOUT"', exact=False).wait_for()
        desktop.DRIVER.close_windows(self.page, {"checks": {}})
        self.pin_from_launcher(value)
        self.page.get_by_role("button", name="打开固定贡献 " + value["spec"]["title"], exact=True).click()
        window = self.page.locator('.window[data-app^="plugin:"]')
        frame = window.locator("iframe")
        frame.wait_for()
        before_view, before_source = window.get_attribute("data-view-id"), frame.get_attribute("src")
        window.locator(".window-title").focus()
        self.page.keyboard.press("Alt+ArrowRight")
        key = f"xelab:windows:{desktop.CORE}:browser-component:{desktop.ACCOUNT}"
        stored = self.page.evaluate("key => localStorage.getItem(key)", key)
        record = json.loads(stored)[0]
        self.assertEqual(set(record["contribution"]), {"deployment_id", "contribution_id", "installation_id", "manifest_digest", "contribution_digest", "bindings_digest"})
        for private in ("BUSINESS-RESULT-NOT-LAYOUT", "private-business-intent", "component-token", "channel_nonce", "bindings\"", "frame_url"):
            self.assertNotIn(private, stored)
        self.page.reload()
        restored = self.page.locator('.window[data-app^="plugin:"]')
        restored.locator("iframe").wait_for()
        self.assertNotEqual(restored.get_attribute("data-view-id"), before_view)
        self.assertNotEqual(restored.locator("iframe").get_attribute("src"), before_source)
        self.assertEqual(restored.evaluate("el => [el.style.left, el.style.top, el.style.width, el.style.height]"),
                         [f'{record["rect"][field]}px' for field in ("x", "y", "width", "height")])
        self.assertEqual(len([call for call in self.fixture.calls if call["method"] == "POST"]), 1)
        self.assertNotIn("BUSINESS-RESULT-NOT-LAYOUT", self.page.locator("body").inner_text())

    def test_changed_restore_is_inert_until_explicit_current_version_discovery(self):
        value = self.window_contribution()
        key = self.seed_restore(value)
        value["manifest_digest"] = "sha256:" + "f" * 64
        self.fixture.open()
        window = self.page.locator('.window[data-app^="plugin:"]')
        window.get_by_role("heading", name="插件窗口等待确认", exact=True).wait_for()
        self.assertEqual(window.locator("iframe").count(), 0)
        self.assertEqual(json.loads(self.page.evaluate("key => localStorage.getItem(key)", key))[0]["contribution"]["manifest_digest"], "sha256:" + "b" * 64)
        window.get_by_role("button", name="明确重新发现并加载", exact=True).click()
        window.locator("iframe").wait_for()
        self.assertEqual(json.loads(self.page.evaluate("key => localStorage.getItem(key)", key))[0]["contribution"]["manifest_digest"], value["manifest_digest"])
        self.assertEqual([call for call in self.fixture.calls if call["method"] == "POST"], [])

    def test_changed_whitelist_or_denied_restore_never_mounts_automatically(self):
        value = self.window_contribution()
        self.seed_restore(value)
        value["bindings"] = []
        self.fixture.open()
        window = self.page.locator('.window[data-app^="plugin:"]')
        window.get_by_role("heading", name="插件窗口等待确认", exact=True).wait_for()
        self.assertEqual(window.locator("iframe").count(), 0)
        path = f'/api/platform/v1/ui/contributions/{value["deployment_id"]}/main'
        self.fixture.denied.add(path)
        window.get_by_role("button", name="明确重新发现并加载", exact=True).click()
        window.get_by_role("heading", name="无权限", exact=True).wait_for()
        self.assertEqual(window.locator("iframe").count(), 0)
        self.fixture.denied.clear()
        window.get_by_role("button", name="明确重新发现并加载", exact=True).click()
        window.locator("iframe").wait_for()
        self.assertEqual([call for call in self.fixture.calls if call["method"] == "POST"], [])

    def test_delayed_restore_cannot_replace_new_interactive_window(self):
        value = self.window_contribution()
        self.seed_restore(value)
        self.fixture.hold_preferences = True
        self.fixture.open()
        active = self.fixture.app("系统状态")
        active.get_by_text('"component-only"', exact=False).wait_for()
        identity = active.get_attribute("data-view-id")
        self.fixture.hold_preferences = False
        for route in self.fixture.pending_preferences:
            self.fixture.route(route)
        self.page.wait_for_function("() => document.querySelector('#connection').textContent === '已连接核心'")
        self.assertEqual(self.page.locator(".window").count(), 1)
        self.assertEqual(active.get_attribute("data-view-id"), identity)
        self.assertEqual(self.page.locator("iframe").count(), 0)

    def test_restore_is_account_scoped_and_logout_removes_current_layout(self):
        value = self.window_contribution()
        key = self.seed_restore(value)
        self.fixture.open()
        self.page.locator('.window[data-app^="plugin:"] iframe').wait_for()
        self.page.get_by_role("button", name="退出", exact=True).click()
        self.assertEqual(self.page.locator("iframe").count(), 0)
        self.assertIsNone(self.page.evaluate("key => localStorage.getItem(key)", key))
        self.subject = desktop.DEPLOYMENT
        self.fixture.saved = desktop.preferences()
        self.fixture.saved["owner_id"] = self.subject
        # The init script intentionally leaves a former account's non-sensitive
        # layout on reload; the new subject must never select that namespace.
        self.page.reload()
        self.page.get_by_role("button", name="退出", exact=True).wait_for()
        self.page.wait_for_function("() => document.querySelector('#connection').textContent === '已连接核心'")
        self.assertEqual(self.page.locator(".window").count(), 0)
        self.assertEqual(self.page.locator("iframe").count(), 0)

    def test_widget_layout_constraints_and_frozen_retry_preserve_preferences(self):
        _, placement = self.widget()
        self.fixture.saved["spec"]["theme"]["mode"] = "dark"
        self.fixture.open()
        window = self.layout_window()
        width = window.get_by_label("宽度格数", exact=True)
        self.assertEqual((width.get_attribute("min"), width.get_attribute("max")), ("2", "4"))
        width.fill("5")
        window.get_by_role("button", name="保存组件布局", exact=True).click()
        self.assertFalse(width.evaluate("el => el.checkValidity()"))
        self.assertEqual(self.custom_calls, [])
        width.fill("4")
        window.get_by_label("列坐标", exact=True).fill("2")
        window.get_by_label("行坐标", exact=True).fill("3")
        window.get_by_label("高度格数", exact=True).fill("3")
        self.fail_preferences = 1
        window.get_by_role("button", name="保存组件布局", exact=True).click()
        window.get_by_role("heading", name="当前不可用", exact=True).wait_for()
        window.get_by_role("button", name="保存组件布局", exact=True).click()
        window.get_by_role("heading", name="组件布局已保存", exact=True).wait_for()
        first, second = self.custom_calls
        self.assertEqual(first["body"], second["body"])
        self.assertEqual(first["headers"]["idempotency-key"], second["headers"]["idempotency-key"])
        self.assertEqual(first["headers"]["if-match"], second["headers"]["if-match"])
        expected = {**placement, "column": 2, "row": 3, "columns": 4, "rows": 3}
        self.assertEqual(self.fixture.saved["spec"]["widgets"], [expected])
        self.assertEqual(self.fixture.saved["spec"]["theme"]["mode"], "dark")
        self.assertEqual(self.page.locator(".widget-card").evaluate("el => [el.style.gridColumn, el.style.gridRow]"), ["3 / span 4", "4 / span 3"])
        window.get_by_label("行坐标", exact=True).fill("4")
        window.get_by_role("button", name="保存组件布局", exact=True).click()
        self.page.wait_for_function("() => document.querySelector('.widget-card').style.gridRow === '5 / span 3'")
        self.assertEqual(self.fixture.saved["spec"]["widgets"][0]["row"], 4)
        self.assertEqual(self.custom_calls[2]["headers"]["if-match"], '"rev-2"')
        self.assertNotEqual(first["headers"]["idempotency-key"], self.custom_calls[2]["headers"]["idempotency-key"])

    def test_widget_overlap_stale_and_denied_never_write_preferences(self):
        value, placement = self.widget()
        self.fixture.saved["spec"]["widgets"].append({**placement, "instance_id": desktop.DEPLOYMENT, "column": 4})
        self.fixture.open()
        self.page.get_by_role("button", name="调整组件布局 Layout widget", exact=True).first.click()
        window = self.page.locator('.window[data-app^="widget-layout:"]')
        window.get_by_label("列坐标", exact=True).fill("4")
        window.get_by_role("button", name="保存组件布局", exact=True).click()
        window.get_by_text("此位置与其他组件重叠", exact=False).wait_for()
        self.assertEqual(self.custom_calls, [])
        self.fixture.denied.add(f'/api/platform/v1/ui/contributions/{value["deployment_id"]}/widget')
        window.get_by_label("列坐标", exact=True).fill("0")
        window.get_by_role("button", name="保存组件布局", exact=True).click()
        window.get_by_role("heading", name="无权限", exact=True).wait_for()
        self.assertEqual(self.custom_calls, [])
        self.fixture.denied.clear()
        self.fixture.contributions["widget"]["contribution_digest"] = "sha256:" + "f" * 64
        window.get_by_role("button", name="保存组件布局", exact=True).click()
        window.get_by_text("固定贡献或权限已改变", exact=False).wait_for()
        self.assertEqual(self.custom_calls, [])

    def test_api_key_metadata_reads_are_authorized_fixed_gets_and_never_show_secret(self):
        self.fixture.open()
        account = self.fixture.app("账户与权限")
        account.get_by_role("button", name="API Key 元数据", exact=True).click()
        keys = self.page.locator('.window[data-app^="api-keys:"]')
        keys.get_by_role("heading", name="Read-only monitor", exact=True).wait_for()
        keys.get_by_role("button", name="读取密钥元数据", exact=True).click()
        self.page.get_by_role("heading", name="API Key 元数据详情", exact=True).wait_for()
        body = self.page.locator("body").inner_text()
        self.assertIn("xk_safe", body)
        self.assertIn("all_snapshot", body)
        self.assertNotIn("DO-NOT-RENDER", body)
        self.assertNotIn("verification_digest", body)
        self.assertEqual([(call["method"], call["path"]) for call in self.custom_calls], [
            ("GET", f"/api/platform/v1/accounts/{desktop.ACCOUNT}/api-keys"),
            ("GET", f"/api/platform/v1/api-keys/{desktop.DEPLOYMENT}")])
        self.assertTrue(all("cookie" not in call["headers"] for call in self.custom_calls))

    def test_api_key_denied_has_real_denial_state_without_key_metadata(self):
        self.key_denied = True
        self.fixture.open()
        self.fixture.app("账户与权限").get_by_role("button", name="API Key 元数据", exact=True).click()
        self.page.locator('.window[data-app^="api-keys:"]').get_by_role("heading", name="无权限", exact=True).wait_for()
        self.assertNotIn("xk_safe", self.page.locator("body").inner_text())
        self.assertNotIn("DO-NOT-RENDER", self.page.locator("body").inner_text())

    def test_desktop_failure_redacts_server_error_messages(self):
        secret = "TOKEN=do-not-render-account-secret"
        self.key_error = (500, "INTERNAL_ERROR", secret)
        self.fixture.open()
        self.fixture.app("账户与权限").get_by_role("button", name="API Key 元数据", exact=True).click()
        window = self.page.locator('.window[data-app^="api-keys:"]')
        window.get_by_role("heading", name="请求失败", exact=True).wait_for()
        body = self.page.locator("body").inner_text()
        self.assertNotIn(secret, body)
        self.assertIn("INTERNAL_ERROR", window.inner_text())

    def test_list_section_pagination_retry_preserves_items_and_clears_error(self):
        key_first = {"id": desktop.DEPLOYMENT, "owner_id": desktop.ACCOUNT, "revision": 1,
                     "name": "First monitor", "prefix": "xk_first", "status": "active",
                     "issuer_credential_id": desktop.ACCOUNT, "created_at": desktop.NOW,
                     "updated_at": desktop.NOW, "last_used_at": None,
                     "inheritance": {"mode": "all_snapshot"}}
        key_second = {"id": "second-key-id", "owner_id": desktop.ACCOUNT, "revision": 1,
                      "name": "Second monitor", "prefix": "xk_second", "status": "active",
                      "issuer_credential_id": desktop.ACCOUNT, "created_at": desktop.NOW,
                      "updated_at": desktop.NOW, "last_used_at": None,
                      "inheritance": {"mode": "all_snapshot"}}
        self.key_pages = {
            None: {"items": [key_first], "next_cursor": "cursor-2"},
            "cursor-2": {"items": [key_second], "next_cursor": None},
        }
        self.fixture.open()
        self.fixture.app("账户与权限").get_by_role("button", name="API Key 元数据", exact=True).click()
        keys_window = self.page.locator('.window[data-app^="api-keys:"]')
        keys_window.get_by_role("heading", name="First monitor", exact=True).wait_for()
        more = keys_window.get_by_role("button", name="加载下一页API Key 元数据", exact=True)
        self.assertTrue(more.is_visible())

        # 1. Trigger failure on pagination
        self.key_error = (503, "UNAVAILABLE", "key database unavailable")
        more.click()
        keys_window.locator('.state[data-kind="unavailable"]').wait_for()
        self.assertEqual(keys_window.locator(".card").count(), 1)
        self.assertTrue(more.is_enabled())

        # 2. Trigger another failure on retry: error state should be replaced, not accumulated
        self.key_error = (500, "INTERNAL_ERROR", "internal failure")
        more.click()
        keys_window.locator('.state[data-kind="error"]').wait_for()
        self.assertEqual(keys_window.locator(".state[data-kind='error']").count(), 1)
        self.assertEqual(keys_window.locator(".card").count(), 1)

        # 3. Successful retry: loads second page, clears error state, hides more button
        self.key_error = None
        more.click()
        keys_window.get_by_role("heading", name="Second monitor", exact=True).wait_for()
        self.assertEqual(keys_window.locator(".card").count(), 2)
        self.assertEqual(keys_window.locator(".state").count(), 0)
        self.assertTrue(more.is_hidden())

    def test_toast_redacts_server_error_messages_across_actions(self):
        value = self.window_contribution("toast-redact")
        self.fixture.open()

        # 1. apiKeys detail button (getApiKey 500) redacts server error.message in #toast
        self.fixture.app("账户与权限").get_by_role("button", name="API Key 元数据", exact=True).click()
        keys_window = self.page.locator('.window[data-app^="api-keys:"]')
        keys_window.get_by_role("heading", name="Read-only monitor", exact=True).wait_for()
        secret_key = "TOKEN=toast-secret-api-key"
        self.key_error = (500, "INTERNAL_ERROR", secret_key)
        keys_window.get_by_role("button", name="读取密钥元数据", exact=True).click()
        self.page.locator("#toast").get_by_text("INTERNAL_ERROR", exact=False).wait_for()
        self.assertNotIn(secret_key, self.page.locator("body").inner_text())
        self.key_error = None
        keys_window.get_by_role("button", name="关闭API Key 元数据", exact=True).click()

        # 2. accounts toolbar action (getEffectivePermissions 403) redacts server error.message
        secret_perm = "TOKEN=toast-secret-effective-perms"
        self.account_action_error = (403, "PERMISSION_DENIED", secret_perm)
        self.fixture.app("账户与权限").get_by_role("button", name="有效权限与阻断祖先", exact=True).click()
        self.page.locator("#toast").get_by_text("PERMISSION_DENIED", exact=False).wait_for()
        self.assertNotIn(secret_perm, self.page.locator("body").inner_text())
        self.account_action_error = None

        # 3. launcher pin failure (503 UNAVAILABLE) redacts explicit server error message
        self.fail_preferences = 1
        self.open_launcher()
        self.page.locator("#app-search").fill(value["spec"]["title"])
        self.page.get_by_role("button", name="固定 " + value["spec"]["title"], exact=True).click()
        self.page.locator("#toast").get_by_text("UNAVAILABLE", exact=False).wait_for()
        self.assertNotIn("explicit component outage", self.page.locator("body").inner_text())
        self.page.locator("#launcher-close").click()

        # 4. Closing settings mid-flight aborts initial preference read without spurious toast
        self.page.evaluate("document.querySelector('#toast').textContent = ''")
        self.fixture.hold_preferences = True
        settings_win = self.fixture.app("设置")
        while not self.fixture.pending_preferences:
            self.page.wait_for_timeout(10)
        settings_win.get_by_role("button", name="关闭设置", exact=True).click()
        self.fixture.hold_preferences = False
        pending = self.fixture.pending_preferences.pop()
        self.reply(pending, {"error": {"code": "UNAVAILABLE", "message": "secret-after-settings-close"}}, 503)
        self.page.wait_for_timeout(120)
        self.assertEqual(self.page.locator("#toast").inner_text(), "")
        self.assertNotIn("secret-after-settings-close", self.page.locator("body").inner_text())

    def test_widget_removal_during_load_prevents_stale_mount_and_polling(self):
        value = contribution("stale_widget", "widget")
        value["spec"]["refresh_interval_seconds"] = 30
        value["contribution_digest"] = "sha256:" + hashlib.sha256(
            json.dumps(value["spec"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.fixture.contributions["stale_widget"] = value
        self.fixture.open()

        self.open_launcher()
        self.page.get_by_role("button", name="启动插件页面", exact=True).click()
        listing = self.page.locator('.window[data-app="contributions"]')
        listing.get_by_role("heading", name="Independent fixture", exact=True).wait_for()

        # Part 1: Hold getUiContribution during renderWidgets(), then remove the widget before mountContribution runs.
        self.arm_hold_widget_after_put = True
        listing.get_by_role("button", name="添加桌面组件", exact=True).click()
        listing.get_by_role("button", name="关闭插件页面", exact=True).click()
        card = self.page.locator("#widgets .widget-card")
        card.wait_for(state="visible")
        while not self.held_widget_routes:
            self.page.wait_for_timeout(10)
        card.get_by_role("button", name="移除", exact=True).click()
        self.page.wait_for_function("() => document.querySelectorAll('#widgets .widget-card').length === 0")

        self.hold_widget_lookup = False
        for held in self.held_widget_routes:
            try:
                held.fallback()
            except Exception:
                pass
        self.held_widget_routes.clear()
        self.page.wait_for_timeout(150)

        self.assertEqual(self.page.locator("#widgets .widget-card").count(), 0)
        self.assertEqual(self.page.locator("#widgets iframe").count(), 0)
        self.assertFalse(any("/installations/" in call["path"] for call in self.fixture.calls))
        self.assertEqual(self.page.locator("#toast").inner_text(), "")

        # Part 2: Mount the widget with refresh_interval_seconds=30, remove it while verifyPureWidget fetches
        # getInstallation, and confirm no getSkill polling verification or DOM mutation continues afterward.
        self.open_launcher()
        self.page.get_by_role("button", name="启动插件页面", exact=True).click()
        listing = self.page.locator('.window[data-app="contributions"]')
        listing.get_by_role("heading", name="Independent fixture", exact=True).wait_for()
        self.hold_installation = True
        listing.get_by_role("button", name="添加桌面组件", exact=True).click()
        listing.get_by_role("button", name="关闭插件页面", exact=True).click()
        card = self.page.locator("#widgets .widget-card")
        card.wait_for(state="visible")
        while not self.held_installation_routes:
            self.page.wait_for_timeout(10)
        card.get_by_role("button", name="移除", exact=True).click()
        self.page.wait_for_function("() => document.querySelectorAll('#widgets .widget-card').length === 0")

        self.hold_installation = False
        for held in self.held_installation_routes:
            try:
                self.reply(held, {"error": {"code": "UNAVAILABLE", "message": "late"}}, 503)
            except Exception:
                pass
        self.held_installation_routes.clear()
        self.page.wait_for_timeout(150)

        self.assertEqual(self.page.locator("#widgets .widget-card").count(), 0)
        self.assertEqual(self.page.locator("#widgets iframe").count(), 0)
        self.assertFalse(any("/skills/" in call["path"] for call in self.fixture.calls))
        self.assertEqual(self.page.locator("#toast").inner_text(), "")

    def test_account_lookup_ignores_stale_response_and_api_keys_window_not_persisted(self):
        slow_id = "00000000-0000-4000-8000-00000000000a"
        fast_id = "00000000-0000-4000-8000-00000000000b"
        self.hold_account_ids.add(slow_id)
        self.fast_accounts[fast_id] = {"id": fast_id, "display_name": "Fresh Fast Account", "status": "active"}

        self.fixture.open()
        accounts_win = self.fixture.app("账户与权限")
        accounts_win.get_by_role("heading", name="Component account · active", exact=True).wait_for()
        uuid_input = accounts_win.get_by_label("账户 UUID")
        read_btn = accounts_win.get_by_role("button", name="读取", exact=True)

        uuid_input.fill(slow_id)
        read_btn.click()
        while slow_id not in self.held_account_routes:
            self.page.wait_for_timeout(10)

        uuid_input.fill(fast_id)
        read_btn.click()
        accounts_win.get_by_text("Fresh Fast Account · active", exact=True).wait_for()

        self.hold_account_ids.discard(slow_id)
        self.reply(self.held_account_routes.pop(slow_id), {"id": slow_id, "display_name": "Stale Slow Account", "status": "active"})
        self.page.wait_for_timeout(120)

        self.assertIn("Fresh Fast Account", accounts_win.inner_text())
        self.assertNotIn("Stale Slow Account", accounts_win.inner_text())

        # Opening API Key 元数据 creates an ephemeral window excluded from persisted localStorage layout.
        accounts_win.get_by_role("button", name="API Key 元数据", exact=True).click()
        self.page.locator('.window[data-app^="api-keys:"]').wait_for()
        saved_apps = self.page.evaluate("""() => {
          const layouts = [];
          for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            if (k && k.startsWith('xelab:windows:')) layouts.push(...JSON.parse(localStorage.getItem(k) || '[]'));
          }
          return layouts.map(item => item.app);
        }""")
        self.assertFalse(any(app.startswith("api-keys:") for app in saved_apps), saved_apps)

    def test_invalid_operation_uuid_shows_local_validation_without_a_core_request(self):
        self.fixture.open()
        self.open_launcher()
        self.page.get_by_role("button", name="启动任务与知识库", exact=True).click()
        window = self.page.locator('.window[data-app="tasks"]')
        window.get_by_role("textbox", name="Operation UUID", exact=True).fill("not-a-valid-uuid")
        window.get_by_role("button", name="查询 Operation", exact=True).click()
        error = window.locator('.state[data-kind="error"]')
        error.get_by_role("heading", name="请求失败", exact=True).wait_for()
        self.assertIn("INVALID_ARGUMENT · 无效的请求参数。", error.inner_text())
        self.assertFalse(any(call["path"].startswith("/api/platform/v1/operations/")
                             for call in self.fixture.calls))


if __name__ == "__main__":
    unittest.main()
