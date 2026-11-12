#!/usr/bin/env python3
"""Chromium component tests for the read-only overview window (issue #14).

Reuses the routed desktop fixture from test_browser.py and layers a second
Playwright route over the three public overview endpoints with explicit
component fixtures. These are component tests, not core/OCI acceptance.
Run from the repository root:

    XELAB_OAUTH_BROWSER_CHROMIUM=<chromium-151> python3 examples/webui/test_overview.py
"""
import json
import unittest
from urllib.parse import parse_qs, urlparse

import test_browser as desktop
from playwright.sync_api import expect

SHELL = desktop.SHELL
CORE = desktop.CORE
ACCOUNT = desktop.ACCOUNT
DEPLOYMENT = desktop.DEPLOYMENT
NODE = "00000000-0000-4000-8000-00000000000a"
INSTANCE = "00000000-0000-4000-8000-00000000000b"
INSTANCE_2 = "00000000-0000-4000-8000-00000000000c"
DEPLOYMENT_2 = "00000000-0000-4000-8000-00000000000d"
NOW = "2026-11-12T00:00:00Z"
NODE_PATH = "/api/platform/v1/node"
DEPLOYMENTS_PATH = "/api/platform/v1/deployments"
INSTANCES_PATH = "/api/platform/v1/instances"
OVERVIEW_PATHS = (NODE_PATH, DEPLOYMENTS_PATH, INSTANCES_PATH)


def node_status(**overrides):
    data = {"id": NODE, "revision": 3, "created_at": NOW, "updated_at": NOW,
            "config": {"kernel_cpu_millis": 4000, "kernel_memory_bytes": 17179869184,
                       "system_cpu_millis": 1000, "system_memory_bytes": 2147483648,
                       "shutdown_grace_ms": 30000, "profile": "component"},
            "host_cpu_millis": 16000, "host_memory_bytes": 68719476736,
            "plugin_cpu_pool_millis": 11000, "plugin_memory_pool_bytes": 49392123904,
            "reserved_cpu_millis": 2500, "reserved_memory_bytes": 8589934592,
            "admission_enabled": True,
            # Fields a broken backend might attach; the whitelist must drop them.
            "token": "secret-node-token", "internal_path": "/var/lib/xelab/private"}
    data.update(overrides)
    return data


def deployment_item(identifier=DEPLOYMENT, name="fixture deployment", phase="ready", enabled=True):
    return {"id": identifier, "revision": 1, "created_at": NOW, "updated_at": NOW,
            "spec": {"display_name": name, "enabled": enabled, "replicas": 2,
                     "installation_id": ACCOUNT,
                     "limits": {"cpu_millis": 500, "memory_bytes": 536870912,
                                "ephemeral_bytes": 268435456, "pids": 128},
                     "config": {"secret_key": "do-not-render"}, "volume_ids": [ACCOUNT]},
            "observed_generation": 1, "phase": phase, "conditions": ["Available"]}


def instance_item(identifier=INSTANCE, deployment=DEPLOYMENT, phase="ready", health="alive"):
    return {"id": identifier, "revision": 1, "created_at": NOW, "updated_at": NOW,
            "deployment_id": deployment, "generation": 1,
            "runtime_id": "containerd://private-runtime-id", "phase": phase, "health": health,
            "limits": {"cpu_millis": 500, "memory_bytes": 536870912,
                       "ephemeral_bytes": 268435456, "pids": 128},
            "last_heartbeat_at": NOW, "restart_count": 0}


class OverviewWindow(unittest.TestCase):
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
        self.node_fixture = node_status()
        self.deployment_pages = [{"items": [deployment_item()]}]
        self.instance_pages = [{"items": [instance_item()]}]
        self.overview_status = {}
        # Playwright runs the most recently registered route first; anything
        # not handled here falls back to the base desktop fixture.
        self.page.route("**/*", self.overview_route)

    def tearDown(self):
        self.fixture.tearDown()

    def count(self, path):
        return sum(call["path"] == path for call in self.fixture.calls)

    def open(self, authenticated=True):
        self.fixture.open(authenticated=authenticated)

    def app(self, name):
        return self.fixture.app(name)

    def overview_route(self, route):
        request = route.request
        url = urlparse(request.url)
        if (f"{url.scheme}://{url.netloc}" != CORE or request.method != "GET"
                or url.path not in OVERVIEW_PATHS):
            route.fallback()
            return
        self.fixture.calls.append({"method": request.method, "path": url.path,
                                   "headers": request.all_headers(), "body": request.post_data})
        headers = {"access-control-allow-origin": SHELL,
                   "access-control-allow-headers": "authorization,content-type,if-match,idempotency-key",
                   "access-control-allow-methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
                   "access-control-expose-headers": "etag,x-request-id",
                   "etag": '"rev-1"', "x-request-id": ACCOUNT}
        if url.path in self.overview_status:
            status, code = self.overview_status[url.path]
            route.fulfill(status=status, headers=headers, content_type="application/json",
                          body=json.dumps({"error": {"code": code, "message": "fixture overview failure", "retryable": False}}))
            return
        if url.path == NODE_PATH:
            data = self.node_fixture
        else:
            pages = self.deployment_pages if url.path == DEPLOYMENTS_PATH else self.instance_pages
            cursor = parse_qs(url.query).get("cursor", [None])[0]
            data = None
            for index, page in enumerate(pages):
                expected = None if index == 0 else f"page-{index}"
                if cursor == expected:
                    data = {"items": page["items"],
                            "next_cursor": f"page-{index + 1}" if index + 1 < len(pages) else None}
                    break
            if data is None:
                route.fulfill(status=400, headers=headers, content_type="application/json",
                              body=json.dumps({"error": {"code": "INVALID_ARGUMENT", "message": "unknown fixture cursor", "retryable": False}}))
                return
        route.fulfill(status=200, headers=headers, content_type="application/json", body=json.dumps(data))

    def open_overview(self):
        window = self.app("总览")
        window.locator(".overview-section[data-section=node] .overview-facts dd").first.wait_for()
        window.locator(".overview-section[data-section=deployments] .overview-body .card, .overview-section[data-section=deployments] .overview-body .state").first.wait_for()
        window.locator(".overview-section[data-section=instances] .overview-body .card, .overview-section[data-section=instances] .overview-body .state").first.wait_for()
        return window

    def section(self, window, key):
        return window.locator(f".overview-section[data-section={key}]")

    def test_success_sources_read_time_and_whitelist(self):
        self.open()
        window = self.open_overview()
        for key, source, title in (("node", "getNode", "节点资源"), ("deployments", "listDeployments", "部署"), ("instances", "listInstances", "实例")):
            section = self.section(window, key)
            self.assertIn(f"来源 {source}", section.locator(".overview-source").inner_text())
            self.assertRegex(section.locator(".overview-read-at").inner_text(), r"^读取于 \d{2}:\d{2}:\d{2}$")
            expect(section.get_by_role("button", name=f"刷新{title}")).to_be_visible()
        facts = self.section(window, "node").inner_text()
        for expected in ("宿主 CPU（毫核）", "16000", "插件 CPU 池（毫核）", "11000", "准入控制", "是",
                         "内核与系统预留", "运行 Profile", "component", "内核预留 CPU（毫核）", "4000"):
            self.assertIn(expected, facts)
        deployments = self.section(window, "deployments").inner_text()
        for expected in ("fixture deployment", "ready", "已启用", "副本 2", "Available", DEPLOYMENT):
            self.assertIn(expected, deployments)
        instances = self.section(window, "instances").inner_text()
        for expected in ("ready", "alive", "重启次数 0", f"最近心跳 {NOW}", INSTANCE):
            self.assertIn(expected, instances)
        self.assertIn("无历史趋势、全局总数或实时监控", window.locator(".overview-note").inner_text())
        text = window.inner_text()
        for forbidden in ("secret-node-token", "/var/lib/xelab/private", "do-not-render",
                          "secret_key", "private-runtime-id", "containerd://", "volume_ids"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(window.locator("pre.result").count(), 0)
        self.assertEqual(self.count(NODE_PATH), 1)
        self.assertEqual(self.count(DEPLOYMENTS_PATH), 1)
        self.assertEqual(self.count(INSTANCES_PATH), 1)

    def test_hostile_names_render_as_text(self):
        self.deployment_pages = [{"items": [deployment_item(name='<img src=x onerror="alert(1)">')]}]
        self.open()
        window = self.open_overview()
        self.assertIn('<img src=x onerror="alert(1)">', self.section(window, "deployments").inner_text())
        self.assertEqual(window.locator("img").count(), 0)

    def test_anonymous_shows_login_required_without_business_calls(self):
        self.open(authenticated=False)
        window = self.app("总览")
        expect(window.locator(".state[data-kind=denied]")).to_be_visible()
        self.assertIn("登录后继续", window.inner_text())
        for path in OVERVIEW_PATHS:
            self.assertEqual(self.count(path), 0)

    def test_partial_failure_sections_stay_independent(self):
        self.overview_status[NODE_PATH] = (403, "PERMISSION_DENIED")
        self.overview_status[INSTANCES_PATH] = (503, "NOT_READY")
        self.open()
        window = self.app("总览")
        expect(self.section(window, "node").locator(".state[data-kind=denied]")).to_be_visible()
        expect(self.section(window, "instances").locator(".state[data-kind=unavailable]")).to_be_visible()
        self.section(window, "deployments").locator(".card").wait_for()
        self.assertIn("无权限", self.section(window, "node").inner_text())
        self.assertIn("当前不可用", self.section(window, "instances").inner_text())
        self.assertIn("fixture deployment", self.section(window, "deployments").inner_text())
        self.assertEqual(self.section(window, "node").locator(".overview-read-at").inner_text(), "读取失败")
        # Recover only the node section; unrelated sections must not be reissued.
        del self.overview_status[NODE_PATH]
        self.section(window, "node").get_by_role("button", name="刷新节点资源").click()
        self.section(window, "node").locator(".overview-facts dd").first.wait_for()
        self.assertEqual(self.count(NODE_PATH), 2)
        self.assertEqual(self.count(DEPLOYMENTS_PATH), 1)
        self.assertEqual(self.count(INSTANCES_PATH), 1)
        self.assertIn("当前不可用", self.section(window, "instances").inner_text())

    def test_empty_lists_have_their_own_state(self):
        self.deployment_pages = [{"items": []}]
        self.instance_pages = [{"items": []}]
        self.open()
        window = self.open_overview()
        for key in ("deployments", "instances"):
            section = self.section(window, key)
            expect(section.locator(".state[data-kind=empty]")).to_be_visible()
            self.assertIn("暂无可见项目", section.inner_text())
            self.assertEqual(section.get_by_role("button", name=f"加载下一页{'部署' if key == 'deployments' else '实例'}").count(), 0)
        expect(self.section(window, "node").locator(".overview-facts").first).to_be_visible()

    def test_pagination_appends_and_exhausts(self):
        self.deployment_pages = [{"items": [deployment_item(), deployment_item(identifier=DEPLOYMENT_2, name="second deployment", phase="disabled", enabled=False)]},
                                 {"items": [deployment_item(identifier=INSTANCE, name="third deployment")]}]
        self.instance_pages = [{"items": [instance_item()]},
                               {"items": [instance_item(identifier=INSTANCE_2, phase="pending", health="unknown")]}]
        self.open()
        window = self.open_overview()
        deployments = self.section(window, "deployments")
        self.assertIn("仅显示当前已取到的项目；还有更多可加载。", deployments.locator(".overview-page-hint").inner_text())
        more = deployments.get_by_role("button", name="加载下一页部署")
        expect(more).to_be_visible()
        more.click()
        deployments.locator(".card").nth(2).wait_for()
        self.assertEqual(deployments.locator(".card").count(), 3)
        self.assertIn("third deployment", deployments.inner_text())
        expect(more).to_be_hidden()
        self.assertIn("已加载全部可见项目。", deployments.locator(".overview-page-hint").inner_text())
        self.assertEqual(self.count(DEPLOYMENTS_PATH), 2)
        self.assertEqual(self.count(INSTANCES_PATH), 1)
        instances = self.section(window, "instances")
        instances.get_by_role("button", name="加载下一页实例").click()
        instances.locator(".card").nth(1).wait_for()
        self.assertEqual(instances.locator(".card").count(), 2)
        self.assertIn("pending", instances.inner_text())
        self.assertEqual(self.count(INSTANCES_PATH), 2)
        self.assertEqual(self.count(NODE_PATH), 1)

    def test_pagination_failure_keeps_loaded_items(self):
        self.deployment_pages = [{"items": [deployment_item()]},
                                 {"items": [deployment_item(identifier=DEPLOYMENT_2, name="second page")]}]
        self.open()
        window = self.open_overview()
        deployments = self.section(window, "deployments")
        self.overview_status[DEPLOYMENTS_PATH] = (403, "PERMISSION_DENIED")
        deployments.get_by_role("button", name="加载下一页部署").click()
        expect(deployments.locator(".state[data-kind=denied]")).to_be_visible()
        self.assertEqual(deployments.locator(".card").count(), 1)
        self.assertIn("fixture deployment", deployments.inner_text())
        self.assertIn("下一页读取失败；已加载内容保持不变。", deployments.locator(".overview-page-hint").inner_text())
        expect(deployments.get_by_role("button", name="加载下一页部署")).to_be_enabled()

    def test_section_and_window_refresh_isolation(self):
        self.open()
        window = self.open_overview()
        self.section(window, "node").get_by_role("button", name="刷新节点资源").click()
        self.page.wait_for_function("document.querySelectorAll('.overview-section[data-section=node] .overview-facts dd').length > 0")
        self.assertEqual((self.count(NODE_PATH), self.count(DEPLOYMENTS_PATH), self.count(INSTANCES_PATH)), (2, 1, 1))
        self.section(window, "deployments").get_by_role("button", name="刷新部署").click()
        self.page.wait_for_function("document.querySelectorAll('.overview-section[data-section=deployments] .card').length > 0")
        self.assertEqual((self.count(NODE_PATH), self.count(DEPLOYMENTS_PATH), self.count(INSTANCES_PATH)), (2, 2, 1))
        window.locator(".window-toolbar").get_by_role("button", name="刷新总览", exact=True).click()
        self.page.wait_for_function("document.querySelectorAll('.overview-section[data-section=instances] .card').length > 0")
        self.assertEqual((self.count(NODE_PATH), self.count(DEPLOYMENTS_PATH), self.count(INSTANCES_PATH)), (3, 3, 2))

    def test_theme_and_viewport_changes_do_not_reissue_calls(self):
        self.open()
        self.open_overview()
        before = tuple(self.count(path) for path in OVERVIEW_PATHS)
        self.page.emulate_media(color_scheme="dark")
        self.page.set_viewport_size({"width": 390, "height": 844})
        self.page.wait_for_timeout(200)
        self.page.set_viewport_size({"width": 1280, "height": 900})
        self.page.emulate_media(color_scheme="light")
        self.page.wait_for_timeout(200)
        self.assertEqual(tuple(self.count(path) for path in OVERVIEW_PATHS), before)

    def test_narrow_screen_stacks_without_overflow(self):
        self.page.set_viewport_size({"width": 390, "height": 844})
        self.open()
        window = self.open_overview()
        overflow = self.page.evaluate("""() => {
            const content = document.querySelector('.window[data-app=overview] .window-content');
            return {document: document.documentElement.scrollWidth - window.innerWidth,
                    content: content.scrollWidth - content.clientWidth};
        }""")
        self.assertLessEqual(overflow["document"], 1)
        self.assertLessEqual(overflow["content"], 1)
        tops = self.page.evaluate("""() => [...document.querySelectorAll('.overview-section')].map(el => el.getBoundingClientRect().top)""")
        self.assertEqual(len(tops), 3)
        self.assertLess(tops[0], tops[1])
        self.assertLess(tops[1], tops[2])
        self.section(window, "node").get_by_role("button", name="刷新节点资源").click()
        self.page.wait_for_function("document.querySelectorAll('.overview-section[data-section=node] .overview-facts dd').length > 0")
        self.assertEqual(self.count(NODE_PATH), 2)

    def test_keyboard_tab_focus_and_activation(self):
        self.deployment_pages = [{"items": [deployment_item()]},
                                 {"items": [deployment_item(identifier=DEPLOYMENT_2, name="keyboard page")]}]
        self.open()
        window = self.open_overview()
        window.locator(".window-title").focus()
        reached = False
        for _ in range(30):
            self.page.keyboard.press("Tab")
            label = self.page.evaluate("document.activeElement?.getAttribute('aria-label') || ''")
            if label == "刷新节点资源":
                reached = True
                break
        self.assertTrue(reached, "node refresh button must be reachable by Tab")
        outline = self.page.evaluate("getComputedStyle(document.activeElement).outlineStyle")
        self.assertEqual(outline, "solid")
        self.page.keyboard.press("Enter")
        self.page.wait_for_function("document.querySelectorAll('.overview-section[data-section=node] .overview-facts dd').length > 0")
        self.assertEqual(self.count(NODE_PATH), 2)
        more = self.section(window, "deployments").get_by_role("button", name="加载下一页部署")
        more.focus()
        self.page.keyboard.press("Space")
        self.section(window, "deployments").locator(".card").nth(1).wait_for()
        self.assertIn("keyboard page", self.section(window, "deployments").inner_text())
        self.assertEqual(self.count(DEPLOYMENTS_PATH), 2)

    def test_expired_session_fails_closed(self):
        self.overview_status[NODE_PATH] = (401, "INVALID_CREDENTIAL")
        self.open()
        self.page.get_by_role("button", name="打开总览", exact=True).click()
        # The 401 tears the private views down immediately; waiting for the
        # window to appear first would race that teardown.
        expect(self.page.locator("#welcome")).to_be_visible()
        self.assertGreaterEqual(self.count(NODE_PATH), 1)
        self.assertEqual(self.page.locator(".window[data-app=overview]").count(), 0)
        self.assertEqual(self.page.locator(".overview-section").count(), 0)

    def test_launcher_search_and_layout_restore(self):
        self.open()
        self.page.locator("#launcher-toggle").click()
        self.page.locator("#app-search").fill("总览")
        self.page.get_by_role("button", name="启动总览", exact=True).click()
        window = self.page.locator(".window[data-app=overview]")
        window.locator(".overview-section[data-section=node] .overview-facts dd").first.wait_for()
        self.page.reload()
        self.page.locator(".dock button").first.wait_for()
        self.page.get_by_role("button", name="退出", exact=True).wait_for()
        restored = self.page.locator(".window[data-app=overview]")
        restored.locator(".overview-section[data-section=node] .overview-facts dd").first.wait_for()
        self.assertEqual(restored.locator(".overview-section").count(), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)