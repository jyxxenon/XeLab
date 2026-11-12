#!/usr/bin/env python3
"""Real Chromium checks for the desktop shell visual contract.

These tests lock the presentation rules introduced by the shell visual slices
(tokens, blur scope, transparency/motion preferences, icon set, window control
hit targets and narrow-viewport sizing) without asserting pixel values, so the
visual layer can evolve as long as the contract holds. They run the actual
desktop shell with the explicit core response fixtures from test_browser, not
Core/OCI acceptance.
"""
import unittest

import test_browser as desktop


class ShellVisual(unittest.TestCase):
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

    def tearDown(self):
        self.fixture.tearDown()

    def open(self, mode="light"):
        self.fixture.saved["spec"]["theme"]["mode"] = mode
        self.fixture.open()

    def style(self, selector, pseudo=None):
        return self.page.evaluate(
            "([selector, pseudo]) => {const el = document.querySelector(selector);"
            " return getComputedStyle(el, pseudo || null);}",
            [selector, pseudo],
        )

    def test_shell_tokens_derive_from_theme_in_light_and_dark(self):
        for mode in ("light", "dark"):
            self.open(mode)
            variables = self.page.evaluate(
                "() => {const style = getComputedStyle(document.documentElement);"
                " return ['--shell-radius', '--shell-border', '--ease-shell', '--menubar-h']"
                "  .map(name => [name, style.getPropertyValue(name).trim()]);}"
            )
            tokens = dict(variables)
            self.assertEqual(tokens["--shell-radius"], "14px", mode)
            self.assertEqual(tokens["--menubar-h"], "46px", mode)
            self.assertIn("cubic-bezier", tokens["--ease-shell"], mode)
            self.assertIn("color-mix", tokens["--shell-border"], mode)
            menubar = self.style(".menubar")
            self.assertNotEqual(menubar["backdropFilter"], "none", mode)
            dock = self.style("#dock")
            self.assertNotEqual(dock["backdropFilter"], "none", mode)
            self.assertIn("radial-gradient", self.style("#desktop")["backgroundImage"], mode)
            self.assertEqual(self.page.evaluate(
                "() => getComputedStyle(document.querySelector('#desktop')).height"),
                "854px", "desktop fills the viewport below the menu bar in " + mode,
            )

    def test_shell_stylesheets_are_linked_in_order(self):
        self.open()
        sheets = self.page.evaluate(
            "() => [...document.styleSheets].map(sheet => (sheet.href || '').split('/').pop())")
        self.assertEqual(sheets[:4], ["styles.css", "desktop.css", "components.css", "motion.css"])
        for name in ("desktop.css", "components.css", "motion.css"):
            status = self.page.evaluate("""async (name) => {
              const response = await fetch('/ui/org.xelab.webui/' + name);
              return {status: response.status, type: response.headers.get('content-type') || ''};
            }""", name)
            self.assertEqual(status["status"], 200, name)
            self.assertIn("css", status["type"], name)
        # The split must not change the cascade: shell and component rules still resolve.
        self.assertEqual(self.style("#dock")["borderRadius"], "20px")
        self.fixture.app("系统状态")
        self.assertEqual(self.style(".window")["borderRadius"], "14px")

    def test_index_referenced_assets_all_resolve(self):
        self.open()
        references = self.page.evaluate(
            "() => [...document.querySelectorAll('link[rel=stylesheet], script[src]')]"
            "  .map(element => element.getAttribute('href') || element.getAttribute('src'))")
        self.assertGreaterEqual(len(references), 5)
        missing = self.page.evaluate("""async (references) => {
          const failed = [];
          for (const reference of references) {
            const response = await fetch(reference);
            if (!response.ok) failed.push(reference + ':' + response.status);
          }
          return failed;
        }""", references)
        self.assertEqual(missing, [], "every stylesheet and script referenced by index.html must load")

    def test_closing_a_window_hands_focus_back_to_the_desktop(self):
        self.open()
        self.fixture.app("系统状态")
        settings = self.fixture.app("设置")
        settings.get_by_role("button", name="关闭设置").click()
        self.page.wait_for_function("() => document.querySelectorAll('.window').length === 1")
        active = self.page.evaluate("() => {const el = document.activeElement;"
                                    " return el.classList.contains('window-title') ? el.closest('.window').dataset.app : el.tagName;}")
        self.assertEqual(active, "resources", "focus should move into the remaining window")

        self.page.locator('.window[data-app="resources"]').get_by_role("button", name="关闭系统状态").click()
        self.page.wait_for_function("() => document.querySelectorAll('.window').length === 0")
        self.assertEqual(
            self.page.evaluate("() => document.activeElement.getAttribute('data-app-id')"),
            "resources",
            "closing the last window should return focus to its Dock button")

    def test_launcher_manages_keyboard_focus(self):
        self.open()
        trigger = self.page.get_by_role("button", name="打开应用启动器", exact=True)
        trigger.click()
        self.page.locator("#launcher").wait_for(state="visible")
        self.assertEqual(self.page.evaluate("document.activeElement.id"), "app-search")
        self.page.keyboard.press("Escape")
        self.page.wait_for_function("() => !document.querySelector('#launcher').open")
        self.assertEqual(
            self.page.evaluate("document.activeElement.getAttribute('aria-label')"),
            "打开应用启动器")
        trigger.press("Enter")
        self.page.locator("#launcher").wait_for(state="visible")
        self.assertEqual(self.page.evaluate("document.activeElement.id"), "app-search")
        self.page.get_by_role("button", name="启动设置", exact=True).click()
        self.page.locator('.window[data-app="settings"]').wait_for()
        self.assertIn("window-title", self.page.evaluate("document.activeElement.className"))

    def test_desktop_wallpaper_is_served_and_applied(self):
        self.open()
        background = self.style("#desktop")["backgroundImage"]
        self.assertIn("wallpaper.svg", background)
        status = self.page.evaluate("""async () => {
          const response = await fetch('/ui/org.xelab.webui/wallpaper.svg');
          return {status: response.status, type: response.headers.get('content-type') || ''};
        }""")
        self.assertEqual(status["status"], 200)
        self.assertIn("svg", status["type"])
        self.assertIn("cover", self.style("#desktop")["backgroundSize"])

    def test_custom_theme_color_scheme_follows_its_desktop_token(self):
        self.open()
        settings = self.fixture.app("设置")
        settings.get_by_label("主题模式", exact=True).select_option("custom")
        desktop = settings.get_by_label("自定义 desktop", exact=True)
        for colour, expected in (("#0B1020", "dark"), ("#F5F7FB", "light")):
            desktop.evaluate(
                "(input, colour) => { input.value = colour; input.dispatchEvent(new Event('input', {bubbles: true})); }",
                colour)
            self.page.wait_for_function(
                "(expected) => document.documentElement.style.colorScheme === expected",
                arg=expected)

    def test_reduced_transparency_removes_shell_blur(self):
        self.open()
        self.page.evaluate("() => document.documentElement.classList.add('reduced-transparency')")
        for selector in (".menubar", "#dock"):
            style = self.style(selector)
            self.assertEqual(style["backdropFilter"], "none", selector)
            self.assertNotIn("rgba(255, 255, 255, 0.8", style["backgroundColor"], selector)

    def test_reduced_motion_disables_shell_transitions(self):
        self.open()
        self.page.evaluate("() => document.documentElement.classList.add('reduced-motion')")
        self.assertEqual(self.style("#dock")["transitionDuration"], "0s")
        self.assertEqual(self.style("#dock")["animationName"], "none")

    def test_dock_and_launcher_use_icon_set_without_text_glyphs(self):
        self.open()
        self.assertGreaterEqual(self.page.locator("#dock svg.app-glyph").count(), 6)
        for icon in self.page.locator("#dock .app-icon").all():
            self.assertEqual(icon.text_content(), "")
            self.assertEqual(icon.locator("svg").count(), 1)
        self.page.get_by_role("button", name="打开应用启动器", exact=True).click()
        self.page.locator("#launcher").wait_for(state="visible")
        self.assertGreaterEqual(self.page.locator("#app-grid .app-icon svg").count(), 8)
        self.assertGreaterEqual(self.page.locator("#launcher svg.app-glyph").count(), 8)
        launcher_icon = self.style("#app-grid .app-icon")
        self.assertEqual(launcher_icon["display"], "grid")
        centered = self.page.evaluate(
            "() => {"
            " const box = document.querySelector('#app-grid .app-icon').getBoundingClientRect();"
            " const svg = document.querySelector('#app-grid .app-icon svg').getBoundingClientRect();"
            " return Math.abs((svg.left - box.left) - (box.right - svg.right)) <= 1.5"
            "  && Math.abs((svg.top - box.top) - (box.bottom - svg.bottom)) <= 1.5;"
            "}"
        )
        self.assertTrue(centered, "launcher app-icon svg must be centered inside its 42x42 tile")

    def test_window_toolbars_and_scrollbars_align_with_shell_tokens(self):
        self.open()
        window = self.fixture.app("插件中心")
        window.locator(".window-content > .toolbar").wait_for()
        header_toolbar = self.style(".window-content > .toolbar")
        self.assertEqual(header_toolbar["borderBottomStyle"], "solid")
        self.assertEqual(header_toolbar["borderBottomWidth"], "1px")
        self.assertEqual(header_toolbar["paddingBottom"], "14px")
        self.assertEqual(self.style(".window-content .toolbar h2")["fontSize"], "17px")
        self.assertEqual(self.style(".window-content .toolbar button")["minHeight"], "32px")
        card_toolbar = self.style(".window-content .card .toolbar")
        self.assertEqual(card_toolbar["borderTopStyle"], "solid")
        self.assertEqual(card_toolbar["borderTopWidth"], "1px")
        self.assertEqual(card_toolbar["paddingTop"], "10px")
        has_scrollbar_and_active = self.page.evaluate(
            "() => {"
            " const texts = [...document.styleSheets].flatMap(s => [...s.cssRules].map(r => r.cssText));"
            " return texts.some(t => t.includes('::-webkit-scrollbar-thumb')) && texts.some(t => t.includes('.primary:active'));"
            "}"
        )
        self.assertTrue(has_scrollbar_and_active)

    def test_window_controls_keep_hit_target_and_reveal_symbols(self):
        self.open()
        self.fixture.app("系统状态")
        control = self.page.locator(".window-controls button").first
        self.assertEqual(control.evaluate("el => getComputedStyle(el).width"), "24px")
        self.assertEqual(control.evaluate("el => getComputedStyle(el).height"), "24px")
        self.assertNotEqual(self.style(".window-controls button", "::before")["backgroundColor"], "rgba(0, 0, 0, 0)")
        self.assertEqual(self.style(".window-controls button", "::after")["opacity"], "0")
        control.hover()
        # The symbol fades in; wait for the transition instead of sampling it.
        self.page.wait_for_function(
            "() => getComputedStyle(document.querySelector('.window-controls button'), '::after').opacity === '1'",
            timeout=2000,
        )

    def test_shell_motion_is_finite_and_reducible(self):
        self.open()
        self.fixture.app("系统状态")
        window = self.page.locator(".window").last
        self.assertEqual(window.evaluate("el => getComputedStyle(el).animationName"), "shell-window-in")
        self.assertEqual(window.evaluate("el => getComputedStyle(el).animationDuration"), "0.16s")
        self.assertTrue(self.page.evaluate(
            "() => [...document.querySelectorAll('*')].every(el => {"
            " const style = getComputedStyle(el);"
            " return style.animationIterationCount !== 'infinite';})"),
            "the shell must not run an endless decorative animation",
        )
        self.page.evaluate("() => document.documentElement.classList.add('reduced-motion')")
        self.assertEqual(window.evaluate("el => getComputedStyle(el).animationName"), "none")

    def test_narrow_viewport_has_no_overflow_and_scales_icons(self):
        self.open()
        self.page.set_viewport_size({"width": 390, "height": 760})
        self.assertLessEqual(self.page.evaluate("document.documentElement.scrollWidth"), 390)
        self.assertEqual(self.style("#dock svg")["width"], "16px")
        self.assertEqual(self.page.evaluate(
            "() => getComputedStyle(document.querySelector('.menubar')).height"), "44px")

    def open_builtin(self, title, launcher=False):
        if launcher:
            self.page.get_by_role("button", name="打开应用启动器", exact=True).click()
            self.page.get_by_role("button", name=f"启动{title}", exact=True).click()
        else:
            self.fixture.app(title)
        window = self.page.locator(".window").last
        window.locator("[data-window-toolbar]").wait_for()
        return window

    def test_builtin_windows_share_a_window_toolbar_and_named_actions(self):
        self.open()
        windows = [
            ("总览", "总览", False), ("插件中心", "插件中心", False),
            ("Skill", "Skill 浏览器", False), ("账户与权限", "账户与权限", False),
            ("系统状态", "资源与系统状态", False), ("设置", "桌面设置", False),
            ("UI 客户端", "UI 客户端", True), ("插件页面", "插件页面", True),
            ("任务与知识库", "任务与能力", True),
        ]
        for window_name, title, launcher in windows:
            with self.subTest(window=window_name):
                window = self.open_builtin(window_name, launcher=launcher)
                toolbar = window.locator("[data-window-toolbar]")
                self.assertEqual(toolbar.count(), 1, window_name)
                self.assertIn("window-toolbar", toolbar.get_attribute("class"), window_name)
                self.assertEqual(toolbar.locator(".window-toolbar-title").inner_text(), title)
                group = toolbar.get_by_role("group", name=f"{title}操作", exact=True)
                self.assertEqual(group.count(), 1, title)
                refresh = group.get_by_role("button", name=f"刷新{title}", exact=True)
                self.assertEqual(refresh.count(), 1, title)
                self.assertEqual(refresh.inner_text(), "刷新", title)
                self.assertEqual(window.get_by_role("button", name="刷新", exact=True).count(), 0,
                                 "refresh must keep its window-specific accessible name")
                window.get_by_role("button", name=f"关闭{window_name}", exact=True).click()

    def test_window_toolbar_stays_visible_while_content_scrolls(self):
        self.open()
        window = self.open_builtin("系统状态")
        content = window.locator(".window-content")
        content.evaluate("""el => {
          const spacer = document.createElement('div');
          spacer.style.height = '1600px';
          spacer.textContent = 'toolbar sticky probe';
          el.append(spacer);
          el.scrollTop = 600;
        }""")
        self.assertGreater(content.evaluate("el => el.scrollTop"), 0)
        toolbar = window.locator("[data-window-toolbar]")
        self.assertTrue(toolbar.is_visible())
        content_box, toolbar_box = content.bounding_box(), toolbar.bounding_box()
        self.assertLessEqual(abs(toolbar_box["y"] - content_box["y"]), 1)
        self.assertGreaterEqual(toolbar_box["height"], 48)

    def test_window_toolbar_wraps_without_inner_overflow_on_narrow_screens(self):
        self.open()
        self.page.set_viewport_size({"width": 390, "height": 760})
        window = self.open_builtin("Skill")
        content = window.locator(".window-content")
        self.assertLessEqual(
            content.evaluate("el => el.scrollWidth"), content.evaluate("el => el.clientWidth") + 1)
        title = window.locator(".window-toolbar-title")
        actions = window.locator(".window-toolbar-actions")
        title_box, actions_box = title.bounding_box(), actions.bounding_box()
        self.assertGreaterEqual(actions_box["y"], title_box["y"] + title_box["height"] - 1,
                                "action group takes its own row on a narrow window")
        self.assertEqual(title.evaluate("el => getComputedStyle(el).textOverflow"), "ellipsis")
        self.assertEqual(title.evaluate("el => getComputedStyle(el).whiteSpace"), "nowrap")
        self.assertTrue(actions.get_by_role("button", name="刷新Skill 浏览器", exact=True).is_visible())

    def test_window_toolbar_refresh_is_keyboard_reachable_and_named(self):
        self.open()
        window = self.open_builtin("总览")
        self.assertEqual(self.page.evaluate(
            "() => document.activeElement && document.activeElement.className"), "window-title")
        for _ in range(12):
            self.page.keyboard.press("Tab")
            if self.page.evaluate(
                    "() => document.activeElement && document.activeElement.getAttribute('aria-label')") == "刷新总览":
                break
        self.assertEqual(self.page.evaluate(
            "() => document.activeElement && document.activeElement.getAttribute('aria-label')"), "刷新总览")
        self.assertNotEqual(self.page.evaluate(
            "() => getComputedStyle(document.activeElement).outlineStyle"), "none")
        self.assertTrue(window.locator(".window-toolbar-actions").is_visible())


if __name__ == "__main__":
    unittest.main()
