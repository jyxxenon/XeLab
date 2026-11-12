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


if __name__ == "__main__":
    unittest.main()
