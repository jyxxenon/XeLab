"""Root navigation evidence is selective, bounded and safe to publish."""

import importlib.util
from itertools import count
import json
import pathlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "m3_ui_root_driver", pathlib.Path(__file__).resolve().parents[1] / "m3-ui-browser.py")
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)

CORE = "https://private-core.test:8443"
UI = "https://private-desktop.test:8443"
REFERENCE = "https://private-reference.test:8443"
UI_ROOT = UI + "/ui/org.xelab.webui/"
SECRET = "private-navigation-diagnostic-marker"


class Request:
    def __init__(self, url=CORE + "/", *, method="GET", resource_type="document",
                 navigation=True, redirected_from=None, failure=SECRET):
        self.url, self.method, self.resource_type = url, method, resource_type
        self.navigation, self.redirected_from, self.failure = navigation, redirected_from, failure

    def is_navigation_request(self):
        return self.navigation

    def all_headers(self):
        raise AssertionError("root diagnostics must not inspect request headers")


class RootNavigationDiagnostics(unittest.TestCase):
    def setUp(self):
        self.report = {}
        self.audit = DRIVER.LoginBootstrapAudit(CORE, UI, REFERENCE, self.report)

    def observation(self, label="owner"):
        return self.report["bootstrap"][label]["root_navigation"]

    def assert_safe_report(self):
        rendered = json.dumps(self.report)
        for private in (SECRET, CORE, UI, REFERENCE, "/ui/org.xelab.webui/"):
            self.assertNotIn(private, rendered)

    def test_filters_exact_root_get_navigation_documents(self):
        before = Request()
        self.audit.request(before, "owner")
        self.audit.stage("owner", "root_navigation")
        for request in (
            before,
            Request(REFERENCE + "/"),
            Request(CORE + "/not-root"),
            Request(CORE + "/?code=" + SECRET),
            Request(UI + "/"),
            Request(UI_ROOT + "?code=" + SECRET),
            Request(UI_ROOT.rstrip("/")),
            Request(method="POST"),
            Request(resource_type="script"),
            Request(navigation=False),
        ):
            # A response or terminal event alone must never enroll a request.
            self.audit.response(SimpleNamespace(request=request, status=200), "owner")
            self.audit.terminal(request, "owner", False)
            if request is not before:
                self.audit.request(request, "owner")
        self.audit.request(Request(), "unrecognized")
        self.assertEqual(self.observation()["document_requests"], [])
        self.assertEqual(self.observation()["dropped_requests"], 0)
        self.assert_safe_report()

    def test_records_redirect_and_terminal_chronology_across_stage_change(self):
        core = Request()
        ui = Request(UI_ROOT, redirected_from=core)
        with patch.object(DRIVER.time, "monotonic", side_effect=count(10, 0.125)):
            self.audit.stage("owner", "root_navigation")
            self.audit.request(core, "owner")
            self.audit.response(SimpleNamespace(request=core, status=303), "owner")
            self.audit.terminal(core, "owner", False)
            self.audit.request(ui, "owner")
            self.audit.stage("owner", "welcome_login_click")
            self.audit.request(Request(), "owner")
            self.audit.response(SimpleNamespace(request=ui, status=200), "owner")
            self.audit.terminal(ui, "owner", False)

        root, desktop = self.observation()["document_requests"]
        self.assertEqual((root["role"], root["redirect_from"], root["status"]), ("core_root", None, 303))
        self.assertEqual((desktop["role"], desktop["redirect_from"], desktop["status"]),
                         ("ui_root", "core_root", 200))
        self.assertLess(root["start_ms"], root["response_ms"])
        self.assertLess(root["response_ms"], root["finished_ms"])
        self.assertLess(root["finished_ms"], desktop["start_ms"])
        self.assertLess(desktop["start_ms"], desktop["response_ms"])
        self.assertLess(desktop["response_ms"], desktop["finished_ms"])
        for hop in (root, desktop):
            self.assertIsNone(hop["failed_ms"])
            self.assertIsNone(hop["failure_category"])
        self.assert_safe_report()

    def test_failure_categories_and_redirect_links_are_scoped(self):
        owner = Request(failure="net::ERR_ABORTED")
        child = Request(UI_ROOT, redirected_from=owner)
        for label, request in (("owner", owner), ("child", child)):
            self.audit.stage(label, "root_navigation")
            self.audit.request(request, label)
            self.audit.terminal(request, label, True)

        for label, role, expected in (("owner", "core_root", "net::ERR_ABORTED"),
                                      ("child", "ui_root", "OTHER")):
            hop, = self.observation(label)["document_requests"]
            self.assertEqual(hop["role"], role)
            self.assertEqual(hop["failure_category"], expected)
            self.assertIsNone(hop["redirect_from"])
            self.assertIsNone(hop["status"])
            self.assertIsNone(hop["finished_ms"])
            self.assertGreaterEqual(hop["failed_ms"], hop["start_ms"])
        self.assert_safe_report()

    def test_limits_records_per_login_without_counting_duplicate_callbacks(self):
        self.audit.stage("owner", "root_navigation")
        for index in range(20):
            request = Request()
            self.audit.request(request, "owner")
            if index == 0:
                self.audit.request(request, "owner")
            self.audit.response(SimpleNamespace(request=request, status=302), "owner")
            self.audit.terminal(request, "owner", False)
        self.audit.stage("child", "root_navigation")
        self.audit.request(Request(), "child")

        self.assertEqual(len(self.observation()["document_requests"]), 8)
        self.assertEqual(self.observation()["dropped_requests"], 12)
        self.assertEqual(len(self.observation("child")["document_requests"]), 1)
        self.assertEqual(self.observation("child")["dropped_requests"], 0)

    def test_observer_failure_does_not_interrupt_later_events(self):
        self.audit.stage("owner", "root_navigation")

        class Broken:
            @property
            def url(self):
                raise RuntimeError(SECRET)

        self.audit.request(Broken(), "owner")
        request = Request()
        self.audit.request(request, "owner")
        self.audit.response(SimpleNamespace(request=request, status=302), "owner")
        self.audit.terminal(request, "owner", False)

        self.assertIs(self.observation()["diagnostic_error"], True)
        hop, = self.observation()["document_requests"]
        self.assertEqual(hop["status"], 302)
        self.assertIsNotNone(hop["finished_ms"])
        self.assert_safe_report()


if __name__ == "__main__":
    unittest.main()
