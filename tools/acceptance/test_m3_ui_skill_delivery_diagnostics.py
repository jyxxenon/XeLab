"""Safe reporting for the interval from a Skill click to its iframe result."""
import importlib.util
import itertools
import json
import pathlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "m3_ui_skill_driver", pathlib.Path(__file__).resolve().parents[1] / "m3-ui-browser.py")
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)

CORE = "https://core.test"
DEPLOYMENT = "00000000-0000-4000-8000-000000000001"
SKILL = "00000000-0000-4000-8000-000000000002"
CALL = "00000000-0000-4000-8000-000000000003"
LABEL = "widget_bridge_calls_real_http_skill"
PRIVATE = "must-never-appear-in-report"


class Request:
    def __init__(self, method, path, origin=CORE):
        self.method, self.url, self.failure = method, origin + path, PRIVATE

    @property
    def post_data(self):
        raise AssertionError("diagnostics must not read request bodies")

    def all_headers(self):
        raise AssertionError("diagnostics must not read request headers")


class SkillDeliveryDiagnostics(unittest.TestCase):
    def setUp(self):
        self.report = {}
        self.audit = DRIVER.SkillDeliveryAudit(CORE, DEPLOYMENT, SKILL, self.report)

    def test_tracks_call_and_read_proof_before_observer_settlement(self):
        invoke = Request("POST", f"/api/platform/v1/skills/{SKILL}/calls")
        proof = Request("GET", f"/api/platform/v1/calls/{CALL}")
        contribution = Request("GET", f"/api/platform/v1/ui/contributions/{DEPLOYMENT}/echo_widget")
        moments = itertools.count()
        with patch.object(DRIVER.time, "monotonic", side_effect=lambda: next(moments) / 10):
            self.audit.start(LABEL)
            self.audit.mark("click")
            self.audit.observe("request", invoke)
            self.audit.mark("wait_for_result")
            self.audit.observe("response", SimpleNamespace(request=invoke, status=200))
            self.audit.observe("finished", invoke)
            self.audit.observe("request", proof)
            self.audit.observe("response", SimpleNamespace(request=proof, status=200))
            self.audit.observe("finished", proof)
            self.audit.observe("request", contribution)
            self.audit.observe("failed", contribution)
            self.audit.end()

        attempt = self.report["skill_delivery"][0]
        self.assertEqual(attempt["label"], LABEL)
        self.assertEqual(attempt["stage"], "wait_for_result")
        self.assertEqual(list(attempt["stages_ms"]), ["fill", "click", "wait_for_result"])
        post, read, metadata = attempt["network_requests"]
        self.assertEqual([row["role"] for row in (post, read, metadata)],
                         ["invoke_skill", "get_call", "contribution"])
        self.assertLess(post["start_ms"], post["response_ms"])
        self.assertLess(post["response_ms"], read["start_ms"])
        self.assertLess(read["start_ms"], read["finished_ms"])
        self.assertEqual((post["status"], read["status"], metadata["status"]), (200, 200, None))
        self.assertEqual(metadata["failure_category"], "OTHER")
        self.assertLess(metadata["failed_ms"], attempt["elapsed_ms"])
        frozen = json.dumps(self.report)
        self.audit.observe("finished", contribution)
        self.audit.mark("complete")
        self.assertEqual(json.dumps(self.report), frozen)
        for private in (CORE, DEPLOYMENT, SKILL, CALL, PRIVATE, "echo_widget"):
            self.assertNotIn(private, frozen)

    def test_selection_and_retention_are_bounded(self):
        self.audit.start(PRIVATE)
        for request in (
            Request("POST", f"/api/platform/v1/skills/{SKILL}/calls", "https://outside.test"),
            Request("POST", f"/api/platform/v1/calls/{CALL}"),
            Request("GET", f"/api/platform/v1/calls/{CALL}?value={PRIVATE}"),
            Request("GET", "/api/platform/v1/calls/" + PRIVATE),
            Request("GET", f"/api/platform/v1/ui/contributions/{DEPLOYMENT}/other"),
        ):
            self.audit.observe("request", request)
        for _ in range(40):
            self.audit.observe("request", Request("GET", f"/api/platform/v1/calls/{CALL}"))
        first = self.report["skill_delivery"][0]
        self.assertEqual(first["label"], "other")
        self.assertEqual(len(first["network_requests"]), 32)
        self.assertEqual(first["dropped_requests"], 8)
        self.assertNotIn(PRIVATE, json.dumps(self.report))
        self.audit.end()
        for _ in range(6):
            self.audit.start(LABEL)
            self.audit.end()
        self.assertEqual(len(self.report["skill_delivery"]), 4)

    def test_failure_snapshot_uses_only_safe_browser_fields(self):
        self.audit.start(LABEL)
        self.audit.mark("wait_for_result")

        class Frame:
            def is_detached(self):
                return False

            def locator(self, selector):
                return self

            def evaluate(self, script, timeout):
                return {"state_class": PRIVATE, "channel_ready": PRIVATE, "call_disabled": True,
                        "result_present": False, "raw_text": PRIVATE}

        self.audit.failure(Frame(), RuntimeError(PRIVATE))
        attempt = self.report["skill_delivery"][0]
        snapshot = attempt["frame_snapshot"]
        self.assertEqual(attempt["error_bucket"], "Other")
        self.assertTrue(snapshot["dom_available"])
        self.assertEqual(snapshot["state_class"], "other")
        self.assertIsNone(snapshot["channel_ready"])
        self.assertTrue(snapshot["call_disabled"])
        self.assertFalse(snapshot["result_present"])
        self.assertNotIn(PRIVATE, json.dumps(self.report))

        self.audit.failure(SimpleNamespace(is_detached=lambda: True), RuntimeError(PRIVATE))
        self.assertEqual(attempt["frame_snapshot"], {"dom_available": False, "detached": True})
