"""Bounded diagnostics preserve lifecycle facts without recording plugin data."""
import importlib.util
import json
import pathlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "m3_ui_window_driver", pathlib.Path(__file__).resolve().parents[1] / "m3-ui-browser.py")
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)
CORE = "https://core.test"
DEPLOYMENT = "00000000-0000-4000-8000-000000000002"
SECRET = "must-never-appear-in-report"
CALL_PROOF = "/api/platform/v1/calls/00000000-0000-4000-8000-000000000003"
CONTRIBUTION = f"/api/platform/v1/ui/contributions/{DEPLOYMENT}/echo_widget"


class Request:
    def __init__(self, role="echo_widget", origin=CORE, method="GET", suffix=""):
        self.url = f"{origin}/api/platform/v1/ui/contributions/{DEPLOYMENT}/{role}{suffix}"
        self.method, self.failure = method, SECRET

    def all_headers(self):
        raise AssertionError("diagnostics must not inspect headers")


class WindowOpenDiagnostics(unittest.TestCase):
    def setUp(self):
        self.report = {}
        self.audit = DRIVER.WindowOpenAudit(CORE, DEPLOYMENT, self.report)

    def test_records_only_selected_lifecycle_and_never_reads_body(self):
        ignored = Request()
        self.audit.observe("request", ignored)
        with patch.object(DRIVER.time, "monotonic", side_effect=[10, 10.2, 13.2, 13.3, 13.4, 16.4, 16.5]):
            self.audit.start()
            source, target = Request(), Request("echo_window")
            self.audit.observe("request", source)
            self.audit.observe("response", SimpleNamespace(request=source, status=200))
            self.audit.observe("finished", source)
            self.audit.observe("request", target)
            self.audit.observe("failed", target)
            self.audit.end()
        records = self.report["window_open_observation"]["metadata_requests"]
        self.assertEqual([r["role"] for r in records], ["source", "target"])
        self.assertEqual(records[0]["status"], 200)
        self.assertLess(records[0]["start_ms"], records[0]["response_ms"])
        self.assertLess(records[0]["response_ms"], records[0]["finished_ms"])
        self.assertEqual(records[1]["failure_category"], "OTHER")
        frozen = json.dumps(self.report)
        self.audit.observe("finished", target)
        self.assertEqual(json.dumps(self.report), frozen)
        for private in (SECRET, CORE, DEPLOYMENT, "echo_widget", "echo_window"):
            self.assertNotIn(private, frozen)

    def test_selection_and_storage_are_bounded(self):
        self.audit.start()
        for request in (Request(origin="https://other.test"), Request(method="POST"),
                        Request("unknown"), Request(suffix="?token=" + SECRET)):
            self.audit.observe("request", request)
        for _ in range(100):
            self.audit.observe("request", Request())
        observation = self.report["window_open_observation"]
        self.assertEqual(len(observation["metadata_requests"]), 32)
        self.assertEqual(observation["dropped_requests"], 68)
        self.assertEqual(len(self.audit.requests), 32)
        self.assertNotIn(SECRET, json.dumps(self.report))

    def test_snapshot_filters_untrusted_values_and_failure_text(self):
        self.audit.start()

        class Widget:
            def is_detached(self):
                return False

            def locator(self, selector):
                return self

            def evaluate(self, script, timeout):
                return {"state_class": SECRET, "open_disabled": SECRET,
                        "call_disabled": True, "state_visible": False, "raw_text": SECRET}

        self.audit.snapshot(Widget())
        snapshot = self.report["window_open_observation"]["widget_snapshot"]
        self.assertEqual(snapshot["state_class"], "other")
        self.assertIsNone(snapshot["open_disabled"])
        self.assertIs(snapshot["call_disabled"], True)
        self.assertNotIn(SECRET, json.dumps(self.report))

        class Detached:
            def is_detached(self):
                raise RuntimeError(SECRET)

        self.audit.snapshot(Detached())
        self.assertFalse(self.report["window_open_observation"]["widget_snapshot"]["dom_available"])
        self.assertNotIn(SECRET, json.dumps(self.report))

    def test_diagnostic_callback_failure_cannot_fail_acceptance(self):
        self.audit.start()

        class Broken:
            @property
            def url(self):
                raise RuntimeError(SECRET)

        self.audit.observe("request", Broken())
        self.assertEqual(self.report["window_open_observation"]["diagnostic_error_bucket"], "Other")
        self.assertNotIn(SECRET, json.dumps(self.report))


class SkillCallDiagnostics(unittest.TestCase):
    def setUp(self):
        self.report = {"http": {"skill_post_attempts": 0, "actual_skill_successes": 0,
                                "call_proof_statuses": [], "contribution_recheck_statuses": []},
                       "observation": {}}
        self.bodies = SimpleNamespace(requests={})
        self.audit = DRIVER.SkillCallAudit(self.report, self.bodies, "valid_call", 2)

    def observe_read(self, path, status, method="GET"):
        DRIVER.observe_skill_read_status(self.report["http"], self.audit, method, path, status)

    def test_stage_timeline_is_bounded_and_uses_fixed_labels(self):
        for stage in DRIVER.SKILL_STAGES:
            self.audit.mark(stage)
        entry = self.report["skill_call_diagnostics"][-1]
        self.assertEqual([item["stage"] for item in entry["timeline"]], list(DRIVER.SKILL_STAGES))
        self.assertLessEqual(entry["elapsed_ms"], 300000)
        self.assertEqual(entry["status"], "completed")
        self.assertEqual(self.report["step"], "valid_call_complete")
        with self.assertRaises(DRIVER.CheckFailed):
            self.audit.mark(SECRET)

    def test_old_entries_are_evicted_and_stage_count_is_bounded(self):
        for index in range(12):
            DRIVER.SkillCallAudit(self.report, self.bodies, f"call_{index}", 1)
        entries = self.report["skill_call_diagnostics"]
        self.assertEqual(len(entries), DRIVER.SkillCallAudit.limit)
        self.assertEqual(entries[0]["label"], "call_4")
        self.assertEqual(entries[-1]["label"], "call_11")

    def test_snapshot_filters_untrusted_values(self):
        class Frame:
            def is_detached(self):
                return False

            def locator(self, selector):
                return self

            def evaluate(self, script, arg, timeout=None):
                return {"state_class": SECRET, "result_matches": True, "result_empty": True,
                        "result_context_matches": SECRET, "call_disabled": False,
                        "call_visible": True, "connected": True, "document_visible": False,
                        "raw_text": SECRET}

        self.audit.snapshot(Frame(), "expected")
        snapshot = self.report["skill_call_diagnostics"][-1]["iframe"]
        self.assertEqual(snapshot["state_class"], "other_nonempty")
        self.assertIs(snapshot["result_matches"], True)
        self.assertIs(snapshot["result_empty"], True)
        self.assertIsNone(snapshot["result_context_matches"])
        self.assertIs(snapshot["call_disabled"], False)
        self.assertIs(snapshot["document_visible"], False)
        self.assertNotIn(SECRET, json.dumps(self.report))

    def test_first_mismatch_reports_one_fixed_stage(self):
        self.assertEqual(self.audit.mismatch(), "submit_not_observed")
        self.report["http"]["skill_post_attempts"] = 1
        self.assertEqual(self.audit.mismatch(), "request_not_correlated")
        state = {"expected_at_start": 2, "response_ms": None, "verified": False}
        self.bodies.requests[1] = state
        self.assertEqual(self.audit.mismatch(), "response_not_observed")
        state["response_ms"] = 10
        self.assertEqual(self.audit.mismatch(), "response_not_verified")
        state["verified"] = True
        self.assertEqual(self.audit.mismatch(), "iframe_unavailable")
        self.audit.entry["iframe"] = {"dom_available": True, "state_class": "waiting"}
        self.assertEqual(self.audit.mismatch(), "iframe_state_waiting")
        self.audit.entry["iframe"] = {"dom_available": True, "state_class": "completed", "result_matches": False}
        self.assertEqual(self.audit.mismatch(), "result_mismatch")
        self.audit.entry["iframe"]["result_matches"] = True
        self.assertEqual(self.audit.mismatch(), "call_proof_not_observed")
        self.observe_read(CALL_PROOF, 503)
        self.assertEqual(self.audit.mismatch(), "call_proof_not_successful")
        self.observe_read(CALL_PROOF, 200)
        self.assertEqual(self.audit.mismatch(), "contribution_recheck_not_observed")
        self.observe_read(CONTRIBUTION, 500)
        self.assertEqual(self.audit.mismatch(), "contribution_recheck_not_successful")
        self.observe_read(CONTRIBUTION, 200)
        self.assertEqual(self.audit.mismatch(), "none")
        self.assertEqual(self.audit.entry["attempts_delta"], 1)
        self.assertEqual(self.audit.entry["successes_delta"], 0)

    def test_failed_contribution_recheck_is_reported_before_missing_frame(self):
        self.report["http"]["skill_post_attempts"] = 1
        self.bodies.requests[1] = {"expected_at_start": 2, "response_ms": 10, "verified": True}
        self.observe_read(CONTRIBUTION, 200)
        self.observe_read(CALL_PROOF, 200)
        self.observe_read(CONTRIBUTION, 503)
        frame = SimpleNamespace(is_detached=lambda: True)
        with patch.object(DRIVER, "wait_for_observers"):
            self.audit.failure(frame, SimpleNamespace(), RuntimeError(SECRET), SECRET)
        self.assertEqual(self.report["http"]["contribution_recheck_statuses"], [200, 503])
        self.assertEqual(self.audit.entry["contribution_recheck_statuses"], [200, 503])
        self.assertEqual(self.audit.entry["mismatch"], "contribution_recheck_not_successful")
        self.assertTrue(self.audit.entry["iframe"]["detached"])

    def test_full_shared_history_does_not_hide_new_audit_reads(self):
        for _ in range(12):
            self.observe_read(CALL_PROOF, 404)
            self.observe_read(CONTRIBUTION, 503)
        previous = self.audit
        previous.mark("complete")
        self.audit = DRIVER.SkillCallAudit(self.report, self.bodies, "next_call", 3)
        self.observe_read(CALL_PROOF, 200)
        self.observe_read(CONTRIBUTION, 200)
        for key, old in (("call_proof_statuses", 404), ("contribution_recheck_statuses", 503)):
            self.assertEqual(self.report["http"][key], [old] * 7 + [200])
            self.assertEqual(previous.entry[key], [old] * 8)
            self.assertEqual(self.audit.entry[key], [200])

    def test_read_statuses_stay_with_the_active_audit_and_selected_gets(self):
        self.observe_read(CALL_PROOF, 200)
        self.audit.mark("complete")
        previous = self.audit
        self.observe_read(CONTRIBUTION, 404)
        DRIVER.observe_skill_read_status(self.report["http"], None, "GET", CONTRIBUTION, 503)
        self.audit = DRIVER.SkillCallAudit(self.report, self.bodies, "next_call", 3)
        self.observe_read(CALL_PROOF, 401, "OPTIONS")
        self.observe_read(CONTRIBUTION, 401, "POST")
        self.observe_read("/api/platform/v1/ui/contributions", 403)
        self.observe_read("/api/platform/v1/calls", 403)
        self.observe_read("/api/platform/v1/node", 403)
        self.assertEqual(self.report["http"]["call_proof_statuses"], [200])
        self.assertEqual(self.report["http"]["contribution_recheck_statuses"], [404, 503])
        self.assertEqual(previous.entry["call_proof_statuses"], [200])
        self.assertEqual(previous.entry["contribution_recheck_statuses"], [])
        self.assertEqual(self.audit.entry["call_proof_statuses"], [])
        self.assertEqual(self.audit.entry["contribution_recheck_statuses"], [])

    def test_observer_pump_reports_fixed_inner_stages(self):
        class Page:
            def evaluate(self, expression):
                self.expression = expression

        class Bodies:
            def read_completed(self):
                self.read = True

            def complete(self):
                return True

        stages = []
        bodies = Bodies()
        DRIVER.wait_for_observers(Page(), {"active_request_observers": 0, "active_response_observers": 0},
                                  bodies, stages.append)
        self.assertEqual(stages, ["audit_pump", "audit_read"])
        self.assertTrue(bodies.read)

    def test_observation_timeout_is_not_reported_as_a_semantic_mismatch(self):
        class Frame:
            def is_detached(self):
                return False

            def locator(self, selector):
                return self

            def evaluate(self, script, arg, timeout=None):
                return {"state_class": "completed", "result_matches": True, "result_empty": False,
                        "result_context_matches": True, "call_disabled": False,
                        "call_visible": True, "connected": True, "document_visible": True}

        self.report["http"]["skill_post_attempts"] = 1
        self.report["http"]["actual_skill_successes"] = 1
        self.observe_read(CALL_PROOF, 200)
        self.observe_read(CONTRIBUTION, 200)
        self.bodies.requests[1] = {"expected_at_start": 2, "response_ms": 10, "verified": True}
        with patch.object(DRIVER, "wait_for_observers", side_effect=RuntimeError(SECRET)):
            self.audit.mark("audit_pump")
            self.audit.failure(Frame(), SimpleNamespace(), RuntimeError(SECRET), "expected")
        entry = self.report["skill_call_diagnostics"][-1]
        self.assertEqual(entry["mismatch"], "observation_incomplete")
        self.assertEqual(self.report["step"], "valid_call_audit_pump")

    def test_skill_result_wait_passes_expected_without_reading_text(self):
        class Frame:
            def wait_for_function(self, expression, *, arg=None, timeout=None):
                self.expression, self.arg = expression, arg

        frame = Frame()
        DRIVER.wait_for_skill_result(frame, "expected component result")
        self.assertEqual(frame.arg, "expected component result")
        self.assertIn("Skill call completed.", frame.expression)
        for code in ("DEADLINE_EXCEEDED", "CHANNEL_CLOSED", "BACKEND_ERROR", "PROTOCOL_ERROR",
                     "PERMISSION_DENIED", "BINDING_UNAVAILABLE", "RATE_LIMITED"):
            self.assertIn(code, frame.expression)

    def test_failure_keeps_fixed_step_and_never_leaks_error_text(self):
        class Frame:
            def is_detached(self):
                return True

        with patch.object(DRIVER, "wait_for_observers", side_effect=RuntimeError(SECRET)):
            self.audit.mark("wait_iframe_result")
            self.audit.failure(Frame(), SimpleNamespace(), RuntimeError(SECRET), SECRET)
        entry = self.report["skill_call_diagnostics"][-1]
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["error_type"], "OtherError")
        self.assertEqual(entry["mismatch"], "submit_not_observed")
        self.assertIs(entry["iframe"]["detached"], True)
        self.assertEqual(self.report["step"], "valid_call_wait_iframe_result")
        self.assertNotIn(SECRET, json.dumps(self.report))


if __name__ == "__main__":
    unittest.main()
