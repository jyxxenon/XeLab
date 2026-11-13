"""Bounded and selective GET lifecycle evidence for Skill result delivery."""

import importlib.util
from itertools import count
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
CALL = "00000000-0000-4000-8000-000000000003"
PROOF = f"/api/platform/v1/calls/{CALL}"
CONTRIBUTION = f"/api/platform/v1/ui/contributions/{DEPLOYMENT}/echo_widget"
LABEL = "widget_bridge_calls_real_http_skill"
PRIVATE = "must-never-appear-in-report"


class Request:
    def __init__(self, path=PROOF, *, method="GET", origin=CORE, failure=PRIVATE):
        self.method, self.url, self.failure = method, origin + path, failure

    @property
    def post_data(self):
        raise AssertionError("diagnostics must not read request bodies")

    def all_headers(self):
        raise AssertionError("diagnostics must not read request headers")


class SkillDeliveryDiagnostics(unittest.TestCase):
    def setUp(self):
        self.report = {"http": {"skill_post_attempts": 0, "actual_skill_successes": 0}}
        self.audit = self.new_audit()

    def new_audit(self):
        return DRIVER.SkillCallAudit(self.report, SimpleNamespace(requests={}), LABEL, 1)

    def observe(self, event, value):
        self.audit.observe_read(event, value, CORE, {CONTRIBUTION})

    def assert_safe_report(self):
        report = json.dumps(self.report)
        for private in (CORE, DEPLOYMENT, CALL, PRIVATE, "echo_widget"):
            self.assertNotIn(private, report)

    def test_tracks_proof_and_recheck_through_response_and_terminal(self):
        proof = Request()
        recheck = Request(CONTRIBUTION, failure="net::ERR_ABORTED")
        pending = Request(CONTRIBUTION)
        with patch.object(DRIVER.time, "monotonic", side_effect=count(self.audit.started + 0.125, 0.125)):
            self.observe("request", proof)
            self.observe("request", proof)
            self.observe("response", SimpleNamespace(request=proof, status=200))
            self.observe("finished", proof)
            self.observe("request", recheck)
            self.observe("response", SimpleNamespace(request=recheck, status=503))
            self.observe("failed", recheck)
            self.observe("finished", recheck)
            self.observe("request", pending)
            self.audit.mark("complete")
            self.observe("finished", pending)

        proof, recheck, pending = self.audit.entry["read_requests"]
        self.assertEqual([row["role"] for row in (proof, recheck, pending)],
                         ["call_proof", "contribution_recheck", "contribution_recheck"])
        self.assertLess(proof["start_ms"], proof["response_ms"])
        self.assertLess(proof["response_ms"], proof["finished_ms"])
        self.assertIsNone(proof["failed_ms"])
        self.assertLess(proof["finished_ms"], recheck["start_ms"])
        self.assertLess(recheck["start_ms"], recheck["response_ms"])
        self.assertLess(recheck["response_ms"], recheck["failed_ms"])
        self.assertIsNone(recheck["finished_ms"])
        self.assertEqual(recheck["failure_category"], "net::ERR_ABORTED")
        self.assertEqual((proof["status"], recheck["status"], pending["status"]), (200, 503, None))
        self.assertIsNone(pending["finished_ms"])
        self.assert_safe_report()

    def test_selects_only_fixed_gets_with_a_seen_start(self):
        for request in (
            Request(method="POST"),
            Request(method="OPTIONS"),
            Request(origin="https://outside.test"),
            Request(PROOF + f"?query={PRIVATE}"),
            Request(CONTRIBUTION + f"#{PRIVATE}"),
            Request("/api/platform/v1/calls/" + PRIVATE),
            Request("/api/platform/v1/calls/" + "-" * 36),
            Request(f"/api/platform/v1/ui/contributions/{CALL}/echo_widget"),
            Request(f"/api/platform/v1/ui/contributions/{DEPLOYMENT}/other"),
        ):
            self.observe("request", request)
            self.observe("response", SimpleNamespace(request=request, status=200))
            self.observe("finished", request)

        unknown = Request()
        self.observe("response", SimpleNamespace(request=unknown, status=200))
        self.observe("finished", unknown)
        self.assertEqual(self.audit.entry["read_requests"], [])
        self.assert_safe_report()

    def test_bounds_records_and_separates_successive_audits(self):
        old_request = Request()
        self.observe("request", old_request)
        for _ in range(40):
            self.observe("request", Request())
        previous = self.audit.entry
        self.audit.mark("complete")
        self.audit = self.new_audit()

        self.observe("response", SimpleNamespace(request=old_request, status=200))
        self.observe("failed", old_request)
        fresh = Request(CONTRIBUTION)
        self.observe("request", fresh)
        self.observe("failed", fresh)

        self.assertEqual(len(previous["read_requests"]), 32)
        self.assertEqual(previous["dropped_read_requests"], 9)
        self.assertIsNone(previous["read_requests"][0]["status"])
        self.assertIsNone(previous["read_requests"][0]["failed_ms"])
        read, = self.audit.entry["read_requests"]
        self.assertEqual(read["failure_category"], "OTHER")
        self.assertIsNotNone(read["failed_ms"])
        self.assert_safe_report()

    def test_observer_error_does_not_interrupt_later_reads(self):
        class Broken:
            method = "GET"

            @property
            def url(self):
                raise RuntimeError(PRIVATE)

        self.observe("request", Broken())
        request = Request()
        self.observe("request", request)
        self.observe("response", SimpleNamespace(request=request, status=200))
        self.observe("finished", request)
        self.assertIs(self.audit.entry["read_observer_error"], True)
        read, = self.audit.entry["read_requests"]
        self.assertEqual(read["status"], 200)
        self.assertIsNotNone(read["finished_ms"])
        self.assert_safe_report()
