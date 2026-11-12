#!/usr/bin/env python3
"""Real signed OCI WebUI/iframe browser acceptance against the actual kernel.

The Rust coordinator owns the database, runtime and public API mutations. This
driver mocks no response, installs no Cookie and injects no session. Passwords
are entered only on the trusted core origin. Reports never contain credentials,
callback query strings, form bodies, browser exception text or stack traces.
"""
from __future__ import annotations

import argparse
import base64
import importlib.metadata
import ipaddress
import json
import os
import pathlib
import re
import stat
import sys
import time
import urllib.parse
import uuid


class CheckFailed(Exception):
    pass


def future_features_unavailable(window):
    state = window.locator('[data-kind="unavailable"]')
    return (state.count() == 1
            and state.get_by_role("heading", name="Batch / Workflow / 微插件 / 知识库尚不可用", exact=True).count() == 1
            and state.get_by_text("未安装或实现的后续执行系统没有可展示的运行结果。", exact=True).count() == 1)


def wait_for_reference_skill(frame):
    # Old signed reference images expose only #state; newer ones keep
    # channel and operation status separate.
    frame.wait_for_function("() => (document.querySelector('#skill-state') ?? document.querySelector('#state'))?.textContent === 'Skill call completed.'")


def error_bucket(error):
    message = str(error)[:8192].lower()
    for bucket, phrases in [
        ("FrameDetached", ("frame was detached", "frame has been detached", "frame is detached")),
        ("TargetClosed", ("target page, context or browser has been closed", "target closed")),
        ("ExecutionContextDestroyed", ("execution context was destroyed",)),
        ("StrictLocator", ("strict mode violation",)),
        ("MissingResource", ("no resource with given identifier", "no data found for resource")),
        ("Evicted", ("evicted from inspector cache",)),
        ("Redirect", ("body is unavailable for redirect",)),
    ]:
        if any(phrase in message for phrase in phrases):
            return bucket
    return "Other"


def record_observer_failure(observed, phase, error):
    observed["observer_failure"] = True
    flag = {"request_headers": "request_headers_failed", "request_body": "request_body_failed", "response_skill_body": "response_skill_body_failed"}.get(phase)
    if flag:
        observed[flag] = True
    name = type(error).__name__
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", name):
        name = "OtherError"
    counts = observed["error_counts"]
    key = phase + ":" + name
    if key not in counts and len(counts) >= 16:
        key = "other"
    counts[key] = min(counts.get(key, 0) + 1, 65535)
    buckets = observed.setdefault("error_buckets", {})
    key = phase + ":" + error_bucket(error)
    if key not in buckets and len(buckets) >= 16:
        key = "other"
    buckets[key] = min(buckets.get(key, 0) + 1, 65535)


def selected_failure_category(value):
    # Compare only exact fixed browser codes; never retain the original value.
    codes = ("net::ERR_ABORTED", "net::ERR_TIMED_OUT", "net::ERR_CONNECTION_RESET", "net::ERR_CONNECTION_CLOSED", "net::ERR_HTTP2_PROTOCOL_ERROR", "net::ERR_FAILED")
    return value if isinstance(value, str) and value in codes else "OTHER"


class LoginBootstrapAudit:
    """Bounded filename/status and boolean diagnostics; never a ready gate."""
    files = ("app.js", "runtime-config.js", "api.js", "oauth.js", "bridge.js", "styles.css")
    stages = ("root_navigation", "welcome_login_click", "account_wait", "account_fill", "password_fill", "login_submit_click", "consent_wait", "consent_submit_click", "callback_wait", "session_wait", "connection_wait", "core_cookie_check", "plugin_cookie_check")

    def __init__(self, core, ui, reference, report):
        self.origins = {core: "core", ui: "ui", reference: "reference"}
        self.ui, self.report, self.requests = ui, report, {}
        self.records = report.setdefault("bootstrap", {})

    def entry(self, label):
        if label not in ("owner", "child"):
            return None
        return self.records.setdefault(label, {"assets": {}, "snapshots": {}})

    def stage(self, label, stage):
        if self.entry(label) is not None and stage in self.stages:
            self.entry(label)["stage"] = stage
            self.report["step"] = label + "_" + stage

    def request(self, request, label):
        if self.entry(label) is None or url_origin(request.url) != self.ui:
            return None
        path = urllib.parse.urlsplit(request.url).path
        filename = path.removeprefix("/ui/org.xelab.webui/")
        if path != "/ui/org.xelab.webui/" + filename or filename not in self.files:
            return None
        if (label, request) not in self.requests and len(self.requests) >= 128:
            entry = self.entry(label)
            entry["ignored_asset_events"] = min(entry.get("ignored_asset_events", 0) + 1, 65535)
            return None
        state = self.requests.setdefault((label, request), {"file": filename, "status": None, "finished": False, "failed": False})
        self.publish(label)
        return state

    def response(self, response, label):
        state = self.request(response.request, label)
        if state is not None:
            state["status"] = response.status if 100 <= response.status <= 599 else 0
            self.publish(label)

    def terminal(self, request, label, failed):
        state = self.request(request, label)
        if state is not None:
            state["failed" if failed else "finished"] = True
            self.publish(label)

    def publish(self, label):
        assets = {}
        for (owner, _), state in self.requests.items():
            if owner != label:
                continue
            item = assets.setdefault(state["file"], {"requested": 0, "finished": 0, "failed": 0, "status_counts": {}})
            item["requested"] = min(item["requested"] + 1, 65535)
            for key in ("finished", "failed"):
                item[key] = min(item[key] + int(state[key]), 65535)
            if state["status"] is not None:
                code = str(state["status"])
                if code not in item["status_counts"] and len(item["status_counts"]) >= 8:
                    code = "0"
                item["status_counts"][code] = min(item["status_counts"].get(code, 0) + 1, 65535)
        self.entry(label)["assets"] = assets

    def snapshot(self, page, label, name):
        if self.entry(label) is None or name not in ("root", "failure"):
            return
        snapshot = {"page_closed": page.is_closed(), "dom_available": False}
        self.entry(label)["snapshots"][name] = snapshot
        try:
            snapshot["origin_class"] = self.origins.get(url_origin(page.url), "other")
            if page.is_closed():
                return
            # One bounded read-only diagnostic after navigation or failure.
            # It never retries an action or participates in its ready predicate.
            value = page.locator("html").evaluate("""() => {
              const button=document.querySelector('#welcome-login');
              const visible=!!button && button.getClientRects().length>0 && getComputedStyle(button).visibility!=='hidden';
              return {ready_state:document.readyState,dock_populated:!!document.querySelector('#dock')?.children.length,
                clock_nonempty:!!document.querySelector('#clock')?.textContent?.trim(),
                welcome_login_exists:!!button,welcome_login_visible:visible,welcome_login_enabled:!!button&&!button.disabled,
                account_exists:!!document.querySelector('#account'),password_exists:!!document.querySelector('#password'),
                consent_exists:!!document.querySelector('#consent'),logged_in_control:document.querySelector('#login')?.textContent==='退出'};
            }""", timeout=1000)
            snapshot["dom_available"] = True
            snapshot["ready_state"] = value.get("ready_state") if value.get("ready_state") in ("loading", "interactive", "complete") else "other"
            for key in ("dock_populated", "clock_nonempty", "welcome_login_exists", "welcome_login_visible", "welcome_login_enabled", "account_exists", "password_exists", "consent_exists", "logged_in_control"):
                snapshot[key] = value.get(key) if isinstance(value.get(key), bool) else None
        except Exception as error:
            snapshot["diagnostic_error_bucket"] = error_bucket(error)

    def failure(self, page, label, error):
        name = type(error).__name__
        self.entry(label)["error_type"] = name if name in ("TimeoutError", "Error", "CheckFailed") else "OtherError"
        self.snapshot(page, label, "failure")


class RequestTimeline:
    """Bounded request lifecycle facts without URLs, payloads or headers."""
    limit = 32

    def __init__(self, core):
        self.core = core
        self.requests, self.started, self.active = {}, None, False

    def begin(self, observation, field):
        self.started, self.active = time.monotonic(), True
        self.requests.clear()
        self.observation = observation
        self.records = observation[field] = []
        observation["dropped_requests"] = 0

    def observe(self, event, value):
        try:
            if event == "request":
                self.request(value)
            elif event == "response":
                self.response(value)
            else:
                self.terminal(value, event == "failed")
        except Exception as error:
            if self.active:
                self.observation["diagnostic_error_bucket"] = error_bucket(error)

    def elapsed(self):
        return min(max(int((time.monotonic() - self.started) * 1000), 0), 300000)

    def request(self, request):
        if not self.active or request in self.requests:
            return
        parsed = urllib.parse.urlsplit(request.url)
        if f"{parsed.scheme}://{parsed.netloc}" != self.core or parsed.query or parsed.fragment:
            return
        role = self.request_role(request.method, parsed.path)
        if role is None:
            return
        if len(self.requests) >= self.limit:
            self.observation["dropped_requests"] = min(self.observation["dropped_requests"] + 1, 65535)
            return
        state = {"role": role, "start_ms": self.elapsed(), "response_ms": None, "finished_ms": None,
                 "failed_ms": None, "status": None, "failure_category": None}
        self.requests[request] = state
        self.records.append(state)

    def response(self, response):
        state = self.requests.get(response.request) if self.active else None
        if state is not None and state["response_ms"] is None:
            state["response_ms"] = self.elapsed()
            state["status"] = response.status if 100 <= response.status <= 599 else 0

    def terminal(self, request, failed):
        state = self.requests.get(request) if self.active else None
        key = "failed_ms" if failed else "finished_ms"
        if state is not None and state[key] is None:
            state[key] = self.elapsed()
            if failed:
                state["failure_category"] = selected_failure_category(request.failure)

    def end(self):
        self.observation["elapsed_ms"] = self.elapsed()
        self.active = False


class WindowOpenAudit(RequestTimeline):
    """Read-only, bounded window.open diagnostics; never an acceptance gate."""
    def __init__(self, core, deployment, report):
        super().__init__(core)
        self.report = report
        self.paths = {f"/api/platform/v1/ui/contributions/{deployment}/echo_widget": "source",
                      f"/api/platform/v1/ui/contributions/{deployment}/echo_window": "target"}

    def start(self):
        observation = {"stage": "window_open_click"}
        self.begin(observation, "metadata_requests")
        self.report["window_open_observation"] = observation

    def request_role(self, method, path):
        return self.paths.get(path) if method == "GET" else None

    def snapshot(self, widget):
        snapshot = {"dom_available": False}
        self.observation["widget_snapshot"] = snapshot
        try:
            snapshot["detached"] = widget.is_detached()
            if snapshot["detached"]:
                return
            # Reduce arbitrary DOM text to fixed labels inside the browser.
            # Neither plugin text, URL, identifiers nor exception text leave it.
            value = widget.locator("html").evaluate("""() => {
              const codes=['DEADLINE_EXCEEDED','CHANNEL_CLOSED','BACKEND_ERROR','PROTOCOL_ERROR',
                'PERMISSION_DENIED','BINDING_UNAVAILABLE','RATE_LIMITED'];
              function classify(text){
                const code=codes.find(code=>text.startsWith(code+':'));
                return text==='The host opened this deployment’s echo window.'?'window_open_succeeded':
                  text==='Skill call completed.'?'previous_skill_completed':code||'other';
              }
              // Prefer the window result; a pending window may coexist with a
              // previous Skill result. Old installed pages use only #state.
              const states=['#window-state','#skill-state','#state'].map(selector=>document.querySelector(selector)).filter(Boolean);
              const state=states.find(node=>classify(node.textContent||'')!=='other')||states[0];
              const stateClass=classify(state?.textContent||'');
              return {state_class:stateClass,state_exists:!!state,state_hidden:!!state?.hidden,
                state_visible:!!state&&state.getClientRects().length>0&&getComputedStyle(state).visibility!=='hidden',
                open_exists:!!document.querySelector('#open-window'),
                open_disabled:document.querySelector('#open-window')?.disabled,
                call_disabled:document.querySelector('#call')?.disabled,
                connected:document.documentElement.isConnected,
                document_visible:document.visibilityState==='visible'};
            }""", timeout=1000)
            snapshot["dom_available"] = True
            labels = ("window_open_succeeded", "previous_skill_completed", "DEADLINE_EXCEEDED", "CHANNEL_CLOSED",
                      "BACKEND_ERROR", "PROTOCOL_ERROR", "PERMISSION_DENIED", "BINDING_UNAVAILABLE", "RATE_LIMITED")
            snapshot["state_class"] = value.get("state_class") if value.get("state_class") in labels else "other"
            for key in ("state_exists", "state_hidden", "state_visible", "open_exists", "open_disabled", "call_disabled", "connected", "document_visible"):
                snapshot[key] = value.get(key) if isinstance(value.get(key), bool) else None
        except Exception as error:
            snapshot["diagnostic_error_bucket"] = error_bucket(error)


class SkillDeliveryAudit(RequestTimeline):
    """Observe iframe delivery without changing the selected business call."""
    labels = ("window_bridge_calls_real_http_skill", "valid_call_after_replay_rejection",
              "widget_bridge_calls_real_http_skill", "limited_child_bridge_call_before_withdrawal")
    stages = ("fill", "click", "wait_for_result", "verify_result", "settle_observers", "complete")

    def __init__(self, core, deployment, skill, report):
        super().__init__(core)
        self.report = report
        self.invoke_path = f"/api/platform/v1/skills/{skill}/calls"
        contribution_prefix = f"/api/platform/v1/ui/contributions/{deployment}/"
        self.contribution_paths = {contribution_prefix + "echo_window", contribution_prefix + "echo_widget"}

    def start(self, label):
        observation = {"label": label if label in self.labels else "other",
                       "stage": "fill", "stages_ms": {"fill": 0}}
        self.begin(observation, "network_requests")
        records = self.report.setdefault("skill_delivery", [])
        records.append(observation)
        del records[:-len(self.labels)]

    def mark(self, stage):
        if self.active and stage in self.stages:
            self.observation["stage"] = stage
            self.observation["stages_ms"][stage] = self.elapsed()

    def request_role(self, method, path):
        if method == "POST" and path == self.invoke_path:
            return "invoke_skill"
        if method != "GET":
            return None
        if path in self.contribution_paths:
            return "contribution"
        prefix = "/api/platform/v1/calls/"
        if path.startswith(prefix):
            identifier = path.removeprefix(prefix)
            try:
                if str(uuid.UUID(identifier)) == identifier:
                    return "get_call"
            except ValueError:
                pass
        return None

    def failure(self, frame, error):
        self.observation["error_bucket"] = error_bucket(error)
        snapshot = {"dom_available": False}
        self.observation["frame_snapshot"] = snapshot
        try:
            snapshot["detached"] = frame.is_detached() is True
            if snapshot["detached"]:
                return
            value = frame.locator("html").evaluate("""() => {
              const state=document.querySelector('#skill-state') ?? document.querySelector('#state');
              const text=state?.textContent || '';
              const codes=['DEADLINE_EXCEEDED','CHANNEL_CLOSED','BACKEND_ERROR','PROTOCOL_ERROR',
                'PERMISSION_DENIED','BINDING_UNAVAILABLE','RATE_LIMITED','UNAVAILABLE'];
              const code=codes.find(code=>text.startsWith(code+':'));
              const channel=document.querySelector('#state')?.textContent;
              return {state_class:text==='Skill call completed.'?'completed':
                  text==='Waiting for the actual Skill result…'?'waiting':!text?'empty':code||'other',
                channel_ready:channel==='Approved channel ready.',
                state_exists:!!state, call_disabled:document.querySelector('#call')?.disabled,
                result_present:!!document.querySelector('#result')?.textContent,
                document_visible:document.visibilityState==='visible'};
            }""", timeout=1000)
            labels = ("completed", "waiting", "empty", "DEADLINE_EXCEEDED", "CHANNEL_CLOSED",
                      "BACKEND_ERROR", "PROTOCOL_ERROR", "PERMISSION_DENIED", "BINDING_UNAVAILABLE",
                      "RATE_LIMITED", "UNAVAILABLE")
            snapshot["dom_available"] = True
            snapshot["state_class"] = value.get("state_class") if value.get("state_class") in labels else "other"
            for key in ("channel_ready", "state_exists", "call_disabled", "result_present", "document_visible"):
                snapshot[key] = value.get(key) if isinstance(value.get(key), bool) else None
        except Exception as snapshot_error:
            snapshot["diagnostic_error_bucket"] = error_bucket(snapshot_error)


class SkillBodyAudit:
    """Read actual selected response bodies outside Playwright event callbacks."""
    def __init__(self, core, skill, report, observed):
        self.core, self.skill = core, skill
        self.report, self.observed = report, observed
        self.requests, self.queue, self.calls = {}, [], []
        self.expected_successes = self.expected_attempts = 0

    def selected(self, request):
        return (url_origin(request.url) == self.core and request.method == "POST"
                and urllib.parse.urlsplit(request.url).path == f"/api/platform/v1/skills/{self.skill}/calls")

    def request(self, request, context_label=None):
        if not self.selected(request):
            return None
        if request not in self.requests:
            self.requests[request] = {"finished": False, "failed": False, "response": None, "read": False, "verified": False, "failure_recorded": False, "context_label": "unlabeled", "finished_before_failed": False, "failed_before_finished": False, "failure_snapshot": None, "echo_matches_request": None, "started_at": time.monotonic(), "response_ms": None, "finished_ms": None, "failed_ms": None, "failure_category": None, "expected_at_start": self.expected_successes}
            self.report["http"]["skill_post_attempts"] += 1
        if context_label in ("owner", "child", "component"):
            self.requests[request]["context_label"] = context_label
        return self.requests[request]

    def response(self, response):
        state = self.request(response.request)
        if state is not None and state["response_ms"] is None:
            state["response_ms"] = self.elapsed_ms(state)
        if state is not None and response.status == 200 and state["response"] is None:
            state["response"] = response
            self.queue.append(state)

    def finished(self, request):
        state = self.request(request)
        if state is not None:
            if state["finished_ms"] is None:
                state["finished_ms"] = self.elapsed_ms(state)
            if state["failed"] and not state["finished"]:
                state["failed_before_finished"] = True
            state["finished"] = True

    def failed(self, request):
        state = self.request(request)
        if state is not None:
            if not state["failed"]:
                state["failed_ms"] = self.elapsed_ms(state)
                try:
                    state["failure_category"] = selected_failure_category(request.failure)
                except Exception:
                    state["failure_category"] = "OTHER"
                state["finished_before_failed"] = state["finished"]
                state["failure_snapshot"] = {"context_label": state["context_label"], "expected_successes": self.expected_successes, "finished": state["finished"], "read": state["read"], "body_verified": state["verified"], "failure_category": state["failure_category"], "response_ms": state["response_ms"], "failed_ms": state["failed_ms"], "finished_ms": state["finished_ms"]}
            state["failed"] = True

    def elapsed_ms(self, state):
        return min(max(int((time.monotonic() - state["started_at"]) * 1000), 0), 300000)

    def expect(self, successes, attempts=None):
        self.expected_successes = successes
        self.expected_attempts = successes if attempts is None else attempts

    def record_reason(self, reason, state, duplicate_index=None):
        # Fixed bounded labels and booleans only: never include an identity,
        # request/response body, URL, header or original exception message.
        reasons = ("SelectedRequestFailed", "ResponseNotObject", "SkillMismatch", "CallNotObject", "CallIdMissing", "CallIdInvalid", "NotCanonical", "CallSkillMismatch", "Duplicate")
        if reason not in reasons:
            raise CheckFailed("invalid_body_diagnostic_reason")
        counts = self.observed.setdefault("skill_body_reasons", {})
        counts[reason] = min(counts.get(reason, 0) + 1, 65535)
        item = dict(state["failure_snapshot"]) if reason == "SelectedRequestFailed" else {
            "context_label": state["context_label"], "expected_successes": self.expected_successes,
            "finished": state["finished"], "read": state["read"], "body_verified": state["verified"],
        }
        item.update(reason=reason, echo_matches_request=state["echo_matches_request"])
        if duplicate_index is not None and 0 <= duplicate_index <= 4:
            item["duplicate_index"] = duplicate_index
        failures = self.observed.setdefault("skill_body_failure_stats", [])
        if len(failures) < 6:
            failures.append(item)

    def reject(self, reason, state, duplicate_index=None):
        self.record_reason(reason, state, duplicate_index)
        raise CheckFailed(reason)

    def read_completed(self):
        # Body RPCs may pump more callbacks. Iterate snapshots, and preserve
        # strong Response/Request references until each actual body is read.
        for state in list(self.requests.values()):
            if state["failed"] and not state["failure_recorded"]:
                state["failure_recorded"] = True
                self.record_reason("SelectedRequestFailed", state)
                record_observer_failure(self.observed, "response_skill_body", CheckFailed("SelectedRequestFailed"))
        for state in list(self.queue):
            if state["read"] or not (state["finished"] or state["failed"]):
                continue
            state["read"] = True
            if state["failed"]:
                continue
            self.observed["active_response_observers"] += 1
            try:
                # Response.json already waits internally; requestfinished is
                # recorded above, so never issue a second response.finished RPC.
                value = state["response"].json()
                if not isinstance(value, dict):
                    self.reject("ResponseNotObject", state)
                call = value.get("call")
                # Optional echo correlation is diagnostic only, never a new
                # acceptance condition. Values stay private even on failure.
                try:
                    request_value = json.loads(state["response"].request.post_data or "null")
                    source = request_value.get("input", {}).get("message")
                    target = call.get("output", {}).get("message") if isinstance(call, dict) else None
                    if isinstance(source, str) and isinstance(target, str):
                        state["echo_matches_request"] = source == target
                except Exception:
                    pass
                if value.get("skill_id") != self.skill:
                    self.reject("SkillMismatch", state)
                if not isinstance(call, dict):
                    self.reject("CallNotObject", state)
                identifier = call.get("call_id")
                if identifier is None:
                    self.reject("CallIdMissing", state)
                if not isinstance(identifier, str):
                    self.reject("CallIdInvalid", state)
                try:
                    canonical = str(uuid.UUID(identifier))
                except ValueError:
                    self.reject("CallIdInvalid", state)
                if canonical != identifier:
                    self.reject("NotCanonical", state)
                if call.get("skill_id", self.skill) != self.skill:
                    self.reject("CallSkillMismatch", state)
                if identifier in self.calls:
                    self.reject("Duplicate", state, self.calls.index(identifier))
                state["verified"] = True
                self.calls.append(identifier)
                self.report["http"]["actual_skill_successes"] += 1
                self.report["http"]["unique_skill_call_ids"] = len(set(self.calls))
            except Exception as error:
                record_observer_failure(self.observed, "response_skill_body", error)
            finally:
                self.observed["active_response_observers"] -= 1
        self.queue[:] = [state for state in self.queue if not state["read"]]
        self.report["body_observation"] = {
            "expected_successes": self.expected_successes, "expected_attempts": self.expected_attempts,
            "actual_successes": self.report["http"]["actual_skill_successes"],
            "unique_call_ids": len(set(self.calls)), "attempts": self.report["http"]["skill_post_attempts"],
            "queued_bodies": len(self.queue),
            "unfinished_requests": sum(not (state["finished"] or state["failed"]) for state in self.requests.values()),
            "finished_requests": sum(state["finished"] for state in self.requests.values()),
            "failed_requests": sum(state["failed"] for state in self.requests.values()),
            "all_requests_finished": all(state["finished"] for state in self.requests.values()),
            "finished_before_failed": any(state["finished_before_failed"] for state in self.requests.values()),
            "finished_before_failed_requests": sum(state["finished_before_failed"] for state in self.requests.values()),
            "failed_before_finished_requests": sum(state["failed_before_finished"] for state in self.requests.values()),
            "request_lifecycle": [{"ordinal": ordinal, "context_label": state["context_label"], "expected_at_start": state["expected_at_start"], "start_ms": 0, "response_ms": state["response_ms"], "finished_ms": state["finished_ms"], "failed_ms": state["failed_ms"], "failure_category": state["failure_category"]} for ordinal, state in enumerate(list(self.requests.values())[:6])],
        }

    def complete(self):
        return (self.report["http"]["actual_skill_successes"] == self.expected_successes
                and len(set(self.calls)) == self.expected_successes
                and self.report["http"]["skill_post_attempts"] == self.expected_attempts
                and not self.queue
                and all(state["finished"] and not state["failed"] for state in self.requests.values()))


def wait_for_observers(page, observed, bodies=None):
    deadline = time.monotonic() + 5
    while True:
        # This outer protocol pump dispatches pending header/lifecycle events;
        # zero active callbacks alone never proves a selected JSON body exists.
        page.evaluate("() => true")
        if bodies is not None:
            bodies.read_completed()
            if observed.get("observer_failure"):
                raise CheckFailed("network_observation_failed")
        if (observed["active_request_observers"] == 0 and observed["active_response_observers"] == 0
                and (bodies is None or bodies.complete())):
            return
        if time.monotonic() >= deadline:
            raise CheckFailed("network_observation_did_not_settle")


def wait_for_widget_window(page, widget, frame, deployment_id, contribution_id="echo_window", report=None, audit=None):
    observation = {} if report is None else report.setdefault("window_open_observation", {})
    try:
        observation["stage"] = "widget_ack"
        widget.get_by_text("The host opened this deployment’s echo window.", exact=True).wait_for()
        observation["stage"] = "fixed_parent"
        opened = page.locator(f'section.window[data-app="plugin:{deployment_id}:{contribution_id}"]')
        opened.wait_for()
        observation["stage"] = "frame_call_visible"
        frame.locator("#call").wait_for(state="visible")
        observation["stage"] = "frame_call_ready"
        frame.wait_for_function("() => document.querySelector('#call')?.disabled === false")
        observation["stage"] = "frame_identity"
        return opened.locator("iframe").element_handle().content_frame() == frame
    except Exception as error:
        observation["error_bucket"] = error_bucket(error)
        if audit is not None:
            audit.snapshot(widget)
        raise
    finally:
        if audit is not None:
            audit.end()


def close_windows(page, report, observed=None, bodies=None):
    report["step"] = "desktop_close_actual_windows"
    for _ in range(16):
        if not page.locator("#windows section.window").count():
            report["checks"]["all_windows_close"] = True
            return
        if observed is not None:
            wait_for_observers(page, observed, bodies)
        focused = page.locator('#windows section.window[data-focused="true"]:visible')
        if not focused.count():
            # A minimized window must be restored through its real Dock control.
            page.locator('#dock button[aria-label^="恢复"]').last.click()
        # Background controls may legitimately be covered by a newer window.
        # Close the current foreground window using its actual UI control.
        focused.last.locator('.window-controls button[aria-label^="关闭"]').click()
    if page.locator("#windows section.window").count():
        raise CheckFailed("all_windows_close")
    report["checks"]["all_windows_close"] = True


def url_origin(value):
    parsed = urllib.parse.urlsplit(value)
    return f"{parsed.scheme}://{parsed.netloc}"


def safe_read_summary(status, value):
    """Keep only bounded protocol facts, never response data or error text."""
    result = {"status": status}
    if isinstance(value, dict):
        if 200 <= status < 300 and isinstance(value.get("items"), list):
            result["item_count"] = len(value["items"])
        error = value.get("error")
        code = error.get("code") if isinstance(error, dict) else None
        if status >= 400 and isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code):
            result["error_code"] = code
    return result


def fixture(path):
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1):
        raise CheckFailed("private_fixture_required")
    value = json.loads(path.read_text())
    required = {"core_origin", "ui_origin", "reference_origin", "client_id", "owner_id", "owner_password", "child_id", "child_password", "skill_id", "reference_deployment_id", "tls_spki_sha256", "connect_ip", "chromium_path", "progress_file", "control_file"}
    if not isinstance(value, dict) or value.keys() != required or any(not isinstance(item, str) or not item for item in value.values()):
        raise CheckFailed("fixture_fields")
    for name in ("core_origin", "ui_origin", "reference_origin"):
        parsed = urllib.parse.urlsplit(value[name])
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or url_origin(value[name]) != value[name]:
            raise CheckFailed("exact_https_origin_required")
        parsed.port
    if len({urllib.parse.urlsplit(value[name]).hostname for name in ("core_origin", "ui_origin", "reference_origin")}) != 3:
        raise CheckFailed("isolated_hosts_required")
    for name in ("owner_id", "child_id", "skill_id", "reference_deployment_id"):
        if str(uuid.UUID(value[name])) != value[name]:
            raise CheckFailed("fixture_uuid")
    if value["owner_id"] == value["child_id"] or not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", value["client_id"]):
        raise CheckFailed("fixture_identity")
    if any(not 12 <= len(value[name]) <= 128 for name in ("owner_password", "child_password")):
        raise CheckFailed("fixture_password_length")
    if len(base64.b64decode(value["tls_spki_sha256"], validate=True)) != 32 or not ipaddress.ip_address(value["connect_ip"]).is_loopback:
        raise CheckFailed("fixture_local_certificate_pin")
    for name in ("progress_file", "control_file"):
        candidate = pathlib.Path(value[name])
        if candidate.parent.resolve() != path.parent.resolve() or candidate.is_symlink():
            raise CheckFailed("private_control_directory_required")
    return value


def private_json(path, value):
    path = pathlib.Path(path)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output, sort_keys=True)
    os.replace(temporary, path)


FETCH = """async ({core,client,path,method,body,key}) => {
  const session=JSON.parse(sessionStorage.getItem(`xelab.oauth:${core}:${client}`));
  if(!session?.access_token)return {status:null,code:'NO_SESSION'};
  const options={method,credentials:'omit',cache:'no-store',redirect:'error',headers:{Authorization:'Bearer '+session.access_token,Accept:'application/json'}};
  if(body!==null){options.headers['Content-Type']='application/json';options.headers['Idempotency-Key']=key;options.body=JSON.stringify(body);}
  const response=await fetch(core+path,options);const value=await response.json();
  return {status:response.status,code:value?.error?.code??null};
}"""


def run(config, report):
    os.environ.pop("DEBUG", None)
    os.environ.pop("PWDEBUG", None)
    from playwright.sync_api import sync_playwright

    def require(condition, name):
        report["step"] = name
        if not condition:
            raise CheckFailed(name)
        report["checks"][name] = True

    core, ui, reference = (config[name] for name in ("core_origin", "ui_origin", "reference_origin"))
    entry = ui + "/ui/org.xelab.webui/"
    reference_base = reference + "/ui/org.xelab.ui-reference/"
    hosts = [urllib.parse.urlsplit(value).hostname for value in (core, ui, reference)]
    resolver = ",".join(f"MAP {host} {config['connect_ip']}" for host in hosts)
    report["playwright_version"] = importlib.metadata.version("playwright")
    report["http"] = {"oauth_token_successes": 0, "callback_successes": 0, "actual_skill_successes": 0, "unique_skill_call_ids": 0, "skill_post_attempts": 0, "node_reads": 0, "preference_writes": 0, "contribution_reads": 0, "read_statuses": {}, "preflight_statuses": {}}
    reads = {"/api/platform/v1/installations": "installation_list",
             "/api/platform/v1/deployments": "deployment_list",
             "/api/platform/v1/skills": "skill_list",
             "/api/platform/v1/sessions": "current_sessions",
             "/api/platform/v1/me/ui-preferences": "current_preferences",
             "/api/platform/v1/ui/contributions": "contribution_list",
             f"/api/platform/v1/accounts/{config['owner_id']}": "owner_account",
             f"/api/platform/v1/accounts/{config['child_id']}": "child_account"}
    observed = {"password_outside_core": False, "core_cookie_on_plugin": False, "observer_failure": False, "request_headers_failed": False, "request_body_failed": False, "response_skill_body_failed": False, "active_request_observers": 0, "active_response_observers": 0, "page_errors": 0, "error_counts": {}, "error_buckets": {}}
    report["observation"] = observed
    bodies = SkillBodyAudit(core, config["skill_id"], report, observed)
    calls = bodies.calls
    bootstrap = LoginBootstrapAudit(core, ui, reference, report)
    window_open = WindowOpenAudit(core, config["reference_deployment_id"], report)
    skill_delivery = SkillDeliveryAudit(core, config["reference_deployment_id"], config["skill_id"], report)

    def observe_delivery(event, value):
        window_open.observe(event, value)
        skill_delivery.observe(event, value)

    def observe_request(request, context_label=None):
        observed["active_request_observers"] += 1
        phase = "request_origin"
        try:
            location = url_origin(request.url)
            bodies.request(request, context_label)
            phase = "request_body"
            body = request.post_data
            if body and "password" in body and location != core:
                observed["password_outside_core"] = True
            if location in (ui, reference):
                phase = "request_headers"
                headers = request.all_headers()
                if "__Host-xelab_auth=" in headers.get("cookie", ""):
                    observed["core_cookie_on_plugin"] = True
        except Exception as error:
            record_observer_failure(observed, phase, error)
        finally:
            observed["active_request_observers"] -= 1

    def observe_response(response):
        observed["active_response_observers"] += 1
        phase = "response_origin"
        try:
            parsed = urllib.parse.urlsplit(response.url)
            if url_origin(response.url) == ui and parsed.path == "/ui/org.xelab.webui/callback" and response.status == 200:
                report["http"]["callback_successes"] += 1
            if url_origin(response.url) != core:
                return
            phase = "response_read"
            if response.request.method in ("GET", "OPTIONS") and parsed.path in reads:
                try:
                    value = response.json()
                except Exception:
                    value = None
                bucket = "preflight_statuses" if response.request.method == "OPTIONS" else "read_statuses"
                entries = report["http"][bucket].setdefault(reads[parsed.path], [])
                entries.append(safe_read_summary(response.status, value))
                del entries[:-8]
            if parsed.path == "/oauth/token" and response.status == 200:
                report["http"]["oauth_token_successes"] += 1
            elif parsed.path == "/api/platform/v1/node" and response.status == 200:
                report["http"]["node_reads"] += 1
            elif parsed.path == "/api/platform/v1/me/ui-preferences" and response.request.method == "PUT" and response.status == 200:
                report["http"]["preference_writes"] += 1
            elif "/ui/contributions" in parsed.path and response.status == 200:
                report["http"]["contribution_reads"] += 1
            elif parsed.path == f"/api/platform/v1/skills/{config['skill_id']}/calls" and response.request.method == "POST":
                # No body RPC in this callback: retain the actual response until
                # requestfinished, then audit it in the outer protocol pump.
                phase = "response_skill_body"
                bodies.response(response)
        except Exception as error:
            record_observer_failure(observed, phase, error)
        finally:
            observed["active_response_observers"] -= 1

    def context(browser, label):
        result = browser.new_context(viewport={"width": 1440, "height": 1000})
        result.on("request", lambda request: observe_request(request, label))
        result.on("response", observe_response)
        result.on("request", lambda request: bootstrap.request(request, label))
        result.on("response", lambda response: bootstrap.response(response, label))
        result.on("requestfinished", lambda request: bootstrap.terminal(request, label, False))
        result.on("requestfailed", lambda request: bootstrap.terminal(request, label, True))
        result.on("requestfinished", bodies.finished)
        result.on("requestfailed", bodies.failed)
        result.on("request", lambda request: observe_delivery("request", request))
        result.on("response", lambda response: observe_delivery("response", response))
        result.on("requestfinished", lambda request: observe_delivery("finished", request))
        result.on("requestfailed", lambda request: observe_delivery("failed", request))
        result.on("page", lambda page: page.on("pageerror", lambda _: observed.__setitem__("page_errors", observed["page_errors"] + 1)))
        return result

    def login(browser, account, password, label):
        bootstrap.stage(label, "root_navigation")
        ctx = context(browser, label)
        page = ctx.new_page()
        page.set_default_timeout(25000)
        try:
            response = page.goto(core + "/", wait_until="domcontentloaded")
            require(response is not None and response.status == 200 and url_origin(page.url) == ui, label + "_root_redirects_to_actual_oci_ui")
            bootstrap.snapshot(page, label, "root")
            bootstrap.stage(label, "welcome_login_click")
            page.locator("#welcome-login").click()
            bootstrap.stage(label, "account_wait")
            page.locator("#account").wait_for()
            require(url_origin(page.url) == core and urllib.parse.urlsplit(page.url).path == "/auth/ui/login", label + "_password_only_on_trusted_core")
            bootstrap.stage(label, "account_fill")
            page.locator("#account").fill(account)
            bootstrap.stage(label, "password_fill")
            page.locator("#password").fill(password)
            bootstrap.stage(label, "login_submit_click")
            page.locator("#submit").click()
            bootstrap.stage(label, "consent_wait")
            page.locator("#consent").wait_for()
            require(url_origin(page.url) == core, label + "_trusted_native_consent")
            require(page.locator('#consent input[name="X-CSRF-Token"]').count() == 1, label + "_request_specific_consent_csrf")
            bootstrap.stage(label, "consent_submit_click")
            page.locator('#consent button[name="approved"][value="true"]').click()
            bootstrap.stage(label, "callback_wait")
            page.wait_for_url(lambda url: url_origin(str(url)) == ui and urllib.parse.urlsplit(str(url)).path == "/ui/org.xelab.webui/")
            bootstrap.stage(label, "session_wait")
            page.wait_for_function("() => document.querySelector('#login')?.textContent === '退出'")
            bootstrap.stage(label, "connection_wait")
            page.wait_for_function("() => document.querySelector('#connection')?.textContent === '已连接核心'")
            require(page.locator("#welcome").is_hidden(), label + "_actual_pkce_login_completed")
            bootstrap.stage(label, "core_cookie_check")
            cookies = ctx.cookies([core])
            session = next((cookie for cookie in cookies if cookie["name"] == "__Host-xelab_auth"), None)
            require(session is not None and session["httpOnly"] and session["secure"] and session["sameSite"] == "Lax" and session["path"] == "/" and session["domain"] == hosts[0], label + "_host_only_core_session_cookie")
            bootstrap.stage(label, "plugin_cookie_check")
            require(not any(cookie["name"] == "__Host-xelab_auth" for cookie in ctx.cookies([ui, reference])), label + "_no_core_cookie_on_plugin_hosts")
        except Exception as error:
            bootstrap.failure(page, label, error)
            raise
        return ctx, page

    def open_app(page, identifier, title, dock=True):
        report["step"] = "open_actual_" + identifier
        if dock:
            page.get_by_role("button", name="打开" + title, exact=True).click()
        else:
            page.get_by_role("button", name="打开应用启动器", exact=True).click()
            page.get_by_role("button", name="启动" + title, exact=True).click()
        result = page.locator(f'section.window[data-app="{identifier}"]').last
        result.wait_for()
        return result

    def contribution_frame(page, identifier="echo_window"):
        report["step"] = "mount_actual_" + identifier
        dialog = open_app(page, "contributions", "插件页面", dock=False)
        title = "Reference echo" if identifier == "echo_window" else "Echo widget"
        card = dialog.locator("article.card").filter(has=page.get_by_role("heading", name=title, exact=True))
        card.wait_for()
        filename = "window.html" if identifier == "echo_window" else "widget.html"
        with page.expect_event("framenavigated", predicate=lambda frame: frame.url.startswith(reference_base + filename)) as navigation:
            card.get_by_role("button", name="打开隔离窗口" if identifier == "echo_window" else "添加桌面组件", exact=True).click()
        frame = navigation.value
        frame.locator("#call").wait_for(state="visible")
        frame.wait_for_function("() => document.querySelector('#call')?.disabled === false")
        if identifier == "echo_widget":
            close_windows(page, report, observed, bodies)
        require(url_origin(frame.url) == reference, identifier + "_actual_isolated_origin")
        require(frame.evaluate("() => { try { parent.document.body; return false; } catch { return true; } }"), identifier + "_parent_dom_blocked")
        require(frame.evaluate("() => { try { parent.sessionStorage.length; return false; } catch { return true; } }"), identifier + "_parent_credential_storage_blocked")
        return frame

    def echo(frame, message, label, expected_successes):
        report["step"] = label
        bodies.expect(expected_successes)
        skill_delivery.start(label)
        try:
            frame.locator("#message").fill(message)
            skill_delivery.mark("click")
            frame.locator("#call").click()
            skill_delivery.mark("wait_for_result")
            wait_for_reference_skill(frame)
            skill_delivery.mark("verify_result")
            require(frame.locator("#result").inner_text() == message, label)
            require(frame.locator("img").count() == 0, label + "_text_not_html")
            skill_delivery.mark("settle_observers")
            wait_for_observers(page, observed, bodies)
            skill_delivery.mark("complete")
        except Exception as error:
            skill_delivery.failure(frame, error)
            raise
        finally:
            skill_delivery.end()

    def fetch(page, path, method="GET", body=None):
        return page.evaluate(FETCH, {"core": core, "client": config["client_id"], "path": path, "method": method, "body": body, "key": str(uuid.uuid4())})

    def coordinator_barrier(page, phase, expected):
        private_json(config["progress_file"], {"phase": phase})
        report["step"] = phase
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            path = pathlib.Path(config["control_file"])
            if path.exists():
                metadata = path.lstat()
                require(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600
                        and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1, "private_coordinator_control")
                control = json.loads(path.read_text())
                if control.get("phase") == expected:
                    return control
            page.wait_for_timeout(50)
        raise CheckFailed("coordinator_barrier_not_completed")

    def current_sibling_frame_url(page):
        # An intentional wrong-source sibling still needs its own approved
        # framing selector. A bare URL must not bypass the new CSP boundary.
        result = page.evaluate("""async ({core,client,deployment}) => {
          const {ApiClient}=await import('/ui/org.xelab.webui/api.js');
          const api=new ApiClient({core_origin:core,client_id:client},{accessToken:async()=>{
            const session=JSON.parse(sessionStorage.getItem('xelab.oauth:'+core+':'+client));
            if(!session?.access_token)throw new Error('No current shell credential');return session.access_token;
          }});
          const response=await api.invoke('getUiContribution',{params:{deployment_id:deployment,contribution_id:'echo_widget'}});
          return response.data.frame_url;
        }""", {"core": core, "client": config["client_id"], "deployment": config["reference_deployment_id"]})
        parsed = urllib.parse.urlsplit(result)
        require(url_origin(result) == reference and parsed.path == "/ui/org.xelab.ui-reference/widget.html"
                and parsed.query.startswith("xelab_frame=v1.") and not parsed.fragment,
                "wrong_source_sibling_uses_approved_framing_selector")
        return result

    with sync_playwright() as playwright:
        report["step"] = "launch_actual_chromium"
        browser = playwright.chromium.launch(executable_path=config["chromium_path"], headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--no-proxy-server", "--host-resolver-rules=" + resolver, "--ignore-certificate-errors-spki-list=" + config["tls_spki_sha256"]])
        report["browser_version"] = browser.version
        owner_context, page = login(browser, config["owner_id"], config["owner_password"], "owner")
        require(coordinator_barrier(page, "await_owner_nondefault_ui", "owner_nondefault_ui_ready").get("cleared") is True,
                "owner_shell_default_ui_was_cleared")
        report["step"] = "reload_actual_nondefault_shell"
        page.reload(wait_until="domcontentloaded")
        page.wait_for_function("() => document.querySelector('#login')?.textContent === '退出'")
        page.wait_for_function("() => document.querySelector('#connection')?.textContent === '已连接核心'")
        require(url_origin(page.url) == ui and urllib.parse.urlsplit(page.url).path == "/ui/org.xelab.webui/",
                "actual_oauth_shell_reloads_while_not_default")
        resources = open_app(page, "resources", "系统状态")
        resources.locator("pre.result").wait_for()
        require('"kernel_cpu_millis": 4000' in resources.inner_text() and '"kernel_memory_bytes": 17179869184' in resources.inner_text(), "desktop_reads_actual_node_reservations")
        close_windows(page, report, observed, bodies)
        plugins = open_app(page, "plugins", "插件中心")
        report["step"] = "desktop_wait_actual_plugin_catalog"
        plugins.get_by_role("heading", name="M3 official WebUI", exact=True).wait_for()
        plugins.get_by_role("heading", name="M3 independent UI reference", exact=True).wait_for()
        require("org.xelab.webui" in plugins.inner_text() and "org.xelab.ui-reference" in plugins.inner_text(), "desktop_reads_actual_installed_plugins")
        close_windows(page, report, observed, bodies)
        accounts = open_app(page, "accounts", "账户与权限")
        accounts.locator("pre.result").wait_for()
        require(config["owner_id"] in accounts.inner_text(), "desktop_reads_actual_owner_identity")
        close_windows(page, report, observed, bodies)
        skills = open_app(page, "skills", "Skill")
        card = skills.locator("article.card").filter(has=page.get_by_role("heading", name="org.xelab.ui-reference.echo", exact=True))
        card.get_by_role("button", name="调用测试", exact=True).click()
        editor = page.locator('section.window[data-app="editor-invokeSkill"]').last
        intent = str(uuid.uuid4())
        editor.get_by_role("textbox", name="请求 JSON", exact=True).fill(json.dumps({"input": {"message": "Actual management UI Skill call"}, "provider_deployment_id": config["reference_deployment_id"], "idempotency_key": intent, "timeout_ms": 10000}))
        bodies.expect(1)
        editor.get_by_role("button", name="提交", exact=True).click()
        editor.locator("pre.result").wait_for()
        require("Actual management UI Skill call" in editor.inner_text(), "desktop_invokes_actual_fixed_skill")
        wait_for_observers(page, observed, bodies)
        close_windows(page, report, observed, bodies)
        settings = open_app(page, "settings", "设置")
        settings.get_by_role("combobox", name="主题模式", exact=True).select_option("dark")
        settings.get_by_role("checkbox", name="减少动画", exact=True).check()
        settings.get_by_role("button", name="保存到当前账户", exact=True).click()
        page.wait_for_function("() => [...document.querySelectorAll('.theme-preview-note')].some(value => value.textContent.includes('已保存到核心'))")
        close_windows(page, report, observed, bodies)
        settings = open_app(page, "settings", "设置")
        require(settings.get_by_role("combobox", name="主题模式", exact=True).input_value() == "dark" and settings.get_by_role("checkbox", name="减少动画", exact=True).is_checked(), "actual_theme_preferences_survive_reread")
        close_windows(page, report, observed, bodies)
        unavailable = open_app(page, "tasks", "任务与知识库", dock=False)
        require(future_features_unavailable(unavailable), "future_execution_features_remain_unavailable")
        close_windows(page, report, observed, bodies)
        window = contribution_frame(page)
        echo(window, "Actual OCI iframe <img src=x onerror=alert(1)>", "window_bridge_calls_real_http_skill", 2)
        report["step"] = "real_channel_nonce_replay_and_source_rejection"
        coordinator_barrier(page, "await_attack_snapshot", "attack_snapshot_ready")
        before = report["http"]["skill_post_attempts"]
        channel = window.evaluate("() => Object.fromEntries(new URLSearchParams(location.hash.slice(1)))")
        window.evaluate("""() => { const meta=Object.fromEntries(new URLSearchParams(location.hash.slice(1)));
          const envelope={protocol:meta.protocol,view_id:meta.view_id,channel_nonce:meta.channel_nonce,type:'request',request_id:2,method:'skill.call',params:{binding_alias:'echo',input:{message:'Must not execute channel replay'},idempotency_key:'forged-channel-intent',timeout_ms:10000}};
          parent.postMessage({...envelope,seq:3,channel_nonce:(meta.channel_nonce[0]==='0'?'1':'0')+meta.channel_nonce.slice(1)},meta.parent_origin);
          parent.postMessage({...envelope,seq:2},meta.parent_origin);
          parent.postMessage({...envelope,seq:3,protocol:'xelab.ui/2'},meta.parent_origin);
        }""")
        page.evaluate("""meta => window.postMessage({protocol:meta.protocol,view_id:meta.view_id,channel_nonce:meta.channel_nonce,seq:3,type:'request',request_id:2,method:'skill.call',params:{binding_alias:'echo',input:{message:'Wrong source must not execute'},idempotency_key:'forged-host-source',timeout_ms:10000}},location.origin)""", channel)
        # An actual sibling on the SAME plugin origin isolates event.source
        # validation from the separate wrong-origin check above.
        sibling_url = current_sibling_frame_url(page)
        with page.expect_event("framenavigated", predicate=lambda frame: frame.url.startswith(reference_base + "widget.html")) as sibling_navigation:
            page.evaluate("""({metadata,url}) => {const frame=document.createElement('iframe');frame.id='source-probe';frame.hidden=true;frame.setAttribute('sandbox','allow-scripts allow-same-origin');frame.src=url+'#'+new URLSearchParams(metadata);document.body.append(frame);}""", {"metadata": channel, "url": sibling_url})
        sibling = sibling_navigation.value
        sibling.locator("#state").wait_for(state="attached")
        sibling.wait_for_load_state("load")
        sibling.evaluate("""meta => parent.postMessage({protocol:meta.protocol,view_id:meta.view_id,channel_nonce:meta.channel_nonce,seq:3,type:'request',request_id:2,method:'skill.call',params:{binding_alias:'echo',input:{message:'Same origin wrong source must not execute'},idempotency_key:'forged-sibling-source',timeout_ms:10000}},meta.parent_origin)""", channel)
        # A subsequent legitimate request/response is the event and network
        # barrier; elapsed silence and successful-only counters are insufficient.
        echo(window, "Actual channel survives rejected messages", "valid_call_after_replay_rejection", 3)
        page.locator("#source-probe").evaluate("element => element.remove()")
        require(report["http"]["skill_post_attempts"] == before + 1, "channel_attacks_create_no_skill_post_attempt")
        proof = coordinator_barrier(page, "await_attack_verification", "attack_verified")
        require(proof.get("calls_delta") == 1 and proof.get("daily_delta") == 1 and proof.get("concurrent") == 0,
                "channel_attacks_create_no_call_or_quota_charge")
        require(window.evaluate("async core => { try { await fetch(core+'/api/platform/v1/node'); return false; } catch { return true; } }", core), "third_party_connect_src_none")
        close_windows(page, report, observed, bodies)
        widget = contribution_frame(page, "echo_widget")
        echo(widget, "Actual OCI widget Skill call", "widget_bridge_calls_real_http_skill", 4)
        window_open.start()
        try:
            with page.expect_event("framenavigated", predicate=lambda frame: frame.url.startswith(reference_base + "window.html")) as opened:
                widget.locator("#open-window").click()
        except Exception as error:
            report["window_open_observation"]["error_bucket"] = error_bucket(error)
            window_open.snapshot(widget)
            window_open.end()
            raise
        require(wait_for_widget_window(page, widget, opened.value, config["reference_deployment_id"], report=report, audit=window_open)
                and url_origin(opened.value.url) == reference, "widget_opens_same_fixed_deployment_window")
        wait_for_observers(page, observed, bodies)
        require(report["http"]["actual_skill_successes"] >= 3, "owner_actual_skill_requests_observed")
        require(report["http"]["preference_writes"] >= 2, "core_preferences_and_widget_layout_persisted")
        owner_call = calls[0]
        require(coordinator_barrier(page, "await_child_default_ui", "child_default_ui_ready").get("restored") is True,
                "default_ui_restored_for_real_child_root_login")
        wait_for_observers(page, observed, bodies)
        owner_context.close()

        child_context, page = login(browser, config["child_id"], config["child_password"], "child")
        require(fetch(page, f"/api/platform/v1/accounts/{config['owner_id']}")["status"] in (403, 404), "child_cannot_read_owner_account")
        require(fetch(page, "/api/platform/v1/calls/" + owner_call)["status"] in (403, 404), "child_cannot_read_owner_call_result")
        frame = contribution_frame(page)
        echo(frame, "Actual limited child Skill call", "limited_child_bridge_call_before_withdrawal", 5)
        wait_for_observers(page, observed, bodies)
        require(coordinator_barrier(page, "await_revoke", "revoked").get("revoked") is True, "actual_inheritance_withdrawal_acknowledged")
        report["step"] = "actual_revocation_closes_old_channel"
        page.wait_for_function("() => document.querySelectorAll('#windows iframe').length === 0", timeout=15000)
        require(page.get_by_text("页面通道已关闭", exact=True).count() >= 1, "withdrawal_invalidates_old_iframe_channel")
        wait_for_observers(page, observed, bodies)
        before = report["http"]["actual_skill_successes"]
        bodies.expect(5, 6)
        denied = fetch(page, f"/api/platform/v1/skills/{config['skill_id']}/calls", "POST", {"input": {"message": "Must be denied after real withdrawal"}, "provider_deployment_id": config["reference_deployment_id"], "idempotency_key": str(uuid.uuid4()), "timeout_ms": 10000})
        require(denied["status"] == 403 and denied["code"] == "PERMISSION_DENIED", "withdrawn_child_new_skill_call_denied")
        require(report["http"]["actual_skill_successes"] == before, "withdrawal_produces_no_success_result")
        wait_for_observers(page, observed, bodies)
        child_context.close()
        require(report["http"]["oauth_token_successes"] >= 2 and report["http"]["callback_successes"] >= 2, "actual_owner_and_child_code_pkce_exchanges")
        browser.close()
        require(observed["active_request_observers"] == 0 and observed["active_response_observers"] == 0, "all_network_observations_completed")
        require(not observed["password_outside_core"] and not observed["core_cookie_on_plugin"] and not observed["observer_failure"], "password_cookie_and_network_observation_boundaries")
        require(report["http"]["actual_skill_successes"] == 5 and len(set(calls)) == 5
                and report["http"]["skill_post_attempts"] == 6, "all_five_unique_skill_responses_observed")
        require(observed["page_errors"] == 0, "no_uncaught_browser_execution_error")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    report = {"status": "failed", "step": "private_fixture", "checks": {}, "http": {}}
    started = time.monotonic()
    try:
        run(fixture(args.fixture), report)
        report["status"], report["step"] = "passed", "complete"
    except Exception as error:
        report["error_type"] = type(error).__name__
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    private_json(args.output, report)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
