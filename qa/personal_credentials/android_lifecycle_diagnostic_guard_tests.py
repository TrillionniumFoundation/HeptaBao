#!/usr/bin/env python3
"""Host-only checks for closed c8/QA15 observations; never access Android."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import sys
import unittest
import xml.etree.ElementTree as ET


DRIVER = Path(__file__).with_name("android_live.py")
REVIEWED_QA16_NON_DIAGNOSTIC_AST = "9d311ce0be1a5529bae49bbfd057ec21f8a2c7aebf3b4a24469c3500d1b768d7"
EXTERNAL_EVENTS = []


def forbid_external(event, args):
    if event == "subprocess.Popen" or event.startswith("socket."):
        EXTERNAL_EVENTS.append(event)
        raise AssertionError("host_guard_attempted_external_operation")


sys.addaudithook(forbid_external)
spec = importlib.util.spec_from_file_location("android_diagnostic_guard_driver", DRIVER)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class DiagnosticFilterChecks(unittest.TestCase):
    def observe(self, raw, pid="31415", after="31415", baseline="31415", baseline_case="wrong_master_refused", log_failed=False):
        device = driver.Device.__new__(driver.Device)
        device.current_case = "wrong_master_refused"
        device._authorization_pid = baseline
        device._authorization_pid_case = baseline_case
        device._authorization_pid_sample_ns = driver.time.monotonic_ns()
        calls = []
        pids = iter([pid, after])

        def shell(*argv, **kwargs):
            calls.append((argv, kwargs))
            self.assertEqual(argv, ("pidof", driver.PROVIDER))
            self.assertEqual(kwargs, {"timeout": 5, "allow_failure": True})
            return next(pids)

        def adb_command(*argv, **kwargs):
            calls.append((argv, kwargs))
            self.assertEqual(argv[0], "shell")
            self.assertEqual(shlex.split(argv[1]), ["logcat", "-d", "-b", "main", "-v", "raw", "--pid=" + pid, "HeptaBaoPreview:I", "*:S"])
            self.assertEqual(kwargs, {})
            if log_failed: raise driver.Failed("device_command_failed")
            return raw.encode() if isinstance(raw, str) else raw

        device.shell = shell
        device.adb_command = adb_command
        return device.provider_events(), calls

    def tearDown(self):
        self.assertEqual(EXTERNAL_EVENTS, [])

    def test_closed_stages_sources_and_presence_are_retained(self):
        codes = [
            "auth_context_bound",
            "reject_unlock_precheck_request_expired",
            "reject_unlock_post_kdf_wrong_result_recipient",
            "reject_service_request_wrong_package",
            "reject_service_request_invalid_request",
            "lock_all_background_locked_before_p1l1h0_after_p0l0h0",
            "cancel_auth_pause_matched_1_before_p1l0h0_after_p0l0h0",
            "cancel_service_listener_matched_0_before_p1l0h0_after_p1l0h0",
            "cancel_service_callback_matched_1_before_p0l0h1_after_p0l0h0",
            "request_created_before_p1l0h0_after_p1l0h0",
            "explicit_login_lock_before_p1l1h0_after_p1l0h0",
            "request_expiry_timer", "request_expiry_access",
            "unlock_expiry_timer_login", "unlock_expiry_timer_handoff",
            "unlock_expiry_access", "handoff_expiry_access", "unlock_callback_stale",
            "service_target_expected", "service_target_self", "service_target_other",
            "trim_background_before_p1l0h0_after_p1l0h0_epoch_advanced",
        ]
        result, calls = self.observe("\n".join(codes))
        self.assertEqual(result["codes"], codes)
        self.assertEqual(len(calls), 3)
        self.assertTrue(result["pid_before_after_equal"])
        self.assertTrue(result["baseline_matches_before"])
        self.assertTrue(result["baseline_matches_after"])
        self.assertEqual(result["recognized_line_count"], len(codes))

    def test_unknown_fields_and_values_are_discarded(self):
        rejected = [
            "reject_unlock_precheck_CANARY_MASTER", "reject_other_stage_wrong_package",
            "service_target_org.heptabao.synthetic.fixture",
            "cancel_auth_pause_matched_true_before_p1l0h0_after_p0l0h0",
            "cancel_auth_pause_matched_1_before_p2l0h0_after_p0l0h0",
            "lock_all_CANARY_TOKEN_before_p1l0h0_after_p0l0h0",
            "lock_all_locked_before_p1l0h0_after_p1l0h0",
            "request_created_before_p1l0h0_after_p1l1h0",
            "explicit_login_lock_before_p1l1h0_after_p0l0h0",
            "request_expiry_access CANARY_URI", "CANARY_EXCEPTION_BODY",
        ]
        result, _ = self.observe("\n".join(rejected + ["reject_service_request_other"]))
        self.assertEqual(result["codes"], ["reject_service_request_other"])
        self.assertNotIn("CANARY", repr(result))

    def test_pid_ambiguity_never_reads_logcat(self):
        for pid in ("", "31415 31416", "31415\n31416", "CANARY_PID"):
            with self.subTest(pid_kind="invalid"):
                result, calls = self.observe("CANARY_PRIVATE_BUFFER", pid)
                self.assertFalse(result["available"])
                self.assertEqual(result["reason"], "provider_pid_unavailable")
                self.assertEqual(len(calls), 1)

    def test_buffer_limit_and_diagnostic_only_scope_are_unchanged(self):
        raw = "\n".join(["request_expiry_access"] * 70 + ["CANARY_PRIVATE_BUFFER", "service_target_self"])
        result, _ = self.observe(raw)
        self.assertEqual(result["scope"], "current_provider_process_buffer_diagnostic_only")
        self.assertEqual(len(result["codes"]), 64)
        self.assertEqual(result["codes"][-1], "service_target_self")
        self.assertEqual(result["recognized_line_count"], 71)
        self.assertEqual(result["unrecognized_line_count"], 1)
        self.assertEqual(result["recognized_lines_omitted_by_limit"], 7)
        self.assertFalse(result["numeric_pid_match_is_process_generation_proof"])
        self.assertFalse(result["log_delivery_order_is_event_order"])
        self.assertNotIn("CANARY", repr(result))

    def test_all_non_diagnostic_driver_ast_and_twelve_cases_match_qa16(self):
        tree = ast.parse(DRIVER.read_text())
        attrs = {"_authorization_pid", "_authorization_pid_case", "_authorization_pid_sample_ns"}

        class RemoveOnlyObservations(ast.NodeTransformer):
            def visit_FunctionDef(self, node):
                if node.name in {"provider_event_projection", "provider_pid", "capture_authorization_pid", "provider_events", "authorization_diagnostic"}: return None
                return self.generic_visit(node)

            def visit_Assign(self, node):
                if len(node.targets) == 1:
                    target = node.targets[0]
                    if isinstance(target, ast.Name) and target.id in {"DIAGNOSTIC_REJECTIONS", "DIAGNOSTIC_CODES"}: return None
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self" and target.attr in attrs: return None
                    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and target.slice.value == "authorization_diagnostic_before_diagnostic_activity": return None
                return self.generic_visit(node)

            def visit_Expr(self, node):
                if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == "self" and node.value.func.attr == "capture_authorization_pid": return None
                return self.generic_visit(node)

        tree = RemoveOnlyObservations().visit(tree)
        digest = hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()
        self.assertEqual(digest, REVIEWED_QA16_NON_DIAGNOSTIC_AST)
        self.assertEqual(len(driver.EXPECTED_CASES), 12)
        self.assertEqual(len(set(driver.EXPECTED_CASES)), 12)
        self.assertEqual(EXTERNAL_EVENTS, [])

    def test_original_bytes_are_counted_before_decoding_or_stripping(self):
        raw = b"\n  auth_context_bound \r\n\nCANARY\xff\n   \n"
        result, _ = self.observe(raw)
        self.assertEqual(result["raw_byte_count"], len(raw))
        self.assertEqual(result["raw_line_count"], 5)
        self.assertEqual(result["nonempty_line_count"], 2)
        self.assertEqual(result["recognized_line_count"], 1)
        self.assertEqual(result["unrecognized_line_count"], 1)
        self.assertGreater(result["raw_byte_count"], len(raw.decode("utf-8", "replace").strip()))
        self.assertNotIn("CANARY", json.dumps(result))
        self.assertNotIn("31415", json.dumps(result))

    def test_empty_raw_buffer_is_an_observation_not_absence_proof(self):
        result, _ = self.observe(b"")
        self.assertTrue(result["available"])
        self.assertEqual(result["codes"], [])
        for name in ("raw_byte_count", "raw_line_count", "recognized_line_count", "unrecognized_line_count"):
            self.assertEqual(result[name], 0)
        self.assertFalse(result["numeric_pid_match_is_process_generation_proof"])
        self.assertFalse(result["log_delivery_order_is_event_order"])

    def test_pid_replacement_and_old_case_are_visible_without_pid_disclosure(self):
        result, _ = self.observe("auth_context_bound", after="27182")
        self.assertFalse(result["pid_before_after_equal"])
        self.assertTrue(result["baseline_matches_before"])
        self.assertFalse(result["baseline_matches_after"])
        self.assertNotIn("27182", json.dumps(result))
        old, _ = self.observe("auth_context_bound", baseline_case="locked_fill_refused")
        self.assertFalse(old["baseline_recorded_for_case"])
        self.assertIsNone(old["baseline_matches_before"])
        self.assertIsNone(old["baseline_age_ms"])

    def test_logcat_failure_still_samples_after_pid(self):
        result, calls = self.observe(b"CANARY", log_failed=True)
        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "logcat_query_unavailable")
        self.assertEqual(len(calls), 3)
        self.assertTrue(result["pid_before_after_equal"])
        self.assertNotIn("raw_byte_count", result)

    def test_oversize_buffer_returns_only_size_and_closed_failure(self):
        raw = b"CANARY" * (1024 * 1024 // 6 + 1)
        result, _ = self.observe(raw)
        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "logcat_buffer_limit")
        self.assertEqual(result["raw_byte_count"], len(raw))
        self.assertEqual(result["codes"], [])
        self.assertNotIn("CANARY", json.dumps(result))

    def ui_observe(self, text, package=None, duplicate=False, changed=False):
        device = driver.Device.__new__(driver.Device)
        component = (driver.PROVIDER, "org.heptabao.preview.AuthActivity")
        foreground = iter([component, (driver.GOOD, driver.ACTIVITY) if changed else component])
        device.foreground = lambda: next(foreground)
        node = ET.Element("node", {"content-desc": "Authorization diagnostic", "package": package or driver.PROVIDER, "text": text})
        device.ui = lambda: [node, node] if duplicate else [node]
        return device.authorization_diagnostic()

    def test_ui_diagnostic_preserves_only_two_stages_and_closed_snapshots(self):
        for stage in ("unlock_precheck", "unlock_post_kdf"):
            result = self.ui_observe("reject_" + stage + "_request_expired_prior_background_locked")
            self.assertTrue(result["available"])
            self.assertEqual(result["stage"], stage)
            self.assertEqual(result["reason"], "request_expired")
            self.assertEqual(result["prior_decision_snapshot"], "background_locked")
            self.assertFalse(result["prior_decision_is_request_cause_proof"])

    def test_ui_diagnostic_rejects_wrong_node_duplicate_and_changed_activity(self):
        value = "reject_unlock_precheck_request_expired_prior_locked"
        for options in ({"package": driver.GOOD}, {"duplicate": True}, {"changed": True}):
            with self.subTest(options=tuple(options)):
                result = self.ui_observe(value, **options)
                self.assertFalse(result["available"])
                self.assertNotIn("stage", result)

    def test_ui_diagnostic_rejects_unknown_values_without_echo(self):
        for value in ("not_observed", "reject_service_request_wrong_package_prior_locked", "reject_unlock_precheck_CANARY_prior_locked", "reject_unlock_precheck_request_expired_prior_CANARY", "reject_unlock_precheck_request_expired_prior_locked CANARY"):
            result = self.ui_observe(value)
            self.assertFalse(result["available"])
            self.assertNotIn("CANARY", json.dumps(result))

    def test_baseline_metadata_failure_does_not_change_authorization_flow(self):
        device = driver.Device.__new__(driver.Device)
        device.current_case = "wrong_master_refused"
        device._authorization_pid = None
        device._authorization_pid_case = None
        device._authorization_pid_sample_ns = None
        device.foreground = lambda: (driver.PROVIDER, "org.heptabao.preview.AuthActivity")
        def unavailable(*args, **kwargs): raise driver.Failed("device_command_failed")
        device.shell = unavailable
        self.assertIsNone(device.capture_authorization_pid())
        self.assertIsNone(device._authorization_pid)
        self.assertEqual(device._authorization_pid_case, device.current_case)


if __name__ == "__main__":
    unittest.main(verbosity=2)
