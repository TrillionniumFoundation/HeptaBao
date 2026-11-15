#!/usr/bin/env python3
"""Host controls for private cancellation correlation; no Android operations."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET


DRIVER = Path(__file__).with_name("android_live.py")
EXTERNAL_EVENTS = []
OBSERVATION = "observation-11111111-2222-4333-8444-555555555555"
OTHER = "observation-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
REVIEWED_QA19_REMAINDER_AST = "1554e655e519d989479d3b281995d57ec26ba123cd1d32a3679bfb721c1d9e50"
BASELINE_CANCEL_HELPER_AST = "da7d68be1fb32d8d77c943f58ded1ca53397c8883df4c0f84b9848915db20e8b"


def forbid_external(event, args):
    if event == "subprocess.Popen" or event.startswith("socket."):
        EXTERNAL_EVENTS.append(event)
        raise AssertionError("host_guard_attempted_external_operation")


sys.addaudithook(forbid_external)
spec = importlib.util.spec_from_file_location("android_cancel_observation_driver", DRIVER)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def receipt(value=OBSERVATION, marker="explicit_cancel", source="auth_pause", before="p1l1h0", after="p0l0h0"):
    return "|".join(("cancel_observation", value, marker, source, before, after))


class CancellationObservationChecks(unittest.TestCase):
    def tearDown(self):
        self.assertEqual(EXTERNAL_EVENTS, [])

    def device(self, kind, text, package=None, duplicate=False, missing=False, before=None, after=None):
        device = driver.Device.__new__(driver.Device)
        expected = (driver.PROVIDER, "org.heptabao.preview." + ("AuthActivity" if kind == "authorization" else "MainActivity"))
        foreground = iter((before or expected, after or expected))
        device.foreground = lambda: next(foreground)
        node = ET.Element("node", {"content-desc": "Authorization observation" if kind == "authorization" else "Cancellation observation",
                                   "package": driver.PROVIDER if package is None else package, "text": text})
        device.ui = lambda: [] if missing else [node, node] if duplicate else [node]
        return device

    def assert_refused(self, device, method="cancellation", expected=OBSERVATION):
        with self.assertRaises(driver.Failed) as caught:
            if method == "authorization": device.authorization_observation()
            else: device.cancellation_observation(expected)
        self.assertNotIn(OBSERVATION, str(caught.exception))
        self.assertNotIn(OTHER, str(caught.exception))
        self.assertNotIn("CANARY", str(caught.exception))

    def test_current_auth_id_is_captured_only_from_bound_auth(self):
        device = self.device("authorization", OBSERVATION)
        self.assertEqual(device.authorization_observation(), OBSERVATION)

    def test_authorization_missing_duplicate_or_wrong_package_rejected(self):
        for options in ({"missing": True}, {"duplicate": True}, {"package": driver.GOOD}):
            with self.subTest(options=tuple(options)):
                self.assert_refused(self.device("authorization", OBSERVATION, **options), "authorization")

    def test_authorization_foreground_before_or_after_change_rejected(self):
        wrong = (driver.GOOD, driver.ACTIVITY)
        for options in ({"before": wrong}, {"after": wrong}):
            self.assert_refused(self.device("authorization", OBSERVATION, **options), "authorization")

    def test_authorization_raw_token_malformed_or_extra_text_rejected(self):
        for value in (OBSERVATION.removeprefix("observation-"), OBSERVATION.upper(), OBSERVATION + "\nCANARY", "CANARY", "not_observed", ""):
            self.assert_refused(self.device("authorization", value), "authorization")

    def test_exact_explicit_cancel_observation_returns_no_identifier(self):
        result = self.device("cancellation", receipt()).cancellation_observation(OBSERVATION)
        self.assertEqual(result, {"observation_matches_current_authorization": True, "explicit_cancel_action_observed": True,
                                 "source": "auth_pause", "before": "p1l1h0", "after": "p0l0h0",
                                 "observation_identifier_is_authority": False})
        self.assertNotIn(OBSERVATION, json.dumps(result))
        self.assertNotIn("11111111", json.dumps(result))

    def test_old_or_wrong_observation_id_rejected(self):
        self.assert_refused(self.device("cancellation", receipt(OTHER)))
        self.assert_refused(self.device("cancellation", receipt()), expected=OTHER)

    def test_home_only_unmarked_or_other_marker_rejected(self):
        for marker in ("unmarked", "home", "CANARY", "", "true"):
            self.assert_refused(self.device("cancellation", receipt(marker=marker)))

    def test_service_cancel_or_unknown_source_rejected(self):
        for source in ("service_listener", "service_callback", "other", "CANARY"):
            self.assert_refused(self.device("cancellation", receipt(source=source)))

    def test_expired_locked_handoff_or_uncleared_state_rejected(self):
        for before in ("p1l0h0", "p0l0h0", "p0l0h1", "p1l1h1", "CANARY"):
            self.assert_refused(self.device("cancellation", receipt(before=before)))
        for after in ("p1l0h0", "p0l1h0", "p0l0h1", "CANARY"):
            self.assert_refused(self.device("cancellation", receipt(after=after)))

    def test_cancellation_missing_duplicate_wrong_node_or_changed_activity_rejected(self):
        wrong = (driver.PROVIDER, "org.heptabao.preview.AuthActivity")
        for options in ({"missing": True}, {"duplicate": True}, {"package": driver.GOOD}, {"before": wrong}, {"after": wrong}):
            self.assert_refused(self.device("cancellation", receipt(), **options))

    def test_extra_fields_missing_record_and_untrusted_expected_id_rejected(self):
        for value in ("not_observed", receipt() + "|CANARY", receipt() + "\n", receipt().replace("cancel_observation", "CANARY"), ""):
            self.assert_refused(self.device("cancellation", value))
        self.assert_refused(self.device("cancellation", receipt()), expected="CANARY")

    def run_cancelled(self, reject_next_fill=False):
        tree = ast.parse(DRIVER.read_text())
        function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "cancelled")
        calls = []
        class Fake:
            def authentication(self): calls.append("authentication")
            def authorization_observation(self): calls.append("capture_observation"); return OBSERVATION
            def unlock(self, master): calls.append("unlock")
            def cancel_authentication(self, *args): calls.append(("cancel_and_empty", len(args))); return {"fixture_return_from_before_unlock_ms": 500, "request_elapsed_ms": 1000}
            def decision(self): calls.append("fresh_main_decision"); return "memory_locked"
            def cancellation_observation(self, expected):
                self_expected = expected
                if self_expected != OBSERVATION: raise AssertionError("wrong_private_id")
                calls.append("matched_cancel_observation")
                return {"observation_matches_current_authorization": True}
            def tap(self, **kwargs): calls.append(("tap", kwargs))
            def wait(self, **kwargs): calls.append(("wait", kwargs)); return object()
            def authorization_status(self, expected, node):
                calls.append(("authorization_status", expected))
                if reject_next_fill: raise driver.Failed("authorization_status_not_observed")
                return {"status": expected}
        context = {"device": Fake(), "time": driver.time, "master": "CANARY_SYNTHETIC_INPUT", "GOOD": driver.GOOD, "Failed": driver.Failed}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), "<actual-cancelled-case>", "exec"), context)
        return context["cancelled"], calls

    def test_trim_global_decision_does_not_replace_current_receipt_and_real_behavior_checks(self):
        action, calls = self.run_cancelled()
        result = action()
        self.assertEqual(calls, ["authentication", "capture_observation", "unlock", ("cancel_and_empty", 2),
                                 "fresh_main_decision", "matched_cancel_observation", "authentication",
                                 ("tap", {"text": "Fill once"}), ("wait", {"text": "Locked or expired"}),
                                 ("authorization_status", "Locked or expired"), ("cancel_and_empty", 0)])
        self.assertEqual(result["provider_decision_before_next_request"], "memory_locked")
        self.assertEqual(result["new_authorization"]["status"], "Locked or expired")
        self.assertNotIn(OBSERVATION, json.dumps(result))

    def test_receipt_alone_cannot_pass_missing_real_rejected_fill(self):
        action, calls = self.run_cancelled(reject_next_fill=True)
        with self.assertRaisesRegex(driver.Failed, "authorization_status_not_observed"): action()
        self.assertIn("matched_cancel_observation", calls)
        self.assertNotIn(("cancel_and_empty", 0), calls)

    def test_original_timed_cancel_and_empty_helper_is_exactly_unchanged(self):
        tree = ast.parse(DRIVER.read_text())
        method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "cancel_authentication")
        self.assertEqual(hashlib.sha256(ast.dump(method, include_attributes=False).encode()).hexdigest(), BASELINE_CANCEL_HELPER_AST)

    def test_reviewed_qa19_remainder_preserves_cancel_observation_scope(self):
        class RemoveChanged(ast.NodeTransformer):
            def visit_FunctionDef(self, node):
                if node.name in {"authorization_observation", "cancellation_observation", "cancelled"}: return None
                return self.generic_visit(node)
        tree = RemoveChanged().visit(ast.parse(DRIVER.read_text()))
        self.assertEqual(hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest(), REVIEWED_QA19_REMAINDER_AST)
        self.assertEqual(len(driver.EXPECTED_CASES), 12)
        self.assertEqual(len(set(driver.EXPECTED_CASES)), 12)


if __name__ == "__main__":
    unittest.main(verbosity=2)
