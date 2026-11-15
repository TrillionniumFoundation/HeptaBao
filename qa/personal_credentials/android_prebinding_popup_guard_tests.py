#!/usr/bin/env python3
"""Actual return-path controls for a popup arriving before the first binding.

Only the existing controlled ADB/clock boundary is replaced. The real driver
parses synthetic WMS/AMS bytes and performs no external command or device call.
These controls do not identify the unknown subcondition in the r16 report.
"""
import importlib.util
import json
from pathlib import Path
import shlex
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("prebinding_return_controls", Path(__file__).with_name("android_return_guard_tests.py"))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
driver = shared.driver


class PrebindingDevice(shared.ScriptedDevice):
    def __init__(self, clock, variant="valid"):
        super().__init__(clock, variant, popup=False)
        self.first_focus = True
        self.binding_delay_applied = False

    def shape(self):
        token, task, parent, owner, popup_id = super().shape()
        if not self.first_focus and self.variant == "replaced_parent": parent = "def35"
        return token, task, parent, owner, popup_id

    def adb_command(self, *args, timeout=25, allow_failure=False):
        command = shlex.split(args[1]) if len(args) == 2 and args[0] == "shell" else None
        first = command == ["dumpsys", "window"] and self.first_focus
        if (command == ["dumpsys", "window"] and not self.first_focus
                and self.variant == "binding_budget" and not self.binding_delay_applied):
            self.clock.advance(25); self.binding_delay_applied = True
        result = super().adb_command(*args, timeout=timeout, allow_failure=allow_failure)
        if first:
            self.first_focus = False
            if self.variant not in {"stable", "focused_app_missing", "focused_app_multiple", "wrong_window_package"}:
                self.popup = True
            # Return the earlier, valid fixture bytes unchanged. Only the next
            # system query observes the different (possibly invalid) surface.
            return result
        if command == ["dumpsys", "window"]:
            value = result.decode()
            if self.variant == "focused_app_missing":
                value = "\n".join(row for row in value.splitlines() if "mFocusedApp=" not in row) + "\n"
            elif self.variant == "focused_app_multiple":
                marker = "    mFocusedApp=" + shared.activity() + "\n"
                value = value.replace(marker, marker + marker)
            elif self.variant == "unknown_title":
                value = value.replace("u0 Autofill UI}", "u0 private.unrecognized.Window}")
            result = value.encode()
        if command and command[:3] == ["dumpsys", "window", "-a"] and self.variant == "wrong_window_package":
            result = result.replace(("package=" + shared.PACKAGE).encode(), ("package=" + driver.PROVIDER).encode())
        return result


class PrebindingPopupGuards(unittest.TestCase):
    def setUp(self):
        self.clock = shared.Clock()
        self.patches = [patch.object(driver, "time", self.clock),
                        patch.object(driver.subprocess, "run", shared.denied_external),
                        patch.object(driver.subprocess, "Popen", shared.denied_external)]
        for item in self.patches: item.start()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.assertEqual(shared.EXTERNAL_CALLS, [])

    def refused(self, variant, *, back=0, error=None):
        device = PrebindingDevice(self.clock, variant)
        with self.assertRaises(driver.Failed) as rejected:
            device.return_to_fixture("after_auth_cancel")
        if error: self.assertEqual(str(rejected.exception), error)
        self.assertEqual(device.back_calls, back)
        self.assertEqual(device.return_diagnostics[-1]["back_command_count"], back)
        self.assertEqual(device._expected_fixture_session, shared.BASE_SESSION)
        self.assertEqual(device.return_diagnostics[-1]["result"], "refused")
        return device

    def test_01_hint_fixture_then_bound_popup_uses_exactly_one_back(self):
        device = PrebindingDevice(self.clock)
        result = device.return_to_fixture("after_auth_cancel")
        self.assertTrue(result["popup_observed_at_direct_binding"])
        self.assertTrue(result["same_parent_session_after_back"])
        self.assertEqual(result["result"], "returned_to_original_fixture")
        self.assertEqual(device.back_calls, 1)
        self.assertEqual(device._expected_fixture_session, shared.BASE_SESSION)
        commands = [shlex.split(row[1]) for row in device.commands if row[0] == "shell"]
        self.assertEqual([row for row in commands if row[0] == "input"], [["input", "-d", "0", "keyevent", "KEYCODE_BACK"]])
        self.assertFalse(any(row[0] == "am" for row in commands))

    def test_02_missing_focused_app_still_refuses_and_records_zero(self):
        device = self.refused("focused_app_missing", error="fixture_return_identity_unavailable")
        diagnostic = device.return_diagnostics[-1]["last_binding_observation"]
        self.assertEqual(diagnostic["identity_components"]["focused_app_field_count"], "zero")
        self.assertEqual(diagnostic["identity_components"]["focused_app_shape"]["shape"], "absent")
        self.assertFalse(diagnostic["bound"])
        self.assertEqual(device.ui_reads, 0)

    def test_03_duplicate_focused_app_still_refuses_and_records_multiple(self):
        device = self.refused("focused_app_multiple", error="fixture_return_identity_unavailable")
        self.assertEqual(device.return_diagnostics[-1]["last_binding_observation"]["identity_components"]["focused_app_field_count"], "multiple")
        self.assertEqual(device.ui_reads, 0)

    def test_04_wrong_window_package_still_refuses_without_ui(self):
        device = self.refused("wrong_window_package", error="fixture_return_identity_unavailable")
        components = device.return_diagnostics[-1]["last_binding_observation"]["identity_components"]
        self.assertEqual(components["window_package_category"], "own_provider")
        self.assertEqual(components["focus_title_category"], "expected_fixture")
        self.assertEqual(device.ui_reads, 0)

    def test_05_non_system_popup_owner_never_authorizes_ui_or_input(self):
        device = self.refused("popup_owner", error="fixture_return_identity_unavailable")
        self.assertEqual(device.return_diagnostics[-1]["reason"], "popup_not_system_owned")
        self.assertEqual(device.ui_reads, 0)

    def test_06_same_component_new_parent_never_refreshes_original_tuple(self):
        device = self.refused("replaced_parent", error="fixture_return_identity_unavailable")
        self.assertEqual(device.return_diagnostics[-1]["reason"], "fixture_return_session_changed")
        self.assertFalse(device.return_diagnostics[-1]["last_binding_observation"]["original_session_matches"])
        self.assertEqual(device.ui_reads, 0)

    def test_07_unknown_title_never_selects_a_validator_or_reads_ui(self):
        device = self.refused("unknown_title", error="fixture_return_identity_unavailable")
        diagnostic = device.return_diagnostics[-1]["last_binding_observation"]
        self.assertEqual(diagnostic["selected_kind"], "not_selected")
        self.assertEqual(diagnostic["identity_components"]["focus_title_category"], "other")
        self.assertEqual(device.ui_reads, 0)

    def test_08_plaintext_popup_is_refused_before_any_back(self):
        device = self.refused("plaintext", error="cached_plaintext_dataset_visible")
        self.assertGreater(device.ui_reads, 0)

    def test_09_slow_first_binding_cannot_extend_original_25_seconds(self):
        device = self.refused("binding_budget", error="expected_ui_missing")
        self.assertTrue(device.binding_delay_applied)
        self.assertEqual(device.ui_reads, 0)

    def test_10_uncertain_back_is_never_retried(self):
        self.refused("input_unknown", back=1, error="device_command_unavailable")

    def test_11_strict_fixture_recheck_does_not_reinterpret_a_popup(self):
        device = PrebindingDevice(self.clock)
        self.assertEqual(device.foreground(), (shared.PACKAGE, driver.ACTIVITY))
        with self.assertRaisesRegex(driver.FocusUnavailable, "fixture_return_window_identity"):
            device._return_snapshot("fixture", shared.BASE_SESSION)
        self.assertEqual((device.back_calls, device.ui_reads), (0, 0))

    def test_12_stable_fixture_needs_no_back_or_classification_change(self):
        device = PrebindingDevice(self.clock, "stable")
        result = device.return_to_fixture("after_auth_fill")
        self.assertEqual(result["result"], "returned_to_original_fixture")
        self.assertEqual(device.back_calls, 0)
        self.assertNotIn("popup_observed_at_direct_binding", result)

    def test_13_popup_still_present_after_back_does_not_get_a_second_key(self):
        self.refused("popup_stays", back=1, error="fixture_return_not_observed")

    def test_14_closed_diagnostics_never_contain_raw_system_identity(self):
        device = self.refused("unknown_title", error="fixture_return_identity_unavailable")
        public = json.dumps(device.return_diagnostics)
        for forbidden in ["private.unrecognized.Window", "ca123", "def34", "abc12", shared.PACKAGE, "private_synthetic_intent_text"]:
            self.assertNotIn(forbidden, public)

    def test_15_popup_replaced_after_ui_is_rejected_before_back(self):
        self.refused("popup_changed", error="fixture_return_identity_unavailable")


if __name__ == "__main__":
    unittest.main(argv=[str(Path(__file__)), *shared.remaining])
