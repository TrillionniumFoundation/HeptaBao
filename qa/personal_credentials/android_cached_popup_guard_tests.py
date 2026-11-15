#!/usr/bin/env python3
"""Host controls for QA16's clear/refocus transition, with no device calls.

The production driver methods consume the existing return suite's synthetic
server WMS/AMS shapes. Only the ADB boundary and clock are replaced. This suite
does not prove Android cache behavior; the unchanged device case must still
choose any offered locked placeholder and verify actual empty fixture fields.
"""
import ast
import importlib.util
import json
from pathlib import Path
import shlex
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location("cache_return_controls", Path(__file__).with_name("android_return_guard_tests.py"))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
driver = shared.driver


class CacheDevice(shared.ScriptedDevice):
    def __init__(self, clock, variant="valid", popup_after_clear=True):
        super().__init__(clock, variant, popup=False)
        self.current_case = "system_cached_plaintext_not_reusable"
        self.popup_after_clear = popup_after_clear
        self.cleared = False
        self.clear_touches = self.username_touches = 0

    def adb_command(self, *args, timeout=25, allow_failure=False):
        if args == ("exec-out", "uiautomator", "dump", "--compressed", "/dev/tty") and self.popup and self.variant == "presentation_absent":
            self.clock.advance(); self.commands.append(tuple(args)); self.ui_reads += 1
            tree = ET.Element("hierarchy", {"rotation": "0"})
            ET.SubElement(tree, "node", {"package": "android", "class": "android.widget.FrameLayout"})
            self.after_ui = True
            return ET.tostring(tree)
        if args == ("exec-out", "uiautomator", "dump", "--compressed", "/dev/tty") and not self.popup:
            self.clock.advance(); self.commands.append(tuple(args)); self.ui_reads += 1
            tree = ET.Element("hierarchy", {"rotation": "0"})
            ET.SubElement(tree, "node", {"text": "Clear fields", "package": driver.GOOD,
                "enabled": "true", "bounds": "[10,100][210,150]"})
            attrs = {"content-desc": "Synthetic username", "package": driver.GOOD,
                "resource-id": driver.GOOD + ":id/login_username", "enabled": "true",
                "bounds": "[10,200][210,250]"}
            if self.variant == "field_package": attrs["package"] = driver.DECOY
            if self.variant == "field_id": attrs["resource-id"] = driver.GOOD + ":id/login_password"
            if self.variant == "field_disabled": attrs["enabled"] = "false"
            if self.variant == "field_bounds": attrs["bounds"] = "[10,200][10,250]"
            ET.SubElement(tree, "node", attrs)
            if self.cleared: self.after_ui = True
            return ET.tostring(tree)
        if len(args) == 2 and args[0] == "shell":
            command = shlex.split(args[1])
            if command == ["input", "-d", "0", "tap", "110", "125"]:
                self.clock.advance(); self.commands.append(tuple(args)); self.clear_touches += 1
                if self.variant == "clear_unknown": raise driver.Failed("device_command_unavailable")
                self.cleared = True; self.popup = self.popup_after_clear
                return b""
            if command == ["input", "-d", "0", "tap", "110", "225"]:
                self.clock.advance(); self.commands.append(tuple(args)); self.username_touches += 1
                if self.variant == "username_unknown": raise driver.Failed("device_command_unavailable")
                self.popup = True
                return b""
        return super().adb_command(*args, timeout=timeout, allow_failure=allow_failure)


class CachedRefocusGuards(unittest.TestCase):
    def setUp(self):
        self.clock = shared.Clock()
        self.patches = [patch.object(driver, "time", self.clock),
            patch.object(driver.subprocess, "run", shared.denied_external),
            patch.object(driver.subprocess, "Popen", shared.denied_external)]
        for item in self.patches: item.start()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.assertEqual(shared.EXTERNAL_CALLS, [])

    def refused(self, variant, *, popup=True, clear=1, username=0, error=None):
        device = CacheDevice(self.clock, variant, popup)
        original = device._expected_fixture_session
        with self.assertRaises(driver.Failed) as rejected:
            device.cached_refocus()
        if error: self.assertEqual(str(rejected.exception), error)
        self.assertEqual((device.clear_touches, device.username_touches, device.back_calls), (clear, username, 0))
        self.assertEqual(device._expected_fixture_session, original)
        self.assertFalse(any(args[0] == "shell" and ("force-stop" in args[1] or "am start" in args[1]) for args in device.commands))
        return device

    def test_01_existing_bound_popup_does_not_search_obscured_username(self):
        device = CacheDevice(self.clock)
        result = device.cached_refocus()
        self.assertEqual(result["path"], "bound_popup_after_clear")
        self.assertEqual((device.clear_touches, device.username_touches, device.back_calls), (1, 0, 0))
        self.assertFalse(result["autofill_internal_session_id_observed"])
        self.assertEqual(device._expected_fixture_session, shared.BASE_SESSION)

    def test_02_fixture_path_uses_one_fresh_bound_display_zero_username_touch(self):
        device = CacheDevice(self.clock, popup_after_clear=False)
        result = device.cached_refocus()
        self.assertEqual(result["path"], "fresh_username_touch_after_clear")
        self.assertEqual((device.clear_touches, device.username_touches, device.back_calls), (1, 1, 0))
        inputs = [shlex.split(args[1]) for args in device.commands if args[0] == "shell" and shlex.split(args[1])[0] == "input"]
        self.assertEqual(inputs, [["input", "-d", "0", "tap", "110", "125"], ["input", "-d", "0", "tap", "110", "225"]])

    def test_03_plaintext_is_rejected_before_dismissal_or_field_touch(self):
        self.refused("plaintext", error="cached_plaintext_dataset_visible")

    def test_04_duplicate_locked_presentations_are_unknown(self):
        self.refused("presentation_duplicate", error="cached_popup_presentation_unrecognized")

    def test_05_other_package_cannot_supply_locked_presentation(self):
        self.refused("presentation_package", error="cached_popup_presentation_unrecognized")

    def test_06_disabled_locked_presentation_is_rejected(self):
        self.refused("presentation_disabled", error="cached_popup_presentation_unrecognized")

    def test_07_unknown_presentation_text_is_rejected(self):
        self.refused("presentation_unknown", error="cached_popup_presentation_unrecognized")

    def test_08_missing_locked_presentation_is_rejected(self):
        self.refused("presentation_absent", error="cached_popup_presentation_unrecognized")

    def test_09_non_system_popup_owner_is_rejected(self):
        self.refused("popup_owner")

    def test_10_non_supported_popup_type_is_rejected(self):
        self.refused("popup_type")

    def test_11_other_parent_cannot_claim_current_fixture(self):
        self.refused("popup_parent")

    def test_12_same_component_new_window_after_read_is_rejected(self):
        self.refused("parent_changed", error="cached_refocus_identity_unavailable")

    def test_13_missing_original_identity_refuses_before_clear(self):
        device = CacheDevice(self.clock); device._expected_fixture_session = None
        with self.assertRaises(driver.Failed): device.cached_refocus()
        self.assertEqual((device.clear_touches, device.username_touches), (0, 0))

    def test_14_wrong_selected_fixture_refuses_before_clear(self):
        device = CacheDevice(self.clock); device.expected_fixture = driver.DECOY
        with self.assertRaises(driver.Failed): device.cached_refocus()
        self.assertEqual((device.clear_touches, device.username_touches), (0, 0))

    def test_15_stale_field_coordinates_never_authorize_touch(self):
        self.refused("stale", popup=False, error="cached_username_sample_stale")

    def test_16_field_package_must_match_actual_fixture(self):
        self.refused("field_package", popup=False, error="fixture_node_package_changed")

    def test_17_field_resource_identity_must_be_username(self):
        self.refused("field_id", popup=False, error="cached_username_target_unavailable")

    def test_18_disabled_username_is_rejected(self):
        self.refused("field_disabled", popup=False, error="cached_username_target_unavailable")

    def test_19_empty_field_bounds_are_rejected(self):
        self.refused("field_bounds", popup=False, error="cached_username_bounds_invalid")

    def test_20_uncertain_username_touch_is_not_retried(self):
        self.refused("username_unknown", popup=False, username=1, error="device_command_unavailable")

    def test_21_uncertain_clear_touch_is_not_retried(self):
        self.refused("clear_unknown", error="device_command_unavailable")

    @staticmethod
    def actual_cached_case(device, clock):
        tree = ast.parse(shared.args.driver.read_text())
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "cached")
        env = {"device": device, "time": clock, "Failed": driver.Failed, "GOOD": driver.GOOD,
               "PROVIDER": driver.PROVIDER}
        module = ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[]))
        exec(compile(module, str(shared.args.driver), "exec"), env)
        return env["cached"]()

    def test_22_disappeared_observed_placeholder_cannot_pass_without_attempt(self):
        class Case:
            emptied = False
            def cached_refocus(self): return {"path": "bound_popup_after_clear"}
            def find(self, text): return None
            def empty(self): self.emptied = True
        device = Case()
        with self.assertRaisesRegex(driver.Failed, "cached_locked_presentation_disappeared"):
            self.actual_cached_case(device, self.clock)
        self.assertFalse(device.emptied)

    def test_23_cached_case_still_attempts_placeholder_and_actual_empty_verification(self):
        class Case:
            def __init__(self): self.calls = []; self.plaintext_checks = 0
            def cached_refocus(self): self.calls.append("refocus"); return {"path": "bound_popup_after_clear"}
            def find(self, text):
                if text == "Fill synthetic login once": self.plaintext_checks += 1; return None
                if text == "Unlock HeptaBao locally": return object()
                raise AssertionError("unknown selector")
            def tap(self, text): self.calls.append(("tap", text))
            def foreground(self): return (driver.PROVIDER, "org.heptabao.preview.AuthActivity")
            def wait(self, text): self.calls.append(("wait", text)); return object()
            def cancel_authentication(self): self.calls.append("cancel_authentication")
            def empty(self): self.calls.append("actual_fixture_empty_verification")
        device = Case(); result = self.actual_cached_case(device, self.clock)
        self.assertTrue(result["locked_placeholder_attempted"])
        self.assertTrue(result["authentication_reappeared"])
        self.assertEqual(device.plaintext_checks, 2)
        self.assertEqual(device.calls, ["refocus", ("tap", "Unlock HeptaBao locally"), ("wait", "Locked"),
            ("tap", "Fill once"), ("wait", "Locked or expired"), "cancel_authentication", "actual_fixture_empty_verification"])

    def test_24_public_helper_result_has_no_raw_window_or_intent_identity(self):
        for popup in (True, False):
            device = CacheDevice(self.clock, popup_after_clear=popup)
            public = json.dumps(device.cached_refocus())
            for value in ("ca123", "abc12", "def34", "10432", "private_synthetic_intent", "ActivityRecord{", "Window{"):
                self.assertNotIn(value, public)


if __name__ == "__main__":
    unittest.main(argv=[str(Path(__file__)), *shared.remaining])
