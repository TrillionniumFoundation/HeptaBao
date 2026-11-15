#!/usr/bin/env python3
"""Offline controls for a delayed locked popup in the original title budget.

Use actual driver parsers/return code with the original return suite's synthetic
WMS/AMS and a controlled ADB/clock boundary. No device or network is accessed.
"""
import importlib.util
from pathlib import Path
import shlex
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("late_popup_return_controls", Path(__file__).with_name("android_return_guard_tests.py"))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
driver = shared.driver


class DelayedDevice(shared.ScriptedDevice):
    def __init__(self, clock, variant="valid", *, initial_popup=False, delay=True):
        super().__init__(clock, variant, popup=initial_popup)
        self.initial_popup = initial_popup
        self.delay = delay
        self.late_triggered = self.trigger_on_final_focus = False
        self.reappeared = self.reappear_on_final_focus = False

    def adb_command(self, *args, timeout=25, allow_failure=False):
        command = shlex.split(args[1]) if len(args) == 2 and args[0] == "shell" else None
        if command == ["dumpsys", "activity", "top-resumed"] and not self.popup:
            if self.delay and not self.late_triggered and (not self.initial_popup or self.after_back):
                self.trigger_on_final_focus = True
            elif self.variant == "reappear" and self.after_back and not self.reappeared:
                self.reappear_on_final_focus = True
        if args == ("exec-out", "uiautomator", "dump", "--compressed", "/dev/tty"):
            if self.variant == "title_ui_late" and self.late_triggered and not self.after_back:
                self.clock.advance(25)
            if self.variant == "post_back_title_late" and self.after_back:
                self.clock.advance(25)
        if (command == ["dumpsys", "window"] and self.variant == "late_binding_budget"
                and self.after_ui and not self.after_back and not self.delay_applied):
            self.clock.advance(25); self.delay_applied = True
        result = super().adb_command(*args, timeout=timeout, allow_failure=allow_failure)
        if command == ["dumpsys", "window"] and not self.popup:
            if self.trigger_on_final_focus:
                # The just-returned fixture snapshot is valid. The next query
                # observes the popup that appeared after that snapshot.
                self.trigger_on_final_focus = False
                self.late_triggered = True
                self.popup = True
            elif self.reappear_on_final_focus:
                self.reappear_on_final_focus = False
                self.reappeared = True
                self.popup = True
        return result


class DelayedPopupGuards(unittest.TestCase):
    def setUp(self):
        self.clock = shared.Clock()
        self.patches = [patch.object(driver, "time", self.clock),
            patch.object(driver.subprocess, "run", shared.denied_external),
            patch.object(driver.subprocess, "Popen", shared.denied_external)]
        for item in self.patches: item.start()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.assertEqual(shared.EXTERNAL_CALLS, [])

    def refused(self, variant, back=0, expected=None, initial_popup=False):
        device = DelayedDevice(self.clock, variant, initial_popup=initial_popup)
        with self.assertRaises(driver.Failed) as rejected:
            device.return_to_fixture("after_auth_cancel")
        if expected: self.assertEqual(str(rejected.exception), expected)
        self.assertEqual(device.back_calls, back)
        self.assertEqual(device.return_diagnostics[-1]["back_command_count"], back)
        self.assertEqual(device._expected_fixture_session, shared.BASE_SESSION)
        self.assertEqual(device.return_diagnostics[-1]["result"], "refused")
        return device

    def test_01_delayed_locked_popup_uses_one_bound_back_then_same_fixture(self):
        device = DelayedDevice(self.clock)
        result = device.return_to_fixture("after_auth_cancel")
        self.assertTrue(result["late_popup_during_title_observation"])
        self.assertTrue(result["same_parent_session_after_back"])
        self.assertEqual(device.back_calls, 1)
        commands = [shlex.split(args[1]) for args in device.commands if args[0] == "shell"]
        self.assertEqual([row for row in commands if row[0] == "input"], [["input", "-d", "0", "keyevent", "KEYCODE_BACK"]])
        self.assertFalse(any(row[:1] == ["am"] for row in commands))
        self.assertEqual(device._expected_fixture_session, shared.BASE_SESSION)

    def test_02_first_delayed_plaintext_observation_refuses_before_back(self):
        self.refused("plaintext", expected="cached_plaintext_dataset_visible")

    def test_03_duplicate_locked_presentation_never_authorizes_back(self):
        self.refused("presentation_duplicate", expected="fixture_return_popup_presentation_unrecognized")

    def test_04_non_system_popup_owner_refuses_without_input(self):
        self.refused("popup_owner")

    def test_05_same_component_replacement_does_not_refresh_original_tuple(self):
        self.refused("parent_changed")

    def test_06_popup_reappearing_after_one_back_is_not_dismissed_again(self):
        self.refused("reappear", back=1, expected="fixture_return_popup_reappeared")

    def test_07_initial_back_already_spends_budget_before_delayed_popup(self):
        self.refused("valid", back=1, expected="fixture_return_popup_reappeared", initial_popup=True)

    def test_08_uncertain_back_result_is_never_retried(self):
        self.refused("input_unknown", back=1, expected="device_command_unavailable")

    def test_09_slow_title_ui_cannot_extend_original_25_second_budget(self):
        self.refused("title_ui_late", expected="expected_ui_missing")

    def test_10_budget_expiry_during_rebinding_never_authorizes_back(self):
        self.refused("late_binding_budget")

    def test_11_post_back_title_observation_cannot_restart_budget(self):
        self.refused("post_back_title_late", back=1, expected="expected_ui_missing")

    def test_12_direct_fixture_without_delayed_popup_still_needs_no_back(self):
        device = DelayedDevice(self.clock, delay=False)
        result = device.return_to_fixture("after_auth_cancel")
        self.assertEqual(result["result"], "returned_to_original_fixture")
        self.assertEqual(device.back_calls, 0)
        self.assertNotIn("late_popup_during_title_observation", result)



cache_spec = importlib.util.spec_from_file_location("late_cached_controls", Path(__file__).with_name("android_cached_popup_guard_tests.py"))
cache = importlib.util.module_from_spec(cache_spec)
cache_spec.loader.exec_module(cache)


class DelayedCachedDevice(cache.CacheDevice):
    def __init__(self, clock, variant="valid"):
        super().__init__(clock, variant, popup_after_clear=False)
        self.cached_late_triggered = False

    def adb_command(self, *args, timeout=25, allow_failure=False):
        command = shlex.split(args[1]) if len(args) == 2 and args[0] == "shell" else None
        if (self.variant == "cached_ui_late" and self.cached_late_triggered
                and args == ("exec-out", "uiautomator", "dump", "--compressed", "/dev/tty")):
            self.clock.advance(25)
        result = super().adb_command(*args, timeout=timeout, allow_failure=allow_failure)
        if command == ["dumpsys", "window"] and self.cleared and not self.cached_late_triggered and not self.popup:
            self.cached_late_triggered = True
            self.popup = True
        return result


class LateCachedPopupGuards(unittest.TestCase):
    def setUp(self):
        self.clock = cache.shared.Clock()
        self.patches = [patch.object(cache.driver, "time", self.clock),
            patch.object(cache.driver.subprocess, "run", cache.shared.denied_external),
            patch.object(cache.driver.subprocess, "Popen", cache.shared.denied_external)]
        for item in self.patches: item.start()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.assertEqual(cache.shared.EXTERNAL_CALLS, [])

    def test_13_delayed_cached_popup_is_observed_without_back_or_blind_username_touch(self):
        device = DelayedCachedDevice(self.clock)
        result = device.cached_refocus()
        self.assertTrue(result["late_popup_during_username_observation"])
        self.assertEqual(result["path"], "bound_popup_after_clear")
        self.assertEqual((device.clear_touches, device.username_touches, device.back_calls), (1, 0, 0))
        self.assertEqual(device._expected_fixture_session, cache.shared.BASE_SESSION)

    def test_14_delayed_cached_plaintext_is_rejected_before_any_dismissal(self):
        device = DelayedCachedDevice(self.clock, "plaintext")
        with self.assertRaisesRegex(cache.driver.Failed, "cached_plaintext_dataset_visible"):
            device.cached_refocus()
        self.assertEqual((device.clear_touches, device.username_touches, device.back_calls), (1, 0, 0))

    def test_15_delayed_cached_popup_cannot_replace_original_parent(self):
        device = DelayedCachedDevice(self.clock, "parent_changed")
        with self.assertRaises(cache.driver.Failed): device.cached_refocus()
        self.assertEqual((device.clear_touches, device.username_touches, device.back_calls), (1, 0, 0))
        self.assertEqual(device._expected_fixture_session, cache.shared.BASE_SESSION)

    def test_16_delayed_cached_ui_cannot_extend_existing_username_budget(self):
        device = DelayedCachedDevice(self.clock, "cached_ui_late")
        with self.assertRaisesRegex(cache.driver.Failed, "expected_ui_missing"):
            device.cached_refocus()
        self.assertEqual((device.clear_touches, device.username_touches, device.back_calls), (1, 0, 0))


if __name__ == "__main__":
    unittest.main(argv=[str(Path(__file__)), *shared.remaining])
