#!/usr/bin/env python3
"""Offline falsification of QA13's single Back and original-fixture return.

The actual driver methods parse synthetic server-format WMS/AMS and UI bytes.
Only the ADB boundary and monotonic clock are replaced. No device or network is
used; these controls do not confer Android or product qualification.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


parser = argparse.ArgumentParser()
parser.add_argument("--driver", type=Path, default=Path(__file__).with_name("android_live.py"))
args, remaining = parser.parse_known_args()
spec = importlib.util.spec_from_file_location("android_return_candidate", args.driver)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
PACKAGE = driver.GOOD
COMPONENT = PACKAGE + "/" + driver.ACTIVITY
BASE_SESSION = ("def34", ("ca123", 42), 10432)
EXTERNAL_CALLS = []


def denied_external(*args, **kwargs):
    EXTERNAL_CALLS.append("external_process_attempt")
    raise AssertionError("external processes are forbidden in this host profile")


class Clock:
    def __init__(self): self.value = 100.0
    def monotonic(self): return self.value
    def monotonic_ns(self): return int(self.value * 1_000_000_000)
    def sleep(self, seconds): self.value += seconds
    def advance(self, seconds=0.005): self.value += seconds


def activity(token="ca123", task=42, package=PACKAGE):
    return "ActivityRecord{" + token + " u0 " + package + "/" + driver.ACTIVITY + " t" + str(task) + "}"


def focus_text(title, window, record):
    return ("WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)\n"
            "  Display: mDisplayId=0\n"
            f"    mCurrentFocus=Window{{{window} u0 {title}}}\n"
            f"    mFocusedApp={record}\n"
            "WINDOW MANAGER WINDOWS (dumpsys window windows)\n"
            "  mTopFocusedDisplayId=0\n")


def window_text(window, title, owner, package, kind, record, task=42, parent=None):
    rows = ["WINDOW MANAGER WINDOWS (dumpsys window windows)",
            f"  Window #0 Window{{{window} u0 {title}}}:",
            f"    mDisplayId=0 taskId={task} mSession=Session{{ignored}} mClient=android.os.BinderProxy@ignored",
            f"    mOwnerUid={owner} showForAllUsers=false package={package} appop=NONE",
            f"    mAttrs={{(0,0)(matchxwrap) ty={kind} fmt=TRANSLUCENT}}",
            f"    mToken={record}", f"    mActivityRecord={record}",
            "    isOnScreen=true", "    isVisible=true"]
    if parent:
        rows.append(f"    mParentWindow=Window{{{parent} u0 {COMPONENT}}} mLayoutAttached=true")
    rows += ["  mGlobalConfiguration=discarded", "  mTopFocusedDisplayId=0"]
    return "\n".join(rows) + "\n"


def top_resumed(parent, package=PACKAGE):
    return ("ACTIVITY MANAGER TOP-RESUMED (dumpsys activity top-resumed)\n"
            f"packageName={package} processName={package}\n"
            "launchedFromUid=2000 launchedFromPackage=com.android.shell launchedFromFeature=null userId=0\n"
            "Intent { act=private_synthetic_intent_text_must_not_survive }\n"
            f"mActivityComponent={package}/{driver.ACTIVITY}\n"
            "state=RESUMED delayedResume=false finishing=false\n"
            f"windows=[Window{{{parent} u0 {package}/{driver.ACTIVITY}}}]\n")


class ScriptedDevice(driver.Device):
    """Run real foreground/ui/return code with a strict, in-memory ADB boundary."""
    def __init__(self, clock, variant="valid", popup=True):
        self.clock, self.variant, self.popup = clock, variant, popup
        self.adb = "/never/execute/adb"
        self.serial = "not_a_device_serial"
        self.expected_fixture = PACKAGE
        self.current_case = "locked_fill_refused"
        self.tap_diagnostics, self.return_diagnostics = [], []
        self.return_phase = "not_observed"
        self._expected_fixture_session = BASE_SESSION
        self._pi_identifiers, self._ui_parents = {}, {}
        self._ui_started_ns = self._ui_finished_ns = 0
        self.last_wait = self.last_public_ui = None
        self.commands, self.back_calls, self.ui_reads = [], 0, 0
        self.after_ui = self.after_back = self.after_title = self.focus_flip = self.delay_applied = False
        self.late_applied = False

    def shape(self):
        token, task, parent, owner, popup_id = "ca123", 42, "def34", 10432, "abc12"
        if self.after_ui and self.variant == "popup_changed": popup_id = "abc13"
        if self.after_ui and self.variant == "parent_changed": parent = "def35"
        if self.after_back:
            if self.variant == "post_window": parent = "def35"
            if self.variant == "post_record": token = "ca124"
            if self.variant == "post_task": task = 43
            if self.variant == "post_owner": owner = 10433
        if self.after_title and self.variant == "title_changes_record": token = "ca125"
        return token, task, parent, owner, popup_id

    def adb_command(self, *args, timeout=25, allow_failure=False):
        self.clock.advance()
        self.commands.append(tuple(args))
        if args == ("exec-out", "uiautomator", "dump", "--compressed", "/dev/tty"):
            self.ui_reads += 1
            hierarchy = ET.Element("hierarchy", {"rotation": "0"})
            if self.popup:
                attrs = {"text": "Unlock HeptaBao locally", "resource-id": driver.PROVIDER + ":id/presentation_text",
                         "package": driver.PROVIDER, "enabled": "true", "bounds": "[10,20][200,80]"}
                if self.variant == "presentation_package": attrs["package"] = driver.DECOY
                if self.variant == "presentation_disabled": attrs["enabled"] = "false"
                if self.variant == "presentation_unknown": attrs["text"] = "unrecognized private text"
                if self.variant != "presentation_absent": ET.SubElement(hierarchy, "node", attrs)
                if self.variant == "presentation_duplicate": ET.SubElement(hierarchy, "node", attrs)
                if self.variant == "plaintext":
                    ET.SubElement(hierarchy, "node", {"text": "Fill synthetic login once", "package": driver.PROVIDER})
                self.after_ui = True
            else:
                package = driver.DECOY if self.variant == "post_title_package" else PACKAGE
                ET.SubElement(hierarchy, "node", {"text": "HeptaBao synthetic native login", "package": package,
                                                   "enabled": "true", "bounds": "[10,20][200,80]"})
                self.after_title = True
            return ET.tostring(hierarchy)
        if len(args) != 2 or args[0] != "shell":
            raise AssertionError("unrecognized ADB command")
        command = shlex.split(args[1])
        token, task, parent, owner, popup_id = self.shape()
        record = activity(token, task)
        if self.after_ui and self.variant == "stale" and not self.delay_applied:
            self.clock.advance(1.0); self.delay_applied = True
        if command == ["dumpsys", "window"]:
            if not self.late_applied and (self.variant in {"late_fixture", "late_popup"}
                                          or (self.after_back and self.variant == "late_after_back")):
                self.clock.advance(3.0); self.late_applied = True
            title = "Autofill UI" if self.popup else COMPONENT
            identity = popup_id if self.popup else parent
            if self.variant == "wrong_app": title = "private.other/private.other.SecretActivity"
            if self.variant == "unknown_focus": title = "private unrelated window"
            if self.focus_flip: identity = "abc13"
            return focus_text(title, identity, record).encode()
        if command[:3] == ["dumpsys", "window", "-a"] and len(command) == 4:
            requested = command[3]
            if requested == popup_id and self.popup:
                popup_owner = 1001 if self.variant == "popup_owner" else 1000
                popup_package = PACKAGE if self.variant == "popup_package" else "android"
                kind = "SYSTEM_DIALOG" if self.variant == "popup_type" else "APPLICATION_ABOVE_SUB_PANEL"
                link = "bad00" if self.variant == "popup_parent" else parent
                raw = window_text(popup_id, "Autofill UI", popup_owner, popup_package, kind, record, task, link)
            elif requested == parent:
                raw = window_text(parent, COMPONENT, owner, PACKAGE, "BASE_APPLICATION", record, task)
                if self.variant == "initial_parent_uid": raw = raw.replace("mOwnerUid=10432", "mOwnerUid=1000")
            else:
                raise driver.Failed("window_selector_unavailable")
            return raw.encode()
        if command == ["dumpsys", "activity", "top-resumed"]:
            raw = top_resumed(parent)
            if self.variant == "top_paused" or (self.after_back and self.variant == "post_top_paused"):
                raw = raw.replace("state=RESUMED", "state=PAUSED")
            if self.after_ui and not self.after_back and self.variant == "refocus_changed": self.focus_flip = True
            return raw.encode()
        if command == ["input", "-d", "0", "keyevent", "KEYCODE_BACK"]:
            self.back_calls += 1
            if self.variant == "input_unknown": raise driver.Failed("device_command_unavailable")
            self.after_back = True
            if self.variant != "popup_stays": self.popup = False
            return b""
        if command == ["am", "force-stop", "--user", "0", PACKAGE]:
            return b""
        if command == ["am", "start", "--user", "0", "--display", "0", "-W", "-f", "0x10008000", "-n", COMPONENT]:
            self.popup = False
            return ("Status: ok\nActivity: " + COMPONENT + "\n").encode()
        raise AssertionError("unrecognized shell command")


class ReturnGuards(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.patches = [patch.object(driver, "time", self.clock),
                        patch.object(driver.subprocess, "run", denied_external),
                        patch.object(driver.subprocess, "Popen", denied_external)]
        for item in self.patches: item.start()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.assertEqual(EXTERNAL_CALLS, [])

    def refused(self, variant, *, back=0, popup=True, expected=None):
        device = ScriptedDevice(self.clock, variant, popup)
        with self.assertRaises(driver.Failed) as error:
            device.return_to_fixture("after_auth_cancel")
        self.assertEqual(device.back_calls, back)
        self.assertEqual(device.return_diagnostics[-1]["back_command_count"], back)
        self.assertEqual(device.return_diagnostics[-1]["result"], "refused")
        if expected is not None: self.assertEqual(str(error.exception), expected)
        return device

    def test_01_bound_popup_single_display_zero_back_same_fixture(self):
        device = ScriptedDevice(self.clock)
        result = device.return_to_fixture("after_auth_cancel")
        self.assertEqual(device.back_calls, 1)
        self.assertTrue(result["same_parent_session_after_back"])
        self.assertEqual(result["result"], "returned_to_original_fixture")
        self.assertIn(("shell", "input -d 0 keyevent KEYCODE_BACK"), device.commands)

    def test_02_direct_original_fixture_needs_no_back(self):
        device = ScriptedDevice(self.clock, popup=False)
        result = device.return_to_fixture("after_auth_fill")
        self.assertEqual(device.back_calls, 0)
        self.assertTrue(result["focus_metadata_after_return"]["original_session_checked"])

    def test_03_wrong_system_owner_no_input_or_ui(self):
        self.assertEqual(self.refused("popup_owner").ui_reads, 0)

    def test_04_wrong_system_package_no_input_or_ui(self):
        self.assertEqual(self.refused("popup_package").ui_reads, 0)

    def test_05_unsupported_popup_type_no_input_or_ui(self):
        self.assertEqual(self.refused("popup_type").ui_reads, 0)

    def test_06_parent_mismatch_no_input_or_ui(self):
        self.assertEqual(self.refused("popup_parent").ui_reads, 0)

    def test_07_wrong_app_never_reads_ui_or_keys(self):
        self.assertEqual(self.refused("wrong_app").ui_reads, 0)

    def test_08_unknown_focus_never_reads_ui_or_keys(self):
        self.assertEqual(self.refused("unknown_focus").ui_reads, 0)

    def test_09_plaintext_dataset_rejected_before_dismiss(self):
        self.refused("plaintext", expected="cached_plaintext_dataset_visible")

    def test_10_duplicate_presentation_rejected(self):
        self.refused("presentation_duplicate")

    def test_11_missing_presentation_rejected(self):
        self.refused("presentation_absent")

    def test_12_wrong_presentation_package_rejected(self):
        self.refused("presentation_package")

    def test_13_disabled_presentation_rejected(self):
        self.refused("presentation_disabled")

    def test_14_unknown_presentation_text_rejected(self):
        self.refused("presentation_unknown")

    def test_15_popup_changes_after_ui_no_back(self):
        self.refused("popup_changed")

    def test_16_parent_changes_after_ui_no_back(self):
        self.refused("parent_changed")

    def test_17_final_focus_changes_after_top_record_no_back(self):
        self.refused("refocus_changed")

    def test_18_at_least_one_second_old_ui_no_back(self):
        self.refused("stale", expected="fixture_return_popup_sample_stale")

    def test_19_uncertain_input_never_retried(self):
        self.refused("input_unknown", back=1, expected="device_command_unavailable")

    def test_20_popup_stays_no_second_back(self):
        self.refused("popup_stays", back=1, expected="fixture_return_not_observed")

    def test_21_post_back_new_fixture_window_rejected(self):
        self.refused("post_window", back=1)

    def test_22_post_back_new_activity_record_rejected(self):
        self.refused("post_record", back=1)

    def test_23_post_back_changed_task_rejected(self):
        self.refused("post_task", back=1)

    def test_24_post_back_changed_owner_rejected(self):
        self.refused("post_owner", back=1)

    def test_25_post_back_not_resumed_rejected(self):
        self.refused("post_top_paused", back=1)

    def test_26_post_back_title_node_wrong_package_rejected(self):
        self.refused("post_title_package", back=1, expected="fixture_node_package_changed")

    def test_27_missing_original_session_refuses_before_query(self):
        device = ScriptedDevice(self.clock)
        device._expected_fixture_session = None
        with self.assertRaises(driver.Failed): device.return_to_fixture("after_auth_cancel")
        self.assertEqual(device.commands, [])

    def test_28_unknown_origin_refuses_before_query(self):
        device = ScriptedDevice(self.clock)
        with self.assertRaises(driver.Failed): device.return_to_fixture("unrecognized")
        self.assertEqual(device.commands, [])

    def test_29_setup_captures_session_with_only_existing_launch(self):
        device = ScriptedDevice(self.clock, popup=False)
        device._expected_fixture_session = None
        device.fixture()
        self.assertEqual(device._expected_fixture_session, BASE_SESSION)
        commands = [shlex.split(row[1]) for row in device.commands if row[0] == "shell"]
        self.assertEqual(sum(row[:2] == ["am", "start"] for row in commands), 1)
        self.assertEqual(sum(row[:2] == ["am", "force-stop"] for row in commands), 1)
        self.assertEqual(device.back_calls, 0)

    def test_30_setup_does_not_capture_unbound_system_owner(self):
        device = ScriptedDevice(self.clock, "initial_parent_uid", popup=False)
        device._expected_fixture_session = None
        with self.assertRaises(driver.Failed): device.fixture()
        self.assertIsNone(device._expected_fixture_session)
        self.assertEqual(device.back_calls, 0)

    def test_31_second_verification_does_not_repeat_back_or_launch(self):
        device = ScriptedDevice(self.clock)
        device.return_to_fixture("after_auth_cancel")
        device.return_to_fixture("before_fixture_verification")
        self.assertEqual(device.back_calls, 1)
        self.assertEqual(device.return_diagnostics[-1]["back_command_count"], 0)
        self.assertFalse(any(row[0] == "shell" and shlex.split(row[1])[:1] == ["am"] for row in device.commands))

    def test_32_public_return_diagnostics_do_not_contain_raw_identity(self):
        device = ScriptedDevice(self.clock)
        device.return_to_fixture("after_auth_cancel")
        public = json.dumps(device.return_diagnostics)
        for value in ("ca123", "abc12", "def34", "10432", "private_synthetic_intent", COMPONENT, "ActivityRecord{", "Window{"):
            self.assertNotIn(value, public)

    def test_33_direct_fixture_still_requires_authoritative_resumed_state(self):
        self.refused("top_paused", popup=False)

    def test_34_existing_session_mismatch_refused_before_ui(self):
        device = ScriptedDevice(self.clock)
        device._expected_fixture_session = ("def35", ("ca123", 42), 10432)
        with self.assertRaises(driver.Failed): device.return_to_fixture("after_auth_cancel")
        self.assertEqual(device.back_calls, 0)
        self.assertEqual(device.ui_reads, 0)

    def test_35_late_successful_fixture_query_cannot_extend_deadline(self):
        self.refused("late_fixture", popup=False, expected="fixture_return_not_observed")

    def test_36_late_successful_popup_query_never_authorizes_back(self):
        self.refused("late_popup", expected="fixture_return_not_observed")

    def test_37_late_post_back_fixture_query_refused_without_retry(self):
        self.refused("late_after_back", back=1, expected="fixture_return_not_observed")

    def test_38_same_component_replacement_after_title_read_is_refused(self):
        for popup in (True, False):
            with self.subTest(popup=popup):
                self.refused("title_changes_record", popup=popup, back=int(popup), expected="fixture_return_identity_unavailable")


if __name__ == "__main__":
    unittest.main(argv=[str(Path(__file__)), *remaining])
