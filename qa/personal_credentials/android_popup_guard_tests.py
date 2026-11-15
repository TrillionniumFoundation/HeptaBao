#!/usr/bin/env python3
"""Offline falsification tests for QA12's narrow system Autofill window contract.

Inputs below are synthetic upstream-format metadata, not device observations.
These tests never invoke ADB, install packages, or confer phone qualification.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import time
import unittest
import xml.etree.ElementTree as ET


parser = argparse.ArgumentParser()
parser.add_argument("--driver", type=Path, default=Path(__file__).with_name("android_live.py"))
args, remaining = parser.parse_known_args()
spec = importlib.util.spec_from_file_location("android_popup_candidate", args.driver)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
PACKAGE = driver.GOOD
COMPONENT = PACKAGE + "/" + driver.ACTIVITY
ACTIVITY = "ActivityRecord{ca123 u0 " + COMPONENT + " t42}"


def focus_text(title="Autofill UI", window="abc12", activity=ACTIVITY, top=0):
    return ("WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)\n"
            "  Display: mDisplayId=0\n"
            f"    mCurrentFocus=Window{{{window} u0 {title}}}\n"
            f"    mFocusedApp={activity}\n"
            "WINDOW MANAGER WINDOWS (dumpsys window windows)\n"
            f"  mTopFocusedDisplayId={top}\n")


def window_text(window, title, owner, package, kind, parent=None):
    lines = ["WINDOW MANAGER WINDOWS (dumpsys window windows)",
             f"  Window #0 Window{{{window} u0 {title}}}:",
             "    mDisplayId=0 taskId=42 mSession=Session{ignored} mClient=android.os.BinderProxy@ignored",
             f"    mOwnerUid={owner} showForAllUsers=false package={package} appop=NONE",
             f"    mAttrs={{(0,0)(matchxwrap) ty={kind} fmt=TRANSLUCENT}}",
             f"    mToken={ACTIVITY}", f"    mActivityRecord={ACTIVITY}",
             "    isOnScreen=true", "    isVisible=true"]
    if parent:
        lines.append(f"    mParentWindow=Window{{{parent} u0 {COMPONENT}}} mLayoutAttached=true")
    lines += ["  mGlobalConfiguration=unrelated_omitted", "  mTopFocusedDisplayId=0"]
    return "\n".join(lines) + "\n"


POPUP = window_text("abc12", "Autofill UI", 1000, "android", "APPLICATION_ABOVE_SUB_PANEL", "def34")
PARENT = window_text("def34", COMPONENT, 10432, PACKAGE, "BASE_APPLICATION")
ACTIVITIES = ("ACTIVITY MANAGER TOP-RESUMED (dumpsys activity top-resumed)\n"
              f"packageName={PACKAGE} processName={PACKAGE}\n"
              "launchedFromUid=2000 launchedFromPackage=com.android.shell launchedFromFeature=null userId=0\n"
              "Intent { act=synthetic_private_intent_must_not_survive }\n"
              f"mActivityComponent={COMPONENT}\n"
              "state=RESUMED delayedResume=false finishing=false\n"
              f"windows=[Window{{def34 u0 {COMPONENT}}}]\n")


class PopupGuards(unittest.TestCase):
    def setUp(self):
        self.focus = driver._focus_snapshot(focus_text())
        self.popup = driver._window_details(POPUP, "abc12")
        self.parent = driver._window_details(PARENT, "def34")

    def evaluate(self, focus=None, popup=None, parent=None, activities=None, final=None):
        return driver.autofill_popup_metadata(focus or self.focus, popup or self.popup,
                                             parent or self.parent, activities or ACTIVITIES,
                                             final or self.focus, PACKAGE)

    def rejected(self, **values):
        with self.assertRaises(driver.FocusUnavailable):
            self.evaluate(**values)

    def test_complete_system_parent_resumed_chain(self):
        result = self.evaluate()
        self.assertTrue(result["available"])
        self.assertEqual(result["classification"], "bound_system_autofill_popup")

    def test_android16_decimal_identity_renderings(self):
        for token in ("123456789", "1234567890", "2147483647", "-2147483648"):
            with self.subTest(shape="canonical_signed_int"):
                identity = driver._activity_identity(ACTIVITY.replace("ca123", token), PACKAGE)
                self.assertEqual(identity, (token, 42))

    def test_identity_unknown_overflow_and_noncanonical_decimal_refused(self):
        for token in ("2147483648", "-2147483649", "0123456789", "+123456789", "abcdef123", "unknown"):
            with self.subTest(shape="invalid_identity"), self.assertRaises(driver.FocusUnavailable):
                driver._activity_identity(ACTIVITY.replace("ca123", token), PACKAGE)

    def test_equal_integer_different_spelling_cannot_merge_record_identity(self):
        focus = {**self.focus, "activity": ACTIVITY.replace("ca123", "123456789")}
        popup = {**self.popup, "token": ACTIVITY.replace("ca123", "75bcd15"), "activity": focus["activity"]}
        self.rejected(focus=focus, popup=popup, final=focus)

    def test_finishing_exiting_and_initial_incomplete_records_stay_refused(self):
        for value in (ACTIVITY[:-1] + " f}}", ACTIVITY[:-1] + " isExiting}", ACTIVITY.split(" t42")[0]):
            with self.subTest(shape="nonactive_or_incomplete"):
                with self.assertRaises(driver.FocusUnavailable): driver._activity_identity(value, PACKAGE)
                self.assertIn(driver._activity_shape(value, PACKAGE)["shape"], {"finishing_or_exiting", "incomplete_record"})

    def test_closed_shape_metadata_does_not_reveal_identity_or_other_target(self):
        values = [ACTIVITY.replace("ca123", "1234567890"), ACTIVITY.replace(COMPONENT, "private.other/private.other.SecretActivity"), "unrecognized secret_field_value"]
        for value in values:
            encoded = json.dumps(driver._activity_shape(value, PACKAGE))
            for sensitive in ("1234567890", "ca123", "private.other", "SecretActivity", "secret_field_value", COMPONENT, "42"):
                self.assertNotIn(sensitive, encoded)

    def test_relations_are_unknown_for_unparsed_records(self):
        self.assertIsNone(driver._activity_relation(None, ACTIVITY, PACKAGE))
        self.assertIsNone(driver._activity_relation("null", ACTIVITY, PACKAGE))
        self.assertFalse(driver._activity_relation(ACTIVITY, ACTIVITY.replace("ca123", "ca124"), PACKAGE))

    def test_title_alone_never_authorizes(self):
        with self.assertRaises(driver.FocusUnavailable):
            driver._window_details("Window{abc12 u0 Autofill UI}", "abc12")

    def test_non_system_uid_rejected(self):
        self.rejected(popup={**self.popup, "owner": 10432})

    def test_non_android_package_rejected(self):
        self.rejected(popup={**self.popup, "package": PACKAGE})

    def test_fullscreen_or_overlay_type_rejected(self):
        for kind in ("SYSTEM_DIALOG", "2008", "APPLICATION_OVERLAY", "2038", "1000"):
            with self.subTest(kind=kind):
                self.rejected(popup={**self.popup, "type": kind})

    def test_nondefault_or_invisible_popup_rejected(self):
        for field, value in (("display", 1), ("visible", False), ("onscreen", False)):
            with self.subTest(field=field):
                self.rejected(popup={**self.popup, field: value})

    def test_parent_component_or_attachment_rejected(self):
        for parent in (None, ("def34", "1", COMPONENT, "true"),
                       ("def34", "0", driver.DECOY + "/" + driver.ACTIVITY, "true"),
                       ("def34", "0", COMPONENT, "false")):
            with self.subTest(parent=parent):
                self.rejected(popup={**self.popup, "parent": parent})

    def test_popup_activity_token_must_match_focused_app(self):
        for field in ("token", "activity"):
            with self.subTest(field=field):
                self.rejected(popup={**self.popup, field: ACTIVITY.replace("ca123", "ca124")})

    def test_parent_activity_token_must_match_popup(self):
        for field in ("token", "activity"):
            with self.subTest(field=field):
                self.rejected(parent={**self.parent, field: ACTIVITY.replace("ca123", "ca124")})

    def test_parent_window_identity_and_owner(self):
        for field, value in (("window", "def35"), ("package", driver.DECOY),
                             ("title", "unrelated"), ("owner", 1000), ("type", "APPLICATION_OVERLAY")):
            with self.subTest(field=field):
                self.rejected(parent={**self.parent, field: value})

    def test_parent_task_display_and_visibility(self):
        for field, value in (("task", 43), ("display", 1), ("visible", False), ("onscreen", False)):
            with self.subTest(field=field):
                self.rejected(parent={**self.parent, field: value})

    def test_nondefault_top_display(self):
        with self.assertRaises(driver.FocusUnavailable):
            driver._focus_snapshot(focus_text(top=1))

    def test_multiple_focus_or_display_sections(self):
        samples = [focus_text().replace("    mFocusedApp=", "    mCurrentFocus=null\n    mFocusedApp="),
                   focus_text().replace("    mFocusedApp=", "  Display: mDisplayId=0\n    mFocusedApp=")]
        for raw in samples:
            with self.subTest(raw=raw), self.assertRaises(driver.FocusUnavailable):
                driver._focus_snapshot(raw)

    def test_wrong_focused_activity(self):
        self.rejected(focus={**self.focus, "activity": ACTIVITY.replace(PACKAGE, driver.DECOY)})

    def test_not_resumed_or_wrong_resumed_record(self):
        self.rejected(activities=ACTIVITIES.replace("state=RESUMED", "state=PAUSED"))
        self.rejected(activities=ACTIVITIES.replace("def34", "def35"))

    def test_duplicate_and_client_nested_resumed_labels(self):
        self.rejected(activities=ACTIVITIES + "state=RESUMED delayedResume=false finishing=false\n")
        self.rejected(activities=ACTIVITIES + f"      ResumedActivity: {ACTIVITY}\n")

    def test_two_space_client_forgery_reproducing_qa10_defect_refused(self):
        old = ("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
               "Display #0 (activities from top to bottom):\n"
               "      CLIENT: arbitrary client output\n"
               f"  ResumedActivity: {ACTIVITY}\n")
        self.rejected(activities=old)
        self.rejected(activities=old.replace("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)",
                                           "ACTIVITY MANAGER TOP-RESUMED (dumpsys activity top-resumed)"))

    def test_top_resumed_header_and_record_uniqueness(self):
        for raw in (ACTIVITIES.replace("TOP-RESUMED", "ACTIVITIES"),
                    ACTIVITIES + ACTIVITIES,
                    ACTIVITIES + f"packageName={PACKAGE} processName={PACKAGE}\n"):
            with self.subTest(raw=raw): self.rejected(activities=raw)

    def test_wrong_package_or_process_is_not_ignored(self):
        for raw in (ACTIVITIES.replace("packageName=" + PACKAGE, "packageName=" + driver.DECOY),
                    ACTIVITIES.replace("processName=" + PACKAGE, "processName=" + PACKAGE + ":other")):
            with self.subTest(raw=raw): self.rejected(activities=raw)

    def test_wrong_user_or_component_is_not_ignored(self):
        for raw in (ACTIVITIES.replace("userId=0", "userId=1"),
                    ACTIVITIES.replace("mActivityComponent=" + COMPONENT, "mActivityComponent=" + driver.DECOY + "/" + driver.ACTIVITY)):
            with self.subTest(raw=raw): self.rejected(activities=raw)

    def test_delayed_or_finishing_activity_refused(self):
        for old, new in (("delayedResume=false", "delayedResume=true"), ("finishing=false", "finishing=true")):
            with self.subTest(field=old): self.rejected(activities=ACTIVITIES.replace(old, new))

    def test_app_text_cannot_shadow_real_wrong_server_fields(self):
        fields = [("packageName=" + PACKAGE + " processName=" + PACKAGE, "packageName=" + driver.DECOY + " processName=" + driver.DECOY),
                  ("mActivityComponent=" + COMPONENT, "mActivityComponent=" + driver.DECOY + "/" + driver.ACTIVITY),
                  ("state=RESUMED delayedResume=false finishing=false", "state=PAUSED delayedResume=false finishing=false"),
                  ("windows=[Window{def34 u0 " + COMPONENT + "}]", "windows=[Window{def35 u0 " + COMPONENT + "}]")]
        for good, wrong in fields:
            forged = ACTIVITIES.replace(good, wrong) + 'taskDescription: label="injected\n  ' + good + '\n"\n'
            with self.subTest(field=good): self.rejected(activities=forged)

    def test_duplicate_user_token_refused(self):
        self.rejected(activities=ACTIVITIES + "taskDescription: label=\"userId=0\"\n")

    def test_unknown_or_duplicate_windows_refused(self):
        for value in ("[]", "[unknown]", f"[Window{{def34 u1 {COMPONENT}}}]",
                      f"[Window{{def34 u0 {COMPONENT}}}, Window{{def34 u0 {COMPONENT}}}]"):
            with self.subTest(value=value):
                self.rejected(activities=ACTIVITIES.replace(f"[Window{{def34 u0 {COMPONENT}}}]", value))

    def test_missing_state_cannot_be_replaced_by_legacy_label(self):
        self.rejected(activities=ACTIVITIES.replace("state=RESUMED delayedResume=false finishing=false", f"  ResumedActivity: {ACTIVITY}"))

    def test_focus_change_after_ams_rejected(self):
        self.rejected(final={**self.focus, "window": "abc13"})

    def test_scoped_window_must_be_unique_and_exact(self):
        for raw, identity in ((POPUP, "abc13"), (POPUP + POPUP, "abc12")):
            with self.subTest(identity=identity), self.assertRaises(driver.FocusUnavailable):
                driver._window_details(raw, identity)

    def test_unknown_or_duplicate_owner_metadata_rejected(self):
        raws = [POPUP.replace("mOwnerUid=1000", "unrecognizedOwner=1000"),
                POPUP.replace("    mAttrs=", "    mOwnerUid=1000 showForAllUsers=false package=android appop=NONE\n    mAttrs=")]
        for raw in raws:
            with self.subTest(raw=raw), self.assertRaises(driver.FocusUnavailable):
                driver._window_details(raw, "abc12")

    def test_android16_qpr2_layer_and_token_same_line(self):
        popup = driver._window_details(POPUP.replace("    mToken=", "    mBaseLayer=21000 mSubLayer=3    mToken="), "abc12")
        parent = driver._window_details(PARENT.replace("    mToken=", "    mBaseLayer=21000 mSubLayer=0    mToken="), "def34")
        self.assertTrue(self.evaluate(popup=popup, parent=parent)["available"])

    def test_layer_token_duplicate_does_not_hide_wrong_token(self):
        raw = POPUP.replace("    mToken=", "    mBaseLayer=21000 mSubLayer=3    mToken=")
        raw = raw.replace("    mActivityRecord=", "    mToken=ActivityRecord{dead0 u0 unrelated/.Activity t9}\n    mActivityRecord=")
        with self.assertRaises(driver.FocusUnavailable): driver._window_details(raw, "abc12")

    def test_unknown_layer_token_prefix_is_refused(self):
        for prefix in ("unknown=21000 ", "mBaseLayer=21000 ", "mBaseLayer=21000 mSubLayer=unexpected "):
            with self.subTest(prefix=prefix), self.assertRaises(driver.FocusUnavailable):
                driver._window_details(POPUP.replace("    mToken=", "    " + prefix + "mToken="), "abc12")

    def test_public_metadata_discards_ids_uid_title_and_client_data(self):
        encoded = json.dumps(self.evaluate())
        for private in ("abc12", "def34", "ca123", "10432", "1000", "Autofill UI", "synthetic_private_intent"):
            self.assertNotIn(private, encoded)

    def device(self, popup=POPUP):
        device = driver.Device.__new__(driver.Device)
        device.expected_fixture = PACKAGE
        calls = []
        def shell(*args):
            calls.append(args)
            if args == ("dumpsys", "window"): return focus_text()
            if args == ("dumpsys", "window", "-a", "abc12"): return popup
            if args == ("dumpsys", "window", "-a", "def34"): return PARENT
            if args == ("dumpsys", "activity", "top-resumed"): return ACTIVITIES
            if args[:2] == ("input", "tap"): return ""
            raise AssertionError("unexpected synthetic shell command")
        device.shell = shell
        return device, calls

    def test_device_queries_exact_window_ids_then_server_only_top_record(self):
        device, calls = self.device()
        self.assertEqual(device.foreground(), driver.AUTOFILL_POPUP)
        self.assertEqual(calls, [("dumpsys", "window"), ("dumpsys", "window", "-a", "abc12"),
                                 ("dumpsys", "window", "-a", "def34"),
                                 ("dumpsys", "activity", "top-resumed"),
                                 ("dumpsys", "window")])

    def test_bad_owner_stops_before_parent_or_activity_reads(self):
        device, calls = self.device(POPUP.replace("mOwnerUid=1000", "mOwnerUid=10432"))
        self.assertIsNone(device.foreground())
        self.assertEqual(len(calls), 2)
        self.assertEqual(device.last_focus_metadata["reason"], "popup_not_system_owned")

    def test_zero_multiple_and_null_focused_app_have_closed_diagnostics(self):
        for raw, count, null in ((focus_text().replace("    mFocusedApp=" + ACTIVITY + "\n", ""), "zero", False),
                                  (focus_text().replace("    mFocusedApp=", "    mFocusedApp=null\n    mFocusedApp="), "multiple", False),
                                  (focus_text().replace(ACTIVITY, "null"), "one", True)):
            with self.subTest(count=count, null=null):
                device, calls = self.device()
                device.shell = lambda *args: raw
                self.assertIsNone(device.foreground())
                metadata = device.last_focus_metadata
                self.assertEqual(metadata["phase"], "focused_app_identity")
                self.assertEqual(metadata["shape_diagnostics"]["focused_app_field_count"], count)
                self.assertEqual(metadata["shape_diagnostics"]["focused_app"]["is_null"], null)

    def test_decimal_complete_chain_and_safe_public_shape(self):
        device, calls = self.device()
        original = device.shell
        device.shell = lambda *args: original(*args).replace("ca123", "1234567890")
        self.assertEqual(device.foreground(), driver.AUTOFILL_POPUP)
        shapes = device.last_focus_metadata["shape_diagnostics"]
        self.assertEqual(shapes["focused_app_field_count"], "one")
        self.assertEqual(shapes["focused_app"]["identity_format"], "canonical_decimal_9_or_10")
        self.assertTrue(shapes["focused_app_matches_parent_token"])
        self.assertNotIn("1234567890", json.dumps(device.last_focus_metadata))

    def test_unrecognized_identity_reports_phase_before_other_queries(self):
        device, calls = self.device()
        original = device.shell
        device.shell = lambda *args: original(*args).replace("ca123", "unknown_private_value")
        self.assertIsNone(device.foreground())
        self.assertEqual(calls, [("dumpsys", "window")])
        self.assertEqual(device.last_focus_metadata["phase"], "focused_app_identity")
        self.assertNotIn("unknown_private_value", json.dumps(device.last_focus_metadata))

    def test_wrong_parent_stops_before_top_activity_query(self):
        device, calls = self.device()
        original = device.shell
        def wrong_parent(*args):
            value = original(*args)
            if args == ("dumpsys", "window", "-a", "def34"):
                return value.replace("mOwnerUid=10432", "mOwnerUid=1000")
            return value
        device.shell = wrong_parent
        self.assertIsNone(device.foreground())
        self.assertFalse(any(call[:2] == ("dumpsys", "activity") for call in calls))

    def test_ordinary_activity_branch_stays_direct(self):
        device, calls = self.device()
        device.shell = lambda *args: focus_text(title=COMPONENT)
        self.assertEqual(device.foreground(), (PACKAGE, driver.ACTIVITY))

    def test_authorized_popup_causes_exactly_one_normal_touch(self):
        device, calls = self.device()
        node = ET.Element("node", {"bounds": "[72,425][694,585]", "enabled": "true", "clickable": "true", "package": driver.PROVIDER, "class": "android.widget.TextView"})
        device.wait = lambda *args, **kwargs: node
        device.node_geometry = lambda value: []
        device.pending_intents = lambda: {"available": True, "own_record_count": 1}
        device.current_case = "locked_fill_refused"
        device.tap_diagnostics = []
        device._ui_started_ns = device._ui_finished_ns = time.monotonic_ns()
        device.tap(text="Unlock HeptaBao locally")
        self.assertEqual([c for c in calls if c[:2] == ("input", "tap")], [("input", "tap", "383", "505")])


if __name__ == "__main__":
    unittest.main(argv=[__file__, *remaining])
