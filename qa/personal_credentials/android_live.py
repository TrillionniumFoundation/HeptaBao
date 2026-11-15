#!/usr/bin/env python3
"""Actual Android system Autofill qualification for one previously authorized device.

Only synthetic, newly installed packages are touched. No raw serial, password,
UI hierarchy, or original password-provider component is emitted in the report.
The private restore journal makes an interrupted run reviewable and recoverable.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

DEVICE_SHA256 = "41ad305f8562a6c47710afe71fabf30cb8692a71d3de1a47ca9949b669bcc6c1"
PROVIDER = "org.heptabao.personal.preview"
GOOD = "org.heptabao.synthetic.fixture"
DECOY = "org.heptabao.synthetic.decoy"
SERVICE = PROVIDER + "/org.heptabao.preview.VaultAutofillService"
ACTIVITY = "org.heptabao.fixture.FixtureActivity"
PACKAGES = {PROVIDER, GOOD, DECOY}
EXPECTED_CASES = [
    "rust_ciphertext_import", "locked_fill_refused", "wrong_master_refused",
    "actual_system_fill_and_login", "system_cached_plaintext_not_reusable",
    "explicit_lock_refused", "expired_authorization_refused", "cancelled_authorization_refused",
    "background_authorization_refused", "independent_process_restart_locked_and_recovered",
    "wrong_package_same_certificate_refused", "same_package_wrong_certificate_refused",
]

DIAGNOSTIC_REJECTIONS = {
    "request_expired", "wrong_result_recipient", "request_changed", "wrong_package", "wrong_certificate",
    "missing_structure", "wrong_activity", "unsupported_windows", "structure_too_large",
    "webview_unsupported", "wrong_fields",
}
DIAGNOSTIC_CODES = DIAGNOSTIC_REJECTIONS | {
    "browser_unsupported", "import_in_progress", "vault_not_imported", "invalid_request",
    "authentication_required", "background_locked", "expired", "locked", "importing",
    "imported_locked", "import_failed", "memory_locked", "unlock_failed", "authentication_failed",
    "unlocked_pending_confirmation", "handoff_pending", "filled_once", "handoff_rejected", "other",
}


def provider_event_projection(raw):
    """Project original stdout bytes into closed codes and counts, never raw lines."""
    allowed = {"ui_hidden_notification", "memory_pressure_locked", "auth_context_bound"}
    allowed.update("auth_rejected_" + code for code in DIAGNOSTIC_REJECTIONS)
    allowed.update({"request_expiry_timer", "request_expiry_access", "unlock_expiry_timer_login", "unlock_expiry_timer_handoff", "unlock_expiry_access", "handoff_expiry_access", "unlock_callback_stale"})
    allowed.update("service_target_" + category for category in ("expected", "self", "other"))
    code_union = "(?:" + "|".join(sorted(DIAGNOSTIC_CODES)) + ")"
    patterns = (
        r"trim_(?:running_moderate|running_low|running_critical|ui_hidden|background|moderate|complete|other)_before_p[01]l[01]h[01]_after_p[01]l0h0_epoch_advanced",
        r"reject_(?:unlock_precheck|unlock_post_kdf|service_request)_" + code_union,
        r"lock_all_" + code_union + r"_before_p[01]l[01]h[01]_after_p0l0h0",
        r"cancel_(?:other|auth_pause|service_listener|service_callback)_matched_[01]_before_p[01]l[01]h[01]_after_p[01]l[01]h[01]",
        r"request_created_before_p[01]l[01]h[01]_after_p1l0h0",
        r"explicit_login_lock_before_p[01]l[01]h[01]_after_p1l0h0",
    )
    lines = raw.splitlines()
    nonempty = [line.decode("utf-8", "replace").strip() for line in lines if line.strip()]
    events = [line for line in nonempty if line in allowed or any(re.fullmatch(pattern, line) for pattern in patterns)]
    return {"raw_byte_count": len(raw), "raw_line_count": len(lines), "nonempty_line_count": len(nonempty),
            "recognized_line_count": len(events), "unrecognized_line_count": len(nonempty) - len(events),
            "recognized_lines_omitted_by_limit": max(0, len(events) - 64), "codes": events[-64:]}


def pending_intent_metadata(raw, identifiers):
    """Only our package section survives; raw Intent data and global UID tails do not."""
    if len(raw) > 1024 * 1024 or not raw.startswith("ACTIVITY MANAGER PENDING INTENTS (dumpsys activity intents)"):
        return {"available": False, "reason": "unrecognized_format"}
    expected_count, section = None, []
    recognized_empty, unknown_before_section, reading_weak_refs = False, False, False
    for line in raw.splitlines()[1:]:
        stripped = line.strip()
        if stripped.startswith("* "):
            live_section = re.fullmatch(r"\* ([A-Za-z0-9_.$]+): ([0-9]+) items", stripped)
            if live_section and live_section.group(1) != PROVIDER:
                return {"available": False, "reason": "package_filter_not_observed"}
            if expected_count is not None: break
            match = re.fullmatch(r"\* " + re.escape(PROVIDER) + r": ([0-9]+) items", stripped)
            if match:
                expected_count = int(match.group(1))
            elif stripped == "* WEAK REFS:":
                recognized_empty = True; reading_weak_refs = True
            elif re.fullmatch(r"\* UID: [0-9]+ total: [0-9]+", stripped):
                recognized_empty = True; reading_weak_refs = False
            else:
                unknown_before_section = True; reading_weak_refs = False
            continue
        if expected_count is not None:
            section.append(stripped)
        elif stripped == "(nothing)":
            recognized_empty = True
        elif stripped and not (reading_weak_refs and re.fullmatch(r"#[0-9]+: (?:null|java\.lang\.ref\.WeakReference@[0-9a-f]+)", stripped)):
            unknown_before_section = True
    if unknown_before_section:
        return {"available": False, "reason": "unrecognized_body_format"}
    if expected_count is None:
        return {"available": True, "own_record_count": 0, "records": []} if recognized_empty else {"available": False, "reason": "unrecognized_empty_format"}
    if expected_count > 256:
        return {"available": False, "reason": "own_record_limit"}
    records = []
    current = None
    cancellation_reasons = {"NULL", "USER_STOPPED", "OWNER_UNINSTALLED", "OWNER_FORCE_STOPPED", "OWNER_CANCELED", "HOSTING_ACTIVITY_DESTROYED", "SUPERSEDED", "ONE_SHOT_SENT", "UNKNOWN"}
    for line in section:
        start = re.fullmatch(r"#[0-9]+: PendingIntentRecord\{([0-9a-f]+) " + re.escape(PROVIDER) + r" startActivity\}", line)
        if start:
            key = start.group(1)  # Local registry identity only; never serialized.
            if key not in identifiers: identifiers[key] = len(identifiers) + 1
            current = {"observation_record_id": identifiers[key], "auth_component_present": False,
                       "one_shot": None, "mutable": None, "immutable": None,
                       "sent": None, "cancelled": None, "cancel_reason": None}
            records.append(current)
        elif current is not None:
            flags = re.fullmatch(r"uid=[0-9]+ packageName=" + re.escape(PROVIDER) + r" featureId=null type=startActivity flags=0x([0-9a-f]+)", line)
            if flags:
                bits = int(flags.group(1), 16)
                current.update(one_shot=bool(bits & 0x40000000), mutable=bool(bits & 0x02000000), immutable=bool(bits & 0x04000000))
            if line.startswith("requestIntent="):
                current["auth_component_present"] = bool(re.search(r"\bcmp=" + re.escape(PROVIDER + "/org.heptabao.preview.AuthActivity") + r"(?:\s|\})", line))
            state = re.fullmatch(r"sent=(true|false) canceled=(true|false)(?: cancelReason=([A-Z_]+))?", line)
            if state:
                current["sent"] = state.group(1) == "true"
                current["cancelled"] = state.group(2) == "true"
                current["cancel_reason"] = state.group(3) if state.group(3) in cancellation_reasons else None
    if len(records) != expected_count or any(row["one_shot"] is None for row in records):
        return {"available": False, "reason": "unrecognized_own_record_format"}
    return {"available": True, "own_record_count": expected_count, "records": records}


class Failed(Exception):
    pass


class FocusUnavailable(Exception):
    """Closed diagnostic code only; never attach raw WindowManager output."""


AUTOFILL_POPUP = ("android", "AutofillUI")


def _one_match(pattern, raw, reason):
    matches = list(re.finditer(pattern, raw, re.MULTILINE))
    if len(matches) != 1:
        raise FocusUnavailable(reason)
    return matches[0]


def _activity_id_supported(value):
    if re.fullmatch(r"[0-9a-f]{1,8}", value):
        return True
    # Android 16 QPR2 appends System.identityHashCode(int) directly. Keep the
    # original token for equality; never merge decimal and hexadecimal spellings.
    return bool(re.fullmatch(r"-?(?:0|[1-9][0-9]{0,9})", value)) and str(int(value)) == value and -2147483648 <= int(value) <= 2147483647


def _activity_identity(value, package):
    if package not in {GOOD, DECOY}:
        raise FocusUnavailable("fixture_not_selected")
    match = re.fullmatch(r"ActivityRecord\{([^ {}\r\n]+) u0 " + re.escape(package + "/" + ACTIVITY) + r" t([0-9]+)\}", value)
    if not match or not _activity_id_supported(match.group(1)):
        raise FocusUnavailable("activity_identity_unavailable")
    return match.group(1), int(match.group(2))


def _activity_shape(value, package):
    """Closed metadata only: never retain a record ID, task number or component."""
    result = {"present": value is not None, "is_null": value == "null", "shape": "unrecognized",
              "expected_component": False, "user_zero": False, "complete_record": False,
              "finishing_marker": False, "exiting_marker": False, "identity_format": "unrecognized"}
    if value is None:
        result["shape"] = "absent"; return result
    if value == "null":
        result["shape"] = "null"; return result
    if not isinstance(value, str) or len(value) > 2048:
        return result
    prefix = re.match(r"^ActivityRecord\{([^ {}\r\n]+) u(-?[0-9]+) ([^ {}\r\n]+)", value)
    if prefix is None:
        return result
    result["expected_component"] = package in {GOOD, DECOY} and prefix.group(3) == package + "/" + ACTIVITY
    result["user_zero"] = prefix.group(2) == "0"
    token = prefix.group(1)
    if re.fullmatch(r"[0-9]{1,8}", token): result["identity_format"] = "digits_1_to_8"
    elif re.fullmatch(r"[0-9a-f]{1,8}", token): result["identity_format"] = "legacy_hex_1_to_8"
    elif re.fullmatch(r"[1-9][0-9]{8,9}", token) and _activity_id_supported(token): result["identity_format"] = "canonical_decimal_9_or_10"
    elif token.startswith("-") and _activity_id_supported(token): result["identity_format"] = "canonical_signed_decimal"
    result["finishing_marker"] = bool(re.search(r" f\}", value))
    result["exiting_marker"] = " isExiting" in value
    complete = re.fullmatch(r"ActivityRecord\{[^ {}\r\n]+ u-?[0-9]+ [^ {}\r\n]+ t-?[0-9]+\}", value)
    result["complete_record"] = complete is not None
    if result["finishing_marker"] or result["exiting_marker"]: result["shape"] = "finishing_or_exiting"
    elif complete: result["shape"] = "complete_record"
    elif re.fullmatch(r"ActivityRecord\{[^ {}\r\n]+ u-?[0-9]+ [^ {}\r\n]+", value): result["shape"] = "incomplete_record"
    return result


def _activity_relation(first, second, package):
    if not isinstance(first, str) or not isinstance(second, str):
        return None
    try:
        return _activity_identity(first, package) == _activity_identity(second, package)
    except FocusUnavailable:
        return None


def _focus_snapshot(raw):
    if len(raw) > 2 * 1024 * 1024:
        raise FocusUnavailable("window_metadata_limit")
    top = _one_match(r"^\s*mTopFocusedDisplayId=([0-9]+)\s*$", raw, "top_display_unavailable")
    if top.group(1) != "0":
        raise FocusUnavailable("nondefault_top_display")
    sections, current, lines = 0, None, []
    for line in raw.splitlines():
        marker = re.match(r"^\s*Display: mDisplayId=([0-9]+)\b", line)
        if marker:
            current = int(marker.group(1))
            if current == 0:
                sections += 1
        elif line.lstrip().startswith("WINDOW MANAGER "):
            current = None
        if current == 0:
            lines.append(line)
    if sections != 1:
        raise FocusUnavailable("default_display_ambiguous")
    section = "\n".join(lines)
    focus = _one_match(r"^\s*mCurrentFocus=(.+)\s*$", section, "focused_window_ambiguous")
    window = re.fullmatch(r"Window\{([0-9a-f]{1,8}) u0 ([^{}\r\n]+)\}", focus.group(1).strip())
    if not window or int(window.group(1), 16) > 0x7fffffff:
        raise FocusUnavailable("focused_window_unrecognized")
    apps = re.findall(r"^\s*mFocusedApp=(.+)\s*$", section, re.MULTILINE)
    return {"window": window.group(1), "title": window.group(2),
            "activity": apps[0].strip() if len(apps) == 1 else None,
            "focused_app_field_count": "one" if len(apps) == 1 else "zero" if not apps else "multiple"}


def _window_details(raw, expected_id):
    """Parse one identity-filtered WMS window, discarding every global tail."""
    if len(raw) > 512 * 1024 or not raw.startswith("WINDOW MANAGER WINDOWS (dumpsys window windows)"):
        raise FocusUnavailable("window_detail_format")
    headers = list(re.finditer(r"^([ \t]*)Window #[0-9]+ Window\{([0-9a-f]{1,8}) u([0-9]+) ([^{}\r\n]+)\}:[ \t]*$", raw, re.MULTILINE))
    if len(headers) != 1 or headers[0].group(2) != expected_id or headers[0].group(3) != "0":
        raise FocusUnavailable("window_detail_identity")
    header = headers[0]
    indent = len(header.group(1).split("\n")[-1])
    body = []
    for line in raw[header.end():].splitlines():
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        body.append(line)
    body = "\n".join(body)
    display = _one_match(r"^\s*mDisplayId=([0-9]+)(?: taskId=([0-9]+))?\s+mSession=.+$", body, "window_display_unavailable")
    owner = _one_match(r"^\s*mOwnerUid=([0-9]+) showForAllUsers=(?:true|false) package=([A-Za-z0-9_.$]+) appop=\S+\s*$", body, "window_owner_unavailable")
    attrs = _one_match(r"^\s*mAttrs=(.+)$", body, "window_attributes_unavailable")
    window_type = _one_match(r"\bty=([A-Z_0-9]+)\b", attrs.group(1), "window_type_unavailable").group(1)
    if len(re.findall(r"\bmToken=", body)) != 1:
        raise FocusUnavailable("window_token_ambiguous")
    # Android 16 QPR2 prints the base/sub-layer prefix without a newline before
    # mToken. Accept that exact form and the standalone form, never arbitrary prefixes.
    token = _one_match(r"^[ \t]*(?:mBaseLayer=-?[0-9]+ mSubLayer=-?[0-9]+[ \t]+)?mToken=([^\r\n]+)$", body, "window_token_unavailable").group(1).strip()
    activity = _one_match(r"^\s*mActivityRecord=(.+)\s*$", body, "window_activity_unavailable").group(1).strip()
    visible = _one_match(r"^\s*isVisible=(true|false)\s*$", body, "window_visibility_unavailable").group(1) == "true"
    onscreen = _one_match(r"^\s*isOnScreen=(true|false)\s*$", body, "window_onscreen_unavailable").group(1) == "true"
    parents = re.findall(r"^\s*mParentWindow=Window\{([0-9a-f]{1,8}) u([0-9]+) ([^{}\r\n]+)\} mLayoutAttached=(true|false)\s*$", body, re.MULTILINE)
    if len(parents) > 1:
        raise FocusUnavailable("window_parent_ambiguous")
    return {"window": expected_id, "title": header.group(4), "display": int(display.group(1)),
            "task": int(display.group(2)) if display.group(2) is not None else None,
            "owner": int(owner.group(1)), "package": owner.group(2), "type": window_type,
            "token": token, "activity": activity, "visible": visible, "onscreen": onscreen,
            "parent": parents[0] if parents else None}


def _popup_parent(focus, popup, package):
    identity = _activity_identity(focus["activity"], package) if focus["activity"] else None
    if identity is None or focus["title"] != "Autofill UI" or popup["title"] != "Autofill UI" or popup["window"] != focus["window"]:
        raise FocusUnavailable("popup_focus_identity")
    if popup["owner"] != 1000 or popup["package"] != "android":
        raise FocusUnavailable("popup_not_system_owned")
    if popup["type"] not in {"APPLICATION_ABOVE_SUB_PANEL", "1005"}:
        raise FocusUnavailable("popup_type_unsupported")
    if popup["display"] != 0 or not popup["visible"] or not popup["onscreen"]:
        raise FocusUnavailable("popup_not_visible_on_default_display")
    parent = popup["parent"]
    if parent is None or parent[1:] != ("0", package + "/" + ACTIVITY, "true") or int(parent[0], 16) > 0x7fffffff:
        raise FocusUnavailable("popup_parent_not_expected_fixture")
    if _activity_identity(popup["token"], package) != identity or _activity_identity(popup["activity"], package) != identity or popup["task"] != identity[1]:
        raise FocusUnavailable("popup_activity_token_mismatch")
    return parent[0], identity


def _bound_parent(focus, popup, parent, package):
    parent_id, identity = _popup_parent(focus, popup, package)
    if parent["window"] != parent_id or parent["title"] != package + "/" + ACTIVITY or parent["package"] != package:
        raise FocusUnavailable("parent_window_identity_mismatch")
    if parent["display"] != 0 or not parent["visible"] or not parent["onscreen"] or parent["task"] != identity[1]:
        raise FocusUnavailable("parent_window_not_active")
    if parent["type"] not in {"BASE_APPLICATION", "APPLICATION", "1", "2"} or parent["owner"] < 10000:
        raise FocusUnavailable("parent_window_type_or_owner")
    if _activity_identity(parent["token"], package) != identity or _activity_identity(parent["activity"], package) != identity:
        raise FocusUnavailable("parent_activity_token_mismatch")
    return parent_id


def _top_resumed_bound(raw, package, parent_id):
    """Server-only top record; never use the -p/-c client-dump command."""
    header = "ACTIVITY MANAGER TOP-RESUMED (dumpsys activity top-resumed)"
    if len(raw) > 1024 * 1024 or not raw.startswith(header + "\n"):
        raise FocusUnavailable("top_resumed_format_unavailable")
    if _one_match(r"^[ \t]*ACTIVITY MANAGER[^\r\n]*$", raw, "top_resumed_header_ambiguous").group(0) != header:
        raise FocusUnavailable("top_resumed_format_unavailable")
    if re.search(r"^[ \t]*(?:CLIENT:|ResumedActivity:)", raw, re.MULTILINE):
        raise FocusUnavailable("top_resumed_client_format_refused")
    # Count generic field prefixes before checking their values. App-supplied intent
    # or task-label text containing forged new lines cannot hide a real wrong value.
    named = _one_match(r"^[ \t]*packageName=([^\r\n]*)$", raw, "top_resumed_package_ambiguous").group(1)
    names = re.fullmatch(r"([A-Za-z0-9_.$]+) processName=([A-Za-z0-9_.$:]+)", named)
    if names is None or names.groups() != (package, package):
        raise FocusUnavailable("top_resumed_package_mismatch")
    launched = _one_match(r"^[ \t]*launchedFromUid=([^\r\n]*)$", raw, "top_resumed_user_ambiguous").group(1)
    user = re.fullmatch(r"[0-9]+ launchedFromPackage=[A-Za-z0-9_.$]+ launchedFromFeature=[A-Za-z0-9_.$:-]+ userId=([0-9]+)", launched)
    if user is None or user.group(1) != "0" or len(re.findall(r"\buserId=", raw)) != 1:
        raise FocusUnavailable("top_resumed_user_mismatch")
    component = _one_match(r"^[ \t]*mActivityComponent=([^\r\n]*)$", raw, "top_resumed_component_ambiguous").group(1)
    if component != package + "/" + ACTIVITY:
        raise FocusUnavailable("top_resumed_component_mismatch")
    state = _one_match(r"^[ \t]*state=([^\r\n]*)$", raw, "top_resumed_state_ambiguous").group(1)
    if state != "RESUMED delayedResume=false finishing=false":
        raise FocusUnavailable("top_resumed_state_refused")
    windows = _one_match(r"^[ \t]*windows=([^\r\n]*)$", raw, "top_resumed_windows_ambiguous").group(1)
    window = r"Window\{([0-9a-f]{1,8}) u([0-9]+) ([^{}\r\n]+)\}"
    if not re.fullmatch(r"\[" + window + r"(?:, " + window + r")*\]", windows):
        raise FocusUnavailable("top_resumed_windows_format")
    children = re.findall(window, windows)
    if not 1 <= len(children) <= 16 or len({row[0] for row in children}) != len(children) or children.count((parent_id, "0", package + "/" + ACTIVITY)) != 1:
        raise FocusUnavailable("top_resumed_parent_window_mismatch")


def autofill_popup_metadata(focus, popup, parent, activities, final_focus, package):
    """Upstream WMS contract, still subject to real OEM qualification; no title-only fallback."""
    parent_id = _bound_parent(focus, popup, parent, package)
    _top_resumed_bound(activities, package, parent_id)
    if final_focus != focus:
        raise FocusUnavailable("popup_focus_changed")
    return {"available": True, "classification": "bound_system_autofill_popup", "display": 0,
            "system_owner": True, "system_package": True, "window_type": 1005,
            "expected_fixture_parent": True, "activity_token_matches": True,
            "fixture_resumed": True, "focus_rechecked": True,
            "resumed_evidence": "server_only_top_resumed_record", "package_filter_used": False,
            "top_resumed_parent_window_matches": True,
            "oem_contract_requires_device_evidence": True}


def _fixture_session(window, package):
    # This WMS window/record/task/owner identity stays in memory. It is not the
    # Android Autofill framework's internal session ID, which is never queried.
    return window["window"], _activity_identity(window["activity"], package), window["owner"]


def _return_identity_components(focus, window, package):
    """Closed observations from already-read metadata; no extra system query."""
    def title_kind(value):
        if value == package + "/" + ACTIVITY: return "expected_fixture"
        if value == "Autofill UI": return "autofill_popup_title"
        if value == PROVIDER + "/org.heptabao.preview.AuthActivity": return "own_auth_activity"
        return "other"
    result = {"focused_app_field_count": focus["focused_app_field_count"],
              "focused_app_shape": _activity_shape(focus["activity"], package),
              "focus_title_category": title_kind(focus["title"]),
              "window_details_parsed": window is not None}
    if window is not None:
        result.update(window_title_category=title_kind(window["title"]),
                      window_package_category="expected_fixture" if window["package"] == package else
                          "system_android" if window["package"] == "android" else
                          "own_provider" if window["package"] == PROVIDER else "other",
                      focus_and_window_id_match=focus["window"] == window["window"],
                      focus_and_window_title_match=focus["title"] == window["title"])
    return result


def fixture_return_metadata(focus, window, activities, final_focus, package, expected_session=None):
    """Bind the resumed fixture window, including the original session on return."""
    identity = _activity_identity(focus["activity"], package) if focus["activity"] else None
    if (identity is None or focus["focused_app_field_count"] != "one"
            or focus["title"] != package + "/" + ACTIVITY
            or window["window"] != focus["window"] or window["title"] != focus["title"]
            or window["package"] != package):
        raise FocusUnavailable("fixture_return_window_identity")
    if (window["display"] != 0 or not window["visible"] or not window["onscreen"]
            or window["task"] != identity[1] or window["parent"] is not None
            or window["type"] not in {"BASE_APPLICATION", "APPLICATION", "1", "2"}
            or window["owner"] < 10000):
        raise FocusUnavailable("fixture_return_window_not_active")
    if (_activity_identity(window["token"], package) != identity
            or _activity_identity(window["activity"], package) != identity):
        raise FocusUnavailable("fixture_return_activity_token")
    _top_resumed_bound(activities, package, window["window"])
    if final_focus != focus:
        raise FocusUnavailable("fixture_return_focus_changed")
    if expected_session is not None and _fixture_session(window, package) != expected_session:
        raise FocusUnavailable("fixture_return_session_changed")
    return {"available": True, "classification": "bound_fixture_activity", "display": 0,
            "fixture_resumed": True, "focus_rechecked": True,
            "resumed_evidence": "server_only_top_resumed_record",
            "original_session_checked": expected_session is not None}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".new." + str(os.getpid()) + "." + str(time.monotonic_ns()))
    with temporary.open("x", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n"); output.flush(); os.fsync(output.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)


def validate_journal(journal):
    required = {"schema", "device_serial_sha256", "service_written", "previous_autofill_service", "setting_write_attempted", "initial_absent", "owned_packages", "created_unix_ns"}
    optional = {"restoration", "package_cleanup"}
    if type(journal) is not dict or not required <= set(journal) <= required | optional:
        raise Failed("invalid_restore_journal")
    previous = journal["previous_autofill_service"]
    if journal["schema"] != 2 or type(previous) is not str or (previous != "null" and not re.fullmatch(r"[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+", previous)):
        raise Failed("invalid_restore_journal")
    if journal["device_serial_sha256"] != DEVICE_SHA256 or journal["service_written"] != SERVICE or type(journal["setting_write_attempted"]) is not bool:
        raise Failed("invalid_restore_journal")
    initial, attempts = journal["initial_absent"], journal["owned_packages"]
    if type(initial) is not dict or set(initial) - PACKAGES or any(value is not True for value in initial.values()):
        raise Failed("invalid_restore_journal")
    if type(attempts) is not dict or set(attempts) - set(initial):
        raise Failed("invalid_restore_journal")
    for hashes in attempts.values():
        if type(hashes) is not list or not 1 <= len(hashes) <= 4 or any(type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes) or len(set(hashes)) != len(hashes):
            raise Failed("invalid_restore_journal")
    if journal["setting_write_attempted"] and set(initial) != PACKAGES:
        raise Failed("invalid_restore_journal")


class Device:
    def __init__(self, adb):
        self.adb = str(adb)
        self.last_wait = None
        self.last_public_ui = {}
        self.last_focus_metadata = {"available": False, "reason": "not_observed"}
        self.expected_fixture = None
        self.current_case = None
        self.tap_diagnostics = []
        self.return_diagnostics = []
        self.return_phase = "not_observed"
        self._expected_fixture_session = None
        self._pi_identifiers = {}
        self._ui_parents = {}
        self._ui_started_ns = 0
        self._ui_finished_ns = 0
        self._authorization_pid = None
        self._authorization_pid_case = None
        self._authorization_pid_sample_ns = None
        raw = self.command([self.adb, "devices"], 15)
        devices = [row.split()[0] for row in raw.decode().splitlines()[1:] if len(row.split()) == 2 and row.split()[1] == "device"]
        if len(devices) != 1 or sha(devices[0].encode()) != DEVICE_SHA256:
            raise Failed("authorized_device_not_unique")
        self.serial = devices[0]

    @staticmethod
    def command(argv, timeout=25, allow_failure=False):
        try:
            result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Failed("device_command_unavailable") from None
        if result.returncode and not allow_failure:
            raise Failed("device_command_failed")
        return result.stdout

    def adb_command(self, *args, timeout=25, allow_failure=False):
        return self.command([self.adb, "-s", self.serial, *map(str, args)], timeout, allow_failure)

    def shell(self, *args, timeout=25, allow_failure=False):
        # Bind synthetic input to the reviewed default display, never another active display.
        if args and args[0] == "input": args = ("input", "-d", "0", *args[1:])
        # adb shell joins arguments. Quote each token for the remote shell, including synthetic input.
        return self.adb_command("shell", " ".join(shlex.quote(str(arg)) for arg in args), timeout=timeout, allow_failure=allow_failure).decode("utf-8", "replace").strip()

    def setting(self):
        value = self.shell("settings", "--user", "0", "get", "secure", "autofill_service")
        if value != "null" and not re.fullmatch(r"[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+", value):
            raise Failed("unexpected_autofill_setting")
        return value

    def package_present(self, package, include_uninstalled=False):
        if package not in PACKAGES: raise Failed("package_out_of_scope")
        command = ["pm", "list", "packages", "--user", "0"]
        if include_uninstalled: command.append("-u")
        command.append(package)
        rows = self.shell(*command).splitlines()  # A failed query is unknown, never absent.
        if any(not re.fullmatch(r"package:[A-Za-z0-9_.$]+", row) for row in rows):
            raise Failed("package_presence_unknown")
        return "package:" + package in rows

    def package_hash(self, package):
        if not self.package_present(package): return None
        rows = self.shell("pm", "path", "--user", "0", package).splitlines()
        if len(rows) != 1 or not rows[0].startswith("package:/data/app/"):
            raise Failed("unexpected_package_layout")
        path = rows[0][8:]
        value = self.shell("sha256sum", path).split()[0]
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise Failed("installed_digest_unavailable")
        return value

    def foreground(self):
        self.last_focus_metadata = {"available": False, "reason": "not_observed"}
        phase, shapes = "initial_focus_snapshot", {}
        try:
            focus = _focus_snapshot(self.shell("dumpsys", "window"))
            component = re.fullmatch(r"([A-Za-z0-9_.$]+)/([A-Za-z0-9_.$]+)", focus["title"])
            if component:
                current = component.groups()
                self.last_focus_metadata = {"available": True, "classification": "activity_window", "display": 0,
                                            "allowed_package": current[0] in PACKAGES | {"android"}}
                return current
            if focus["title"] != "Autofill UI":
                raise FocusUnavailable("focused_title_not_supported")
            package = self.expected_fixture
            if package not in {GOOD, DECOY}:
                raise FocusUnavailable("fixture_not_selected")
            phase = "focused_app_identity"
            shapes["focused_app_field_count"] = focus["focused_app_field_count"]
            shapes["focused_app"] = _activity_shape(focus["activity"], package)
            if focus["activity"] is None:
                raise FocusUnavailable("activity_identity_unavailable")
            _activity_identity(focus["activity"], package)
            # WMS supports an identity-hash selector; never dump a guessed package/title.
            phase = "popup_window_details"
            popup = _window_details(self.shell("dumpsys", "window", "-a", focus["window"]), focus["window"])
            shapes["popup_token"] = _activity_shape(popup["token"], package)
            shapes["popup_activity"] = _activity_shape(popup["activity"], package)
            shapes["focused_app_matches_popup_token"] = _activity_relation(focus["activity"], popup["token"], package)
            shapes["focused_app_matches_popup_activity"] = _activity_relation(focus["activity"], popup["activity"], package)
            phase = "popup_parent_binding"
            parent_id, _ = _popup_parent(focus, popup, package)
            phase = "parent_window_details"
            parent = _window_details(self.shell("dumpsys", "window", "-a", parent_id), parent_id)
            shapes["parent_token"] = _activity_shape(parent["token"], package)
            shapes["parent_activity"] = _activity_shape(parent["activity"], package)
            shapes["focused_app_matches_parent_token"] = _activity_relation(focus["activity"], parent["token"], package)
            shapes["focused_app_matches_parent_activity"] = _activity_relation(focus["activity"], parent["activity"], package)
            phase = "parent_window_binding"
            _bound_parent(focus, popup, parent, package)
            # This exact command dumps one server-owned top record without an app
            # callback. It is not a package filter. All unrelated raw fields are discarded.
            phase = "server_top_resumed_query"
            activities = self.shell("dumpsys", "activity", "top-resumed")
            phase = "final_focus_snapshot"
            final_focus = _focus_snapshot(self.shell("dumpsys", "window"))
            shapes["final_focused_app_field_count"] = final_focus["focused_app_field_count"]
            shapes["final_focused_app"] = _activity_shape(final_focus["activity"], package)
            phase = "complete_system_chain"
            self.last_focus_metadata = autofill_popup_metadata(focus, popup, parent, activities, final_focus, package)
            self.last_focus_metadata["shape_diagnostics"] = shapes
            return AUTOFILL_POPUP
        except FocusUnavailable as error:
            self.last_focus_metadata = {"available": False, "reason": str(error),
                                        "phase": phase, "shape_diagnostics": shapes,
                                        "oem_contract_requires_device_evidence": True}
            return None

    def ui(self):
        current = self.foreground()
        focus_deadline = time.monotonic() + 3
        while (current is None or current[0] not in PACKAGES | {"android"}) and time.monotonic() < focus_deadline:
            # Activity transitions may temporarily have no focused window. Read metadata only until an allowed app owns focus.
            time.sleep(0.05)
            current = self.foreground()
        if current is None or current[0] not in PACKAGES | {"android"}:
            raise Failed("unexpected_foreground_no_ui_read")
        # No hierarchy file is created on the device or host. Parse only in memory.
        self._ui_started_ns = time.monotonic_ns()
        raw = self.adb_command("exec-out", "uiautomator", "dump", "--compressed", "/dev/tty", timeout=20)
        start, end = raw.find(b"<hierarchy"), raw.find(b"</hierarchy>")
        if start < 0 or end < start:
            raise Failed("ui_hierarchy_unavailable")
        try:
            tree = ET.fromstring(raw[start:end + len(b"</hierarchy>")])
            nodes = list(tree.iter("node"))
            self._ui_parents = {child: parent for parent in tree.iter() for child in parent}
            self._ui_finished_ns = time.monotonic_ns()
            allowed = {"unlock heptabao locally", "heptabao · local authorization", "locked", "locked or expired", "authorization rejected", "heptabao synthetic native login", "fill synthetic login once", "unlock failed", "request autofill", "unlock locally", "fill once", "cancel"}
            self.last_public_ui = {"foreground": current, "controls": sorted({node.get("text", "").casefold() for node in nodes if node.get("text", "").casefold() in allowed})}
            return nodes
        except ET.ParseError:
            raise Failed("ui_hierarchy_invalid") from None

    def find(self, text=None, description=None):
        for node in self.ui():
            if (text is not None and node.get("text", "").casefold() == text.casefold()) or (description is not None and node.get("content-desc") == description):
                return node
        return None

    def wait(self, text=None, description=None, seconds=25):
        self.last_wait = {"text": text, "description": description}
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            node = self.find(text, description)
            if node is not None:
                return node
            time.sleep(0.25)
        raise Failed("expected_ui_missing")

    def tap(self, text=None, description=None):
        diagnostic = text in {"Request Autofill", "Unlock HeptaBao locally"}
        menu = text == "Unlock HeptaBao locally"
        node = self.wait(text, description)
        match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
        if not match or node.get("enabled") != "true":
            raise Failed("ui_target_unavailable")
        left, top, right, bottom = map(int, match.groups())
        if right <= left or bottom <= top:
            raise Failed("ui_target_bounds_invalid")
        point = [(left + right) // 2, (top + bottom) // 2]
        event = None
        if diagnostic:
            event = {"selector": text, "case": self.current_case, "display": 0, "point": point,
                     "selected_node_and_ancestors": self.node_geometry(node),
                     "dump_duration_ms": round((self._ui_finished_ns - self._ui_started_ns) / 1e6),
                     "sampling_is_not_case_proof": True}
            if menu:
                event["pending_intents_immediately_before_tap"] = self.pending_intents()
                current = self.foreground()
                event["foreground_before_tap"] = self.public_component(current)
                event["focus_metadata_before_tap"] = getattr(self, "last_focus_metadata", {"available": False, "reason": "not_observed"})
                if current != (self.expected_fixture, ACTIVITY) and not (current is not None and current[0] == "android"):
                    self.tap_diagnostics.append(event)
                    raise Failed("autofill_menu_context_changed")
            self.tap_diagnostics.append(event)
            event["dump_end_to_input_start_ms"] = round((time.monotonic_ns() - self._ui_finished_ns) / 1e6)
            if menu and event["dump_end_to_input_start_ms"] >= 1000:
                raise Failed("autofill_menu_sample_stale")
        input_started = time.monotonic_ns()
        self.shell("input", "tap", str(point[0]), str(point[1]))
        if event is not None:
            event["input_command_completed"] = True
            event["input_command_ms"] = round((time.monotonic_ns() - input_started) / 1e6)
            if menu:
                event["pending_intents_after_tap"] = self.pending_intents()
                event["foreground_after_tap"] = self.public_component(self.foreground())

    @staticmethod
    def public_component(component):
        if component in {(GOOD, ACTIVITY), (DECOY, ACTIVITY), (PROVIDER, "org.heptabao.preview.MainActivity"), (PROVIDER, "org.heptabao.preview.AuthActivity")}:
            return {"component": list(component)}
        return {"classification": "system_window" if component and component[0] == "android" else "unavailable_or_other"}

    def node_geometry(self, node):
        out = []
        for _ in range(8):
            if node is None or node.tag != "node": break
            package = node.get("package")
            cls = node.get("class", "")
            row = {"package": package if package in PACKAGES | {"android"} else "other_omitted",
                   "class": cls if re.fullmatch(r"android\.(?:widget|view)\.[A-Za-z0-9_$]+", cls) else "other_omitted",
                   "is_presentation_text_id": node.get("resource-id") == PROVIDER + ":id/presentation_text"}
            bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
            row["bounds"] = list(map(int, bounds.groups())) if bounds else None
            for key in ("enabled", "clickable", "focusable", "focused", "scrollable", "visible-to-user"):
                row[key] = {"true": True, "false": False}.get(node.get(key))
            out.append(row)
            node = self._ui_parents.get(node)
        return out

    def pending_intents(self):
        # Framework-side exact package filter. The parser discards all URI tokens,
        # request extras, weak-reference entries, and the global UID-count tail.
        started = time.monotonic_ns()
        try:
            raw = self.shell("dumpsys", "activity", "-a", "intents", PROVIDER, timeout=5)
            result = pending_intent_metadata(raw, self._pi_identifiers)
        except Failed:
            result = {"available": False, "reason": "query_failed"}
        result["query_duration_ms"] = round((time.monotonic_ns() - started) / 1e6)
        result["observation_monotonic_ns"] = time.monotonic_ns()
        return result

    def fixture(self, package=GOOD):
        if package not in {GOOD, DECOY}: raise Failed("fixture_out_of_scope")
        self._expected_fixture_session = None
        self.shell("am", "force-stop", "--user", "0", package)
        launched = self.shell("am", "start", "--user", "0", "--display", "0", "-W", "-f", "0x10008000", "-n", package + "/" + ACTIVITY)
        if "Status: ok" not in launched or ("Activity: " + package + "/" + ACTIVITY) not in launched:
            raise Failed("fixture_activity_not_started")
        self.expected_fixture = package
        self.assert_fixture(self.wait(text="HeptaBao synthetic native login"))
        # Capture the original window/token/task only at this existing case setup.
        # Returning from authentication must never silently accept a new Activity.
        self.return_phase = "bind_initial_fixture_session"
        try:
            _, session, _ = self._return_snapshot("fixture")
        except FocusUnavailable:
            raise Failed("initial_fixture_session_unavailable") from None
        self._expected_fixture_session = session

    def _return_snapshot(self, kind, expected_session=None):
        package = self.expected_fixture
        if package not in {GOOD, DECOY} or kind not in {"fixture", "popup", "fixture_or_popup"}:
            raise FocusUnavailable("fixture_return_scope")
        diagnostic = {"scope": "existing_return_binding_metadata_only", "causal_case_proof": False,
                      "requested_kind": kind, "selected_kind": "not_selected", "phase": "focus_snapshot",
                      "bound": False}
        self._return_binding_diagnostic = diagnostic
        focus = _focus_snapshot(self.shell("dumpsys", "window"))
        diagnostic["identity_components"] = _return_identity_components(focus, None, package)
        if kind == "fixture_or_popup":
            # The earlier surface sample is only a hint. Select the validator
            # from this snapshot, then require its complete unchanged identity
            # chain before UI access or input. A title alone grants nothing.
            if focus["title"] == package + "/" + ACTIVITY: kind = "fixture"
            elif focus["title"] == "Autofill UI": kind = "popup"
            else: raise FocusUnavailable("fixture_return_surface_not_supported")
        diagnostic["selected_kind"] = kind
        diagnostic["phase"] = "window_details"
        window = _window_details(self.shell("dumpsys", "window", "-a", focus["window"]), focus["window"])
        diagnostic["identity_components"] = _return_identity_components(focus, window, package)
        if kind == "popup":
            diagnostic["phase"] = "popup_parent_binding"
            parent_id, _ = _popup_parent(focus, window, package)
            parent = _window_details(self.shell("dumpsys", "window", "-a", parent_id), parent_id)
            _bound_parent(focus, window, parent, package)
        else:
            parent = window
        diagnostic["phase"] = "server_top_resumed_query"
        activities = self.shell("dumpsys", "activity", "top-resumed")
        diagnostic["phase"] = "final_focus_snapshot"
        final_focus = _focus_snapshot(self.shell("dumpsys", "window"))
        diagnostic["final_focus_matches"] = final_focus == focus
        diagnostic["phase"] = "complete_binding"
        if kind == "popup":
            metadata = autofill_popup_metadata(focus, window, parent, activities, final_focus, package)
        else:
            metadata = fixture_return_metadata(focus, window, activities, final_focus, package, expected_session)
        session = _fixture_session(parent, package)
        diagnostic["original_session_checked"] = expected_session is not None
        diagnostic["original_session_matches"] = expected_session is None or session == expected_session
        if expected_session is not None and session != expected_session:
            raise FocusUnavailable("fixture_return_session_changed")
        diagnostic["bound"] = True
        return focus, session, metadata

    def _wait_return_surface(self, after_back=False):
        # Metadata-only transition observation; never key into an unrecognized app.
        deadline = time.monotonic() + 3
        while True:
            current = self.foreground()
            # A slow successful query cannot extend the observation deadline.
            if time.monotonic() >= deadline:
                raise Failed("fixture_return_not_observed")
            if current == (self.expected_fixture, ACTIVITY):
                return current
            if current == AUTOFILL_POPUP and not after_back:
                return current
            if current is not None and current != AUTOFILL_POPUP and not (
                    not after_back and current == (PROVIDER, "org.heptabao.preview.AuthActivity")):
                raise Failed("fixture_return_foreground_changed")
            time.sleep(0.05)

    def _wait_return_title(self, deadline):
        # Observe a delayed popup within the original title budget. Its UI only
        # selects the branch; the complete system/parent/record binding is still
        # repeated by return_to_fixture before any ordinary Back input.
        self.last_wait = {"text": "HeptaBao synthetic native login", "description": None}
        while True:
            if time.monotonic() >= deadline:
                raise Failed("expected_ui_missing")
            nodes = self.ui()
            if time.monotonic() >= deadline:
                raise Failed("expected_ui_missing")
            if any(node.get("text", "").casefold() == "fill synthetic login once" for node in nodes):
                raise Failed("cached_plaintext_dataset_visible")
            current = self.last_public_ui.get("foreground")
            if current == AUTOFILL_POPUP:
                return None
            if current != (self.expected_fixture, ACTIVITY):
                raise Failed("fixture_return_foreground_changed")
            for node in nodes:
                if node.get("text", "").casefold() == "heptabao synthetic native login":
                    return node
            time.sleep(0.25)

    def return_to_fixture(self, origin):
        if origin not in {"after_auth_cancel", "after_auth_fill", "before_fixture_verification"}:
            raise Failed("fixture_return_origin_out_of_scope")
        event = {"origin": origin, "case": self.current_case, "back_command_count": 0,
                 "sampling_is_not_case_proof": True, "result": "pending"}
        self.return_diagnostics.append(event)
        self._return_binding_diagnostic = None
        try:
            self.return_phase = "await_return_surface"
            if self._expected_fixture_session is None:
                raise Failed("original_fixture_session_unavailable")
            surface = self._wait_return_surface()
            title_deadline = None
            while True:
                if title_deadline is not None and time.monotonic() >= title_deadline:
                    raise Failed("expected_ui_missing")
                if surface == AUTOFILL_POPUP:
                    if event["back_command_count"] != 0:
                        raise Failed("fixture_return_popup_reappeared")
                    self.return_phase = "bind_return_popup_before_ui"
                    before, session, metadata = self._return_snapshot("popup", self._expected_fixture_session)
                    self.return_phase = "inspect_return_popup_presentation"
                    nodes = self.ui()
                    if any(node.get("text", "").casefold() == "fill synthetic login once" for node in nodes):
                        raise Failed("cached_plaintext_dataset_visible")
                    menus = [node for node in nodes if node.get("resource-id") == PROVIDER + ":id/presentation_text"]
                    if (len(menus) != 1 or menus[0].get("package") != PROVIDER
                            or menus[0].get("text", "").casefold() != "unlock heptabao locally"
                            or menus[0].get("enabled") != "true"):
                        raise Failed("fixture_return_popup_presentation_unrecognized")
                    self.return_phase = "recheck_return_popup_before_back"
                    latest, latest_session, metadata = self._return_snapshot("popup", session)
                    if latest != before or latest_session != session:
                        raise FocusUnavailable("fixture_return_popup_changed")
                    elapsed_ms = (time.monotonic_ns() - self._ui_finished_ns) / 1e6
                    event["dump_end_to_back_start_ms"] = round(elapsed_ms)
                    event["focus_metadata_before_back"] = metadata
                    if elapsed_ms >= 1000:
                        raise Failed("fixture_return_popup_sample_stale")
                    if title_deadline is not None and time.monotonic() >= title_deadline:
                        raise Failed("expected_ui_missing")
                    self.return_phase = "dismiss_bound_return_popup_once"
                    event["back_command_count"] = 1  # An uncertain input is never retried.
                    started = time.monotonic_ns()
                    self.shell("input", "keyevent", "KEYCODE_BACK")
                    event["back_command_completed"] = True
                    event["back_command_ms"] = round((time.monotonic_ns() - started) / 1e6)
                    self.return_phase = "observe_fixture_after_back"
                    self._wait_return_surface(after_back=True)
                    _, _, metadata = self._return_snapshot("fixture", session)
                    event["same_parent_session_after_back"] = True
                else:
                    self.return_phase = "bind_direct_fixture_return"
                    binding_started = time.monotonic()
                    _, _, metadata = self._return_snapshot("fixture_or_popup", self._expected_fixture_session)
                    if metadata["classification"] == "bound_system_autofill_popup":
                        # A popup can arrive between the surface hint and this
                        # complete binding. Reuse the existing popup path, its
                        # plaintext-first checks, and its single Back budget.
                        # Start the same 25-second budget before this binding;
                        # the additional validation can never reset/extend it.
                        event["popup_observed_at_direct_binding"] = True
                        if title_deadline is None: title_deadline = binding_started + 25
                        surface = AUTOFILL_POPUP
                        continue
                event["focus_metadata_after_return"] = metadata
                self.return_phase = "observe_returned_fixture_title"
                if title_deadline is None:
                    title_deadline = time.monotonic() + 25
                node = self._wait_return_title(title_deadline)
                if node is None:
                    event["late_popup_during_title_observation"] = True
                    surface = AUTOFILL_POPUP
                    continue
                self.assert_fixture(node)
                self.return_phase = "recheck_fixture_identity_after_title"
                _, _, metadata = self._return_snapshot("fixture", self._expected_fixture_session)
                if time.monotonic() >= title_deadline:
                    raise Failed("expected_ui_missing")
                event["focus_metadata_after_title"] = metadata
                event["result"] = "returned_to_original_fixture"
                self.return_phase = "returned_to_original_fixture"
                return event
        except FocusUnavailable as error:
            event["result"] = "refused"; event["reason"] = str(error)
            if self._return_binding_diagnostic is not None:
                event["last_binding_observation"] = dict(self._return_binding_diagnostic)
            raise Failed("fixture_return_identity_unavailable") from None
        except Failed as error:
            event["result"] = "refused"; event["reason"] = str(error)
            raise

    def assert_fixture(self, node=None):
        component = self.foreground()
        if self.expected_fixture not in {GOOD, DECOY} or component != (self.expected_fixture, ACTIVITY):
            raise Failed("fixture_activity_changed")
        if node is not None and node.get("package") != self.expected_fixture:
            raise Failed("fixture_node_package_changed")
        return component

    def _wait_cached_username(self, deadline):
        # Observe the same field or its bound system popup without dismissing
        # either or creating a new Autofill request. The original budget is fixed.
        self.last_wait = {"text": None, "description": "Synthetic username"}
        while True:
            if time.monotonic() >= deadline:
                raise Failed("expected_ui_missing")
            nodes = self.ui()
            if time.monotonic() >= deadline:
                raise Failed("expected_ui_missing")
            if any(node.get("text", "").casefold() == "fill synthetic login once" for node in nodes):
                raise Failed("cached_plaintext_dataset_visible")
            current = self.last_public_ui.get("foreground")
            if current == AUTOFILL_POPUP:
                return None
            if current != (GOOD, ACTIVITY):
                raise Failed("cached_refocus_foreground_changed")
            for node in nodes:
                if node.get("content-desc") == "Synthetic username":
                    return node
            time.sleep(0.25)

    def cached_refocus(self):
        # Clearing an already focused field may itself reopen Autofill UI. Keep
        # the original window/Activity/task/owner; never dismiss a plaintext menu
        # or start another request to make the cached-data control pass.
        original = self._expected_fixture_session
        if self.expected_fixture != GOOD or original is None:
            raise Failed("cached_original_fixture_unavailable")
        try:
            self._return_snapshot("fixture", original)
            self.tap(text="Clear fields")
            surface = self._wait_return_surface()
            username_deadline = None
            late_popup = False
            while True:
                if username_deadline is not None and time.monotonic() >= username_deadline:
                    raise Failed("expected_ui_missing")
                if surface == AUTOFILL_POPUP:
                    before, session, _ = self._return_snapshot("popup", original)
                    nodes = self.ui()
                    if any(node.get("text", "").casefold() == "fill synthetic login once" for node in nodes):
                        raise Failed("cached_plaintext_dataset_visible")
                    menus = [node for node in nodes if node.get("resource-id") == PROVIDER + ":id/presentation_text"]
                    if (len(menus) != 1 or menus[0].get("package") != PROVIDER
                            or menus[0].get("text", "").casefold() != "unlock heptabao locally"
                            or menus[0].get("enabled") != "true"):
                        raise Failed("cached_popup_presentation_unrecognized")
                    latest, latest_session, _ = self._return_snapshot("popup", original)
                    if latest != before or latest_session != session:
                        raise FocusUnavailable("cached_popup_changed")
                    if username_deadline is not None and time.monotonic() >= username_deadline:
                        raise Failed("expected_ui_missing")
                    return {"path": "bound_popup_after_clear", "username_touch_count": 0,
                            "late_popup_during_username_observation": late_popup,
                            "same_fixture_wms_identity": True, "autofill_internal_session_id_observed": False}
                if surface != (GOOD, ACTIVITY):
                    raise Failed("cached_refocus_foreground_changed")
                if username_deadline is None:
                    username_deadline = time.monotonic() + 25
                node = self._wait_cached_username(username_deadline)
                if node is None:
                    late_popup = True
                    surface = AUTOFILL_POPUP
                    continue
                self.assert_fixture(node)
                self._return_snapshot("fixture", original)
                bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
                if (node.get("resource-id") != GOOD + ":id/login_username"
                        or node.get("enabled") != "true" or bounds is None):
                    raise Failed("cached_username_target_unavailable")
                left, top, right, bottom = map(int, bounds.groups())
                if right <= left or bottom <= top:
                    raise Failed("cached_username_bounds_invalid")
                if (time.monotonic_ns() - self._ui_finished_ns) / 1e6 >= 1000:
                    raise Failed("cached_username_sample_stale")
                if time.monotonic() >= username_deadline:
                    raise Failed("expected_ui_missing")
                # One ordinary touch using this fresh, bound node; no retry after
                # uncertain input. shell() binds actual input argv to display 0.
                self.shell("input", "tap", str((left + right) // 2), str((top + bottom) // 2))
                return {"path": "fresh_username_touch_after_clear", "username_touch_count": 1,
                        "late_popup_during_username_observation": False,
                        "same_fixture_wms_identity": True, "autofill_internal_session_id_observed": False}
        except FocusUnavailable:
            raise Failed("cached_refocus_identity_unavailable") from None

    def empty(self):
        self.verify("Empty fields")

    def verify(self, expected):
        # Dismiss only a fully bound locked placeholder, after checking for plaintext.
        # The verification still requires a newly incremented fixture counter.
        self.return_to_fixture("before_fixture_verification")
        self.assert_fixture()
        self.tap(text="HeptaBao synthetic native login")
        before = self.wait(description="Fixture verification")
        self.assert_fixture(before)
        match = re.fullmatch(r"Verification (\d+): .+", before.get("text", ""))
        if not match: raise Failed("fixture_verification_counter_missing")
        count = int(match.group(1)) + 1
        self.tap(text="Verify synthetic login")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            after = self.wait(description="Fixture verification")
            self.assert_fixture(after)
            prefix = "Verification " + str(count) + ": "
            if after.get("text", "").startswith(prefix):
                if after.get("text") != prefix + expected: raise Failed("actual_fixture_values_rejected")
                return
            time.sleep(0.25)
        raise Failed("fixture_verification_not_executed")

    def authentication(self):
        self._authorization_pid = None
        self._authorization_pid_case = None
        self._authorization_pid_sample_ns = None
        self.fixture()
        self.tap(text="Request Autofill")
        self.tap(text="Unlock HeptaBao locally")
        self.wait(text="HeptaBao · local authorization")
        self.wait(text="Locked")
        self.capture_authorization_pid()

    def authorization_status(self, expected, node=None):
        if node is None: node = self.wait(description="Authorization status")
        component = self.foreground()
        if component != (PROVIDER, "org.heptabao.preview.AuthActivity") or node.get("package") != PROVIDER or node.get("content-desc") != "Authorization status" or node.get("text") != expected:
            raise Failed("authorization_status_not_observed")
        return {"activity": list(component), "status": expected}

    def authorization_observation(self):
        # Private, non-authorizing correlation only; never return this identifier
        # in a public case result, failure context, log, or saved UI dump.
        expected = (PROVIDER, "org.heptabao.preview.AuthActivity")
        if self.foreground() != expected: raise Failed("authorization_observation_unbound")
        nodes = [node for node in self.ui() if node.get("content-desc") == "Authorization observation"]
        if self.foreground() != expected or len(nodes) != 1 or nodes[0].get("package") != PROVIDER:
            raise Failed("authorization_observation_unbound")
        value = nodes[0].get("text", "")
        if not re.fullmatch(r"observation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value):
            raise Failed("authorization_observation_unavailable")
        return value

    def cancellation_observation(self, expected_observation):
        # Read the fresh Main instance already opened by decision(). The bounded
        # record is distinct from its raceable global lastDecision snapshot.
        if not re.fullmatch(r"observation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", expected_observation):
            raise Failed("cancel_observation_mismatch")
        expected = (PROVIDER, "org.heptabao.preview.MainActivity")
        if self.foreground() != expected: raise Failed("cancel_observation_unbound")
        nodes = [node for node in self.ui() if node.get("content-desc") == "Cancellation observation"]
        if self.foreground() != expected or len(nodes) != 1 or nodes[0].get("package") != PROVIDER:
            raise Failed("cancel_observation_unbound")
        fields = nodes[0].get("text", "").split("|")
        if fields != ["cancel_observation", expected_observation, "explicit_cancel", "auth_pause", "p1l1h0", "p0l0h0"]:
            raise Failed("cancel_observation_mismatch")
        return {"observation_matches_current_authorization": True, "explicit_cancel_action_observed": True,
                "source": "auth_pause", "before": "p1l1h0", "after": "p0l0h0",
                "observation_identifier_is_authority": False}

    def provider_pid(self):
        try:
            pid = self.shell("pidof", PROVIDER, timeout=5, allow_failure=True)
            return pid if re.fullmatch(r"[1-9][0-9]{0,9}", pid) else None
        except Failed:
            return None

    def capture_authorization_pid(self):
        # Metadata only, after the existing Auth/Locked waits and before input.
        # A numeric PID match is not proof of an OS process generation or request ID.
        try:
            if self.foreground() != (PROVIDER, "org.heptabao.preview.AuthActivity"):
                return
            pid = self.provider_pid()
            if self.foreground() != (PROVIDER, "org.heptabao.preview.AuthActivity"):
                return
            self._authorization_pid = pid
            self._authorization_pid_case = self.current_case
            self._authorization_pid_sample_ns = time.monotonic_ns()
        except Failed:
            return

    def provider_events(self):
        # Read only the observed process's dedicated static-code tag. Raw bytes
        # exist in memory for counting, and are never returned or persisted.
        started = time.monotonic_ns()
        same_case = getattr(self, "_authorization_pid_case", None) == self.current_case
        baseline = getattr(self, "_authorization_pid", None) if same_case else None
        sampled = getattr(self, "_authorization_pid_sample_ns", None) if baseline is not None else None
        before = self.provider_pid()
        before_finished = time.monotonic_ns()
        result = {"available": False, "scope": "current_provider_process_buffer_diagnostic_only", "codes": [],
                  "baseline_recorded_for_case": baseline is not None, "pid_before_present": before is not None,
                  "pid_after_present": False, "baseline_matches_before": baseline == before if baseline is not None and before is not None else None,
                  "baseline_matches_after": None, "pid_before_after_equal": None,
                  "numeric_pid_match_is_process_generation_proof": False, "log_delivery_order_is_event_order": False,
                  "baseline_age_ms": round((started - sampled) / 1e6) if sampled is not None else None,
                  "pid_before_query_ms": round((before_finished - started) / 1e6)}
        if before is None:
            result.update(reason="provider_pid_unavailable", duration_ms=round((before_finished - started) / 1e6))
            return result
        args = ("logcat", "-d", "-b", "main", "-v", "raw", "--pid=" + before, "HeptaBaoPreview:I", "*:S")
        raw = None
        try:
            raw = self.adb_command("shell", " ".join(shlex.quote(arg) for arg in args))
        except Failed:
            result["reason"] = "logcat_query_unavailable"
        log_finished = time.monotonic_ns()
        after = self.provider_pid()
        finished = time.monotonic_ns()
        result.update(pid_after_present=after is not None, pid_before_after_equal=before == after if after is not None else None,
                      baseline_matches_after=baseline == after if baseline is not None and after is not None else None,
                      logcat_query_ms=round((log_finished - before_finished) / 1e6),
                      pid_after_query_ms=round((finished - log_finished) / 1e6), duration_ms=round((finished - started) / 1e6))
        if raw is not None:
            if len(raw) > 1024 * 1024:
                result.update(reason="logcat_buffer_limit", raw_byte_count=len(raw))
            else:
                result.update(available=True, **provider_event_projection(raw))
        return result

    def authorization_diagnostic(self):
        # Failure-only read. The TextView describes an existing rejection branch;
        # prior_decision_snapshot is a raceable global observation, never its cause.
        started = time.monotonic_ns()
        result = {"available": False, "scope": "existing_rejection_branch_ui_diagnostic_only",
                  "prior_decision_is_request_cause_proof": False}
        try:
            expected = (PROVIDER, "org.heptabao.preview.AuthActivity")
            if self.foreground() != expected:
                result["reason"] = "auth_activity_not_foreground"
            else:
                nodes = [node for node in self.ui() if node.get("content-desc") == "Authorization diagnostic"]
                if self.foreground() != expected:
                    result["reason"] = "auth_activity_changed"
                elif len(nodes) != 1 or nodes[0].get("package") != PROVIDER:
                    result["reason"] = "diagnostic_node_unbound"
                else:
                    code_union = "(" + "|".join(sorted(DIAGNOSTIC_CODES)) + ")"
                    match = re.fullmatch(r"reject_(unlock_precheck|unlock_post_kdf)_" + code_union + "_prior_" + code_union, nodes[0].get("text", ""))
                    if match:
                        result.update(available=True, stage=match.group(1), reason=match.group(2), prior_decision_snapshot=match.group(3))
                    else:
                        result["reason"] = "diagnostic_not_observed"
        except Failed:
            result["reason"] = "diagnostic_query_unavailable"
        result["duration_ms"] = round((time.monotonic_ns() - started) / 1e6)
        return result

    def unlock(self, master, expect_success=True):
        self.tap(description="Master password")
        node = self.find(description="Master password")
        current = self.foreground()
        if node is None or node.get("package") != PROVIDER or node.get("password") != "true" or node.get("focused") != "true" or current != (PROVIDER, "org.heptabao.preview.AuthActivity"):
            raise Failed("password_input_target_changed")
        self.shell("input", "text", master)
        self.tap(text="Unlock locally")
        expected = "Unlocked; confirm within 20 seconds" if expect_success else "Unlock failed"
        return self.authorization_status(expected, self.wait(text=expected, seconds=40))

    def cancel_authentication(self, authentication_started=None, unlock_started=None):
        if authentication_started is not None:
            if time.monotonic() - unlock_started >= 18 or time.monotonic() - authentication_started >= 100:
                raise Failed("cancel_check_could_be_expiry")
        self.tap(text="Cancel")
        self.return_to_fixture("after_auth_cancel")
        evidence = None
        if authentication_started is not None:
            elapsed = time.monotonic() - unlock_started; request_elapsed = time.monotonic() - authentication_started
            if elapsed >= 18 or request_elapsed >= 100: raise Failed("cancel_check_could_be_expiry")
            evidence = {"fixture_return_from_before_unlock_ms": round(elapsed * 1000), "request_elapsed_ms": round(request_elapsed * 1000)}
        self.empty()
        return evidence

    def auth_task(self):
        if self.foreground() != (PROVIDER, "org.heptabao.preview.AuthActivity"):
            raise Failed("authorization_activity_not_foreground")
        raw = self.shell("dumpsys", "activity", "activities", PROVIDER)
        rows = [line for line in raw.splitlines() if "org.heptabao.preview.AuthActivity" in line and ("mResumedActivity" in line or "topResumedActivity" in line)]
        tasks = set()
        for row in rows:
            match = re.search(r"\bt([0-9]+)\b", row)
            if match: tasks.add(int(match.group(1)))
        if len(tasks) != 1: raise Failed("authorization_task_unavailable")
        return tasks.pop()

    def decision(self, reset_to_locked=False):
        component = PROVIDER + "/org.heptabao.preview.MainActivity"
        # NEW_TASK|CLEAR_TASK creates a fresh status snapshot without stopping the
        # provider process. Only post-case diagnostics and negative-case setup use it.
        launched = self.shell("am", "start", "--user", "0", "--display", "0", "-W", "-f", "0x10008000", "-n", component)
        if "Status: ok" not in launched or ("Activity: " + component) not in launched:
            raise Failed("provider_status_activity_not_started")
        self.wait(description="Provider status")
        if reset_to_locked: self.tap(text="Lock now")
        node = self.wait(description="Provider status")
        if self.foreground() != (PROVIDER, "org.heptabao.preview.MainActivity") or node.get("package") != PROVIDER:
            raise Failed("provider_status_activity_changed")
        match = re.search(r"Decision: ([a-z_]+)$", node.get("text", ""))
        if not match:
            raise Failed("provider_decision_unavailable")
        if reset_to_locked and match.group(1) != "locked": raise Failed("provider_locked_baseline_not_observed")
        return match.group(1)


def restore(device, journal, journal_path):
    validate_journal(journal)
    if journal.get("setting_write_attempted"):
        current = device.setting()
        previous = journal["previous_autofill_service"]
        if current == SERVICE:
            if previous == "null":
                device.shell("settings", "--user", "0", "delete", "secure", "autofill_service")
            else:
                device.shell("settings", "--user", "0", "put", "secure", "autofill_service", previous)
            if device.setting() != previous:
                raise Failed("autofill_restore_verification_failed")
            journal["restoration"] = "restored_original"
        elif current == previous:
            journal["restoration"] = "already_original"
        else:
            journal["restoration"] = "external_change_preserved"
    else:
        journal["restoration"] = "not_changed"
    atomic_json(journal_path, journal)
    cleanup = {}
    for package, hashes in journal.get("owned_packages", {}).items():
        current_hash = device.package_hash(package)
        if current_hash is None:
            cleanup[package] = "absent"
        elif current_hash in hashes:
            device.adb_command("uninstall", package, timeout=60)
            if device.package_hash(package) is not None:
                raise Failed("owned_package_cleanup_failed")
            cleanup[package] = "removed_owned_package"
        else:
            cleanup[package] = "unknown_artifact_preserved"
    journal["package_cleanup"] = cleanup
    atomic_json(journal_path, journal)
    return journal["restoration"], cleanup


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb", required=True, type=Path)
    parser.add_argument("--apks", type=Path)
    parser.add_argument("--build-receipt", type=Path)
    parser.add_argument("--master-file", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--restore", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    device = Device(args.adb)
    if device.shell("am", "get-current-user") != "0" or device.shell("getprop", "ro.build.version.sdk") != "36":
        raise Failed("unsupported_device_user_or_api")
    if args.restore:
        info = args.restore.lstat(); parent = args.restore.parent.lstat()
        if args.restore.is_symlink() or args.restore.parent.is_symlink() or not args.restore.is_file() or info.st_uid != os.getuid() or info.st_mode & 0o077 or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise Failed("unsafe_restore_journal")
        journal = json.loads(args.restore.read_text())
        validate_journal(journal)
        restored, cleanup = restore(device, journal, args.restore)
        print(json.dumps({"ok": True, "restoration": restored, "package_cleanup": cleanup}, sort_keys=True))
        return
    if any(value is None for value in (args.apks, args.build_receipt, args.master_file, args.output)):
        raise Failed("missing_run_input")
    if args.master_file.is_symlink() or args.master_file.stat().st_uid != os.getuid() or args.master_file.stat().st_mode & 0o077:
        raise Failed("unsafe_master_file")
    master = args.master_file.read_text()
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", master):
        raise Failed("unexpected_synthetic_master")
    build = json.loads(args.build_receipt.read_text())
    variants = {"provider": PROVIDER, "fixture-good": GOOD, "fixture-wrong-certificate": GOOD, "fixture-wrong-package": DECOY}
    for variant, package in variants.items():
        artifact = build["artifacts"][variant]
        if artifact["package"] != package or artifact["sha256"] != sha((args.apks / (variant + ".apk")).read_bytes()):
            raise Failed("apk_build_binding_mismatch")
    if build["crypto_interop"].get("ok") is not True or build["crypto_interop"].get("checks") != 12:
        raise Failed("host_interop_not_qualified")
    if build["artifacts"]["fixture-good"]["signer_sha256"] != build["artifacts"]["fixture-wrong-package"]["signer_sha256"] or build["artifacts"]["fixture-good"]["signer_sha256"] == build["artifacts"]["fixture-wrong-certificate"]["signer_sha256"]:
        raise Failed("negative_certificate_fixtures_invalid")
    args.output.mkdir(mode=0o700, exist_ok=False)
    parent_directory = os.open(args.output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(parent_directory)
    finally: os.close(parent_directory)
    journal_path = args.output / "restore.private.json"
    journal = {"schema": 2, "device_serial_sha256": DEVICE_SHA256, "service_written": SERVICE, "previous_autofill_service": device.setting(), "setting_write_attempted": False, "initial_absent": {}, "owned_packages": {}, "created_unix_ns": time.time_ns()}
    atomic_json(journal_path, journal)
    report = {"schema": 1, "scope": "native_synthetic_autofill_only", "synthetic_only": True, "production_qualified": False, "credential_entry": "synthetic_only_adb_input_text_argv", "expected_cases": EXPECTED_CASES, "expected_count": len(EXPECTED_CASES), "current_case": None, "device_serial_sha256": DEVICE_SHA256, "api": 36, "release": device.shell("getprop", "ro.build.version.release"), "model": device.shell("getprop", "ro.product.model"), "hardware_sku": device.shell("getprop", "ro.boot.hardware.sku"), "build_fingerprint_sha256": sha(device.shell("getprop", "ro.build.fingerprint").encode()), "build_receipt_sha256": sha(args.build_receipt.read_bytes()), "qa_script_sha256": sha(Path(__file__).read_bytes()), "started_unix_ns": time.time_ns(), "cases": [], "installed_apk_sha256": {}, "previous_setting_sha256": sha(journal["previous_autofill_service"].encode()), "unsupported": ["browser", "WebView filling", "arbitrary applications", "passkeys", "sharing"]}
    def case(name, action):
        if name not in EXPECTED_CASES or any(row["name"] == name for row in report["cases"]): raise Failed("unexpected_case_inventory")
        report["current_case"] = name
        device.current_case = name
        print(json.dumps({"case": name, "state": "running"}), flush=True)
        started = time.monotonic(); evidence = action()
        if not isinstance(evidence, dict): raise Failed("case_evidence_missing")
        report["cases"].append({"name": name, "passed": True, "elapsed_ms": round((time.monotonic() - started) * 1000), "evidence": evidence})
        report["current_case"] = None
        device.current_case = None
        atomic_json(args.output / "progress.json", report)
        print(json.dumps({"case": name, "passed": True}), flush=True)
    def install(variant):
        artifact = build["artifacts"][variant]; package = artifact["package"]
        if journal["initial_absent"].get(package) is not True or device.package_present(package): raise Failed("refuse_unowned_or_existing_package")
        allowed = journal["owned_packages"].setdefault(package, [])
        if artifact["sha256"] not in allowed: allowed.append(artifact["sha256"])
        atomic_json(journal_path, journal)
        device.adb_command("install", "--user", "0", "--no-streaming", args.apks / (variant + ".apk"), timeout=90)
        if device.package_hash(package) != artifact["sha256"]:
            raise Failed("installed_apk_digest_mismatch")
        report["installed_apk_sha256"][variant] = artifact["sha256"]
    interrupted = False
    def stop(signum, frame):
        nonlocal interrupted
        if interrupted: return
        interrupted = True
        raise Failed("run_interrupted")
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    failure = None
    try:
        for package in PACKAGES:
            # Include uninstalled retained package records: never overwrite an unknown prior preview.
            if device.package_present(package) or device.package_present(package, True):
                raise Failed("target_package_preexists")
        journal["initial_absent"] = {package: True for package in PACKAGES}
        atomic_json(journal_path, journal)
        install("provider"); install("fixture-good"); install("fixture-wrong-package")
        if device.setting() != journal["previous_autofill_service"]:
            raise Failed("autofill_setting_changed_before_write")
        journal["setting_write_attempted"] = True; atomic_json(journal_path, journal)
        device.shell("settings", "--user", "0", "put", "secure", "autofill_service", SERVICE)
        if device.setting() != SERVICE: raise Failed("autofill_enable_not_applied")
        def imported():
            device.fixture(); device.tap(text="Import synthetic encrypted vault"); device.tap(text="Import")
            status = device.wait(description="Provider status")
            deadline = time.monotonic() + 20
            while "Encrypted vault imported; locked" not in status.get("text", "") and time.monotonic() < deadline:
                time.sleep(0.25); status = device.wait(description="Provider status")
            if "Encrypted vault imported; locked" not in status.get("text", ""): raise Failed("ciphertext_import_failed")
            return {"provider_status": "Encrypted vault imported; locked", "ciphertext_sha256": build["fixture_public"]["ciphertext_sha256"]}
        case("rust_ciphertext_import", imported)
        def locked():
            device.authentication(); device.tap(text="Fill once")
            observed = device.authorization_status("Locked or expired", device.wait(text="Locked or expired")); device.cancel_authentication()
            return {"authorization": observed, "target": GOOD, "fixture_values": "Empty fields", "unlocked_in_this_case": False}
        case("locked_fill_refused", locked)
        def wrong_master():
            device.authentication(); denied = device.unlock(("A" if master[0] != "A" else "B") + master[1:], False)
            device.tap(text="Fill once")
            observed = device.authorization_status("Locked or expired", device.wait(text="Locked or expired")); device.cancel_authentication()
            return {"unlock": denied, "authorization": observed, "target": GOOD, "fixture_values": "Empty fields"}
        case("wrong_master_refused", wrong_master)
        def login():
            device.authentication(); device.unlock(master); device.tap(text="Fill once")
            device.return_to_fixture("after_auth_fill"); device.verify("Synthetic login accepted")
            actual = device.assert_fixture()
            if actual != (GOOD, ACTIVITY): raise Failed("accepted_fixture_target_changed")
            return {"target": GOOD, "actual_activity": list(actual), "fixture_values": "Synthetic login accepted", "target_apk_sha256": build["artifacts"]["fixture-good"]["sha256"]}
        case("actual_system_fill_and_login", login)
        def cached():
            authentication_reappeared = False
            refocus = device.cached_refocus()
            locked_placeholder_attempted = False
            time.sleep(1)
            if device.find(text="Fill synthetic login once") is not None: raise Failed("cached_plaintext_dataset_visible")
            node = device.find(text="Unlock HeptaBao locally")
            if node is None and refocus["path"] == "bound_popup_after_clear":
                raise Failed("cached_locked_presentation_disappeared")
            if node is not None:
                device.tap(text="Unlock HeptaBao locally"); locked_placeholder_attempted = True; time.sleep(0.5)
                if device.foreground() == (PROVIDER, "org.heptabao.preview.AuthActivity"):
                    authentication_reappeared = True
                    device.wait(text="Locked"); device.tap(text="Fill once"); device.wait(text="Locked or expired"); device.cancel_authentication()
            if device.find(text="Fill synthetic login once") is not None: raise Failed("cached_plaintext_dataset_visible")
            device.empty()
            return {"target": GOOD, "same_fixture_wms_identity_after_success": True,
                    "autofill_internal_session_id_observed": False, "refocus": refocus,
                    "plaintext_dataset_menu_observed": False, "locked_placeholder_attempted": locked_placeholder_attempted,
                    "authentication_reappeared": authentication_reappeared, "fixture_values": "Empty fields",
                    "successful_control": "actual_system_fill_and_login"}
        case("system_cached_plaintext_not_reusable", cached)
        def explicit_lock():
            authentication_started = time.monotonic(); device.authentication()
            unlock_started = time.monotonic(); device.unlock(master)
            device.tap(text="Lock"); device.tap(text="Fill once")
            observed = device.authorization_status("Locked or expired", device.wait(text="Locked or expired"))
            elapsed = time.monotonic() - unlock_started; request_elapsed = time.monotonic() - authentication_started
            if elapsed >= 18 or request_elapsed >= 100: raise Failed("explicit_lock_check_could_be_expiry")
            device.cancel_authentication()
            return {"authorization": observed, "target": GOOD, "successful_unlock_before_lock": True, "rejection_from_before_unlock_ms": round(elapsed * 1000), "request_elapsed_ms": round(request_elapsed * 1000), "fixture_values": "Empty fields"}
        case("explicit_lock_refused", explicit_lock)
        def expired():
            device.authentication(); device.unlock(master); observed_unlocked = time.monotonic(); time.sleep(21)
            device.tap(text="Fill once")
            observed = device.authorization_status("Locked or expired", device.wait(text="Locked or expired")); elapsed = time.monotonic() - observed_unlocked
            device.cancel_authentication()
            return {"authorization": observed, "target": GOOD, "successful_unlock_before_expiry": True, "elapsed_after_observed_unlock_ms": round(elapsed * 1000), "fixture_values": "Empty fields"}
        case("expired_authorization_refused", expired)
        def cancelled():
            authentication_started = time.monotonic(); device.authentication()
            observation_id = device.authorization_observation()
            unlock_started = time.monotonic(); device.unlock(master)
            timing = device.cancel_authentication(authentication_started, unlock_started)
            cancellation_decision = device.decision()
            cancellation_observation = device.cancellation_observation(observation_id)
            device.authentication(); device.tap(text="Fill once")
            observed = device.authorization_status("Locked or expired", device.wait(text="Locked or expired")); device.cancel_authentication()
            return {"provider_decision_before_next_request": cancellation_decision, "cancellation_observation": cancellation_observation,
                    "new_authorization": observed, "target": GOOD, "successful_unlock_before_cancel": True, "timing": timing, "fixture_values": "Empty fields"}
        case("cancelled_authorization_refused", cancelled)
        def background():
            authentication_started = time.monotonic()
            device.authentication(); task = device.auth_task()
            unlocked_at = time.monotonic()
            device.unlock(master)
            device.shell("input", "keyevent", "KEYCODE_HOME")
            device.shell("am", "task", "focus", str(task))
            device.wait(text="HeptaBao · local authorization")
            if device.auth_task() != task: raise Failed("authorization_task_changed")
            device.tap(text="Fill once")
            observed = device.authorization_status("Authorization rejected", device.wait(text="Authorization rejected"))
            if time.monotonic() - unlocked_at >= 18 or time.monotonic() - authentication_started >= 100: raise Failed("background_check_could_be_expiry")
            rejection_ms = round((time.monotonic() - unlocked_at) * 1000)
            request_elapsed_ms = round((time.monotonic() - authentication_started) * 1000)
            device.cancel_authentication()
            return {"authorization": observed, "target": GOOD, "same_authentication_task": True, "successful_unlock_before_home": True, "rejection_from_before_unlock_ms": rejection_ms, "request_elapsed_ms": request_elapsed_ms, "fixture_values": "Empty fields"}
        case("background_authorization_refused", background)
        def restarted():
            device.shell("am", "force-stop", "--user", "0", PROVIDER)
            device.shell("am", "start", "--user", "0", "--display", "0", "-W", "-n", PROVIDER + "/org.heptabao.preview.MainActivity")
            node = device.wait(description="Provider status")
            if "Encrypted vault imported; locked" not in node.get("text", ""): raise Failed("restart_ciphertext_missing")
            device.authentication(); device.tap(text="Fill once"); device.wait(text="Locked or expired"); device.cancel_authentication()
            control = login()
            return {"ciphertext_retained": True, "initial_restart_authorization": "Locked or expired", "fresh_unlock_and_fill": control}
        case("independent_process_restart_locked_and_recovered", restarted)
        def rejected_package():
            baseline = device.decision(True)
            device.fixture(DECOY); device.tap(text="Request Autofill"); time.sleep(1); device.empty()
            observed = device.decision()
            if observed != "wrong_package": raise Failed("wrong_package_cause_not_observed")
            return {"provider_baseline_before_request": baseline, "provider_decision": observed, "target": DECOY, "target_apk_sha256": build["artifacts"]["fixture-wrong-package"]["sha256"], "same_certificate_as_accepted_target": True, "fixture_values": "Empty fields"}
        case("wrong_package_same_certificate_refused", rejected_package)
        def rejected_certificate():
            if device.package_hash(GOOD) != build["artifacts"]["fixture-good"]["sha256"]: raise Failed("fixture_ownership_changed")
            device.adb_command("uninstall", GOOD, timeout=60)
            install("fixture-wrong-certificate")
            baseline = device.decision(True)
            device.fixture(); device.tap(text="Request Autofill"); time.sleep(1); device.empty()
            observed = device.decision()
            if observed != "wrong_certificate": raise Failed("wrong_certificate_cause_not_observed")
            return {"provider_baseline_before_request": baseline, "provider_decision": observed, "target": GOOD, "target_apk_sha256": build["artifacts"]["fixture-wrong-certificate"]["sha256"], "different_certificate_from_accepted_target": True, "fixture_values": "Empty fields"}
        case("same_package_wrong_certificate_refused", rejected_certificate)
    except Failed as error:
        failure = str(error)
        report["failure_context"] = {"expected_control": device.last_wait, "public_ui": device.last_public_ui,
                                     "focus_metadata": getattr(device, "last_focus_metadata", None),
                                     "fixture_return_phase": device.return_phase}
        try:
            if device.package_hash(PROVIDER) == build["artifacts"]["provider"]["sha256"]:
                report["failure_context"]["authorization_diagnostic_before_diagnostic_activity"] = device.authorization_diagnostic()
                report["failure_context"]["provider_events_before_diagnostic_activity"] = device.provider_events()
                report["failure_context"]["provider_decision"] = device.decision()
                report["failure_context"]["provider_decision_observation"] = "after_launching_MainActivity_may_change_lifecycle_not_original_state_proof"
        except Failed:
            report["failure_context"]["provider_decision"] = "unavailable"
    except Exception:
        failure = "unexpected_driver_failure"
    finally:
        # No raw exception, argv, serial, hierarchy, or secret is printed, including failures.
        try:
            restored, cleanup = restore(device, journal, journal_path)
            report["restoration"] = restored; report["package_cleanup"] = cleanup
            if any(value == "unknown_artifact_preserved" for value in cleanup.values()): failure = failure or "cleanup_external_change_preserved"
        except Exception:
            report["restoration"] = "verification_required"
            failure = failure or "restoration_failed"
        report["missing_cases"] = [name for name in EXPECTED_CASES if not any(row["name"] == name for row in report["cases"])]
        if report["missing_cases"]: failure = failure or "incomplete_case_inventory"
        report["finished_unix_ns"] = time.time_ns(); report["passed"] = failure is None
        report["interaction_diagnostics"] = {"scope": "public_geometry_and_package_scoped_pending_intent_metadata", "causal_case_proof": False, "pending_intent_absence_does_not_distinguish_cancel_from_one_shot_send": True, "events": device.tap_diagnostics}
        report["fixture_return_diagnostics"] = {"scope": "bound_popup_single_back_and_same_wms_window_record_task_owner", "autofill_internal_session_id_observed": False, "causal_case_proof": False, "events": device.return_diagnostics}
        report["error"] = failure; report["checks_passed"] = len(report["cases"])
        atomic_json(args.output / "report.json", report)
    print(json.dumps({"ok": report["passed"], "checks_passed": report["checks_passed"], "error": failure, "restoration": report["restoration"], "report": str(args.output / "report.json"), "report_sha256": sha((args.output / "report.json").read_bytes())}, sort_keys=True), flush=True)
    if failure: raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except Failed as error:
        print(json.dumps({"ok": False, "error": str(error)}), flush=True)
        raise SystemExit(1)
