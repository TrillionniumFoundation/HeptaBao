#!/usr/bin/env python3
"""Phased actual-device helper for the explicitly authorized synthetic Passkey QA.

Never run concurrently with another phone UI task. Each invocation performs one
reviewable phase; no phase silently reports the entire qualification as passed.
Only our fresh packages and explicitly selected synthetic documents are changed.
The master enters the real password EditText; the provider has no QA unlock path.
The synthetic-only adb/input child argv exception is explicit in every journal.
"""
import argparse
import hashlib
import atexit
import fcntl
import itertools
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import stat
import time
import urllib.request
import xml.etree.ElementTree as ET

DEVICE_SHA256 = "41ad305f8562a6c47710afe71fabf30cb8692a71d3de1a47ca9949b669bcc6c1"
PROVIDER = "org.heptabao.passkey.preview"
FIXTURE = "org.heptabao.passkey.fixture"
DECOY = "org.heptabao.passkey.decoy"
SERVICE = PROVIDER + "/" + PROVIDER + ".ProviderService"
OWNED = {PROVIDER, FIXTURE, DECOY}
SYSTEM_UI = {"android", "com.android.settings", "com.google.android.documentsui", "com.android.documentsui",
             "com.google.android.credentialmanager", "com.android.credentialmanager", "com.google.android.gms"}
SETTING_KEYS = ("credential_service", "credential_service_primary", "autofill_service")
SAFE_SYSTEM_WORDS = {"recent", "downloads", "documents", "internal storage", "internal shared storage", "images", "audio", "videos",
    "save", "open", "cancel", "select", "search", "show roots", "navigate up", "more options", "view options", "new folder", "done", "back",
    "passwords, passkeys & accounts", "passwords, passkeys and accounts", "preferred service", "additional services", "use service", "turn on",
    "turn off", "allow", "ok", "continue", "create", "create a passkey", "use a passkey", "passkeys", "passwords", "manage passwords",
    "save to", "sign in", "use another device", "more options", "motorola", "xt2551-3", "heptabao synthetic vault", "synthetic-user"}
SAFE_SYNTHETIC_LABELS = {"heptabao passkey preview", "heptabao synthetic passkeys", "heptabao synthetic vault",
    "heptabao fixture-good", "heptabao fixture-wrong-package", "heptabao-passkey-qa-20261106-r4",
    "heptabao-passkey-qa-r4-seed.hbv", "heptabao-passkey-qa-r4-corrupt.hbv", "heptabao-passkey-backup.hbv"}


class Failed(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failed(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, value):
    temporary = path.with_name(path.name + ".pending-" + secrets.token_hex(8))
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def private_directory(path):
    require(path.is_absolute() and str(path) == str(path.resolve()), "unsafe_driver_root")
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, "unsafe_driver_root")


def private_file(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1 and info.st_size <= maximum, "unsafe_driver_file")
        with os.fdopen(fd, "rb", closefd=False) as stream: raw = stream.read(maximum + 1)
        require(len(raw) <= maximum, "driver_file_too_large"); return raw
    finally: os.close(fd)


def valid_setting(value):
    return type(value) is str and (value in ("null", "") or re.fullmatch(
        r"[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+(?::[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+)*", value) is not None)


def validate_journal(journal, build, expected_digest):
    required = {"schema", "device_sha256", "build_receipt_sha256", "started_unix_ns", "original_settings", "owned_settings",
        "settings_intent", "owned_packages", "initial_packages_absent", "install_intents", "reverse_owned", "phases", "credential_entry", "production_qualified",
        "credential_manager_exercised", "p4_qualified"}
    require(type(journal) is dict and required <= set(journal) <= required | {"restoration"}, "invalid_journal_schema")
    require(type(journal["schema"]) is int and journal["schema"] == 1 and journal["device_sha256"] == DEVICE_SHA256 and journal["build_receipt_sha256"] == expected_digest,
            "journal_binding_changed")
    for name in ("original_settings", "owned_settings"):
        values = journal[name]
        require(type(values) is dict and (set(values) == set(SETTING_KEYS) or name == "owned_settings" and not values)
                and all(valid_setting(v) for v in values.values()), "invalid_journal_settings")
    require(type(journal["owned_packages"]) is dict and set(journal["owned_packages"]) <= OWNED, "invalid_journal_packages")
    allowed = {package: {v["sha256"] for v in build["artifacts"].values() if v["package"] == package} for package in OWNED}
    require(type(journal["initial_packages_absent"]) is dict and set(journal["initial_packages_absent"]) == OWNED
            and all(value is True for value in journal["initial_packages_absent"].values()), "missing_initial_package_absence")
    intents = journal["install_intents"]
    require(type(intents) is list and len(intents) <= 64, "invalid_install_intents")
    for entry in intents:
        require(type(entry) is dict and set(entry) == {"variant", "package", "sha256", "attempted_unix_ns"}
                and type(entry["variant"]) is str and entry["variant"] in build["artifacts"]
                and entry["package"] == build["artifacts"][entry["variant"]]["package"]
                and entry["sha256"] == build["artifacts"][entry["variant"]]["sha256"]
                and type(entry["attempted_unix_ns"]) is int and entry["attempted_unix_ns"] > 0, "invalid_install_intents")
    for package, values in journal["owned_packages"].items():
        require(type(values) is list and 0 < len(values) <= 16
                and all(type(v) is str and re.fullmatch(r"[0-9a-f]{64}", v) is not None for v in values)
                and set(values) <= allowed[package]
                and all(any(v == e["sha256"] and package == e["package"] for e in intents) for v in values), "invalid_journal_packages")
    require(type(journal["reverse_owned"]) is bool and type(journal["phases"]) is list and len(journal["phases"]) < 4096
            and journal["production_qualified"] is False and journal["p4_qualified"] is False
            and journal["credential_entry"] == "synthetic_only_adb_input_text_argv", "invalid_journal_state")
    intent = journal["settings_intent"]
    if intent is not None:
        require(type(intent) is dict and set(intent) == {"kind", "before", "allowed_after", "armed_unix_ns"}
                and intent["kind"] in ("enable_additional_provider", "select_primary_from_empty"), "invalid_settings_intent")
        require(type(intent["before"]) is dict and set(intent["before"]) == set(SETTING_KEYS)
                and all(valid_setting(v) for v in intent["before"].values()), "invalid_settings_intent")
        require(type(intent["allowed_after"]) is dict and set(intent["allowed_after"]) == set(SETTING_KEYS), "invalid_settings_intent")
        for values in intent["allowed_after"].values():
            require(type(values) is list and 0 < len(values) <= 1440 and all(valid_setting(v) for v in values), "invalid_settings_intent")
        require(intent["before"] == journal["original_settings"], "invalid_settings_intent")
        if intent["kind"] == "select_primary_from_empty":
            components = {SERVICE, PROVIDER + "/.ProviderService"}
            require(intent["before"]["credential_service"] in ("null", "")
                    and intent["before"]["credential_service_primary"] in ("null", "")
                    and set(intent["allowed_after"]["credential_service"]) == components
                    and set(intent["allowed_after"]["credential_service_primary"]) == components
                    and intent["allowed_after"]["autofill_service"] == [intent["before"]["autofill_service"]], "invalid_settings_intent")


class Device:
    def __init__(self, adb):
        self.adb = str(adb)
        result = self.command([self.adb, "devices"], 15)
        devices = [row.split()[0] for row in result.stdout.decode().splitlines()[1:] if len(row.split()) == 2 and row.split()[1] == "device"]
        require(len(devices) == 1 and sha(devices[0].encode()) == DEVICE_SHA256, "authorized_device_not_unique")
        self.serial = devices[0]

    @staticmethod
    def command(argv, timeout=30, allow_failure=False):
        try: result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired): raise Failed("device_command_unknown_outcome") from None
        require(allow_failure or result.returncode == 0, "device_command_failed")
        return result

    def adb_call(self, *args, timeout=30, allow_failure=False):
        return self.command([self.adb, "-s", self.serial, *map(str, args)], timeout, allow_failure)

    def shell(self, *args, timeout=30, allow_failure=False):
        result = self.adb_call("shell", " ".join(shlex.quote(str(x)) for x in args), timeout=timeout, allow_failure=allow_failure)
        return result.stdout.decode("utf-8", "replace").strip()

    def setting(self, key):
        require(key in SETTING_KEYS, "invalid_setting")
        value = self.shell("settings", "--user", "0", "get", "secure", key)
        require(valid_setting(value), "unexpected_setting")
        return value

    def package_hash(self, package):
        require(package in OWNED, "package_out_of_scope")
        # Empty output proves absence only after a successful, strictly parsed
        # presence query. A failed pm path (including code 1 + empty stdout)
        # must never grant installation/uninstallation ownership.
        listing = self.adb_call("shell", "pm list packages -u --user 0 " + shlex.quote(package))
        require(not listing.stderr.strip(), "package_presence_query_unconfirmed")
        rows = listing.stdout.decode("utf-8", "strict").splitlines()
        require(all(re.fullmatch(r"package:[A-Za-z0-9_.$]+", row) for row in rows), "package_presence_query_unconfirmed")
        if "package:" + package not in rows: return None
        paths = self.shell("pm", "path", "--user", "0", package).splitlines()
        require(len(paths) == 1 and paths[0].startswith("package:/data/app/"), "unexpected_package_layout")
        value = self.shell("sha256sum", paths[0][8:]).split()[0]
        require(re.fullmatch(r"[0-9a-f]{64}", value), "installed_digest_unavailable")
        return value

    def foreground(self):
        # Android 16's 'windows' subcommand can omit mCurrentFocus. Inspect the
        # complete display-0 section and require that display to be top-focused.
        raw = self.shell("dumpsys", "window")
        top = re.search(r"mTopFocusedDisplayId=(\d+)", raw)
        require(top is not None and top.group(1) == "0", "top_focused_display_not_zero")
        sections = list(re.finditer(r"Display: mDisplayId=(\d+)|DisplayContent\{[^\n]*?displayId=(\d+)", raw))
        candidates = []
        for index, section in enumerate(sections):
            display = section.group(1) or section.group(2)
            if display != "0": continue
            end = sections[index + 1].start() if index + 1 < len(sections) else len(raw)
            candidates.extend(re.findall(r"mCurrentFocus=Window\{[^\n]*? ([A-Za-z0-9_.$]+)/([A-Za-z0-9_.$]+)\}", raw[section.start():end]))
        if not candidates:
            # One global current-focus line is unambiguous only when display 0
            # is explicitly the top-focused display and no other focus exists.
            candidates = re.findall(r"mCurrentFocus=Window\{[^\n]*? ([A-Za-z0-9_.$]+)/([A-Za-z0-9_.$]+)\}", raw)
        candidates = set(candidates)
        require(len(candidates) == 1, "focused_window_unavailable")
        package, activity = candidates.pop()
        require(package in OWNED | SYSTEM_UI, "unexpected_foreground_no_ui_read")
        return package, activity

    def ui(self):
        before = self.foreground()
        result = self.adb_call("exec-out", "uiautomator", "dump", "--compressed", "/dev/tty", timeout=25)
        raw = result.stdout; start = raw.find(b"<hierarchy"); end = raw.find(b"</hierarchy>")
        require(start >= 0 and end > start, "ui_hierarchy_unavailable")
        try: nodes = list(ET.fromstring(raw[start:end + len(b"</hierarchy>")]).iter("node"))
        except ET.ParseError: raise Failed("ui_hierarchy_invalid") from None
        require(self.foreground() == before, "foreground_changed_during_ui_read")
        return before, nodes

    def tap(self, kind, value):
        foreground, nodes = self.ui()
        attr = {"text": "text", "description": "content-desc", "id": "resource-id"}[kind]
        candidates = [node for node in nodes if node.get(attr) == value and node.get("enabled") == "true"]
        require(len(candidates) == 1, "ui_target_not_unique")
        self.tap_node(candidates[0], foreground)

    def tap_node(self, node, foreground):
        bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
        require(bounds is not None and self.foreground() == foreground, "ui_target_changed")
        left, top, right, bottom = map(int, bounds.groups()); require(right > left and bottom > top, "invalid_ui_bounds")
        self.shell("input", "-d", "0", "tap", (left + right) // 2, (top + bottom) // 2)

    def input_master(self, path, wrong=False):
        foreground, nodes = self.ui()
        require(foreground in {(PROVIDER, PROVIDER + ".HomeActivity"), (PROVIDER, PROVIDER + ".OperationActivity")}, "password_activity_changed")
        fields = [n for n in nodes if n.get("package") == PROVIDER and n.get("password") == "true" and n.get("class") == "android.widget.EditText"]
        require(len(fields) == 1 and not fields[0].get("text"), "password_field_not_empty")
        self.tap_node(fields[0], foreground)
        current, focused = self.ui()
        require(current == foreground and any(n.get("package") == PROVIDER and n.get("password") == "true" and n.get("focused") == "true" for n in focused), "password_focus_changed")
        master_bytes = private_file(path, 64)
        master = secrets.token_urlsafe(24) if wrong else master_bytes.decode("ascii", "strict")
        del master_bytes
        require(re.fullmatch(r"[A-Za-z0-9_-]{32}", master), "unexpected_synthetic_master")
        # Explicitly authorized synthetic QA exception: adb/input child argv
        # briefly contains this synthetic value. No process receipt prints it.
        self.shell("input", "-d", "0", "text", master)
        del master
        require(self.foreground() == foreground, "password_target_changed_after_input")

    def public_ui(self):
        foreground, nodes = self.ui(); output = []
        for node in nodes:
            package = node.get("package", ""); text = node.get("text", ""); description = node.get("content-desc", "")
            if node.get("password") == "true" or node.get("class") == "android.widget.EditText":
                text = "[input omitted]"
            elif package not in OWNED and text.casefold() not in SAFE_SYSTEM_WORDS | SAFE_SYNTHETIC_LABELS:
                text = "[other label]" if text else ""
            if package not in OWNED and description.casefold() not in SAFE_SYSTEM_WORDS | SAFE_SYNTHETIC_LABELS:
                description = "[other description]" if description else ""
            if text or description or node.get("clickable") == "true":
                output.append({"package": package if package in OWNED | SYSTEM_UI else "[other package]", "class": node.get("class"),
                    "text": text, "description": description, "resource_id": node.get("resource-id"), "bounds": node.get("bounds"),
                    "clickable": node.get("clickable"), "enabled": node.get("enabled"), "focused": node.get("focused")})
        return {"foreground": foreground, "nodes": output}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--expected-build-sha256", required=True)
    parser.add_argument("--phase", required=True, choices=("preflight", "install", "inspect", "launch-provider", "launch-fixture", "launch-decoy",
        "tap", "input-master", "back", "hide-keyboard", "settings-arm", "settings-arm-primary-empty", "settings-selected", "kill-provider", "kill-fixture", "reverse", "rp-state", "wrong-certificate", "good-certificate", "restore"))
    parser.add_argument("--selector-kind", choices=("text", "description", "id"), default="text")
    parser.add_argument("--selector")
    parser.add_argument("--master-file", type=Path)
    parser.add_argument("--wrong", action="store_true")
    args = parser.parse_args(); os.umask(0o077)
    root, artifacts = args.root.absolute(), args.artifacts.absolute(); receipt_path = artifacts / "build.receipt.json"
    private_directory(root.parent); private_directory(artifacts)
    require(sha(receipt_path.read_bytes()) == args.expected_build_sha256, "build_receipt_changed")
    build = json.loads(receipt_path.read_text()); device = Device(args.adb)
    journal_path = root / "journal.private.json"
    if args.phase == "preflight":
        root.mkdir(mode=0o700, exist_ok=False)
        parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(parent)
        finally: os.close(parent)
    private_directory(root)
    lock = os.open(root / "driver.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(lock)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1, "unsafe_driver_lock")
    try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: raise Failed("driver_phase_already_running") from None
    atexit.register(os.close, lock)
    if args.phase == "preflight":
        require(all(device.package_hash(package) is None for package in OWNED), "package_preexists_not_owned")
        require(device.shell("getprop", "ro.product.model") == "XT2551-3" and device.shell("getprop", "ro.build.version.sdk") == "36", "device_combination_changed")
        journal = {"schema": 1, "device_sha256": DEVICE_SHA256, "build_receipt_sha256": args.expected_build_sha256,
            "started_unix_ns": time.time_ns(), "original_settings": {key: device.setting(key) for key in SETTING_KEYS},
            "owned_settings": {}, "settings_intent": None, "owned_packages": {}, "initial_packages_absent": {p: True for p in sorted(OWNED)},
            "install_intents": [], "reverse_owned": False, "phases": [],
            "credential_entry": "synthetic_only_adb_input_text_argv", "production_qualified": False,
            "credential_manager_exercised": False, "p4_qualified": False}
        atomic(journal_path, journal)
    else:
        journal = json.loads(private_file(journal_path, 8 * 1024 * 1024))
    validate_journal(journal, build, args.expected_build_sha256)
    result = {"ok": True, "phase": args.phase}

    def install(variant):
        artifact = build["artifacts"][variant]; package = artifact["package"]; path = artifacts / "apks" / (variant + ".apk")
        require(package in OWNED and sha(path.read_bytes()) == artifact["sha256"], "apk_changed")
        require(device.package_hash(package) is None, "refuse_existing_package")
        journal["owned_packages"].setdefault(package, []).append(artifact["sha256"])
        journal["install_intents"].append({"variant": variant, "package": package, "sha256": artifact["sha256"], "attempted_unix_ns": time.time_ns()})
        atomic(journal_path, journal)  # Record the attempted side effect before ADB.
        output = device.adb_call("install", "--user", "0", path, timeout=90).stdout
        require(b"Success" in output and device.package_hash(package) == artifact["sha256"], "install_unconfirmed")

    def remove(package):
        current = device.package_hash(package)
        if current is None: return
        require(current in journal["owned_packages"].get(package, []), "unknown_package_preserved")
        device.adb_call("uninstall", package, timeout=60)
        require(device.package_hash(package) is None, "package_removal_unconfirmed")

    if args.phase == "install":
        for variant in ("provider", "fixture-good", "fixture-wrong-package"): install(variant)
        result["installed_sha256"] = {p: device.package_hash(p) for p in sorted(OWNED)}
    elif args.phase.startswith("launch-"):
        package, activity = {"launch-provider": (PROVIDER, PROVIDER + ".HomeActivity"),
            "launch-fixture": (FIXTURE, FIXTURE + ".FixtureActivity"), "launch-decoy": (DECOY, FIXTURE + ".FixtureActivity")}[args.phase]
        require(device.package_hash(package) in journal["owned_packages"].get(package, []), "unowned_package")
        # Only explicit case initialization clears an owned task. Cancellation /
        # background / cache cases use back or ordinary task transitions instead.
        raw = device.shell("am", "start", "--user", "0", "-W", "-f", "0x10008000", "-n", package + "/" + activity)
        require("Status: ok" in raw and ("Activity: " + package + "/") in raw, "activity_launch_unconfirmed")
        result["activity"] = package + "/" + activity
    elif args.phase == "inspect": result.update(device.public_ui())
    elif args.phase == "tap":
        require(args.selector is not None and len(args.selector) <= 256, "selector_missing")
        if device.foreground()[0] in SYSTEM_UI:
            require(journal["settings_intent"] is not None, "arm_exact_settings_intent_before_ui_tap")
            for key in SETTING_KEYS:
                value = device.setting(key); intent = journal["settings_intent"]
                require(value == intent["before"][key] or value in intent["allowed_after"][key], "external_settings_change_preserved")
        device.tap(args.selector_kind, args.selector); result["selector"] = args.selector
    elif args.phase == "input-master":
        require(args.master_file is not None and str(args.master_file.resolve()).startswith(str(artifacts.parent / "private") + "/"), "master_outside_private_root")
        device.input_master(args.master_file, args.wrong); result["synthetic_wrong_password"] = args.wrong
    elif args.phase == "back":
        device.foreground(); device.shell("input", "-d", "0", "keyevent", "KEYCODE_BACK")
    elif args.phase == "hide-keyboard":
        require(device.foreground()[0] == PROVIDER, "keyboard_target_changed")
        raw = device.shell("dumpsys", "input_method")
        shown = bool(re.search(r"mInputShown=true|mIsInputViewShown=true", raw))
        if shown: device.shell("input", "-d", "0", "keyevent", "KEYCODE_BACK")
        result["keyboard_was_shown"] = shown
    elif args.phase == "settings-arm":
        require(journal["settings_intent"] is None, "settings_intent_already_armed")
        before = {key: device.setting(key) for key in SETTING_KEYS}
        require(before == journal["original_settings"], "settings_changed_before_arming")
        old = [] if before["credential_service"] in ("null", "") else before["credential_service"].split(":")
        require(len(old) <= 5 and all(v.split("/")[0] != PROVIDER for v in old), "unexpected_existing_provider_set")
        exact_values = set()
        # The platform serializes a set. Persist every exact ordering of only the
        # previously observed entries plus our one additional provider. No other
        # setting target or service is authorized by this action.
        for component in (SERVICE, PROVIDER + "/.ProviderService"):
            exact_values.update(":".join(order) for order in itertools.permutations(old + [component]))
        allowed = {key: [before[key]] for key in SETTING_KEYS}
        allowed["credential_service"] = sorted(exact_values)
        if before["credential_service_primary"] == "null": allowed["credential_service_primary"].append("")
        journal["settings_intent"] = {"kind": "enable_additional_provider", "before": before,
            "allowed_after": allowed, "armed_unix_ns": time.time_ns()}
        atomic(journal_path, journal); result["exact_enabled_values_count"] = len(exact_values)
    elif args.phase == "settings-arm-primary-empty":
        # This OEM exposes only a preferred-provider picker when no provider is
        # enabled. Re-arm before selecting anything, while all settings are
        # still exactly the initial values. Never replace an existing default.
        before = {key: device.setting(key) for key in SETTING_KEYS}
        require(before == journal["original_settings"]
                and before["credential_service"] in ("null", "")
                and before["credential_service_primary"] in ("null", "")
                and not journal["owned_settings"], "refuse_existing_primary_or_changed_settings")
        require(journal["settings_intent"] is None or journal["settings_intent"]["kind"] == "enable_additional_provider", "settings_intent_already_armed")
        components = sorted({SERVICE, PROVIDER + "/.ProviderService"})
        journal["settings_intent"] = {"kind": "select_primary_from_empty", "before": before,
            "allowed_after": {"credential_service": components, "credential_service_primary": components,
                "autofill_service": [before["autofill_service"]]}, "armed_unix_ns": time.time_ns()}
        validate_journal(journal, build, args.expected_build_sha256)
        atomic(journal_path, journal); result["prior_primary_empty"] = True
    elif args.phase == "settings-selected":
        current = {key: device.setting(key) for key in SETTING_KEYS}
        intent = journal["settings_intent"]; require(intent is not None, "settings_intent_missing")
        require(all(current[key] in intent["allowed_after"][key] for key in SETTING_KEYS), "unexpected_setting_outcome_preserved")
        journal["owned_settings"] = current
        result["provider_enabled"] = True
        result["settings_sha256"] = {key: sha(value.encode()) for key, value in current.items()}
    elif args.phase in ("kill-provider", "kill-fixture"):
        package = PROVIDER if args.phase == "kill-provider" else FIXTURE
        require(device.package_hash(package) in journal["owned_packages"].get(package, []), "unowned_package")
        previous = device.shell("pidof", package, allow_failure=True)
        device.shell("am", "force-stop", "--user", "0", package)
        require(not device.shell("pidof", package, allow_failure=True), "owned_process_not_stopped")
        result["previous_pid_sha256"] = sha(previous.encode())
    elif args.phase == "reverse":
        rows = device.adb_call("reverse", "--list").stdout.decode().splitlines()
        require(not any("tcp:38491" in row for row in rows), "reverse_mapping_preexists")
        journal["reverse_owned"] = True; atomic(journal_path, journal)
        device.adb_call("reverse", "tcp:38491", "tcp:38491")
        require(any(row.split()[-2:] == ["tcp:38491", "tcp:38491"] for row in device.adb_call("reverse", "--list").stdout.decode().splitlines()), "reverse_unconfirmed")
    elif args.phase == "rp-state":
        with urllib.request.urlopen("http://127.0.0.1:38491/state", timeout=5) as response:
            require(response.status == 200, "rp_state_unavailable"); result["rp"] = json.load(response)
    elif args.phase in ("wrong-certificate", "good-certificate"):
        remove(FIXTURE); install("fixture-wrong-cert" if args.phase == "wrong-certificate" else "fixture-good")
        result["installed_sha256"] = device.package_hash(FIXTURE)
    elif args.phase == "restore":
        settings = {}
        for key in SETTING_KEYS:
            current, original = device.setting(key), journal["original_settings"][key]
            if current == original: settings[key] = "already_original"
            elif current == journal["owned_settings"].get(key) or (journal["settings_intent"] is not None
                    and current in journal["settings_intent"]["allowed_after"][key]):
                if original == "null": device.shell("settings", "--user", "0", "delete", "secure", key)
                else: device.shell("settings", "--user", "0", "put", "secure", key, original)
                require(device.setting(key) == original, "setting_restore_unconfirmed"); settings[key] = "restored_original"
            else: settings[key] = "external_change_preserved"
        reverse = "not_owned"
        if journal["reverse_owned"]:
            mappings = device.adb_call("reverse", "--list").stdout.decode().splitlines()
            owned = [row.split()[-2:] for row in mappings if len(row.split()) >= 2 and row.split()[-2] == "tcp:38491"]
            if owned == [["tcp:38491", "tcp:38491"]]:
                device.adb_call("reverse", "--remove", "tcp:38491")
                after = device.adb_call("reverse", "--list").stdout.decode().splitlines()
                require(not any(len(row.split()) >= 2 and row.split()[-2] == "tcp:38491" for row in after), "reverse_restore_unconfirmed")
                reverse = "removed_and_absence_verified"
            elif not owned: reverse = "already_absent_verified"
            else: reverse = "external_change_preserved"
        for package in sorted(OWNED): remove(package)
        journal["restoration"] = settings; result["restoration"] = settings; result["packages_removed"] = sorted(OWNED)
        result["reverse_restoration"] = reverse
    journal["phases"].append({"phase": args.phase, "completed_unix_ns": time.time_ns(), "result": result})
    atomic(journal_path, journal)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try: main()
    except Failed as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True)); raise SystemExit(1)
