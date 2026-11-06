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


class Failed(Exception):
    pass


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
        self.expected_fixture = None
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
        raw = self.shell("dumpsys", "window")
        if not re.search(r"(?m)^\s*mTopFocusedDisplayId=0\s*$", raw):
            return None
        current_display = None
        default_display = []
        for line in raw.splitlines():
            marker = re.match(r"^\s*Display: mDisplayId=([0-9]+)\b", line)
            if marker: current_display = int(marker.group(1))
            if current_display == 0: default_display.append(line)
        matches = re.findall(r"mCurrentFocus=Window\{[^\n]*? ([A-Za-z0-9_.$]+)/([A-Za-z0-9_.$]+)\}", "\n".join(default_display))
        if len(matches) != 1:
            return None
        return matches[0]

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
        raw = self.adb_command("exec-out", "uiautomator", "dump", "--compressed", "/dev/tty", timeout=20)
        start, end = raw.find(b"<hierarchy"), raw.find(b"</hierarchy>")
        if start < 0 or end < start:
            raise Failed("ui_hierarchy_unavailable")
        try:
            nodes = list(ET.fromstring(raw[start:end + len(b"</hierarchy>")]).iter("node"))
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
        node = self.wait(text, description)
        match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
        if not match or node.get("enabled") != "true":
            raise Failed("ui_target_unavailable")
        left, top, right, bottom = map(int, match.groups())
        if right <= left or bottom <= top:
            raise Failed("ui_target_bounds_invalid")
        self.shell("input", "tap", str((left + right) // 2), str((top + bottom) // 2))

    def fixture(self, package=GOOD):
        if package not in {GOOD, DECOY}: raise Failed("fixture_out_of_scope")
        self.shell("am", "force-stop", "--user", "0", package)
        launched = self.shell("am", "start", "--user", "0", "--display", "0", "-W", "-f", "0x10008000", "-n", package + "/" + ACTIVITY)
        if "Status: ok" not in launched or ("Activity: " + package + "/" + ACTIVITY) not in launched:
            raise Failed("fixture_activity_not_started")
        self.expected_fixture = package
        self.assert_fixture(self.wait(text="HeptaBao synthetic native login"))

    def assert_fixture(self, node=None):
        component = self.foreground()
        if self.expected_fixture not in {GOOD, DECOY} or component != (self.expected_fixture, ACTIVITY):
            raise Failed("fixture_activity_changed")
        if node is not None and node.get("package") != self.expected_fixture:
            raise Failed("fixture_node_package_changed")
        return component

    def empty(self):
        self.verify("Empty fields")

    def verify(self, expected):
        # Dismiss a suggestion overlay; require an incremented counter, not a stale status label.
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
        self.fixture()
        self.tap(text="Request Autofill")
        self.tap(text="Unlock HeptaBao locally")
        self.wait(text="HeptaBao · local authorization")
        self.wait(text="Locked")

    def authorization_status(self, expected, node=None):
        if node is None: node = self.wait(description="Authorization status")
        component = self.foreground()
        if component != (PROVIDER, "org.heptabao.preview.AuthActivity") or node.get("package") != PROVIDER or node.get("content-desc") != "Authorization status" or node.get("text") != expected:
            raise Failed("authorization_status_not_observed")
        return {"activity": list(component), "status": expected}

    def provider_events(self):
        # Read only this process's dedicated static-code tag. This is diagnostic
        # context, not a case assertion: the process buffer may include old cases.
        pid = self.shell("pidof", PROVIDER, allow_failure=True)
        if not re.fullmatch(r"[0-9]+", pid): return {"available": False}
        raw = self.shell("logcat", "-d", "-b", "main", "-v", "raw", "--pid=" + pid,
                         "HeptaBaoPreview:I", "*:S")
        allowed = {"ui_hidden_notification", "memory_pressure_locked", "auth_context_bound"}
        rejection_codes = {"request_expired", "wrong_result_recipient", "request_changed", "wrong_package", "wrong_certificate", "missing_structure", "wrong_activity", "unsupported_windows", "structure_too_large", "webview_unsupported", "wrong_fields"}
        allowed.update("auth_rejected_" + code for code in rejection_codes)
        events = [line.strip() for line in raw.splitlines() if line.strip() in allowed]
        return {"available": True, "scope": "current_provider_process_buffer_diagnostic_only", "codes": events[-64:]}

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
        self.assert_fixture(self.wait(text="HeptaBao synthetic native login"))
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
        print(json.dumps({"case": name, "state": "running"}), flush=True)
        started = time.monotonic(); evidence = action()
        if not isinstance(evidence, dict): raise Failed("case_evidence_missing")
        report["cases"].append({"name": name, "passed": True, "elapsed_ms": round((time.monotonic() - started) * 1000), "evidence": evidence})
        report["current_case"] = None
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
            device.wait(text="HeptaBao synthetic native login"); device.verify("Synthetic login accepted")
            actual = device.assert_fixture()
            if actual != (GOOD, ACTIVITY): raise Failed("accepted_fixture_target_changed")
            return {"target": GOOD, "actual_activity": list(actual), "fixture_values": "Synthetic login accepted", "target_apk_sha256": build["artifacts"]["fixture-good"]["sha256"]}
        case("actual_system_fill_and_login", login)
        def cached():
            authentication_reappeared = False
            device.tap(text="Clear fields"); device.tap(description="Synthetic username")
            time.sleep(1)
            if device.find(text="Fill synthetic login once") is not None: raise Failed("cached_plaintext_dataset_visible")
            node = device.find(text="Unlock HeptaBao locally")
            if node is not None:
                device.tap(text="Unlock HeptaBao locally"); time.sleep(0.5)
                if device.foreground() == (PROVIDER, "org.heptabao.preview.AuthActivity"):
                    authentication_reappeared = True
                    device.wait(text="Locked"); device.tap(text="Fill once"); device.wait(text="Locked or expired"); device.cancel_authentication()
            if device.find(text="Fill synthetic login once") is not None: raise Failed("cached_plaintext_dataset_visible")
            device.empty()
            return {"target": GOOD, "same_system_session_after_success": True, "plaintext_dataset_menu_observed": False, "authentication_reappeared": authentication_reappeared, "fixture_values": "Empty fields", "successful_control": "actual_system_fill_and_login"}
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
            unlock_started = time.monotonic(); device.unlock(master)
            timing = device.cancel_authentication(authentication_started, unlock_started)
            cancellation_decision = device.decision()
            if cancellation_decision != "background_locked": raise Failed("cancel_cause_not_observed")
            device.authentication(); device.tap(text="Fill once")
            observed = device.authorization_status("Locked or expired", device.wait(text="Locked or expired")); device.cancel_authentication()
            return {"provider_decision_before_next_request": cancellation_decision, "new_authorization": observed, "target": GOOD, "successful_unlock_before_cancel": True, "timing": timing, "fixture_values": "Empty fields"}
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
        report["failure_context"] = {"expected_control": device.last_wait, "public_ui": device.last_public_ui}
        try:
            if device.package_hash(PROVIDER) == build["artifacts"]["provider"]["sha256"]:
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
