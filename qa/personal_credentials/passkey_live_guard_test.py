#!/usr/bin/env python3
"""Synthetic host-only regression checks for the phone driver's ownership guards."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest import mock


def main():
    source = Path(__file__).with_name("passkey_live.py")
    spec = importlib.util.spec_from_file_location("passkey_live_under_test", source)
    live = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(live)
    os.umask(0o077)
    passed = []
    device = live.Device.__new__(live.Device)
    device.adb = "/synthetic/adb"; device.serial = "synthetic"

    def presence(name, responses, result=None, denied=False):
        with mock.patch.object(subprocess, "run", side_effect=[subprocess.CompletedProcess([], *r) for r in responses]):
            try:
                actual = device.package_hash(live.PROVIDER)
            except live.Failed:
                assert denied, name
            else:
                assert not denied and actual == result, name
        passed.append(name)

    row = ("package:" + live.PROVIDER + "\n").encode()
    presence("pm_failure_empty_stdout_denied", [(1, b"", b"")], denied=True)
    presence("pm_success_empty_stdout_absent", [(0, b"", b"")])
    presence("pm_failure_fake_presence_denied", [(1, row, b"")], denied=True)
    presence("pm_success_error_text_denied", [(0, b"Error: unavailable\n", b"")], denied=True)
    presence("pm_success_stderr_denied", [(0, b"", b"error")], denied=True)
    presence("substring_package_not_owned", [(0, ("package:" + live.PROVIDER + ".other\n").encode(), b"")])
    presence("present_failed_path_denied", [(0, row, b""), (1, b"", b"")], denied=True)
    presence("present_empty_path_denied", [(0, row, b""), (0, b"", b"")], denied=True)
    presence("present_full_digest_verified", [(0, row, b""), (0, b"package:/data/app/test/base.apk\n", b""),
        (0, ("a" * 64 + "  /data/app/test/base.apk\n").encode(), b"")], result="a" * 64)

    components = sorted({live.SERVICE, live.PROVIDER + "/.ProviderService"})
    original = {"credential_service": "", "credential_service_primary": "", "autofill_service": "synthetic.original/.Service"}
    joint = [{"credential_service": enabled, "credential_service_primary": primary, "autofill_service": live.SYSTEM_BRIDGE}
             for enabled in components for primary in components]
    intent = {"kind": "select_primary_with_verified_system_bridge_from_empty", "before": original,
              "allowed_after": {"credential_service": components, "credential_service_primary": components,
                                "autofill_service": [live.SYSTEM_BRIDGE]}, "joint_after": joint,
              "bridge": {"component": live.SYSTEM_BRIDGE, "apk_path": live.SYSTEM_BRIDGE_APK,
                         "apk_sha256": live.SYSTEM_BRIDGE_SHA256, "system_flag": True, "service_query": live.SYSTEM_BRIDGE_SHORT},
              "armed_unix_ns": 1}
    journal = {"schema": 1, "device_sha256": live.DEVICE_SHA256, "build_receipt_sha256": "b" * 64,
               "started_unix_ns": 1, "original_settings": original, "owned_settings": joint[0], "settings_intent": intent,
               "owned_packages": {live.PROVIDER: ["a" * 64]}, "initial_packages_absent": {p: True for p in live.OWNED},
               "install_intents": [{"variant": "provider", "package": live.PROVIDER, "sha256": "a" * 64, "attempted_unix_ns": 1}],
               "reverse_owned": True, "phases": [], "credential_entry": "synthetic_only_adb_input_text_argv",
               "production_qualified": False, "credential_manager_exercised": False, "p4_qualified": False}
    build = {"artifacts": {"provider": {"package": live.PROVIDER, "sha256": "a" * 64}}}
    live.validate_journal(journal, build, "b" * 64); passed.append("valid_joint_authorization")

    def invalid_journal(name, mutate):
        value = copy.deepcopy(journal); mutate(value)
        try:
            live.validate_journal(value, build, "b" * 64)
        except live.Failed:
            passed.append(name)
        else:
            raise AssertionError(name)

    invalid_journal("hash_string_not_list_denied", lambda j: j["owned_packages"].__setitem__(live.PROVIDER, "a" * 64))
    invalid_journal("hash_substring_denied", lambda j: j["owned_packages"].__setitem__(live.PROVIDER, ["a" * 32]))
    invalid_journal("unrecorded_install_denied", lambda j: j.__setitem__("install_intents", []))
    invalid_journal("initial_package_presence_denied", lambda j: j["initial_packages_absent"].__setitem__(live.PROVIDER, False))
    invalid_journal("foreign_joint_primary_denied", lambda j: j["settings_intent"]["joint_after"][0].__setitem__("credential_service_primary", "other/.Service"))
    invalid_journal("bridge_not_system_denied", lambda j: j["settings_intent"]["bridge"].__setitem__("system_flag", False))
    invalid_journal("bridge_digest_change_denied", lambda j: j["settings_intent"]["bridge"].__setitem__("apk_sha256", "c" * 64))
    invalid_journal("extra_autofill_target_denied", lambda j: j["settings_intent"]["allowed_after"]["autofill_service"].append("other/.Service"))

    class Settings:
        def __init__(self, state, interfere=False):
            self.state = dict(state); self.writes = []; self.interfere = interfere
        def setting(self, key):
            return self.state[key]
        def shell(self, *args):
            assert args[:3] == ("settings", "--user", "0") and args[4] == "secure"
            key = args[5]; value = "null" if args[3] == "delete" else args[6]
            self.state[key] = value; self.writes.append((key, value))
            if self.interfere:
                self.interfere = False; self.state["credential_service_primary"] = "unrelated/.Service"
            return ""

    def denied(call):
        try:
            call()
        except live.Failed:
            return
        raise AssertionError("expected_fail_closed")

    with tempfile.TemporaryDirectory(prefix="passkey-joint-restore-") as directory:
        root = Path(directory); fake = Settings(joint[0])
        live.restore_joint_settings(fake, root, journal)
        assert fake.state == original and len(fake.writes) == 3
        plan = json.loads((root / "joint-settings-restore.private.json").read_bytes())
        assert plan["completed"] == 3
        passed.append("joint_restore_exact_tuple_to_original")
        fake.state["credential_service_primary"] = "unrelated/.Service"
        denied(lambda: live.restore_joint_settings(fake, root, journal)); assert len(fake.writes) == 3
        passed.append("external_change_after_restore_preserved")
    with tempfile.TemporaryDirectory(prefix="passkey-joint-unknown-") as directory:
        root = Path(directory); unknown = dict(joint[0]); unknown["credential_service_primary"] = "unrelated/.Service"
        fake = Settings(unknown)
        denied(lambda: live.restore_joint_settings(fake, root, journal))
        assert fake.state == unknown and not fake.writes and not list(root.iterdir())
        passed.append("shared_bridge_with_unknown_primary_preserved_as_whole")
    with tempfile.TemporaryDirectory(prefix="passkey-joint-crash-") as directory:
        root = Path(directory); fake = Settings(joint[0]); real_atomic = live.atomic; calls = 0
        def fail_ack(path, value):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic_ack_not_persisted")
            real_atomic(path, value)
        with mock.patch.object(live, "atomic", side_effect=fail_ack):
            try:
                live.restore_joint_settings(fake, root, journal)
            except OSError:
                pass
            else:
                raise AssertionError("missing_injected_fault")
        assert len(fake.writes) == 1
        live.restore_joint_settings(fake, root, journal)
        assert fake.state == original and len(fake.writes) == 3
        passed.append("committed_unacknowledged_step_reconciled_without_repeat")
    with tempfile.TemporaryDirectory(prefix="passkey-joint-interference-") as directory:
        root = Path(directory); fake = Settings(joint[0], interfere=True)
        denied(lambda: live.restore_joint_settings(fake, root, journal)); state = dict(fake.state)
        denied(lambda: live.restore_joint_settings(fake, root, journal))
        assert fake.state == state and len(fake.writes) == 1
        passed.append("unknown_mid_restore_tuple_stops_further_writes")
    with tempfile.TemporaryDirectory(prefix="passkey-joint-tamper-") as directory:
        root = Path(directory); fake = Settings(joint[0]); real_atomic = live.atomic
        def stop_before_write(path, value):
            real_atomic(path, value); raise OSError("synthetic_stop_after_intent")
        with mock.patch.object(live, "atomic", side_effect=stop_before_write):
            try:
                live.restore_joint_settings(fake, root, journal)
            except OSError:
                pass
        plan_path = root / "joint-settings-restore.private.json"; plan = json.loads(plan_path.read_bytes())
        plan["states"][-1]["autofill_service"] = "attacker/.Service"; real_atomic(plan_path, plan)
        denied(lambda: live.restore_joint_settings(fake, root, journal)); assert not fake.writes
        passed.append("sidecar_target_not_derivable_from_original_denied")
    with tempfile.TemporaryDirectory(prefix="passkey-joint-already-") as directory:
        fake = Settings(original); live.restore_joint_settings(fake, Path(directory), journal)
        assert not fake.writes; passed.append("already_original_has_no_side_effect")
    print(json.dumps({"schema": 1, "scope": "host_only_driver_stubs", "driver_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                      "test_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "passed": len(passed),
                      "checks": passed, "adb_calls": 0, "phone_qualified": False}, sort_keys=True))


if __name__ == "__main__":
    main()
