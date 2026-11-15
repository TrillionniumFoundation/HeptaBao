#!/usr/bin/env python3
"""One reviewed correction of the observed Android credential/Autofill linkage.

This never enables a provider or expands the live helper's allowed settings.
It restores only the original Autofill component after comparing all three
current settings to the separately recorded post-selection snapshot. Unknown
changes are preserved. The initial failed qualification attempt remains intact.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import os
import time

BRIDGE = "com.android.credentialmanager/com.android.credentialmanager.autofill.CredentialAutofillService"
DRIVER_SHA256 = "ae8d8cc6294b0583f94802250fe0704c8f01dca9e3c907a4204c2a1888f7b18d"
BUILD_SHA256 = "c7f84bd9ff3dcde9adf1bf7b24c641f393bb1274cb27e3b860f41845b98d107c"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--snapshot-sha256", required=True)
    parser.add_argument("--provenance-sha256", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    base = args.base
    driver = base / "passkey_live.primary-r4.py"
    assert hashlib.sha256(driver.read_bytes()).hexdigest() == DRIVER_SHA256
    spec = importlib.util.spec_from_file_location("passkey_live", driver)
    live = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(live)
    root = base / "live-r4"
    live.private_directory(base)
    live.private_directory(root)
    # The ordinary live helper uses this same private flock. No concurrent UI
    # phase may change settings while this corrective compare-and-restore runs.
    import fcntl
    import stat
    fd = os.open(root / "driver.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        live.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                     and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "unsafe_driver_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raw = live.private_file(root / "settings-unexpected.private.json", 8 * 1024 * 1024)
        live.require(live.sha(raw) == args.snapshot_sha256, "snapshot_changed")
        observed = json.loads(raw)
        provenance_raw = live.private_file(root / "autofill-bridge-provenance.public.json", 65536)
        live.require(live.sha(provenance_raw) == args.provenance_sha256, "provenance_changed")
        provenance = json.loads(provenance_raw)
        live.require(provenance["snapshot_sha256"] == args.snapshot_sha256
                     and provenance["system_flag"] is True
                     and provenance["bridge_component"] == BRIDGE
                     and provenance["current_matches_observed_after"] is True
                     and provenance["service_query"] in (BRIDGE,
                         "com.android.credentialmanager/.autofill.CredentialAutofillService"), "system_bridge_unproven")
        journal_raw = live.private_file(root / "journal.private.json", 8 * 1024 * 1024)
        journal = json.loads(journal_raw)
        build_raw = live.private_file(base / "artifacts/build.receipt.json", 1024 * 1024)
        live.require(live.sha(build_raw) == BUILD_SHA256, "build_receipt_changed")
        build = json.loads(build_raw)
        live.validate_journal(journal, build, BUILD_SHA256)
        live.require(set(observed) == {"before", "after", "intent"}
                     and observed["before"] == journal["original_settings"]
                     and observed["intent"] == journal["settings_intent"]
                     and journal["settings_intent"]["kind"] == "select_primary_from_empty"
                     and not journal["owned_settings"], "observation_not_bound_to_action")
        own = {live.SERVICE, live.PROVIDER + "/.ProviderService"}
        after = observed["after"]
        live.require(set(after) == set(live.SETTING_KEYS)
                     and after["credential_service"] in own
                     and after["credential_service_primary"] in own
                     and after["autofill_service"] == BRIDGE, "unexpected_observed_outcome")
        original = observed["before"]["autofill_service"]
        live.require(live.valid_setting(original) and original != BRIDGE, "original_setting_unavailable")
        desired = dict(after)
        desired["autofill_service"] = original
        device = live.Device("/home/alex/.local/bin/adb")
        current = {key: device.setting(key) for key in live.SETTING_KEYS}
        live.require(current == after, "current_settings_changed_preserved")
        live.require(device.package_hash(live.PROVIDER) == build["artifacts"]["provider"]["sha256"], "provider_artifact_changed")
        live.require(device.shell("sha256sum", provenance["bridge_apk_path"]).split()[0]
                     == provenance["bridge_apk_sha256"], "system_bridge_artifact_changed")
        intent = {"schema": 1, "kind": "restore_original_autofill_after_observed_system_bridge_linkage",
                  "created_unix_ns": time.time_ns(), "journal_sha256": live.sha(journal_raw),
                  "snapshot_sha256": args.snapshot_sha256, "provenance_sha256": args.provenance_sha256,
                  "before": current, "desired": desired}
        intent_path = root / "autofill-correction-intent.private.json"
        live.require(not intent_path.exists(), "correction_already_attempted_reconcile_first")
        live.atomic(intent_path, intent)
        live.require({key: device.setting(key) for key in live.SETTING_KEYS} == current,
                     "settings_changed_after_intent_preserved")
        if original == "null":
            device.shell("settings", "--user", "0", "delete", "secure", "autofill_service")
        else:
            device.shell("settings", "--user", "0", "put", "secure", "autofill_service", original)
        verified = {key: device.setting(key) for key in live.SETTING_KEYS}
        live.require(verified == desired, "correction_outcome_unknown")
        # Never rewrite the pre-selection authorization or failed outcome.
        live.require(live.private_file(root / "journal.private.json", 8 * 1024 * 1024) == journal_raw,
                     "journal_changed_during_correction")
        receipt = {"schema": 1, "ok": True, "scope": "restore_original_autofill_only",
                   "snapshot_sha256": args.snapshot_sha256, "provenance_sha256": args.provenance_sha256,
                   "journal_sha256": live.sha(journal_raw), "intent_sha256": live.sha(intent_path.read_bytes()),
                   "before_sha256": {k: live.sha(v.encode()) for k, v in current.items()},
                   "after_sha256": {k: live.sha(v.encode()) for k, v in verified.items()},
                   "credential_services_unchanged": True, "autofill_matches_original": True,
                   "original_failed_observation_preserved": True, "original_authorization_unchanged": True}
        live.atomic(root / "autofill-correction.result.public.json", receipt)
        print(json.dumps(receipt, sort_keys=True))
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"ok": False, "error": "corrective_restore_failed_or_unknown_reconcile_before_retry"}))
        raise SystemExit(1) from None
