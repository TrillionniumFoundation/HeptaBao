#!/usr/bin/env python3
"""Predeclared Android r4 acceptance profile; phase success is not case success.

This file declares expected behavior only. Actual results belong in a separate
append-only evidence report, including every failed, blocked, or missing case.
"""
import json

PROFILE = {
    "schema": 1,
    "profile": "android16-native-passkey-r4-synthetic",
    "runtime_source_bundle_sha256": "1b7af164b251f7075a1d54e3f950b96dc0581b5d2e14899d1857209a6e3118b0",
    "build_receipt_sha256": "c7f84bd9ff3dcde9adf1bf7b24c641f393bb1274cb27e3b860f41845b98d107c",
    "device_sha256": "41ad305f8562a6c47710afe71fabf30cb8692a71d3de1a47ca9949b669bcc6c1",
    "android_api": 36,
    "rp_id": "passkeys.heptabao.test",
    "fixture_certificate_sha256": "ab74dc07d6ac2e4b5d176637da98a0c4820ef987b862697b2487aa60714c882d",
    "rp_source_sha256": "386de84bb5335f21998a000b4a1267eaa17fadbde1e1753d5df1c30325709a63",
    "credential_entry": "synthetic_only_adb_input_text_argv",
    "production_qualified": False,
    "general_web_rp_support": False,
    "physical_cross_device_passkey_migration": False,
    "case_result_states": ["passed", "failed", "blocked", "missing"],
    "cases": [
        {"id": "M01", "group": "main", "behavior": "ordinary SAF imports the fixed encrypted seed into a fresh app-private store after password approval", "evidence": ["SAF actual UI", "fixed seed digest", "provider import result"]},
        {"id": "M02", "group": "main", "behavior": "real platform CredentialManager create completes after provider selection and fresh password approval; independent RP verifies registration", "evidence": ["platform selector", "OperationActivity approval", "RP registration record and public-key digest"]},
        {"id": "M03", "group": "main", "behavior": "real CredentialManager get returns a signature accepted by independent RP with exact challenge, native origin, RP ID, UP, UV and increasing counter", "evidence": ["actual fixture authentication result", "RP verification event and persisted counter"]},
        {"id": "M04", "group": "main", "behavior": "ordinary SAF exports a latest confirmed encrypted backup and provider reports write/read-back verification", "evidence": ["actual document selection", "provider export result", "exported ciphertext digest"]},
        {"id": "M05", "group": "main", "behavior": "force-stop ends the provider process; a new process imports the latest confirmed backup into a distinct fresh private store", "evidence": ["old process gone", "new process identity", "SAF import result and fresh-store identity"]},
        {"id": "M06", "group": "main", "behavior": "real get after fresh-store restore verifies against the original RP public key with a strictly newer counter and backup-state flag", "evidence": ["RP persisted key before/after", "verified counter and flags"]},
        {"id": "G01", "group": "guard", "behavior": "wrong password during import does not activate the staged vault", "evidence": ["provider rejection", "active-store state unchanged"]},
        {"id": "G02", "group": "guard", "behavior": "wrong password for a selected CredentialManager operation does not deliver a credential", "evidence": ["provider rejection", "RP successful-event/counter state unchanged"]},
        {"id": "G03", "group": "guard", "behavior": "locked provider refuses CredentialManager credential delivery", "evidence": ["explicit lock", "platform result", "RP state unchanged"]},
        {"id": "G04", "group": "guard", "behavior": "wrong RP target is refused", "evidence": ["fixture wrong-target action", "platform/provider rejection", "RP state unchanged"]},
        {"id": "G05", "group": "guard", "behavior": "same package signed by the wrong certificate is refused", "evidence": ["installed artifact digest", "platform/provider rejection", "RP state unchanged"]},
        {"id": "G06", "group": "guard", "behavior": "wrong package signed by the pinned certificate is refused", "evidence": ["decoy artifact digest", "platform/provider rejection", "RP state unchanged"]},
        {"id": "G07", "group": "guard", "behavior": "cancel/back before approval yields no RP-accepted credential", "evidence": ["ordinary task transition without task clearing", "platform result", "RP state unchanged"]},
        {"id": "G08", "group": "guard", "behavior": "after selecting a backup target, opening a new picker and cancelling makes Write refuse the old target", "evidence": ["picker cancellation", "provider refusal", "old target digest unchanged"]},
        {"id": "G09", "group": "guard", "behavior": "after staging A, cancelling or failing a new selection makes Import refuse reuse of A", "evidence": ["new selection cancellation/failure", "provider refusal", "active-store state unchanged"]},
        {"id": "G10", "group": "guard", "behavior": "wrong password for export is refused before truncating or writing the selected destination", "evidence": ["provider rejection", "destination content digest unchanged"]},
        {"id": "G11", "group": "guard", "behavior": "restoring a stale backup whose counter was already used does not bypass the RP strict counter rule", "evidence": ["stale backup digest and counter history", "RP counter_rollback_or_replay rejection"]},
        {"id": "M07", "group": "cleanup", "behavior": "settings are compare-restored; only this run's package hashes, reverse mapping and tracked synthetic documents are removed; unknown changes are preserved and reported", "evidence": ["pre-action private journal", "final settings comparison", "positive package absence queries", "reverse/document cleanup receipt"]},
    ],
    "report_rules": [
        "Keep every case; report expected, executed, passed, failed, blocked and missing separately.",
        "A successful ADB phase, installation, host test or signature-only unit test does not pass a CredentialManager behavior.",
        "Retain initial failures and later candidate attempts; do not pool runtime hashes into one qualification.",
        "Fresh-store restore on this one phone is not physical cross-device migration or generic passkey portability.",
        "Latest-backup recovery is supported only when its counter has not been superseded at the strict RP.",
    ],
}

if __name__ == "__main__":
    print(json.dumps(PROFILE, sort_keys=True, indent=2))
