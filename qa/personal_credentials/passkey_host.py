#!/usr/bin/env python3
"""Cross-language .hbv/WebAuthn host checks; never a phone qualification.

Uses the exact provider crypto sources, separate JVM processes and the independent
RP verifier. Source fixture is a Rust-created empty vault and private synthetic
unlock/recovery files. No actual CredentialManager or Android filesystem is used.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

BC_SHA256 = "fc50334d4d87b4272e72fa95ca748ead05bdef02ef760a5b13f64ffee317cd81"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "rp-script", "java-home", "bc-jar", "fixture", "build-receipt", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source, rp_script, jdk, bc, fixture, build_receipt, root = [p.resolve() for p in
        (args.source, args.rp_script, args.java_home, args.bc_jar, args.fixture, args.build_receipt, args.output)]
    assert digest(bc) == BC_SHA256
    build = json.loads(build_receipt.read_text()); certificate = build["fixture_certificate_sha256"]
    os.umask(0o077); root.mkdir(mode=0o700); classes = root / "classes"; classes.mkdir(); logs = root / "logs"; logs.mkdir()
    report = {"schema": 1, "scope": "host_crypto_and_format_only", "android_device_exercised": False,
              "credential_manager_exercised": False, "started_unix_ns": time.time_ns(), "build_receipt_sha256": digest(build_receipt),
              "rp_script_sha256": digest(rp_script), "bc_sha256": BC_SHA256, "commands": [], "checks": []}
    sources = sorted((source / "common/java").rglob("*.java")) + sorted((source / "tests").rglob("*.java"))
    report["source_files"] = {str(p.relative_to(source)): digest(p) for p in sources}
    env = dict(os.environ, JAVA_HOME=str(jdk), PATH=str(jdk / "bin") + ":/opt/homebrew/opt/openssl@3/bin:/opt/homebrew/bin:/usr/bin:/bin")

    def run(argv, label):
        result = subprocess.run([str(x) for x in argv], env=env, capture_output=True, timeout=120)
        (logs / (label + ".stdout")).write_bytes(result.stdout); (logs / (label + ".stderr")).write_bytes(result.stderr)
        report["commands"].append({"label": label, "argv": [str(x) for x in argv], "exit_code": result.returncode,
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
        if result.returncode: raise RuntimeError("host_command_failed_" + label)
        return result.stdout

    def check(label, detail=True):
        report["checks"].append({"name": label, "passed": True, "detail": detail})

    def request_file(options, label):
        path = root / (label + ".options.json"); path.write_text(json.dumps(options["publicKey"], separators=(",", ":"))); return path

    def java(mode, vault, options, label):
        request = request_file(options, label); prefix = root / label
        stdout = run([jdk / "bin/java", "-Xmx256m", "-cp", str(classes) + os.pathsep + str(bc), "org.heptabao.passkey.core.HostInterop",
            mode, vault, fixture / "master.private", fixture / "recovery.private.json", certificate, request, prefix], label)
        result = json.loads(stdout); assert result["ok"] and result["scope"] == "host_core_only"
        if mode == "negative": return result
        return result, prefix.with_name(prefix.name + ".vault.hbv"), json.loads(prefix.with_name(prefix.name + ".response.json").read_text())

    spec = importlib.util.spec_from_file_location("heptabao_passkey_independent_rp", rp_script)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    store = None
    try:
        run([jdk / "bin/javac", "--release", "17", "-encoding", "UTF-8", "-cp", bc, "-d", classes] + sources, "compile-core-harness")
        check("host_harness_compiles")
        store = module.Store(root / "rp", certificate)
        report["rp_crypto_backend"] = store.crypto.description
        registration = store.options("registration", {})
        negative = java("negative", fixture / "seed.hbv", registration, "seed-negatives")
        check("seed_crypto_negative_cases", negative)
        created, created_vault, credential = java("create", fixture / "seed.hbv", registration, "created")
        registered = store.verify("registration", {"ceremony_id": registration["ceremony_id"], "credential": credential})
        assert registered["ok"] and registered["sign_count"] == 0
        check("java_attestation_verified_by_independent_rp", registered)
        negative = java("negative", created_vault, registration, "record-negatives")
        check("record_crypto_negative_cases", negative)

        def authenticate(mode, vault, label, expected_counter, expect_failure=None):
            options = store.options("authentication", {})
            result, next_vault, credential = java(mode, vault, options, label)
            assert result["sign_count"] == expected_counter
            try:
                verified = store.verify("authentication", {"ceremony_id": options["ceremony_id"], "credential": credential})
            except module.RPError as error:
                assert expect_failure is not None and error.code == expect_failure
                check(label, {"rejected": error.code, "counter": expected_counter, "restored": mode == "recover-get"})
            else:
                assert expect_failure is None and verified["ok"] and verified["sign_count"] == expected_counter
                check(label, verified)
            return next_vault

        first = authenticate("get", created_vault, "first-authentication", 1)
        stale_backup = root / "stale-backup.hbv"; shutil.copyfile(first, stale_backup); os.chmod(stale_backup, 0o600)
        second = authenticate("get", first, "original-device-advances", 2)
        authenticate("recover-get", stale_backup, "stale-backup-rejected", 2, "counter_rollback_or_replay")
        recovery_root = root / "fresh-private-store"; recovery_root.mkdir(mode=0o700)
        latest = recovery_root / "latest-confirmed-backup.hbv"; shutil.copyfile(second, latest); os.chmod(latest, 0o600)
        restored = authenticate("recover-get", latest, "latest-backup-recovery-new-process", 3)
        check("restored_store_is_new_path_and_jvm", {"fresh_directory": str(recovery_root), "ciphertext_sha256": digest(latest)})
        store.close(); store = module.Store(root / "rp", certificate)
        final = authenticate("get", restored, "rp-and-authenticator-process-restart", 4)
        report["final_ciphertext_path"] = str(final); report["final_ciphertext_sha256"] = digest(final)
        report["registered_public_key_sha256"] = registered["public_key_sha256"]
        report["public_key_digest_encoding"] = "spki_der"
        report["credential_id"] = created["credential_id"]
        report["result"] = "PASS"
    except Exception:
        report["result"] = "FAIL"; raise
    finally:
        if store is not None: store.close()
        report["finished_unix_ns"] = time.time_ns(); report["passed_checks"] = len(report["checks"])
        (root / "result.public.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"ok": True, "scope": report["scope"], "passed_checks": report["passed_checks"], "report": str(root / "result.public.json"), "sha256": digest(root / "result.public.json")}, sort_keys=True))


if __name__ == "__main__":
    main()
