#!/usr/bin/env python3
"""Offline schema-2 -> schema-3 wrapping/SSH-OTP migration and old-binary rejection.

Only newly initialized synthetic TLS state is used. Binary pins are required;
passing does not qualify a mixed-version HA upgrade or production rollback.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins


def main() -> int:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--legacy-binary", required=True)
    parser.add_argument("--expected-legacy-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    binary, legacy = Path(args.binary).resolve(strict=True), Path(args.legacy_binary).resolve(strict=True)
    try:
        new_digest, old_digest = validate_binary_pins(binary, legacy, args.expected_legacy_sha256)
    except ValueError as error:
        parser.error(str(error))
    output = Path(args.output).resolve()
    mode = output.parent.stat()
    if output.exists() or mode.st_uid != os.geteuid() or mode.st_mode & 0o077:
        parser.error("new output in caller-owned mode 0700 directory required")
    root = Path(tempfile.mkdtemp(prefix="heptabao-wrapping-upgrade-"))
    root.chmod(0o700)
    instance = None
    report = {"schema": "heptabao.wrapping-upgrade.v1", "synthetic_only": True,
              "candidate_binary_sha256": new_digest, "legacy_binary_sha256": old_digest,
              "runner_sha256": file_hash(Path(__file__)), "cases": [],
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
              "source_worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "started_at_unix": time.time(), "independent_qualification": False,
              "full_migration_qualification": False, "production_authority": False}

    def check(name, condition):
        report["cases"].append({"case": name, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(name)

    def client():
        return Client(instance.address, str(instance.root / "ca.crt"), instance.token)

    try:
        spec = importlib.util.spec_from_file_location("wrapping_upgrade_smoke", ROOT / "qa/single-node/smoke.py")
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        instance = smoke.Instance(legacy, root / "state")
        instance.start()
        status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("wrapping_upgrade.legacy_init", status == 200)
        instance.token, key = init["root_token"], init["keys_base64"][0]
        check("wrapping_upgrade.legacy_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("wrapping_upgrade.legacy_kv", instance.call("POST", "secret/data/upgrade", {"data": {"v": "synthetic"}})[0] == 200)
        instance.stop()
        original = file_hash(instance.root / "data/state.hbs")
        instance.binary = binary
        instance.start()
        check("wrapping_upgrade.new_unseals_legacy", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("wrapping_upgrade.old_read_works", instance.call("GET", "secret/data/upgrade")[0] == 200)
        check("wrapping_upgrade.read_preserves_old_bytes", file_hash(instance.root / "data/state.hbs") == original)
        payload = {"synthetic": "wrapped-across-binary-transition"}
        response = client().request("POST", "/v1/sys/wrapping/wrap", payload, wrap_ttl="300s")
        check("wrapping_upgrade.capture", response.status == 200 and response.body.get("data") is None)
        wrapped = response.body["wrap_info"]["token"]
        check("ssh_upgrade.mount", instance.call("POST", "sys/mounts/upgrade-ssh", {"type":"ssh"})[0] == 204)
        check("ssh_upgrade.role", instance.call("POST", "upgrade-ssh/roles/test", {
            "key_type":"otp", "default_user":"deploy", "cidr_list":"127.0.0.0/8"})[0] == 204)
        status, issued = instance.call("POST", "upgrade-ssh/creds/test", {"ip":"127.0.0.1"})
        check("ssh_upgrade.issue", status == 200 and bool(issued.get("lease_id")))
        otp, lease = issued["data"]["key"], issued["lease_id"]
        instance.stop()
        protected = file_hash(instance.root / "data/state.hbs")
        check("wrapping_upgrade.mutation_upgrades_bytes", protected != original)
        instance.binary = legacy
        instance.start()
        check("wrapping_upgrade.old_binary_rejects_new_state", instance.call("POST", "sys/unseal", {"key": key})[0] == 503)
        check("wrapping_upgrade.old_binary_cannot_release", instance.call("POST", "sys/wrapping/unwrap", {}, token=wrapped)[0] == 503)
        check("ssh_upgrade.old_binary_cannot_verify", instance.call("POST", "upgrade-ssh/verify", {"otp":otp}, token="")[0] == 503)
        check("wrapping_upgrade.failed_downgrade_preserves_bytes", file_hash(instance.root / "data/state.hbs") == protected)
        instance.stop()
        instance.binary = binary
        instance.start()
        check("wrapping_upgrade.new_reopens", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        metadata = client().request("POST", "/v1/sys/wrapping/lookup", {"token": wrapped}, token="")
        check("wrapping_upgrade.original_capability_preserved", metadata.status == 200 and metadata.body.get("data", {}).get("creation_ttl") == 300)
        status, result = instance.call("POST", "sys/wrapping/unwrap", {}, token=wrapped)
        check("wrapping_upgrade.exact_single_release", status == 200 and result.get("data") == payload)
        status, verified = instance.call("POST", "upgrade-ssh/verify", {"otp":otp}, token="")
        check("ssh_upgrade.verify_after_recovery", status == 200 and verified.get("data", {}).get("username") == "deploy")
        check("ssh_upgrade.lease_retained_after_use", instance.call("POST", "sys/leases/lookup", {"lease_id":lease})[0] == 200)
        instance.stop()
        instance.start()
        check("wrapping_upgrade.reopen_consumed_state", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("wrapping_upgrade.replay_stays_denied", instance.call("POST", "sys/wrapping/unwrap", {}, token=wrapped)[0] == 400)
        check("ssh_upgrade.replay_remains_consumed", instance.call("POST", "upgrade-ssh/verify", {"otp":otp}, token="")[0] == 400)
        check("wrapping_upgrade.binaries_unchanged", file_hash(binary) == new_digest and file_hash(legacy) == old_digest)
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["failure"] = str(error) if isinstance(error, ScenarioFailure) else type(error).__name__
    finally:
        if instance is not None:
            try:
                instance.stop()
            except Exception:
                report["status"], report["failure"] = "failed", "process_cleanup_failed"
        try:
            shutil.rmtree(root)
        except OSError:
            report["status"], report["failure"] = "failed", "private_fixture_cleanup_failed"
        report["finished_at_unix"] = time.time()
        private_write(output, report)
    print(json.dumps({"status": report["status"], "count": len(report["cases"]), "failure": report.get("failure")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
