#!/usr/bin/env python3
"""Exercise a local legacy -> identity-aware -> legacy-denied -> new sequence.

Both binaries are explicit offline inputs; the legacy SHA-256 must be supplied
from its verified build receipt. Only fresh, private, synthetic TLS state is
used. A passing sequence is not full migration or rolling-upgrade admission.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash


def validate_binary_pins(candidate: Path, legacy: Path, expected_legacy: str) -> tuple[str, str]:
    if re.fullmatch(r"[0-9a-f]{64}", expected_legacy) is None:
        raise ValueError("invalid legacy binary digest")
    candidate_digest, legacy_digest = file_hash(candidate), file_hash(legacy)
    if legacy_digest != expected_legacy or candidate_digest == legacy_digest:
        raise ValueError("legacy pin mismatch or identical candidate")
    return candidate_digest, legacy_digest


def main() -> int:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--legacy-binary", required=True)
    parser.add_argument("--expected-legacy-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    binary = Path(args.binary).resolve(strict=True)
    legacy = Path(args.legacy_binary).resolve(strict=True)
    try:
        candidate_digest, legacy_digest = validate_binary_pins(binary, legacy, args.expected_legacy_sha256)
    except ValueError as error:
        parser.error(str(error))
    output = Path(args.output).resolve()
    if output.exists():
        parser.error("output already exists")
    mode = output.parent.stat()
    if mode.st_uid != os.geteuid() or mode.st_mode & 0o077:
        parser.error("output directory must be caller-owned with mode 0700")
    root = Path(tempfile.mkdtemp(prefix="heptabao-identity-upgrade-"))
    root.chmod(0o700)
    result = {"schema": "heptabao.identity-upgrade-comparison.v1", "synthetic_only": True,
              "candidate_binary_sha256": candidate_digest, "legacy_binary_sha256": legacy_digest,
              "runner_sha256": file_hash(Path(__file__)), "cases": [],
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
              "source_worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "started_at_unix": time.time(), "independent_qualification": False,
              "full_migration_qualification": False, "production_authority": False}
    instance = None

    def check(name, condition):
        result["cases"].append({"case": name, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(name)

    try:
        spec = importlib.util.spec_from_file_location("identity_upgrade_smoke", ROOT / "qa/single-node/smoke.py")
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        instance = smoke.Instance(legacy, root / "state")
        instance.start()
        status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("upgrade.legacy_init", status == 200)
        instance.token, key = init["root_token"], init["keys_base64"][0]
        check("upgrade.legacy_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("upgrade.legacy_policy", instance.call("PUT", "sys/policies/acl/upgrade-reader", {
            "policy": 'path "secret/data/upgrade" { capabilities = ["read"] }'})[0] == 204)
        check("upgrade.legacy_value", instance.call("POST", "secret/data/upgrade", {"data": {"v": "synthetic"}})[0] == 200)
        role = "auth/approle/role/upgrade"
        check("upgrade.legacy_role", instance.call("POST", role, {"token_policies": ["upgrade-reader"], "secret_id_num_uses": 0})[0] == 204)
        status, rid = instance.call("GET", role + "/role-id")
        check("upgrade.legacy_role_id", status == 200)
        status, sid = instance.call("POST", role + "/secret-id", {})
        check("upgrade.legacy_secret_id", status == 200)
        credentials = {"role_id": rid["data"]["role_id"], "secret_id": sid["data"]["secret_id"]}
        instance.stop()
        old_state_digest = file_hash(instance.root / "data/state.hbs")
        instance.binary = binary
        instance.start()
        check("upgrade.new_reads_legacy_seal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        status, data = instance.call("GET", "secret/data/upgrade")
        check("upgrade.new_reads_legacy_value", status == 200 and data["data"]["data"] == {"v": "synthetic"})
        check("upgrade.read_does_not_rewrite_legacy", file_hash(instance.root / "data/state.hbs") == old_state_digest)
        status, logged = instance.call("POST", "auth/approle/login", credentials, token="")
        check("upgrade.new_login", status == 200)
        token, entity = logged["auth"]["client_token"], logged["auth"]["entity_id"]
        check("upgrade.new_entity_binding", isinstance(entity, str) and bool(entity))
        check("upgrade.bound_token_policy_works", instance.call("GET", "secret/data/upgrade", token=token)[0] == 200)
        check("upgrade.disable_entity", instance.call("POST", "identity/entity/id/" + entity, {"disabled": True})[0] == 204)
        check("upgrade.disabled_blocks_durable_token_policy", instance.call("GET", "secret/data/upgrade", token=token)[0] == 403)
        instance.stop()
        new_state_digest = file_hash(instance.root / "data/state.hbs")
        instance.binary = legacy
        instance.start()
        check("upgrade.old_binary_rejects_schema", instance.call("POST", "sys/unseal", {"key": key})[0] == 503)
        check("upgrade.old_binary_remains_sealed", instance.call("GET", "sys/health")[0] == 503)
        check("upgrade.old_binary_cannot_serve_bound_token", instance.call("GET", "secret/data/upgrade", token=token)[0] == 503)
        check("upgrade.failed_downgrade_does_not_rewrite_state", file_hash(instance.root / "data/state.hbs") == new_state_digest)
        instance.stop()
        instance.binary = binary
        instance.start()
        check("upgrade.current_binary_reopens", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("upgrade.disabled_survives_binary_roundtrip", instance.call("GET", "secret/data/upgrade", token=token)[0] == 403)
        check("upgrade.reenable", instance.call("POST", "identity/entity/id/" + entity, {"disabled": False})[0] == 204)
        check("upgrade.nonrevoked_token_can_resume", instance.call("GET", "secret/data/upgrade", token=token)[0] == 200)
        result["status"] = "passed"
    except ScenarioFailure as error:
        result["status"], result["failure"] = "failed", str(error)
    except Exception as error:
        result["status"], result["failure"] = "failed", "unexpected_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        shutil.rmtree(root)
        result["binaries_unchanged"] = file_hash(binary) == candidate_digest and file_hash(legacy) == legacy_digest
        result["finished_at_unix"] = time.time()
        private_write(output, result)
    print(json.dumps({"status": result["status"], "count": len(result["cases"]),
                      "failure": result.get("failure"), "full_migration_qualification": False}))
    return 0 if result["status"] == "passed" and result["binaries_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
