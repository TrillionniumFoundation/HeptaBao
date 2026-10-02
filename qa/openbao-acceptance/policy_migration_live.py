#!/usr/bin/env python3
"""Real pinned OpenBao 2.6.2 -> HeptaBao ACL policy migration rehearsal.

Synthetic root-namespace policies only. The source is never cut over or mutated
except for creating/removing the fixture policies. Built-in root/default policy
semantics, namespaces, tokens, and production rollback remain outside this gate.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile

from bao_http import BaoError, Client, SafeArgumentParser, private_write
import migrate_policies as migration
from official_openbao_launcher import BINARY_SHA256, file_digest, start_oracle, stop_oracle
from heptabao.private_state import StateDirectory

ROOT = Path(__file__).resolve().parents[2]


def run_tool(arguments, expected_code=0):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = migration.main(arguments)
    result = json.loads(output.getvalue())
    if code != expected_code:
        raise BaoError("policy_live_cli_" + result.get("reason", "unexpected_result"))
    return result


def run(binary, output):
    checks = []

    def check(name, condition):
        if not condition:
            raise BaoError("policy_live_" + name)
        checks.append(name)

    if not all(Path(os.environ.get(name, "/absent-oracle")).is_file() for name in ("HB_ORACLE_BINARY", "HB_ORACLE_ARCHIVE")):
        raise FileNotFoundError("pinned oracle prerequisite missing")

    with tempfile.TemporaryDirectory(prefix="heptabao-policy-migration-live-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        spec = importlib.util.spec_from_file_location("policy_migration_smoke", ROOT / "qa/single-node/smoke.py")
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        oracle = instance = None
        source_names = ["hb-migrate-reader", "hb-migrate-deny"]
        policies = {
            source_names[0]: 'path "secret/data/migration" { capabilities = ["read", "list"] }',
            source_names[1]: 'path "secret/data/blocked" { capabilities = ["deny"] }',
        }
        try:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            oracle = start_oracle(port)
            source = Client(oracle["address"], oracle["ca_file"], Path(oracle["token_file"]).read_text().strip())
            instance = smoke.Instance(binary.resolve(), root / "candidate")
            instance.start()
            status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
            check("candidate_initialized", status == 200)
            instance.token = init["root_token"]
            unseal = init["keys_base64"][0]
            check("candidate_unsealed", instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200)
            target = Client(instance.address, str(instance.root / "ca.crt"), instance.token)

            for name, source_text in policies.items():
                check(
                    "source_fixture_" + name,
                    source.request("POST", "/v1/sys/policies/acl/" + name, {"policy": source_text}).status == 204,
                )
                check("source_readback_" + name, migration.read_policy(source, name) == source_text)

            target_token = root / "target.token"
            fd = os.open(target_token, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(instance.token)
            os.environ.update(
                HB_SOURCE_ADDR=oracle["address"],
                HB_SOURCE_CACERT=oracle["ca_file"],
                HB_SOURCE_TOKEN_FILE=oracle["token_file"],
                HB_TARGET_ADDR=instance.address,
                HB_TARGET_CACERT=str(instance.root / "ca.crt"),
                HB_TARGET_TOKEN_FILE=str(target_token),
            )
            for name in ("HB_SOURCE_TOKEN", "HB_TARGET_TOKEN", "HB_SOURCE_NAMESPACE", "HB_TARGET_NAMESPACE"):
                os.environ.pop(name, None)

            checkpoint = root / "policy-checkpoint.json"
            dry = run_tool([])
            check("dry_run_inventory", dry["status"] == "dry_run_complete" and dry["objects_checked"] == len(policies))
            check(
                "dry_run_no_effect",
                all(migration.read_policy(target, name, absent_ok=True) is None for name in source_names),
            )
            applied_args = [
                "--checkpoint",
                str(checkpoint),
                "--apply",
                "--source-writes-frozen",
                "--target-exclusive",
            ]
            applied = run_tool(applied_args)
            check("actual_copy", applied["objects_copied"] == len(policies))
            for name, source_text in policies.items():
                check("exact_target_readback_" + name, migration.read_policy(target, name) == source_text)
            check(
                "builtins_not_transferred",
                applied["root_authority_transferred"] is False
                and applied["default_policy_transferred"] is False
                and set(applied["reserved_policies_observed"]) == {"default", "root"},
            )

            repeated = run_tool(applied_args)
            check("repeat_idempotent", repeated["objects_already_verified"] == len(policies))
            instance.stop()
            instance.start()
            check("restart_unseal", instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200)
            after_restart = run_tool(applied_args)
            check("restart_resume_idempotent", after_restart["objects_already_verified"] == len(policies))
            for name, source_text in policies.items():
                check("restart_target_readback_" + name, migration.read_policy(target, name) == source_text)
                check("source_unchanged_" + name, migration.read_policy(source, name) == source_text)

            result = {
                "schema": "heptabao.acl-policy-migration-live.v1",
                "status": "passed_scoped_policy_transfer",
                "checks": checks,
                "count": len(checks),
                "candidate_binary_sha256": file_digest(binary),
                "oracle_binary_sha256": BINARY_SHA256,
                "official_openbao_version": source.health()["version"],
                "full_asset_migration": False,
                "source_cutover": False,
                "cutover_authority": False,
                "rollback_authority": False,
                "independent_qualification": False,
            }
            private_write(output, result, replace=False)
            return result
        finally:
            if oracle is not None:
                try:
                    cleanup = Client(
                        oracle["address"],
                        oracle["ca_file"],
                        Path(oracle["token_file"]).read_text().strip(),
                    )
                    for name in source_names:
                        cleanup.request("DELETE", "/v1/sys/policies/acl/" + name)
                except Exception:
                    pass
            if instance is not None:
                instance.stop()
            if oracle is not None:
                stop_oracle(oracle)
                shutil.rmtree(oracle["root"], ignore_errors=True)


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if os.path.lexists(args.output):
        raise BaoError("output_already_exists")
    with StateDirectory(args.output.absolute().parent):
        pass
    result = run(args.binary.resolve(), args.output)
    print(json.dumps({key: result[key] for key in ("status", "count", "full_asset_migration")}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError:
        print(json.dumps({"status": "blocked_prerequisite", "full_asset_migration": False}))
        raise SystemExit(77) from None
    except Exception as error:
        reason = (
            str(error)
            if isinstance(error, BaoError) and str(error).startswith("policy_live_")
            else "policy_migration_live_failed"
        )
        print(json.dumps({"status": "failed", "reason": reason, "full_asset_migration": False}))
        raise SystemExit(2) from None
