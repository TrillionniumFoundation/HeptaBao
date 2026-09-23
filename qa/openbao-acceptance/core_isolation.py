#!/usr/bin/env python3
"""Compare a bounded candidate behavior profile on new local TLS instances only.

No live endpoint/credential option exists. The official pinned binary/archive
must be supplied through HB_ORACLE_BINARY and HB_ORACLE_ARCHIVE. The result is a
selected-behavior observation, not full-surface or independent qualification.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from bao_http import BaoError, Client, SafeArgumentParser, private_read, private_write
from official_openbao_launcher import BINARY_SHA256, restart_oracle, start_oracle, stop_oracle

ROOT = Path(__file__).resolve().parents[2]


class ScenarioFailure(Exception):
    """Carries only a fixed scenario ID, never request/response secrets."""


def run_scenarios(client: Client, results: list[dict] | None = None) -> list[dict]:
    results = [] if results is None else results

    def call(method, path, body=None, token=None):
        return client.request(method, "/v1/" + path, body, token=token)

    def check(name, response, status, expected_data=None):
        result = {"case": name, "status": response.status,
                  "passed": response.status == status}
        if expected_data is not None:
            result["data_matches"] = response.body.get("data") == expected_data
            result["passed"] &= result["data_matches"]
        results.append(result)
        if not result["passed"]:
            raise ScenarioFailure(name)
        return response.body

    def token(name, **options):
        body = check(name, call("POST", "auth/token/create", options), 200)
        return body["auth"]["client_token"]

    alice = token("token.alice", policies=["default"], ttl="1h")
    bob = token("token.bob", policies=["default"], ttl="1h")
    check("cubbyhole.empty", call("GET", "cubbyhole/item", token=alice), 404)
    check("cubbyhole.write", call("POST", "cubbyhole/item", {"value": "synthetic-a"}, alice), 204)
    check("cubbyhole.read", call("GET", "cubbyhole/item", token=alice), 200, {"value": "synthetic-a"})
    check("cubbyhole.peer_denied_view", call("GET", "cubbyhole/item", token=bob), 404)
    check("cubbyhole.root_has_distinct_view", call("GET", "cubbyhole/item"), 404)
    check("cubbyhole.replace", call("PUT", "cubbyhole/item", {"new": 1}, alice), 204)
    check("cubbyhole.replace_readback", call("GET", "cubbyhole/item", token=alice), 200, {"new": 1})
    check("cubbyhole.child_write", call("POST", "cubbyhole/folder/a", {"v": 2}, alice), 204)
    check("cubbyhole.nested_write", call("POST", "cubbyhole/folder/deep/b", {"v": 3}, alice), 204)
    check("cubbyhole.list_root", call("LIST", "cubbyhole/", token=alice), 200, {"keys": ["folder/", "item"]})
    check("cubbyhole.list_folder", call("LIST", "cubbyhole/folder", token=alice), 200, {"keys": ["a", "deep/"]})
    check("cubbyhole.list_query", call("GET", "cubbyhole/folder?list=true", token=alice), 200, {"keys": ["a", "deep/"]})
    check("cubbyhole.list_file_empty", call("LIST", "cubbyhole/item", token=alice), 404)
    check("cubbyhole.delete", call("DELETE", "cubbyhole/item", token=alice), 204)
    check("cubbyhole.deleted_read", call("GET", "cubbyhole/item", token=alice), 404)
    check("cubbyhole.delete_idempotent", call("DELETE", "cubbyhole/item", token=alice), 204)
    # Three uses: successful write, successful read, final-use successful read.
    finite = token("token.finite", policies=["default"], ttl="1h", num_uses=3)
    check("cubbyhole.finite_write", call("POST", "cubbyhole/once", {"v": "finite"}, finite), 204)
    check("cubbyhole.finite_read", call("GET", "cubbyhole/once", token=finite), 200, {"v": "finite"})
    check("cubbyhole.final_read", call("GET", "cubbyhole/once", token=finite), 200, {"v": "finite"})
    check("cubbyhole.final_replay_denied", call("GET", "cubbyhole/once", token=finite), 403)
    check("cubbyhole.revoke", call("POST", "auth/token/revoke", {"token": alice}), 204)
    check("cubbyhole.revoked_denied", call("GET", "cubbyhole/folder/a", token=alice), 403)

    mount = "core-isolation"
    check("acl.mount", call("POST", "sys/mounts/" + mount, {"type": "kv", "options": {"version": "2"}}), 204)
    item = mount + "/data/locked"
    check("acl.seed", call("POST", item, {"data": {"v": "before"}}), 200)
    policy = (f'path "{mount}/*" {{ capabilities = ["read", "create", "update", "delete"] }}\n'
              f'path "{item}" {{ capabilities = ["read"] }}')
    check("acl.policy", call("PUT", "sys/policies/acl/core-specific", {"policy": policy}), 204)
    reader = token("acl.reader", policies=["core-specific"], no_default_policy=True, ttl="1h")
    check("acl.exact_read", call("GET", item, token=reader), 200)
    check("acl.narrow_write_denied", call("POST", item, {"data": {"v": "forbidden"}}, reader), 403)
    check("acl.narrow_delete_denied", call("DELETE", item, token=reader), 403)
    unchanged = call("GET", item)
    check("acl.unchanged_version", unchanged, 200)
    if (unchanged.body.get("data", {}).get("data") != {"v": "before"}
            or unchanged.body.get("data", {}).get("metadata", {}).get("version") != 1):
        raise ScenarioFailure("acl.denials_no_effect")
    results.append({"case": "acl.denials_no_effect", "passed": True})
    check("acl.no_default_cubbyhole", call("POST", "cubbyhole/item", {"v": 1}, reader), 403)

    # Identical paths across policies union; a deny at that same path dominates.
    for name, cap in [("core-extra", "update"), ("core-deny", "deny")]:
        policy = f'path "{item}" {{ capabilities = ["{cap}"] }}'
        check("acl." + name, call("PUT", "sys/policies/acl/" + name, {"policy": policy}), 204)
    union = token("acl.union_token", policies=["core-specific", "core-extra"], no_default_policy=True, ttl="1h")
    check("acl.same_pattern_union", call("POST", item, {"data": {"v": "union"}}, union), 200)
    deny = token("acl.deny_token", policies=["core-specific", "core-extra", "core-deny"], no_default_policy=True, ttl="1h")
    check("acl.same_pattern_deny", call("GET", item, token=deny), 403)

    # Default policy override can authorize only create, not overwrite/update.
    path = "cubbyhole/create-only"
    check("acl.create_policy", call("PUT", "sys/policies/acl/core-create", {
        "policy": f'path "{path}" {{ capabilities = ["create", "read"] }}'}), 204)
    creator = token("acl.creator", policies=["core-create"], no_default_policy=True, ttl="1h")
    check("acl.create_allowed", call("POST", path, {"v": 1}, creator), 204)
    check("acl.update_not_create", call("POST", path, {"v": 2}, creator), 403)
    check("acl.create_unchanged", call("GET", path, token=creator), 200, {"v": 1})
    return results


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()



def successful_comparison(cases: dict, side_failures: dict) -> bool:
    """Never admit matching failed/empty prefixes or mismatched observations."""
    if side_failures or set(cases) != {"candidate", "oracle"}:
        return False
    candidate, oracle = cases["candidate"], cases["oracle"]
    if not isinstance(candidate, list) or not isinstance(oracle, list):
        return False
    if not candidate or len(candidate) > 4096 or candidate != oracle:
        return False
    for observations in (candidate, oracle):
        seen = set()
        for row in observations:
            if not isinstance(row, dict) or row.get("passed") is not True:
                return False
            name = row.get("case")
            if not isinstance(name, str) or not name or name in seen:
                return False
            seen.add(name)
    return True

def main(*, scenario_runner=run_scenarios, restart_runner=None, profile="core-isolation",
         scope="selected_cubbyhole_and_acl_behavior_only", runner_path=None) -> int:
    if profile not in ("core-isolation", "identity-live", "response-wrapping", "capabilities-live",
                        "ssh-otp-live", "pki-live", "pkiext-live", "audit-file-management", "namespace-tree", "kv-metadata-cas-live",
                        "kv-enumeration-live"):
        raise ValueError("unknown local comparison profile")
    runner_path = Path(__file__) if runner_path is None else Path(runner_path)
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    binary = Path(args.binary).resolve(strict=True)
    output = Path(args.output).resolve()
    if output.exists():
        parser.error("output already exists")
    output_dir = output.parent.stat()
    if output_dir.st_uid != os.geteuid() or output_dir.st_mode & 0o077:
        parser.error("output directory must be owned by the caller with mode 0700")
    private_root = Path(tempfile.mkdtemp(prefix="heptabao-core-isolation-"))
    private_root.chmod(0o700)
    spec = importlib.util.spec_from_file_location("core_smoke", ROOT / "qa/single-node/smoke.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    instance = smoke.Instance(binary, private_root / "candidate")
    oracle = None
    candidate_unseal_key = None
    result = {"schema": "heptabao." + profile + "-comparison.v1", "synthetic_only": True,
              "target_version": "2.6.2", "full_openbao_compatibility": False,
              "independent_qualification": False, "production_authority": False,
              "candidate_binary_sha256": file_hash(binary), "oracle_binary_sha256": BINARY_SHA256,
              "cargo_lock_sha256": file_hash(ROOT / "Cargo.lock"),
              "runner_sha256": file_hash(runner_path),
              "launcher_harness_sha256": file_hash(Path(__file__)),
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
              "source_worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "started_at_unix": time.time(), "cases": {}, "scope": scope}
    if profile == "audit-file-management":
        result["audit_api_profile"] = "deployment_owned_file_v2"
        result["supersedes_candidate_only_idempotent_enable_profile"] = True
    try:
        instance.start()
        status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if status != 200:
            raise ScenarioFailure("candidate.init")
        instance.token = init["root_token"]
        candidate_unseal_key = init["keys_base64"][0]
        if instance.call("POST", "sys/unseal", {"key": candidate_unseal_key})[0] != 200:
            raise ScenarioFailure("candidate.unseal")
        candidate = Client(instance.address, str(instance.root / "ca.crt"), instance.token)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        oracle = (start_oracle(port, audit_file=True)
                  if profile == "audit-file-management" else start_oracle(port))
        reference = Client(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"], 8192).decode().strip())
        # Same ordered requests run independently; no protected operation proxies.
        # Preserve both sides even if one rejects early. Equality of two empty
        # traces or matching failure prefixes can never qualify a profile.
        result["side_failures"] = {}
        for name, client in (("candidate", candidate), ("oracle", reference)):
            result["cases"][name] = []
            try:
                scenario_runner(client, result["cases"][name])
            except (ScenarioFailure, BaoError) as error:
                result["side_failures"][name] = str(error)
            except Exception as error:
                result["side_failures"][name] = "unexpected_" + type(error).__name__
        if restart_runner is not None and not result["side_failures"]:
            for name in ("candidate", "oracle"):
                try:
                    if name == "candidate":
                        instance.stop()
                        instance.start()
                        if instance.call("POST", "sys/unseal", {"key": candidate_unseal_key})[0] != 200:
                            raise ScenarioFailure("candidate.restart_unseal")
                        restarted = Client(instance.address, str(instance.root / "ca.crt"), instance.token)
                    else:
                        stop_oracle(oracle)
                        restart_oracle(oracle)
                        restarted = Client(
                            oracle["address"],
                            oracle["ca_file"],
                            private_read(oracle["token_file"], 8192).decode().strip(),
                        )
                    restart_runner(restarted, result["cases"][name])
                except (ScenarioFailure, BaoError) as error:
                    result["side_failures"][name] = str(error)
                except Exception as error:
                    result["side_failures"][name] = "unexpected_" + type(error).__name__
        result["cases_match"] = result["cases"]["candidate"] == result["cases"]["oracle"]
        result["case_count_per_side"] = len(result["cases"]["candidate"])
        complete = successful_comparison(result["cases"], result["side_failures"])
        result["status"] = "passed" if complete else "mismatch"
    except (ScenarioFailure, BaoError) as error:
        result["status"] = "failed"
        result["safe_failure_code"] = str(error)
    except Exception as error:
        result["status"] = "failed"
        result["safe_failure_code"] = "unexpected_" + type(error).__name__
    finally:
        instance.stop()
        if oracle is not None:
            stop_oracle(oracle)
            shutil.rmtree(oracle["root"])
        shutil.rmtree(private_root)
        result["candidate_binary_unchanged"] = file_hash(binary) == result["candidate_binary_sha256"]
        result["finished_at_unix"] = time.time()
        private_write(output, result)
    print(json.dumps({"status": result["status"], "cases_per_side": result.get("case_count_per_side", 0),
                      "failure": result.get("safe_failure_code"), "side_failures": result.get("side_failures", {}), "full_openbao_compatibility": False}))
    return 0 if result["status"] == "passed" and result["candidate_binary_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
