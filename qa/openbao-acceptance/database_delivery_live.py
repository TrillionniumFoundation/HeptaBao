#!/usr/bin/env python3
"""Real database-plugin effects gated before reply across live authority changes.

The provider is a checksum-bound external fixture process, not a production DB.
Only synthetic state is used. Reports never contain tokens or credential bytes.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import time

import plugin_database_live as provider_fixture
from database_config_completion_live import source_identity
from plugin_completion_live import FixtureFailure, identity_requester, require, sha256

CASES = (
    "issue_policy", "issue_batch_policy", "issue_revoke", "issue_expiry",
    "issue_identity_disabled", "issue_identity_group_revoked", "issue_namespace_seal",
    "issue_seal", "issue_seal_cycle", "renew_seal_cycle", "issue_final_use_refused", "issue_finite_use", "issue_batch", "issue_unrelated_write",
    "issue_reply_lost", "renew_reply_lost", "issue_service_crash",
    "renew_policy", "renew_revoke", "renew_identity_group_revoked",
    "renew_unrelated_write", "revoke_policy",
)
POSITIVE = {"issue_finite_use", "issue_batch", "issue_unrelated_write", "renew_unrelated_write", "revoke_policy"}


def configure(binary, root, action, reply_lost=False):
    root.mkdir(mode=0o700)
    instance = provider_fixture.smoke.Instance(binary, root / "server")
    plugin, state, *_ = provider_fixture.configure(instance, root)
    entered, release, armed, events = (root / name for name in ("entered", "release", "armed", "events"))
    anchor = "os.replace(tmp,STATE)"
    source = plugin.read_text()
    require(source.count(anchor) == 1, "gate_anchor")
    gate = (
        "\nimport pathlib,time\n"
        f"with open({str(events)!r},'a',encoding='utf-8') as event:\n"
        "    event.write(action+'\\n'); event.flush(); os.fsync(event.fileno())\n"
        f"if action=={action!r} and pathlib.Path({str(armed)!r}).exists():\n"
        f"    pathlib.Path({str(entered)!r}).write_text('effect_committed')\n"
        "    end=time.monotonic()+15\n"
        f"    while not pathlib.Path({str(release)!r}).exists():\n"
        "        if time.monotonic()>end: raise SystemExit(70)\n"
        "        time.sleep(0.005)\n"
    )
    plugin.write_text(source.replace(anchor, anchor + gate + (f"\nif action=={action!r}: raise SystemExit(74)\n" if reply_lost else ""), 1))
    cfg_path = instance.root / "server.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["plugin_database"][0]["command_sha256"] = sha256(plugin)
    cfg["plugin_database"][0]["timeout_ms"] = 20000
    cfg_path.write_text(json.dumps(cfg))
    return instance, state, entered, release, armed, events


def check_case(binary, root, case):
    action = case.split("_", 1)[0]
    instance, state_path, entered, release, armed, events = configure(binary, root / case, action, case.endswith("reply_lost"))
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        require(status == 200, "initialize")
        instance.token = initialized["root_token"]
        unseal_key = initialized["keys_base64"][0]
        require(instance.call("POST", "sys/unseal", {"key": unseal_key})[0] == 200, "unseal")
        namespace = "team" if case == "issue_namespace_seal" else ""
        if namespace:
            require(instance.call("POST", "sys/namespaces/team", {})[0] == 200, "namespace")
        require(instance.call("POST", "sys/mounts/database", {"type": "database"}, namespace=namespace)[0] == 204, "mount")
        configuration = {"plugin_name": "database_fixture", "connection_url": "plugin://fixture",
                         "username": "manager", "password": "manager-password",
                         "allowed_roles": ["reader"], "verify_connection": True}
        require(instance.call("POST", "database/config/local", configuration, namespace=namespace)[0] == 204, "configuration")
        role = {"db_name": "local", "provider_role": "reader", "default_ttl": 60, "max_ttl": 600}
        require(instance.call("POST", "database/roles/reader", role, namespace=namespace)[0] == 204, "role")
        policy = ('path "database/creds/reader" { capabilities = ["read"] } '
                  'path "sys/leases/renew" { capabilities = ["update", "sudo"] } '
                  'path "sys/leases/revoke" { capabilities = ["update", "sudo"] }')
        require(instance.call("POST", "sys/policies/acl/reader", {"policy": policy}, namespace=namespace)[0] == 204, "policy")
        if "identity_" in case:
            token, entity, group = identity_requester(instance)
        else:
            options = {"policies": ["reader"], "ttl": "5s" if case.endswith("expiry") else "10m"}
            if case == "issue_final_use_refused":
                options["num_uses"] = 1
            elif case == "issue_finite_use":
                options["num_uses"] = 2
            if "batch" in case:
                options["type"] = "batch"
            status, issued = instance.call("POST", "auth/token/create", options, namespace=namespace)
            require(status == 200, "requester")
            token = issued["auth"]["client_token"]
            if "batch" in case:
                require(token.startswith("hvb."), "batch_credential")
        lease = None
        if action != "issue":
            # Independent admin requester, not the still-live lease owner.
            status, value = instance.call("GET", "database/creds/reader")
            require(status == 200, "root_owned_lease")
            lease = value["lease_id"]
        armed.write_text("armed")
        method = "GET" if action == "issue" else "POST"
        path = "database/creds/reader" if action == "issue" else "sys/leases/" + action
        body = None if action == "issue" else {"lease_id": lease}
        if action == "renew":
            body["increment"] = 120
        if case == "issue_final_use_refused":
            # A consumed final-use token cannot own a renewable external lease.
            require(instance.call(method, path, body, token=token, namespace=namespace)[0] == 403, "final_use_owner_refused")
            require(not state_path.exists() and not events.exists(), "final_use_no_provider_effect")
            require(instance.call(method, path, body, token=token, namespace=namespace)[0] == 403, "final_use_not_reusable")
            return {"case": case, "passed": True, "provider_effect_committed_before_change": False, "status": 403, "expected_status": 403, "no_provider_entry": True}
        future = pool.submit(instance.call, method, path, body, token=token, namespace=namespace)
        deadline = time.monotonic() + 8
        while not entered.exists():
            if future.done() or time.monotonic() >= deadline:
                raise FixtureFailure("provider_did_not_commit")
            time.sleep(0.01)
        provider_before = json.loads(state_path.read_text())
        require(provider_before.get("active") is (action != "revoke"), "provider_effect_observed")
        if case == "issue_service_crash":
            instance.stop()
        elif case.endswith("policy"):
            require(instance.call("POST", "sys/policies/acl/reader", {"policy": 'path "*" { capabilities = ["deny"] }'})[0] == 204, "concurrent_policy")
        elif case.endswith("revoke"):
            require(instance.call("POST", "auth/token/revoke", {"token": token})[0] == 204, "concurrent_revoke")
        elif case.endswith("expiry"):
            time.sleep(5.2)
        elif case.endswith("identity_disabled"):
            require(instance.call("POST", "identity/entity/id/" + entity, {"disabled": True})[0] == 204, "identity_disabled")
        elif case.endswith("identity_group_revoked"):
            require(instance.call("POST", "identity/group/id/" + group, {"member_entity_ids": []})[0] == 204, "identity_group_revoked")
        elif case == "issue_namespace_seal":
            require(instance.call("POST", "sys/namespaces/team/seal", {})[0] == 204, "namespace_seal")
        elif case == "issue_seal":
            require(instance.call("POST", "sys/seal", {})[0] == 204, "global_seal")
        elif case.endswith("seal_cycle"):
            require(instance.call("POST", "sys/seal", {})[0] == 204, "global_seal")
            require(instance.call("POST", "sys/unseal", {"key": unseal_key})[0] == 200, "new_activation")
        elif case.endswith("unrelated_write"):
            require(instance.call("POST", "secret/data/unrelated", {"data": {"progress": True}})[0] == 200, "unrelated_progress")
        release.write_text("release")
        if case == "issue_service_crash":
            try:
                future.result(timeout=12)
            except (OSError,):
                pass
            else:
                raise FixtureFailure("crashed_request_unexpectedly_completed")
            status, response = 503, {}
        else:
            status, response = future.result(timeout=12)
        positive = case in POSITIVE
        expected = (204 if action == "revoke" else 200) if positive else 503
        require(status == expected, "delivery_status")
        if action == "issue" and positive:
            require(isinstance(response.get("data", {}).get("password"), str), "authorized_secret_delivered")
        else:
            require(not response.get("data", {}).get("password"), "no_secret_released")
        lease = response.get("lease_id", lease)
        # Capture the real provider identity internally, never in the report.
        provider_identity = provider_before["provider_id"]
        if case == "issue_finite_use":
            lookup_status, lookup = instance.call("POST", "auth/token/lookup", {"token": token})
            require(lookup_status == 200 and lookup.get("data", {}).get("num_uses") == 1, "finite_use_not_reauthenticated")
        if case == "issue_namespace_seal":
            require(instance.call("POST", "sys/namespaces/team/unseal", {})[0] == 204, "namespace_unseal")
        # Reopen encrypted service state before any explicit cleanup.
        instance.stop()
        instance.start()
        require(instance.call("POST", "sys/unseal", {"key": unseal_key})[0] == 200, "restart_unseal")
        if not positive:
            # The original identity must survive; no fresh issue is permitted.
            deadline = time.monotonic() + 8
            while json.loads(state_path.read_text()).get("active") is True:
                if isinstance(lease, str):
                    instance.call("POST", "sys/leases/reconcile/" + lease, {}, namespace=namespace)
                if time.monotonic() >= deadline:
                    raise FixtureFailure("durable_cleanup_not_observed")
                time.sleep(0.05)
            after = json.loads(state_path.read_text())
            require(after["provider_id"] == provider_identity, "cleanup_kept_provider_identity")
            require(after["seq"] > provider_before["seq"], "cleanup_advanced_generation")
        elif action == "revoke":
            require(json.loads(state_path.read_text()).get("active") is False, "subtractive_cleanup_survived_policy")
        else:
            require(isinstance(lease, str), "lease_identity_retained")
            require(instance.call("POST", "sys/leases/lookup", {"lease_id": lease}, namespace=namespace)[0] == 200, "positive_lease_reopened")
        require(events.read_text().splitlines().count("issue") == 1, "no_duplicate_issue")
        return {"case": case, "passed": True, "provider_effect_committed_before_change": True,
                "status": status, "expected_status": expected, "restart_checked": True,
                "same_identity_cleanup_checked": not positive, "no_duplicate_issue": True}
    finally:
        release.touch()
        pool.shutdown(wait=True, cancel_futures=True)
        instance.stop()


def run(binary, root):
    os.umask(0o077)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[2]
    identity = source_identity(repo)
    binary_digest, runner_digest = sha256(binary), sha256(Path(__file__))
    results = []
    for case in CASES:
        try:
            results.append(check_case(binary, root, case))
        except Exception as error:
            results.append({"case": case, "passed": False, "safe_failure_code": str(error) if isinstance(error, FixtureFailure) else type(error).__name__})
    unchanged = identity == source_identity(repo) and sha256(binary) == binary_digest and sha256(Path(__file__)) == runner_digest
    passed = unchanged and bool(CASES) and len(set(CASES)) == len(CASES) and len(results) == len(CASES) and all(x["passed"] for x in results)
    report = {"status": "passed" if passed else "failed", "source_identity": identity,
              "binary_sha256": binary_digest, "runner_sha256": runner_digest,
              "source_binary_and_runner_unchanged": unchanged, "cases": results,
              "external_plugin_process": True, "native_database_provider": False,
              "full_openbao_compatibility": False, "independent_qualification": False}
    (root / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.binary.resolve(strict=True), args.work_dir.resolve()))
