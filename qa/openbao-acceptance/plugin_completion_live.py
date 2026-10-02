#!/usr/bin/env python3
"""Gate real plugin replies across concurrent authoritative Service changes.

Only synthetic secrets are used. The report retains statuses and boolean checks,
never a bearer, wrapping key, plugin payload or provider error response.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

import plugin_auth_live as auth_fixture
import plugin_kms_live as kms_fixture
import plugin_secret_live as secret_fixture

CASES = (
    "secret_revoke", "secret_policy", "secret_expiry", "secret_seal", "secret_seal_cycle",
    "secret_mount_recreate", "secret_namespace_seal", "secret_namespace_delete_refused",
    "secret_final_use", "secret_batch", "secret_identity_disabled", "secret_identity_group_revoked",
    "kms_revoke", "kms_policy", "kms_expiry", "kms_seal", "kms_seal_cycle", "kms_final_use", "kms_identity_disabled", "kms_identity_group_revoked",
    "auth_current", "auth_unrelated_write", "auth_delayed_ttl", "auth_seal",
    "auth_seal_cycle", "auth_namespace_seal", "auth_config_change", "auth_mount_recreate",
)


class FixtureFailure(RuntimeError):
    """A static, secret-independent check identifier."""


def require(value, code):
    if value is not True:
        raise FixtureFailure(code)


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def configure(binary, root, kind):
    root.mkdir(mode=0o700)
    instance = secret_fixture.smoke.Instance(binary, root / "server")
    values = {"kms": kms_fixture, "secret": secret_fixture, "auth": auth_fixture}[kind].configure(instance, root)
    plugin = values[0]
    count = values[2] if kind == "kms" else values[1]
    entered, release = root / "entered", root / "release"
    source = plugin.read_text()
    anchor = "p=json.dumps(result,sort_keys=True).encode()" if kind == "auth" else "q=json.loads(r[11:].decode())"
    require(source.count(anchor) == 1, "plugin_gate_anchor")
    gate = (
        "\nimport pathlib,time\n"
        f"pathlib.Path({str(entered)!r}).write_text('entered')\n"
        "end=time.monotonic()+15\n"
        f"while not pathlib.Path({str(release)!r}).exists():\n"
        "    if time.monotonic()>end: raise SystemExit(70)\n"
        "    time.sleep(0.005)\n"
    )
    plugin.write_text(source.replace(anchor, anchor + gate, 1))
    config_path = instance.root / "server.json"
    config = json.loads(config_path.read_text())
    for spec in config[{"kms": "plugin_kms", "secret": "plugin_secrets", "auth": "plugin_auth"}[kind]]:
        spec["command_sha256"] = sha256(plugin)
        spec["timeout_ms"] = 20000
    config_path.write_text(json.dumps(config))
    return instance, entered, release, count



def identity_requester(instance):
    require(instance.call("POST", "sys/auth/response-owner", {"type": "approle"})[0] == 204, "identity_mount")
    role = "auth/response-owner/role/reader"
    require(instance.call("POST", role, {"token_policies": ["default"], "secret_id_num_uses": 0})[0] == 204, "identity_role")
    status, value = instance.call("GET", role + "/role-id")
    require(status == 200, "identity_role_id")
    role_id = value["data"]["role_id"]
    status, value = instance.call("POST", role + "/secret-id", {})
    require(status == 200, "identity_secret_id")
    status, value = instance.call("POST", "auth/response-owner/login", {"role_id": role_id, "secret_id": value["data"]["secret_id"]})
    require(status == 200, "identity_login")
    token, entity = value["auth"]["client_token"], value["auth"]["entity_id"]
    require(isinstance(entity, str) and bool(entity), "identity_entity")
    require("reader" not in value["auth"].get("token_policies", []), "identity_not_static_policy")
    status, value = instance.call("POST", "identity/group", {"name": "response-readers", "type": "internal", "policies": ["reader"], "member_entity_ids": [entity]})
    require(status == 200, "identity_group")
    return token, entity, value["data"]["id"]


def check_auth_case(binary, root, case):
    instance, entered, release, count = configure(binary, root / case, "auth")
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    namespace = "team" if case == "auth_namespace_seal" else ""
    try:
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        require(status == 200, "initialize")
        instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
        require(instance.call("POST", "sys/unseal", {"key": key})[0] == 200, "unseal")
        if namespace:
            require(instance.call("POST", "sys/namespaces/team", {})[0] == 200, "create_namespace")
        mount = {"type": "plugin"}
        config = {"plugin_id": "auth_fixture", "policies": ["reader"],
                  "token_ttl": "2s" if case == "auth_delayed_ttl" else "10m", "token_max_ttl": "30m"}
        require(instance.call("POST", "sys/auth/external", mount, namespace=namespace)[0] == 204, "auth_mount")
        require(instance.call("POST", "sys/policies/acl/reader", {"policy": 'path "auth/token/lookup-self" { capabilities = ["read"] }'}, namespace=namespace)[0] == 204, "auth_policy")
        require(instance.call("POST", "auth/external/config", config, namespace=namespace)[0] == 204, "auth_config")
        login = {"username": "alice", "password": "correct"}
        future = pool.submit(instance.call, "POST", "auth/external/login", login, token="", namespace=namespace)
        limit = time.monotonic() + 8
        while not entered.exists():
            if future.done() or time.monotonic() >= limit:
                raise FixtureFailure("auth_provider_did_not_reach_decision")
            time.sleep(0.01)
        if case in ("auth_seal", "auth_seal_cycle"):
            require(instance.call("POST", "sys/seal", {})[0] == 204, "auth_global_seal")
            if case == "auth_seal_cycle":
                require(instance.call("POST", "sys/unseal", {"key": key})[0] == 200, "auth_new_activation")
        elif case == "auth_namespace_seal":
            require(instance.call("POST", "sys/namespaces/team/seal", {})[0] == 204, "auth_namespace_seal")
        elif case == "auth_config_change":
            config = dict(config, token_ttl="20m")
            require(instance.call("POST", "auth/external/config", config)[0] == 204, "auth_config_replaced")
        elif case == "auth_mount_recreate":
            require(instance.call("DELETE", "sys/auth/external")[0] == 204, "auth_mount_disabled")
            require(instance.call("POST", "sys/auth/external", mount)[0] == 204, "auth_mount_recreated")
            require(instance.call("POST", "auth/external/config", config)[0] == 204, "auth_same_config_recreated")
        elif case == "auth_unrelated_write":
            require(instance.call("POST", "sys/policies/acl/unrelated", {"policy": 'path "unused/*" { capabilities = ["read"] }'})[0] == 204, "auth_unrelated_write")
        elif case == "auth_delayed_ttl":
            time.sleep(3.1)
        release.write_text("release")
        status, response = future.result(timeout=12)
        positive = case in ("auth_current", "auth_unrelated_write", "auth_delayed_ttl")
        expected = 200 if positive else 409 if case in ("auth_config_change", "auth_mount_recreate") else 503
        token = response.get("auth", {}).get("client_token")
        released = isinstance(token, str) and bool(token)
        lookup = instance.call("GET", "auth/token/lookup-self", token=token, namespace=namespace)[0] if positive and released else None
        correct = status == expected and released == positive and (not positive or lookup == 200)
        if not positive and correct:
            if case == "auth_seal":
                require(instance.call("POST", "sys/unseal", {"key": key})[0] == 200, "auth_recover_global_seal")
            elif case == "auth_namespace_seal":
                require(instance.call("POST", "sys/namespaces/team/unseal", {})[0] == 204, "auth_recover_namespace_seal")
            fresh_status, fresh = instance.call("POST", "auth/external/login", login, token="", namespace=namespace)
            fresh_token = fresh.get("auth", {}).get("client_token")
            correct = fresh_status == 200 and isinstance(fresh_token, str) and instance.call("GET", "auth/token/lookup-self", token=fresh_token, namespace=namespace)[0] == 200
        return {"case": case, "passed": bool(correct), "status": status, "expected_status": expected,
                "token_released": released, "lookup_status": lookup, "provider_decision_before_change": True}
    finally:
        release.touch()
        pool.shutdown(wait=True, cancel_futures=True)
        instance.stop()


def check_case(binary, root, case):
    if case.startswith("auth_"):
        return check_auth_case(binary, root, case)
    kind = "kms" if case.startswith("kms_") else "secret"
    instance, entered, release, count = configure(binary, root / case, kind)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        require(status == 200, "initialize")
        instance.token = initialized["root_token"]
        require(instance.call("POST", "sys/unseal", {"key": initialized["keys_base64"][0]})[0] == 200, "unseal")
        namespace = "team" if "namespace" in case else ""
        if namespace:
            require(instance.call("POST", "sys/namespaces/team", {})[0] == 200, "create_namespace")
        mount = {"type": "plugin", "config": {"plugin_id": "readonly_fixture"}}
        if kind == "secret":
            require(instance.call("POST", "sys/mounts/external", mount, namespace=namespace)[0] == 204, "mount")
        path = "external/item" if kind == "secret" else "sys/plugins/kms/kms_fixture/wrap"
        capability = '["read"]' if kind == "secret" else '["update", "sudo"]'
        policy = f'path "{path}" {{ capabilities = {capability} }}'
        if case == "secret_namespace_delete_refused":
            token = instance.token
        else:
            require(instance.call("POST", "sys/policies/acl/reader", {"policy": policy}, namespace=namespace)[0] == 204, "policy")
            if "_identity_" in case:
                token, entity, group = identity_requester(instance)
            else:
                options = {"policies": ["reader"], "ttl": "5s" if case.endswith("expiry") else "10m"}
                if case.endswith("final_use"):
                    options["num_uses"] = 1
                if case.endswith("batch"):
                    options["type"] = "batch"
                status, issued = instance.call("POST", "auth/token/create", options, namespace=namespace)
                require(status == 200, "issue_requester")
                token = issued["auth"]["client_token"]
                if case.endswith("batch"):
                    require(token.startswith("hvb."), "real_batch_credential")
        body = None if kind == "secret" else kms_fixture.request({"plaintext": "c3ludGhldGlj"})
        method = "GET" if kind == "secret" else "POST"
        future = pool.submit(instance.call, method, path, body, token=token, namespace=namespace)
        limit = time.monotonic() + 8
        while not entered.exists():
            if future.done() or time.monotonic() > limit:
                raise FixtureFailure("provider_did_not_enter")
            time.sleep(0.01)
        if case.endswith("identity_disabled"):
            require(instance.call("POST", "identity/entity/id/" + entity, {"disabled": True})[0] == 204, "concurrent_identity_disabled")
        elif case.endswith("identity_group_revoked"):
            require(instance.call("POST", "identity/group/id/" + group, {"member_entity_ids": []})[0] == 204, "concurrent_identity_membership")
        elif case.endswith("revoke"):
            require(instance.call("POST", "auth/token/revoke", {"token": token})[0] == 204, "concurrent_revoke")
        elif case.endswith("policy"):
            require(instance.call("POST", "sys/policies/acl/reader", {"policy": f'path "{path}" {{ capabilities = ["deny"] }}'})[0] == 204, "concurrent_policy")
        elif case.endswith("expiry"):
            # Let provider entry be observable before crossing the token expiry.
            # A one-second credential may expire before its subprocess is
            # scheduled under build load and would not test completion at all.
            time.sleep(5.2)
        elif case == "secret_namespace_seal":
            require(instance.call("POST", "sys/namespaces/team/seal", {})[0] == 204, "concurrent_namespace_seal")
        elif case == "secret_namespace_delete_refused":
            require(instance.call("DELETE", "sys/namespaces/team", {})[0] == 409, "populated_namespace_delete_refused")
            require(instance.call("GET", "sys/namespaces/team")[0] == 200, "refused_delete_preserves_namespace")
        elif case.endswith("seal"):
            require(instance.call("POST", "sys/seal", {})[0] == 204, "concurrent_global_seal")
        elif case.endswith("seal_cycle"):
            require(instance.call("POST", "sys/seal", {})[0] == 204, "concurrent_global_seal")
            require(instance.call("POST", "sys/unseal", {"key": initialized["keys_base64"][0]})[0] == 200, "new_activation")
        elif case == "secret_mount_recreate":
            require(instance.call("DELETE", "sys/mounts/external")[0] == 204, "delete_mount")
            require(instance.call("POST", "sys/mounts/external", mount)[0] == 204, "recreate_mount")
        release.write_text("release")
        status, response = future.result(timeout=12)
        positive = case.endswith("final_use") or case.endswith("batch") or case == "secret_namespace_delete_refused"
        expected = 200 if positive else (403 if "_identity_" in case or case.endswith(("revoke", "policy", "expiry")) else 503)
        has_data = isinstance(response.get("data"), dict)
        correct = status == expected and has_data == positive
        if positive and correct:
            if kind == "secret":
                correct = response["data"].get("source") == "sealed-readonly-plugin"
            else:
                correct = isinstance(response["data"].get("ciphertext"), str)
        if case.endswith("final_use") and correct:
            before = count.read_text().count("\n")
            retried, _ = instance.call(method, path, body, token=token, namespace=namespace)
            correct = retried == 403 and count.read_text().count("\n") == before
        return {"case": case, "passed": correct, "status": status,
                "expected_status": expected, "data_released": has_data,
                "provider_entered": True}
    finally:
        release.touch()
        pool.shutdown(wait=True, cancel_futures=True)
        instance.stop()


def run(binary, root):
    os.umask(0o077)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[2]
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    patch = hashlib.sha256(subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=repo)).hexdigest()
    binary_digest = sha256(binary)
    runner_digest = sha256(Path(__file__))
    results = []
    for case in CASES:
        try:
            results.append(check_case(binary, root, case))
        except Exception as error:
            results.append({"case": case, "passed": False, "safe_failure_code": str(error) if isinstance(error, FixtureFailure) else type(error).__name__})
    unchanged = (sha256(binary) == binary_digest
        and sha256(Path(__file__)) == runner_digest
        and head == subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        and patch == hashlib.sha256(subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=repo)).hexdigest())
    report = {"status": "passed" if unchanged and all(x["passed"] for x in results) else "failed",
              "source_head": head, "tracked_patch_sha256": patch,
              "binary_sha256": binary_digest, "runner_sha256": runner_digest,
              "source_and_binary_unchanged": unchanged, "cases": results,
              "full_openbao_plugin_compatibility": False, "independent_qualification": False}
    (root / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.binary.resolve(strict=True), args.work_dir.resolve()))
