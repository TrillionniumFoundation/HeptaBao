#!/usr/bin/env python3
"""Real delayed provider validation must not publish unauthorized configuration.

Uses synthetic credentials and private disposable state only. Reports contain
boolean observations and status codes, not provider payloads or bearer tokens.
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

import plugin_database_live as database_fixture
from plugin_completion_live import FixtureFailure, identity_requester, require, sha256

CASES = (
    "revoke", "policy", "expiry", "seal", "namespace_seal",
    "identity_disabled", "identity_group_revoked", "final_use", "batch", "unrelated_write",
)


def configure(binary, root):
    root.mkdir(mode=0o700)
    instance = database_fixture.smoke.Instance(binary, root / "server")
    plugin = database_fixture.configure(instance, root)[0]
    entered, release = root / "entered", root / "release"
    anchor = "q=json.loads(r[11:].decode())"
    source = plugin.read_text()
    require(source.count(anchor) == 1, "gate_anchor")
    gate = (
        "\nimport pathlib,time\n"
        "if q.get('action')=='configure' and q.get('connection_url')=='plugin://replacement':\n"
        f"    pathlib.Path({str(entered)!r}).write_text('entered')\n"
        "    end=time.monotonic()+15\n"
        f"    while not pathlib.Path({str(release)!r}).exists():\n"
        "        if time.monotonic()>end: raise SystemExit(70)\n"
        "        time.sleep(0.005)\n"
    )
    plugin.write_text(source.replace(anchor, anchor + gate, 1))
    config_path = instance.root / "server.json"
    config = json.loads(config_path.read_text())
    for spec in config["plugin_database"]:
        spec["command_sha256"] = sha256(plugin)
        spec["timeout_ms"] = 20000
    config_path.write_text(json.dumps(config))
    return instance, entered, release


def check_case(binary, root, case):
    instance, entered, release = configure(binary, root / case)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        require(status == 200, "initialize")
        instance.token = initialized["root_token"]
        unseal_key = initialized["keys_base64"][0]
        require(instance.call("POST", "sys/unseal", {"key": unseal_key})[0] == 200, "unseal")
        namespace = "team" if case == "namespace_seal" else ""
        if namespace:
            require(instance.call("POST", "sys/namespaces/team", {})[0] == 200, "namespace")
        require(instance.call("POST", "sys/mounts/database", {"type": "database"}, namespace=namespace)[0] == 204, "mount")
        path = "database/config/local"
        original = {
            "plugin_name": "database_fixture", "connection_url": "plugin://original",
            "username": "manager", "password": "manager-password",
            "allowed_roles": ["reader"], "verify_connection": True,
        }
        require(instance.call("POST", path, original, namespace=namespace)[0] == 204, "original_config")
        policy = f'path "{path}" {{ capabilities = ["read", "update", "sudo"] }}'
        require(instance.call("POST", "sys/policies/acl/reader", {"policy": policy}, namespace=namespace)[0] == 204, "policy")
        if case.startswith("identity_"):
            token, entity, group = identity_requester(instance)
        else:
            options = {"policies": ["reader"], "ttl": "5s" if case == "expiry" else "10m"}
            if case == "final_use":
                options["num_uses"] = 1
            if case == "batch":
                options["type"] = "batch"
            status, issued = instance.call("POST", "auth/token/create", options, namespace=namespace)
            require(status == 200, "requester")
            token = issued["auth"]["client_token"]
            if case == "batch":
                require(token.startswith("hvb."), "real_batch_credential")
        replacement = dict(original, connection_url="plugin://replacement")
        future = pool.submit(instance.call, "POST", path, replacement, token=token, namespace=namespace)
        limit = time.monotonic() + 8
        while not entered.exists():
            if future.done() or time.monotonic() > limit:
                raise FixtureFailure("provider_did_not_enter")
            time.sleep(0.01)
        if case == "revoke":
            require(instance.call("POST", "auth/token/revoke", {"token": token})[0] == 204, "concurrent_revoke")
        elif case == "policy":
            require(instance.call("POST", "sys/policies/acl/reader", {"policy": f'path "{path}" {{ capabilities = ["deny"] }}'})[0] == 204, "concurrent_policy")
        elif case == "expiry":
            time.sleep(5.2)
        elif case == "seal":
            require(instance.call("POST", "sys/seal", {})[0] == 204, "concurrent_seal")
        elif case == "namespace_seal":
            require(instance.call("POST", "sys/namespaces/team/seal", {})[0] == 204, "concurrent_namespace_seal")
        elif case == "identity_disabled":
            require(instance.call("POST", "identity/entity/id/" + entity, {"disabled": True})[0] == 204, "concurrent_identity_disable")
        elif case == "identity_group_revoked":
            require(instance.call("POST", "identity/group/id/" + group, {"member_entity_ids": []})[0] == 204, "concurrent_identity_group")
        elif case == "unrelated_write":
            require(instance.call("POST", "secret/data/other", {"data": {"progress": True}})[0] == 200, "unrelated_write")
        release.write_text("release")
        status, _ = future.result(timeout=12)
        positive = case in ("final_use", "batch", "unrelated_write")
        expected = 204 if positive else (503 if case in ("seal", "namespace_seal") else 403)
        if case == "seal":
            require(instance.call("POST", "sys/unseal", {"key": unseal_key})[0] == 200, "unseal_for_readback")
        elif case == "namespace_seal":
            require(instance.call("POST", "sys/namespaces/team/unseal", {})[0] == 204, "namespace_unseal_for_readback")
        read_status, observed = instance.call("GET", path, namespace=namespace)
        expected_url = "plugin://replacement" if positive else "plugin://original"
        preserved = read_status == 200 and observed.get("data", {}).get("connection_url") == expected_url
        finite_use_preserved = True
        if case == "final_use":
            finite_use_preserved = instance.call("POST", path, replacement, token=token, namespace=namespace)[0] == 403
        # The same installed configuration must survive a complete service exit.
        instance.stop()
        instance.start()
        require(instance.call("POST", "sys/unseal", {"key": unseal_key})[0] == 200, "restart_unseal")
        restart_status, restarted = instance.call("GET", path, namespace=namespace)
        durable = restart_status == 200 and restarted.get("data", {}).get("connection_url") == expected_url
        return {"case": case, "passed": status == expected and preserved and durable and finite_use_preserved,
                "status": status, "expected_status": expected, "provider_entered": True,
                "configuration_correct": preserved, "restart_configuration_correct": durable,
                "finite_use_preserved": finite_use_preserved}
    finally:
        release.touch()
        pool.shutdown(wait=True, cancel_futures=True)
        instance.stop()


def source_identity(repo):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo)
    untracked = git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")
    return {
        "head": git("rev-parse", "HEAD").decode().strip(),
        "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
        "tracked_patch_sha256": hashlib.sha256(git("diff", "HEAD", "--binary")).hexdigest(),
        "untracked_file_sha256": {path: sha256(repo / path) for path in untracked if path},
    }


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
    unchanged = (sha256(binary) == binary_digest
                 and sha256(Path(__file__)) == runner_digest
                 and identity == source_identity(repo))
    report = {"status": "passed" if unchanged and results and len(set(CASES)) == len(CASES) and all(x["passed"] for x in results) else "failed",
              "source_head": identity["head"], "source_identity": identity, "binary_sha256": binary_digest, "runner_sha256": runner_digest,
              "source_binary_and_runner_unchanged": unchanged, "cases": results,
              "full_openbao_compatibility": False, "independent_qualification": False}
    (root / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.binary.resolve(strict=True), args.work_dir.resolve()))
