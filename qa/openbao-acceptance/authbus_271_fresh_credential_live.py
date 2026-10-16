#!/usr/bin/env python3
"""Fresh, isolated OpenBao 2.7.1 AppRole/TLS/Policy/KV/lease differential.

No external endpoints, existing credentials, production configuration or J3160.
Use only independently initialized synthetic loopback HTTPS instances. Record
status and boolean evidence, never a token, policy secret, or unseal share.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/openbao-acceptance"))
sys.path.insert(0, str(ROOT / "qa/single-node"))
sys.path.insert(0, str(ROOT / "clients/python/src"))
from bao_http import private_read, private_write
from official_openbao_launcher import (
    pinned_artifact, restart_oracle, start_oracle, stop_oracle, verify_inputs,
)
from online_evidence import source_identity
from smoke import Instance, free_loopback_port
from kv2_271_large_live import request

VERSION = "2.7.1"
POLICY_NAME = "authbus-271-reader"
EXPECTED = (
    "mount_kv", "mount_auth", "write_allowed", "write_blocked",
    "install_policy", "install_role", "role_id", "issue_secret_id",
    "login", "read_allowed", "deny_other_key", "lookup_self",
    "renew_self", "spent_secret_id_denied", "revoke_self",
    "revoked_read_denied", "restart", "revoked_after_restart",
    "new_secret_id", "fresh_login_after_restart", "fresh_read",
    "fresh_revoke",
)


def scenario(address: str, ca: Path, token: str, restart,
             rows: list[dict]) -> None:
    def check(case: str, status: int | None, passed: bool) -> None:
        rows.append({"case": case, "status": status, "passed": passed is True})
        if passed is not True:
            raise RuntimeError(case)

    def call(case: str, method: str, path: str, body=None,
             *, caller: str | None = None, status=200) -> dict:
        code, value = request(
            address, ca, token if caller is None else caller, method, path, body,
        )
        check(case, code, code == status)
        return value

    call("mount_kv", "POST", "sys/mounts/authbus",
         {"type": "kv", "options": {"version": "2"}}, status=204)
    call("mount_auth", "POST", "sys/auth/approle", {"type": "approle"}, status=204)
    call("write_allowed", "POST", "authbus/data/allowed",
         {"data": {"fixture": "authbus-fresh-271"}})
    call("write_blocked", "POST", "authbus/data/blocked",
         {"data": {"fixture": "must-not-be-disclosed"}})
    rules = 'path "authbus/data/allowed" { capabilities = ["read"] }'
    call("install_policy", "PUT", "sys/policies/acl/" + POLICY_NAME,
         {"policy": rules}, status=204)
    call("install_role", "POST", "auth/approle/role/reader",
         {"token_policies": [POLICY_NAME], "token_ttl": 60,
          "token_max_ttl": 120, "secret_id_ttl": 120,
          "secret_id_num_uses": 1}, status=204)
    role = call("role_id", "GET", "auth/approle/role/reader/role-id")
    role_id = role.get("data", {}).get("role_id")
    check_case = isinstance(role_id, str) and bool(role_id)
    if not check_case:
        raise RuntimeError("role_id_shape")
    issued = call("issue_secret_id", "POST", "auth/approle/role/reader/secret-id", {})
    secret = issued.get("data", {}).get("secret_id")
    if not isinstance(secret, str) or not secret:
        raise RuntimeError("secret_id_shape")
    def login(secret_id: str):
        return request(address, ca, "", "POST", "auth/approle/login",
                       {"role_id": role_id, "secret_id": secret_id})
    status, logged = login(secret)
    bearer = logged.get("auth", {}).get("client_token")
    check("login", status, status == 200 and isinstance(bearer, str) and bool(bearer))
    data = call("read_allowed", "GET", "authbus/data/allowed", caller=bearer)
    if data.get("data", {}).get("data", {}).get("fixture") != "authbus-fresh-271":
        raise RuntimeError("read_allowed_shape")
    blocked_status, blocked_body = request(
        address, ca, bearer, "GET", "authbus/data/blocked",
    )
    check("deny_other_key", blocked_status,
          blocked_status == 403 and "data" not in blocked_body)
    lookup = call("lookup_self", "GET", "auth/token/lookup-self", caller=bearer)
    if not isinstance(lookup.get("data", {}).get("ttl"), int):
        raise RuntimeError("lookup_self_shape")
    renewal = call("renew_self", "POST", "auth/token/renew-self",
                   {"increment": 20}, caller=bearer)
    if not isinstance(renewal.get("auth", {}).get("lease_duration"), int):
        raise RuntimeError("renew_self_shape")
    duplicate_status, duplicate_body = login(secret)
    check("spent_secret_id_denied", duplicate_status,
          duplicate_status in (400, 403)
          and not duplicate_body.get("auth"))
    call("revoke_self", "POST", "auth/token/revoke-self", {}, caller=bearer,
         status=204)
    status, body = request(address, ca, bearer, "GET", "authbus/data/allowed")
    check("revoked_read_denied", status, status == 403 and "data" not in body)
    restart()
    check("restart", None, True)
    status, body = request(address, ca, bearer, "GET", "authbus/data/allowed")
    check("revoked_after_restart", status, status == 403 and "data" not in body)
    fresh = call("new_secret_id", "POST", "auth/approle/role/reader/secret-id", {})
    next_id = fresh.get("data", {}).get("secret_id")
    if not isinstance(next_id, str) or not next_id:
        raise RuntimeError("new_secret_id_shape")
    code, reply = login(next_id)
    next_token = reply.get("auth", {}).get("client_token")
    check("fresh_login_after_restart", code,
          code == 200 and isinstance(next_token, str) and bool(next_token))
    fresh_data = call("fresh_read", "GET", "authbus/data/allowed", caller=next_token)
    if fresh_data.get("data", {}).get("data", {}).get("fixture") != "authbus-fresh-271":
        raise RuntimeError("fresh_read_shape")
    call("fresh_revoke", "POST", "auth/token/revoke-self", {},
         caller=next_token, status=204)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--private-work-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    os.umask(0o077)
    if a.output.exists() or a.private_work_root.exists():
        raise RuntimeError("fixture_or_report_already_exists")
    verify_inputs(version=VERSION)
    before = source_identity(ROOT, a.binary)
    a.private_work_root.mkdir(mode=0o700, parents=False)
    os.environ["HB_ORACLE_WORK_ROOT"] = str(a.private_work_root)
    report = {
        "schema": "heptabao.openbao271-fresh-authbus-https-differential.v1",
        **before, "official_version": VERSION,
        "official_artifact": pinned_artifact(version=VERSION),
        "synthetic_only": True, "tls_verified": True,
        "external_credentials_used": False,
        "independent_qualification": False, "replacement_authority": False,
        "observations": {}, "failures": {},
    }
    for label in ("official", "candidate"):
        instance = None
        oracle = None
        try:
            if label == "official":
                oracle = start_oracle(free_loopback_port(), version=VERSION)
                address, ca = oracle["address"], Path(oracle["ca_file"])
                token = private_read(Path(oracle["token_file"])).decode().strip()
                def restart():
                    stop_oracle(oracle)
                    restart_oracle(oracle)
            else:
                instance = Instance(a.binary, a.private_work_root / "candidate")
                instance.start()
                code, initialized = instance.call(
                    "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1},
                )
                if code != 200:
                    raise RuntimeError("candidate_initialize")
                token, key = initialized["root_token"], initialized["keys_base64"][0]
                instance.token = token
                if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                    raise RuntimeError("candidate_unseal")
                address, ca = instance.address, instance.root / "ca.crt"
                def restart():
                    instance.stop()
                    instance.start()
                    if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                        raise RuntimeError("candidate_reunseal")
            report["observations"][label] = []
            scenario(address, ca, token, restart, report["observations"][label])
        except BaseException as e:
            allowed = set(EXPECTED) | {
                "role_id_shape", "secret_id_shape", "lookup_self_shape",
                "read_allowed_shape", "renew_self_shape", "new_secret_id_shape",
                "fresh_read_shape", "candidate_initialize", "candidate_unseal",
                "candidate_reunseal",
            }
            report["failures"][label] = str(e) if isinstance(e, RuntimeError) and str(e) in allowed else type(e).__name__
        finally:
            if instance is not None:
                instance.stop()
            if oracle is not None:
                stop_oracle(oracle)
    after = source_identity(ROOT, a.binary)
    report["source_and_binary_unchanged"] = before == after
    official = {r["case"]: r for r in report["observations"].get("official", [])}
    candidate = {r["case"]: r for r in report["observations"].get("candidate", [])}
    report["mismatches"] = [
        {"case": k, "official_status": official[k]["status"],
         "candidate_status": candidate[k]["status"]}
        for k in EXPECTED if k in official and k in candidate
        and official[k] != candidate[k]
    ]
    report["status"] = "passed" if (
        not report["failures"] and not report["mismatches"] and before == after
        and all(
            [r["case"] for r in report["observations"].get(label, [])] == list(EXPECTED)
            and all(r["passed"] for r in report["observations"][label])
            for label in ("official", "candidate")
        )
    ) else "failed"
    private_write(a.output, report, replace=False)
    print(json.dumps({
        "status": report["status"], "failures": report["failures"],
        "mismatches": report["mismatches"],
        "source_commit": before["source_commit"],
        "binary_sha256": before["binary_sha256"],
        "replacement_authority": False,
    }))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
