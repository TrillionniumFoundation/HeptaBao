#!/usr/bin/env python3
"""Bounded P0 observation of the normal native-v6-file TLS credential service.

All credentials are generated in this controller's memory. The launched service
uses only --config, loopback, a private test CA, and an explicit native_v6_file
profile. This is a finite single-node observation, not HA/replacement approval.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "qa" / "openbao-acceptance"), str(REPO / "qa" / "single-node")]
import owned_process
import smoke
from bao_http import private_write
from online_evidence import admit_output, publish, source_identity

CASES = frozenset("""
uninitialized_health initialize_once initialized_sealed sealed_read_denied
wrong_unseal_denied unseal active_health kv2_mount userpass_mount
native_activation formal_native_v6 reader_policy version_one_write
version_two_cas_write historical_version_read current_version_read
stale_cas_rejected stale_cas_keeps_version user_created user_login
user_read wrong_password_denied user_write_denied wrong_path_denied
wrong_namespace_denied invalid_token_denied missing_token_denied denial_audited
expiry_token_created expiry_token_reads expiry_wait_bounded expired_token_denied
revocable_token_created revocable_token_reads token_revoke revoked_token_denied
wrapped_result_withheld wrapped_result_unwrapped wrapped_result_single_use
response_body_discarded original_server_reaped restart_is_sealed
restart_sealed_read_denied restart_unseal restart_formal_profile
user_token_survives_restart historical_version_survives_restart
expired_denial_survives_restart revoked_denial_survives_restart
lost_body_result_recovered recovery_cas_prevents_duplicate audit_parseable
audit_redacts_credentials disk_redacts_credentials diagnostics_redacted
final_server_reaped owned_processes_closed
""".split())


class CheckFailed(Exception):
    pass


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def execute(binary: Path, root: Path, report: dict, check) -> None:
    instance = None
    sensitive: list[str] = []

    def call(name, method, path, body=None, *, expected=200, **kwargs):
        status, result = instance.call(method, path, body, **kwargs)
        allowed = {expected} if type(expected) is int else set(expected)
        report["http_statuses"].append({"case": name, "status": status})
        check(name, status in allowed)
        return result

    def secret_token(result):
        value = result["auth"]["client_token"]
        if not isinstance(value, str) or not value:
            raise CheckFailed("token_shape")
        sensitive.append(value)
        return value

    try:
        instance = smoke.Instance(binary, root / "server")
        config_path = instance.root / "server.json"
        config = json.loads(config_path.read_text())
        config["storage"] = {"native_v6_file": {"path": config["data_dir"]}}
        private_write(config_path, config, replace=True)
        report["service_config_sha256"] = sha(config_path)
        instance.start()
        first_pid = instance.process.pid
        call("uninitialized_health", "GET", "sys/health", expected=501, token="")
        initialized = call("initialize_once", "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}, token="")
        instance.token = initialized["root_token"]
        unseal = initialized["keys_base64"][0]
        sensitive.extend((instance.token, unseal))
        call("initialized_sealed", "GET", "sys/health", expected=503, token="")
        call("sealed_read_denied", "GET", "personal/data/item", expected=503)
        call("wrong_unseal_denied", "POST", "sys/unseal", {"key": "00" * 32}, expected=(400, 403), token="")
        call("unseal", "POST", "sys/unseal", {"key": unseal}, token="")
        call("active_health", "GET", "sys/health", token="")
        call("kv2_mount", "POST", "sys/mounts/personal", {"type": "kv", "options": {"version": "2"}}, expected=204)
        call("userpass_mount", "POST", "sys/auth/personal-user", {"type": "userpass"}, expected=204)
        call("native_activation", "POST", "sys/storage/native-v6/activate", {}, expected=204)
        status, capacity = instance.call("GET", "sys/internal/capacity")
        check("formal_native_v6", status == 200 and capacity.get("data", {}).get("native_kv2_reader_format") == 2)
        call("reader_policy", "PUT", "sys/policies/acl/personal-reader", {
            "policy": 'path "personal/data/item" { capabilities=["read"] }'
        }, expected=204)
        first_value = "synthetic-p0-v1-" + secrets.token_urlsafe(32)
        second_value = "synthetic-p0-v2-" + secrets.token_urlsafe(32)
        recovery_value = "synthetic-p0-recovery-" + secrets.token_urlsafe(32)
        password = "synthetic-p0-password-" + secrets.token_urlsafe(32)
        sensitive.extend((first_value, second_value, recovery_value, password))
        call("version_one_write", "POST", "personal/data/item", {"data": {"value": first_value}, "options": {"cas": 0}})
        call("version_two_cas_write", "POST", "personal/data/item", {"data": {"value": second_value}, "options": {"cas": 1}})
        status, value = instance.call("GET", "personal/data/item?version=1")
        check("historical_version_read", status == 200 and value["data"]["data"]["value"] == first_value)
        status, value = instance.call("GET", "personal/data/item")
        check("current_version_read", status == 200 and value["data"]["data"]["value"] == second_value and value["data"]["metadata"]["version"] == 2)
        call("stale_cas_rejected", "POST", "personal/data/item", {"data": {"value": "synthetic-uncommitted"}, "options": {"cas": 1}}, expected=400)
        status, value = instance.call("GET", "personal/data/item")
        check("stale_cas_keeps_version", status == 200 and value["data"]["data"]["value"] == second_value and value["data"]["metadata"]["version"] == 2)
        call("user_created", "POST", "auth/personal-user/users/test-reader", {
            "password": password, "token_policies": ["personal-reader"], "token_no_default_policy": True,
            "token_ttl": "120s", "token_max_ttl": "120s",
        }, expected=204)
        login = call("user_login", "POST", "auth/personal-user/login/test-reader", {"password": password}, token="")
        user_token = secret_token(login)
        status, value = instance.call("GET", "personal/data/item", token=user_token)
        check("user_read", status == 200 and value["data"]["data"]["value"] == second_value)
        call("wrong_password_denied", "POST", "auth/personal-user/login/test-reader", {"password": "synthetic-wrong-password"}, expected=(400, 403), token="")
        audit_before = len((instance.root / "audit.jsonl").read_bytes().splitlines())
        call("user_write_denied", "POST", "personal/data/item", {"data": {"value": "synthetic-forbidden"}}, token=user_token, expected=403)
        audit_lines = (instance.root / "audit.jsonl").read_bytes().splitlines()
        denial_records = [json.loads(line) for line in audit_lines[audit_before:]]
        check("denial_audited", len(denial_records) >= 2 and any(row.get("event", {}).get("status") == 403 for row in denial_records))
        call("wrong_path_denied", "GET", "personal/data/other", token=user_token, expected=403)
        call("wrong_namespace_denied", "GET", "personal/data/item", token=user_token, namespace="unowned", expected=(403, 404))
        call("invalid_token_denied", "GET", "personal/data/item", token="synthetic-invalid-token", expected=403)
        call("missing_token_denied", "GET", "personal/data/item", token="", expected=403)
        expiry = call("expiry_token_created", "POST", "auth/token/create", {"policies": ["personal-reader"], "no_default_policy": True, "ttl": "2s", "explicit_max_ttl": "2s"})
        expiry_token = secret_token(expiry)
        call("expiry_token_reads", "GET", "personal/data/item", token=expiry_token)
        duration = expiry["auth"]["lease_duration"]
        check("expiry_wait_bounded", type(duration) is int and 0 < duration <= 2)
        # Expiry is the real server clock. This profile does not force time.
        time.sleep(duration + 1)
        report["expiry_wait_seconds"] = duration + 1
        call("expired_token_denied", "GET", "personal/data/item", token=expiry_token, expected=403)
        revocable = call("revocable_token_created", "POST", "auth/token/create", {"policies": ["personal-reader"], "no_default_policy": True, "ttl": "120s"})
        revoke_token = secret_token(revocable)
        call("revocable_token_reads", "GET", "personal/data/item", token=revoke_token)
        call("token_revoke", "POST", "auth/token/revoke", {"token": revoke_token}, expected=204)
        call("revoked_token_denied", "GET", "personal/data/item", token=revoke_token, expected=403)
        status, wrapped = instance.call("GET", "personal/data/item", extra_headers={"X-Vault-Wrap-TTL": "60s"})
        wrapping_token = wrapped.get("wrap_info", {}).get("token", "")
        if wrapping_token:
            sensitive.append(wrapping_token)
        check("wrapped_result_withheld", status == 200 and bool(wrapping_token) and wrapped.get("data") is None and second_value not in json.dumps(wrapped))
        status, unwrapped = instance.call("POST", "sys/wrapping/unwrap", {}, token=wrapping_token)
        check("wrapped_result_unwrapped", status == 200 and unwrapped["data"]["data"]["value"] == second_value)
        call("wrapped_result_single_use", "POST", "sys/wrapping/unwrap", {}, token=wrapping_token, expected=(400, 403))
        # Real HTTPS write; the client deliberately discards the response BODY.
        # We do not describe this as an unknown status: headers were observed.
        request = urllib.request.Request(instance.address + "/v1/personal/data/recovery", method="POST",
            headers={"Content-Type": "application/json", "X-Vault-Token": instance.token},
            data=json.dumps({"data": {"value": recovery_value}, "options": {"cas": 0}}).encode())
        with instance.client.open(request, timeout=10) as response:
            status = response.status
        check("response_body_discarded", status == 200)
        report["lost_response_scope"] = "successful_status_headers_observed_response_body_discarded"
        original = instance.process
        instance.stop()  # Actual SIGKILL; no graceful seal or shutdown.
        check("original_server_reaped", original.returncode == -9)
        instance.start()
        report["server_processes"] = [first_pid, instance.process.pid]
        call("restart_is_sealed", "GET", "sys/health", expected=503, token="")
        call("restart_sealed_read_denied", "GET", "personal/data/item", token=user_token, expected=503)
        call("restart_unseal", "POST", "sys/unseal", {"key": unseal}, token="")
        status, capacity = instance.call("GET", "sys/internal/capacity")
        check("restart_formal_profile", status == 200 and capacity.get("data", {}).get("native_kv2_reader_format") == 2)
        status, value = instance.call("GET", "personal/data/item", token=user_token)
        check("user_token_survives_restart", status == 200 and value["data"]["data"]["value"] == second_value and value["data"]["metadata"]["version"] == 2)
        status, value = instance.call("GET", "personal/data/item?version=1", token=user_token)
        check("historical_version_survives_restart", status == 200 and value["data"]["data"]["value"] == first_value)
        call("expired_denial_survives_restart", "GET", "personal/data/item", token=expiry_token, expected=403)
        call("revoked_denial_survives_restart", "GET", "personal/data/item", token=revoke_token, expected=403)
        status, value = instance.call("GET", "personal/data/recovery")
        check("lost_body_result_recovered", status == 200 and value["data"]["data"]["value"] == recovery_value and value["data"]["metadata"]["version"] == 1)
        call("recovery_cas_prevents_duplicate", "POST", "personal/data/recovery", {"data": {"value": recovery_value}, "options": {"cas": 0}}, expected=400)
        original = instance.process
        instance.stop()
        check("final_server_reaped", original.returncode == -9)
        audit = (instance.root / "audit.jsonl").read_bytes()
        records = [json.loads(line) for line in audit.splitlines()]
        check("audit_parseable", len(records) >= 2 * len(report["http_statuses"]) and all(isinstance(row, dict) for row in records))
        report["audit_record_count"] = len(records)
        check("audit_redacts_credentials", all(value.encode() not in audit for value in sensitive))
        disk_files = [path for path in (instance.root / "data").rglob("*") if path.is_file()]
        check("disk_redacts_credentials", bool(disk_files) and all(value.encode() not in path.read_bytes() for path in disk_files for value in sensitive))
        diagnostics = (instance.root / "server.log").read_bytes() + json.dumps(report).encode()
        check("diagnostics_redacted", all(value.encode() not in diagnostics for value in sensitive))
        report["service_data_file_count"] = len(disk_files)
    finally:
        if instance is not None and instance.process is not None:
            instance.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=REPO)
    parser.add_argument("--work-parent", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if any(not path.is_absolute() for path in (args.binary, args.source_root, args.work_parent, args.report)):
        parser.error("all paths must be absolute")
    binary = args.binary.resolve(strict=True)
    root = args.source_root.resolve(strict=True)
    if root != REPO.resolve():
        parser.error("source root must contain this exact checked-out profile")
    if args.report.is_relative_to(root) or args.work_parent.is_relative_to(root):
        parser.error("work and report directories must be outside the source tree")
    for path in (args.work_parent, args.report.parent):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            parser.error("work and report parents must be owned private directories")
    admitted = admit_output(args.report)
    before = source_identity(root, binary)
    report = {"schema": "heptabao.personal-credentials.p0-service.v1", "checks": [], "http_statuses": [],
        "expected_count": len(CASES), "required_cases": sorted(CASES), "failure": None,
        "scope": "normal_native_v6_file_single_node_loopback_tls_synthetic_credentials",
        "fixture_server_flags": False, "synthetic_credentials_only": True,
        "real_credential_adoption": False, "ha_qualified": False, "full_replacement_qualified": False,
        "source_root": str(root), "binary_path": str(binary), "cargo_lock_sha256": sha(root / "Cargo.lock"),
        "profile_sha256": sha(Path(__file__)), "started_unix_ns": time.time_ns()}

    def check(name, condition):
        if name not in CASES or any(row["case"] == name for row in report["checks"]):
            raise CheckFailed("invalid_case_definition")
        passed = bool(condition)
        report["checks"].append({"case": name, "passed": passed})
        if not passed:
            raise CheckFailed(name)

    owner = owned_process.Owner(args.work_parent, profile="method_control")
    try:
        with owned_process.activated(owner):
            execute(binary, owner.root, report, check)
        check("owned_processes_closed", owner.receipt["passed_process_method"] is True)
    except BaseException as error:
        report["failure"] = str(error) if isinstance(error, CheckFailed) else type(error).__name__
    report["original_process_receipt"] = str(owner.root / "original-process-receipt.json")
    report["original_process_receipt_sha256"] = sha(owner.root / "original-process-receipt.json")
    report["passed_count"] = sum(row["passed"] for row in report["checks"])
    report["missing_cases"] = sorted(CASES - {row["case"] for row in report["checks"]})
    report["finished_unix_ns"] = time.time_ns()
    after = source_identity(root, binary)
    publish(args.report, admitted, report, before, after, len(CASES), required_cases=CASES)
    print(json.dumps({key: report.get(key) for key in ("status", "passed_count", "expected_count", "failure", "source_commit", "binary_sha256")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"status": "controller_failed", "error_class": type(error).__name__}), file=sys.stderr)
        raise SystemExit(1) from None
