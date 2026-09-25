#!/usr/bin/env python3
"""Exercise bounded LDAP dynamic secrets against an isolated real slapd.

All TLS keys, LDAP data and synthetic credentials live in --work-dir, which must
be a new absolute directory on the test volume. The redacted receipt records
scoped behavior only; the retained tombstone is not OpenBao delete parity.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

from ldap_openldap_live import Directory, private, openldap_paths, openldap_environment

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/single-node"))
from smoke import Instance


BASE = "ou=people,dc=example,dc=test"
CREATION = """dn: uid={{.Username}},ou=people,dc=example,dc=test
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: {{.Username}}
sn: Synthetic
uid: {{.Username}}
userPassword: {{.Password}}
"""
DELETION = """dn: uid={{.Username}},ou=people,dc=example,dc=test
changetype: delete
"""


def command(directory: Directory, tool: str, *arguments: str, dn=None, password=None):
    """Pass secrets by an inherited pipe, never a file, argv or environment."""
    read_fd, write_fd = os.pipe()
    try:
        secret = directory.admin_password if password is None else password
        stream = os.fdopen(write_fd, "wb")
        write_fd = -1  # Ownership moved before write/flush, including failures.
        with stream:
            stream.write(secret.encode("utf-8"))
        return subprocess.run(
            [tool, "-x", "-H", directory.origin, "-D", dn or directory.admin_dn,
             "-y", "/dev/fd/" + str(read_fd), "-o", "nettimeout=3", *arguments],
            env=directory.ldap_env, capture_output=True, text=True, timeout=6,
            pass_fds=(read_fd,),
        )
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)


def bind_result(directory: Directory, dn: str, password: str) -> int:
    return command(directory, "ldapwhoami", dn=dn, password=password).returncode


def read_entry(directory: Directory, dn: str):
    result = command(directory, "ldapsearch", "-LLL", "-o", "ldif-wrap=no",
                     "-b", dn, "-s", "base", "(objectClass=*)",
                     "dn", "description", "userPassword", "entryUUID")
    if result.returncode == 32:
        return None
    if result.returncode != 0:
        raise RuntimeError("ldap_readback_failed")
    if len(result.stdout) > 64 * 1024:
        raise RuntimeError("ldap_readback_exceeds_bound")
    attributes: dict[str, list[str]] = {}
    for line in result.stdout.splitlines():
        if not line or line.startswith("#"):
            continue
        if ": " not in line:
            raise RuntimeError("ldap_readback_invalid_ldif")
        name, value = line.split(": ", 1)
        if name.endswith(":"):
            name = name[:-1]
            value = base64.b64decode(value, validate=True).decode("utf-8")
        attributes.setdefault(name.lower(), []).append(value)
    if len(attributes.get("dn", [])) != 1:
        raise RuntimeError("ldap_readback_not_one_entry")
    return attributes


def entry_marker(entry):
    values = [] if entry is None else entry.get("description", [])
    if len(values) != 1 or re.fullmatch(r"hb-(request|tombstone):[0-9a-f]{64}", values[0]) is None:
        return None
    return values[0]


def wait_until(predicate, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.25)
    return False


def write_receipt(path: Path, report) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "w") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not all(path.is_absolute() for path in (args.binary, args.work_dir, args.output)):
        parser.error("binary, work-dir and output must be absolute")
    if args.output.resolve().is_relative_to(args.work_dir.resolve()):
        parser.error("output must be outside the disposable work-dir")
    if args.output.exists():
        parser.error("output must not already exist")

    checks = []
    report = {
        "schema": "heptabao.openldap-secret-live.v1",
        "status": "failed", "checks": checks,
        "candidate_binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "candidate_binary_source_head": subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
            capture_output=True, check=True).stdout.strip(),
        "source_worktree_dirty": bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True,
            capture_output=True, check=True).stdout.strip()),
        "execution_platform": platform.platform(),
        "actual_slapd_distribution": True,
        "tls_verification": "Pinned fixture CA, loopback IP SAN, LDAPTLS_REQCERT=demand",
        "revocation_profile": "Retained per-DN tombstone prevents delayed Add from recreating the issued identity",
        "independent_qualification": False,
        "full_openbao_parity": False,
        "production_authority": False,
        "uncovered": [
            "OpenBao 2.6.2 differential and actual delete semantics",
            "Static roles, root rotation, library checkout, AD and RACF schemas",
            "Multi-host HA and provider replication/failover",
            "Lost Add/Modify reply fault injection and physical power/disk faults",
            "Existing bound LDAP session authority after password rotation",
            "Tombstone garbage collection and unbounded deployment churn",
        ],
    }
    missing = [tool for tool in ("ldapadd", "ldapsearch", "ldapwhoami", "openssl")
               if shutil.which(tool) is None]
    try:
        executable, _, _, private_prerequisite = openldap_paths()
    except (OSError, ValueError):
        missing.append("safe_openldap_prerequisite")
    if missing:
        report.update(status="blocked", missing_dependencies=missing,
                      actual_slapd_distribution=False)
        write_receipt(args.output, report)
        return 77
    version = subprocess.run([str(executable), "-VV"], capture_output=True, text=True, timeout=5,
                             env=openldap_environment(executable, private_prerequisite))
    report["openldap_distribution"] = (version.stdout + version.stderr).splitlines()[0][:300]
    args.work_dir.mkdir(mode=0o700, exist_ok=False)
    instance = None
    directory = Directory.__new__(Directory)
    sensitive = []
    current_case = "fixture_setup"

    def check(name, condition):
        nonlocal current_case
        current_case = name
        checks.append({"case": name, "passed": bool(condition)})
        if not condition:
            raise RuntimeError(name)

    try:
        instance = Instance(args.binary, args.work_dir / "candidate")
        Directory.__init__(directory, args.work_dir / "openldap",
                           instance.root / "tls.crt", instance.root / "tls.key",
                           instance.root / "ca.crt")
        sensitive.append(directory.admin_password)
        check("real_openldap_manager_bind", bind_result(directory, directory.admin_dn,
                                                       directory.admin_password) == 0)
        config_path = instance.root / "server.json"
        config = json.loads(config_path.read_text())
        config["outbound_endpoints"] = [{
            "origin": directory.origin, "address": f"127.0.0.1:{directory.port}",
            "server_name": "127.0.0.1", "path_prefix": "/",
            "ca_pem": (instance.root / "ca.crt").read_text(),
        }]
        config["lifecycle_interval_seconds"] = 1
        private(config_path, json.dumps(config))
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("initialize", status == 200)
        instance.token = initialized["root_token"]
        key = initialized["keys_base64"][0]
        check("unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("mount_ldap_secrets", instance.call("POST", "sys/mounts/ldap", {"type": "ldap"})[0] == 204)
        manager_config = {"url": directory.origin, "binddn": directory.admin_dn,
                          "bindpass": directory.admin_password, "userdn": BASE, "schema": "openldap"}
        check("configure_real_ldap_secrets", instance.call("POST", "ldap/config", manager_config)[0] == 204)
        status, read = instance.call("GET", "ldap/config")
        check("config_readback_redacts_manager_password",
              status == 200 and read.get("data", {}).get("userdn") == BASE
              and directory.admin_password not in json.dumps(read) and "bindpass" not in read.get("data", {}))
        check("unauthorized_config_denied", instance.call("POST", "ldap/config", manager_config, token="invalid-synthetic")[0] == 403)
        role = {"creation_ldif": CREATION, "deletion_ldif": DELETION,
                "default_ttl": 180, "max_ttl": 600}
        check("create_dynamic_role", instance.call("POST", "ldap/role/app", role)[0] == 204)
        short_role = dict(role, default_ttl=60, max_ttl=120)
        check("create_expiring_role", instance.call("POST", "ldap/role/short", short_role)[0] == 204)
        escape_role = dict(role, creation_ldif=CREATION.replace("ou=people", "ou=groups"),
                           deletion_ldif=DELETION.replace("ou=people", "ou=groups"))
        status, _ = instance.call("POST", "ldap/role/escape", escape_role)
        if status == 204:
            status, _ = instance.call("GET", "ldap/creds/escape")
        check("outside_userdn_rejected", status == 400)
        policy = ('path "ldap/creds/*" { capabilities = ["read"] }\n'
                  'path "sys/leases/renew" { capabilities = ["update", "sudo"] }')
        check("issuer_policy", instance.call("POST", "sys/policies/acl/ldap-issuer", {"policy": policy})[0] == 204)
        status, token = instance.call("POST", "auth/token/create", {"policies": ["ldap-issuer"], "ttl": "1h"})
        check("issuer_token", status == 200)
        issuer = token["auth"]["client_token"]
        status, token = instance.call("POST", "auth/token/create", {"policies": ["ldap-issuer"], "ttl": "1h"})
        check("other_issuer_token", status == 200)
        other_issuer = token["auth"]["client_token"]

        def issue(role_name, case):
            status, response = instance.call("GET", "ldap/creds/" + role_name, token=issuer)
            data = response.get("data", {})
            check(case, status == 200 and bool(response.get("lease_id"))
                  and bool(data.get("username")) and bool(data.get("password"))
                  and len(data.get("distinguished_names", [])) == 1)
            sensitive.append(data["password"])
            return response["lease_id"], data["username"], data["password"], data["distinguished_names"][0]

        lease, username, password, dn = issue("app", "issue_actual_directory_credential")
        check("issued_password_binds_real_openldap", bind_result(directory, dn, password) == 0)
        check("incorrect_password_is_ldap49", bind_result(directory, dn, password + "wrong") == 49)
        entry = read_entry(directory, dn)
        marker = entry_marker(entry)
        check("issued_entry_has_request_marker", marker is not None and marker.startswith("hb-request:")
              and len(entry.get("entryuuid", [])) == 1)
        uuid = entry["entryuuid"]
        tombstone = marker.replace("hb-request:", "hb-tombstone:", 1)
        check("other_issuer_cannot_renew", instance.call("POST", "sys/leases/renew",
              {"lease_id": lease, "increment": 300}, token=other_issuer)[0] in (403, 409))
        status, renewed = instance.call("POST", "sys/leases/renew", {"lease_id": lease, "increment": 300}, token=issuer)
        check("owner_renews_active_lease", status == 200 and renewed.get("lease_duration", 0) >= 299)
        directory.stop()
        directory.start()
        check("credential_survives_provider_restart", bind_result(directory, dn, password) == 0)
        instance.stop()
        instance.start()
        check("service_restart_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("config_survives_restart", instance.call("GET", "ldap/config")[1].get("data", {}).get("userdn") == BASE)
        check("role_survives_restart", instance.call("GET", "ldap/role/app")[0] == 200)
        check("renew_after_both_restarts", instance.call("POST", "sys/leases/renew",
              {"lease_id": lease, "increment": 300}, token=issuer)[0] == 200)
        check("revoke_actual_directory_credential", instance.call("POST", "sys/leases/revoke", {"lease_id": lease})[0] == 204)
        check("revoked_password_is_ldap49", bind_result(directory, dn, password) == 49)
        entry = read_entry(directory, dn)
        check("revoke_retains_same_entry_tombstone", entry_marker(entry) == tombstone and entry["entryuuid"] == uuid)
        stale = directory.root / "stale-add.ldif"
        private(stale, CREATION.replace("{{.Username}}", username).replace("{{.Password}}", password))
        check("delayed_add_blocked_by_tombstone", command(directory, "ldapadd", "-f", str(stale)).returncode == 68)
        check("delayed_add_cannot_restore_password", bind_result(directory, dn, password) == 49)
        directory.stop()
        directory.start()
        check("tombstone_survives_provider_restart", entry_marker(read_entry(directory, dn)) == tombstone)
        check("revoked_password_denied_after_provider_restart", bind_result(directory, dn, password) == 49)

        pending_lease, _, pending_password, pending_dn = issue("app", "issue_before_provider_outage")
        pending_marker = entry_marker(read_entry(directory, pending_dn))
        directory.stop()
        status, pending = instance.call("POST", "sys/leases/revoke", {"lease_id": pending_lease})
        check("provider_outage_retains_revoke_intent", status == 503 and pending.get("reconcile_required") is True
              and pending.get("lease_id") == pending_lease and not pending.get("data"))
        instance.stop()
        directory.start()
        instance.start()
        check("pending_revoke_restart_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        expected_pending_marker = pending_marker.replace("hb-request:", "hb-tombstone:", 1)
        check("restart_reconciles_pending_revoke", wait_until(
            lambda: entry_marker(read_entry(directory, pending_dn)) == expected_pending_marker, 15))
        check("reconciled_password_is_ldap49", bind_result(directory, pending_dn, pending_password) == 49)

        expiry_lease, _, expiry_password, expiry_dn = issue("short", "issue_for_idle_expiry")
        expiry_marker = entry_marker(read_entry(directory, expiry_dn))
        check("short_credential_initially_usable", bind_result(directory, expiry_dn, expiry_password) == 0)
        expected_expiry_marker = expiry_marker.replace("hb-request:", "hb-tombstone:", 1)
        # No HeptaBao request drives this interval: only the host-owned lifecycle
        # worker can turn the durable lease into an external directory revoke.
        check("idle_expiry_retains_native_tombstone", wait_until(
            lambda: entry_marker(read_entry(directory, expiry_dn)) == expected_expiry_marker, 75))
        check("expired_password_is_ldap49", bind_result(directory, expiry_dn, expiry_password) == 49)
        check("expired_lease_cannot_renew", instance.call("POST", "sys/leases/renew",
              {"lease_id": expiry_lease, "increment": 120}, token=issuer)[0] in (400, 403, 404, 409))
        instance.stop()
        directory.stop()
        directory.start()
        instance.start()
        check("final_both_restart_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("expiry_denial_survives_both_restarts", bind_result(directory, expiry_dn, expiry_password) == 49
              and entry_marker(read_entry(directory, expiry_dn)) == expected_expiry_marker)
        check("reconciled_denial_survives_both_restarts", bind_result(directory, pending_dn, pending_password) == 49
              and entry_marker(read_entry(directory, pending_dn)) == expected_pending_marker)
        plaintexts = [value.encode() for value in sensitive]
        check("candidate_storage_contains_no_plaintext_credentials", all(
            all(secret not in path.read_bytes() for secret in plaintexts)
            for path in (instance.root / "data").rglob("*") if path.is_file()))
        audit = (instance.root / "audit.jsonl").read_bytes()
        check("candidate_audit_redacts_credentials", all(secret not in audit for secret in plaintexts))
        report["status"] = "passed"
    except Exception as error:
        report["failure"] = {"case": current_case, "error_type": type(error).__name__}
    finally:
        if getattr(directory, "proc", None) is not None:
            directory.stop()
        if instance is not None:
            instance.stop()
        report["check_count"] = len(checks)
        write_receipt(args.output, report)
        shutil.rmtree(args.work_dir)
    print(json.dumps({"status": report["status"], "check_count": len(checks)}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
