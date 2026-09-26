#!/usr/bin/env python3
"""Candidate batch lease lifecycle against private real PostgreSQL/OpenLDAP.

No OpenBao provider protocol parity or HA claim. Mutations run once. LDAP keeps
its existing 60-second minimum; expiry observation is a bounded read-only wait.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time

from core_isolation import ROOT
from online_evidence import admit_output, complete_checks, publish, source_identity
from postgres_live import Postgres, Instance
from ldap_openldap_live import Directory, private
from openldap_secret_live import BASE, CREATION, DELETION, bind_result, entry_marker, read_entry

REQUIRED = frozenset({"real_provider_ready", "batch_lease_cap", "renew_uses_batch_own_expiry",
    "parent_revocation_provider_cleanup", "orphan_provider_survives_parent_revoke",
    "orphan_provider_survives_restart", "batch_expiry_provider_cleanup",
    "completion_real_provider_observed", "completion_no_secret",
    "completion_cleanup_after_restart", "secrets_absent", "complete"})


class FixtureError(Exception):
    pass


class Trace:
    def __init__(self):
        self.checks = []
        self.case = "setup"
        self.secrets = []
        self.diagnostics = {}

    def check(self, case, passed):
        if not re.fullmatch(r"[a-z0-9_]{1,120}", case) or any(row["case"] == case for row in self.checks):
            raise FixtureError("invalid_case_identity")
        self.case = case
        self.checks.append({"case": case, "passed": passed is True})
        if passed is not True:
            raise FixtureError(case)

    def secret(self, value):
        if isinstance(value, str) and value:
            self.secrets.append(value.encode())
        return value


def wait_read(predicate, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate() is True:
            return True
        time.sleep(.05)
    return False


def no_secret_failure(status, body):
    return (status == 503 and body.get("retry_allowed") is False
            and body.get("reconcile_required") is True and isinstance(body.get("lease_id"), str) and bool(body["lease_id"])
            and not body.get("data") and not body.get("auth") and not body.get("wrap_info"))


def credential(body, trace, kind):
    data = body.get("data", {})
    username, password = data.get("username"), data.get("password")
    lease = body.get("lease_id")
    if not isinstance(lease, str) or not isinstance(username, str) or not isinstance(password, str):
        raise FixtureError("credential_shape")
    trace.secret(password)
    result = dict(lease=lease, username=username, password=password)
    if kind == "openldap":
        dns = data.get("distinguished_names")
        if not isinstance(dns, list) or len(dns) != 1 or not isinstance(dns[0], str):
            raise FixtureError("ldap_credential_shape")
        result["dn"] = dns[0]
    elif not re.fullmatch(r"hbp_[0-9a-f]{32}", username):
        raise FixtureError("pg_username_shape")
    return result


class Provider:
    def __init__(self, kind, instance, root, pg_bin, trace):
        self.kind, self.instance, self.trace = kind, instance, trace
        cert, key, ca = (instance.root / name for name in ("tls.crt", "tls.key", "ca.crt"))
        self.pg = self.directory = self.relay = None
        if kind == "postgres":
            self.pg = Postgres(pg_bin, root / "postgres", cert, key, ca)
            self.pg.start()
            self.pg.install()
            trace.secret(self.pg.password)
            trace.secret(self.pg.manager_password)
            self.origin, self.port, self.server_name = self.pg.origin, self.pg.port, "localhost"
            self.mount, self.path = "database", "database/creds/reader"
        else:
            self.directory = Directory.__new__(Directory)
            self.directory.proc = None
            Directory.__init__(self.directory, root / "directory", cert, key, ca)
            trace.secret(self.directory.admin_password)
            self.origin, self.port, self.server_name = self.directory.origin, self.directory.port, "127.0.0.1"
            self.mount, self.path = "ldap", "ldap/creds/reader"
        trace.check("real_provider_ready", self.pg is not None or bind_result(
            self.directory, self.directory.admin_dn, self.directory.admin_password) == 0)

    def configure(self):
        i, t = self.instance, self.trace
        t.check("mount_provider", i.call("POST", "sys/mounts/" + self.mount,
                {"type": "database" if self.pg else "ldap"})[0] == 204)
        if self.pg:
            t.check("configure_provider", i.call("POST", "database/config/local", dict(
                plugin_name="postgresql-database-plugin", connection_url=self.origin + "/app",
                username="hb_manager", password=self.pg.manager_password, allowed_roles=["reader"]))[0] == 204)
            body = dict(db_name="local", provider_role="app_reader", default_ttl=120, max_ttl=600)
            role_path = "database/roles/reader"
        else:
            t.check("configure_provider", i.call("POST", "ldap/config", dict(url=self.origin,
                binddn=self.directory.admin_dn, bindpass=self.directory.admin_password,
                userdn=BASE, schema="openldap"))[0] == 204)
            body = dict(creation_ldif=CREATION, deletion_ldif=DELETION, default_ttl=120, max_ttl=600)
            role_path = "ldap/role/reader"
        t.check("configure_role", i.call("POST", role_path, body)[0] == 204)

    def login(self, cred):
        if self.pg:
            return self.pg.login(cred["username"], cred["password"])
        return bind_result(self.directory, cred["dn"], cred["password"]) == 0

    def cleaned(self, cred):
        if self.pg:
            result = self.pg.sql("SELECT count(*) FROM pg_roles WHERE rolname='" + cred["username"] + "'")
            return result.returncode == 0 and result.stdout.strip() == "0"
        marker = entry_marker(read_entry(self.directory, cred["dn"]))
        return marker is not None and marker.startswith("hb-tombstone:")

    def close(self):
        try:
            if self.relay:
                self.relay.close()
        finally:
            try:
                if self.pg:
                    self.pg.stop()
            finally:
                if self.directory:
                    self.directory.stop()


def configure_listener(instance, provider, lifecycle=1):
    path = instance.root / "server.json"
    config = json.loads(path.read_text())
    config.update(timeout_seconds=5, lifecycle_interval_seconds=lifecycle,
        outbound_endpoints=[dict(origin=provider.origin, address=f"127.0.0.1:{provider.port}",
            server_name=provider.server_name, path_prefix="/", ca_pem=(instance.root / "ca.crt").read_text()), *getattr(provider, "additional_endpoints", [])])
    private(path, json.dumps(config))


def mint(instance, trace, case, ttl, *, parent=None, orphan=False, batch=True):
    route = "auth/token/create-orphan" if orphan else "auth/token/create"
    body = {"policies": ["lease-owner"], "ttl": ttl}
    if batch:
        body["type"] = "batch"
    status, response = instance.call("POST", route, body, token=parent)
    auth = response.get("auth", {})
    trace.check(case, status == 200 and isinstance(auth.get("client_token"), str)
                and (not batch or auth.get("token_type") == "batch" and auth.get("renewable") is False))
    trace.secret(auth.get("accessor"))
    return trace.secret(auth["client_token"])


def ttl(instance, raw):
    status, response = instance.call("POST", "auth/token/lookup", {"token": raw})
    value = response.get("data", {}).get("ttl")
    if status != 200 or type(value) is not int or value < 0:
        raise FixtureError("token_ttl_lookup")
    return value


def issue(instance, provider, trace, raw, case):
    before = ttl(instance, raw)
    status, response = instance.call("GET", provider.path, token=raw)
    duration = response.get("lease_duration")
    trace.check(case, status == 200 and type(duration) is int and 0 < duration <= before)
    return credential(response, trace, provider.kind)


def renew(instance, trace, case, raw, lease):
    before = ttl(instance, raw)
    status, response = instance.call("POST", "sys/leases/renew", {"lease_id": lease, "increment": 600})
    duration = response.get("lease_duration")
    trace.check(case, status == 200 and type(duration) is int and 0 < duration <= before)
    return duration


def restart(instance, provider, key, trace, case, lifecycle=1):
    instance.stop()
    configure_listener(instance, provider, lifecycle)
    instance.start()
    trace.check(case, instance.call("POST", "sys/unseal", {"key": key})[0] == 200)


def lifecycle(instance, provider, trace, key):
    policy = (f'path "{provider.mount}/creds/*" {{ capabilities=["read"] }}\n'
        'path "auth/token/create" { capabilities=["update"] }\n')
    trace.check("issuer_policy", instance.call("POST", "sys/policies/acl/lease-owner", {"policy": policy})[0] == 204)
    parent = mint(instance, trace, "service_parent", 300, batch=False)
    child = mint(instance, trace, "child_batch", 180, parent=parent)
    orphan = mint(instance, trace, "orphan_batch", 600, orphan=True)
    child_cred = issue(instance, provider, trace, child, "batch_lease_cap")
    orphan_cred = issue(instance, provider, trace, orphan, "orphan_lease_cap")
    trace.check("real_child_credential_login", provider.login(child_cred))
    trace.check("real_orphan_credential_login", provider.login(orphan_cred))
    status, response = instance.call("POST", "auth/token/renew", {"token": parent, "increment": 10})
    trace.check("parent_shortened_but_live", status == 200 and 0 < ttl(instance, parent) <= 10)
    duration = renew(instance, trace, "renew_uses_batch_own_expiry", child, child_cred["lease"])
    trace.check("live_parent_ttl_is_not_batch_lease_cap", duration > 10)
    trace.check("revoke_service_parent", instance.call("POST", "auth/token/revoke", {"token": parent})[0] == 204)
    trace.check("parent_revocation_provider_cleanup", wait_read(lambda: provider.cleaned(child_cred), 15))
    trace.check("revoked_child_credential_denied", not provider.login(child_cred))
    trace.check("revoked_child_bearer_denied", instance.call("GET", "auth/token/lookup-self", token=child)[0] == 403)
    trace.check("orphan_provider_survives_parent_revoke", provider.login(orphan_cred))
    restart(instance, provider, key, trace, "lifecycle_restart")
    trace.check("orphan_provider_survives_restart", provider.login(orphan_cred))
    renew(instance, trace, "orphan_root_renew_cap", orphan, orphan_cred["lease"])
    trace.check("orphan_explicit_cleanup", instance.call("POST", "sys/leases/revoke", {"lease_id": orphan_cred["lease"]})[0] == 204)
    trace.check("orphan_provider_cleaned", provider.cleaned(orphan_cred))
    short = mint(instance, trace, "short_orphan_batch", 62 if provider.directory else 3, orphan=True)
    expired = issue(instance, provider, trace, short, "short_batch_lease_cap")
    trace.check("short_credential_initially_works", provider.login(expired))
    trace.check("batch_expiry_provider_cleanup", wait_read(lambda: provider.cleaned(expired), 77 if provider.directory else 15))
    trace.check("expired_credential_denied", not provider.login(expired))
    trace.check("expired_batch_bearer_denied", instance.call("GET", "auth/token/lookup-self", token=short)[0] == 403)


PG_GATE_SQL = """
ALTER FUNCTION heptabao_provider.observe(text) RENAME TO fixture_original_observe;
CREATE TABLE heptabao_provider.fixture_completion_gate (enabled boolean NOT NULL);
INSERT INTO heptabao_provider.fixture_completion_gate VALUES (true);
REVOKE ALL ON heptabao_provider.fixture_completion_gate FROM PUBLIC;
CREATE FUNCTION heptabao_provider.observe(p_id text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE observed jsonb;
BEGIN
  observed := heptabao_provider.fixture_original_observe(p_id);
  IF (SELECT enabled FROM heptabao_provider.fixture_completion_gate)
     AND observed->>'found'='true' AND observed->>'action'='issue'
     AND current_query() LIKE 'SELECT heptabao_provider.observe%' THEN
    PERFORM pg_sleep(1.2);
  END IF;
  RETURN observed;
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.observe(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION heptabao_provider.observe(text) TO hb_manager;
"""


def postgres_completion(instance, provider, trace, key):
    pg = provider.pg
    restart(instance, provider, key, trace, "completion_worker_paused", lifecycle=60)
    trace.check("completion_real_sql_gate_installed", pg.sql(PG_GATE_SQL).returncode == 0)
    short = mint(instance, trace, "completion_short_batch", 3, orphan=True)
    trace.check("completion_owner_one_second_remaining", wait_read(lambda: ttl(instance, short) == 1, 3.5))
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(instance.call, "GET", provider.path, token=short)
        observed = wait_read(lambda: pg.sql("SELECT count(*) FROM pg_stat_activity WHERE usename='hb_manager' AND wait_event='PgSleep' AND query LIKE 'SELECT heptabao_provider.observe%'").stdout.strip() == "1", 1)
        trace.check("completion_real_provider_observed", observed)
        role = pg.sql("SELECT username FROM heptabao_provider.leases WHERE action='issue' ORDER BY seq DESC LIMIT 1")
        username = role.stdout.strip()
        trace.check("completion_remote_role_committed", role.returncode == 0 and re.fullmatch(r"hbp_[0-9a-f]{32}", username) is not None)
        status, response = future.result(timeout=6)
    trace.check("completion_no_secret", no_secret_failure(status, response))
    lease = response["lease_id"]
    status, lookup = instance.call("POST", "sys/leases/lookup", {"lease_id": lease})
    trace.check("completion_pending_revoke_persisted", status == 200 and lookup.get("data", {}).get("phase") == "PendingRevoke")
    trace.check("completion_gate_disabled", pg.sql("UPDATE heptabao_provider.fixture_completion_gate SET enabled=false").returncode == 0)
    restart(instance, provider, key, trace, "completion_restart")
    trace.check("completion_cleanup_after_restart", wait_read(lambda: provider.cleaned({"username": username}), 15))


def run(args, work, trace):
    instance = provider = None
    try:
        instance = Instance(args.binary, work / "candidate")
        provider = Provider.__new__(Provider)
        Provider.__init__(provider, args.provider, instance, work, args.postgres_bin, trace)
        configure_listener(instance, provider)
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        trace.check("initialize", status == 200)
        instance.token = trace.secret(initialized["root_token"])
        key = trace.secret(initialized["keys_base64"][0])
        trace.check("unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        provider.configure()
        lifecycle(instance, provider, trace, key)
        if provider.pg:
            postgres_completion(instance, provider, trace, key)
        else:
            from batch_provider_ldap_gate import ldap_completion
            ldap_completion(instance, provider, trace, key)
        instance.stop()
        targets = [p for p in (instance.root / "data").rglob("*") if p.is_file()]
        targets.extend(p for p in (instance.root / "audit.jsonl", instance.root / "server.log") if p.exists())
        trace.check("secrets_absent", all(secret not in p.read_bytes() for p in targets for secret in trace.secrets))
        trace.check("complete", True)
    finally:
        if instance is not None:
            instance.stop()
        if provider is not None:
            provider.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--build-source-commit", required=True)
    parser.add_argument("--provider", required=True, choices=("postgres", "openldap"))
    parser.add_argument("--postgres-bin", type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (not re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit)
        or not re.fullmatch(r"[0-9a-f]{64}", args.expected_binary_sha256)
        or not all(p.is_absolute() for p in (args.binary, args.work_dir, args.output))
        or args.work_dir.exists() or args.output.is_relative_to(args.work_dir)
        or args.provider == "postgres" and (args.postgres_bin is None or not args.postgres_bin.is_absolute())):
        parser.error("invalid fixed artifact or private work paths")
    admitted = admit_output(args.output)
    before = source_identity(ROOT, args.binary)
    if before["source_dirty"] or before["binary_sha256"] != args.expected_binary_sha256:
        parser.error("candidate/source identity admission failed")
    args.work_dir.mkdir(mode=0o700)
    trace = Trace()
    report = {"schema": "heptabao.batch-provider-lease-live.v1", "checks": trace.checks,
        "diagnostics": trace.diagnostics, "provider": args.provider, "build_source_commit": args.build_source_commit,
        "build_source_binding": "caller supplied commit, exact candidate binary SHA; distinct from harness source",
        "profile": "candidate real provider; retained LDAP tombstone and operator-installed PG contract, no differential/HA claim",
        "failure": None, "secrets_scope": "candidate data, audit and server logs; provider credential stores remain private"}
    try:
        run(args, args.work_dir, trace)
    except Exception as error:
        report["failure"] = {"case": trace.case, "error_type": type(error).__name__}
    after = source_identity(ROOT, args.binary)
    report["after_identity"] = after
    publish(args.output, admitted, report, before, after, required_cases=REQUIRED)
    if report["status"] == "passed":
        shutil.rmtree(args.work_dir)
    print(json.dumps({"status": report["status"], "check_count": len(trace.checks), "failure": report.get("failure")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
