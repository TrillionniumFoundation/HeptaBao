#!/usr/bin/env python3
"""Exercise bounded OpenBao 2.6.2 PostgreSQL statement templates on PostgreSQL 17.

The fixture creates a new loopback cluster and synthetic generated users. It
validates the Service-owned durable intent, provider transaction/readback and
recovery boundary. It is scoped evidence, not complete database compatibility.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/openbao-acceptance"))
sys.path.insert(0, str(ROOT / "qa/single-node"))
from database_config_completion_live import source_identity
from postgres_live import Postgres
from smoke import Instance


REQUIRED_CASES = frozenset({
    "statement_protocol_available", "manager_cannot_mutate_statement_ledger",
    "statement_ledger_has_no_plaintext_columns", "upgrade_database_created",
    "legacy_v2_installed", "static_root_extension_installed_first",
    "manager_cannot_install_statement_extension", "owner_installs_statement_extension",
    "fresh_and_upgrade_statement_extensions_match", "application_table_created",
    "create_statement_role", "statement_role_readback",
    "statement_partial_update_preserves_templates",
    "unsupported_credential_type_rejected", "nonempty_credential_config_rejected",
    "provider_role_statement_mix_rejected", "unknown_placeholder_rejected",
    "statement_issue_returns_credential", "issued_statement_password_logs_in",
    "issued_role_can_select_granted_table", "issued_role_cannot_insert",
    "statement_provider_ledger_observed", "statement_digest_binds_exact_rendered_templates",
    "semantic_reencoding_conflicts", "legacy_effect_advances_shared_floor",
    "exact_statement_retry_survives_later_global_floor",
    "exact_retry_did_not_replace_role_identity", "statement_renewal",
    "renewal_preserves_password", "statement_renewal_readback",
    "service_restart_unseal", "statement_lease_survives_restart",
    "statement_revoke", "revoked_statement_role_absent",
    "statement_provider_row_retired", "create_default_revoke_role",
    "default_revoke_issue", "manager_cannot_call_default_revoke_outside_ledger",
    "default_revoke_completes", "create_broken_statement_role",
    "failed_creation_is_indeterminate_not_success",
    "failed_creation_rolls_back_role_and_ledger",
    "candidate_storage_contains_no_statement_passwords",
    "candidate_audit_contains_no_statement_passwords",
    "provider_ledger_contains_no_statement_text",
})


class FixtureFailure(RuntimeError):
    pass


def require(value, code):
    if value is not True:
        raise FixtureFailure(code)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def quote(value: str) -> str:
    if not isinstance(value, str) or "\0" in value or len(value) > 128 * 1024:
        raise FixtureFailure("unsafe_fixture_sql_value")
    return "'" + value.replace("'", "''") + "'"


def row(pg: Postgres, query: str, *, database: str = "app") -> list[str]:
    result = pg.sql(query, database=database)
    require(result.returncode == 0, "operator_readback_failed")
    return result.stdout.strip().split("|") if result.stdout.strip() else []


def manager_call(pg: Postgres, query: str, *, database: str = "app"):
    return pg.sql(query, user="hb_manager", password=pg.manager_password, database=database)


def role_query(pg: Postgres, username: str, password: str, query: str):
    return pg.sql(query, user=username, password=password, database="app")


def configure(instance: Instance, pg: Postgres):
    path = instance.root / "server.json"
    config = json.loads(path.read_text())
    config["lifecycle_interval_seconds"] = 0
    config["outbound_endpoints"] = [{
        "origin": pg.origin,
        "address": f"127.0.0.1:{pg.port}",
        "server_name": "localhost",
        "ca_pem": (instance.root / "ca.crt").read_text(),
    }]
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
    require(status == 200, "initialize")
    instance.token = initialized["root_token"]
    key = initialized["keys_base64"][0]
    require(instance.call("POST", "sys/unseal", {"key": key})[0] == 200, "unseal")
    require(instance.call("POST", "sys/mounts/database", {"type": "database"})[0] == 204, "mount")
    connection = {
        "plugin_name": "postgresql-database-plugin",
        "connection_url": pg.origin + "/app",
        "username": "hb_manager",
        "password": pg.manager_password,
        "allowed_roles": ["templated", "defaulted", "broken", "legacy"],
    }
    require(instance.call("POST", "database/config/local", connection)[0] == 204, "configure")
    require(instance.call("POST", "database/roles/legacy", {
        "db_name": "local", "provider_role": "app_reader", "default_ttl": 60, "max_ttl": 300,
    })[0] == 204, "legacy_role")
    return key


def statement_extension(path: Path) -> str:
    source = path.read_text()
    start = source.index("-- PostgreSQL statement-template extension.")
    end = source.index("COMMIT;", start)
    return source[start:end]


def run(binary: Path, postgres_bin: Path, work: Path, output: Path) -> int:
    os.umask(0o077)
    before = source_identity(ROOT)
    binary_hash = digest(binary)
    runner_hash = digest(Path(__file__))
    checks = []
    sensitive = []
    current_case = "setup"
    instance = Instance(binary, work / "candidate")
    pg = None

    def check(name, condition):
        nonlocal current_case
        current_case = name
        checks.append({"case": name, "passed": condition is True})
        require(condition is True, name)

    try:
        pg = Postgres(postgres_bin, work / "postgres", instance.root / "tls.crt",
                      instance.root / "tls.key", instance.root / "ca.crt")
        pg.start(); pg.install()
        check("statement_protocol_available", manager_call(
            pg, "SELECT heptabao_provider.statement_protocol()"
        ).stdout.strip() == "heptabao-postgresql-statements-v1")
        check("manager_cannot_mutate_statement_ledger", manager_call(
            pg, "DELETE FROM heptabao_provider.statement_leases"
        ).returncode != 0)
        check("statement_ledger_has_no_plaintext_columns", row(pg,
            "SELECT string_agg(column_name,',' ORDER BY ordinal_position) FROM information_schema.columns "
            "WHERE table_schema='heptabao_provider' AND table_name='statement_leases'"
        ) == ["manager,fence_id,lease_id,username,seq,action,expires,request_digest,statements_digest,password_digest,role_oid,payload_digest"])

        # Exercise the actual v2 -> static/root -> statement forward path.
        check("upgrade_database_created", pg.sql(
            "CREATE DATABASE statement_upgrade", database="postgres"
        ).returncode == 0)
        legacy = ROOT / "qa/openbao-acceptance/fixtures/postgresql-provider-v2-legacy.sql"
        check("legacy_v2_installed", pg.sql(legacy.read_text(), database="statement_upgrade").returncode == 0)
        static_upgrade = ROOT / "bootstrap/postgresql/upgrade_v2_static_credentials.sql"
        check("static_root_extension_installed_first", pg.sql(
            static_upgrade.read_text(), database="statement_upgrade"
        ).returncode == 0)
        statement_upgrade = ROOT / "bootstrap/postgresql/upgrade_v3_statement_templates.sql"
        check("manager_cannot_install_statement_extension", pg.sql(
            statement_upgrade.read_text(), user="hb_manager", password=pg.manager_password,
            database="statement_upgrade"
        ).returncode != 0)
        check("owner_installs_statement_extension", pg.sql(
            statement_upgrade.read_text(), database="statement_upgrade"
        ).returncode == 0)
        check("fresh_and_upgrade_statement_extensions_match", statement_extension(
            ROOT / "bootstrap/postgresql/provider.sql"
        ) == statement_extension(statement_upgrade))

        check("application_table_created", pg.sql(
            "CREATE TABLE public.items(id integer PRIMARY KEY,value text NOT NULL);"
            "INSERT INTO public.items VALUES(1,'visible');"
        ).returncode == 0)
        key = configure(instance, pg)

        creation = [
            "DO $body$ BEGIN PERFORM 1; END $body$;",
            "CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"
            "GRANT CONNECT ON DATABASE app TO \"{{name}}\";"
            "GRANT USAGE ON SCHEMA public TO \"{{name}}\";"
            "GRANT SELECT ON TABLE public.items TO \"{{name}}\";",
        ]
        renewal = ["ALTER ROLE \"{{name}}\" VALID UNTIL '{{expiration}}'"]
        revocation = [
            "ALTER ROLE \"{{name}}\" NOLOGIN VALID UNTIL '1970-01-01 00:00:00+00';"
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='{{name}}' AND pid<>pg_backend_pid();"
            "REVOKE SELECT ON TABLE public.items FROM \"{{name}}\";"
            "REVOKE USAGE ON SCHEMA public FROM \"{{name}}\";"
            "REVOKE CONNECT ON DATABASE app FROM \"{{name}}\";"
            "DROP ROLE IF EXISTS \"{{name}}\";"
        ]
        rollback = ["DROP ROLE IF EXISTS \"{{name}}\""]
        body = {
            "db_name": "local", "creation_statements": creation,
            "renew_statements": renewal, "revocation_statements": revocation,
            "rollback_statements": rollback, "credential_type": "password",
            "credential_config": {}, "default_ttl": 60, "max_ttl": 300,
        }
        check("create_statement_role", instance.call(
            "POST", "database/roles/templated", body
        )[0] == 204)
        status, readback = instance.call("GET", "database/roles/templated")
        data = readback.get("data", {})
        check("statement_role_readback", status == 200
              and data.get("creation_statements") == creation
              and data.get("renew_statements") == renewal
              and data.get("revocation_statements") == revocation
              and data.get("rollback_statements") == rollback
              and data.get("credential_type") == "password"
              and data.get("credential_config") == {}
              and "provider_role" not in data)
        check("statement_partial_update_preserves_templates", instance.call(
            "POST", "database/roles/templated", {"max_ttl": 600}
        )[0] == 204 and instance.call("GET", "database/roles/templated")[1]
            .get("data", {}).get("creation_statements") == creation)
        for name, invalid in (
            ("unsupported_credential_type_rejected", {"credential_type": "rsa_private_key"}),
            ("nonempty_credential_config_rejected", {"credential_config": {"password_policy": "external"}}),
            ("provider_role_statement_mix_rejected", {"provider_role": "app_reader"}),
            ("unknown_placeholder_rejected", {"creation_statements": ["SELECT '{{unknown}}'"]}),
        ):
            check(name, instance.call("POST", "database/roles/templated", invalid)[0] == 400)

        status, issued = instance.call("GET", "database/creds/templated")
        lease_id = issued.get("lease_id")
        username = issued.get("data", {}).get("username")
        password = issued.get("data", {}).get("password")
        check("statement_issue_returns_credential", status == 200
              and isinstance(lease_id, str)
              and isinstance(username, str)
              and re.fullmatch(r"hbp_[0-9a-f]{32}", username) is not None
              and isinstance(password, str)
              and re.fullmatch(r"[0-9a-f]{64}", password) is not None)
        sensitive.append(password)
        check("issued_statement_password_logs_in", pg.login(username, password))
        check("issued_role_can_select_granted_table", role_query(
            pg, username, password, "SELECT value FROM public.items WHERE id=1"
        ).stdout.strip() == "visible")
        check("issued_role_cannot_insert", role_query(
            pg, username, password, "INSERT INTO public.items VALUES(2,'denied')"
        ).returncode != 0)

        provider_id = row(pg, "SELECT lease_id FROM heptabao_provider.statement_leases "
                          "WHERE username=" + quote(username))[0]
        ledger = row(pg, "SELECT fence_id,seq,action,expires,request_digest,statements_digest,role_oid "
                     "FROM heptabao_provider.statement_leases WHERE lease_id=" + quote(provider_id))
        check("statement_provider_ledger_observed", len(ledger) == 7
              and re.fullmatch(r"hbf1:[0-9a-f]{64}", ledger[0]) is not None
              and ledger[2] == "issue"
              and re.fullmatch(r"[0-9a-f]{64}", ledger[4]) is not None
              and re.fullmatch(r"[0-9a-f]{64}", ledger[5]) is not None)
        fence, issue_seq, _, issue_expires, issue_digest, _, _ = ledger

        # Another provider effect overtakes the global floor; exact issue replay
        # remains read-only and cannot execute statements twice.
        check("legacy_effect_advances_shared_floor", instance.call(
            "GET", "database/creds/legacy"
        )[0] == 200)
        templates = [
            "DO $body$ BEGIN PERFORM 1; END $body$",
            "CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'",
            "GRANT CONNECT ON DATABASE app TO \"{{name}}\"",
            "GRANT USAGE ON SCHEMA public TO \"{{name}}\"",
            "GRANT SELECT ON TABLE public.items TO \"{{name}}\"",
        ]
        encoded_templates = json.dumps(templates, separators=(",", ":"), ensure_ascii=False)
        expected_statements_digest = hashlib.sha256(encoded_templates.encode()).hexdigest()
        check("statement_digest_binds_exact_rendered_templates", ledger[5] == expected_statements_digest)
        retry = "SELECT heptabao_provider.apply_statements(" + ",".join([
            quote(fence), quote(provider_id), quote(username), issue_seq + "::bigint",
            "'issue'", issue_expires + "::bigint", quote(password), quote(issue_digest),
            quote(encoded_templates) + "::text",
        ]) + ")::text"
        check("exact_statement_retry_survives_later_global_floor", manager_call(
            pg, retry
        ).returncode == 0)
        reencoded_templates = json.dumps(templates, indent=1, ensure_ascii=False)
        require(reencoded_templates != encoded_templates
                and json.loads(reencoded_templates) == templates,
                "semantic_reencoding_fixture")
        conflicting_retry = "SELECT heptabao_provider.apply_statements(" + ",".join([
            quote(fence), quote(provider_id), quote(username), issue_seq + "::bigint",
            "'issue'", issue_expires + "::bigint", quote(password), quote(issue_digest),
            quote(reencoded_templates) + "::text",
        ]) + ")::text"
        check("semantic_reencoding_conflicts", manager_call(
            pg, conflicting_retry
        ).returncode != 0)
        check("exact_retry_did_not_replace_role_identity", row(pg,
            "SELECT count(*) FROM pg_roles WHERE rolname=" + quote(username)
        ) == ["1"] and pg.login(username, password))

        status, renewed = instance.call("POST", "sys/leases/renew", {
            "lease_id": lease_id, "increment": 180,
        })
        check("statement_renewal", status == 200 and renewed.get("lease_duration", 0) >= 179)
        check("renewal_preserves_password", pg.login(username, password))
        renewed_row = row(pg, "SELECT seq,action,expires FROM heptabao_provider.statement_leases "
                          "WHERE lease_id=" + quote(provider_id))
        check("statement_renewal_readback", len(renewed_row) == 3
              and int(renewed_row[0]) > int(issue_seq) and renewed_row[1] == "renew")

        instance.stop(); instance.start()
        check("service_restart_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("statement_lease_survives_restart", instance.call(
            "POST", "sys/leases/lookup", {"lease_id": lease_id}
        )[0] == 200 and pg.login(username, password))
        check("statement_revoke", instance.call(
            "POST", "sys/leases/revoke", {"lease_id": lease_id}
        )[0] == 204)
        check("revoked_statement_role_absent", not pg.login(username, password)
              and row(pg, "SELECT count(*) FROM pg_roles WHERE rolname=" + quote(username)) == ["0"])
        check("statement_provider_row_retired", row(pg,
            "SELECT count(*) FROM heptabao_provider.statement_leases WHERE lease_id=" + quote(provider_id)
        ) == ["0"])

        # Empty custom revocation selects the bounded provider default cleanup.
        default_body = dict(body)
        default_body.pop("revocation_statements")
        check("create_default_revoke_role", instance.call(
            "POST", "database/roles/defaulted", default_body
        )[0] == 204)
        status, defaulted = instance.call("GET", "database/creds/defaulted")
        default_lease = defaulted.get("lease_id")
        default_user = defaulted.get("data", {}).get("username")
        default_password = defaulted.get("data", {}).get("password")
        check("default_revoke_issue", status == 200 and pg.login(default_user, default_password))
        sensitive.append(default_password)
        check("manager_cannot_call_default_revoke_outside_ledger", manager_call(
            pg, "SELECT heptabao_provider.default_statement_revoke(" + quote(default_user) + "::name)"
        ).returncode != 0 and pg.login(default_user, default_password))
        check("default_revoke_completes", instance.call(
            "POST", "sys/leases/revoke", {"lease_id": default_lease}
        )[0] == 204 and not pg.login(default_user, default_password))

        # PostgreSQL creation is one transaction. A late statement failure leaves
        # neither a generated role nor a provider ledger success row.
        broken = dict(body)
        broken["creation_statements"] = [
            "CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';SELECT 1/0"
        ]
        check("create_broken_statement_role", instance.call(
            "POST", "database/roles/broken", broken
        )[0] == 204)
        before_roles = int(row(pg, "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'hbp_%'")[0])
        before_rows = int(row(pg, "SELECT count(*) FROM heptabao_provider.statement_leases")[0])
        status, failure = instance.call("GET", "database/creds/broken")
        check("failed_creation_is_indeterminate_not_success", status == 503
              and failure.get("reconcile_required") is True)
        check("failed_creation_rolls_back_role_and_ledger", int(row(pg,
            "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'hbp_%'"
        )[0]) == before_roles and int(row(pg,
            "SELECT count(*) FROM heptabao_provider.statement_leases"
        )[0]) == before_rows)

        plaintexts = [value.encode() for value in sensitive if value]
        check("candidate_storage_contains_no_statement_passwords", all(
            all(secret not in path.read_bytes() for secret in plaintexts)
            for path in (instance.root / "data").rglob("*") if path.is_file()
        ))
        audit = (instance.root / "audit.jsonl").read_bytes()
        check("candidate_audit_contains_no_statement_passwords", all(
            secret not in audit for secret in plaintexts
        ))
        check("provider_ledger_contains_no_statement_text", row(pg,
            "SELECT count(*) FROM information_schema.columns WHERE table_schema='heptabao_provider' "
            "AND table_name='statement_leases' AND column_name LIKE '%statement%'"
        ) == ["1"])

        actual_cases = {row["case"] for row in checks}
        check("required_case_set_complete", actual_cases == REQUIRED_CASES)
        after = source_identity(ROOT)
        unchanged = before == after and digest(binary) == binary_hash and digest(Path(__file__)) == runner_hash
        check("source_binary_and_runner_unchanged", unchanged)
        report = {
            "schema": "heptabao.postgresql-statement-templates-live.v1",
            "status": "passed", "source_identity": before,
            "binary_sha256": binary_hash, "runner_sha256": runner_hash,
            "provider_sql_sha256": digest(ROOT / "bootstrap/postgresql/provider.sql"),
            "upgrade_sql_sha256": digest(ROOT / "bootstrap/postgresql/upgrade_v3_statement_templates.sql"),
            "postgres_version": subprocess.check_output([str(postgres_bin / "postgres"), "--version"], text=True).strip(),
            "checks": checks, "check_count": len(checks),
            "real_postgresql_executed": True,
            "dynamic_statement_templates": True,
            "full_openbao_compatibility": False,
            "independent_qualification": False,
            "production_authority": False,
        }
    except Exception as error:
        report = {
            "schema": "heptabao.postgresql-statement-templates-live.v1",
            "status": "failed", "failure": {"case": current_case, "error_type": type(error).__name__},
            "source_identity": before, "binary_sha256": binary_hash,
            "runner_sha256": runner_hash, "checks": checks, "check_count": len(checks),
            "real_postgresql_executed": pg is not None,
            "full_openbao_compatibility": False,
            "independent_qualification": False,
            "production_authority": False,
        }
    finally:
        instance.stop()
        if pg is not None: pg.stop()
        shutil.rmtree(work, ignore_errors=True)
    output.write_text(json.dumps(report, indent=2) + "\n"); output.chmod(0o600)
    print(json.dumps({"status": report["status"], "check_count": len(checks), "failure": report.get("failure")}))
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--postgres-bin", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True); postgres_bin = args.postgres_bin.resolve(strict=True)
    work = args.work_dir.resolve(); output = args.output.resolve()
    if work.exists() or output.exists() or output.is_relative_to(work):
        parser.error("work-dir and output must be separate new absolute paths")
    required = [postgres_bin / name for name in ("postgres", "initdb", "psql")]
    if not all(path.is_file() and os.access(path, os.X_OK) for path in required):
        return 77
    work.mkdir(mode=0o700, parents=True)
    return run(binary, postgres_bin, work, output)


if __name__ == "__main__":
    raise SystemExit(main())
