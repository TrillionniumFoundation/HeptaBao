#!/usr/bin/env python3
"""Exercise explicit PostgreSQL password authentication on a private PG17 cluster.

The profile proves raw client passwords continue to authenticate while every
provider mutation persists a SCRAM-SHA-256 verifier. It covers dynamic roles,
statement templates, static roles and manager rotation. It is scoped product
evidence, not complete OpenBao database compatibility or production authority.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/openbao-acceptance"))
sys.path.insert(0, str(ROOT / "qa/single-node"))
from database_config_completion_live import source_identity
from postgres_live import Postgres
from smoke import Instance

REQUIRED_CASES = frozenset({
    "password_authentication_protocol_available",
    "provider_scram_validator_available",
    "scram_wrapper_rejects_raw_client_password",
    "rejected_raw_wrapper_has_no_provider_effect",
    "malformed_scram_wrapper_rejected",
    "noncanonical_scram_wrapper_rejected",
    "fixture_default_password_encryption_is_md5",
    "invalid_password_authentication_rejected",
    "configure_scram_connection", "config_readback_scram_and_redacted",
    "create_dynamic_role", "dynamic_issue", "dynamic_raw_password_logs_in",
    "dynamic_role_uses_scram_verifier", "create_statement_role",
    "statement_issue", "statement_raw_password_logs_in",
    "statement_role_uses_scram_verifier", "operator_enrolls_static_identity",
    "create_static_role", "static_credential", "static_raw_password_logs_in",
    "static_role_uses_scram_verifier", "root_rotation",
    "manager_uses_scram_verifier", "post_root_rotation_service_operational",
    "restart_unseal", "scram_config_survives_restart",
    "post_restart_issue", "post_restart_password_logs_in",
    "upgrade_database_created", "legacy_v2_installed",
    "static_extension_installed", "statement_extension_installed",
    "manager_cannot_install_password_extension",
    "owner_installs_password_extension",
    "upgrade_preserves_owner_function_identity_and_acl",
    "upgrade_is_repeatable", "manager_cannot_use_forward_scram_before_grant",
    "operator_grants_forward_scram_contract", "upgraded_validator_rejects_raw",
    "forward_protocol_available", "fresh_and_upgrade_extensions_match", "candidate_state_has_no_raw_credentials",
    "candidate_audit_has_no_raw_credentials", "complete",
})


class FixtureFailure(RuntimeError):
    pass


def require(value, code):
    if value is not True:
        raise FixtureFailure(code)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def row(pg: Postgres, query: str, *, database: str = "app") -> list[str]:
    result = pg.sql(query, database=database)
    require(result.returncode == 0, "operator_readback_failed")
    return result.stdout.strip().split("|") if result.stdout.strip() else []


def scram_role(pg: Postgres, username: str) -> bool:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,62}", username) is None:
        raise FixtureFailure("unsafe_role_readback")
    return row(pg, "SELECT rolpassword LIKE 'SCRAM-SHA-256$4096:%' FROM pg_authid "
                   "WHERE rolname='" + username + "'") == ["t"]


def extension(path: Path) -> str:
    source = path.read_text()
    start = source.index("-- PostgreSQL password-authentication extension.")
    return source[start:source.index("COMMIT;", start)]


def configure_instance(instance: Instance, pg: Postgres):
    path = instance.root / "server.json"
    config = json.loads(path.read_text())
    config["lifecycle_interval_seconds"] = 0
    config["outbound_endpoints"] = [{
        "origin": pg.origin,
        "address": f"127.0.0.1:{pg.port}",
        "server_name": "localhost",
        "ca_pem": (instance.root / "ca.crt").read_text(),
    }]
    path.write_text(json.dumps(config)); path.chmod(0o600)
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {
        "secret_shares": 1, "secret_threshold": 1,
    })
    require(status == 200, "initialize")
    instance.token = initialized["root_token"]
    key = initialized["keys_base64"][0]
    require(instance.call("POST", "sys/unseal", {"key": key})[0] == 200, "unseal")
    require(instance.call("POST", "sys/mounts/database", {"type": "database"})[0] == 204,
            "mount")
    connection = {
        "plugin_name": "postgresql-database-plugin",
        "connection_url": pg.origin + "/app",
        "username": "hb_manager",
        "password": pg.manager_password,
        "allowed_roles": ["dynamic", "templated", "staticapp"],
        "password_authentication": "scram-sha-256",
    }
    return key, connection


def run(binary: Path, postgres_bin: Path, work: Path, output: Path) -> int:
    os.umask(0o077)
    before = source_identity(ROOT)
    binary_hash, runner_hash = digest(binary), digest(Path(__file__))
    checks, sensitive = [], []
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
        sensitive.extend([pg.password, pg.manager_password])
        check("fixture_default_password_encryption_is_md5",
              pg.sql("ALTER SYSTEM SET password_encryption='md5'").returncode == 0
              and pg.sql("SELECT pg_reload_conf()").stdout.strip() == "t"
              and row(pg, "SHOW password_encryption") == ["md5"])
        check("password_authentication_protocol_available", pg.sql(
            "SELECT heptabao_provider.password_authentication_protocol()",
            user="hb_manager", password=pg.manager_password,
        ).stdout.strip() == "heptabao-postgresql-password-authentication-v1")
        known_verifier = (
            "SCRAM-SHA-256$4096:AAECAwQFBgcICQoLDA0ODw==$"
            "ONYbSJBXtKl6bP6PVqw8pm9e7EiacprLnoUQPFS80Hw=:"
            "IPOtHuGJ2HifEQg74W2XXqqCrCyQG55GbPRHa6g6n9w="
        )
        check("provider_scram_validator_available", pg.sql(
            "SELECT heptabao_provider.valid_scram_verifier('" + known_verifier + "'),"
            "heptabao_provider.valid_scram_verifier('" + ("e1" * 32) + "'),"
            "heptabao_provider.valid_scram_verifier('SCRAM-SHA-256$4096:bad')",
            user="hb_manager", password=pg.manager_password,
        ).stdout.strip() == "t|f|f")
        raw_fence = "hbf1:" + ("e2" * 32)
        raw_lease = "hb1:" + ("e3" * 32)
        raw_user = "hbp_" + ("e4" * 16)
        raw_call = pg.sql(
            "SELECT heptabao_provider.apply_scram('" + raw_fence + "','" + raw_lease
            + "','" + raw_user + "',1,'issue'," + str(int(time.time()) + 300)
            + ",'app_reader','" + ("e5" * 32) + "','" + ("e6" * 32) + "')",
            user="hb_manager", password=pg.manager_password,
        )
        check("scram_wrapper_rejects_raw_client_password", raw_call.returncode != 0)
        check("rejected_raw_wrapper_has_no_provider_effect", row(pg,
            "SELECT (SELECT count(*) FROM heptabao_provider.fences WHERE fence_id='"
            + raw_fence + "'),(SELECT count(*) FROM heptabao_provider.leases WHERE lease_id='"
            + raw_lease + "'),(SELECT count(*) FROM pg_roles WHERE rolname='" + raw_user + "')"
        ) == ["0", "0", "0"])
        malformed_fence = "hbf1:" + ("e7" * 32)
        malformed = pg.sql(
            "SELECT heptabao_provider.apply_scram('" + malformed_fence + "','hb1:"
            + ("e8" * 32) + "','hbp_" + ("e9" * 16)
            + "',1,'issue'," + str(int(time.time()) + 300)
            + ",'app_reader','SCRAM-SHA-256$4096:bad','" + ("ea" * 32) + "')",
            user="hb_manager", password=pg.manager_password,
        )
        check("malformed_scram_wrapper_rejected", malformed.returncode != 0 and row(pg,
            "SELECT count(*) FROM heptabao_provider.fences WHERE fence_id='"
            + malformed_fence + "'") == ["0"])
        noncanonical_fence = "hbf1:" + ("ec" * 32)
        noncanonical = known_verifier[:-2] + "x="
        noncanonical_call = pg.sql(
            "SELECT heptabao_provider.apply_scram('" + noncanonical_fence + "','hb1:"
            + ("ed" * 32) + "','hbp_" + ("ee" * 16)
            + "',1,'issue'," + str(int(time.time()) + 300)
            + ",'app_reader','" + noncanonical + "','" + ("ef" * 32) + "')",
            user="hb_manager", password=pg.manager_password,
        )
        check("noncanonical_scram_wrapper_rejected",
              noncanonical_call.returncode != 0 and row(pg,
              "SELECT count(*) FROM heptabao_provider.fences WHERE fence_id='"
              + noncanonical_fence + "'") == ["0"])

        initial_static = "a1" * 32
        sensitive.append(initial_static)
        check("operator_enrolls_static_identity", pg.sql(
            "CREATE ROLE app_static LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS PASSWORD '" + initial_static + "';"
            "INSERT INTO heptabao_provider.allowed_static_roles "
            "VALUES('hb_manager','app_static');"
        ).returncode == 0)

        key, connection = configure_instance(instance, pg)
        invalid = dict(connection, password_authentication="md5")
        check("invalid_password_authentication_rejected", instance.call(
            "POST", "database/config/local", invalid
        )[0] == 400)
        check("configure_scram_connection", instance.call(
            "POST", "database/config/local", connection
        )[0] == 204)
        status, configured = instance.call("GET", "database/config/local")
        data = configured.get("data", {})
        check("config_readback_scram_and_redacted", status == 200
              and data.get("password_authentication") == "scram-sha-256"
              and "password" not in data)

        check("create_dynamic_role", instance.call("POST", "database/roles/dynamic", {
            "db_name": "local", "provider_role": "app_reader",
            "default_ttl": 60, "max_ttl": 300,
        })[0] == 204)
        status, issued = instance.call("GET", "database/creds/dynamic")
        dyn_user, dyn_password = (issued.get("data", {}).get(k) for k in ("username", "password"))
        check("dynamic_issue", status == 200 and isinstance(dyn_user, str)
              and isinstance(dyn_password, str))
        sensitive.append(dyn_password)
        check("dynamic_raw_password_logs_in", pg.login(dyn_user, dyn_password))
        check("dynamic_role_uses_scram_verifier", scram_role(pg, dyn_user))

        creation = [
            "CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}' "
            "VALID UNTIL '{{expiration}}'; GRANT app_reader TO \"{{name}}\";"
        ]
        revocation = [
            "ALTER ROLE \"{{name}}\" NOLOGIN; "
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE usename='{{name}}' AND pid<>pg_backend_pid(); "
            "DROP ROLE IF EXISTS \"{{name}}\";"
        ]
        check("create_statement_role", instance.call("POST", "database/roles/templated", {
            "db_name": "local", "creation_statements": creation,
            "revocation_statements": revocation,
            "rollback_statements": ["DROP ROLE IF EXISTS \"{{name}}\""],
            "renew_statements": ["ALTER ROLE \"{{name}}\" VALID UNTIL '{{expiration}}'"],
            "default_ttl": 60, "max_ttl": 300,
        })[0] == 204)
        status, issued = instance.call("GET", "database/creds/templated")
        stmt_user, stmt_password = (issued.get("data", {}).get(k) for k in ("username", "password"))
        check("statement_issue", status == 200 and isinstance(stmt_user, str)
              and isinstance(stmt_password, str))
        sensitive.append(stmt_password)
        check("statement_raw_password_logs_in", pg.login(stmt_user, stmt_password))
        check("statement_role_uses_scram_verifier", scram_role(pg, stmt_user))

        check("create_static_role", instance.call("POST", "database/static-roles/staticapp", {
            "db_name": "local", "username": "app_static", "rotation_period": 300,
        })[0] == 204)
        status, static = instance.call("GET", "database/static-creds/staticapp")
        static_password = static.get("data", {}).get("password")
        check("static_credential", status == 200 and isinstance(static_password, str))
        sensitive.append(static_password)
        check("static_raw_password_logs_in", pg.login("app_static", static_password))
        check("static_role_uses_scram_verifier", scram_role(pg, "app_static"))

        old_manager = pg.manager_password
        check("root_rotation", instance.call("POST", "database/rotate-root/local", {})[0] == 204)
        check("manager_uses_scram_verifier", scram_role(pg, "hb_manager")
              and not pg.login("hb_manager", old_manager))
        check("post_root_rotation_service_operational", instance.call(
            "GET", "database/creds/dynamic"
        )[0] == 200)

        instance.stop(); instance.start()
        check("restart_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        status, configured = instance.call("GET", "database/config/local")
        check("scram_config_survives_restart", status == 200 and configured.get(
            "data", {}).get("password_authentication") == "scram-sha-256")
        status, issued = instance.call("GET", "database/creds/dynamic")
        restart_user = issued.get("data", {}).get("username")
        restart_password = issued.get("data", {}).get("password")
        check("post_restart_issue", status == 200 and isinstance(restart_user, str)
              and isinstance(restart_password, str))
        sensitive.append(restart_password)
        check("post_restart_password_logs_in", pg.login(restart_user, restart_password)
              and scram_role(pg, restart_user))

        check("upgrade_database_created", pg.sql(
            "CREATE DATABASE password_upgrade", database="postgres"
        ).returncode == 0)
        legacy = ROOT / "qa/openbao-acceptance/fixtures/postgresql-provider-v2-legacy.sql"
        check("legacy_v2_installed", pg.sql(legacy.read_text(), database="password_upgrade").returncode == 0)
        check("static_extension_installed", pg.sql((ROOT /
            "bootstrap/postgresql/upgrade_v2_static_credentials.sql").read_text(),
            database="password_upgrade").returncode == 0)
        check("statement_extension_installed", pg.sql((ROOT /
            "bootstrap/postgresql/upgrade_v3_statement_templates.sql").read_text(),
            database="password_upgrade").returncode == 0)
        upgrade = ROOT / "bootstrap/postgresql/upgrade_v4_password_authentication.sql"
        identity_query = """SELECT p.oid,p.proname,p.proowner,p.proacl,p.prosecdef,p.proconfig
            FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='heptabao_provider'
              AND p.proname IN ('apply','rotate_static','rotate_root','apply_statements')
            ORDER BY p.proname"""
        owner_functions_before = pg.sql(identity_query, database="password_upgrade")
        require(owner_functions_before.returncode == 0, "owner_function_identity_before")
        check("manager_cannot_install_password_extension", pg.sql(
            "SET SESSION AUTHORIZATION hb_manager; " + upgrade.read_text(),
            database="password_upgrade"
        ).returncode != 0)
        check("owner_installs_password_extension", pg.sql(
            upgrade.read_text(), database="password_upgrade"
        ).returncode == 0)
        owner_functions_after = pg.sql(identity_query, database="password_upgrade")
        check("upgrade_preserves_owner_function_identity_and_acl",
              owner_functions_after.returncode == 0
              and owner_functions_after.stdout == owner_functions_before.stdout)
        check("upgrade_is_repeatable", pg.sql(
            upgrade.read_text(), database="password_upgrade"
        ).returncode == 0)
        check("manager_cannot_use_forward_scram_before_grant", row(pg,
            "SELECT has_function_privilege('hb_manager',"
            "'heptabao_provider.password_authentication_protocol()',"
            "'EXECUTE')", database="password_upgrade") == ["f"])
        grants = """GRANT EXECUTE ON FUNCTION
            heptabao_provider.password_authentication_protocol(),
            heptabao_provider.apply_scram(text,text,text,bigint,text,bigint,text,text,text),
            heptabao_provider.rotate_static_scram(text,text,text,bigint,text,text,bigint),
            heptabao_provider.rotate_root_scram(text,text,bigint,text,text),
            heptabao_provider.apply_statements_scram(text,text,text,bigint,text,bigint,text,text,text),
            heptabao_provider.valid_scram_verifier(text)
            TO hb_manager"""
        check("operator_grants_forward_scram_contract", pg.sql(
            grants, database="password_upgrade"
        ).returncode == 0 and row(pg,
            "SELECT has_function_privilege('hb_manager',"
            "'heptabao_provider.password_authentication_protocol()',"
            "'EXECUTE'),has_function_privilege('hb_manager',"
            "'heptabao_provider.valid_scram_verifier(text)',"
            "'EXECUTE')", database="password_upgrade") == ["t", "t"])
        check("upgraded_validator_rejects_raw", pg.sql(
            "SELECT heptabao_provider.valid_scram_verifier('" + ("eb" * 32) + "')",
            database="password_upgrade"
        ).stdout.strip() == "f")
        check("forward_protocol_available", pg.sql(
            "SELECT heptabao_provider.password_authentication_protocol()",
            database="password_upgrade"
        ).stdout.strip() == "heptabao-postgresql-password-authentication-v1")
        check("fresh_and_upgrade_extensions_match", extension(
            ROOT / "bootstrap/postgresql/provider.sql") == extension(upgrade))

        plaintexts = [value.encode() for value in sensitive if isinstance(value, str)]
        state_files = [path for path in (instance.root / "data").rglob("*") if path.is_file()]
        check("candidate_state_has_no_raw_credentials", all(
            secret not in path.read_bytes() for secret in plaintexts for path in state_files
        ))
        audit = (instance.root / "audit.jsonl").read_bytes()
        check("candidate_audit_has_no_raw_credentials", all(secret not in audit for secret in plaintexts))
        check("complete", True)
        names = [entry["case"] for entry in checks]
        require(len(names) == len(set(names)) and set(names) == REQUIRED_CASES,
                "case_denominator_mismatch")
        after = source_identity(ROOT)
        passed = before == after and digest(binary) == binary_hash and digest(Path(__file__)) == runner_hash
        report = {
            "schema": "heptabao.postgresql-password-authentication-live.v1",
            "status": "passed" if passed else "failed", "checks": checks,
            "source_identity": before, "source_and_binary_unchanged": passed,
            "binary_sha256": binary_hash, "runner_sha256": runner_hash,
            "actual_postgresql_17": True,
            "password_authentication": ["password", "scram-sha-256"],
            "full_openbao_compatibility": False,
            "independent_qualification": False, "production_authority": False,
            "uncovered": ["username_template", "password-policy generation",
                          "non-PostgreSQL providers", "multi-host provider faults"],
        }
    except Exception as error:
        report = {
            "schema": "heptabao.postgresql-password-authentication-live.v1",
            "status": "failed", "checks": checks,
            "failure": {"case": current_case, "error_type": type(error).__name__},
            "full_openbao_compatibility": False,
            "independent_qualification": False, "production_authority": False,
        }
    finally:
        instance.stop()
        if pg is not None: pg.stop()
        output.write_text(json.dumps(report, indent=2) + "\n"); output.chmod(0o600)
        shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({"status": report["status"], "check_count": len(checks)}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--postgres-bin", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    raise SystemExit(run(args.binary.resolve(strict=True), args.postgres_bin.resolve(strict=True),
                         args.work_dir.resolve(), args.output.resolve()))
