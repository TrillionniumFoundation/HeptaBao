#!/usr/bin/env python3
"""Exercise bounded static-role and manager-password rotation on real PostgreSQL 17.

This profile uses a new private loopback PostgreSQL cluster and synthetic roles.
It never accepts an external DSN and never reports credential bytes. It is scoped
product evidence, not full OpenBao compatibility or production qualification.
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
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/openbao-acceptance"))
sys.path.insert(0, str(ROOT / "qa/single-node"))
from database_config_completion_live import source_identity
from postgres_live import Postgres
from smoke import Instance


class FixtureFailure(RuntimeError):
    pass


def require(value, code):
    if value is not True:
        raise FixtureFailure(code)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sql_literal(value: str, pattern: str) -> str:
    if re.fullmatch(pattern, value) is None:
        raise FixtureFailure("unsafe_fixture_sql_value")
    return "'" + value + "'"


def row(pg: Postgres, query: str, *, database: str = "app") -> list[str]:
    result = pg.sql(query, database=database)
    require(result.returncode == 0, "operator_readback_failed")
    return result.stdout.strip().split("|") if result.stdout.strip() else []


def manager_call(
    pg: Postgres,
    query: str,
    password: str | None = None,
    database: str = "app",
) -> subprocess.CompletedProcess:
    return pg.sql(
        query,
        user="hb_manager",
        password=pg.manager_password if password is None else password,
        database=database,
    )


def configure_instance(instance: Instance, pg: Postgres) -> tuple[str, str]:
    config_path = instance.root / "server.json"
    config = json.loads(config_path.read_text())
    config["lifecycle_interval_seconds"] = 1
    config["outbound_endpoints"] = [{
        "origin": pg.origin,
        "address": f"127.0.0.1:{pg.port}",
        "server_name": "localhost",
        "ca_pem": (instance.root / "ca.crt").read_text(),
    }]
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)
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
        "allowed_roles": ["staticapp", "dynamic"],
    }
    require(instance.call("POST", "database/config/local", connection)[0] == 204, "configure")
    require(instance.call("POST", "database/roles/dynamic", {
        "db_name": "local", "provider_role": "app_reader", "default_ttl": 60, "max_ttl": 300,
    })[0] == 204, "dynamic_role")
    return key, initialized["root_token"]


def run(binary: Path, postgres_bin: Path, work: Path, output: Path) -> int:
    os.umask(0o077)
    before = source_identity(ROOT)
    binary_hash = digest(binary)
    runner_hash = digest(Path(__file__))
    checks: list[dict[str, object]] = []
    sensitive: list[str] = []
    current_case = "setup"
    instance = Instance(binary, work / "candidate")
    pg: Postgres | None = None

    def check(name: str, condition: bool) -> None:
        nonlocal current_case
        current_case = name
        checks.append({"case": name, "passed": condition is True})
        require(condition is True, name)

    try:
        pg = Postgres(postgres_bin, work / "postgres", instance.root / "tls.crt",
                      instance.root / "tls.key", instance.root / "ca.crt")
        pg.start()
        pg.install()
        initial_static = "a1" * 32
        sensitive.extend([pg.password, pg.manager_password, initial_static])
        bootstrap = (
            "CREATE ROLE app_static LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS PASSWORD '" + initial_static + "';"
            "INSERT INTO heptabao_provider.allowed_static_roles VALUES('hb_manager','app_static');"
        )
        check("operator_enrolls_static_identity", pg.sql(bootstrap).returncode == 0)
        check("static_protocol_available", manager_call(
            pg, "SELECT heptabao_provider.static_protocol()"
        ).stdout.strip() == "heptabao-postgresql-static-v1")
        check("manager_cannot_mutate_static_ledger", manager_call(
            pg, "DELETE FROM heptabao_provider.static_roles"
        ).returncode != 0)

        # Provider tombstones are fail-closed at a fixed per-manager bound and the
        # capacity check occurs before any physical password mutation.
        check("capacity_database_created", pg.sql(
            "CREATE DATABASE capacity_app", database="postgres"
        ).returncode == 0)
        provider_source = (ROOT / "bootstrap/postgresql/provider.sql").read_text()
        check("capacity_provider_installed", pg.sql(
            provider_source, database="capacity_app"
        ).returncode == 0)
        capacity_grant = (
            "GRANT USAGE ON SCHEMA heptabao_provider TO hb_manager;"
            "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA heptabao_provider TO hb_manager;"
            "INSERT INTO heptabao_provider.allowed_static_roles "
            "VALUES('hb_manager','app_static');"
        )
        check("capacity_manager_grants_installed", pg.sql(
            capacity_grant, database="capacity_app"
        ).returncode == 0)
        seed = """
INSERT INTO heptabao_provider.static_roles(
 manager,fence_id,static_id,username,seq,request_digest,password_digest,
 role_oid,rotated_at,payload_digest,retired)
SELECT 'hb_manager','hbf1:'||repeat('1',64),
       'hbs1:'||encode(sha256(convert_to(i::text,'UTF8')),'hex'),
       ('cap_'||lpad(i::text,4,'0'))::name,i,
       encode(sha256(convert_to(('request-'||i)::text,'UTF8')),'hex'),
       repeat('0',64),(SELECT oid FROM pg_roles WHERE rolname='app_static'),
       0,repeat('0',64),true
  FROM generate_series(1,4096) AS i;
"""
        check("provider_identity_capacity_filled", pg.sql(
            seed, database="capacity_app"
        ).returncode == 0)
        capacity_attempt = (
            "SELECT heptabao_provider.rotate_static("
            + sql_literal("hbf1:" + "2" * 64, r"hbf1:[0-9a-f]{64}") + ","
            + sql_literal("hbs1:" + "f" * 64, r"hbs1:[0-9a-f]{64}") + ","
            + "'app_static',1::bigint,"
            + sql_literal("b2" * 32, r"[0-9a-f]{64}") + ","
            + sql_literal("c3" * 32, r"[0-9a-f]{64}") + ",1::bigint)::text"
        )
        check("provider_capacity_rejects_before_password_mutation", manager_call(
            pg, capacity_attempt, database="capacity_app"
        ).returncode != 0 and pg.login("app_static", initial_static))
        capacity_rows = row(pg, "SELECT count(*) FROM heptabao_provider.static_roles "
                            "WHERE manager='hb_manager'", database="capacity_app")
        check("provider_capacity_remains_bounded", capacity_rows == ["4096"])

        # The forward extension must be owner-only and install the same tombstone shape.
        check("upgrade_database_created", pg.sql("CREATE DATABASE upgrade_app", database="postgres").returncode == 0)
        legacy = ROOT / "qa/openbao-acceptance/fixtures/postgresql-provider-v2-legacy.sql"
        check("legacy_provider_installed_for_upgrade", pg.sql(legacy.read_text(), database="upgrade_app").returncode == 0)
        grant = ("GRANT USAGE ON SCHEMA heptabao_provider TO hb_manager;"
                 "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA heptabao_provider TO hb_manager;"
                 "INSERT INTO heptabao_provider.allowed_groups VALUES('hb_manager','app_reader');")
        check("legacy_manager_grants_installed", pg.sql(grant, database="upgrade_app").returncode == 0)
        upgrade = (ROOT / "bootstrap/postgresql/upgrade_v2_static_credentials.sql").read_text()
        check("manager_cannot_install_static_extension", pg.sql(
            upgrade, user="hb_manager", password=pg.manager_password, database="upgrade_app"
        ).returncode != 0)
        check("owner_installs_static_extension", pg.sql(upgrade, database="upgrade_app").returncode == 0)
        shape = row(pg, "SELECT count(*) FROM information_schema.columns WHERE table_schema='heptabao_provider' "
                    "AND table_name='static_roles' AND column_name='retired'", database="upgrade_app")
        check("upgrade_installs_retirement_tombstone", shape == ["1"])

        key, _ = configure_instance(instance, pg)
        create = {"db_name": "local", "username": "app_static", "rotation_period": 5}
        check("create_static_role", instance.call("POST", "database/static-roles/staticapp", create)[0] == 204)
        status, role = instance.call("GET", "database/static-roles/staticapp")
        role_data = role.get("data", {})
        check("static_role_readback_redacts_password", status == 200
              and role_data.get("username") == "app_static"
              and "password" not in role_data and "current_password" not in role_data
              and "pending_password" not in role_data)
        status, listed = instance.call("LIST", "database/static-roles")
        check("static_role_list", status == 200 and listed.get("data", {}).get("keys") == ["staticapp"])
        status, credential = instance.call("GET", "database/static-creds/staticapp")
        first_password = credential.get("data", {}).get("password")
        check("static_credential_returned", status == 200 and isinstance(first_password, str)
              and re.fullmatch(r"[0-9a-f]{64}", first_password) is not None)
        sensitive.append(first_password)
        check("initial_operator_password_retired", not pg.login("app_static", initial_static))
        check("issued_static_password_logs_in", pg.login("app_static", first_password))

        # Wait for the real lifecycle owner rather than simulating its state transition.
        deadline = time.monotonic() + 15
        automatic_password = first_password
        while time.monotonic() < deadline:
            status, value = instance.call("GET", "database/static-creds/staticapp")
            candidate = value.get("data", {}).get("password") if status == 200 else None
            if isinstance(candidate, str) and candidate != first_password:
                automatic_password = candidate
                break
            time.sleep(0.25)
        check("automatic_static_rotation", automatic_password != first_password)
        sensitive.append(automatic_password)
        check("automatic_rotation_invalidates_old_password", not pg.login("app_static", first_password))
        check("automatic_rotation_new_password_logs_in", pg.login("app_static", automatic_password))

        check("manual_static_rotation", instance.call("POST", "database/rotate-role/staticapp", {})[0] == 204)
        status, credential = instance.call("GET", "database/static-creds/staticapp")
        manual_password = credential.get("data", {}).get("password")
        check("manual_rotation_returns_new_password", status == 200 and isinstance(manual_password, str)
              and manual_password != automatic_password)
        sensitive.append(manual_password)
        check("manual_rotation_invalidates_old_password", not pg.login("app_static", automatic_password))
        check("manual_rotation_new_password_logs_in", pg.login("app_static", manual_password))

        fields = row(pg, "SELECT static_id,fence_id,seq,request_digest,rotated_at,retired "
                     "FROM heptabao_provider.static_roles WHERE manager='hb_manager' AND username='app_static'")
        check("active_provider_identity_observed", len(fields) == 6
              and re.fullmatch(r"hbs1:[0-9a-f]{64}", fields[0]) is not None
              and re.fullmatch(r"hbf1:[0-9a-f]{64}", fields[1]) is not None
              and fields[5] == "f")
        static_id, fence_id, seq, request_digest, rotated_at, _ = fields
        for value, pattern in ((static_id, r"hbs1:[0-9a-f]{64}"), (fence_id, r"hbf1:[0-9a-f]{64}"),
                               (seq, r"[1-9][0-9]*"), (request_digest, r"[0-9a-f]{64}"),
                               (rotated_at, r"[0-9]+"), (manual_password, r"[0-9a-f]{64}")):
            require(re.fullmatch(pattern, value) is not None, "provider_identity_shape")

        # An unrelated dynamic effect advances the global provider floor. Exact static
        # readback must remain valid; floor equality is not an application proof.
        status, dynamic = instance.call("GET", "database/creds/dynamic")
        check("unrelated_provider_effect_advances_floor", status == 200)
        dynamic_credential = dynamic.get("data", {})
        sensitive.extend([dynamic_credential.get("password", "")])
        floor = row(pg, "SELECT last_seq FROM heptabao_provider.fences WHERE manager='hb_manager' "
                    "AND fence_id=" + sql_literal(fence_id, r"hbf1:[0-9a-f]{64}"))
        check("static_operation_overtaken_by_global_floor", len(floor) == 1 and int(floor[0]) > int(seq))
        exact = "SELECT heptabao_provider.rotate_static(" + ",".join([
            sql_literal(fence_id, r"hbf1:[0-9a-f]{64}"),
            sql_literal(static_id, r"hbs1:[0-9a-f]{64}"),
            "'app_static'", seq + "::bigint",
            sql_literal(manual_password, r"[0-9a-f]{64}"),
            sql_literal(request_digest, r"[0-9a-f]{64}"), rotated_at + "::bigint",
        ]) + ")::text"
        check("exact_static_retry_survives_later_global_floor", manager_call(pg, exact).returncode == 0)

        check("delete_static_role", instance.call("DELETE", "database/static-roles/staticapp")[0] == 204)
        check("deleted_static_role_absent_from_api", instance.call("GET", "database/static-roles/staticapp")[0] == 404)
        retired = row(pg, "SELECT fence_id,static_id,username,seq,request_digest,retired "
                      "FROM heptabao_provider.static_roles WHERE manager='hb_manager' AND username='app_static'")
        check("provider_retains_bounded_retirement_tombstone", len(retired) == 6 and retired[5] == "t")
        retired_fence, retired_id, retired_name, retired_seq, retired_digest, _ = retired
        wrong = "0" * 64 if retired_digest != "0" * 64 else "1" * 64
        query = "SELECT heptabao_provider.static_retired(" + ",".join([
            sql_literal(retired_fence, r"hbf1:[0-9a-f]{64}"),
            sql_literal(retired_id, r"hbs1:[0-9a-f]{64}"),
            sql_literal(retired_name, r"[A-Za-z_][A-Za-z0-9_-]{0,62}"),
            retired_seq + "::bigint", sql_literal(wrong, r"[0-9a-f]{64}"),
        ]) + ")"
        check("wrong_retirement_digest_is_not_proof", manager_call(pg, query).stdout.strip() == "f")
        query = query.replace(sql_literal(wrong, r"[0-9a-f]{64}"),
                              sql_literal(retired_digest, r"[0-9a-f]{64}"))
        check("exact_retirement_digest_is_observable", manager_call(pg, query).stdout.strip() == "t")
        check("retired_static_observation_is_absent", json.loads(manager_call(
            pg, "SELECT heptabao_provider.observe_static(" + sql_literal(retired_id, r"hbs1:[0-9a-f]{64}") + ")"
        ).stdout).get("found") is False)

        check("same_identity_static_recreation", instance.call(
            "POST", "database/static-roles/staticapp", create
        )[0] == 204)
        status, credential = instance.call("GET", "database/static-creds/staticapp")
        recreated_password = credential.get("data", {}).get("password")
        check("recreated_static_password_logs_in", status == 200 and isinstance(recreated_password, str)
              and pg.login("app_static", recreated_password))
        sensitive.append(recreated_password)
        bounded = row(pg, "SELECT count(*),bool_and(NOT retired) FROM heptabao_provider.static_roles "
                      "WHERE manager='hb_manager' AND username='app_static'")
        check("recreation_reuses_one_provider_identity", bounded == ["1", "t"])

        old_manager = pg.manager_password
        check("old_manager_password_initially_usable", pg.login("hb_manager", old_manager))
        config_path = instance.root / "server.json"
        instance.stop()
        config = json.loads(config_path.read_text())
        config["lifecycle_interval_seconds"] = 0
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o600)
        instance.start()
        check("disable_lifecycle_restart_unseal", instance.call(
            "POST", "sys/unseal", {"key": key}
        )[0] == 200)
        pg.stop()
        status, pending_root = instance.call("POST", "database/rotate-root/local", {})
        check("provider_outage_retains_root_intent", status == 503
              and pending_root.get("reconcile_required") is True
              and pending_root.get("retry_allowed") is False)
        instance.stop()
        instance.start()
        check("pending_root_survives_service_restart", instance.call(
            "POST", "sys/unseal", {"key": key}
        )[0] == 200)
        pg.start()
        status, overtaking_lease = instance.call("GET", "database/creds/dynamic")
        check("unrelated_dynamic_effect_overtakes_pending_root", status == 200
              and isinstance(overtaking_lease.get("lease_id"), str))
        sensitive.append(overtaking_lease.get("data", {}).get("password", ""))
        overtaking_floor = row(pg, "SELECT max(last_seq) FROM heptabao_provider.fences "
                               "WHERE manager='hb_manager'")
        check("overtaking_provider_floor_observed", len(overtaking_floor) == 1
              and int(overtaking_floor[0]) > 0)
        instance.stop()
        config = json.loads(config_path.read_text())
        config["lifecycle_interval_seconds"] = 1
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o600)
        instance.start()
        check("enable_lifecycle_restart_unseal", instance.call(
            "POST", "sys/unseal", {"key": key}
        )[0] == 200)
        deadline = time.monotonic() + 20
        first_root = []
        while time.monotonic() < deadline:
            first_root = row(pg, "SELECT seq,root_id,request_digest,fence_id "
                             "FROM heptabao_provider.root_rotations WHERE manager='hb_manager'")
            if len(first_root) == 4 and not pg.login("hb_manager", old_manager):
                break
            time.sleep(0.25)
        check("lifecycle_recovers_overtaken_root_intent", len(first_root) == 4
              and int(first_root[0]) > int(overtaking_floor[0]))
        check("first_root_rotation_ledger_observed", len(first_root) == 4
              and int(first_root[0]) > 0
              and re.fullmatch(r"hbr1:[0-9a-f]{64}", first_root[1]) is not None
              and re.fullmatch(r"[0-9a-f]{64}", first_root[2]) is not None
              and re.fullmatch(r"hbf1:[0-9a-f]{64}", first_root[3]) is not None)
        first_root_seq = int(first_root[0])
        first_root_id, first_root_fence = first_root[1], first_root[3]
        check("old_manager_password_denied", not pg.login("hb_manager", old_manager))
        status, config = instance.call("GET", "database/config/local")
        config_data = config.get("data", {})
        check("manager_password_readback_redacted", status == 200
              and isinstance(config_data, dict) and "password" not in config_data
              and config_data.get("password_authentication") == "password"
              and old_manager not in json.dumps(config))
        check("service_uses_rotated_manager_password", instance.call(
            "POST", "database/rotate-role/staticapp", {}
        )[0] == 204)

        instance.stop()
        instance.start()
        check("service_restart_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("rotated_manager_survives_restart", instance.call(
            "POST", "database/rotate-role/staticapp", {}
        )[0] == 204)
        hypothetical = first_root_seq + 1
        retry_query = (
            "SET SESSION AUTHORIZATION hb_manager; SELECT heptabao_provider.root_rotation_retriable("
            + sql_literal(first_root_fence, r"hbf1:[0-9a-f]{64}") + ","
            + sql_literal(first_root_id, r"hbr1:[0-9a-f]{64}") + ","
            + str(hypothetical) + "::bigint)"
        )
        check("root_retry_proof_requires_overtaken_unapplied_sequence",
              pg.sql(retry_query).stdout.strip() == "t")
        exact_query = retry_query.replace(str(hypothetical) + "::bigint", str(first_root_seq) + "::bigint")
        check("exact_applied_root_is_not_readmitted",
              pg.sql(exact_query).stdout.strip() == "f")
        check("second_manager_rotation", instance.call("POST", "database/rotate-root/local", {})[0] == 204)
        check("second_manager_rotation_remains_operational", instance.call(
            "POST", "database/rotate-role/staticapp", {}
        )[0] == 204)
        root_rows = row(pg, "SELECT count(*),min(seq),max(seq) FROM heptabao_provider.root_rotations "
                        "WHERE manager='hb_manager'")
        check("root_rotation_ledger_is_single_and_monotonic", len(root_rows) == 3
              and root_rows[0] == "1" and int(root_rows[1]) > first_root_seq
              and int(root_rows[2]) == int(root_rows[1]))

        # Known fixture credentials must not appear in encrypted state or audit output.
        plaintexts = [value.encode() for value in sensitive if isinstance(value, str) and value]
        check("candidate_storage_contains_no_plaintext_credentials", all(
            all(secret not in path.read_bytes() for secret in plaintexts)
            for path in (instance.root / "data").rglob("*") if path.is_file()
        ))
        audit = (instance.root / "audit.jsonl").read_bytes()
        check("candidate_audit_redacts_rotation_credentials", all(secret not in audit for secret in plaintexts))

        after = source_identity(ROOT)
        unchanged = before == after and digest(binary) == binary_hash and digest(Path(__file__)) == runner_hash
        check("source_binary_and_runner_unchanged", unchanged)
        report = {
            "schema": "heptabao.postgresql-static-rotation-live.v1",
            "status": "passed",
            "source_identity": before,
            "binary_sha256": binary_hash,
            "runner_sha256": runner_hash,
            "provider_sql_sha256": digest(ROOT / "bootstrap/postgresql/provider.sql"),
            "upgrade_sql_sha256": digest(ROOT / "bootstrap/postgresql/upgrade_v2_static_credentials.sql"),
            "postgres_version": subprocess.check_output([str(postgres_bin / "postgres"), "--version"], text=True).strip(),
            "checks": checks,
            "check_count": len(checks),
            "real_postgresql_executed": True,
            "static_role_rotation": True,
            "manager_password_rotation": True,
            "retirement_tombstone": True,
            "full_openbao_compatibility": False,
            "independent_qualification": False,
            "production_authority": False,
        }
    except Exception as error:
        report = {
            "schema": "heptabao.postgresql-static-rotation-live.v1",
            "status": "failed",
            "failure": {"case": current_case, "error_type": type(error).__name__},
            "source_identity": before,
            "binary_sha256": binary_hash,
            "runner_sha256": runner_hash,
            "checks": checks,
            "check_count": len(checks),
            "real_postgresql_executed": pg is not None,
            "full_openbao_compatibility": False,
            "independent_qualification": False,
            "production_authority": False,
        }
    finally:
        instance.stop()
        if pg is not None:
            pg.stop()
        shutil.rmtree(work, ignore_errors=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    output.chmod(0o600)
    print(json.dumps({"status": report["status"], "check_count": len(checks), "failure": report.get("failure")}))
    return 0 if report["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--postgres-bin", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    postgres_bin = args.postgres_bin.resolve(strict=True)
    work = args.work_dir.resolve()
    output = args.output.resolve()
    if work.exists() or output.exists() or output.is_relative_to(work):
        parser.error("work-dir and output must be separate new absolute paths")
    required = [postgres_bin / name for name in ("postgres", "initdb", "psql")]
    if not all(path.is_file() and os.access(path, os.X_OK) for path in required):
        return 77
    work.mkdir(mode=0o700, parents=True)
    return run(binary, postgres_bin, work, output)


if __name__ == "__main__":
    raise SystemExit(main())
