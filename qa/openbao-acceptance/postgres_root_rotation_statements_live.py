#!/usr/bin/env python3
"""Exercise bounded PostgreSQL root-rotation statements on real PostgreSQL 17.

The profile uses a new private loopback cluster and synthetic identities. It
covers the exact schema-56 to current schema-59 boundary while the root-statement feature remains fenced at schema 57, fresh and owner-only forward
provider installation, password and SCRAM paths, idempotency, restart, and
negative SQL grammar cases. It is scoped evidence, not arbitrary SQL parity.
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

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/openbao-acceptance"))
sys.path.insert(0, str(ROOT / "qa/single-node"))
from database_config_completion_live import source_identity
from postgres_live import Postgres
from smoke import Instance

PIN_PATH = ROOT / "qa/openbao-acceptance/fixtures/postgres-schema-migration-sources-v1.json"
PINS = json.loads(PIN_PATH.read_text())
SCHEMA56_SOURCE = PINS["schema56_root_rotation_statements"]["commit"]
SCHEMA56_TREE = PINS["schema56_root_rotation_statements"]["tree"]
CUSTOM_STATEMENTS = [
    'ALTER USER "{{name}}" PASSWORD \'{{password}}\'',
    'ALTER ROLE "{{username}}" WITH ENCRYPTED PASSWORD \'{{password}}\'',
]
REQUIRED_CASES = frozenset({
    "fresh_root_statement_protocol",
    "upgrade_database_created",
    "v5_baseline_installed",
    "v5_manager_grants_installed",
    "manager_cannot_install_v6",
    "owner_installs_v6",
    "manager_requires_v6_function_grants",
    "operator_grants_v6_functions",
    "forward_root_statement_protocol",
    "upgrade_is_repeatable",
    "fresh_and_forward_definitions_match",
    "quoted_manager_created",
    "quoted_manager_old_login",
    "quoted_manager_exact_statement_apply",
    "quoted_manager_old_password_denied",
    "quoted_manager_new_password_logs_in",
    "quoted_manager_exact_retry",
    "quoted_manager_conflicting_retry_rejected",
    "quoted_manager_conflict_preserves_password",
    "quoted_manager_arbitrary_sql_rejected_before_mutation",
    "legacy_binary_initialize",
    "legacy_binary_unseal",
    "legacy_binary_mount",
    "legacy_binary_connection",
    "schema56_state_created_by_pinned_binary",
    "candidate_reads_schema56",
    "schema56_read_does_not_rewrite_state",
    "schema56_root_statement_field_is_empty",
    "invalid_api_statements_fail_atomically",
    "candidate_promotes_root_statements_to_current_schema59",
    "configured_statement_order_round_trips",
    "omitted_root_statements_preserve",
    "null_root_statements_clear",
    "reconfigured_root_statements_restore_order",
    "schema56_binary_rejects_schema59",
    "failed_downgrade_preserves_state",
    "candidate_reopens_schema59",
    "failed_downgrade_preserves_logical_frontier",
    "custom_root_rotation",
    "old_manager_password_denied",
    "custom_statements_survive_rotation",
    "service_uses_rotated_manager_password",
    "restart_unseal",
    "service_lease_retires_before_authentication_change",
    "custom_statements_survive_restart",
    "second_custom_root_rotation",
    "scram_configuration",
    "scram_custom_root_rotation",
    "scram_provider_verifier_observed",
    "scram_service_remains_operational",
    "root_rotation_ledger_single_and_monotonic",
    "candidate_storage_contains_no_plaintext_credentials",
    "candidate_audit_contains_no_plaintext_credentials",
    "source_and_binary_unchanged",
    "complete",
})


class FixtureFailure(RuntimeError):
    pass


def require(value, code):
    if value is not True:
        raise FixtureFailure(code)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def durable_application_snapshot(root: Path) -> dict[str, str]:
    expected = {"state.hbs", "journal.hbj", "ledger.hbl", "seal.json"}
    files = {path.name: path for path in root.iterdir() if path.is_file()}
    require(set(files) == expected, "unexpected_durable_artifact_set")
    # DurableService reopen authenticates the journal and may materialize its
    # committed replay records into a freshly sealed ledger checkpoint.  That
    # physical ledger frame is not application-state migration.  Snapshot,
    # journal and seal artifacts must remain byte-identical.
    return {
        name: digest(files[name])
        for name in ("state.hbs", "journal.hbj", "seal.json")
    }


def durable_ledger_digest(root: Path) -> str:
    path = root / "ledger.hbl"
    require(path.is_file(), "durable_ledger_missing")
    return digest(path)


def capacity_frontier(instance: Instance) -> dict[str, int]:
    status, body = instance.call("GET", "sys/internal/capacity")
    data = body.get("data", {})
    names = (
        "state_bytes",
        "generation",
        "retained_operations",
        "journal_bytes",
        "state_schema",
    )
    require(
        status == 200 and all(type(data.get(name)) is int for name in names),
        "durable_frontier_unavailable",
    )
    return {name: data[name] for name in names}


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def sql_dollar_literal(value: str) -> str:
    delimiter = "$hbroot$"
    if delimiter in value:
        raise FixtureFailure("direct_parameter_contains_dollar_delimiter")
    return delimiter + value + delimiter


def row(pg: Postgres, query: str, *, database: str = "app") -> list[str]:
    result = pg.sql(query, database=database)
    require(result.returncode == 0, "operator_readback_failed")
    return result.stdout.strip().split("|") if result.stdout.strip() else []


def role_call(
    pg: Postgres,
    role: str,
    password: str,
    query: str,
    *,
    database: str = "app",
) -> subprocess.CompletedProcess:
    return pg.sql(query, user=role, password=password, database=database)


def manager_call(pg: Postgres, query: str, *, database: str = "app"):
    return role_call(pg, "hb_manager", pg.manager_password, query, database=database)


def configure_outbound(instance: Instance, pg: Postgres) -> None:
    path = instance.root / "server.json"
    config = json.loads(path.read_text())
    config["lifecycle_interval_seconds"] = 0
    config["outbound_endpoints"] = [{
        "origin": pg.origin,
        "address": f"127.0.0.1:{pg.port}",
        "server_name": "localhost",
        "ca_pem": pg.ca.read_text(),
    }]
    path.write_text(json.dumps(config))
    path.chmod(0o600)


def initialize(instance: Instance, pg: Postgres) -> tuple[str, str]:
    configure_outbound(instance, pg)
    instance.start()
    status, initialized = instance.call(
        "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
    )
    require(status == 200, "initialize")
    instance.token = initialized["root_token"]
    key = initialized["keys_base64"][0]
    require(instance.call("POST", "sys/unseal", {"key": key})[0] == 200, "unseal")
    require(
        instance.call("POST", "sys/mounts/database", {"type": "database"})[0] == 204,
        "mount",
    )
    return key, initialized["root_token"]


def function_definitions(pg: Postgres, database: str) -> str:
    result = pg.sql(
        "SELECT p.proname||':'||pg_get_function_identity_arguments(p.oid)||E'\\n'"
        "||pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n "
        "ON n.oid=p.pronamespace WHERE n.nspname='heptabao_provider' "
        "AND p.proname IN ('root_statement_protocol','rotate_root_statements',"
        "'rotate_root_statements_scram') ORDER BY p.proname,"
        "pg_get_function_identity_arguments(p.oid)",
        database=database,
    )
    require(result.returncode == 0, "provider_definition_readback_failed")
    return result.stdout


def run(
    binary: Path,
    legacy_binary: Path,
    postgres_bin: Path,
    work: Path,
    output: Path,
    build_source_commit: str,
    legacy_source_commit: str,
    expected_binary_sha256: str,
    expected_legacy_sha256: str,
) -> int:
    os.umask(0o077)
    before = source_identity(ROOT)
    binary_hash = digest(binary)
    legacy_hash = digest(legacy_binary)
    runner_hash = digest(Path(__file__))
    require(before["head"] == build_source_commit, "candidate_source_commit_mismatch")
    require(PINS.get("schema") == "heptabao.postgresql-schema-migration-sources.v1",
            "schema_source_pin_format_mismatch")
    require(legacy_source_commit == SCHEMA56_SOURCE, "schema56_source_pin_mismatch")
    legacy_tree = subprocess.check_output(
        ["git", "rev-parse", legacy_source_commit + "^{tree}"], cwd=ROOT, text=True
    ).strip()
    require(legacy_tree == SCHEMA56_TREE, "schema56_source_tree_mismatch")
    require(binary_hash == expected_binary_sha256, "candidate_binary_digest_mismatch")
    require(legacy_hash == expected_legacy_sha256, "legacy_binary_digest_mismatch")
    require(binary_hash != legacy_hash, "candidate_and_legacy_binaries_must_differ")
    checks: list[dict[str, object]] = []
    sensitive: list[str] = []
    current_case = "setup"
    pg: Postgres | None = None
    instance: Instance | None = None
    legacy_instance: Instance | None = None
    durable_reopen_observations: dict[str, object] = {}

    def check(name: str, condition: bool) -> None:
        nonlocal current_case
        current_case = name
        checks.append({"case": name, "passed": condition is True})
        require(condition is True, name)

    try:
        instance = Instance(binary, work / "candidate")
        pg = Postgres(
            postgres_bin,
            work / "postgres",
            instance.root / "tls.crt",
            instance.root / "tls.key",
            instance.root / "ca.crt",
        )
        pg.start()
        pg.install()
        sensitive.extend([pg.password, pg.manager_password])
        check(
            "fresh_root_statement_protocol",
            manager_call(
                pg, "SELECT heptabao_provider.root_statement_protocol()"
            ).stdout.strip() == "heptabao-postgresql-root-statements-v1",
        )

        check(
            "upgrade_database_created",
            pg.sql("CREATE DATABASE root_statement_upgrade", database="postgres").returncode
            == 0,
        )
        baseline = (
            ROOT
            / "qa/openbao-acceptance/fixtures/postgresql-provider-v5-root-statements-baseline.sql"
        )
        upgrade = ROOT / "bootstrap/postgresql/upgrade_v6_root_rotation_statements.sql"
        check(
            "v5_baseline_installed",
            pg.sql(baseline.read_text(), database="root_statement_upgrade").returncode
            == 0,
        )
        grants = (
            "GRANT USAGE ON SCHEMA heptabao_provider TO hb_manager;"
            "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA heptabao_provider TO hb_manager;"
            "INSERT INTO heptabao_provider.allowed_groups "
            "VALUES('hb_manager','app_reader');"
        )
        check(
            "v5_manager_grants_installed",
            pg.sql(grants, database="root_statement_upgrade").returncode == 0,
        )
        check(
            "manager_cannot_install_v6",
            pg.sql(
                upgrade.read_text(),
                user="hb_manager",
                password=pg.manager_password,
                database="root_statement_upgrade",
            ).returncode
            != 0,
        )
        check(
            "owner_installs_v6",
            pg.sql(upgrade.read_text(), database="root_statement_upgrade").returncode
            == 0,
        )
        check(
            "manager_requires_v6_function_grants",
            manager_call(
                pg,
                "SELECT heptabao_provider.root_statement_protocol()",
                database="root_statement_upgrade",
            ).returncode
            != 0,
        )
        v6_grants = (
            "GRANT EXECUTE ON FUNCTION heptabao_provider.root_statement_protocol() "
            "TO hb_manager;"
            "GRANT EXECUTE ON FUNCTION heptabao_provider.rotate_root_statements("
            "text,text,bigint,text,text,text) TO hb_manager;"
            "GRANT EXECUTE ON FUNCTION heptabao_provider.rotate_root_statements_scram("
            "text,text,bigint,text,text,text) TO hb_manager;"
        )
        check(
            "operator_grants_v6_functions",
            pg.sql(v6_grants, database="root_statement_upgrade").returncode == 0,
        )
        check(
            "forward_root_statement_protocol",
            manager_call(
                pg,
                "SELECT heptabao_provider.root_statement_protocol()",
                database="root_statement_upgrade",
            ).stdout.strip()
            == "heptabao-postgresql-root-statements-v1",
        )
        check(
            "upgrade_is_repeatable",
            pg.sql(upgrade.read_text(), database="root_statement_upgrade").returncode
            == 0,
        )
        check(
            "fresh_and_forward_definitions_match",
            function_definitions(pg, "app")
            == function_definitions(pg, "root_statement_upgrade"),
        )

        quoted_role = 'hb_quote"manager'
        quoted_old = "Quoted-Old-Password-1"
        quoted_new = "Quoted-New-'\\-Password-2"
        sensitive.extend([quoted_old, quoted_new])
        create_quoted = (
            'CREATE ROLE "hb_quote""manager" LOGIN NOSUPERUSER NOCREATEDB '
            "NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD "
            + sql_literal(quoted_old)
            + ";GRANT USAGE ON SCHEMA heptabao_provider TO "
            '"hb_quote""manager";GRANT EXECUTE ON FUNCTION '
            "heptabao_provider.rotate_root_statements(text,text,bigint,text,text,text) "
            'TO "hb_quote""manager";'
        )
        check("quoted_manager_created", pg.sql(create_quoted).returncode == 0)
        check("quoted_manager_old_login", pg.login(quoted_role, quoted_old))
        direct_statements = json.dumps(CUSTOM_STATEMENTS, separators=(",", ":"))
        fence = "hbf1:" + "1" * 64
        root_id = "hbr1:" + "2" * 64
        request_digest = "3" * 64
        direct_query = (
            "SET standard_conforming_strings=off;"
            "SELECT heptabao_provider.rotate_root_statements("
            + ",".join([
                sql_dollar_literal(fence),
                sql_dollar_literal(root_id),
                "1::bigint",
                sql_dollar_literal(quoted_new),
                sql_dollar_literal(request_digest),
                sql_dollar_literal(direct_statements),
            ])
            + ")::text"
        )
        check(
            "quoted_manager_exact_statement_apply",
            role_call(pg, quoted_role, quoted_old, direct_query).stdout.strip()
            == "true",
        )
        check("quoted_manager_old_password_denied", not pg.login(quoted_role, quoted_old))
        check("quoted_manager_new_password_logs_in", pg.login(quoted_role, quoted_new))
        check(
            "quoted_manager_exact_retry",
            role_call(pg, quoted_role, quoted_new, direct_query).stdout.strip()
            == "true",
        )
        conflict_statements = json.dumps(
            list(reversed(CUSTOM_STATEMENTS)), separators=(",", ":")
        )
        conflict_query = direct_query.replace(
            sql_dollar_literal(direct_statements), sql_dollar_literal(conflict_statements)
        )
        check(
            "quoted_manager_conflicting_retry_rejected",
            role_call(pg, quoted_role, quoted_new, conflict_query).returncode != 0,
        )
        check(
            "quoted_manager_conflict_preserves_password",
            pg.login(quoted_role, quoted_new),
        )
        arbitrary = json.dumps(
            ['ALTER ROLE "{{username}}" PASSWORD \'{{password}}\'; SELECT 1'],
            separators=(",", ":"),
        )
        arbitrary_query = direct_query.replace(
            sql_dollar_literal(direct_statements), sql_dollar_literal(arbitrary)
        )
        check(
            "quoted_manager_arbitrary_sql_rejected_before_mutation",
            role_call(pg, quoted_role, quoted_new, arbitrary_query).returncode != 0
            and pg.login(quoted_role, quoted_new),
        )

        legacy_instance = Instance(legacy_binary, work / "schema56-state")
        legacy_key, _ = initialize(legacy_instance, pg)
        legacy_connection = {
            "plugin_name": "postgresql-database-plugin",
            "connection_url": pg.origin + "/app",
            "username": "hb_manager",
            "password": pg.manager_password,
            "allowed_roles": ["dynamic"],
        }
        check(
            "legacy_binary_initialize",
            isinstance(legacy_instance.token, str) and bool(legacy_instance.token),
        )
        check("legacy_binary_unseal", True)
        check("legacy_binary_mount", True)
        check(
            "legacy_binary_connection",
            legacy_instance.call(
                "POST", "database/config/local", legacy_connection
            )[0]
            == 204,
        )
        schema56_frontier = capacity_frontier(legacy_instance)
        legacy_instance.stop()
        data_root = legacy_instance.root / "data"
        state_path = data_root / "state.hbs"
        schema56_application = durable_application_snapshot(data_root)
        schema56_ledger = durable_ledger_digest(data_root)
        check("schema56_state_created_by_pinned_binary", state_path.is_file())

        legacy_instance.binary = binary
        legacy_instance.start()
        check(
            "candidate_reads_schema56",
            legacy_instance.call("POST", "sys/unseal", {"key": legacy_key})[0] == 200,
        )
        status, readback = legacy_instance.call("GET", "database/config/local")
        read_data = readback.get("data", {})
        check(
            "schema56_root_statement_field_is_empty",
            status == 200 and read_data.get("root_rotation_statements") == [],
        )
        schema56_after_application = durable_application_snapshot(data_root)
        schema56_after_frontier = capacity_frontier(legacy_instance)
        schema56_after_ledger = durable_ledger_digest(data_root)
        durable_reopen_observations["schema56"] = {
            "application_artifacts_unchanged": (
                schema56_after_application == schema56_application
            ),
            "frontier_before": schema56_frontier,
            "frontier_after": schema56_after_frontier,
            "logical_frontier_unchanged": schema56_after_frontier == schema56_frontier,
            "ledger_checkpoint_resealed_or_materialized": (
                schema56_after_ledger != schema56_ledger
            ),
        }
        check(
            "schema56_read_does_not_rewrite_state",
            schema56_after_application == schema56_application
            and schema56_after_frontier == schema56_frontier,
        )
        invalid_values = [
            ["SELECT 1"],
            ['ALTER ROLE "{{username}}" WITH PASSWORD \'{{password}}\'; DROP ROLE hb_manager'],
            ['ALTER ROLE "{{username}}" VALID UNTIL \'{{password}}\''],
            ['ALTER ROLE {{username}} WITH PASSWORD \'{{password}}\''],
            ['ALTER ROLE "{{unknown}}" WITH PASSWORD \'{{password}}\''],
            ['ALTER ROLE "{{username}}" WITH PASSWORD \'{{password}}\'' for _ in range(17)],
        ]
        invalid_ok = True
        for value in invalid_values:
            rejected = legacy_instance.call(
                "POST",
                "database/config/local",
                {"root_rotation_statements": value},
            )
            unchanged = legacy_instance.call("GET", "database/config/local")
            invalid_ok = (
                invalid_ok
                and rejected[0] == 400
                and unchanged[1].get("data", {}).get("root_rotation_statements") == []
            )
        check("invalid_api_statements_fail_atomically", invalid_ok)
        check(
            "candidate_promotes_root_statements_to_current_schema59",
            legacy_instance.call(
                "POST",
                "database/config/local",
                {"root_rotation_statements": CUSTOM_STATEMENTS},
            )[0]
            == 204,
        )
        status, configured = legacy_instance.call("GET", "database/config/local")
        check(
            "configured_statement_order_round_trips",
            status == 200
            and configured.get("data", {}).get("root_rotation_statements")
            == CUSTOM_STATEMENTS,
        )
        check(
            "omitted_root_statements_preserve",
            legacy_instance.call(
                "POST", "database/config/local", {"allowed_roles":["dynamic"]}
            )[0] == 204
            and legacy_instance.call("GET", "database/config/local")[1]
                .get("data", {}).get("root_rotation_statements") == CUSTOM_STATEMENTS,
        )
        check(
            "null_root_statements_clear",
            legacy_instance.call(
                "POST", "database/config/local", {"root_rotation_statements":None}
            )[0] == 204
            and legacy_instance.call("GET", "database/config/local")[1]
                .get("data", {}).get("root_rotation_statements") == [],
        )
        check(
            "reconfigured_root_statements_restore_order",
            legacy_instance.call(
                "POST", "database/config/local",
                {"root_rotation_statements":CUSTOM_STATEMENTS},
            )[0] == 204
            and legacy_instance.call("GET", "database/config/local")[1]
                .get("data", {}).get("root_rotation_statements") == CUSTOM_STATEMENTS,
        )

        schema59_frontier = capacity_frontier(legacy_instance)
        legacy_instance.stop()
        schema59_application = durable_application_snapshot(data_root)
        schema59_ledger = durable_ledger_digest(data_root)
        require(
            schema59_application != schema56_application
            and schema59_frontier["state_schema"] == 59,
            "schema59_state_not_published",
        )

        legacy_instance.binary = legacy_binary
        legacy_instance.start()
        check(
            "schema56_binary_rejects_schema59",
            legacy_instance.call("POST", "sys/unseal", {"key": legacy_key})[0] == 503,
        )
        legacy_instance.stop()
        downgrade_application = durable_application_snapshot(data_root)
        downgrade_ledger = durable_ledger_digest(data_root)
        durable_reopen_observations["schema59_old_reader_refusal"] = {
            "application_artifacts_unchanged": (
                downgrade_application == schema59_application
            ),
            "frontier_before": schema59_frontier,
            "ledger_checkpoint_resealed_or_materialized": (
                downgrade_ledger != schema59_ledger
            ),
        }
        check(
            "failed_downgrade_preserves_state",
            downgrade_application == schema59_application,
        )

        legacy_instance.binary = binary
        legacy_instance.start()
        check(
            "candidate_reopens_schema59",
            legacy_instance.call("POST", "sys/unseal", {"key": legacy_key})[0] == 200,
        )
        check(
            "failed_downgrade_preserves_logical_frontier",
            capacity_frontier(legacy_instance) == schema59_frontier,
        )
        old_manager = pg.manager_password
        check(
            "custom_root_rotation",
            legacy_instance.call("POST", "database/rotate-root/local", {})[0] == 204,
        )
        check("old_manager_password_denied", not pg.login("hb_manager", old_manager))
        status, configured = legacy_instance.call("GET", "database/config/local")
        check(
            "custom_statements_survive_rotation",
            status == 200
            and configured.get("data", {}).get("root_rotation_statements")
            == CUSTOM_STATEMENTS
            and "password" not in configured.get("data", {}),
        )
        role_status, _ = legacy_instance.call(
            "POST",
            "database/roles/dynamic",
            {
                "db_name": "local",
                "provider_role": "app_reader",
                "default_ttl": 60,
                "max_ttl": 300,
            },
        )
        credential_status, credential = legacy_instance.call(
            "GET", "database/creds/dynamic"
        )
        service_lease = credential.get("lease_id")
        check(
            "service_uses_rotated_manager_password",
            role_status == 204
            and credential_status == 200
            and isinstance(service_lease, str)
            and bool(service_lease),
        )
        legacy_instance.stop()
        legacy_instance.start()
        check(
            "restart_unseal",
            legacy_instance.call("POST", "sys/unseal", {"key": legacy_key})[0] == 200,
        )
        status, configured = legacy_instance.call("GET", "database/config/local")
        check(
            "custom_statements_survive_restart",
            status == 200
            and configured.get("data", {}).get("root_rotation_statements")
            == CUSTOM_STATEMENTS,
        )
        check(
            "second_custom_root_rotation",
            legacy_instance.call("POST", "database/rotate-root/local", {})[0] == 204,
        )
        revoke_status, _ = legacy_instance.call(
            "POST", "sys/leases/revoke", {"lease_id": service_lease}
        )
        retired_status, _ = legacy_instance.call(
            "POST", "sys/leases/lookup", {"lease_id": service_lease}
        )
        check(
            "service_lease_retires_before_authentication_change",
            revoke_status == 204 and retired_status in (400, 404),
        )
        check(
            "scram_configuration",
            legacy_instance.call(
                "POST",
                "database/config/local",
                {"password_authentication": "scram-sha-256"},
            )[0]
            == 204,
        )
        check(
            "scram_custom_root_rotation",
            legacy_instance.call("POST", "database/rotate-root/local", {})[0] == 204,
        )
        verifier = row(
            pg,
            "SELECT rolpassword LIKE 'SCRAM-SHA-256$4096:%' "
            "FROM pg_authid WHERE rolname='hb_manager'",
        )
        check("scram_provider_verifier_observed", verifier == ["t"])
        check(
            "scram_service_remains_operational",
            legacy_instance.call("GET", "database/creds/dynamic")[0] == 200,
        )
        ledger = row(
            pg,
            "SELECT count(*),min(seq),max(seq),"
            "bool_and(length(payload_digest)=64) "
            "FROM heptabao_provider.root_rotations WHERE manager='hb_manager'",
        )
        check(
            "root_rotation_ledger_single_and_monotonic",
            len(ledger) == 4
            and ledger[0] == "1"
            and int(ledger[1]) == int(ledger[2])
            and int(ledger[2]) > 0
            and ledger[3] == "t",
        )

        plaintexts = [value.encode() for value in sensitive if value]
        check(
            "candidate_storage_contains_no_plaintext_credentials",
            all(
                all(secret not in path.read_bytes() for secret in plaintexts)
                for path in (legacy_instance.root / "data").rglob("*")
                if path.is_file()
            ),
        )
        audit = (legacy_instance.root / "audit.jsonl").read_bytes()
        check(
            "candidate_audit_contains_no_plaintext_credentials",
            all(secret not in audit for secret in plaintexts),
        )
        after = source_identity(ROOT)
        unchanged = (
            before == after
            and digest(binary) == binary_hash
            and digest(legacy_binary) == legacy_hash
            and digest(Path(__file__)) == runner_hash
        )
        check("source_and_binary_unchanged", unchanged)
        check("complete", set(row["case"] for row in checks) | {"complete"} == REQUIRED_CASES)
        report = {
            "schema": "heptabao.postgresql-root-rotation-statements-live.v1",
            "status": "passed",
            "source_identity": before,
            "legacy_source_commit": legacy_source_commit,
            "binary_sha256": binary_hash,
            "legacy_binary_sha256": legacy_hash,
            "runner_sha256": runner_hash,
            "provider_sql_sha256": digest(ROOT / "bootstrap/postgresql/provider.sql"),
            "upgrade_sql_sha256": digest(
                ROOT / "bootstrap/postgresql/upgrade_v6_root_rotation_statements.sql"
            ),
            "postgres_version": subprocess.check_output(
                [str(postgres_bin / "postgres"), "--version"], text=True
            ).strip(),
            "checks": checks,
            "check_count": len(checks),
            "durable_reopen_observations": durable_reopen_observations,
            "real_postgresql_executed": True,
            "schema56_to_schema59_upgrade": True,
            "bounded_root_rotation_statements": True,
            "arbitrary_sql_supported": False,
            "full_openbao_compatibility": False,
            "independent_qualification": False,
            "production_authority": False,
        }
    except Exception as error:
        report = {
            "schema": "heptabao.postgresql-root-rotation-statements-live.v1",
            "status": "failed",
            "failure": {
                "case": current_case,
                "error_type": type(error).__name__,
                "safe_failure_code": (
                    str(error) if isinstance(error, FixtureFailure)
                    else type(error).__name__
                ),
            },
            "source_identity": before,
            "legacy_source_commit": legacy_source_commit,
            "binary_sha256": binary_hash,
            "legacy_binary_sha256": legacy_hash,
            "runner_sha256": runner_hash,
            "checks": checks,
            "check_count": len(checks),
            "durable_reopen_observations": durable_reopen_observations,
            "real_postgresql_executed": pg is not None,
            "full_openbao_compatibility": False,
            "independent_qualification": False,
            "production_authority": False,
        }
    finally:
        if instance is not None:
            instance.stop()
        if legacy_instance is not None:
            legacy_instance.stop()
        if pg is not None:
            pg.stop()
    names = [check["case"] for check in checks]
    complete = (
        report["status"] == "passed"
        and len(names) == len(set(names))
        and set(names) == REQUIRED_CASES
        and all(check["passed"] is True for check in checks)
    )
    if not complete:
        report["status"] = "failed"
        report.setdefault("failure", {
            "case": "fixed_case_denominator",
            "error_type": "FixtureFailure",
        })
        report["retained_failure_work_dir"] = str(work)
    else:
        shutil.rmtree(work, ignore_errors=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    output.chmod(0o600)
    print(json.dumps({
        "status": report["status"],
        "check_count": len(checks),
        "failure": report.get("failure"),
    }))
    return 0 if report["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--legacy-binary", required=True, type=Path)
    parser.add_argument("--build-source-commit", required=True)
    parser.add_argument("--legacy-source-commit", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--expected-legacy-sha256", required=True)
    parser.add_argument("--postgres-bin", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    legacy_binary = args.legacy_binary.resolve(strict=True)
    postgres_bin = args.postgres_bin.resolve(strict=True)
    work = args.work_dir.resolve()
    output = args.output.resolve()
    if work.exists() or output.exists() or output.is_relative_to(work):
        parser.error("work-dir and output must be separate new absolute paths")
    if not re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit):
        parser.error("invalid build source commit")
    if not re.fullmatch(r"[0-9a-f]{40}", args.legacy_source_commit):
        parser.error("invalid legacy source commit")
    for value in (args.expected_binary_sha256, args.expected_legacy_sha256):
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            parser.error("invalid executable digest")
    required = [postgres_bin / name for name in ("postgres", "initdb", "psql")]
    if not all(path.is_file() and os.access(path, os.X_OK) for path in required):
        return 77
    work.mkdir(mode=0o700, parents=True)
    return run(
        binary,
        legacy_binary,
        postgres_bin,
        work,
        output,
        args.build_source_commit,
        args.legacy_source_commit,
        args.expected_binary_sha256,
        args.expected_legacy_sha256,
    )


if __name__ == "__main__":
    raise SystemExit(main())
