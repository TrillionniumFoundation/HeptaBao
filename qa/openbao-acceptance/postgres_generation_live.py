#!/usr/bin/env python3
"""Exercise PostgreSQL password policies and username templates on real PG17.

The profile covers fresh and v4-to-v5 provider installation, Service-owned
password policies, dynamic/static/root credential paths, and restart. It uses
only a new private loopback cluster and synthetic identities.
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
from candidate_state_schema import expected_schema
from postgres_live import Postgres
from smoke import Instance

PIN_PATH = ROOT / "qa/openbao-acceptance/fixtures/postgres-schema-migration-sources-v1.json"
PINS = json.loads(PIN_PATH.read_text())
SCHEMA55_SOURCE = PINS["schema55_generation"]["commit"]
SCHEMA55_TREE = PINS["schema55_generation"]["tree"]
OFFICIAL_TEMPLATE = '{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 20) (unix_time) | truncate 63 }}'
REQUIRED_CASES = frozenset({
    "fresh_generation_protocol", "forward_generation_protocol",
    "fresh_and_upgrade_generation_owners_match",
    "manager_cannot_install_generation_upgrade",
    "manager_requires_generation_protocol_grant",
    "legacy_provider_cleanup_preserved",
    "legacy_state_created_by_pinned_binary", "legacy_read_does_not_rewrite_state",
    "legacy_connection_shape_preserved", "legacy_dynamic_username_and_password",
    "legacy_old_binary_rejects_current_schema", "legacy_failed_downgrade_preserves_state",
    "legacy_candidate_reopens", "legacy_failed_downgrade_preserves_logical_frontier",
    "initialize", "unseal", "mount", "password_policy_crud",
    "connection_default_password_policy", "dynamic_role_policy_override",
    "official_default_username_template", "custom_username_template",
    "official_default_password_shape", "dynamic_password_logs_in",
    "override_password_logs_in", "custom_password_logs_in",
    "partial_connection_update_with_active_leases",
    "partial_update_preserves_manager_and_policy",
    "provider_identity_change_rejected_with_active_leases",
    "partial_template_issue", "partial_template_password_inherits_connection",
    "official_template_reset",
    "operator_enrolls_static_identity", "static_role_policy_override",
    "static_password_logs_in", "root_rotation_connection_policy",
    "old_manager_password_denied", "rotated_manager_password_logs_in",
    "restart_unseal", "generation_config_survives_restart",
    "deleted_role_policy_blocks_new_issue", "existing_lease_survives_policy_delete",
    "candidate_storage_contains_no_plaintext_credentials",
    "candidate_audit_contains_no_plaintext_credentials",
    "source_and_binary_unchanged", "complete",
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
    # Reopen may materialize the same committed operations into a freshly
    # sealed ledger checkpoint. Snapshot, journal and seal are byte-stable.
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
        "state_bytes", "generation", "retained_operations",
        "journal_bytes", "state_schema",
    )
    require(
        status == 200 and all(type(data.get(name)) is int for name in names),
        "durable_frontier_unavailable",
    )
    return {name: data[name] for name in names}


AUDIT_OPAQUE_FIELDS = frozenset({"mac", "path_digest", "previous"})


def audit_contains_plaintext(audit: bytes, plaintexts: list[bytes]) -> bool:
    """Inspect semantic audit text while excluding authenticated digest fields.

    Raw substring search is invalid for low-entropy synthetic credentials: the
    initial all-zero chain frontier is Base64-encoded as a run of `A` bytes.
    Malformed records fail closed, and every non-cryptographic string field is
    still searched for plaintext or embedded error/detail disclosure.
    """
    try:
        records = [json.loads(line) for line in audit.splitlines() if line]
    except (UnicodeDecodeError, json.JSONDecodeError):
        return True
    if not records or any(not isinstance(record, dict) for record in records):
        return True

    def exposed(value, secret: str, key: str | None = None) -> bool:
        if key in AUDIT_OPAQUE_FIELDS:
            return False
        if isinstance(value, dict):
            return any(exposed(child, secret, child_key) for child_key, child in value.items())
        if isinstance(value, list):
            return any(exposed(child, secret) for child in value)
        return isinstance(value, str) and secret in value

    for plaintext in plaintexts:
        try:
            secret = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            # JSON audit is UTF-8 text. A non-UTF-8 secret can only appear through
            # an encoded representation, which is not plaintext disclosure.
            continue
        if secret and any(exposed(record, secret) for record in records):
            return True
    return False


def row(pg: Postgres, query: str, *, database: str = "app") -> list[str]:
    result = pg.sql(query, database=database)
    require(result.returncode == 0, "operator_readback_failed")
    return result.stdout.strip().split("|") if result.stdout.strip() else []


def manager_call(pg: Postgres, query: str, *, database: str = "app"):
    return pg.sql(
        query, user="hb_manager", password=pg.manager_password, database=database
    )


def definitions(pg: Postgres, database: str) -> str:
    names = (
        "apply", "apply_statements", "default_statement_revoke",
        "generation_protocol", "retire", "retire_statement", "retired",
        "statement_retired", "valid_dynamic_username", "valid_password_credential",
    )
    quoted = ",".join("'" + name + "'" for name in names)
    query = (
        "SELECT p.proname||':'||pg_get_function_identity_arguments(p.oid)||E'\\n'"
        "||pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n "
        "ON n.oid=p.pronamespace WHERE n.nspname='heptabao_provider' "
        f"AND p.proname IN ({quoted}) ORDER BY p.proname,"
        "pg_get_function_identity_arguments(p.oid)"
    )
    result = pg.sql(query, database=database)
    require(result.returncode == 0, "provider_definition_readback_failed")
    return result.stdout
def policy(length: int, character: str) -> str:
    return (
        f'length = {length}\nrule "charset" {{ charset = "{character}" '
        f'min-chars = {length} }}'
    )


def official_password(value) -> bool:
    return (
        isinstance(value, str) and len(value) == 20
        and any(c.islower() for c in value)
        and any(c.isupper() for c in value)
        and any(c.isdigit() for c in value)
        and "-" in value
    )


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
    path.write_text(json.dumps(config)); path.chmod(0o600)


def configure_instance(instance: Instance, pg: Postgres):
    configure_outbound(instance, pg)
    instance.start()
    status, initialized = instance.call(
        "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
    )
    require(status == 200, "initialize")
    instance.token = initialized["root_token"]
    key = initialized["keys_base64"][0]
    require(instance.call("POST", "sys/unseal", {"key": key})[0] == 200, "unseal")
    require(instance.call("POST", "sys/mounts/database", {"type": "database"})[0] == 204, "mount")
    return key
def run(binary: Path, legacy_binary: Path, postgres_bin: Path, work: Path, output: Path,
        build_source_commit: str, legacy_source_commit: str,
        expected_binary_sha256: str, expected_legacy_sha256: str) -> int:
    os.umask(0o077)
    before = source_identity(ROOT)
    current_schema = expected_schema(ROOT, build_source_commit)
    binary_hash, legacy_hash, runner_hash = (
        digest(binary), digest(legacy_binary), digest(Path(__file__))
    )
    require(before["head"] == build_source_commit, "candidate_source_commit_mismatch")
    require(PINS.get("schema") == "heptabao.postgresql-schema-migration-sources.v1",
            "schema_source_pin_format_mismatch")
    require(legacy_source_commit == SCHEMA55_SOURCE, "schema55_source_pin_mismatch")
    legacy_tree = subprocess.check_output(
        ["git", "rev-parse", legacy_source_commit + "^{tree}"], cwd=ROOT, text=True
    ).strip()
    require(legacy_tree == SCHEMA55_TREE, "schema55_source_tree_mismatch")
    require(binary_hash == expected_binary_sha256, "candidate_binary_digest_mismatch")
    require(legacy_hash == expected_legacy_sha256, "legacy_binary_digest_mismatch")
    require(binary_hash != legacy_hash, "candidate_and_legacy_binaries_must_differ")
    checks, sensitive = [], []
    current_case = "setup"
    instance = Instance(binary, work / "candidate")
    legacy_instance = None
    pg = None
    durable_reopen_observations: dict[str, object] = {}

    def check(name, condition):
        nonlocal current_case
        current_case = name
        checks.append({"case": name, "passed": condition is True})
        require(condition is True, name)

    try:
        pg = Postgres(
            postgres_bin, work / "postgres", instance.root / "tls.crt",
            instance.root / "tls.key", instance.root / "ca.crt"
        )
        pg.start(); pg.install()
        sensitive.extend([pg.password, pg.manager_password])
        check(
            "fresh_generation_protocol",
            manager_call(pg, "SELECT heptabao_provider.generation_protocol()").stdout.strip()
            == "heptabao-postgresql-generation-v1",
        )
        check(
            "fresh_generation_validators",
            manager_call(pg,
                "SELECT heptabao_provider.valid_dynamic_username('v-root-reader-Aa0b-1700000000'),"
                "heptabao_provider.valid_password_credential('Aa1-safe-policy')"
            ).stdout.strip() == "t|t",
        )
        check(
            "upgrade_database_created",
            pg.sql("CREATE DATABASE generation_upgrade", database="postgres").returncode == 0,
        )
        baseline = ROOT / "qa/openbao-acceptance/fixtures/postgresql-provider-v4-generation-baseline.sql"
        upgrade = ROOT / "bootstrap/postgresql/upgrade_v5_password_policy_username_templates.sql"
        check(
            "v4_generation_baseline_installed",
            pg.sql(baseline.read_text(), database="generation_upgrade").returncode == 0,
        )
        grants = (
            "GRANT USAGE ON SCHEMA heptabao_provider TO hb_manager;"
            "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA heptabao_provider TO hb_manager;"
            "INSERT INTO heptabao_provider.allowed_groups VALUES('hb_manager','app_reader');"
        )
        check(
            "v4_manager_grants_installed",
            pg.sql(grants, database="generation_upgrade").returncode == 0,
        )
        check(
            "manager_cannot_install_generation_upgrade",
            manager_call(pg, upgrade.read_text(), database="generation_upgrade").returncode != 0,
        )
        check(
            "owner_installs_generation_upgrade",
            pg.sql(upgrade.read_text(), database="generation_upgrade").returncode == 0,
        )
        check(
            "manager_requires_generation_protocol_grant",
            manager_call(pg, "SELECT heptabao_provider.generation_protocol()",
                         database="generation_upgrade").returncode != 0,
        )
        check(
            "operator_grants_generation_protocol",
            pg.sql(
                "GRANT EXECUTE ON FUNCTION heptabao_provider.generation_protocol() TO hb_manager",
                database="generation_upgrade",
            ).returncode == 0,
        )
        check(
            "forward_generation_protocol",
            manager_call(pg, "SELECT heptabao_provider.generation_protocol()",
                         database="generation_upgrade").stdout.strip()
            == "heptabao-postgresql-generation-v1",
        )
        check(
            "fresh_and_upgrade_generation_owners_match",
            definitions(pg, "app") == definitions(pg, "generation_upgrade"),
        )
        legacy = manager_call(
            pg,
            "SELECT heptabao_provider.apply('hbf1:'||repeat('1',64),"
            "'hb1:'||repeat('2',64),'hbp_'||repeat('a',28),1,'revoke',0,"
            "'app_reader','',repeat('3',64))::text",
            database="generation_upgrade",
        )
        try:
            legacy_observation = json.loads(legacy.stdout)
        except (TypeError, json.JSONDecodeError):
            legacy_observation = None
        check(
            "legacy_provider_cleanup_preserved",
            legacy.returncode == 0
            and isinstance(legacy_observation, dict)
            and legacy_observation.get("found") is True
            and legacy_observation.get("fence_id") == "hbf1:" + "1" * 64
            and legacy_observation.get("lease_id") == "hb1:" + "2" * 64
            and legacy_observation.get("username") == "hbp_" + "a" * 28
            and legacy_observation.get("seq") == 1
            and legacy_observation.get("action") == "revoke"
            and legacy_observation.get("expires") == 0
            and legacy_observation.get("request_digest") == "3" * 64
            and legacy_observation.get("login") is False
            and legacy_observation.get("active_sessions") == 0,
        )
        check(
            "legacy_cleanup_retired",
            manager_call(
                pg,
                "SELECT heptabao_provider.retire('hbf1:'||repeat('1',64),"
                "'hb1:'||repeat('2',64),'hbp_'||repeat('a',28),1)",
                database="generation_upgrade",
            ).stdout.strip() == "t",
        )
        # A real schema-55 connection created by the pinned predecessor must
        # remain byte-stable under current pure reads and retain its legacy
        # username/password profile until a current mutation publishes the current schema.
        legacy_instance = Instance(legacy_binary, work / "legacy-state")
        configure_outbound(legacy_instance, pg)
        legacy_instance.start()
        status, legacy_init = legacy_instance.call(
            "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
        )
        check("legacy_binary_initialize", status == 200)
        legacy_instance.token = legacy_init["root_token"]
        legacy_key = legacy_init["keys_base64"][0]
        check("legacy_binary_unseal", legacy_instance.call(
            "POST", "sys/unseal", {"key": legacy_key}
        )[0] == 200)
        check("legacy_binary_mount", legacy_instance.call(
            "POST", "sys/mounts/database", {"type": "database"}
        )[0] == 204)
        legacy_connection = {
            "plugin_name": "postgresql-database-plugin",
            "connection_url": pg.origin + "/app",
            "username": "hb_manager",
            "password": pg.manager_password,
            "allowed_roles": ["legacy"],
        }
        check("legacy_binary_connection", legacy_instance.call(
            "POST", "database/config/legacy", legacy_connection
        )[0] == 204)
        legacy_role = {
            "db_name": "legacy", "provider_role": "app_reader",
            "default_ttl": 60, "max_ttl": 300,
        }
        check("legacy_binary_role", legacy_instance.call(
            "POST", "database/roles/legacy", legacy_role
        )[0] == 204)
        schema55_frontier = capacity_frontier(legacy_instance)
        legacy_instance.stop()
        legacy_data_root = legacy_instance.root / "data"
        legacy_state = legacy_data_root / "state.hbs"
        schema55_application = durable_application_snapshot(legacy_data_root)
        schema55_ledger = durable_ledger_digest(legacy_data_root)
        check("legacy_state_created_by_pinned_binary", legacy_state.is_file())

        legacy_instance.binary = binary
        legacy_instance.start()
        check("legacy_candidate_unseal", legacy_instance.call(
            "POST", "sys/unseal", {"key": legacy_key}
        )[0] == 200)
        status, legacy_read = legacy_instance.call("GET", "database/config/legacy")
        legacy_data = legacy_read.get("data", {})
        check(
            "legacy_connection_shape_preserved",
            status == 200 and "password_policy" not in legacy_data
            and legacy_data.get("username_template") == "",
        )
        schema55_after_application = durable_application_snapshot(legacy_data_root)
        schema55_after_frontier = capacity_frontier(legacy_instance)
        schema55_after_ledger = durable_ledger_digest(legacy_data_root)
        durable_reopen_observations["schema55"] = {
            "application_artifacts_unchanged": (
                schema55_after_application == schema55_application
            ),
            "frontier_before": schema55_frontier,
            "frontier_after": schema55_after_frontier,
            "logical_frontier_unchanged": schema55_after_frontier == schema55_frontier,
            "ledger_checkpoint_resealed_or_materialized": (
                schema55_after_ledger != schema55_ledger
            ),
        }
        check(
            "legacy_read_does_not_rewrite_state",
            schema55_after_application == schema55_application
            and schema55_after_frontier == schema55_frontier,
        )
        status, legacy_issued = legacy_instance.call("GET", "database/creds/legacy")
        legacy_username = legacy_issued.get("data", {}).get("username")
        legacy_password = legacy_issued.get("data", {}).get("password")
        check(
            "legacy_dynamic_username_and_password",
            status == 200
            and isinstance(legacy_username, str)
            and re.fullmatch(r"hbp_[0-9a-f]{32}", legacy_username) is not None
            and isinstance(legacy_password, str)
            and re.fullmatch(r"[0-9a-f]{64}", legacy_password) is not None
            and pg.login(legacy_username, legacy_password),
        )
        sensitive.append(legacy_password)
        current_schema_frontier = capacity_frontier(legacy_instance)
        legacy_instance.stop()
        current_schema_application = durable_application_snapshot(legacy_data_root)
        current_schema_ledger = durable_ledger_digest(legacy_data_root)
        require(
            current_schema_application != schema55_application
            and current_schema_frontier["state_schema"] == current_schema,
            "current_schema_state_not_published",
        )

        legacy_instance.binary = legacy_binary
        legacy_instance.start()
        check("legacy_old_binary_rejects_current_schema", legacy_instance.call(
            "POST", "sys/unseal", {"key": legacy_key}
        )[0] == 503)
        legacy_instance.stop()
        downgrade_application = durable_application_snapshot(legacy_data_root)
        downgrade_ledger = durable_ledger_digest(legacy_data_root)
        durable_reopen_observations["current_schema_old_reader_refusal"] = {
            "application_artifacts_unchanged": (
                downgrade_application == current_schema_application
            ),
            "frontier_before": current_schema_frontier,
            "ledger_checkpoint_resealed_or_materialized": (
                downgrade_ledger != current_schema_ledger
            ),
        }
        check(
            "legacy_failed_downgrade_preserves_state",
            downgrade_application == current_schema_application,
        )

        legacy_instance.binary = binary
        legacy_instance.start()
        check("legacy_candidate_reopens", legacy_instance.call(
            "POST", "sys/unseal", {"key": legacy_key}
        )[0] == 200 and pg.login(legacy_username, legacy_password))
        check(
            "legacy_failed_downgrade_preserves_logical_frontier",
            capacity_frontier(legacy_instance) == current_schema_frontier,
        )
        legacy_instance.stop()
        initial_static = "a1" * 32
        sensitive.append(initial_static)
        check(
            "operator_enrolls_static_identity",
            pg.sql(
                "CREATE ROLE app_static LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS PASSWORD '" + initial_static + "';"
                "INSERT INTO heptabao_provider.allowed_static_roles "
                "VALUES('hb_manager','app_static');"
            ).returncode == 0,
        )
        key = configure_instance(instance, pg)
        check("initialize", True)
        check("unseal", True)
        check("mount", True)
        for name, length, character in (
            ("connection-policy", 12, "A"),
            ("role-policy", 14, "B"),
        ):
            check(
                "password_policy_" + name,
                instance.call(
                    "POST", "sys/policies/password/" + name,
                    {"policy": policy(length, character)},
                )[0] == 204,
            )
        status, generated = instance.call(
            "GET", "sys/policies/password/role-policy/generate"
        )
        check(
            "password_policy_crud",
            status == 200 and generated.get("data", {}).get("password") == "B" * 14,
        )
        base_connection = {
            "plugin_name": "postgresql-database-plugin",
            "connection_url": pg.origin + "/app",
            "username": "hb_manager",
            "password": pg.manager_password,
        }
        local = dict(
            base_connection,
            allowed_roles=["default", "override", "staticapp"],
            password_policy="connection-policy",
        )
        check(
            "configure_local_generation",
            instance.call("POST", "database/config/local", local)[0] == 204,
        )
        status, configured = instance.call("GET", "database/config/local")
        data = configured.get("data", {})
        check(
            "connection_policy_readback",
            status == 200 and data.get("password_policy") == "connection-policy",
        )
        check(
            "official_template_readback",
            data.get("username_template") == OFFICIAL_TEMPLATE,
        )
        custom = dict(
            base_connection,
            allowed_roles=["custom"],
            password_policy="connection-policy",
            username_template='{{ printf "custom-%s-%s" (.DisplayName | truncate 4) (.RoleName | truncate 6) }}',
        )
        check(
            "configure_custom_generation",
            instance.call("POST", "database/config/custom", custom)[0] == 204,
        )
        official = dict(base_connection, allowed_roles=["official"])
        check(
            "configure_official_defaults",
            instance.call("POST", "database/config/official", official)[0] == 204,
        )
        role = {"provider_role": "app_reader", "default_ttl": 60, "max_ttl": 300}
        check(
            "create_default_role",
            instance.call("POST", "database/roles/default", dict(role, db_name="local"))[0] == 204,
        )
        check(
            "create_override_role",
            instance.call("POST", "database/roles/override", dict(
                role, db_name="local",
                credential_config={"password_policy": "role-policy"},
            ))[0] == 204,
        )
        check(
            "role_policy_readback",
            instance.call("GET", "database/roles/override")[1]
            .get("data", {}).get("credential_config")
            == {"password_policy": "role-policy"},
        )
        check(
            "create_custom_role",
            instance.call("POST", "database/roles/custom", dict(role, db_name="custom"))[0] == 204,
        )
        check(
            "create_official_role",
            instance.call("POST", "database/roles/official", dict(role, db_name="official"))[0] == 204,
        )
        issued = {}
        for name in ("default", "override", "custom", "official"):
            status, response = instance.call("GET", "database/creds/" + name)
            username = response.get("data", {}).get("username")
            password = response.get("data", {}).get("password")
            check(name + "_issue", status == 200 and isinstance(username, str)
                  and isinstance(password, str) and isinstance(response.get("lease_id"), str))
            issued[name] = (username, password, response["lease_id"])
            sensitive.append(password)
        check(
            "official_default_username_template",
            re.fullmatch(r"v-root-default-[0-9A-Za-z]{20}-[0-9]{10}", issued["default"][0])
            is not None,
        )
        check(
            "connection_default_password_policy",
            issued["default"][1] == "A" * 12,
        )
        check(
            "dynamic_role_policy_override",
            issued["override"][1] == "B" * 14,
        )
        check(
            "custom_username_template",
            issued["custom"][0] == "custom-root-custom",
        )
        check("official_default_password_shape", official_password(issued["official"][1]))
        check("dynamic_password_logs_in", pg.login(*issued["default"][:2]))
        check("override_password_logs_in", pg.login(*issued["override"][:2]))
        check("custom_password_logs_in", pg.login(*issued["custom"][:2]))
        check("official_password_logs_in", pg.login(*issued["official"][:2]))

        partial_template = '{{ printf "partial-%s" (.RoleName | truncate 16) }}'
        check(
            "partial_connection_update_with_active_leases",
            instance.call(
                "POST", "database/config/local",
                {
                    "allowed_roles": ["default", "override", "partial", "staticapp"],
                    "username_template": partial_template,
                    "verify_connection": True,
                },
            )[0] == 204,
        )
        status, partial_config = instance.call("GET", "database/config/local")
        partial_data = partial_config.get("data", {})
        check(
            "partial_update_preserves_manager_and_policy",
            status == 200
            and partial_data.get("connection_url") == pg.origin + "/app"
            and partial_data.get("username") == "hb_manager"
            and partial_data.get("password_policy") == "connection-policy"
            and partial_data.get("username_template") == partial_template
            and pg.login("hb_manager", pg.manager_password),
        )
        denied_status, denied = instance.call(
            "POST", "database/config/local",
            {"password": "must-not-replace-live-manager", "verify_connection": True},
        )
        check(
            "provider_identity_change_rejected_with_active_leases",
            denied_status == 409 and "data" not in denied
            and pg.login("hb_manager", pg.manager_password),
        )
        check(
            "create_partial_role",
            instance.call(
                "POST", "database/roles/partial", dict(role, db_name="local")
            )[0] == 204,
        )
        status, partial = instance.call("GET", "database/creds/partial")
        partial_username = partial.get("data", {}).get("username")
        partial_password = partial.get("data", {}).get("password")
        check(
            "partial_template_issue",
            status == 200 and partial_username == "partial-partial"
            and isinstance(partial_password, str)
            and pg.login(partial_username, partial_password),
        )
        check(
            "partial_template_password_inherits_connection",
            partial_password == "A" * 12,
        )
        sensitive.append(partial_password)
        check(
            "official_template_reset",
            instance.call(
                "POST", "database/config/local",
                {"username_template": "", "verify_connection": True},
            )[0] == 204
            and instance.call("GET", "database/config/local")[1]
            .get("data", {}).get("username_template") == OFFICIAL_TEMPLATE,
        )
        static_request = {
            "db_name": "local", "username": "app_static", "rotation_period": 60,
            "credential_config": {"password_policy": "role-policy"},
        }
        check(
            "create_static_role",
            instance.call("POST", "database/static-roles/staticapp", static_request)[0] == 204,
        )
        status, static = instance.call("GET", "database/static-creds/staticapp")
        static_password = static.get("data", {}).get("password")
        check(
            "static_role_policy_override",
            status == 200 and static_password == "B" * 14,
        )
        sensitive.append(static_password)
        check("static_password_logs_in", pg.login("app_static", static_password))
        old_manager = pg.manager_password
        check(
            "root_rotation_connection_policy",
            instance.call("POST", "database/rotate-root/local", {})[0] == 204,
        )
        rotated_manager = "A" * 12
        sensitive.append(rotated_manager)
        check("old_manager_password_denied", not pg.login("hb_manager", old_manager))
        check("rotated_manager_password_logs_in", pg.login("hb_manager", rotated_manager))
        pg.manager_password = rotated_manager
        check(
            "post_root_rotation_service_operational",
            instance.call("POST", "database/rotate-role/staticapp", {})[0] == 204,
        )
        check(
            "delete_role_password_policy",
            instance.call("DELETE", "sys/policies/password/role-policy", {})[0] == 204,
        )
        denied_status, denied = instance.call("GET", "database/creds/override")
        check(
            "deleted_role_policy_blocks_new_issue",
            denied_status == 404 and "data" not in denied,
        )
        check(
            "existing_lease_survives_policy_delete",
            pg.login(issued["override"][0], issued["override"][1]),
        )
        instance.stop(); instance.start()
        check("restart_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        status, restarted = instance.call("GET", "database/config/local")
        restarted_data = restarted.get("data", {})
        check(
            "generation_config_survives_restart",
            status == 200
            and restarted_data.get("password_policy") == "connection-policy"
            and restarted_data.get("username_template") == OFFICIAL_TEMPLATE,
        )
        status, post_restart = instance.call("GET", "database/creds/default")
        check(
            "post_restart_generation_operational",
            status == 200
            and post_restart.get("data", {}).get("password") == "A" * 12,
        )
        if status == 200:
            sensitive.append(post_restart["data"]["password"])
        plaintexts = [value.encode() for value in sensitive if isinstance(value, str) and value]
        check(
            "candidate_storage_contains_no_plaintext_credentials",
            all(
                all(secret not in path.read_bytes() for secret in plaintexts)
                for path in (instance.root / "data").rglob("*") if path.is_file()
            ),
        )
        audit = (instance.root / "audit.jsonl").read_bytes()
        check(
            "candidate_audit_contains_no_plaintext_credentials",
            not audit_contains_plaintext(audit, plaintexts),
        )
        after = source_identity(ROOT)
        unchanged = (
            before == after and digest(binary) == binary_hash
            and digest(Path(__file__)) == runner_hash
        )
        check("source_and_binary_unchanged", unchanged)
        observed = {entry["case"] for entry in checks if entry["passed"] is True}
        check("complete", REQUIRED_CASES - {"complete"} <= observed)
        report = {
            "schema": "heptabao.postgresql-generation-live.v1",
            "status": "passed",
            "source_identity": before,
            "binary_sha256": binary_hash,
            "legacy_binary_sha256": legacy_hash,
            "build_source_commit": build_source_commit,
            "legacy_source_commit": legacy_source_commit,
            "runner_sha256": runner_hash,
            "expected_current_state_schema": current_schema,
            "provider_sql_sha256": digest(ROOT / "bootstrap/postgresql/provider.sql"),
            "baseline_sql_sha256": digest(baseline),
            "upgrade_sql_sha256": digest(upgrade),
            "postgres_version": subprocess.check_output(
                [str(postgres_bin / "postgres"), "--version"], text=True
            ).strip(),
            "checks": checks,
            "check_count": len(checks),
            "durable_reopen_observations": durable_reopen_observations,
            "fresh_and_forward_provider_equal": True,
            "real_postgresql_executed": True,
            "password_policy_generation": True,
            "postgresql_username_templates": True,
            "full_openbao_compatibility": False,
            "independent_qualification": False,
            "production_authority": False,
        }
    except Exception as error:
        report = {
            "schema": "heptabao.postgresql-generation-live.v1",
            "status": "failed",
            "failure": {"case": current_case, "error_type": type(error).__name__},
            "source_identity": before,
            "binary_sha256": binary_hash,
            "legacy_binary_sha256": legacy_hash,
            "build_source_commit": build_source_commit,
            "legacy_source_commit": legacy_source_commit,
            "runner_sha256": runner_hash,
            "expected_current_state_schema": current_schema,
            "checks": checks,
            "check_count": len(checks),
            "durable_reopen_observations": durable_reopen_observations,
            "real_postgresql_executed": pg is not None,
            "full_openbao_compatibility": False,
            "independent_qualification": False,
            "production_authority": False,
        }
    finally:
        instance.stop()
        if legacy_instance is not None:
            legacy_instance.stop()
        if pg is not None:
            pg.stop()
        shutil.rmtree(work, ignore_errors=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    output.chmod(0o600)
    print(json.dumps({
        "status": report["status"], "check_count": len(checks),
        "failure": report.get("failure"),
    }, sort_keys=True))
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
    if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in
               (args.build_source_commit, args.legacy_source_commit)):
        parser.error("source commit pins must be lowercase SHA-1 values")
    if not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in
               (args.expected_binary_sha256, args.expected_legacy_sha256)):
        parser.error("binary pins must be lowercase SHA-256 values")
    postgres_bin = args.postgres_bin.resolve(strict=True)
    work = args.work_dir.resolve()
    output = args.output.resolve()
    if work.exists() or output.exists() or output.is_relative_to(work):
        parser.error("work-dir and output must be separate new absolute paths")
    required = [postgres_bin / name for name in ("postgres", "initdb", "psql")]
    if not all(path.is_file() and os.access(path, os.X_OK) for path in required):
        return 77
    work.mkdir(mode=0o700, parents=True)
    return run(
        binary, legacy_binary, postgres_bin, work, output,
        args.build_source_commit, args.legacy_source_commit,
        args.expected_binary_sha256, args.expected_legacy_sha256,
    )


if __name__ == "__main__":
    raise SystemExit(main())
