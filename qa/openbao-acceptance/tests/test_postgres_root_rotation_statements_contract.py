"""PostgreSQL root-rotation statements stay bounded and migration-safe."""
from pathlib import Path
import hashlib
import json
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
MARKER = "-- PostgreSQL bounded root-rotation statement extension."


def extension(path: Path) -> str:
    source = path.read_text()
    start = source.index(MARKER)
    end = source.index("COMMIT;", start)
    return source[start:end].rstrip() + "\n"


class RootRotationStatementsContractTests(unittest.TestCase):
    def test_fresh_and_forward_install_share_exact_extension(self):
        fresh = extension(ROOT / "bootstrap/postgresql/provider.sql")
        upgrade = extension(
            ROOT / "bootstrap/postgresql/upgrade_v6_root_rotation_statements.sql"
        )
        self.assertEqual(fresh, upgrade)
        self.assertIn("heptabao-postgresql-root-statements-v1", fresh)
        self.assertIn("rotate_root_statements_scram", fresh)

    def test_upgrade_baseline_is_the_exact_published_v5_provider(self):
        baseline = ROOT / "qa/openbao-acceptance/fixtures/postgresql-provider-v5-root-statements-baseline.sql"
        pins = json.loads(
            (ROOT / "qa/openbao-acceptance/fixtures/postgres-schema-migration-sources-v1.json").read_text()
        )
        published_commit = pins["schema56_root_rotation_statements"]["commit"]
        published = subprocess.check_output(
            ["git", "show", published_commit + ":bootstrap/postgresql/provider.sql"], cwd=ROOT
        )
        baseline_bytes = baseline.read_bytes()
        self.assertEqual(
            hashlib.sha256(baseline_bytes).hexdigest(),
            "29d075931c2b6ce3b627287956377c05dc2b3a0c62e97fd916e832fdfe3586b2",
        )
        self.assertEqual(baseline_bytes, published)
        self.assertNotEqual(
            baseline_bytes,
            (ROOT / "bootstrap/postgresql/provider.sql").read_bytes(),
            "the immutable v5 fixture must not silently adopt the current v6 provider",
        )
    def test_schema_migration_sources_are_exact_ancestors_and_trees(self):
        pins = json.loads((ROOT / "qa/openbao-acceptance/fixtures/postgres-schema-migration-sources-v1.json").read_text())
        self.assertEqual(pins["schema"], "heptabao.postgresql-schema-migration-sources.v1")
        for key in ("schema55_generation", "schema56_root_rotation_statements"):
            commit = pins[key]["commit"]
            tree = pins[key]["tree"]
            observed = subprocess.check_output(
                ["git", "rev-parse", commit + "^{tree}"], cwd=ROOT, text=True
            ).strip()
            self.assertEqual(observed, tree)
            self.assertEqual(
                subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"], cwd=ROOT).returncode,
                0,
            )

    def test_service_schema57_fences_configuration_and_pending_intents(self):
        service = (ROOT / "crates/heptabao-server/src/service.rs").read_text()
        identity = (ROOT / "crates/heptabao-server/src/service_identity.rs").read_text()
        database = (ROOT / "crates/heptabao-server/src/service_database.rs").read_text()
        rotation = (ROOT / "crates/heptabao-server/src/service_database_rotation.rs").read_text()
        self.assertIn("CURRENT_STATE_SCHEMA: u32 = 61;", service)
        self.assertIn("database root rotation statements require schema 57", identity)
        self.assertIn("| 54 | 55 | 56 | 57 | 58 | 59 | 60 | CURRENT_STATE_SCHEMA => Ok(()),", identity)
        self.assertIn("has_root_rotation_statement_state", database)
        self.assertIn("!connection.root_rotation_statements.is_empty()", database)
        self.assertIn("!rotation.statements.is_empty()", database)
        self.assertIn("heptabao.database.root.statements.v1", rotation)
        self.assertIn("root_rotation_statement_state_requires_schema57_independently", rotation)

    def test_capacity_observation_reports_loaded_schema(self):
        capacity = (ROOT / "crates/heptabao-server/src/service_capacity.rs").read_text()
        self.assertIn("let state_schema = state.schema;", capacity)
        self.assertIn('"state_schema": state_schema', capacity)
        self.assertNotIn('"state_schema": CURRENT_STATE_SCHEMA', capacity)
        self.assertIn("capacity_reports_loaded_schema_not_binary_maximum", capacity)

    def test_api_preserves_official_list_semantics_but_rejects_arbitrary_sql(self):
        database = (ROOT / "crates/heptabao-server/src/service_database.rs").read_text()
        statements = (ROOT / "crates/heptabao-server/src/service_database_statements.rs").read_text()
        self.assertIn('"root_rotation_statements"', database)
        self.assertIn("parse_root_rotation_statement_field", database)
        self.assertIn("body.get(key).is_some_and(Value::is_null)", statements)
        self.assertIn("return Ok(Some(Vec::new()))", statements)
        self.assertIn("Some(values) => values", database)
        self.assertIn("None => Vec::new()", database)
        self.assertIn("MAX_RENDERED_STATEMENTS: usize = 64", statements)
        self.assertIn("MAX_STATEMENT_BYTES: usize = 16 * 1024", statements)
        self.assertIn("MAX_STATEMENTS_BYTES: usize = 64 * 1024", statements)
        for command in ("ALTER ROLE", "ALTER USER"):
            self.assertIn(command, statements)
        for placeholder in ('\\"{{username}}\\"', '\\"{{name}}\\"', "{{password}}"):
            self.assertIn(placeholder, statements)
        self.assertIn("root rotation statements must be bounded PostgreSQL password changes", statements)
    def test_provider_executes_only_after_identity_digest_and_global_fence_checks(self):
        source = extension(ROOT / "bootstrap/postgresql/provider.sql")
        self.assertLess(source.index("root-rotation semantic conflict"), source.index("EXECUTE rendered"))
        self.assertLess(source.index("provider global fence rejected stale root rotation"), source.index("EXECUTE rendered"))
        self.assertIn("jsonb_build_array(p_fence,p_id,p_seq,p_password,p_digest,p_statements)", source)
        self.assertIn("pg_advisory_xact_lock", source)
        self.assertIn("quote_ident(session_user)", source)
        self.assertIn("quote_literal(p_password)", source)
        self.assertIn("chr(39)||'{{password}}'||chr(39)", source)
        profile = (ROOT / "qa/openbao-acceptance/postgres_root_rotation_statements_live.py").read_text()
        self.assertIn("SET standard_conforming_strings=off;", profile)
        self.assertIn("def durable_application_snapshot(root: Path)", profile)
        self.assertIn("def durable_ledger_digest(root: Path)", profile)
        self.assertIn("def capacity_frontier(instance: Instance)", profile)
        self.assertIn('("state.hbs", "journal.hbj", "seal.json")', profile)
        self.assertNotIn('for name in ("state.hbs", "journal.hbj", "ledger.hbl"', profile)
        self.assertIn('"ledger_checkpoint_resealed_or_materialized"', profile)
        self.assertIn('"failed_downgrade_preserves_logical_frontier"', profile)
        self.assertIn("revoke_status == 204 and retired_status in (400, 404)", profile)
        self.assertIn("capacity_frontier(legacy_instance) == current_schema_frontier", profile)
        self.assertIn("def sql_dollar_literal(value: str)", profile)
        self.assertIn("sql_dollar_literal(direct_statements)", profile)
        self.assertIn("Quoted-New-'\\\\-Password-2", profile)
        self.assertIn('report["retained_failure_work_dir"] = str(work)', profile)
        self.assertIn("shutil.rmtree(work, ignore_errors=True)", profile)
        self.assertNotIn("escaped_password", source)
        self.assertNotIn("'{{name}}',session_user", source)
        self.assertNotIn("'{{username}}',session_user", source)
        self.assertIn("root rotation statement postcondition failed", source)
        self.assertIn("password_digest,payload_digest", source)

    def test_forward_upgrade_is_owner_only_repeatable_and_non_destructive(self):
        upgrade = (ROOT / "bootstrap/postgresql/upgrade_v6_root_rotation_statements.sql").read_text()
        self.assertTrue(upgrade.strip().startswith("-- Forward-only upgrade"))
        self.assertIn("SET LOCAL lock_timeout = '5s'", upgrade)
        self.assertIn("SET LOCAL statement_timeout = '30s'", upgrade)
        for protocol in (
            "heptabao-postgresql-provider-v2",
            "heptabao-postgresql-static-v1",
            "heptabao-postgresql-statements-v1",
            "heptabao-postgresql-password-authentication-v1",
            "heptabao-postgresql-generation-v1",
        ):
            self.assertIn(protocol, upgrade)
        for forbidden in ("DROP TABLE", "DROP FUNCTION", "TRUNCATE", "DELETE FROM"):
            self.assertNotIn(forbidden, upgrade)

    def test_current_contract_does_not_claim_arbitrary_statement_parity(self):
        docs = (ROOT / "docs/engines/HEPTABAO_POSTGRESQL_PROVIDER.md").read_text()
        state = (ROOT / "docs/architecture/HEPTABAO_CURRENT_STATE_FORMAT.md").read_text()
        self.assertIn("upgrade_v6_root_rotation_statements.sql", docs)
        self.assertIn("Schema 57 independently", docs)
        self.assertIn("explicit `null`, an empty string or", docs)
        self.assertIn("quote_literal(p_password)", docs)
        self.assertIn("arbitrary official root-rotation SQL", docs)
        self.assertIn("root_rotation_statements", state)
        self.assertIn("older reader must reject nonempty lists", state)


if __name__ == "__main__":
    unittest.main()
