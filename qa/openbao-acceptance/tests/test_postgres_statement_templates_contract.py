"""Statement templates remain bounded, identity-bound and executable."""
from pathlib import Path
import ast
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]


def extension(path: Path) -> str:
    source = path.read_text()
    start = source.index("-- PostgreSQL statement-template extension.")
    boundaries = [source.index("COMMIT;", start)]
    later = source.find("-- PostgreSQL password-authentication extension.", start)
    if later >= 0:
        boundaries.append(later)
    return source[start:min(boundaries)].rstrip() + "\n"


def function(source: str, name: str) -> str:
    match = re.search(
        r"CREATE FUNCTION heptabao_provider\." + re.escape(name)
        + r"\(.*?END \$\$;", source, re.S,
    )
    if match is None:
        raise AssertionError("missing provider function: " + name)
    return match.group(0)


class PostgresStatementTemplateContractTests(unittest.TestCase):
    def test_fresh_and_forward_install_share_exact_extension(self):
        fresh = extension(ROOT / "bootstrap/postgresql/provider.sql")
        upgrade = extension(ROOT / "bootstrap/postgresql/upgrade_v3_statement_templates.sql")
        self.assertEqual(fresh, upgrade)
        self.assertIn("heptabao-postgresql-statements-v1", fresh)

    def test_provider_ledger_has_only_identity_and_digest_fields(self):
        source = extension(ROOT / "bootstrap/postgresql/provider.sql")
        table = source[source.index("CREATE TABLE heptabao_provider.statement_leases"):]
        table = table[:table.index(");")]
        for field in ("request_digest", "statements_digest", "password_digest",
                      "role_oid", "payload_digest"):
            self.assertIn(field, table)
        for forbidden in ("statement text", "password text", "creation_statements",
                          "revocation_statements", "rollback_statements"):
            self.assertNotIn(forbidden, table)

    def test_capacity_and_fence_precede_any_statement_execution(self):
        apply = function(extension(ROOT / "bootstrap/postgresql/provider.sql"), "apply_statements")
        self.assertIn("identity_count>=4096", apply)
        self.assertIn("identity_count>=8192", apply)
        self.assertLess(apply.index("statement provider issuance capacity exhausted"),
                        apply.index("FOR statement IN"))
        self.assertLess(apply.index("provider global fence rejected stale statement operation"),
                        apply.index("FOR statement IN"))
        self.assertIn("statement provider semantic conflict", apply)
        self.assertIn("statement provider resurrection rejected", apply)
        self.assertIn("statement provider postcondition failed", apply)

    def test_statement_payload_digest_is_exact_and_readback_is_compared(self):
        source = extension(ROOT / "bootstrap/postgresql/provider.sql")
        apply = function(source, "apply_statements")
        self.assertIn("p_password text,p_digest text,p_statements text", apply)
        self.assertIn("parsed_statements:=p_statements::jsonb", apply)
        self.assertIn("sha256(convert_to(p_statements,'UTF8'))", apply)
        self.assertNotIn("sha256(convert_to(p_statements::text", apply)
        rust = (ROOT / "crates/heptabao-server/src/service_database_statements.rs").read_text()
        selector = (ROOT / "crates/heptabao-server/src/service_database.rs").read_text()
        self.assertIn('object.get("statements_digest") != Some(&json!(expected_statements_digest))', rust)
        self.assertIn("self.connection.statement_apply_function()", rust)
        self.assertIn("$9::text", selector)
        self.assertNotIn("$9::jsonb", rust + selector)

    def test_parser_tracks_comments_escapes_and_unmatched_placeholder_closers(self):
        rust = (ROOT / "crates/heptabao-server/src/service_database_statements.rs").read_text()
        for guard in ("line_comment", "block_comment_depth", "escape_single",
                      "database statement comment nesting exceeds bound"):
            self.assertIn(guard, rust)
        self.assertIn("(None, Some(_)) => return Err(())", rust)

    def test_default_revoke_is_bounded_but_not_a_direct_definer_bypass(self):
        source = extension(ROOT / "bootstrap/postgresql/provider.sql")
        helper = function(source, "default_statement_revoke")
        self.assertNotIn("SECURITY DEFINER", helper)
        self.assertIn("schema_count>64", helper)
        self.assertIn("ALTER ROLE %I NOLOGIN", helper)
        self.assertIn("pg_terminate_backend", helper)
        self.assertIn("REVOKE CONNECT ON DATABASE", helper)
        self.assertIn("DROP ROLE IF EXISTS", helper)
        self.assertIn(
            "REVOKE ALL ON FUNCTION heptabao_provider.default_statement_revoke(name) FROM PUBLIC",
            source,
        )

    def test_api_persists_official_v262_fields_without_silent_credential_downgrade(self):
        source = (ROOT / "crates/heptabao-server/src/service_database.rs").read_text()
        for field in ("creation_statements", "revocation_statements",
                      "rollback_statements", "renew_statements",
                      "credential_type", "credential_config"):
            self.assertIn('"' + field + '"', source)
        statements = (ROOT / "crates/heptabao-server/src/service_database_statements.rs").read_text()
        self.assertIn('value != "password"', statements)
        self.assertIn("password credential_config requires an integrated password-policy owner", statements)
        self.assertIn("provider_role and statement templates are mutually exclusive", source)
        self.assertIn("statement-backed database roles currently require PostgreSQL", source)

    def test_schema54_gate_and_current_schema_are_explicit(self):
        service = (ROOT / "crates/heptabao-server/src/service.rs").read_text()
        identity = (ROOT / "crates/heptabao-server/src/service_identity.rs").read_text()
        database = (ROOT / "crates/heptabao-server/src/service_database.rs").read_text()
        self.assertRegex(service, r"CURRENT_STATE_SCHEMA: u32 = 55;")
        self.assertIn("database statement templates require schema 54", identity)
        self.assertIn("Exact legacy tuple: old pending intents must reopen byte-stably", database)
        self.assertIn("heptabao.database.statements.v1", database)

    def test_forward_upgrade_is_owner_only_and_does_not_rewrite_old_provider_tables(self):
        upgrade = (ROOT / "bootstrap/postgresql/upgrade_v3_statement_templates.sql").read_text()
        self.assertTrue(upgrade.strip().startswith("-- Forward-only upgrade"))
        self.assertTrue(upgrade.strip().endswith("COMMIT;"))
        self.assertIn("heptabao_provider.protocol() <> 'heptabao-postgresql-provider-v2'", upgrade)
        for forbidden in ("DROP TABLE", "DROP FUNCTION", "ALTER TABLE heptabao_provider.leases",
                          "UPDATE heptabao_provider.leases", "TRUNCATE"):
            self.assertNotIn(forbidden, upgrade)

    def test_real_profile_has_a_fixed_case_denominator_and_no_authority_claim(self):
        path = ROOT / "qa/openbao-acceptance/postgres_statement_templates_live.py"
        source = path.read_text()
        tree = ast.parse(source)
        assignment = next(
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "REQUIRED_CASES"
                    for target in node.targets)
        )
        call = assignment.value
        self.assertIsInstance(call, ast.Call)
        values = ast.literal_eval(call.args[0])
        self.assertGreaterEqual(len(values), 40)
        for case in ("exact_statement_retry_survives_later_global_floor",
                     "failed_creation_rolls_back_role_and_ledger",
                     "manager_cannot_call_default_revoke_outside_ledger",
                     "candidate_storage_contains_no_statement_passwords"):
            self.assertIn(case, values)
        for flag in ("full_openbao_compatibility", "independent_qualification",
                     "production_authority"):
            self.assertIn('"' + flag + '": False', source)

    def test_real_profile_is_a_mandatory_replacement_step(self):
        workflow = (ROOT / ".github/workflows/codex-openbao-replacement-ci.yml").read_text()
        self.assertEqual(workflow.count("postgres_statement_templates_live.py"), 1)
        self.assertIn("--postgres-bin /usr/lib/postgresql/17/bin", workflow)
        self.assertIn("heptabao-postgresql-statement-templates", workflow)


if __name__ == "__main__":
    unittest.main()
