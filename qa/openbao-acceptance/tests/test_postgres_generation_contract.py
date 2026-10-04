"""Password-policy and PostgreSQL username generation stay migration-safe."""
from pathlib import Path
import importlib.util
import json
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/openbao-acceptance"))
from candidate_state_schema import parse_current_schema

PROFILE_PATH = ROOT / "qa/openbao-acceptance/postgres_generation_live.py"
sys.path.insert(0, str(PROFILE_PATH.parent))
PROFILE_SPEC = importlib.util.spec_from_file_location("postgres_generation_contract_profile", PROFILE_PATH)
if PROFILE_SPEC is None or PROFILE_SPEC.loader is None:
    raise RuntimeError("cannot load PostgreSQL generation profile")
PROFILE = importlib.util.module_from_spec(PROFILE_SPEC)
PROFILE_SPEC.loader.exec_module(PROFILE)


def extension(path: Path) -> str:
    source = path.read_text()
    start = source.index("-- Schema-56 generation extension.")
    marker = source.find("-- PostgreSQL bounded root-rotation statement extension.", start)
    end = marker if marker >= 0 else source.index("COMMIT;", start)
    return source[start:end]


def last_function(source: str, name: str) -> str:
    matches = list(re.finditer(
        r"CREATE(?: OR REPLACE)? FUNCTION heptabao_provider\."
        + re.escape(name) + r"\(.*?END \$\$;", source, re.S))
    if not matches:
        raise AssertionError("missing provider function: " + name)
    return matches[-1].group(0)


class PostgresGenerationContractTests(unittest.TestCase):
    def test_fresh_and_forward_install_share_exact_extension(self):
        fresh = extension(ROOT / "bootstrap/postgresql/provider.sql")
        upgrade = extension(ROOT / "bootstrap/postgresql/upgrade_v5_password_policy_username_templates.sql")
        self.assertEqual(fresh, upgrade)
        self.assertIn("heptabao-postgresql-generation-v1", fresh)
        self.assertIn("valid_dynamic_username", fresh)
        self.assertIn("valid_password_credential", fresh)

    def test_provider_accepts_bounded_templates_but_reserves_short_legacy_issue(self):
        source = extension(ROOT / "bootstrap/postgresql/provider.sql")
        validator = last_function(source, "valid_dynamic_username")
        self.assertIn("octet_length(p_value) BETWEEN 1 AND 63", validator)
        self.assertIn("p_value ~ '^[ -~]+$'", validator)
        password = last_function(source, "valid_password_credential")
        self.assertIn("octet_length(p_value) BETWEEN 1 AND 16384", password)
        self.assertIn("p_value !~ '[[:cntrl:]]'", password)
        apply = last_function(source, "apply")
        self.assertIn("valid_dynamic_username(p_name)", apply)
        self.assertIn("p_action <> 'revoke' AND p_name ~ '^hbp_[0-9a-f]{28}$'", apply)
        for name in ("retired", "retire", "statement_retired", "apply_statements", "retire_statement"):
            with self.subTest(name=name):
                self.assertIn("valid_dynamic_username", last_function(source, name))

    def test_service_preserves_legacy_absence_and_persists_new_defaults(self):
        database = (ROOT / "crates/heptabao-server/src/service_database.rs").read_text()
        username = (ROOT / "crates/heptabao-server/src/service_database_username.rs").read_text()
        policy = (ROOT / "crates/heptabao-server/src/auth_password_policy.rs").read_text()
        self.assertIn('password_policy: Option<String>', database)
        self.assertIn('(provider == DatabaseProvider::Postgresql).then(String::new)', database.replace("\n", ""))
        self.assertIn("DEFAULT_POSTGRESQL_USERNAME_TEMPLATE.to_owned()", database)
        self.assertIn("provider_identity_changed", database)
        self.assertIn("database_connection_has_provider_references", database)
        self.assertIn("heptabao_provider.generation_protocol()", database)
        self.assertIn("None => Ok(hex(&crypto::random::<32>()", database)
        self.assertIn('re.fullmatch(r"hbp_[0-9a-f]{32}", legacy_username)',
                      (ROOT / "qa/openbao-acceptance/postgres_generation_live.py").read_text())
        self.assertIn('r#"{{ printf "v-%s-%s-%s-%s"', username)
        self.assertIn("generate_database_password", policy)
        self.assertIn("DEFAULT_PASSWORD_LENGTH: usize = 20", policy)

    def test_schema_and_statement_injection_boundaries_are_explicit(self):
        service = (ROOT / "crates/heptabao-server/src/service.rs").read_text()
        identity = (ROOT / "crates/heptabao-server/src/service_identity.rs").read_text()
        database = (ROOT / "crates/heptabao-server/src/service_database.rs").read_text()
        self.assertGreaterEqual(parse_current_schema(service), 56)
        self.assertIn("password policy state requires schema 56", identity)
        self.assertIn("database password policies and username templates require schema 56", identity)
        self.assertRegex(identity, r"(?s)match self.schema\s*\{.*?\b56\b[^=]*\|\s*CURRENT_STATE_SCHEMA\s*\|\s*AAD_BOUND_STATE_SCHEMA\s*\|\s*TYPED_PKI_STATE_SCHEMA\s*\|\s*JWT_USER_CLAIM_STATE_SCHEMA\s*\|\s*JWT_PEM_KEYSET_STATE_SCHEMA\s*\|\s*TRANSIT_BYOK_STATE_SCHEMA\s*\|\s*PKI_ISSUER_PATH_STATE_SCHEMA\s*\|\s*LOCAL_TYPED_PKI_STATE_SCHEMA\s*\|\s*RECOVERY_CREDENTIAL_STATE_SCHEMA\s*\|\s*INDEXED_RECOVERY_WIRE_STATE_SCHEMA\s*\|\s*LOCAL_PKI_IDENTIFIER_STATE_SCHEMA\s*\|\s*LOCAL_PKI_ROOT_FIELDS_STATE_SCHEMA\s*\|\s*LOCAL_PKI_MULTI_ISSUER_STATE_SCHEMA\s*\|\s*LOCAL_PKI_CRL_STATE_SCHEMA\s*\|\s*LOCAL_PKI_INTERMEDIATE_STATE_SCHEMA\s*=>\s*Ok\(\(\)\)")
        self.assertIn("state.schema = 55;", database)
        self.assertIn("statement-template password policy must use only ASCII", database)

    def test_forward_upgrade_is_owner_only_repeatable_and_data_preserving(self):
        upgrade = (ROOT / "bootstrap/postgresql/upgrade_v5_password_policy_username_templates.sql").read_text()
        self.assertTrue(upgrade.strip().startswith("-- Forward-only upgrade"))
        self.assertIn("SET LOCAL lock_timeout = '5s'", upgrade)
        self.assertIn("SET LOCAL statement_timeout = '30s'", upgrade)
        self.assertEqual(upgrade.count("CREATE OR REPLACE FUNCTION"), 10)
        for forbidden in ("DROP FUNCTION", "DROP TABLE", "ALTER TABLE", "TRUNCATE"):
            self.assertNotIn(forbidden, upgrade)
        self.assertNotIn("DELETE FROM heptabao_provider.fences", upgrade)
        self.assertRegex(upgrade, r"DELETE FROM heptabao_provider\.(leases|statement_leases)\s+WHERE manager=session_user AND lease_id=p_id")
        for protocol in ("provider-v2", "static-v1", "statements-v1", "password-authentication-v1"):
            self.assertIn(protocol, upgrade)

    def test_audit_scan_ignores_only_authenticated_digest_fields(self):
        secret = b"A" * 12
        safe = (json.dumps({
            "event": {
                "schema": 2, "kind": "request", "sequence": 1,
                "previous": "A" * 43, "path_digest": "A" * 44,
            },
            "mac": "A" * 44,
        }) + "\n").encode()
        self.assertFalse(PROFILE.audit_contains_plaintext(safe, [secret]))
        leaked = (json.dumps({
            "event": {
                "schema": 2, "kind": "request leaked " + secret.decode(),
                "sequence": 1, "previous": "A" * 43,
                "path_digest": "A" * 44,
            },
            "mac": "A" * 44,
        }) + "\n").encode()
        self.assertTrue(PROFILE.audit_contains_plaintext(leaked, [secret]))
        self.assertTrue(PROFILE.audit_contains_plaintext(b"not-json\n", [secret]))

    def test_migration_distinguishes_application_state_from_ledger_checkpoint(self):
        profile = PROFILE_PATH.read_text()
        self.assertIn("def durable_application_snapshot(root: Path)", profile)
        self.assertIn("def durable_ledger_digest(root: Path)", profile)
        self.assertIn("def capacity_frontier(instance: Instance)", profile)
        self.assertIn('("state.hbs", "journal.hbj", "seal.json")', profile)
        self.assertIn('"ledger_checkpoint_resealed_or_materialized"', profile)
        self.assertIn('"legacy_failed_downgrade_preserves_logical_frontier"', profile)
        self.assertIn("capacity_frontier(legacy_instance) == current_schema_frontier", profile)
        self.assertNotIn("def durable_digest(root: Path)", profile)

    def test_real_profile_binds_the_tree_pinned_schema55_reader(self):
        profile = PROFILE_PATH.read_text()
        self.assertIn("postgres-schema-migration-sources-v1.json", profile)
        self.assertIn("SCHEMA55_SOURCE", profile)
        self.assertIn("SCHEMA55_TREE", profile)
        self.assertIn("schema55_source_pin_mismatch", profile)
        self.assertIn("schema55_source_tree_mismatch", profile)

    def test_real_profile_and_ci_are_mandatory(self):
        profile = ROOT / "qa/openbao-acceptance/postgres_generation_live.py"
        self.assertTrue(profile.is_file())
        source = profile.read_text()
        for case in (
            "fresh_generation_protocol", "forward_generation_protocol",
            "connection_default_password_policy", "dynamic_role_policy_override",
            "official_default_username_template", "custom_username_template",
            "legacy_state_created_by_pinned_binary", "legacy_read_does_not_rewrite_state",
            "legacy_connection_shape_preserved", "legacy_old_binary_rejects_current_schema",
            "legacy_failed_downgrade_preserves_logical_frontier",
            "partial_connection_update_with_active_leases",
            "provider_identity_change_rejected_with_active_leases",
            "official_template_reset", "static_role_policy_override",
            "root_rotation_connection_policy", "source_and_binary_unchanged",
        ):
            self.assertIn(case, source)
        for argument in (
            "--legacy-binary", "--build-source-commit", "--legacy-source-commit",
            "--expected-binary-sha256", "--expected-legacy-sha256",
        ):
            self.assertIn(argument, source)
        self.assertNotIn("->>'terminal'", source)
        for field in (
            'legacy_observation.get("found") is True',
            'legacy_observation.get("action") == "revoke"',
            'legacy_observation.get("login") is False',
            'legacy_observation.get("active_sessions") == 0',
        ):
            self.assertIn(field, source)
        workflow = (ROOT / ".github/workflows/codex-openbao-replacement-ci.yml").read_text()
        self.assertEqual(workflow.count("postgres_generation_live.py"), 1)
        for boundary in (
            "feature_source=", "legacy_source=", "git worktree add --detach",
            "--legacy-binary", "--expected-legacy-sha256",
            'test -z "$(git status --porcelain=v1 --untracked-files=all)"',
        ):
            self.assertIn(boundary, workflow)


if __name__ == "__main__":
    unittest.main()
