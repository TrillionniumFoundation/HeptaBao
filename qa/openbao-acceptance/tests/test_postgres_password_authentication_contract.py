"""PostgreSQL password-authentication selection stays bounded and upgradeable."""
from pathlib import Path
import ast
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]


def extension(path: Path) -> str:
    source = path.read_text()
    start = source.index("-- PostgreSQL password-authentication extension.")
    end = source.index("COMMIT;", start)
    return source[start:end]


def function(source: str, name: str) -> str:
    match = re.search(
        r"CREATE(?: OR REPLACE)? FUNCTION heptabao_provider\."
        + re.escape(name) + r"\(.*?END \$\$;",
        source,
        re.S,
    )
    if match is None:
        raise AssertionError("missing provider function: " + name)
    return match.group(0)


class PostgresPasswordAuthenticationContractTests(unittest.TestCase):
    def test_fresh_and_forward_install_share_exact_extension(self):
        fresh = extension(ROOT / "bootstrap/postgresql/provider.sql")
        upgrade = extension(
            ROOT / "bootstrap/postgresql/upgrade_v4_password_authentication.sql"
        )
        self.assertEqual(fresh, upgrade)
        self.assertIn("heptabao-postgresql-password-authentication-v1", fresh)

    def test_verifier_validation_is_canonical_and_not_a_session_setting(self):
        source = extension(ROOT / "bootstrap/postgresql/provider.sql")
        validator = function(source, "valid_scram_verifier")
        self.assertIn("SCRAM-SHA-256[$]4096", validator)
        self.assertIn("encode(decode(parts[1],'base64'),'base64')=parts[1]", validator)
        self.assertIn("octet_length(decode(parts[3],'base64'))=32", validator)
        self.assertIn("EXCEPTION WHEN others", validator)
        accepted = function(source, "valid_password_credential")
        self.assertIn("p_value ~ '^[0-9a-f]{64}$'", accepted)
        self.assertIn("valid_scram_verifier", accepted)
        self.assertNotIn("set_config('password_encryption'", source)

    def test_scram_wrappers_reuse_existing_fenced_mutation_owners(self):
        source = extension(ROOT / "bootstrap/postgresql/provider.sql")
        calls = {
            "apply_scram": "RETURN heptabao_provider.apply(",
            "rotate_static_scram": "RETURN heptabao_provider.rotate_static(",
            "rotate_root_scram": "RETURN heptabao_provider.rotate_root(",
            "apply_statements_scram": "RETURN heptabao_provider.apply_statements(",
        }
        for name, call in calls.items():
            with self.subTest(name=name):
                body = function(source, name)
                self.assertIn("SECURITY DEFINER", body)
                self.assertIn("valid_scram_verifier", body)
                self.assertIn(call, body)
                self.assertNotIn("CREATE ROLE", body)
                self.assertNotIn("ALTER ROLE", body)

    def test_owner_replacement_is_explicit_and_limited(self):
        source = extension(ROOT / "bootstrap/postgresql/provider.sql")
        replaced = set(re.findall(
            r"CREATE OR REPLACE FUNCTION heptabao_provider\.([a-z_]+)", source
        ))
        self.assertEqual(replaced, {
            "valid_scram_verifier", "valid_password_credential",
            "apply", "rotate_static", "rotate_root", "apply_statements",
            "password_authentication_protocol", "apply_scram",
            "rotate_static_scram", "rotate_root_scram",
            "apply_statements_scram",
        })
        for name in ("apply", "rotate_static", "rotate_root", "apply_statements"):
            with self.subTest(name=name):
                body = function(source, name)
                self.assertIn("SECURITY DEFINER", body)
                self.assertIn("valid_password_credential", body)
                self.assertIn("pg_advisory_xact_lock", body)
                self.assertIn("payload_hash", body)
        upgrade = (ROOT /
            "bootstrap/postgresql/upgrade_v4_password_authentication.sql").read_text()
        for forbidden in ("DROP FUNCTION", "DROP TABLE", "ALTER TABLE", "TRUNCATE"):
            self.assertNotIn(forbidden, upgrade)
        for protocol in ("heptabao-postgresql-provider-v2",
                         "heptabao-postgresql-static-v1",
                         "heptabao-postgresql-statements-v1"):
            self.assertIn(protocol, upgrade)

    def test_service_routes_every_password_mutation_through_selection(self):
        database = (ROOT / "crates/heptabao-server/src/service_database.rs").read_text()
        rotation = (ROOT /
            "crates/heptabao-server/src/service_database_rotation.rs").read_text()
        statements = (ROOT /
            "crates/heptabao-server/src/service_database_statements.rs").read_text()
        for symbol in ("apply_scram", "rotate_static_scram", "rotate_root_scram",
                       "apply_statements_scram"):
            self.assertIn(symbol, database)
        self.assertIn("self.connection.static_rotation_function()", rotation)
        self.assertIn("self.connection.root_rotation_function()", rotation)
        self.assertIn("self.connection.statement_apply_function()", statements)
        self.assertIn("password_authentication_protocol()", database)
        self.assertIn("generate_provider_password", database)
        self.assertIn("provider_password", database)

    def test_api_and_schema_fence_are_explicit(self):
        database = (ROOT / "crates/heptabao-server/src/service_database.rs").read_text()
        service = (ROOT / "crates/heptabao-server/src/service.rs").read_text()
        identity = (ROOT / "crates/heptabao-server/src/service_identity.rs").read_text()
        self.assertIn('"password_authentication"', database)
        self.assertIn('"scram-sha-256"', database)
        self.assertIn('"password"', database)
        static_profile = (ROOT /
            "qa/openbao-acceptance/postgres_static_rotation_live.py").read_text()
        self.assertIn('config_data.get("password_authentication") == "password"',
                      static_profile)
        self.assertIn('"password" not in config_data', static_profile)
        self.assertRegex(service, r"CURRENT_STATE_SCHEMA: u32 = 55;")
        self.assertIn("PostgreSQL SCRAM password authentication requires schema 55",
                      identity)

    def test_real_profile_has_fixed_cross_path_denominator_and_no_authority_claim(self):
        path = ROOT / "qa/openbao-acceptance/postgres_password_authentication_live.py"
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
        self.assertGreaterEqual(len(values), 42)
        for case in (
            "fixture_default_password_encryption_is_md5",
            "scram_wrapper_rejects_raw_client_password",
            "rejected_raw_wrapper_has_no_provider_effect",
            "noncanonical_scram_wrapper_rejected",
            "dynamic_role_uses_scram_verifier",
            "statement_role_uses_scram_verifier",
            "static_role_uses_scram_verifier",
            "manager_uses_scram_verifier",
            "upgrade_preserves_owner_function_identity_and_acl",
            "upgrade_is_repeatable",
            "forward_protocol_available",
        ):
            self.assertIn(case, values)
        for flag in ("full_openbao_compatibility", "independent_qualification",
                     "production_authority"):
            self.assertIn('"' + flag + '": False', source)

    def test_real_profile_is_mandatory_in_replacement_ci(self):
        workflow = (ROOT / ".github/workflows/codex-openbao-replacement-ci.yml").read_text()
        self.assertEqual(workflow.count("postgres_password_authentication_live.py"), 1)
        self.assertIn("--postgres-bin /usr/lib/postgresql/17/bin", workflow)
        self.assertIn("heptabao-postgresql-password-authentication", workflow)

    def test_forward_upgrade_is_owner_only_repeatable_and_secret_free(self):
        upgrade = (ROOT /
            "bootstrap/postgresql/upgrade_v4_password_authentication.sql").read_text()
        self.assertTrue(upgrade.strip().startswith("-- Forward-only upgrade"))
        self.assertTrue(upgrade.strip().endswith("COMMIT;"))
        self.assertEqual(upgrade.count("CREATE OR REPLACE FUNCTION"), 11)
        self.assertNotIn("PASSWORD '", upgrade)
        self.assertNotRegex(upgrade, r"(?<![A-Za-z0-9])[0-9a-f]{64}(?![A-Za-z0-9])")
        self.assertIn("valid_scram_verifier", upgrade)
        self.assertIn("valid_password_credential", upgrade)


if __name__ == "__main__":
    unittest.main()
