"""Static/root rotation stays mandatory, digest-bound and source-aligned."""
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "qa/openbao-acceptance/postgres_static_rotation_live.py"
SPEC = importlib.util.spec_from_file_location("postgres_static_rotation_contract", RUNNER)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
from postgres_provider_contract import (
    HISTORICAL_V4, current_provider_contract_matches, provider_function,
)


def extension(path):
    text = path.read_text()
    start = text.index("-- PostgreSQL static-role and manager-password rotation extension.")
    boundaries = [text.index("COMMIT;", start)]
    next_extension = text.find("-- PostgreSQL statement-template extension.", start)
    if next_extension >= 0:
        boundaries.append(next_extension)
    return text[start:min(boundaries)]


class PostgresStaticRotationContractTests(unittest.TestCase):
    def test_historical_extension_and_current_final_contract_match_upgrades(self):
        self.assertEqual(
            extension(ROOT / HISTORICAL_V4),
            extension(ROOT / "bootstrap/postgresql/upgrade_v2_static_credentials.sql"),
        )
        self.assertTrue(current_provider_contract_matches(ROOT))
        self.assertNotIn(
            "PostgreSQL statement-template extension",
            extension(ROOT / "bootstrap/postgresql/provider.sql"),
        )

    def test_retirement_is_a_digest_bound_bounded_tombstone(self):
        source = (ROOT / "bootstrap/postgresql/provider.sql").read_text()
        self.assertIn("retired boolean NOT NULL DEFAULT false", source)
        self.assertIn("p_fence text,p_id text,p_name text,p_seq bigint,p_digest text", source)
        self.assertIn("s.payload_digest=payload_hash AND s.retired", source)
        self.assertIn("root_rotation_retriable", source)
        self.assertIn("r.seq<p_seq", source)
        self.assertIn("r.password_digest=verifier", source)
        self.assertNotIn("DELETE FROM heptabao_provider.static_roles", source)
        self.assertIn("payload_digest=payload_hash,retired=true", source)
        self.assertIn("payload_digest=EXCLUDED.payload_digest,retired=false", source)
        self.assertIn("static-role provider identity capacity exhausted", source)
        self.assertIn(")>=4096", source)
        self.assertLess(
            source.index("static-role provider identity capacity exhausted"),
            source.index("ALTER ROLE %I PASSWORD %L"),
        )

    def test_same_sequence_proof_survives_a_later_global_floor(self):
        current = (ROOT / "bootstrap/postgresql/provider.sql").read_text()
        source = "\n".join(provider_function(current, name) for name in (
            "rotate_static", "rotate_root", "root_rotation_retriable",
            "root_rotation_observed", "static_retired", "retire_static",
        ))
        self.assertGreaterEqual(source.count("floor<p_seq"), 3)
        self.assertNotIn("floor<>p_seq", source)

    def test_real_profile_is_a_mandatory_replacement_step(self):
        workflow = (ROOT / ".github/workflows/codex-openbao-replacement-ci.yml").read_text()
        self.assertEqual(workflow.count("postgres_static_rotation_live.py"), 1)
        self.assertIn("--postgres-bin /usr/lib/postgresql/17/bin", workflow)
        self.assertIn('--work-dir "$RUNNER_TEMP/heptabao-postgresql-static-rotation"', workflow)

    def test_current_builtin_password_shape_is_checked_before_exact_replay(self):
        value = "aA1-" + "b" * 16
        self.assertTrue(MODULE.official_password(value))
        self.assertFalse(MODULE.official_password("a" * 20))
        source = RUNNER.read_text()
        self.assertIn('official_password(first_password)', source)
        self.assertIn('sql_literal(manual_password, r"[A-Za-z0-9-]{20}")', source)
        self.assertNotIn('sql_literal(manual_password, r"[0-9a-f]{64}")', source)

    def test_fixture_sql_literal_rejects_controlled_input_escape(self):
        self.assertEqual(MODULE.sql_literal("a1" * 32, r"[0-9a-f]{64}"), "'" + "a1" * 32 + "'")
        with self.assertRaises(MODULE.FixtureFailure):
            MODULE.sql_literal("safe';DROP ROLE x;--", r"[A-Za-z_][A-Za-z0-9_]{0,62}")


if __name__ == "__main__":
    unittest.main()
