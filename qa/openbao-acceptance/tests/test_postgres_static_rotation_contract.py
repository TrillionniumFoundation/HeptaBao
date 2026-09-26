"""Static/root rotation stays mandatory, digest-bound and source-aligned."""
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "qa/openbao-acceptance/postgres_static_rotation_live.py"
SPEC = importlib.util.spec_from_file_location("postgres_static_rotation_contract", RUNNER)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def extension(path):
    text = path.read_text()
    start = text.index("-- PostgreSQL static-role and manager-password rotation extension.")
    end = text.index("COMMIT;", start)
    return text[start:end]


class PostgresStaticRotationContractTests(unittest.TestCase):
    def test_fresh_and_forward_install_share_the_exact_extension(self):
        self.assertEqual(
            extension(ROOT / "bootstrap/postgresql/provider.sql"),
            extension(ROOT / "bootstrap/postgresql/upgrade_v2_static_credentials.sql"),
        )

    def test_retirement_is_a_digest_bound_bounded_tombstone(self):
        source = extension(ROOT / "bootstrap/postgresql/provider.sql")
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
        source = extension(ROOT / "bootstrap/postgresql/provider.sql")
        self.assertGreaterEqual(source.count("floor<p_seq"), 3)
        self.assertNotIn("floor<>p_seq", source)

    def test_real_profile_is_a_mandatory_replacement_step(self):
        workflow = (ROOT / ".github/workflows/codex-openbao-replacement-ci.yml").read_text()
        self.assertEqual(workflow.count("postgres_static_rotation_live.py"), 1)
        self.assertIn("--postgres-bin /usr/lib/postgresql/17/bin", workflow)
        self.assertIn('--work-dir "$RUNNER_TEMP/heptabao-postgresql-static-rotation"', workflow)

    def test_fixture_sql_literal_rejects_controlled_input_escape(self):
        self.assertEqual(MODULE.sql_literal("a1" * 32, r"[0-9a-f]{64}"), "'" + "a1" * 32 + "'")
        with self.assertRaises(MODULE.FixtureFailure):
            MODULE.sql_literal("safe';DROP ROLE x;--", r"[A-Za-z_][A-Za-z0-9_]{0,62}")


if __name__ == "__main__":
    unittest.main()
