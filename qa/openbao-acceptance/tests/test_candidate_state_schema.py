from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from candidate_state_schema import expected_schema, parse_current_schema


class CandidateSchemaTests(unittest.TestCase):
    def test_exact_source_declaration_is_independent_of_observed_reply(self):
        self.assertEqual(parse_current_schema("const CURRENT_STATE_SCHEMA: u32 = 61;"), 61)
        self.assertEqual(parse_current_schema("pub(crate) const CURRENT_STATE_SCHEMA: u32 = 62;"), 62)

    def test_missing_duplicate_zero_expression_and_overflow_fail_closed(self):
        for source in ("", "// const CURRENT_STATE_SCHEMA: u32 = 61;",
                       "const CURRENT_STATE_SCHEMA: u32 = 0;",
                       "const CURRENT_STATE_SCHEMA: u32 = 4294967296;",
                       "const CURRENT_STATE_SCHEMA: u32 = 60 + 1;",
                       "const CURRENT_STATE_SCHEMA: u32 = 60;\nconst CURRENT_STATE_SCHEMA: u32 = 61;"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                parse_current_schema(source)

    def test_immutable_git_object_not_mutable_worktree_or_runtime_is_read(self):
        sha="a"*40
        with patch("candidate_state_schema.subprocess.check_output", return_value="const CURRENT_STATE_SCHEMA: u32 = 61;") as show:
            self.assertEqual(expected_schema(Path("/synthetic"),sha),61)
        self.assertEqual(show.call_args.args[0], ["git","show",sha+":crates/heptabao-server/src/service.rs"])
        with self.assertRaises(ValueError):
            expected_schema(Path("/synthetic"),"HEAD")

    def test_both_profiles_keep_exact_schema_and_post_refusal_frontier_checks(self):
        root=Path(__file__).resolve().parents[1]
        for name in ("postgres_generation_live.py","postgres_root_rotation_statements_live.py"):
            source=(root/name).read_text()
            with self.subTest(name=name):
                self.assertIn("current_schema = expected_schema(ROOT, build_source_commit)",source)
                self.assertIn('current_schema_frontier["state_schema"] == current_schema',source)
                self.assertIn("capacity_frontier(legacy_instance) == current_schema_frontier",source)
                self.assertNotIn('["state_schema"] == 59',source)
                self.assertIn('"expected_current_state_schema": current_schema',source)
