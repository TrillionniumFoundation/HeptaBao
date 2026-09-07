from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts/validate_plan_v1_4_5.py"
SPEC = importlib.util.spec_from_file_location("validate_plan_v1_4_5", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class PlanV145HostileTests(unittest.TestCase):
    def candidate(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "repo"
        shutil.copytree(
            ROOT,
            root,
            ignore=shutil.ignore_patterns(".git", "target", "__pycache__", "*.pyc"),
        )
        return temporary, root

    def assert_rejected(self, path: str, mutate) -> None:
        temporary, root = self.candidate()
        try:
            target = root / path
            mutate(target)
            self.assertTrue(VALIDATOR.validate(root))
        finally:
            temporary.cleanup()

    def test_current_tree_passes(self) -> None:
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_rustfmt_whitespace_is_semantically_transparent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "sample.rs"
            path.write_text(
                "fn sample() { anchor\n    .verify_current(); }\n",
                encoding="utf-8",
            )
            errors: list[str] = []
            VALIDATOR.require_tokens(
                errors,
                root,
                "sample.rs",
                ("anchor.verify_current",),
            )
            self.assertEqual(errors, [])

    def test_raw_durable_store_escape_is_rejected(self) -> None:
        self.assert_rejected(
            "crates/heptabao-durable-core/src/lib.rs",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8")
                + "\npub const fn store_mut(&mut self) {}\n",
                encoding="utf-8",
            ),
        )

    def test_missing_append_poison_state_is_rejected(self) -> None:
        self.assert_rejected(
            "crates/heptabao-operation-ledger/src/lib.rs",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "ReplayRequiredAfterAppendFailure",
                    "RemovedReplayRequiredState",
                ),
                encoding="utf-8",
            ),
        )

    def test_unscoped_historical_gate_is_rejected(self) -> None:
        self.assert_rejected(
            ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "    branches:\n      - codex/plan-v1.3-gap-closure-v2\n",
                    "",
                ),
                encoding="utf-8",
            ),
        )

    def test_inherited_gate_must_bind_immutable_v145_checkpoint(self) -> None:
        self.assert_rejected(
            ".github/workflows/plan-v1.4.5-security-invariant-closure.yml",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'git diff --name-only "$V145_BASELINE" "$V145_HEAD"',
                    'git diff --name-only "$V145_BASELINE" "$HEAD_SHA"',
                ),
                encoding="utf-8",
            ),
        )

    def test_missing_ancestor_hostile_test_is_rejected(self) -> None:
        self.assert_rejected(
            "crates/heptabao-filesystem-guard/src/lib.rs",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "intermediate_symlink_is_rejected",
                    "removed_ancestor_hostile_test",
                ),
                encoding="utf-8",
            ),
        )

    def test_authority_drift_is_rejected(self) -> None:
        self.assert_rejected(
            "planning/HEPTABAO_V1_4_5_SECURITY_INVARIANT_STATUS.yaml",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "  production_authority: false",
                    "  production_authority: true",
                ),
                encoding="utf-8",
            ),
        )

    def test_temporary_source_generator_is_rejected(self) -> None:
        temporary, root = self.candidate()
        try:
            path = root / "scripts/apply_v1_4_5_gap_closure.py"
            path.write_text("raise SystemExit('temporary')\n", encoding="utf-8")
            self.assertTrue(VALIDATOR.validate(root))
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
