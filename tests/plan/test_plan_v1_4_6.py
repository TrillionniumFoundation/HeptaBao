from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts/validate_plan_v1_4_6.py"
SPEC = importlib.util.spec_from_file_location("validate_plan_v1_4_6", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class PlanV146HostileTests(unittest.TestCase):
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
                "fn sample() { anchor\n    .with_current_fence(); }\n",
                encoding="utf-8",
            )
            errors: list[str] = []
            VALIDATOR.require_tokens(
                errors,
                root,
                "sample.rs",
                ("anchor.with_current_fence",),
            )
            self.assertEqual(errors, [])

    def test_anchor_fence_removal_is_rejected(self) -> None:
        self.assert_rejected(
            "crates/heptabao-rollback-anchor/src/lib.rs",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "fn with_current_fence<T, F>",
                    "fn removed_current_fence<T, F>",
                ),
                encoding="utf-8",
            ),
        )

    def test_phase_aware_anchor_error_removal_is_rejected(self) -> None:
        self.assert_rejected(
            "crates/heptabao-rollback-anchor/src/lib.rs",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "OutcomeUnknownAfterEntry",
                    "RemovedPostEntryFenceState",
                ),
                encoding="utf-8",
            ),
        )

    def test_post_entry_fence_error_downgrade_is_rejected(self) -> None:
        self.assert_rejected(
            "crates/heptabao-recovery-core/src/lib.rs",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "AnchorFenceOutcomeUnknown",
                    "CheckpointNotAnchored",
                ),
                encoding="utf-8",
            ),
        )

    def test_reintroduced_target_toc_tou_is_rejected(self) -> None:
        self.assert_rejected(
            "crates/heptabao-recovery-core/src/lib.rs",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8")
                + "\nfn is_empty(&self) -> Result<bool, TestError> { Ok(true) }\n",
                encoding="utf-8",
            ),
        )

    def test_append_error_before_persistence_is_rejected(self) -> None:
        self.assert_rejected(
            "crates/heptabao-operation-ledger/src/lib.rs",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "self.payloads.push(payload.into_bytes());\n            if fail_after_persistence",
                    "if fail_after_persistence",
                ),
                encoding="utf-8",
            ),
        )

    def test_owner_only_file_mode_removal_is_rejected(self) -> None:
        self.assert_rejected(
            "crates/heptabao-single-node-store/src/lib.rs",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace("options.mode(0o600);", ""),
                encoding="utf-8",
            ),
        )

    def test_filesystem_guard_test_isolation_removal_is_rejected(self) -> None:
        self.assert_rejected(
            "crates/heptabao-filesystem-guard/src/lib.rs",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "static TEST_SERIAL: Mutex<()> = Mutex::new(());",
                    "static REMOVED_TEST_SERIAL: Mutex<()> = Mutex::new(());",
                ),
                encoding="utf-8",
            ),
        )

    def test_push_context_is_rejected(self) -> None:
        self.assert_rejected(
            ".github/workflows/plan-v1.4.6-authoritative-recovery-closure.yml",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "on:\n  pull_request:",
                    "on:\n  push:\n    branches: [main]\n  pull_request:",
                ),
                encoding="utf-8",
            ),
        )

    def test_development_materializer_residue_is_rejected(self) -> None:
        temporary, root = self.candidate()
        try:
            path = root / "scripts/apply_v1_4_6_unreviewed.py"
            path.write_text("raise SystemExit('development only')\n", encoding="utf-8")
            self.assertTrue(VALIDATOR.validate(root))
        finally:
            temporary.cleanup()

    def test_false_closed_blocker_is_rejected(self) -> None:
        self.assert_rejected(
            "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_6.yaml",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "state: IMPLEMENTED_SOURCE_REVIEW_REQUIRED",
                    "state: CLOSED",
                    1,
                ),
                encoding="utf-8",
            ),
        )

    def test_authority_drift_is_rejected(self) -> None:
        self.assert_rejected(
            "planning/HEPTABAO_V1_4_6_AUTHORITATIVE_RECOVERY_STATUS.yaml",
            lambda path: path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "  production_authority: false",
                    "  production_authority: true",
                ),
                encoding="utf-8",
            ),
        )


if __name__ == "__main__":
    unittest.main()
