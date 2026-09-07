from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_plan_v1_4_1 import ValidationFailure, validate  # noqa: E402
from validate_v1_4_1_inherited_surface import (  # noqa: E402
    EXPECTED_DELTA,
    InheritedSurfaceFailure,
    validate_delta,
)


class PlanV141Tests(unittest.TestCase):
    def copy_repository(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        target = Path(temporary.name) / "repository"
        shutil.copytree(
            ROOT,
            target,
            ignore=shutil.ignore_patterns(".git", "target", "__pycache__", "*.pyc"),
        )
        return temporary, target

    def test_current_repository_validates(self) -> None:
        validate(ROOT)

    def test_missing_workspace_member_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        cargo = target / "Cargo.toml"
        cargo.write_text(
            cargo.read_text(encoding="utf-8").replace(
                '    "crates/heptabao-journaled-core",\n', "", 1
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "workspace members"):
            validate(target)

    def test_authority_promotion_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        status = target / "planning/HEPTABAO_V1_4_1_DURABLE_OPERATION_LEDGER_STATUS.yaml"
        status.write_text(
            status.read_text(encoding="utf-8").replace(
                "  production_authority: false",
                "  production_authority: true",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "authority claims"):
            validate(target)

    def test_journal_directory_enumeration_must_not_follow_symlinks(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-single-node-journal/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                "fs::symlink_metadata(entry.path())",
                "entry.metadata()",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "follows symlinks"):
            validate(target)

    def test_intent_before_state_order_is_mandatory(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-journaled-core/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                ".record(intent.clone())",
                ".record_after_state(intent.clone())",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "persists accepted/intent before state"):
            validate(target)

    def test_duplicate_yaml_key_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        status = target / "planning/HEPTABAO_V1_4_1_DURABLE_OPERATION_LEDGER_STATUS.yaml"
        with status.open("a", encoding="utf-8") as stream:
            stream.write("\nrevision: '1.4.1'\n")
        with self.assertRaisesRegex(ValidationFailure, "duplicate key"):
            validate(target)

    def test_temporary_write_workflow_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        workflow = target / ".github/workflows/v1.4.1-source-export.yml"
        workflow.write_text("name: forbidden\n", encoding="utf-8")
        with self.assertRaisesRegex(ValidationFailure, "temporary write-capable workflow remains"):
            validate(target)

    def test_unmanifested_or_inherited_path_change_fails_closed(self) -> None:
        observed = dict(EXPECTED_DELTA)
        observed["crates/heptabao-token/src/lib.rs"] = "A"
        with self.assertRaisesRegex(InheritedSurfaceFailure, "inherited or unmanifested"):
            validate_delta(observed)

    def test_expected_delta_status_cannot_be_changed_to_deletion(self) -> None:
        observed = dict(EXPECTED_DELTA)
        observed["Cargo.toml"] = "D"
        with self.assertRaisesRegex(InheritedSurfaceFailure, "status drifted"):
            validate_delta(observed)


if __name__ == "__main__":
    unittest.main()
