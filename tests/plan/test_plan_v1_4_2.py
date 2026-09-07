from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_plan_v1_4_2 import ValidationFailure, validate  # noqa: E402


class PlanV142Tests(unittest.TestCase):
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

    def test_duplicate_yaml_key_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        status = target / "planning/HEPTABAO_V1_4_2_ANCHORED_RECOVERY_STATUS.yaml"
        with status.open("a", encoding="utf-8") as stream:
            stream.write("\nrevision: '1.4.2'\n")
        with self.assertRaisesRegex(ValidationFailure, "duplicate key"):
            validate(target)

    def test_authority_promotion_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        status = target / "planning/HEPTABAO_V1_4_2_ANCHORED_RECOVERY_STATUS.yaml"
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

    def test_workspace_member_removal_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        cargo = target / "Cargo.toml"
        cargo.write_text(
            cargo.read_text(encoding="utf-8").replace(
                '    "crates/heptabao-recovery-core",\n',
                "",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "workspace members"):
            validate(target)

    def test_manifest_path_removal_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        manifest = target / "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_2.yaml"
        source = manifest.read_text(encoding="utf-8")
        entry = """- path: crates/heptabao-recovery-core/src/lib.rs
  role: RUST_CRATE
  source_binding: RESOLVE_FROM_EXACT_SOURCE
"""
        self.assertIn(entry, source)
        manifest.write_text(source.replace(entry, "", 1), encoding="utf-8")
        with self.assertRaisesRegex(ValidationFailure, "manifest schema validation failed|manifest path/role set drifted"):
            validate(target)

    def test_active_revocation_guard_removal_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-key-lifecycle/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                "ActiveRevocationForbidden",
                "ActiveRevocationAllowed",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "key lifecycle source"):
            validate(target)

    def test_checkpoint_authenticator_identity_binding_is_mandatory(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-rollback-anchor/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                "append_field(&mut output, authenticator_id.as_str().as_bytes())",
                "let _ = authenticator_id",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "rollback anchor source"):
            validate(target)

    def test_restore_requires_externally_verified_checkpoint(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-recovery-core/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                "anchored_checkpoint: &VerifiedRecoveryCheckpoint",
                "anchored_checkpoint: &RecoveryCheckpoint",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "recovery source"):
            validate(target)

    def test_restore_target_empty_check_is_mandatory(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-recovery-core/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                "if !target.is_empty()",
                "if false",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "recovery source"):
            validate(target)

    def test_outcome_unknown_cannot_be_collapsed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-recovery-core/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                "RecoveryRestoreError::PublishOutcomeUnknown",
                "RecoveryRestoreError::Provider",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "recovery source"):
            validate(target)

    def test_temporary_write_workflow_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        workflow = target / ".github/workflows/v1.4.2-source-materializer.yml"
        workflow.write_text("name: forbidden\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValidationFailure,
            "temporary write-capable V1.4.2 workflow remains",
        ):
            validate(target)


if __name__ == "__main__":
    unittest.main()
