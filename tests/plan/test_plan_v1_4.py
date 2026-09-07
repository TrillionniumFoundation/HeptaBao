from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_plan_v1_4 import ValidationFailure, validate  # noqa: E402
from validate_v1_4_inherited_surface import (  # noqa: E402
    EXPECTED_DELTA,
    InheritedSurfaceFailure,
    validate_delta,
)


class PlanV14Tests(unittest.TestCase):
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
                '    "crates/heptabao-durable-core",\n', "", 1
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "workspace members"):
            validate(target)

    def test_authority_promotion_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        status = target / "planning/HEPTABAO_V1_4_DURABLE_FOUNDATION_STATUS.yaml"
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

    def test_barrier_before_storage_order_is_mandatory(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        core = target / "crates/heptabao-durable-core/src/lib.rs"
        core.write_text(
            core.read_text(encoding="utf-8").replace(
                ".seal(&context, plaintext)",
                ".seal_without_contract(&context, plaintext)",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "seals plaintext before storage"):
            validate(target)

    def test_duplicate_yaml_key_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        status = target / "planning/HEPTABAO_V1_4_DURABLE_FOUNDATION_STATUS.yaml"
        with status.open("a", encoding="utf-8") as stream:
            stream.write("\nrevision: '1.4'\n")
        with self.assertRaisesRegex(ValidationFailure, "duplicate key"):
            validate(target)

    def test_unmanifested_or_inherited_path_change_fails_closed(self) -> None:
        observed = dict(EXPECTED_DELTA)
        observed["crates/heptabao-policy/src/lib.rs"] = "A"
        with self.assertRaisesRegex(InheritedSurfaceFailure, "inherited or unmanifested"):
            validate_delta(observed)

    def test_expected_delta_status_cannot_be_changed_to_deletion(self) -> None:
        observed = dict(EXPECTED_DELTA)
        observed["Cargo.toml"] = "D"
        with self.assertRaisesRegex(InheritedSurfaceFailure, "status drifted"):
            validate_delta(observed)


if __name__ == "__main__":
    unittest.main()
