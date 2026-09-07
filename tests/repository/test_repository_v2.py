"""Regression tests for the current V2 repository validator."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_repository_v2", ROOT / "scripts/validate_repository_v2.py"
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class RepositoryV2Tests(unittest.TestCase):
    def test_current_repository_is_consistent(self) -> None:
        self.assertEqual([], VALIDATOR.validate())

    def test_v3_guide_rejects_missing_semantic_sections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "guide.md"
            path.write_text(
                "# guide\n\n"
                "docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md\n",
                encoding="utf-8",
            )
            errors = VALIDATOR.validate_v3_guide(path)
            self.assertGreaterEqual(len(errors), len(VALIDATOR.V3_HEADINGS))

    def test_workspace_glob_expands_to_real_crates(self) -> None:
        members = VALIDATOR.workspace_members()
        self.assertEqual(40, len(members))
        self.assertTrue(all("*" not in member for member in members))
        self.assertTrue(all((ROOT / member / "Cargo.toml").is_file() for member in members))

    def test_workspace_matrix_lock_and_guides_use_one_package_set(self) -> None:
        matrix = VALIDATOR.read_yaml(VALIDATOR.MATRIX_PATH)
        matrix_names = {item["crate"] for item in matrix["modules"]}
        package_names = {
            VALIDATOR.package_name(ROOT / member / "Cargo.toml")
            for member in VALIDATOR.workspace_members()
        }
        guide_names = {
            path.stem for path in (ROOT / "docs/modules").glob("heptabao-*.md")
        }
        self.assertEqual(package_names, matrix_names)
        self.assertEqual(package_names, guide_names)
        self.assertTrue(package_names.issubset(VALIDATOR.lockfile_names()))

    def test_g4_contracts_are_implemented_and_no_longer_planned(self) -> None:
        matrix = VALIDATOR.read_yaml(VALIDATOR.MATRIX_PATH)
        by_name = {item["crate"]: item for item in matrix["modules"]}
        self.assertEqual([], matrix["planned_modules"])
        self.assertTrue(VALIDATOR.G4_PACKAGES.issubset(by_name))
        for name in VALIDATOR.G4_PACKAGES:
            self.assertEqual("V3", by_name[name]["documentation_standard"])
            self.assertEqual("IMPLEMENTED_REVIEW_REQUIRED", by_name[name]["state"])

    def test_current_portals_bind_plan_count_and_package_index(self) -> None:
        state = VALIDATOR.read_yaml(VALIDATOR.STATE_PATH)
        names = {
            VALIDATOR.package_name(ROOT / member / "Cargo.toml")
            for member in VALIDATOR.workspace_members()
        }
        self.assertEqual(
            [], VALIDATOR.validate_current_documentation(state["plan_id"], names)
        )

    def test_external_blockers_remain_fail_closed(self) -> None:
        blockers = VALIDATOR.read_yaml(VALIDATOR.BLOCKERS_PATH)
        self.assertGreater(len(blockers["external_blockers"]), 0)
        self.assertTrue(
            all(
                item["state"] == "EXTERNAL_COMPLETION_REQUIRED"
                for item in blockers["external_blockers"]
            )
        )


if __name__ == "__main__":
    unittest.main()
