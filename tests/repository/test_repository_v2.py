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
        self.assertGreaterEqual(len(members), 30)
        self.assertTrue(all("*" not in member for member in members))
        self.assertTrue(all((ROOT / member / "Cargo.toml").is_file() for member in members))

    def test_workspace_and_matrix_use_one_package_set(self) -> None:
        matrix = VALIDATOR.read_yaml(VALIDATOR.MATRIX_PATH)
        matrix_names = {item["crate"] for item in matrix["modules"]}
        package_names = {
            VALIDATOR.package_name(ROOT / member / "Cargo.toml")
            for member in VALIDATOR.workspace_members()
        }
        self.assertEqual(package_names, matrix_names)


if __name__ == "__main__":
    unittest.main()
