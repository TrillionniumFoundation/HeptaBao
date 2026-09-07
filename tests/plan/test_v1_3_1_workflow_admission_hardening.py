from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "validate_plan_v1_3_1.py"
SPEC = importlib.util.spec_from_file_location(
    "validate_plan_v1_3_1_admission_hardening",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def copy_repository(target: Path) -> None:
    shutil.copytree(
        ROOT,
        target,
        dirs_exist_ok=True,
        symlinks=False,
        ignore=shutil.ignore_patterns(
            ".git",
            "target",
            "__pycache__",
            "*.pyc",
            ".pytest_cache",
        ),
    )


def mutate_text(root: Path, relative: str, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"mutation marker not found in {relative}: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


class WorkflowAdmissionHardeningTests(unittest.TestCase):
    def test_checked_in_admission_contract_passes(self) -> None:
        MODULE.validate(ROOT)

    def test_legacy_validator_dependency_must_be_manifest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repo"
            copy_repository(target)
            manifest_path = target / MODULE.ACTIVE_MANIFEST
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            manifest["documents"] = [
                entry
                for entry in manifest["documents"]
                if entry.get("path") != MODULE.LEGACY_VALIDATOR_PATH
            ]
            manifest_path.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            with self.assertRaises(MODULE.ValidationError):
                MODULE.validate(target)

    def test_legacy_validator_dependency_must_be_required_by_final_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repo"
            copy_repository(target)
            input_path = target / MODULE.FINAL_CLOSURE_INPUT
            final_input = yaml.safe_load(input_path.read_text(encoding="utf-8"))
            final_input["workflow_coverage"]["required_manifest_paths"].remove(
                MODULE.LEGACY_VALIDATOR_PATH
            )
            input_path.write_text(
                yaml.safe_dump(final_input, sort_keys=False),
                encoding="utf-8",
            )
            with self.assertRaises(MODULE.ValidationError):
                MODULE.validate(target)

    def test_missing_canonical_workflow_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repo"
            copy_repository(target)
            (
                target
                / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
            ).unlink()
            with self.assertRaises(MODULE.ValidationError):
                MODULE.validate(target)

    def test_yaml_extension_pull_request_workflow_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repo"
            copy_repository(target)
            rogue = target / ".github/workflows/rogue.yaml"
            rogue.write_text(
                """name: rogue
on:
  pull_request:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  reject:
    runs-on: ubuntu-latest
    steps:
      - run: echo rogue
""",
                encoding="utf-8",
            )
            with self.assertRaises(MODULE.ValidationError):
                MODULE.validate(target)

    def test_glob_active_branch_push_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repo"
            copy_repository(target)
            rogue = target / ".github/workflows/rogue.yml"
            rogue.write_text(
                """name: rogue
on:
  push:
    branches:
      - "codex/**"
  workflow_dispatch:
permissions:
  contents: read
jobs:
  reject:
    runs-on: ubuntu-latest
    steps:
      - run: echo rogue
""",
                encoding="utf-8",
            )
            with self.assertRaises(MODULE.ValidationError):
                MODULE.validate(target)

    def test_duplicate_top_level_trigger_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repo"
            copy_repository(target)
            rogue = target / ".github/workflows/rogue.yml"
            rogue.write_text(
                """name: rogue
on:
  workflow_dispatch:
on:
  push:
    branches: ["main"]
permissions:
  contents: read
jobs:
  reject:
    runs-on: ubuntu-latest
    steps:
      - run: echo rogue
""",
                encoding="utf-8",
            )
            with self.assertRaises((MODULE.ValidationError, yaml.YAMLError)):
                MODULE.validate(target)

    def test_boolean_true_key_cannot_masquerade_as_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repo"
            copy_repository(target)
            rogue = target / ".github/workflows/rogue.yml"
            rogue.write_text(
                """name: rogue
true:
  pull_request:
permissions:
  contents: read
jobs:
  reject:
    runs-on: ubuntu-latest
    steps:
      - run: echo rogue
""",
                encoding="utf-8",
            )
            with self.assertRaises(MODULE.ValidationError):
                MODULE.validate(target)

    def test_write_capable_workflow_permission_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repo"
            copy_repository(target)
            mutate_text(
                target,
                ".github/workflows/export-exact-audit-source.yml",
                "contents: read",
                "contents: write",
            )
            with self.assertRaises(MODULE.ValidationError):
                MODULE.validate(target)

    def test_persisted_checkout_credentials_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repo"
            copy_repository(target)
            mutate_text(
                target,
                ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml",
                "persist-credentials: false",
                "persist-credentials: true",
            )
            with self.assertRaises(MODULE.ValidationError):
                MODULE.validate(target)


if __name__ == "__main__":
    unittest.main()
