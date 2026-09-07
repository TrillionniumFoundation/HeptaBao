from __future__ import annotations

import importlib.util
import os
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/validate_repository_identity_v1.py"
SPEC = importlib.util.spec_from_file_location("validate_repository_identity_hardening", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RepositoryIdentityTransferHardeningTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        for relative in MODULE.REQUIRED_PATHS:
            source = ROOT / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return temporary, root

    def workflow(self, root: Path) -> Path:
        return root / MODULE.WORKFLOW_PATH

    def test_duplicate_workflow_yaml_key_is_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = self.workflow(root)
        needle = f'      EXPECTED_REPOSITORY_ID: "{MODULE.CURRENT_REPOSITORY_ID}"\n'
        path.write_text(path.read_text(encoding="utf-8").replace(needle, needle + needle, 1), encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "duplicate workflow YAML key"):
            MODULE.validate_repository_identity(root)

    def test_workflow_identity_moved_to_unrelated_mapping_is_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = self.workflow(root)
        needle = f'      EXPECTED_REPOSITORY_ID: "{MODULE.CURRENT_REPOSITORY_ID}"\n'
        value = path.read_text(encoding="utf-8").replace(needle, "", 1)
        value = value.replace("concurrency:\n", f'concurrency:\n  EXPECTED_REPOSITORY_ID: "{MODULE.CURRENT_REPOSITORY_ID}"\n', 1)
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "workflow identity environment drift"):
            MODULE.validate_repository_identity(root)

    def test_workflow_identity_in_block_scalar_is_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = self.workflow(root)
        needle = f'      EXPECTED_REPOSITORY_ID: "{MODULE.CURRENT_REPOSITORY_ID}"\n'
        value = path.read_text(encoding="utf-8").replace(needle, "", 1)
        marker = '          evidence="$RUNNER_TEMP/v1.3.1-$SOURCE_KIND/root"\n'
        value = value.replace(
            marker,
            marker + "          cat <<'IDENTITY_ENV_MARKER' >/dev/null\n"
            + f'          EXPECTED_REPOSITORY_ID: "{MODULE.CURRENT_REPOSITORY_ID}"\n'
            + "          IDENTITY_ENV_MARKER\n",
            1,
        )
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "workflow identity environment drift"):
            MODULE.validate_repository_identity(root)

    def test_commented_identity_validator_does_not_count(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = self.workflow(root)
        value = path.read_text(encoding="utf-8").replace(
            "            scripts/validate_repository_identity_v1.py\n",
            "            # scripts/validate_repository_identity_v1.py\n",
            1,
        )
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "must invoke"):
            MODULE.validate_repository_identity(root)

    def test_heredoc_identity_validator_does_not_count(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = self.workflow(root)
        value = path.read_text(encoding="utf-8").replace("            scripts/validate_repository_identity_v1.py\n", "", 1)
        marker = '          evidence="$RUNNER_TEMP/v1.3.1-$SOURCE_KIND/root"\n'
        value = value.replace(
            marker,
            marker + "          cat <<'IDENTITY_VALIDATOR_MARKER' >/dev/null\n"
            + "          scripts/validate_repository_identity_v1.py\n"
            + "          IDENTITY_VALIDATOR_MARKER\n",
            1,
        )
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "must invoke"):
            MODULE.validate_repository_identity(root)

    def test_disabled_gate_a_step_is_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = self.workflow(root)
        marker = "      - name: Validate Gate A inherited contracts and Python regression\n"
        path.write_text(path.read_text(encoding="utf-8").replace(marker, marker + "        if: ${{ false }}\n", 1), encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "must not be disabled"):
            MODULE.validate_repository_identity(root)

    def test_disabled_matrix_job_is_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = self.workflow(root)
        marker = "  full-technical-matrix:\n"
        path.write_text(path.read_text(encoding="utf-8").replace(marker, marker + "    if: ${{ false }}\n", 1), encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "must not be conditionally disabled"):
            MODULE.validate_repository_identity(root)

    def assert_symlink_rejected(self, target: str, directory: bool = False) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        alias = root / "alias"
        try:
            alias.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "refuses symlink"):
            MODULE.validate_repository_identity(root)

    def test_broken_symlink_is_rejected(self) -> None:
        self.assert_symlink_rejected("missing-target")

    def test_directory_symlink_is_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        (root / "ordinary-directory").mkdir()
        alias = root / "directory-alias"
        try:
            alias.symlink_to("ordinary-directory", target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlink creation is unavailable")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "refuses symlink"):
            MODULE.validate_repository_identity(root)

    def test_nested_symlink_is_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        nested = root / "nested" / "deeper"
        nested.mkdir(parents=True)
        (nested / "ordinary.txt").write_text("ordinary", encoding="utf-8")
        try:
            (nested / "alias.txt").symlink_to("ordinary.txt")
        except (OSError, NotImplementedError):
            self.skipTest("nested symlink creation is unavailable")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "refuses symlink"):
            MODULE.validate_repository_identity(root)

    def test_non_regular_entry_is_rejected(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable")
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        try:
            os.mkfifo(root / "unexpected.fifo")
        except (OSError, NotImplementedError):
            self.skipTest("FIFO creation is unavailable")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "non-regular entry"):
            MODULE.validate_repository_identity(root)


if __name__ == "__main__":
    unittest.main()
