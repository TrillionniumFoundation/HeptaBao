from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/validate_repository_identity_v1.py"
SPEC = importlib.util.spec_from_file_location("validate_repository_identity_v1", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RepositoryIdentityTransferTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        for relative in MODULE.REQUIRED_PATHS:
            source = ROOT / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return temporary, root

    def test_current_repository_identity_passes(self) -> None:
        tracked = MODULE.validate_repository_identity(ROOT)
        self.assertGreater(tracked, 300)

    def test_historical_name_is_rejected_in_current_execution_surface(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "scripts/collect_github_job_identity_v1.py"
        value = path.read_text(encoding="utf-8").replace(
            MODULE.CURRENT_REPOSITORY,
            MODULE.HISTORICAL_REPOSITORY,
        )
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "historical repository name"):
            MODULE.validate_repository_identity(root)

    def test_stable_repository_id_drift_is_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
        value = path.read_text(encoding="utf-8").replace(
            f"repository_id: {MODULE.CURRENT_REPOSITORY_ID}",
            "repository_id: 1",
        )
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "repository_id"):
            MODULE.validate_repository_identity(root)

    def test_duplicate_repository_identity_key_is_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
        value = path.read_text(encoding="utf-8").replace(
            f"  repository_id: {MODULE.CURRENT_REPOSITORY_ID}\n",
            f"  repository_id: {MODULE.CURRENT_REPOSITORY_ID}\n  repository_id: 1\n",
            1,
        )
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "duplicate key"):
            MODULE.validate_repository_identity(root)

    def test_comment_cannot_camouflage_repository_id_drift(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
        value = path.read_text(encoding="utf-8").replace(
            f"  repository_id: {MODULE.CURRENT_REPOSITORY_ID}\n",
            f"  repository_id: 1\n  # repository_id: {MODULE.CURRENT_REPOSITORY_ID}\n",
            1,
        )
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "repository_id drift"):
            MODULE.validate_repository_identity(root)

    def test_workflow_head_owner_must_be_event_derived(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = root / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        value = path.read_text(encoding="utf-8").replace(
            "EXPECTED_HEAD_OWNER: ${{ github.event.pull_request.head.repo.owner.login || github.repository_owner }}",
            "EXPECTED_HEAD_OWNER: ProfHepta",
            1,
        )
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "workflow identity environment drift"):
            MODULE.validate_repository_identity(root)

    def test_canonical_workflow_must_invoke_identity_validator(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = root / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        value = path.read_text(encoding="utf-8").replace(
            "            scripts/validate_repository_identity_v1.py\n",
            "",
            1,
        )
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "must invoke"):
            MODULE.validate_repository_identity(root)

    def test_repository_owner_and_ratifier_must_remain_separate(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
        value = path.read_text(encoding="utf-8").replace(
            "repository_owner_may_differ_from_ratifier: true",
            "repository_owner_may_differ_from_ratifier: false",
        )
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "repository_owner_may_differ"):
            MODULE.validate_repository_identity(root)

    def test_current_receipt_schema_cannot_accept_historical_name(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "schemas/heptabao_v1_3_1_lane_arbitration_v1.schema.json"
        value = path.read_text(encoding="utf-8").replace(
            MODULE.CURRENT_REPOSITORY,
            MODULE.HISTORICAL_REPOSITORY,
        )
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "historical repository name"):
            MODULE.validate_repository_identity(root)

    def test_bootstrap_codeowners_cannot_claim_independent_review(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = root / ".github/CODEOWNERS"
        value = path.read_text(encoding="utf-8").replace(
            "# Bootstrap ownership only. This file does not satisfy independent-review\n",
            "# Canonical owners.\n",
        )
        path.write_text(value, encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "bootstrap-only"):
            MODULE.validate_repository_identity(root)

    def test_generated_bytecode_is_not_treated_as_exported_source(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        cache = root / "scripts/__pycache__"
        cache.mkdir(parents=True, exist_ok=True)
        (cache / "validator.cpython-313.pyc").write_bytes(
            f"generated:{MODULE.DEPRECATED_OWNER}/HeptaBao".encode("utf-8")
        )
        self.assertGreater(MODULE.validate_repository_identity(root), 0)

    def test_source_archive_symlink_is_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        target = root / "ordinary.txt"
        target.write_text("ordinary", encoding="utf-8")
        alias = root / "alias.txt"
        try:
            alias.symlink_to(target.name)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "refuses symlink"):
            MODULE.validate_repository_identity(root)

    def test_deprecated_owner_alias_is_rejected_anywhere_tracked(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        marker = root / "deprecated.txt"
        marker.write_text(f"{MODULE.DEPRECATED_OWNER}/HeptaBao\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IdentityFailure, "deprecated owner identity"):
            MODULE.validate_repository_identity(root)


if __name__ == "__main__":
    unittest.main()
