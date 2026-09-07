from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_plan_v1_4_3 import ValidationFailure, validate  # noqa: E402


class PlanV143Tests(unittest.TestCase):
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
        status = target / "planning/HEPTABAO_V1_4_3_DESCRIPTOR_FENCING_STATUS.yaml"
        with status.open("a", encoding="utf-8") as stream:
            stream.write("\nrevision: '1.4.3'\n")
        with self.assertRaisesRegex(ValidationFailure, "duplicate key"):
            validate(target)

    def test_authority_promotion_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        status = target / "planning/HEPTABAO_V1_4_3_DESCRIPTOR_FENCING_STATUS.yaml"
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

    def test_network_filesystem_claim_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        status = target / "planning/HEPTABAO_V1_4_3_DESCRIPTOR_FENCING_STATUS.yaml"
        status.write_text(
            status.read_text(encoding="utf-8").replace(
                "  network_filesystem_supported: false",
                "  network_filesystem_supported: true",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "bounded profile"):
            validate(target)

    def test_workspace_guard_removal_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        cargo = target / "Cargo.toml"
        cargo.write_text(
            cargo.read_text(encoding="utf-8").replace(
                '    "crates/heptabao-filesystem-guard",\n',
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
        manifest = target / "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_3.yaml"
        source = manifest.read_text(encoding="utf-8")
        entry = """- path: crates/heptabao-filesystem-guard/src/lib.rs
  role: RUST_CRATE
  source_binding: RESOLVE_FROM_EXACT_SOURCE
"""
        self.assertIn(entry, source)
        manifest.write_text(source.replace(entry, "", 1), encoding="utf-8")
        with self.assertRaisesRegex(
            ValidationFailure,
            "manifest schema validation failed|manifest path/role set drifted",
        ):
            validate(target)

    def test_directory_lock_removal_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-filesystem-guard/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                "match handle.try_lock()",
                "match Ok(())",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "filesystem guard source"):
            validate(target)

    def test_proc_descriptor_binding_removal_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-filesystem-guard/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                'format!("/proc/self/fd/{}", handle.as_raw_fd())',
                'format!("{}", handle.as_raw_fd())',
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "filesystem guard source"):
            validate(target)

    def test_subprocess_contention_test_removal_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-filesystem-guard/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                "Command::new",
                "Command::disabled",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "subprocess contention"):
            validate(target)

    def test_store_descriptor_ownership_removal_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-single-node-store/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                "root: ExclusiveDirectory",
                "root: PathBuf",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "generation store source"):
            validate(target)

    def test_store_check_then_create_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-single-node-store/src/lib.rs"
        text = source.read_text(encoding="utf-8")
        anchor = "        let bundle_name = bundle_file_name(generation);\n"
        self.assertIn(anchor, text)
        text = text.replace(
            anchor,
            anchor + "        if self.bundle_path(generation).exists() {}\n",
            1,
        )
        source.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ValidationFailure, "check-then-create"):
            validate(target)

    def test_journal_descriptor_ownership_removal_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-single-node-journal/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                "root: ExclusiveDirectory",
                "root: PathBuf",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "durable journal source"):
            validate(target)

    def test_nofollow_read_removal_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        source = target / "crates/heptabao-single-node-journal/src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                "options.custom_flags(O_NOFOLLOW | O_CLOEXEC)",
                "options.custom_flags(O_CLOEXEC)",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationFailure, "durable journal source"):
            validate(target)

    def test_temporary_write_workflow_fails_closed(self) -> None:
        temporary, target = self.copy_repository()
        self.addCleanup(temporary.cleanup)
        workflow = target / ".github/workflows/v1.4.3-source-materializer.yml"
        workflow.write_text("name: forbidden\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValidationFailure,
            "temporary write-capable V1.4.3 workflow remains",
        ):
            validate(target)


if __name__ == "__main__":
    unittest.main()
