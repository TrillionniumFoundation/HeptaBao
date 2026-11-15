from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from governance_source_contracts import (
    ARCHIVED_WORKFLOWS,
    archived_document_reference,
    descriptor_guard_errors,
    descriptor_provider_errors,
    historical_contract_errors,
    historical_workflow,
    retired_workflow_errors,
)

GUARD = "crates/heptabao-filesystem-guard/src/lib.rs"
LEAF = "crates/heptabao-filesystem-guard/src/relative.rs"
WRITE = "crates/heptabao-filesystem-guard/src/durable_write.rs"
STORE = "crates/heptabao-single-node-store/src/lib.rs"
JOURNAL = "crates/heptabao-single-node-journal/src/lib.rs"
CANONICAL = ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
PR_HISTORY = {
    CANONICAL: "codex/plan-v1.3-gap-closure-v2",
    ".github/workflows/plan-v1.4.2-anchored-recovery.yml": "codex/plan-v1.4-full-gap-closure-v1",
    ".github/workflows/plan-v1.4.3-descriptor-fencing.yml": "codex/plan-v1.4.2-recovery-foundation-v1",
    ".github/workflows/plan-v1.4.6-authoritative-recovery-closure.yml": "integration/v1.4.4-technical-candidate",
    ".github/workflows/plan-v1.4.7-post-merge-truth-and-external-admission.yml": "integration/v1.4.4-technical-candidate",
}


class GovernanceSourceContractTests(unittest.TestCase):
    def candidate(self, *paths: str) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "source"
        root.mkdir()
        for relative in paths:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, path)
        return root

    def descriptor_candidate(self) -> Path:
        root = self.candidate(GUARD, LEAF, WRITE, STORE, JOURNAL)
        self.assertEqual(descriptor_provider_errors(root, "store"), [])
        self.assertEqual(descriptor_provider_errors(root, "journal"), [])
        return root

    def mutate(self, root: Path, relative: str, old: str, new: str) -> None:
        path = root / relative
        source = path.read_text()
        self.assertIn(old, source)
        updated = source.replace(old, new, 1)
        self.assertNotEqual(updated, source)
        path.write_text(updated)

    def assert_descriptor_rejected(self, root: Path, marker: str) -> None:
        errors = descriptor_guard_errors(root)
        self.assertTrue(errors)
        self.assertTrue(any(marker in error for error in errors), errors)

    def test_current_descriptor_providers_have_the_actual_safe_contract(self) -> None:
        self.assertEqual(descriptor_provider_errors(ROOT, "store"), [])
        self.assertEqual(descriptor_provider_errors(ROOT, "journal"), [])

    def test_earlier_plan_validators_check_the_active_shared_write_source(self) -> None:
        import validate_plan_v1_4
        import validate_plan_v1_4_1

        sources = (
            GUARD, LEAF, WRITE, STORE, JOURNAL,
            "crates/heptabao-storage-api/src/lib.rs",
            "crates/heptabao-barrier-api/src/lib.rs",
            "crates/heptabao-durable-core/src/lib.rs",
            "crates/heptabao-journal-api/src/lib.rs",
            "crates/heptabao-operation-ledger/src/lib.rs",
            "crates/heptabao-journaled-core/src/lib.rs",
        )
        for old, new in (
            ("root.open_file(leaf_name, FileAccess::CreateNew)",
             "root.open_file(leaf_name, FileAccess::Write)"),
            ("root.open_file(&temporary_name, FileAccess::CreateNew)",
             "root.open_file(&temporary_name, FileAccess::Write)"),
            ("root.rename(&temporary_name, target_name)",
             "root.rename(&temporary_name, other_name)"),
            ("file.sync_all()?;", "file.sync_data()?;"),
            ("root.sync_all().map_err(io::Error::other)", "Ok(())"),
        ):
            with self.subTest(contract=old):
                root = self.candidate(*sources)
                for module in (validate_plan_v1_4, validate_plan_v1_4_1):
                    module.validate_rust_sources(root)
                self.mutate(root, WRITE, old, new)
                for module in (validate_plan_v1_4, validate_plan_v1_4_1):
                    with self.subTest(validator=module.__name__):
                        with self.assertRaisesRegex(module.ValidationFailure, "shared (create|replace) lost"):
                            module.validate_rust_sources(root)

    def test_leaf_exclusive_create_removal_is_rejected(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, LEAF,
                    "FileAccess::CreateNew => OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL",
                    "FileAccess::CreateNew => OFlags::WRONLY | OFlags::CREATE")
        self.assert_descriptor_rejected(root, "descriptor leaf source")

    def test_leaf_nofollow_removal_is_rejected(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, LEAF,
                    "flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK",
                    "flags | OFlags::CLOEXEC | OFlags::NONBLOCK")
        self.assert_descriptor_rejected(root, "descriptor leaf source")

    def test_owner_only_mode_cannot_add_group_read(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, LEAF, "Mode::RUSR | Mode::WUSR",
                    "Mode::RUSR | Mode::WUSR | Mode::RGRP")
        self.assert_descriptor_rejected(root, "descriptor leaf source")

    def test_singly_linked_regular_file_gate_cannot_disappear(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, LEAF, "!metadata.is_file() || metadata.nlink() != 1",
                    "!metadata.is_file()")
        self.assert_descriptor_rejected(root, "descriptor leaf source")

    def test_owner_verification_must_run_before_and_after_open(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, LEAF, "self.verify().map_err(io::Error::other)?;", "")
        self.assert_descriptor_rejected(root, "pre/post owner verification")

    def test_owner_checks_cannot_both_move_after_open(self) -> None:
        root = self.descriptor_candidate()
        path = root / LEAF
        source = path.read_text()
        check = "self.verify().map_err(io::Error::other)?;"
        self.assertIn(check, source)
        source = source.replace(check, "", 1)
        anchor = "            let metadata = file.metadata()?;"
        self.assertIn(anchor, source)
        source = source.replace(anchor, anchor + "\n            " + check, 1)
        path.write_text(source)
        self.assert_descriptor_rejected(root, "pre/post owner verification")

    def test_invalid_file_branch_cannot_return_success(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, LEAF,
                    'return Err(io::Error::other(\n                    "guarded leaf is not a singly-linked regular file",\n                ));',
                    "return Ok(file);")
        self.assert_descriptor_rejected(root, "descriptor leaf source")

    def test_leaf_open_cannot_switch_to_a_path_owner(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, LEAF, "&self.handle,", "&foreign_handle,")
        self.assert_descriptor_rejected(root, "descriptor leaf source")

    def test_directory_walk_nofollow_removal_is_rejected(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, GUARD,
                    "OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC",
                    "OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC")
        self.assert_descriptor_rejected(root, "filesystem guard source")

    def test_comments_cannot_forge_removed_exclusive_create(self) -> None:
        root = self.descriptor_candidate()
        old = "FileAccess::CreateNew => OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL"
        self.mutate(root, LEAF, old,
                    "FileAccess::CreateNew => OFlags::WRONLY | OFlags::CREATE")
        with (root / LEAF).open("a") as file:
            file.write("\n// " + old + "\n")
        self.assert_descriptor_rejected(root, "descriptor leaf source")

    def test_store_uses_exclusive_descriptor_create(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, WRITE, "root.open_file(leaf_name, FileAccess::CreateNew)?",
                    "root.open_file(leaf_name, FileAccess::Write)?")
        errors = descriptor_provider_errors(root, "store")
        self.assertTrue(any("generation store source" in error for error in errors))

    def test_journal_uses_descriptor_read(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, JOURNAL, ".open_file(leaf_name, FileAccess::Read)",
                    ".open_file(leaf_name, FileAccess::Write)")
        errors = descriptor_provider_errors(root, "journal")
        self.assertTrue(any("durable journal source" in error for error in errors))

    def test_shared_helper_is_required_by_both_actual_callers(self) -> None:
        root = self.descriptor_candidate()
        (root / WRITE).unlink()
        for kind in ("store", "journal"):
            self.assertTrue(any("shared durable-write source missing" in error
                                for error in descriptor_provider_errors(root, kind)))

    def test_each_caller_must_keep_its_import_wrapper_and_counter(self) -> None:
        mutations = (
            ("AtomicReplaceError, DirectoryGuardError", "DirectoryGuardError"),
            ("fn write_new_file_and_sync_parent(", "fn unused_write_helper("),
            ("heptabao_filesystem_guard::write_new_file_and_sync_parent(root, leaf_name, bytes)", "Ok(())"),
            ("heptabao_filesystem_guard::atomic_replace(root, target_name, bytes, &TEMP_SEQUENCE)", "Ok(())"),
            ("&TEMP_SEQUENCE)", "&FOREIGN_SEQUENCE)"),
            ("static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);", ""),
            ("static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);",
             "#[cfg(any())]\nstatic TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);"),
        )
        for kind, relative in (("store", STORE), ("journal", JOURNAL)):
            for old, new in mutations:
                with self.subTest(kind=kind, mutation=old):
                    root = self.descriptor_candidate()
                    self.mutate(root, relative, old, new)
                    self.assertTrue(descriptor_provider_errors(root, kind))

    def test_shared_helper_must_be_exported_from_the_actual_guard_crate(self) -> None:
        for old, new in (
            ("mod durable_write;", "mod unrelated_write;"),
            ("pub use durable_write::{AtomicReplaceError, atomic_replace, write_new_file_and_sync_parent};", ""),
        ):
            with self.subTest(mutation=old):
                root = self.descriptor_candidate()
                self.mutate(root, GUARD, old, new)
                self.assertTrue(descriptor_provider_errors(root, "store"))
                self.assertTrue(descriptor_provider_errors(root, "journal"))

    def test_module_attributes_cannot_redirect_the_verified_shared_source(self) -> None:
        for attributes in (
            '#[path = "alternate_durable.rs"]\n',
            '#[cfg_attr(all(), path = "alternate_durable.rs")]\n',
            '#[allow(dead_code)]\n/* between attributes */\n#[path = "alternate_durable.rs"]\n// before module\n',
            '#[path = "alternate_durable.rs"] ',
            '#[path = "alternate_durable.rs"]\npub ',
            '#[path = "alternate_durable.rs"]\npub(crate) ',
            '#[path = "alternate_durable.rs"]\npub\n',
        ):
            with self.subTest(attributes=attributes):
                root = self.descriptor_candidate()
                alternate = root / "crates/heptabao-filesystem-guard/src/alternate_durable.rs"
                alternate.write_text((root / WRITE).read_text().replace(
                    "root.verify().map_err(io::Error::other)?;", "", 1))
                self.mutate(root, GUARD, "mod durable_write;", attributes + "mod durable_write;")
                for kind in ("store", "journal"):
                    self.assertTrue(any("default module binding" in error
                                        for error in descriptor_provider_errors(root, kind)))

    def test_conditional_export_cannot_hide_a_different_implementation(self) -> None:
        root = self.descriptor_candidate()
        export = "pub use durable_write::{AtomicReplaceError, atomic_replace, write_new_file_and_sync_parent};"
        self.mutate(root, GUARD, export, "#[cfg(any())]\n" + export)
        for kind in ("store", "journal"):
            self.assertTrue(any("public export binding" in error
                                for error in descriptor_provider_errors(root, kind)))

    def test_descriptor_imports_must_be_unconditional_in_callers_and_helper(self) -> None:
        for relative, item in (
            (STORE, "use heptabao_filesystem_guard::{"),
            (JOURNAL, "use heptabao_filesystem_guard::{"),
            (WRITE, "use crate::{ExclusiveDirectory, FileAccess};"),
        ):
            for attribute in ("#[cfg(any())]\n", "#[cfg_attr(all(), cfg(any()))]\n"):
                with self.subTest(relative=relative, attribute=attribute):
                    root = self.descriptor_candidate()
                    self.mutate(root, relative, item, attribute + item)
                    kinds = ("store", "journal") if relative == WRITE else (
                        "store" if relative == STORE else "journal",
                    )
                    for kind in kinds:
                        self.assertTrue(any("import" in error
                                            for error in descriptor_provider_errors(root, kind)))

    def test_shared_write_order_cleanup_and_published_state_cannot_drift(self) -> None:
        mutations = (
            ("root.verify().map_err(io::Error::other)?;", ""),
            ("file.write_all(bytes)?;\n    file.flush()?;", "file.flush()?;\n    file.write_all(bytes)?;"),
            ("file.flush()?;", ""),
            ("file.sync_all()?;", ""),
            ("root.sync_all().map_err(io::Error::other)", "Ok(())"),
            ("if let Err(error) = root.verify()", "if let Err(error) = foreign.verify()"),
            ("temporary_sequence.fetch_add(1, Ordering::Relaxed)", "foreign_sequence.fetch_add(1, Ordering::Relaxed)"),
            ("root.open_file(&temporary_name, FileAccess::CreateNew)?", "root.open_file(&temporary_name, FileAccess::Write)?"),
            ("let _ = root.remove_file(&temporary_name);", ""),
            ("root.rename(&temporary_name, target_name)", "foreign.rename(&temporary_name, target_name)"),
            ("if let Err(error) = root.sync_all()", "if let Err(error) = foreign.sync_all()"),
            ("published: true,", "published: false,"),
        )
        for old, new in mutations:
            with self.subTest(mutation=old):
                root = self.descriptor_candidate()
                self.mutate(root, WRITE, old, new)
                self.assertTrue(descriptor_provider_errors(root, "store"))
                self.assertTrue(descriptor_provider_errors(root, "journal"))

    def test_publication_unknown_mappings_remain_in_the_owning_caller(self) -> None:
        for kind, relative, old, new in (
            ("store", STORE, "Err(error) if error.published => Err(FileStoreError::CommitOutcomeUnknown)",
             "Err(error) if error.published => Ok(())"),
            ("store", STORE, "if error.published {\n                return Err(FileStoreError::CommitOutcomeUnknown);",
             "if false {\n                return Err(FileStoreError::CommitOutcomeUnknown);"),
            ("journal", JOURNAL, "Err(FileJournalError::InitializationOutcomeUnknown)", "Ok(())"),
            ("journal", JOURNAL, "Err(error) if error.published => Err(FileJournalError::AppendOutcomeUnknown)",
             "Err(error) if error.published => Ok(())"),
        ):
            with self.subTest(kind=kind, mutation=old):
                root = self.descriptor_candidate()
                self.mutate(root, relative, old, new)
                self.assertTrue(descriptor_provider_errors(root, kind))

    def test_comments_cannot_restore_a_removed_shared_delegation(self) -> None:
        root = self.descriptor_candidate()
        call = "heptabao_filesystem_guard::atomic_replace(root, target_name, bytes, &TEMP_SEQUENCE)"
        self.mutate(root, STORE, call, "Ok(()) // " + call)
        self.assertTrue(descriptor_provider_errors(root, "store"))

    def test_rename_cannot_change_its_destination_directory_owner(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, LEAF,
                    "rustix::fs::renameat(&self.handle, from, &self.handle, to)?",
                    "rustix::fs::renameat(&self.handle, from, &foreign_handle, to)?")
        self.assert_descriptor_rejected(root, "descriptor rename source")

    def test_enumeration_cannot_change_its_directory_owner(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, LEAF,
                    "rustix::fs::Dir::read_from(&self.handle)?",
                    "rustix::fs::Dir::read_from(&foreign_handle)?")
        self.assert_descriptor_rejected(root, "descriptor enumeration source")

    def test_journal_layout_cannot_skip_entry_type_and_owner_inspection(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(root, JOURNAL,
                    ".open_file(name, FileAccess::Read)",
                    ".open_file(name, FileAccess::Write)")
        errors = descriptor_provider_errors(root, "journal")
        self.assertTrue(any("descriptor-owned entry inspection" in error for error in errors))

    def test_current_retired_workflows_are_exactly_manual_and_read_only(self) -> None:
        for relative in (*PR_HISTORY, ".github/workflows/export-exact-audit-source.yml"):
            with self.subTest(workflow=relative):
                self.assertEqual(retired_workflow_errors(ROOT, relative), [])

    def test_current_domain_rejects_restored_pr_trigger(self) -> None:
        root = self.candidate(CANONICAL)
        self.assertEqual(retired_workflow_errors(root, CANONICAL), [])
        self.mutate(root, CANONICAL, "  workflow_dispatch:\n",
                    "  workflow_dispatch:\n  pull_request:\n")
        self.assertIn("retired workflow must remain exactly manual-only",
                      retired_workflow_errors(root, CANONICAL))

    def test_current_domain_keeps_write_and_credential_denials(self) -> None:
        for old, new in (
            ("contents: read", "contents: write"),
            ("persist-credentials: false", "persist-credentials: true"),
            ("  workflow_dispatch:\n", "  workflow_dispatch:\n  push:\n"),
        ):
            with self.subTest(change=new):
                root = self.candidate(CANONICAL)
                self.assertEqual(retired_workflow_errors(root, CANONICAL), [])
                self.mutate(root, CANONICAL, old, new)
                self.assertTrue(retired_workflow_errors(root, CANONICAL))

    def test_genuine_pr_history_keeps_its_old_branch_and_read_only_contract(self) -> None:
        for relative, branch in PR_HISTORY.items():
            with self.subTest(workflow=relative):
                text = historical_workflow(ROOT, relative)
                self.assertEqual(historical_contract_errors(text, branch), [])
                for changed in (
                    text.replace(branch, "foreign/history-base", 1),
                    text.replace("contents: read", "contents: write", 1),
                    text.replace("persist-credentials: false", "persist-credentials: true", 1),
                    text.replace("  workflow_dispatch:\n", "", 1),
                ):
                    self.assertNotEqual(changed, text)
                    self.assertTrue(historical_contract_errors(changed, branch))

    def test_genuine_export_history_preserves_the_original_exact_source_marker(self) -> None:
        relative = ".github/workflows/export-exact-audit-source.yml"
        text = historical_workflow(ROOT, relative)
        self.assertIn('      - "codex/plan-v1.3-gap-closure-v2"', text)
        self.assertIn('git archive --format=tar --prefix=HeptaBao/ "$SOURCE_SHA"', text)
        self.assertIn("contents: read", text)
        self.assertNotIn("contents: write", text)
        self.assertNotIn("git push", text)
        self.assertNotIn("persist-credentials: true", text)
        # This genuine archived push+dispatch header does not grant current CI.
        self.assertEqual(retired_workflow_errors(ROOT, relative), [])

    def test_archival_fixture_tampering_fails_authentication(self) -> None:
        record = ARCHIVED_WORKFLOWS[CANONICAL]
        root = self.candidate(record["fixture"])
        self.assertEqual(historical_workflow(root, CANONICAL),
                         historical_workflow(ROOT, CANONICAL))
        with (root / record["fixture"]).open("a") as file:
            file.write("\n# changed history\n")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            historical_workflow(root, CANONICAL)

    def test_deleted_document_workflow_has_only_a_pinned_archival_reference(self) -> None:
        relative = ".github/workflows/plan-v1.4.4-module-documentation.yml"
        record = ARCHIVED_WORKFLOWS[relative]
        root = self.candidate(record["fixture"])
        archived_document_reference(root, relative, record)
        forged = dict(record, SHA256="0" * 64)
        with self.assertRaisesRegex(ValueError, "unrecognized"):
            archived_document_reference(root, relative, forged)
        with self.assertRaisesRegex(ValueError, "unrecognized"):
            archived_document_reference(root, "docs/modules/missing-active-guide.md", record)
        active = root / relative
        active.parent.mkdir(parents=True)
        active.write_text(historical_workflow(root, relative))
        with self.assertRaisesRegex(ValueError, "regained a current path"):
            archived_document_reference(root, relative, record)


    def test_leaf_error_call_optional_trailing_comma_preserves_owned_contract(self) -> None:
        root = self.descriptor_candidate()
        self.mutate(
            root, LEAF,
            '"guarded leaf is not a singly-linked regular file",\n',
            '"guarded leaf is not a singly-linked regular file"\n',
        )
        self.assertEqual(descriptor_provider_errors(root, "store"), [])
        self.assertEqual(descriptor_provider_errors(root, "journal"), [])
        self.mutate(root, LEAF, "!metadata.is_file() || metadata.nlink() != 1",
                    "!metadata.is_file()")
        self.assert_descriptor_rejected(root, "descriptor leaf source")

    def test_read_only_job_scopes_keep_write_none_and_unknown_scope_denials(self) -> None:
        changes = (
            ("      actions: read\n", "      actions: write\n"),
            ("      actions: read\n", "      actions: none\n"),
            ("      actions: read\n", "      actions: null\n"),
            ("      pull-requests: read\n", "      pull-requests: write\n"),
            ("      pull-requests: read\n", "      pull-requests: none\n"),
            ("      pull-requests: read\n", "      pull-requests: null\n"),
            ("      pull-requests: read\n", "      packages: read\n"),
            ("    permissions:\n      contents: read\n",
             "    permissions:\n      contents: none\n"),
            ("    permissions:\n      contents: read\n", "    permissions:\n"),
        )
        for old, new in changes:
            with self.subTest(change=new):
                root = self.candidate(CANONICAL)
                self.assertEqual(retired_workflow_errors(root, CANONICAL), [])
                self.mutate(root, CANONICAL, old, new)
                self.assertIn("workflow job gained write permission",
                              retired_workflow_errors(root, CANONICAL))


if __name__ == "__main__":
    unittest.main()
