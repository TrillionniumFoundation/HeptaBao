from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATE = ROOT / "crates" / "heptabao-durable-service"
GUIDE = ROOT / "docs" / "modules" / "heptabao-durable-service.md"
ARCHITECTURE = (
    ROOT / "docs" / "architecture" / "HEPTABAO_V2_1_DURABLE_RUNTIME_PIPELINE.md"
)
PLAN = ROOT / "docs" / "plan" / "HEPTABAO_MASTER_DEVELOPMENT_PLAN_V2_1.md"
MATRIX = ROOT / "planning" / "HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml"
REGISTER = ROOT / "planning" / "HEPTABAO_BLOCKER_REGISTER_V2_0.yaml"
WORKFLOW = ROOT / ".github" / "workflows" / "v2-1-main-convergence.yml"


class DurableRuntimeV21Tests(unittest.TestCase):
    def test_source_manifest_docs_plan_and_truth_are_bound(self) -> None:
        required = [
            CRATE / "Cargo.toml",
            CRATE / "src" / "lib.rs",
            GUIDE,
            ARCHITECTURE,
            PLAN,
            MATRIX,
            REGISTER,
            WORKFLOW,
        ]
        missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
        self.assertEqual([], missing)

        manifest = (CRATE / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('name = "heptabao-durable-service"', manifest)
        self.assertIn("publish = false", manifest)
        self.assertIn("workspace = true", manifest)

        matrix = MATRIX.read_text(encoding="utf-8")
        self.assertEqual(1, matrix.count("crate: heptabao-durable-service"))
        self.assertIn("domain: restart-safe sealed durable mutation runtime", matrix)
        self.assertIn("source: crates/heptabao-durable-service/src/lib.rs", matrix)
        self.assertIn("guide: docs/modules/heptabao-durable-service.md", matrix)

        register = REGISTER.read_text(encoding="utf-8")
        self.assertEqual(1, register.count("id: HB-V2-REP-008"))
        self.assertIn("class: REPOSITORY_CONTROLLED", register)
        self.assertIn("state: IMPLEMENTED_REVIEW_REQUIRED", register)

    def test_persist_ack_order_and_reconciliation_are_explicit(self) -> None:
        source = (CRATE / "src" / "lib.rs").read_text(encoding="utf-8")
        for required in (
            "JournalEvent::Intent",
            "persist_snapshot",
            "JournalEvent::Commit",
            "persist_ledger",
            "MutationOutcome::Committed",
            "ServiceError::OutcomeUnknown",
            "ReconciliationStatus::Aborted",
            "ReconciliationStatus::Committed",
        ):
            self.assertIn(required, source)

        execute = source[source.index("fn execute(") : source.index("fn append_frame(")]
        # Cryptographic serialization and terminal-record capacity reservation
        # happen before the first I/O attempt. Afterwards every failure must
        # retain OutcomeUnknown, including genuine append/snapshot/ledger errors.
        entry = execute.index("self.unresolved = true")
        for serialization in ("sealed_snapshot", "sealed_ledger", "sealed_journal_record"):
            self.assertLess(execute.index(serialization), entry)
        self.assertLess(execute.index("JournalCapacityExhausted"), entry)
        admitted = execute[entry:]
        positions = [
            admitted.index("self.append_frame(&intent)"),
            admitted.index("snapshot_path(&self.root)"),
            admitted.index("self.append_frame(&commit)"),
            admitted.index("ledger_path(&self.root)"),
            admitted.index("MutationOutcome::Committed"),
        ]
        self.assertEqual(sorted(positions), positions)
        self.assertIn("ServiceError::OutcomeUnknown { recovery_reference }", admitted)

        architecture = ARCHITECTURE.read_text(encoding="utf-8")
        self.assertIn("intent journal", architecture.lower())
        self.assertIn("sealed state publication", architecture.lower())
        self.assertIn("replay ledger", architecture.lower())
        self.assertIn("never blind retry", architecture.lower())

    def test_request_identity_is_principal_namespace_and_operation_bound(self) -> None:
        source = (CRATE / "src" / "lib.rs").read_text(encoding="utf-8")
        for field in (
            "principal: String",
            "namespace: String",
            "request_id: String",
            "resource: String",
            "authorization_digest: [u8; 32]",
            "value_digest: [u8; 32]",
        ):
            self.assertIn(field, source)
        self.assertIn("RequestBindingConflict", source)
        self.assertIn("RequestCapacityExhausted", source)
        self.assertNotIn("pop_first", source)
        self.assertNotIn("remove_entry(0", source)

    def test_all_persisted_payloads_cross_the_barrier(self) -> None:
        source = (CRATE / "src" / "lib.rs").read_text(encoding="utf-8")
        for function in ("sealed_snapshot", "sealed_journal_record", "sealed_ledger"):
            start = source.index(f"fn {function}")
            next_function = source.find("\nfn ", start + 4)
            body = source[start : next_function if next_function != -1 else None]
            self.assertIn("barrier", body)
            self.assertIn(".seal(", body)

        for function in ("load_snapshot", "load_journal", "load_ledger"):
            start = source.index(f"fn {function}")
            next_function = source.find("\nfn ", start + 4)
            body = source[start : next_function if next_function != -1 else None]
            self.assertIn("barrier", body)
            self.assertIn(".open(", body)

    def test_executable_recovery_and_security_regressions_exist(self) -> None:
        source = (CRATE / "src" / "lib.rs").read_text(encoding="utf-8")
        tests = set(re.findall(r"fn ([a-z0-9_]+)\(\) -> Result<\(\), ServiceError>", source))
        required = {
            "put_restart_read_and_duplicate_are_durable",
            "published_snapshot_is_reconciled_after_restart",
            "intent_without_publication_is_aborted_and_retryable",
            "commit_journal_rebuilds_missing_ledger",
            "namespace_keys_do_not_collide",
            "capacity_never_evicts_committed_request_identity",
            "request_identity_is_exact_operation_bound",
            "writer_fence_and_secret_redaction_hold",
            "persisted_files_do_not_contain_plaintext_secret",
            "corruption_and_wrong_barrier_fail_closed",
        }
        self.assertTrue(required.issubset(tests), sorted(required - tests))
        for regression in (
            "ambiguous_namespace_resource_pairs_are_isolated_across_restart_and_delete",
            "legacy_schema_is_rejected_without_rewriting_it",
            "genuine_snapshot_and_ledger_io_faults_preserve_recovery_reference",
            "failed_append_does_not_consume_sequence_and_reopen_recovers",
            "authenticated_old_snapshot_and_contradictory_ledger_fail_closed",
            "journal_budget_reserves_terminal_record_before_entry",
            "actual_sigkill_releases_writer_and_recovers_pending_publication",
            "real_partial_write_efbig_tail_is_recovered",
        ):
            self.assertIn(f"fn {regression}()", source)
        self.assertIn("child.kill()", source)
        self.assertIn("ulimit -f 1", source)
        self.assertIn("ExclusiveDirectory::open(root)", source)
        self.assertIn('b"HBS2"', source)
        self.assertNotIn('format!("{namespace}/{resource}")', source)


    def test_current_workflow_is_read_only_and_main_bound(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("persist-credentials: true", workflow)
        self.assertIn("branches: [main]", workflow)
        self.assertIn("cargo +1.98.0 test --locked --workspace --all-targets", workflow)
        self.assertIn("cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings", workflow)

    def test_authority_claims_remain_fail_closed(self) -> None:
        texts = [
            MATRIX.read_text(encoding="utf-8"),
            REGISTER.read_text(encoding="utf-8"),
            PLAN.read_text(encoding="utf-8"),
            GUIDE.read_text(encoding="utf-8"),
        ]
        combined = "\n".join(texts)
        for claim in (
            "qualification: false",
            "compatibility_claim: false",
            "production_authority: false",
            "migration_authority: false",
            "release_authority: false",
        ):
            self.assertIn(claim, combined)
        self.assertIn("authority_effect: NONE", combined)


if __name__ == "__main__":
    unittest.main()
