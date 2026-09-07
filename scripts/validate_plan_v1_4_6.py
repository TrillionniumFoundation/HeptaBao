#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

EXPECTED_CLAIMS = {
    "qualification": False,
    "compatibility_claim": False,
    "selected_candidates": [],
    "selection_effect": "NONE",
    "production_authority": False,
    "migration_authority": False,
    "release_authority": False,
    "authority_effect": "NONE",
}

REQUIRED_PATHS = (
    "docs/plan/HEPTABAO_PLAN_V1_4_6_AUTHORITATIVE_RECOVERY_CLOSURE.md",
    "docs/recovery/HEPTABAO_AUTHORITATIVE_RECOVERY_PROTOCOL_V1.md",
    "docs/CURRENT_DOCUMENTATION.md",
    "planning/HEPTABAO_V1_4_6_AUTHORITATIVE_RECOVERY_STATUS.yaml",
    "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_6.yaml",
    "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_6.yaml",
    "scripts/validate_plan_v1_4_6.py",
    "tests/plan/test_plan_v1_4_6.py",
    ".github/workflows/plan-v1.4.6-authoritative-recovery-closure.yml",
)

FORBIDDEN_GLOBS = (
    ".diagnostics/v1.4.6*",
    "scripts/apply_v1_4_6*.py",
    "scripts/fix_apply_v1_4_6*.py",
    ".github/workflows/materialize-v1.4.6*.yml",
)


def text(root: Path, path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def load_yaml(root: Path, path: str):
    return yaml.safe_load(text(root, path))


def require_tokens(errors: list[str], root: Path, path: str, tokens: tuple[str, ...]) -> None:
    value = text(root, path)
    compact_value = "".join(value.split()) if path.endswith(".rs") else value
    for token in tokens:
        if token in value:
            continue
        if path.endswith(".rs") and "".join(token.split()) in compact_value:
            continue
        errors.append(f"{path} missing required semantic token {token!r}")


def forbid_tokens(errors: list[str], root: Path, path: str, tokens: tuple[str, ...]) -> None:
    value = text(root, path)
    for token in tokens:
        if token in value:
            errors.append(f"{path} contains forbidden semantic token {token!r}")


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    for path in REQUIRED_PATHS:
        if not (root / path).is_file():
            errors.append(f"missing required V1.4.6 path: {path}")
    for pattern in FORBIDDEN_GLOBS:
        for path in root.glob(pattern):
            errors.append(f"development-only V1.4.6 artifact remains: {path.relative_to(root)}")
    if errors:
        return errors

    require_tokens(
        errors,
        root,
        "crates/heptabao-rollback-anchor/src/lib.rs",
        (
            "pub enum AnchorFenceError",
            "CheckpointNotCurrent",
            "ProviderBeforeEntry",
            "OutcomeUnknownAfterEntry",
            "fn with_current_fence<T, F>",
            "F: FnOnce() -> T",
            "AnchorCoordinatorError::FenceOutcomeUnknown",
            "current_checkpoint_fence_rejects_stale_checkpoint",
        ),
    )
    forbid_tokens(
        errors,
        root,
        "crates/heptabao-rollback-anchor/src/lib.rs",
        ("AnchorFenceError::Provider(error)",),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-recovery-core/src/lib.rs",
        (
            "pub enum StageFailure",
            "fn stage_if_empty(",
            "with_current_fence(&publish_checkpoint",
            "map_anchor_restore_error",
            "AnchorFenceOutcomeUnknown",
            "CheckpointAuthenticator",
            "anchor_fence_is_held_across_target_publication",
            "post_entry_anchor_fence_failure_is_outcome_unknown",
            "PublishReceiptMismatchOutcomeUnknown",
        ),
    )
    forbid_tokens(
        errors,
        root,
        "crates/heptabao-recovery-core/src/lib.rs",
        (
            "fn is_empty(&self) -> Result<bool",
            "fn stage(&mut self, image: AuthorizedRecoveryImage)",
            "anchor.verify_current(&publish_checkpoint)",
            ".map_err(|_| {\n                RecoveryRestoreError::Contract(RecoveryContractError::CheckpointNotAnchored)",
        ),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-operation-ledger/src/lib.rs",
        (
            "append_outcome_unknown_after_persistence_requires_authoritative_replay",
            "let fail_after_persistence = self.fail_on_append == Some(self.calls);",
            "self.payloads.push(payload.into_bytes());\n            if fail_after_persistence",
            "assert_eq!(ledger.operation_count(), 1);",
        ),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-single-node-store/src/lib.rs",
        (
            "options.mode(0o600);",
            "durable_store_files_are_owner_only_on_unix",
            "recover_commit",
            "exact_orphan_bundle_is_completed_only_for_matching_intent",
        ),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-filesystem-guard/src/lib.rs",
        (
            "static TEST_SERIAL: Mutex<()> = Mutex::new(());",
            "fn serial_test() -> MutexGuard<'static, ()>",
            "let _serial = serial_test();",
            "cooperating_processes_observe_writer_fence",
            "second_open_is_fenced_until_drop",
        ),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-journal-api/src/lib.rs",
        ("fn recover_authoritative", "AppendFailureDisposition::OutcomeUnknown"),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-single-node-journal/src/lib.rs",
        ("fn recover_authoritative", "reconcile_next_orphan"),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-journaled-core/src/lib.rs",
        (
            "recover_durable_intent",
            "CommitRecovery::Committed",
            "CommitRecovery::NotCommitted",
            "generic-reconcile-forbidden",
        ),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-storage-api/src/lib.rs",
        (
            "pub struct CommitIntent",
            "not proof that a matching ledger record was persisted",
            "fn recover_commit",
        ),
    )

    workflow_path = ".github/workflows/plan-v1.4.6-authoritative-recovery-closure.yml"
    workflow = text(root, workflow_path)
    for token in (
        "pull_request:",
        "contents: read",
        "matrix.source_kind",
        "exact-head",
        "prospective-merge",
        "github.event.pull_request.head.sha",
        "github.sha",
        "validate_plan_v1_4_6.py",
        "cargo +1.98.0 test --locked --workspace --all-targets",
    ):
        if token not in workflow:
            errors.append(f"{workflow_path} missing {token!r}")
    for token in ("push:", "contents: write", "git push", "persist-credentials: true"):
        if token in workflow:
            errors.append(f"{workflow_path} is not a read-only PR-only gate: {token!r}")

    blocker = load_yaml(root, "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_6.yaml")
    status = load_yaml(root, "planning/HEPTABAO_V1_4_6_AUTHORITATIVE_RECOVERY_STATUS.yaml")
    manifest = load_yaml(root, "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_6.yaml")
    expected_ids = [f"HB-BLK-REPO-{number:03d}" for number in range(49, 59)]
    actual_ids = [item.get("id") for item in blocker.get("added_blockers", [])]
    if actual_ids != expected_ids:
        errors.append(f"V1.4.6 blocker set drifted: {actual_ids!r}")
    for item in blocker.get("added_blockers", []):
        if item.get("state") == "CLOSED":
            errors.append(f"{item.get('id')} cannot claim CLOSED without external review receipt")
        if item.get("closure_receipt_required") is not True:
            errors.append(f"{item.get('id')} lost closure receipt requirement")
    for name, value in (("blocker", blocker), ("status", status), ("manifest", manifest)):
        if value.get("claims") != EXPECTED_CLAIMS:
            errors.append(f"{name} authority boundary drifted")
    paths = [item.get("path") for item in manifest.get("documents", [])]
    if len(paths) != len(set(paths)):
        errors.append("V1.4.6 manifest contains duplicate paths")
    for path in paths:
        if not isinstance(path, str) or not (root / path).is_file():
            errors.append(f"V1.4.6 manifest path missing: {path!r}")

    implementation = status.get("implementation") or {}
    for key in (
        "phase_aware_anchor_fence_error",
        "typed_anchor_contract_provider_and_authenticator_errors",
        "post_entry_fence_uncertainty_hostile_test",
        "rustfmt_stable_inherited_semantic_validation",
    ):
        if implementation.get(key) != "IMPLEMENTED_SOURCE":
            errors.append(f"status missing implemented source state for {key!r}")

    require_tokens(
        errors,
        root,
        "scripts/validate_plan_v1_4_5.py",
        (
            'compact_value = "".join(value.split()) if path.endswith(".rs") else value',
            '"".join(token.split()) in compact_value',
        ),
    )
    require_tokens(
        errors,
        root,
        "tests/plan/test_plan_v1_4_5.py",
        ("test_rustfmt_whitespace_is_semantically_transparent",),
    )
    require_tokens(
        errors,
        root,
        "tests/plan/test_plan_v1_4_6.py",
        (
            "test_post_entry_fence_error_downgrade_is_rejected",
            "test_phase_aware_anchor_error_removal_is_rejected",
            "test_rustfmt_whitespace_is_semantically_transparent",
        ),
    )

    require_tokens(
        errors,
        root,
        "docs/modules/heptabao-filesystem-guard.md",
        (
            "V1.4.6 fork/exec test isolation",
            "`O_CLOEXEC` closes inherited",
            "descriptors at exec rather than at fork",
            "fail-closed `WriterBusy`",
        ),
    )
    require_tokens(
        errors,
        root,
        "docs/modules/heptabao-rollback-anchor.md",
        (
            "V1.4.6 phase-aware fence completion",
            "ProviderBeforeEntry",
            "OutcomeUnknownAfterEntry",
        ),
    )
    require_tokens(
        errors,
        root,
        "docs/modules/heptabao-recovery-core.md",
        (
            "V1.4.6 outer-fence outcome preservation",
            "AnchorFenceOutcomeUnknown",
            "reconcile both external anchor and target",
        ),
    )

    require_tokens(
        errors,
        root,
        "docs/recovery/HEPTABAO_AUTHORITATIVE_RECOVERY_PROTOCOL_V1.md",
        (
            "Capability topology",
            "Anchor publication-fence protocol",
            "Atomic empty-target admission",
            "Durable mutation recovery state machine",
            "Storage crash matrix",
            "Journal append-unknown matrix",
            "CI provenance contract",
            "OutcomeUnknownAfterEntry",
            "post_entry_anchor_fence_failure_is_outcome_unknown",
            "Known limitations",
        ),
    )
    require_tokens(
        errors,
        root,
        "docs/plan/HEPTABAO_PLAN_V1_4_6_AUTHORITATIVE_RECOVERY_CLOSURE.md",
        (
            "phase-aware",
            "HB-BLK-REPO-049` through `HB-BLK-REPO-058",
            "33574894762",
        ),
    )
    require_tokens(
        errors,
        root,
        "docs/CURRENT_DOCUMENTATION.md",
        (
            "V1.4.6 authoritative recovery closure",
            "HEPTABAO_AUTHORITATIVE_RECOVERY_PROTOCOL_V1.md",
            "V1.4.5 security invariant closure",
        ),
    )
    module_markers = {
        "docs/modules/heptabao-storage-api.md": "V1.4.6 authoritative commit recovery",
        "docs/modules/heptabao-single-node-store.md": "V1.4.6 exact orphan and permission closure",
        "docs/modules/heptabao-journal-api.md": "V1.4.6 authoritative replay contract",
        "docs/modules/heptabao-single-node-journal.md": "V1.4.6 exact-next orphan recovery",
        "docs/modules/heptabao-operation-ledger.md": "V1.4.6 persisted-then-error evidence",
        "docs/modules/heptabao-durable-core.md": "V1.4.6 prepared mutation semantics",
        "docs/modules/heptabao-journaled-core.md": "V1.4.6 interrupted commit recovery",
        "docs/modules/heptabao-key-lifecycle.md": "V1.4.6 authoritative journal recovery",
        "docs/modules/heptabao-rollback-anchor.md": "V1.4.6 publication fence",
        "docs/modules/heptabao-recovery-core.md": "V1.4.6 atomic admission and fenced publish",
    }
    for path, marker in module_markers.items():
        if marker not in text(root, path):
            errors.append(f"{path} missing implementation addendum {marker!r}")

    readme = text(root, "README.md")
    for token in (
        "V1.4.6 authoritative recovery closure",
        "not production-deployable",
        "docs/CURRENT_DOCUMENTATION.md",
    ):
        if token not in readme:
            errors.append(f"README missing current-truth token {token!r}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    errors = validate(Path(args.root).resolve())
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("V1.4.6 authoritative recovery validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
