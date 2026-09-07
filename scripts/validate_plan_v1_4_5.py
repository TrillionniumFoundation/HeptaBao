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
    "docs/plan/HEPTABAO_PLAN_V1_4_5_SECURITY_INVARIANT_CLOSURE.md",
    "docs/security/HEPTABAO_SECURITY_INVARIANT_CLOSURE_V1.md",
    "docs/CURRENT_DOCUMENTATION.md",
    "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_5.yaml",
    "planning/HEPTABAO_V1_4_5_SECURITY_INVARIANT_STATUS.yaml",
    "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_5.yaml",
    "scripts/validate_plan_v1_4_5.py",
    "tests/plan/test_plan_v1_4_5.py",
    ".github/workflows/plan-v1.4.5-security-invariant-closure.yml",
)

TEMPORARY_PATHS = (
    "scripts/apply_v1_4_5_gap_closure.py",
    ".bootstrap/v1.4.5/apply.py.gz.b64",
    ".github/workflows/v1.4.5-gap-closure-bootstrap.yml",
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
            errors.append(f"{path} contains forbidden capability/transition {token!r}")


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    for path in REQUIRED_PATHS:
        if not (root / path).is_file():
            errors.append(f"missing required V1.4.5 path: {path}")
    for path in TEMPORARY_PATHS:
        if (root / path).exists():
            errors.append(f"temporary source generator remains in final tree: {path}")
    if errors:
        return errors

    require_tokens(
        errors,
        root,
        "crates/heptabao-journal-api/src/lib.rs",
        (
            "pub enum AppendFailureDisposition",
            "DefinitelyNotAppended",
            "OutcomeUnknown",
            "fn classify_append_failure",
        ),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-operation-ledger/src/lib.rs",
        (
            "pub enum LedgerWriteState",
            "ReplayRequiredAfterAppendFailure",
            "append_outcome_unknown_after_persistence_requires_authoritative_replay",
            "pub fn reopen(self)",
        ),
    )
    forbid_tokens(
        errors,
        root,
        "crates/heptabao-operation-ledger/src/lib.rs",
        (
            "pub fn into_journal(self)",
            "OperationClass::DurableMutation,\n                OperationPhase::IntentCommitted,\n                OperationPhase::Reconciled",
        ),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-key-lifecycle/src/lib.rs",
        (
            "pub enum KeyLedgerWriteState",
            "ReplayRequiredAfterAppendFailure",
            "append_outcome_unknown_poison_requires_replay",
            "pub fn reopen(self)",
        ),
    )
    forbid_tokens(
        errors,
        root,
        "crates/heptabao-key-lifecycle/src/lib.rs",
        ("pub fn into_journal(self)",),
    )
    forbid_tokens(
        errors,
        root,
        "crates/heptabao-durable-core/src/lib.rs",
        ("pub const fn store_mut", "pub fn into_parts(self) -> (S, B)"),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-journaled-core/src/lib.rs",
        (
            "recover_durable_intent",
            "generic-reconcile-forbidden",
            "current.class() == OperationClass::DurableMutation",
        ),
    )
    forbid_tokens(
        errors,
        root,
        "crates/heptabao-journaled-core/src/lib.rs",
        (
            "pub fn into_parts(self) -> (DurableStateEngine",
            "pub fn reconcile_committed_state",
        ),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-rollback-anchor/src/lib.rs",
        (
            "pub fn verify_current",
            "receipt.current != next",
            "alternate_authenticated_cas_receipt_is_rejected",
        ),
    )
    forbid_tokens(
        errors,
        root,
        "crates/heptabao-rollback-anchor/src/lib.rs",
        (
            "#[derive(Clone, Debug, Eq, PartialEq)]\npub struct VerifiedRecoveryCheckpoint",
            "pub fn into_checkpoint",
            "pub const fn authenticator(&self)",
            "pub fn into_parts(self) -> (A, P)",
        ),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-recovery-core/src/lib.rs",
        (
            "pub struct AuthorizedRecoveryImage",
            "anchor.verify_current",
            "PublishReceiptMismatchOutcomeUnknown",
            "stale_checkpoint_cannot_authorize_restore",
            "wrong_receipt_after_publication_is_outcome_unknown",
            "pub anchor_revision: AnchorRevision",
        ),
    )
    forbid_tokens(
        errors,
        root,
        "crates/heptabao-recovery-core/src/lib.rs",
        (
            "pub fn into_image(self) -> RecoveryImage",
            "pub fn into_parts(mut self) -> RecoveryImageParts",
            "fn stage(&mut self, image: VerifiedRecoveryImage)",
        ),
    )
    require_tokens(
        errors,
        root,
        "crates/heptabao-filesystem-guard/src/lib.rs",
        (
            "fn open_absolute_directory_no_symlinks",
            "for component in components",
            "O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC",
            "intermediate_symlink_is_rejected",
        ),
    )

    historical = text(root, ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml")
    expected_scope = "branches:\n      - codex/plan-v1.3-gap-closure-v2"
    if expected_scope not in historical:
        errors.append("historical V1.3.1 exact-ratifier workflow is not branch scoped")

    workflow = text(root, ".github/workflows/plan-v1.4.5-security-invariant-closure.yml")
    for token in (
        "contents: read",
        "matrix.source_kind",
        "cargo +1.98.0 test",
        "validate_plan_v1_4_5.py",
        "V145_HEAD: 936cb5599d206cea895de2ae04a1289a0b3a0326",
        'git merge-base --is-ancestor "$V145_HEAD" "$HEAD_SHA"',
        'git diff --name-only "$V145_BASELINE" "$V145_HEAD"',
        'git diff --check "$V145_BASELINE" "$V145_HEAD"',
    ):
        if token not in workflow:
            errors.append(f"V1.4.5 workflow missing {token!r}")
    for token in (
        "contents: write",
        "git push",
        "update-ref",
        "persist-credentials: true",
        'git diff --name-only "$V145_BASELINE" "$HEAD_SHA"',
        'git diff --check "$V145_BASELINE" "$HEAD_SHA"',
    ):
        if token in workflow:
            errors.append(f"V1.4.5 workflow contains forbidden successor-unsafe token: {token!r}")

    blocker = load_yaml(root, "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_5.yaml")
    status = load_yaml(root, "planning/HEPTABAO_V1_4_5_SECURITY_INVARIANT_STATUS.yaml")
    manifest = load_yaml(root, "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_5.yaml")
    expected_ids = [f"HB-BLK-REPO-{number:03d}" for number in range(41, 49)]
    actual_ids = [item.get("id") for item in blocker.get("added_blockers", [])]
    if actual_ids != expected_ids:
        errors.append(f"V1.4.5 blocker set drifted: {actual_ids!r}")
    for name, value in (("blocker", blocker), ("status", status), ("manifest", manifest)):
        if value.get("claims") != EXPECTED_CLAIMS:
            errors.append(f"{name} authority boundary drifted")
    paths = [item.get("path") for item in manifest.get("documents", [])]
    if len(paths) != len(set(paths)):
        errors.append("V1.4.5 manifest contains duplicate paths")
    for path in paths:
        if not isinstance(path, str) or not (root / path).is_file():
            errors.append(f"V1.4.5 manifest path missing: {path!r}")

    require_tokens(
        errors,
        root,
        "docs/security/HEPTABAO_SECURITY_INVARIANT_CLOSURE_V1.md",
        (
            "Capability topology",
            "Journal append failure matrix",
            "Durable mutation reconciliation matrix",
            "Recovery sequence and failure semantics",
            "Hostile evidence map",
        ),
    )
    require_tokens(
        errors,
        root,
        "docs/CURRENT_DOCUMENTATION.md",
        ("Current normative set", "Supersession chain", "V1.4.5 security invariant closure"),
    )
    module_markers = {
        "docs/modules/heptabao-journal-api.md": "V1.4.5 append-outcome classification",
        "docs/modules/heptabao-operation-ledger.md": "V1.4.5 poisoned write state",
        "docs/modules/heptabao-key-lifecycle.md": "V1.4.5 append-unknown fail-stop",
        "docs/modules/heptabao-durable-core.md": "V1.4.5 capability closure",
        "docs/modules/heptabao-journaled-core.md": "V1.4.5 reconciliation closure",
        "docs/modules/heptabao-rollback-anchor.md": "V1.4.5 live-anchor verification",
        "docs/modules/heptabao-recovery-core.md": "V1.4.5 linear restore admission",
        "docs/modules/heptabao-filesystem-guard.md": "V1.4.5 ancestor provenance",
    }
    for path, marker in module_markers.items():
        if marker not in text(root, path):
            errors.append(f"{path} missing security semantic addendum {marker!r}")

    readme = text(root, "README.md")
    for token in (
        "V1.4.5 security invariant closure",
        "V1.4.4",
        "19 / 19",
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
    print("V1.4.5 security invariant validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
