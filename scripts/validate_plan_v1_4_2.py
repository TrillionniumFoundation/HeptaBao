#!/usr/bin/env python3
"""Fail-closed validator for the HeptaBao V1.4.2 anchored recovery kernel."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from yaml.constructor import ConstructorError
from yaml.resolver import BaseResolver

from yaml12_loader import Yaml12SafeLoader

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_CRATES = {
    "crates/heptabao-key-lifecycle",
    "crates/heptabao-rollback-anchor",
    "crates/heptabao-recovery-core",
}

EXPECTED_WORKSPACE_MEMBERS = {
    "crates/heptabao-authbus-contracts",
    "crates/heptabao-barrier-api",
    "crates/heptabao-durable-core",
    "crates/heptabao-governance",
    "crates/heptabao-journal-api",
    "crates/heptabao-journaled-core",
    "crates/heptabao-key-lifecycle",
    "crates/heptabao-operation-ledger",
    "crates/heptabao-oracle-observer",
    "crates/heptabao-p0-server",
    "crates/heptabao-platform-bakeoff",
    "crates/heptabao-platform-contracts",
    "crates/heptabao-protocol",
    "crates/heptabao-recovery-core",
    "crates/heptabao-rollback-anchor",
    "crates/heptabao-single-node-journal",
    "crates/heptabao-single-node-store",
    "crates/heptabao-storage-api",
}

EXPECTED_DOCUMENTS = {
    "docs/plan/HEPTABAO_PLAN_V1_4_2_KEY_LIFECYCLE_ROLLBACK_AND_RECOVERY.md": "PLAN",
    "docs/recovery/HEPTABAO_ANCHORED_RECOVERY_CONTRACT_V1.md": "RECOVERY_CONTRACT",
    "planning/HEPTABAO_V1_4_2_ANCHORED_RECOVERY_STATUS.yaml": "STATUS",
    "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_2.yaml": "BLOCKER_REGISTER",
    "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_2.yaml": "MANIFEST",
    "schemas/heptabao_normative_document_manifest_v1_4_2.schema.json": "SCHEMA",
    "crates/heptabao-key-lifecycle/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-key-lifecycle/src/lib.rs": "RUST_CRATE",
    "crates/heptabao-rollback-anchor/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-rollback-anchor/src/lib.rs": "RUST_CRATE",
    "crates/heptabao-recovery-core/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-recovery-core/src/lib.rs": "RUST_CRATE",
    "scripts/validate_plan_v1_4_2.py": "VALIDATOR",
    "scripts/validate_v1_4_2_inherited_surface.py": "VALIDATOR",
    "tests/plan/test_plan_v1_4_2.py": "TEST",
    ".github/workflows/plan-v1.4.2-anchored-recovery.yml": "WORKFLOW",
}

EXPECTED_BLOCKERS = {
    "HB-BLK-REPO-028",
    "HB-BLK-REPO-029",
    "HB-BLK-REPO-030",
    "HB-BLK-REPO-031",
    "HB-BLK-REPO-032",
}

EXPECTED_EXTERNAL = [
    "HB-BLK-CTRL-001",
    "HB-BLK-EXT-001",
    "HB-BLK-EXT-002",
    "HB-BLK-EXT-003",
    "HB-BLK-EXT-004",
    "HB-BLK-EXT-005",
    "HB-BLK-EXT-006",
    "HB-BLK-EXT-007",
]

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

EXPECTED_NEW_LOCK_DEPENDENCIES = {
    "heptabao-key-lifecycle": {
        "heptabao-barrier-api",
        "heptabao-journal-api",
    },
    "heptabao-rollback-anchor": {
        "heptabao-barrier-api",
        "heptabao-journal-api",
        "heptabao-storage-api",
    },
    "heptabao-recovery-core": {
        "heptabao-barrier-api",
        "heptabao-journal-api",
        "heptabao-rollback-anchor",
        "heptabao-storage-api",
    },
}


class ValidationFailure(RuntimeError):
    """Raised when one closed-world V1.4.2 invariant is not satisfied."""


class UniqueKeyYaml12Loader(Yaml12SafeLoader):
    """YAML 1.2 loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyYaml12Loader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyYaml12Loader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationFailure(message)


def read_text(root: Path, relative: str) -> str:
    path = root / relative
    require(path.is_file(), f"required file is missing: {relative}")
    return path.read_text(encoding="utf-8")


def load_yaml(root: Path, relative: str) -> Any:
    try:
        return yaml.load(read_text(root, relative), Loader=UniqueKeyYaml12Loader)
    except yaml.YAMLError as error:
        raise ValidationFailure(f"invalid or ambiguous YAML {relative}: {error}") from error


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationFailure(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json(root: Path, relative: str) -> Any:
    try:
        return json.loads(
            read_text(root, relative),
            object_pairs_hook=_unique_json_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValidationFailure(f"non-standard JSON constant: {value}")
            ),
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ValidationFailure(f"invalid JSON {relative}: {error}") from error


def validate_claims(value: Any, location: str) -> None:
    require(isinstance(value, dict), f"{location} claims must be a mapping")
    require(value == EXPECTED_CLAIMS, f"{location} authority claims drifted: {value!r}")


def validate_manifest(root: Path) -> None:
    manifest_path = "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_2.yaml"
    schema_path = "schemas/heptabao_normative_document_manifest_v1_4_2.schema.json"
    manifest = load_yaml(root, manifest_path)
    schema = load_json(root, schema_path)
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        raise ValidationFailure(f"V1.4.2 manifest schema does not meta-validate: {error}") from error
    errors = sorted(
        Draft202012Validator(schema).iter_errors(manifest),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    require(
        not errors,
        "V1.4.2 manifest schema validation failed: "
        + "; ".join(error.message for error in errors),
    )
    indexed: dict[str, str] = {}
    for entry in manifest["documents"]:
        path = entry["path"]
        require(path not in indexed, f"duplicate V1.4.2 manifest path: {path}")
        indexed[path] = entry["role"]
        require((root / path).is_file(), f"manifested V1.4.2 path is missing: {path}")
    require(indexed == EXPECTED_DOCUMENTS, "V1.4.2 manifest path/role set drifted")
    validate_claims(manifest["claims"], "manifest")


def validate_status_and_blockers(root: Path) -> None:
    status = load_yaml(root, "planning/HEPTABAO_V1_4_2_ANCHORED_RECOVERY_STATUS.yaml")
    require(
        status.get("status")
        == "SOURCE_IMPLEMENTED_EXACT_HEAD_EXECUTION_AND_INDEPENDENT_REVIEW_REQUIRED",
        "V1.4.2 status overstates or understates source maturity",
    )
    require(
        status.get("current_plan")
        == "docs/plan/HEPTABAO_PLAN_V1_4_2_KEY_LIFECYCLE_ROLLBACK_AND_RECOVERY.md",
        "V1.4.2 current plan pointer drifted",
    )
    require(
        status.get("profile")
        == {
            "id": "HB-P1-DEV-ANCHORED-RECOVERY-SINGLE-PROCESS",
            "operating_system": "linux",
            "production_supported": False,
            "replicated": False,
            "multi_process_supported": False,
            "external_anchor_provider_selected": False,
            "archive_authenticator_provider_selected": False,
            "compatibility_supported": False,
        },
        "V1.4.2 bounded profile drifted",
    )
    implementation = status.get("implementation")
    require(isinstance(implementation, dict) and implementation, "implementation state is missing")
    require(
        all(value == "IMPLEMENTED_SOURCE" for value in implementation.values()),
        "implementation fields must remain source-only before exact execution",
    )
    require(status.get("external_open") == EXPECTED_EXTERNAL, "external blocker set drifted")
    validate_claims(status.get("claims"), "status")

    blockers = load_yaml(root, "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_2.yaml")
    added = blockers.get("added_blockers")
    require(isinstance(added, list), "V1.4.2 blocker list is missing")
    require(
        {entry.get("id") for entry in added} == EXPECTED_BLOCKERS,
        "V1.4.2 repository blocker IDs drifted",
    )
    for entry in added:
        identifier = entry.get("id")
        require(entry.get("class") == "REPOSITORY_CONTROLLED", f"{identifier} class drifted")
        require(entry.get("state") == "IMPLEMENTED_SOURCE", f"{identifier} state overclaims")
        require(entry.get("closure_receipt_required") is True, f"{identifier} lost receipt gate")
        require(entry.get("closure_criteria"), f"{identifier} has no closure criteria")
        require(entry.get("required_execution"), f"{identifier} has no execution gate")
        require(entry.get("evidence"), f"{identifier} has no evidence path")
    require(
        blockers.get("external_and_control_blockers_carried_forward") == EXPECTED_EXTERNAL,
        "V1.4.2 did not carry every external/control blocker",
    )
    validate_claims(
        {key: blockers.get(key) for key in EXPECTED_CLAIMS},
        "blocker register",
    )


def validate_workspace(root: Path) -> None:
    cargo = tomllib.loads(read_text(root, "Cargo.toml"))
    members = cargo.get("workspace", {}).get("members")
    require(isinstance(members, list), "workspace members are missing")
    require(len(members) == len(set(members)), "workspace contains duplicate members")
    require(set(members) == EXPECTED_WORKSPACE_MEMBERS, "V1.4.2 workspace members drifted")
    package = cargo.get("workspace", {}).get("package", {})
    require(package.get("edition") == "2024", "workspace edition drifted")
    require(package.get("rust-version") == "1.98", "workspace Rust floor drifted")
    for crate in EXPECTED_CRATES:
        crate_toml = tomllib.loads(read_text(root, f"{crate}/Cargo.toml"))
        require(crate_toml.get("package", {}).get("publish") is False, f"{crate} became publishable")
        require(crate_toml.get("lints", {}).get("workspace") is True, f"{crate} lost workspace lints")

    lock = tomllib.loads(read_text(root, "Cargo.lock"))
    packages = lock.get("package", [])
    indexed = {entry.get("name"): entry for entry in packages}
    for name, expected_dependencies in EXPECTED_NEW_LOCK_DEPENDENCIES.items():
        require(name in indexed, f"Cargo.lock is missing {name}")
        dependencies = set(indexed[name].get("dependencies", []))
        require(dependencies == expected_dependencies, f"Cargo.lock dependencies drifted for {name}")


def require_tokens(source: str, tokens: list[str], location: str) -> None:
    missing = [token for token in tokens if token not in source]
    require(not missing, f"{location} lost required invariants: {missing}")


def require_rust_tokens(source: str, tokens: list[str], location: str) -> None:
    compact_source = re.sub(r"\s+", "", source)
    missing = [
        token
        for token in tokens
        if re.sub(r"\s+", "", token) not in compact_source
    ]
    require(not missing, f"{location} lost required invariants: {missing}")


def validate_key_lifecycle_source(root: Path) -> None:
    source = read_text(root, "crates/heptabao-key-lifecycle/src/lib.rs")
    require_rust_tokens(
        source,
        [
            "HEPTABAO-KEY-RING-EVENT-V1",
            "pub enum KeyStatus",
            "pub enum KeyUseDirective",
            "KeyRingEventKind::Rotate",
            "ActiveRevocationForbidden",
            "self.epochs.insert(previous, KeyStatus::DecryptOnly)",
            "self.epochs.insert(event.epoch, KeyStatus::Active)",
            "candidate.apply(&event)",
            ".append(expected_tail, payload)",
            "KeyUseDirective::Deny",
        ],
        "key lifecycle source",
    )
    lower = source.lower()
    for forbidden in ["secretstate", "wrapped_key", "key_material", "private_key"]:
        require(forbidden not in lower, f"key lifecycle source contains forbidden key material surface: {forbidden}")
    require("#![forbid(unsafe_code)]" in source, "key lifecycle source permits unsafe code")


def validate_anchor_source(root: Path) -> None:
    source = read_text(root, "crates/heptabao-rollback-anchor/src/lib.rs")
    require_rust_tokens(
        source,
        [
            "pub struct AnchorAuthenticatorId",
            "authenticator_id: AnchorAuthenticatorId",
            "append_field(&mut output, authenticator_id.as_str().as_bytes())",
            "pub struct VerifiedRecoveryCheckpoint",
            "pub fn verify_owned",
            "AnchorContractError::CheckpointNotCurrent",
            "reread.as_ref() != Some(&receipt.current)",
            "AnchorContractError::AuthenticatorMismatch",
            "AnchorContractError::RollbackDetected",
            "AnchorContractError::DivergentObservation",
            "AnchorContractError::KeyEpochRegression",
            ".compare_and_swap(",
            "AnchorContractError::ReceiptMismatch",
        ],
        "rollback anchor source",
    )
    require("#![forbid(unsafe_code)]" in source, "rollback anchor source permits unsafe code")


def validate_recovery_source(root: Path) -> None:
    source = read_text(root, "crates/heptabao-recovery-core/src/lib.rs")
    require_rust_tokens(
        source,
        [
            "HEPTABAO-RECOVERY-ARCHIVE-V1",
            "authenticator_id: RecoveryAuthenticatorId",
            "checkpoint_authenticator_id_len",
            "RecoveryContractError::AuthenticatorMismatch",
            "anchored_checkpoint: &VerifiedRecoveryCheckpoint",
            "verified.checkpoint() != anchored_checkpoint.checkpoint()",
            "RecoveryContractError::CheckpointNotAnchored",
            "if state_len == 0 || state_len > MAX_RECOVERY_STATE_BYTES",
            "payload_budget > MAX_RECOVERY_PAYLOAD_BYTES",
            "if !target.is_empty()",
            "let staged = target.stage(verified)",
            "PublishFailure::OutcomeUnknown",
            "RecoveryRestoreError::PublishOutcomeUnknown",
            "RecoveryContractError::RestoreReceiptMismatch",
            "TrailingArchiveBytes",
        ],
        "recovery source",
    )
    require("#![forbid(unsafe_code)]" in source, "recovery source permits unsafe code")
    require(".field(\"sealed_state\"" not in source, "recovery Debug output exposes state bytes")
    require(".field(\"payload\"" not in source, "recovery Debug output exposes journal payload bytes")


def validate_documents(root: Path) -> None:
    plan = read_text(root, "docs/plan/HEPTABAO_PLAN_V1_4_2_KEY_LIFECYCLE_ROLLBACK_AND_RECOVERY.md")
    contract = read_text(root, "docs/recovery/HEPTABAO_ANCHORED_RECOVERY_CONTRACT_V1.md")
    require_tokens(
        plan,
        [
            "6b2c11d46c65603f1a1e8ded742335990b61a79b",
            "a83b78d1f2312f495ed82c2af1071342676380f2",
            "HB-BLK-REPO-028",
            "HB-BLK-REPO-032",
            "externally verified checkpoint",
            "Outcome-unknown",
            "production_supported            = false",
        ],
        "V1.4.2 plan",
    )
    require_tokens(
        contract,
        [
            "Three independent facts",
            "VerifiedRecoveryCheckpoint",
            "The target must be empty",
            "Blind retry after outcome-unknown is forbidden",
            "Explicit non-claims",
        ],
        "anchored recovery contract",
    )


def validate_workflow(root: Path) -> None:
    relative = ".github/workflows/plan-v1.4.2-anchored-recovery.yml"
    workflow = load_yaml(root, relative)
    require(isinstance(workflow, dict), "V1.4.2 workflow is not a mapping")
    require(workflow.get("name") == "plan-v1.4.2-anchored-recovery", "workflow name drifted")
    triggers = workflow.get("on")
    require(isinstance(triggers, dict), "workflow trigger mapping is missing")
    require(set(triggers) == {"pull_request", "workflow_dispatch"}, "workflow trigger set drifted")
    pull_request = triggers.get("pull_request")
    require(
        isinstance(pull_request, dict)
        and pull_request.get("branches") == ["codex/plan-v1.4-full-gap-closure-v1"],
        "workflow base branch drifted",
    )
    require(workflow.get("permissions") == {"contents": "read"}, "workflow gained write permission")
    jobs = workflow.get("jobs")
    require(isinstance(jobs, dict) and set(jobs) == {"anchored-recovery"}, "workflow job set drifted")
    job = jobs["anchored-recovery"]
    require(job.get("permissions") == {"contents": "read"}, "workflow job gained write permission")
    workflow_text = read_text(root, relative)
    require("persist-credentials: false" in workflow_text, "workflow persists checkout credentials")
    for forbidden in ["contents: write", "git push", "update-ref", "create commit", "curl --request POST"]:
        require(forbidden not in workflow_text, f"workflow contains write-capable token: {forbidden}")
    require_tokens(
        workflow_text,
        [
            "python scripts/validate_plan_v1_4_2.py",
            "python scripts/validate_v1_4_2_inherited_surface.py",
            "test_plan_v1_4_2.py",
            "baseline=\"6b2c11d46c65603f1a1e8ded742335990b61a79b\"",
            "python scripts/validate_plan_v1_4_1.py",
            "cargo +1.98.0 fmt --all -- --check",
            "cargo +1.98.0 test --locked --workspace --all-targets",
            "cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings",
            "V1.4.2 authority boundary drifted",
        ],
        "V1.4.2 workflow",
    )

    workflow_directory = root / ".github/workflows"
    if workflow_directory.is_dir():
        temporary = sorted(
            path.name
            for path in workflow_directory.iterdir()
            if path.is_file() and path.name.startswith("v1.4.2-")
        )
        require(not temporary, f"temporary write-capable V1.4.2 workflow remains: {temporary}")


def validate(root: Path = ROOT) -> None:
    validate_manifest(root)
    validate_status_and_blockers(root)
    validate_workspace(root)
    validate_key_lifecycle_source(root)
    validate_anchor_source(root)
    validate_recovery_source(root)
    validate_documents(root)
    validate_workflow(root)


def main() -> int:
    try:
        validate(ROOT)
    except (OSError, ValidationFailure, tomllib.TOMLDecodeError) as error:
        print(f"V1.4.2 validation failed: {error}", file=sys.stderr)
        return 1
    print("V1.4.2 key lifecycle, rollback anchor, and recovery validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
