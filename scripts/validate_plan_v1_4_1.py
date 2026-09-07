#!/usr/bin/env python3
"""Fail-closed validator for the HeptaBao V1.4.1 journaled operation kernel."""

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
    "crates/heptabao-journal-api",
    "crates/heptabao-single-node-journal",
    "crates/heptabao-operation-ledger",
    "crates/heptabao-journaled-core",
}

EXPECTED_DOCUMENTS = {
    "docs/plan/HEPTABAO_PLAN_V1_4_1_DURABLE_JOURNAL_AND_OPERATION_LEDGER.md": "PLAN",
    "docs/audit/HEPTABAO_DURABLE_OPERATION_LEDGER_V1.md": "AUDIT_CONTRACT",
    "planning/HEPTABAO_V1_4_1_DURABLE_OPERATION_LEDGER_STATUS.yaml": "STATUS",
    "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_1.yaml": "BLOCKER_REGISTER",
    "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_1.yaml": "MANIFEST",
    "schemas/heptabao_normative_document_manifest_v1_4_1.schema.json": "SCHEMA",
    "crates/heptabao-journal-api/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-journal-api/src/lib.rs": "RUST_CRATE",
    "crates/heptabao-single-node-journal/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-single-node-journal/src/lib.rs": "RUST_CRATE",
    "crates/heptabao-operation-ledger/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-operation-ledger/src/lib.rs": "RUST_CRATE",
    "crates/heptabao-journaled-core/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-journaled-core/src/lib.rs": "RUST_CRATE",
    "scripts/validate_plan_v1_4_1.py": "VALIDATOR",
    "scripts/validate_v1_4_1_inherited_surface.py": "VALIDATOR",
    "tests/plan/test_plan_v1_4_1.py": "TEST",
    ".github/workflows/plan-v1.4.1-durable-operation-ledger.yml": "WORKFLOW",
}

EXPECTED_BLOCKERS = {
    "HB-BLK-REPO-023",
    "HB-BLK-REPO-024",
    "HB-BLK-REPO-025",
    "HB-BLK-REPO-026",
    "HB-BLK-REPO-027",
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

FORBIDDEN_TEMP_WORKFLOWS = {
    ".github/workflows/v1.4.1-source-export.yml",
    ".github/workflows/v1.4.1-rust-materializer.yml",
    ".github/workflows/v1.4.1-rust-materializer-v2.yml",
    ".github/workflows/v1.4.1-final-source-materializer.yml",
    ".github/workflows/v1.4.1-finalize-source.yml",
    ".github/workflows/v1.4.1-postcommit-reconcile-fix.yml",
    ".github/workflows/v1.4.1-final-reconcile-v2.yml",
    ".github/workflows/v1.4.1-unresolved-operation-fence.yml",
    ".github/workflows/v1.4.1-secure-journal-permissions.yml",
    ".github/workflows/v1.4.1-converge-final-source.yml",
}


class ValidationFailure(RuntimeError):
    """Raised when one closed-world V1.4.1 invariant is not satisfied."""


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
    manifest_path = "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_1.yaml"
    schema_path = "schemas/heptabao_normative_document_manifest_v1_4_1.schema.json"
    manifest = load_yaml(root, manifest_path)
    schema = load_json(root, schema_path)
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        raise ValidationFailure(f"V1.4.1 manifest schema does not meta-validate: {error}") from error
    errors = sorted(
        Draft202012Validator(schema).iter_errors(manifest),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    require(
        not errors,
        "V1.4.1 manifest schema validation failed: "
        + "; ".join(error.message for error in errors),
    )
    indexed: dict[str, str] = {}
    for entry in manifest["documents"]:
        path = entry["path"]
        require(path not in indexed, f"duplicate V1.4.1 manifest path: {path}")
        indexed[path] = entry["role"]
        require((root / path).is_file(), f"manifested V1.4.1 path is missing: {path}")
    require(indexed == EXPECTED_DOCUMENTS, "V1.4.1 manifest path/role set drifted")
    validate_claims(manifest["claims"], "manifest")


def validate_status_and_blockers(root: Path) -> None:
    status = load_yaml(
        root, "planning/HEPTABAO_V1_4_1_DURABLE_OPERATION_LEDGER_STATUS.yaml"
    )
    require(
        status.get("status")
        == "SOURCE_IMPLEMENTED_EXACT_HEAD_EXECUTION_AND_INDEPENDENT_REVIEW_REQUIRED",
        "V1.4.1 status overstates or understates source maturity",
    )
    require(
        status.get("current_plan")
        == "docs/plan/HEPTABAO_PLAN_V1_4_1_DURABLE_JOURNAL_AND_OPERATION_LEDGER.md",
        "V1.4.1 current plan pointer drifted",
    )
    require(
        status.get("profile")
        == {
            "id": "HB-P1-DEV-JOURNALED-SINGLE-PROCESS",
            "operating_system": "linux",
            "production_supported": False,
            "replicated": False,
            "multi_process_supported": False,
            "compatibility_supported": False,
        },
        "V1.4.1 bounded profile drifted",
    )
    implementation = status.get("implementation")
    require(isinstance(implementation, dict) and implementation, "implementation state is missing")
    require(
        all(value == "IMPLEMENTED_SOURCE" for value in implementation.values()),
        "implementation fields must remain source-only before exact execution",
    )
    require(status.get("external_open") == EXPECTED_EXTERNAL, "external blocker set drifted")
    validate_claims(status.get("claims"), "status")

    blockers = load_yaml(root, "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_1.yaml")
    added = blockers.get("added_blockers")
    require(isinstance(added, list), "V1.4.1 blocker list is missing")
    require(
        {entry.get("id") for entry in added} == EXPECTED_BLOCKERS,
        "V1.4.1 repository blocker IDs drifted",
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
        "V1.4.1 did not carry every external/control blocker",
    )
    validate_claims(
        {key: blockers.get(key) for key in EXPECTED_CLAIMS},
        "blocker register",
    )


def validate_workspace(root: Path) -> None:
    cargo = tomllib.loads(read_text(root, "Cargo.toml"))
    members = set(cargo.get("workspace", {}).get("members", []))
    require(EXPECTED_CRATES <= members, "V1.4.1 crates are not all workspace members")
    require(len(members) == 15, f"V1.4.1 workspace must contain exactly 15 crates, found {len(members)}")
    lock = read_text(root, "Cargo.lock")
    for crate in EXPECTED_CRATES:
        package = crate.removeprefix("crates/")
        require(
            lock.count(f'name = "{package}"') == 1,
            f"Cargo.lock must contain exactly one {package} package",
        )

    manifests = {
        "crates/heptabao-journal-api/Cargo.toml": set(),
        "crates/heptabao-single-node-journal/Cargo.toml": {"heptabao-journal-api"},
        "crates/heptabao-operation-ledger/Cargo.toml": {
            "heptabao-journal-api",
            "heptabao-storage-api",
        },
        "crates/heptabao-journaled-core/Cargo.toml": {
            "heptabao-barrier-api",
            "heptabao-durable-core",
            "heptabao-journal-api",
            "heptabao-operation-ledger",
            "heptabao-storage-api",
        },
    }
    for relative, expected_dependencies in manifests.items():
        parsed = tomllib.loads(read_text(root, relative))
        dependencies = set(parsed.get("dependencies", {}))
        require(
            dependencies == expected_dependencies,
            f"provider-neutral dependency boundary drifted in {relative}: {dependencies}",
        )
        require(parsed.get("package", {}).get("publish") is False, f"{relative} became publishable")


def require_tokens(text: str, tokens: list[str], location: str) -> None:
    missing = [token for token in tokens if token not in text]
    require(not missing, f"{location} is missing required source contracts: {missing}")


def validate_rust_sources(root: Path) -> None:
    journal_api = read_text(root, "crates/heptabao-journal-api/src/lib.rs")
    require_tokens(
        journal_api,
        [
            "pub trait JournalAuthenticator",
            "pub trait DurableJournal",
            "pub const fn checked_next",
            "pub struct JournalPayload",
            "impl Drop for JournalPayload",
            "JournalSequenceOverflow",
        ],
        "journal API",
    )

    journal = read_text(root, "crates/heptabao-single-node-journal/src/lib.rs")
    require("entry.metadata()" not in journal, "journal directory enumeration follows symlinks")
    require_tokens(
        journal,
        [
            "pub fn create_new",
            "pub fn reopen_existing",
            "pub fn reconcile_next_orphan",
            "create_new(true)",
            "fs::rename",
            "sync_all",
            "AppendOutcomeUnknown",
            "PendingOrphan",
            "AuthenticationFailed",
            "fs::symlink_metadata(entry.path())",
            "secure_create_new",
        ],
        "single-node journal",
    )
    require(
        "fn parse_entry_file_name(name: &str) -> Result<Option<JournalSequence>, DecodeError>"
        in journal,
        "journal entry-name parser is not provider-neutral",
    )

    ledger = read_text(root, "crates/heptabao-operation-ledger/src/lib.rs")
    require_tokens(
        ledger,
        [
            "HEPTABAO-OPERATION-EVENT-V1",
            "pub enum OperationPhase",
            "pub enum RetryDirective",
            "fn validate_transition",
            "fn allowed_transition",
            "OperationPhase::EffectUnknown",
            "RetryDirective::ReconcileOnly",
            "DuplicateAcceptedOperation",
            "ImmutableFieldDrift",
            "TrailingEventBytes",
        ],
        "operation ledger",
    )

    core = read_text(root, "crates/heptabao-journaled-core/src/lib.rs")
    require_tokens(
        core,
        [
            "pub struct JournaledDurableCore",
            "OperationPhase::IntentCommitted",
            "StateCommittedLedgerIncomplete",
            "record_response_audit_failure_after_commit",
            "reconcile_committed_state",
            "blocking_phase",
            "record_rejected_before_dispatch",
            "UnresolvedOperationBlocksMutation",
            "record_delivery",
            "ExistingOperation",
        ],
        "journaled durable core",
    )
    accepted_position = core.find(".record(accepted.clone())")
    intent_position = core.find(".record(intent.clone())")
    state_position = core.find(".state\n            .persist(")
    committed_position = core.find(".record(committed)")
    require(
        -1 not in (accepted_position, intent_position, state_position, committed_position)
        and accepted_position < intent_position < state_position < committed_position,
        "journaled core no longer persists accepted/intent before state and commit outcome after state",
    )
    require(
        "fn detail_code(value: &str) -> Result<StableDetailCode, OperationContractError>" in core,
        "journaled core detail-code helper retained unconstrained generic inference",
    )

    for relative in (
        "crates/heptabao-journal-api/src/lib.rs",
        "crates/heptabao-single-node-journal/src/lib.rs",
        "crates/heptabao-operation-ledger/src/lib.rs",
        "crates/heptabao-journaled-core/src/lib.rs",
    ):
        source = read_text(root, relative)
        require("#![forbid(unsafe_code)]" in source, f"{relative} lost unsafe prohibition")
        require("saturating_add" not in source, f"{relative} uses silent saturating arithmetic")


def validate_documents(root: Path) -> None:
    plan = read_text(
        root, "docs/plan/HEPTABAO_PLAN_V1_4_1_DURABLE_JOURNAL_AND_OPERATION_LEDGER.md"
    )
    audit = read_text(root, "docs/audit/HEPTABAO_DURABLE_OPERATION_LEDGER_V1.md")
    require_tokens(
        plan,
        [
            "HB-P1-DEV-JOURNALED-SINGLE-PROCESS",
            "AppendOutcomeUnknown",
            "StateCommittedLedgerIncomplete",
            "ReconcileOnly",
            "20-path V1.4.1 extension allowlist",
            "qualification=false",
            "production_authority=false",
        ],
        "V1.4.1 plan",
    )
    require_tokens(
        audit,
        [
            "heptabao-journal.marker",
            "TAIL",
            "previous_tag",
            "State machine invariants",
            "retry only as a new operation identity",
            "external rollback anchor",
        ],
        "durable operation ledger contract",
    )


def validate_workflow(root: Path) -> None:
    relative = ".github/workflows/plan-v1.4.1-durable-operation-ledger.yml"
    workflow_text = read_text(root, relative)
    workflow = load_yaml(root, relative)
    require(workflow.get("permissions") == {"contents": "read"}, "V1.4.1 workflow permissions drifted")
    jobs = workflow.get("jobs")
    require(isinstance(jobs, dict), "V1.4.1 workflow jobs are missing")
    job = jobs.get("journaled-single-node")
    require(isinstance(job, dict), "canonical V1.4.1 job is missing")
    require(job.get("runs-on") == "ubuntu-24.04", "V1.4.1 runner profile drifted")
    steps = job.get("steps")
    require(isinstance(steps, list) and steps, "V1.4.1 workflow has no executable steps")
    checkout_steps = [step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@")]
    require(len(checkout_steps) == 1, "V1.4.1 workflow must have exactly one checkout step")
    checkout = checkout_steps[0]
    require(
        re.fullmatch(r"actions/checkout@[0-9a-f]{40}", checkout["uses"]) is not None,
        "checkout action is not commit pinned",
    )
    checkout_with = checkout.get("with", {})
    require(checkout_with.get("persist-credentials") is False, "checkout credentials are persisted")
    require(
        checkout_with.get("ref") == "${{ github.event.pull_request.head.sha || github.sha }}",
        "V1.4.1 workflow does not check out the exact source head",
    )
    commands = "\n".join(str(step.get("run", "")) for step in steps)
    for command in (
        "python scripts/validate_plan_v1_4_1.py",
        "python scripts/validate_v1_4_1_inherited_surface.py",
        "python -m unittest discover -s tests/plan -p 'test_plan_v1_4_1.py' -v",
        "python -m unittest discover -s tests/platform -p 'test_*.py' -v",
        "python -m unittest discover -s tests/oracle -p 'test_*.py' -v",
        "cargo +1.98.0 fmt --all -- --check",
        "cargo +1.98.0 test --locked --workspace --all-targets",
        "cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings",
    ):
        require(command in commands, f"V1.4.1 workflow omits required command: {command}")
    require(
        'baseline="33e1c14c3e417ea1c9ea181e2181751736c7bce5"' in commands,
        "V1.4.1 workflow does not pin the frozen V1.4 baseline",
    )
    require("git worktree add --detach" in commands, "V1.4.1 workflow does not replay frozen V1.4")
    require("contents: write" not in workflow_text, "V1.4.1 workflow gained write permission")
    require("git push" not in workflow_text, "V1.4.1 workflow gained source publication")

    for path in FORBIDDEN_TEMP_WORKFLOWS:
        require(not (root / path).exists(), f"temporary write-capable workflow remains: {path}")


def validate(root: Path = ROOT) -> None:
    validate_manifest(root)
    validate_status_and_blockers(root)
    validate_workspace(root)
    validate_rust_sources(root)
    validate_documents(root)
    validate_workflow(root)


def main() -> int:
    try:
        validate(ROOT)
    except (OSError, ValidationFailure, tomllib.TOMLDecodeError) as error:
        print(f"V1.4.1 validation failed: {error}", file=sys.stderr)
        return 1
    print("V1.4.1 durable journal and operation ledger validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
