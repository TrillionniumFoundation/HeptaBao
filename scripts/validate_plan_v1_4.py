#!/usr/bin/env python3
"""Fail-closed validator for the HeptaBao V1.4 durable foundation."""

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
    "crates/heptabao-storage-api",
    "crates/heptabao-barrier-api",
    "crates/heptabao-single-node-store",
    "crates/heptabao-durable-core",
}

EXPECTED_DOCUMENTS = {
    "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_4.md": "PLAN",
    "docs/storage/HEPTABAO_SINGLE_NODE_DURABLE_STORE_V1.md": "STORAGE_CONTRACT",
    "planning/HEPTABAO_V1_4_DURABLE_FOUNDATION_STATUS.yaml": "STATUS",
    "planning/HEPTABAO_BLOCKER_REGISTER_V1_4.yaml": "BLOCKER_REGISTER",
    "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4.yaml": "MANIFEST",
    "schemas/heptabao_normative_document_manifest_v1_4.schema.json": "SCHEMA",
    "crates/heptabao-storage-api/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-storage-api/src/lib.rs": "RUST_CRATE",
    "crates/heptabao-barrier-api/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-barrier-api/src/lib.rs": "RUST_CRATE",
    "crates/heptabao-single-node-store/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-single-node-store/src/lib.rs": "RUST_CRATE",
    "crates/heptabao-durable-core/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-durable-core/src/lib.rs": "RUST_CRATE",
    "scripts/validate_plan_v1_4.py": "VALIDATOR",
    "scripts/validate_v1_4_inherited_surface.py": "VALIDATOR",
    "tests/plan/test_plan_v1_4.py": "TEST",
    ".github/workflows/plan-v1.4-durable-single-node.yml": "WORKFLOW",
}

EXPECTED_BLOCKERS = {
    "HB-BLK-REPO-018",
    "HB-BLK-REPO-019",
    "HB-BLK-REPO-020",
    "HB-BLK-REPO-021",
    "HB-BLK-REPO-022",
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


class ValidationFailure(RuntimeError):
    """Raised when one closed-world V1.4 invariant is not satisfied."""


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
    text = read_text(root, relative)
    try:
        return yaml.load(text, Loader=UniqueKeyYaml12Loader)
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
    text = read_text(root, relative)
    try:
        return json.loads(
            text,
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
    manifest_path = "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4.yaml"
    schema_path = "schemas/heptabao_normative_document_manifest_v1_4.schema.json"
    manifest = load_yaml(root, manifest_path)
    schema = load_json(root, schema_path)
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:  # jsonschema exposes several schema error subclasses
        raise ValidationFailure(f"V1.4 manifest schema does not meta-validate: {error}") from error
    errors = sorted(
        Draft202012Validator(schema).iter_errors(manifest),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    require(
        not errors,
        "V1.4 manifest schema validation failed: "
        + "; ".join(error.message for error in errors),
    )
    entries = manifest["documents"]
    indexed: dict[str, str] = {}
    for entry in entries:
        path = entry["path"]
        require(path not in indexed, f"duplicate V1.4 manifest path: {path}")
        indexed[path] = entry["role"]
        require((root / path).is_file(), f"manifested V1.4 path is missing: {path}")
    require(indexed == EXPECTED_DOCUMENTS, "V1.4 manifest path/role set drifted")
    validate_claims(manifest["claims"], "manifest")


def validate_status_and_blockers(root: Path) -> None:
    status = load_yaml(root, "planning/HEPTABAO_V1_4_DURABLE_FOUNDATION_STATUS.yaml")
    require(
        status.get("status")
        == "SOURCE_IMPLEMENTED_EXACT_HEAD_EXECUTION_AND_INDEPENDENT_REVIEW_REQUIRED",
        "V1.4 status overstates or understates the source state",
    )
    require(
        status.get("current_plan")
        == "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_4.md",
        "V1.4 current plan pointer drifted",
    )
    profile = status.get("profile")
    require(isinstance(profile, dict), "V1.4 profile is missing")
    require(
        profile
        == {
            "id": "HB-P1-DEV-DURABLE-SINGLE-PROCESS",
            "production_supported": False,
            "multi_process_supported": False,
            "compatibility_supported": False,
        },
        "V1.4 bounded profile drifted",
    )
    implementation = status.get("implementation")
    require(isinstance(implementation, dict), "V1.4 implementation state is missing")
    require(
        implementation
        and all(value == "IMPLEMENTED_SOURCE" for value in implementation.values()),
        "V1.4 implementation fields must remain source-only before execution",
    )
    require(status.get("external_open") == EXPECTED_EXTERNAL, "external blocker set drifted")
    validate_claims(status.get("claims"), "status")

    blockers = load_yaml(root, "planning/HEPTABAO_BLOCKER_REGISTER_V1_4.yaml")
    added = blockers.get("added_blockers")
    require(isinstance(added, list), "V1.4 blocker list is missing")
    require(
        {entry.get("id") for entry in added} == EXPECTED_BLOCKERS,
        "V1.4 repository blocker IDs drifted",
    )
    for entry in added:
        require(entry.get("class") == "REPOSITORY_CONTROLLED", f"{entry.get('id')} class drifted")
        require(entry.get("state") == "IMPLEMENTED_SOURCE", f"{entry.get('id')} state overclaims")
        require(entry.get("closure_receipt_required") is True, f"{entry.get('id')} lost receipt gate")
        require(entry.get("closure_criteria"), f"{entry.get('id')} has no closure criteria")
        require(entry.get("required_execution"), f"{entry.get('id')} has no execution gate")
    require(
        blockers.get("external_and_control_blockers_carried_forward") == EXPECTED_EXTERNAL,
        "V1.4 did not carry every external/control blocker",
    )
    top_level_claims = {key: blockers.get(key) for key in EXPECTED_CLAIMS}
    validate_claims(top_level_claims, "blocker register")


def validate_workspace(root: Path) -> None:
    cargo = tomllib.loads(read_text(root, "Cargo.toml"))
    members = set(cargo.get("workspace", {}).get("members", []))
    require(EXPECTED_CRATES <= members, "V1.4 crates are not all root workspace members")
    lock = read_text(root, "Cargo.lock")
    for crate in EXPECTED_CRATES:
        package = crate.removeprefix("crates/")
        require(
            lock.count(f'name = "{package}"') == 1,
            f"Cargo.lock must contain exactly one {package} package",
        )

    manifests = {
        "crates/heptabao-storage-api/Cargo.toml": set(),
        "crates/heptabao-barrier-api/Cargo.toml": {"heptabao-storage-api"},
        "crates/heptabao-single-node-store/Cargo.toml": {"heptabao-storage-api"},
        "crates/heptabao-durable-core/Cargo.toml": {
            "heptabao-barrier-api",
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
    storage = read_text(root, "crates/heptabao-storage-api/src/lib.rs")
    require_tokens(
        storage,
        [
            "pub trait DurableGenerationStore",
            "pub trait IntegrityProvider",
            "pub const fn checked_next",
            "pub struct OpaqueState",
            "impl Drop for OpaqueState",
            "GenerationOverflow",
        ],
        "storage API",
    )

    barrier = read_text(root, "crates/heptabao-barrier-api/src/lib.rs")
    require_tokens(
        barrier,
        [
            "pub trait BarrierProvider",
            "pub struct BarrierContext",
            "canonical_associated_data",
            "pub struct SealedEnvelope",
            "TrailingEnvelopeBytes",
            "impl Drop for SecretState",
            "impl Drop for SealedEnvelope",
        ],
        "barrier API",
    )
    require(
        "ring::" not in barrier and "openssl" not in barrier and "aws_lc" not in barrier,
        "barrier contract embedded an unselected production provider",
    )

    store = read_text(root, "crates/heptabao-single-node-store/src/lib.rs")
    require_tokens(
        store,
        [
            "pub fn create_new",
            "pub fn reopen_existing",
            "pub fn adopt_legacy",
            "create_new(true)",
            "fs::rename",
            "sync_all",
            "CommitOutcomeUnknown",
            "GenerationConflict",
            "GenerationAlreadyExists",
            "read_and_verify_bundle",
        ],
        "single-node store",
    )

    core = read_text(root, "crates/heptabao-durable-core/src/lib.rs")
    require_tokens(
        core,
        [
            "pub struct DurableStateEngine",
            "BarrierPurpose::AuthoritativeState",
            "BarrierEpochMismatch",
            "CommitReceiptMismatch",
            "associated_data_mismatch_fails_authentication",
        ],
        "durable core",
    )
    seal_position = core.find(".seal(&context, plaintext)")
    commit_position = core.find(".commit(expected_current, candidate)")
    require(
        0 <= seal_position < commit_position,
        "durable core no longer seals plaintext before storage commit",
    )

    for relative in (
        "crates/heptabao-storage-api/src/lib.rs",
        "crates/heptabao-barrier-api/src/lib.rs",
        "crates/heptabao-single-node-store/src/lib.rs",
        "crates/heptabao-durable-core/src/lib.rs",
    ):
        source = read_text(root, relative)
        require("#![forbid(unsafe_code)]" in source, f"{relative} lost unsafe prohibition")
        require("saturating_add" not in source, f"{relative} uses silent saturating generation arithmetic")


def validate_documents(root: Path) -> None:
    plan = read_text(root, "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_4.md")
    storage = read_text(root, "docs/storage/HEPTABAO_SINGLE_NODE_DURABLE_STORE_V1.md")
    require_tokens(
        plan,
        [
            "HB-P1-DEV-DURABLE-SINGLE-PROCESS",
            "barrier-before-storage",
            "CommitOutcomeUnknown",
            "qualification=false",
            "production_authority=false",
            "frozen V1.3.1 baseline",
        ],
        "V1.4 plan",
    )
    require_tokens(
        storage,
        [
            "CreateNew",
            "ReopenExisting",
            "AdoptLegacy",
            "CURRENT",
            "outcome unknown",
            "HB-BLK-EXT-006",
        ],
        "single-node store document",
    )


def validate_workflow(root: Path) -> None:
    relative = ".github/workflows/plan-v1.4-durable-single-node.yml"
    workflow_text = read_text(root, relative)
    workflow = load_yaml(root, relative)
    require(workflow.get("permissions") == {"contents": "read"}, "V1.4 workflow permissions drifted")
    jobs = workflow.get("jobs")
    require(isinstance(jobs, dict), "V1.4 workflow jobs are missing")
    job = jobs.get("durable-single-node")
    require(isinstance(job, dict), "canonical V1.4 job is missing")
    require(job.get("runs-on") == "ubuntu-24.04", "V1.4 runner profile drifted")
    steps = job.get("steps")
    require(isinstance(steps, list) and steps, "V1.4 workflow has no executable steps")

    checkout_steps = [step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@")]
    require(len(checkout_steps) == 1, "V1.4 workflow must have exactly one checkout step")
    checkout = checkout_steps[0]
    require(
        re.fullmatch(r"actions/checkout@[0-9a-f]{40}", checkout["uses"]) is not None,
        "checkout action is not commit pinned",
    )
    checkout_with = checkout.get("with", {})
    require(checkout_with.get("persist-credentials") is False, "checkout credentials are persisted")
    require(
        checkout_with.get("ref") == "${{ github.event.pull_request.head.sha || github.sha }}",
        "V1.4 workflow does not check out the exact source head",
    )

    commands = "\n".join(str(step.get("run", "")) for step in steps)
    for command in (
        "python scripts/validate_plan_v1_4.py",
        "python scripts/validate_v1_4_inherited_surface.py",
        "python -m unittest discover -s tests/plan -p 'test_plan_v1_4.py' -v",
        "python -m unittest discover -s tests/platform -p 'test_*.py' -v",
        "python -m unittest discover -s tests/oracle -p 'test_*.py' -v",
        "cargo +1.98.0 fmt --all -- --check",
        "cargo +1.98.0 test --locked --workspace --all-targets",
        "cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings",
    ):
        require(command in commands, f"V1.4 workflow does not execute required command: {command}")
    require(
        'baseline="a5b9739e46f4bed54dbb3edd0e32400481b3b12f"' in commands,
        "V1.4 workflow does not pin the historical replay baseline",
    )
    require("git worktree add --detach" in commands, "V1.4 workflow does not replay the frozen baseline")
    require(
        "python -m unittest discover -s tests/plan -p 'test_*.py' -v" in commands,
        "V1.4 workflow does not run the complete historical plan suite in the frozen worktree",
    )
    require("contents: write" not in workflow_text, "V1.4 workflow gained write permission")
    require("git push" not in workflow_text, "V1.4 workflow gained source publication")


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
        print(f"V1.4 validation failed: {error}", file=sys.stderr)
        return 1
    print("V1.4 durable single-node foundation validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
