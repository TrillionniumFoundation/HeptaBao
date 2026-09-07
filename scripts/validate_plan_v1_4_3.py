#!/usr/bin/env python3
"""Fail-closed validator for HeptaBao V1.4.3 descriptor fencing."""

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
    "crates/heptabao-filesystem-guard",
    "crates/heptabao-single-node-journal",
    "crates/heptabao-single-node-store",
}

EXPECTED_WORKSPACE_MEMBERS = {
    "crates/heptabao-authbus-contracts",
    "crates/heptabao-barrier-api",
    "crates/heptabao-durable-core",
    "crates/heptabao-filesystem-guard",
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
    "docs/plan/HEPTABAO_PLAN_V1_4_3_DESCRIPTOR_ANCHOR_AND_WRITER_FENCING.md": "PLAN",
    "docs/storage/HEPTABAO_DESCRIPTOR_ANCHOR_AND_WRITER_FENCE_V1.md": "FILESYSTEM_CONTRACT",
    "planning/HEPTABAO_V1_4_3_DESCRIPTOR_FENCING_STATUS.yaml": "STATUS",
    "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_3.yaml": "BLOCKER_REGISTER",
    "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_3.yaml": "MANIFEST",
    "schemas/heptabao_normative_document_manifest_v1_4_3.schema.json": "SCHEMA",
    "crates/heptabao-filesystem-guard/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-filesystem-guard/src/lib.rs": "RUST_CRATE",
    "crates/heptabao-single-node-store/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-single-node-store/src/lib.rs": "RUST_CRATE",
    "crates/heptabao-single-node-journal/Cargo.toml": "RUST_CRATE",
    "crates/heptabao-single-node-journal/src/lib.rs": "RUST_CRATE",
    "scripts/validate_plan_v1_4_3.py": "VALIDATOR",
    "scripts/validate_v1_4_3_inherited_surface.py": "VALIDATOR",
    "tests/plan/test_plan_v1_4_3.py": "TEST",
    ".github/workflows/plan-v1.4.3-descriptor-fencing.yml": "WORKFLOW",
}

EXPECTED_BLOCKERS = {
    "HB-BLK-REPO-033",
    "HB-BLK-REPO-034",
    "HB-BLK-REPO-035",
    "HB-BLK-REPO-036",
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

EXPECTED_LOCK_DEPENDENCIES = {
    "heptabao-filesystem-guard": set(),
    "heptabao-single-node-journal": {
        "heptabao-filesystem-guard",
        "heptabao-journal-api",
    },
    "heptabao-single-node-store": {
        "heptabao-filesystem-guard",
        "heptabao-storage-api",
    },
}


class ValidationFailure(RuntimeError):
    """Raised when one closed-world V1.4.3 invariant is not satisfied."""


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
    manifest_path = "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_3.yaml"
    schema_path = "schemas/heptabao_normative_document_manifest_v1_4_3.schema.json"
    manifest = load_yaml(root, manifest_path)
    schema = load_json(root, schema_path)
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        raise ValidationFailure(f"V1.4.3 manifest schema does not meta-validate: {error}") from error
    errors = sorted(
        Draft202012Validator(schema).iter_errors(manifest),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    require(
        not errors,
        "V1.4.3 manifest schema validation failed: "
        + "; ".join(error.message for error in errors),
    )
    indexed: dict[str, str] = {}
    for entry in manifest["documents"]:
        path = entry["path"]
        require(path not in indexed, f"duplicate V1.4.3 manifest path: {path}")
        indexed[path] = entry["role"]
        require((root / path).is_file(), f"manifested V1.4.3 path is missing: {path}")
    require(indexed == EXPECTED_DOCUMENTS, "V1.4.3 manifest path/role set drifted")
    validate_claims(manifest["claims"], "manifest")


def validate_status_and_blockers(root: Path) -> None:
    status = load_yaml(root, "planning/HEPTABAO_V1_4_3_DESCRIPTOR_FENCING_STATUS.yaml")
    require(
        status.get("status")
        == "SOURCE_IMPLEMENTED_EXACT_HEAD_EXECUTION_AND_INDEPENDENT_REVIEW_REQUIRED",
        "V1.4.3 status overstates or understates source maturity",
    )
    require(
        status.get("current_plan")
        == "docs/plan/HEPTABAO_PLAN_V1_4_3_DESCRIPTOR_ANCHOR_AND_WRITER_FENCING.md",
        "V1.4.3 current plan pointer drifted",
    )
    require(
        status.get("profile")
        == {
            "id": "HB-P1-DEV-DESCRIPTOR-FENCED-SINGLE-NODE",
            "operating_system": "linux",
            "local_filesystem_required": True,
            "proc_self_fd_required": True,
            "flat_root_namespace": True,
            "descriptor_anchored": True,
            "cooperating_multi_process_writer_fencing": True,
            "network_filesystem_supported": False,
            "production_supported": False,
            "replicated": False,
            "compatibility_supported": False,
        },
        "V1.4.3 bounded profile drifted",
    )
    baseline = status.get("source_baseline")
    require(
        baseline
        == {
            "repository_id": 1349115072,
            "repository": "TrillionniumFoundation/HeptaBao",
            "inherited_head": "34e8dc0caceb84288d4ef61f79cd7ca062718b63",
            "inherited_tree": "a1a0e7ab4e5ae8d4a2a5a7cde425eaf94a54b1d7",
            "source_identity": "RESOLVE_FROM_EXACT_GIT_HEAD",
        },
        "V1.4.3 exact baseline binding drifted",
    )
    implementation = status.get("implementation")
    require(isinstance(implementation, dict) and implementation, "implementation state is missing")
    require(
        all(value == "IMPLEMENTED_SOURCE" for value in implementation.values()),
        "implementation fields must remain source-only before exact execution",
    )
    execution = status.get("execution_required")
    require(isinstance(execution, dict) and execution, "V1.4.3 execution gates are missing")
    require(
        execution.get("final_project_ratification") == "REQUIRED_DESIGNATED_RATIFIER_HEAD",
        "designated-ratifier boundary drifted",
    )
    require(
        execution.get("independent_filesystem_storage_and_security_review")
        == "REQUIRED_EXTERNAL_IDENTITY",
        "independent-review boundary drifted",
    )
    require(status.get("external_open") == EXPECTED_EXTERNAL, "external blocker set drifted")
    validate_claims(status.get("claims"), "status")

    blockers = load_yaml(root, "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_3.yaml")
    added = blockers.get("added_blockers")
    require(isinstance(added, list), "V1.4.3 blocker list is missing")
    require(
        {entry.get("id") for entry in added} == EXPECTED_BLOCKERS,
        "V1.4.3 repository blocker IDs drifted",
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
        "V1.4.3 did not carry every external/control blocker",
    )
    require(blockers.get("product_gaps_carried_forward"), "product gap inventory is missing")
    validate_claims(
        {key: blockers.get(key) for key in EXPECTED_CLAIMS},
        "blocker register",
    )


def validate_workspace(root: Path) -> None:
    cargo = tomllib.loads(read_text(root, "Cargo.toml"))
    members = cargo.get("workspace", {}).get("members")
    require(isinstance(members, list), "workspace members are missing")
    require(len(members) == len(set(members)), "workspace contains duplicate members")
    require(set(members) == EXPECTED_WORKSPACE_MEMBERS, "V1.4.3 workspace members drifted")
    package = cargo.get("workspace", {}).get("package", {})
    require(package.get("edition") == "2024", "workspace edition drifted")
    require(package.get("rust-version") == "1.98", "workspace Rust floor drifted")
    for crate in EXPECTED_CRATES:
        crate_toml = tomllib.loads(read_text(root, f"{crate}/Cargo.toml"))
        require(crate_toml.get("package", {}).get("publish") is False, f"{crate} became publishable")
        require(crate_toml.get("lints", {}).get("workspace") is True, f"{crate} lost workspace lints")

    store = tomllib.loads(read_text(root, "crates/heptabao-single-node-store/Cargo.toml"))
    journal = tomllib.loads(read_text(root, "crates/heptabao-single-node-journal/Cargo.toml"))
    require(
        store.get("dependencies", {}).get("heptabao-filesystem-guard")
        == {"path": "../heptabao-filesystem-guard"},
        "generation store lost filesystem guard dependency",
    )
    require(
        journal.get("dependencies", {}).get("heptabao-filesystem-guard")
        == {"path": "../heptabao-filesystem-guard"},
        "journal lost filesystem guard dependency",
    )

    lock = tomllib.loads(read_text(root, "Cargo.lock"))
    packages = lock.get("package", [])
    indexed = {entry.get("name"): entry for entry in packages}
    for name, expected_dependencies in EXPECTED_LOCK_DEPENDENCIES.items():
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


def validate_guard_source(root: Path) -> None:
    source = read_text(root, "crates/heptabao-filesystem-guard/src/lib.rs")
    require_rust_tokens(
        source,
        [
            "#![forbid(unsafe_code)]",
            "pub struct DirectoryIdentity",
            "pub struct ExclusiveDirectory",
            "original_path: PathBuf",
            "access_path: PathBuf",
            "handle: File",
            "identity: DirectoryIdentity",
            "if !original_path.is_absolute()",
            "fs::symlink_metadata(&original_path)",
            ".custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)",
            "identity(&opened) != before_identity",
            "identity(&after) != before_identity",
            "format!(\"/proc/self/fd/{}\", handle.as_raw_fd())",
            "match handle.try_lock()",
            "TryLockError::WouldBlock",
            "DirectoryGuardError::WriterBusy",
            "validate_leaf(name)?",
            "self.handle.sync_all()",
            "cooperating_processes_observe_writer_fence",
            "descriptor_survives_root_path_replacement",
        ],
        "filesystem guard source",
    )
    require("unsafe {" not in source, "filesystem guard contains an unsafe block")
    require("Command::new" in source, "writer fence lacks a subprocess contention test")
    require("MAX_GUARDED_LEAF_BYTES: usize = 240" in source, "leaf bound drifted")


def validate_store_source(root: Path) -> None:
    source = read_text(root, "crates/heptabao-single-node-store/src/lib.rs")
    require_rust_tokens(
        source,
        [
            "root: ExclusiveDirectory",
            "ExclusiveDirectory::open(root).map_err(map_directory_guard_error)?",
            "self.root.verify().map_err(map_directory_guard_error)?",
            "self.root.access_path()",
            "pub fn root_identity(&self)",
            "DirectoryGuardError::WriterBusy => FileStoreError::WriterBusy",
            "options.custom_flags(O_NOFOLLOW | O_CLOEXEC)",
            "let file = options.open(path)",
            "let metadata = file.metadata()",
            "options.write(true).create_new(true)",
            "write_new_file_and_sync_parent(&self.root, &bundle_name, &bundle_bytes)",
            "atomic_replace(&self.root, CURRENT_NAME, &current_bytes)",
            "root.sync_all().map_err(io::Error::other)",
            "FileStoreError::CommitOutcomeUnknown",
            "second_store_writer_is_fenced",
            "open_store_remains_bound_after_root_path_replacement",
        ],
        "generation store source",
    )
    compact = re.sub(r"\s+", "", source)
    require(
        compact.count("options.custom_flags(O_NOFOLLOW|O_CLOEXEC)") >= 2,
        "generation store source lost nofollow on a read or create path",
    )
    require("fn validate_root" not in source, "generation store retained path-reopen root validation")
    require("if self.bundle_path(generation).exists()" not in source, "generation creation regained a check-then-create race")


def validate_journal_source(root: Path) -> None:
    source = read_text(root, "crates/heptabao-single-node-journal/src/lib.rs")
    require_rust_tokens(
        source,
        [
            "root: ExclusiveDirectory",
            "ExclusiveDirectory::open(root).map_err(map_directory_guard_error)?",
            "self.root.verify().map_err(map_directory_guard_error)?",
            "self.root.access_path()",
            "pub fn root_identity(&self)",
            "DirectoryGuardError::WriterBusy => FileJournalError::WriterBusy",
            "options.custom_flags(O_NOFOLLOW | O_CLOEXEC)",
            "let file = options.open(path)",
            "let metadata = file.metadata()",
            "options.write(true).create_new(true)",
            "write_new_file_and_sync_parent(&self.root, &entry_name, &encoded)",
            "atomic_replace(&self.root, TAIL_NAME, &encoded)",
            "root.sync_all().map_err(io::Error::other)",
            "FileJournalError::AppendOutcomeUnknown",
            "second_journal_writer_is_fenced",
            "open_journal_remains_bound_after_root_path_replacement",
        ],
        "durable journal source",
    )
    compact = re.sub(r"\s+", "", source)
    require(
        compact.count("options.custom_flags(O_NOFOLLOW|O_CLOEXEC)") >= 2,
        "durable journal source lost nofollow on a read or create path",
    )
    require("fn validate_root" not in source, "journal retained path-reopen root validation")


def validate_documents(root: Path) -> None:
    plan = read_text(
        root,
        "docs/plan/HEPTABAO_PLAN_V1_4_3_DESCRIPTOR_ANCHOR_AND_WRITER_FENCING.md",
    )
    contract = read_text(root, "docs/storage/HEPTABAO_DESCRIPTOR_ANCHOR_AND_WRITER_FENCE_V1.md")
    require_tokens(
        plan,
        [
            "34e8dc0caceb84288d4ef61f79cd7ca062718b63",
            "a1a0e7ab4e5ae8d4a2a5a7cde425eaf94a54b1d7",
            "HB-BLK-REPO-033",
            "HB-BLK-REPO-036",
            "O_DIRECTORY",
            "O_NOFOLLOW",
            "File::try_lock",
            "/proc/self/fd/<fd>",
            "The writer fence is advisory",
            "production_supported              = false",
        ],
        "V1.4.3 plan",
    )
    require_tokens(
        contract,
        [
            "(device, inode, descriptor, descriptor_access_path, exclusive_lock_lifetime)",
            "Contention returns",
            "WriterBusy",
            "Root replacement",
            "No check-then-open or check-then-create result is treated as authority",
            "post-rename directory sync failure: outcome unknown",
            "Explicit non-claims",
        ],
        "descriptor anchor contract",
    )


def validate_workflow(root: Path) -> None:
    relative = ".github/workflows/plan-v1.4.3-descriptor-fencing.yml"
    workflow = load_yaml(root, relative)
    require(isinstance(workflow, dict), "V1.4.3 workflow is not a mapping")
    require(workflow.get("name") == "plan-v1.4.3-descriptor-fencing", "workflow name drifted")
    triggers = workflow.get("on")
    require(isinstance(triggers, dict), "workflow trigger mapping is missing")
    require(set(triggers) == {"pull_request", "workflow_dispatch"}, "workflow trigger set drifted")
    pull_request = triggers.get("pull_request")
    require(
        isinstance(pull_request, dict)
        and pull_request.get("branches") == ["codex/plan-v1.4.2-recovery-foundation-v1"],
        "workflow base branch drifted",
    )
    require(workflow.get("permissions") == {"contents": "read"}, "workflow gained write permission")
    jobs = workflow.get("jobs")
    require(isinstance(jobs, dict) and set(jobs) == {"descriptor-fencing"}, "workflow job set drifted")
    job = jobs["descriptor-fencing"]
    require(job.get("runs-on") == "ubuntu-24.04", "descriptor profile runner drifted")
    require(job.get("permissions") == {"contents": "read"}, "workflow job gained write permission")
    workflow_text = read_text(root, relative)
    require("persist-credentials: false" in workflow_text, "workflow persists checkout credentials")
    for forbidden in [
        "contents: write",
        "git push",
        "update-ref",
        "create commit",
        "curl --request POST",
        "GH_TOKEN",
    ]:
        require(forbidden not in workflow_text, f"workflow contains write-capable token: {forbidden}")
    require_tokens(
        workflow_text,
        [
            "python scripts/validate_plan_v1_4_3.py",
            "python scripts/validate_v1_4_3_inherited_surface.py",
            "test_plan_v1_4_3.py",
            "baseline=\"34e8dc0caceb84288d4ef61f79cd7ca062718b63\"",
            "python scripts/validate_plan_v1_4_2.py",
            "python scripts/validate_v1_4_2_inherited_surface.py",
            "cargo +1.98.0 fmt --all -- --check",
            "cargo +1.98.0 test --locked --workspace --all-targets",
            "cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings",
            "V1.4.3 authority boundary drifted",
        ],
        "V1.4.3 workflow",
    )

    workflow_directory = root / ".github/workflows"
    if workflow_directory.is_dir():
        temporary = sorted(
            path.name
            for path in workflow_directory.iterdir()
            if path.is_file() and path.name.startswith("v1.4.3-")
        )
        require(not temporary, f"temporary write-capable V1.4.3 workflow remains: {temporary}")


def validate(root: Path = ROOT) -> None:
    validate_manifest(root)
    validate_status_and_blockers(root)
    validate_workspace(root)
    validate_guard_source(root)
    validate_store_source(root)
    validate_journal_source(root)
    validate_documents(root)
    validate_workflow(root)


def main() -> int:
    try:
        validate(ROOT)
    except (OSError, ValidationFailure, tomllib.TOMLDecodeError) as error:
        print(f"V1.4.3 validation failed: {error}", file=sys.stderr)
        return 1
    print("V1.4.3 descriptor anchoring and writer fencing validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
