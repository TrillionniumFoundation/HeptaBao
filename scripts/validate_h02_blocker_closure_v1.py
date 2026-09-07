#!/usr/bin/env python3
"""Validate the active H02 OS, durable-storage and clock closure contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "planning/HEPTABAO_H02_OS_DURABLE_CLOCK_BLOCKER_CLOSURE_V1.yaml"
MANIFEST_PATH = ROOT / "probes/h02/openraft-tokio/Cargo.toml"
LOCK_PATH = ROOT / "probes/h02/openraft-tokio/Cargo.lock"
WORKFLOW_PATH = ROOT / ".github/workflows/h02-openraft-blocker-closure.yml"
LINUX_DURABLE_WORKFLOW = ROOT / ".github/workflows/h02-durable-store-v2.yml"
MACOS_DURABLE_WORKFLOW = ROOT / ".github/workflows/h02-durable-store-macos-v2.yml"
MSRV_WORKFLOW = ROOT / ".github/workflows/h02-openraft-effective-msrv-boundary.yml"
RESULT_SCHEMA_PATH = ROOT / "schemas/heptabao_h02_blocker_closure_result_v1.schema.json"
EVIDENCE_SCHEMA_PATH = ROOT / "schemas/heptabao_h02_blocker_closure_evidence_v1.schema.json"
DURABLE_MAIN = ROOT / "probes/h02/openraft-tokio/src/bin/durable_store_lab.rs"
DURABLE_STORE = ROOT / "probes/h02/openraft-tokio/src/bin/durable_store_lab/store.rs"
DURABLE_CLUSTER = ROOT / "probes/h02/openraft-tokio/src/bin/durable_store_lab/cluster.rs"
OPENRAFT_PROBE_MAIN = ROOT / "probes/h02/openraft-tokio/src/main.rs"

REQUIRED_FILES = [
    PLAN_PATH,
    MANIFEST_PATH,
    LOCK_PATH,
    WORKFLOW_PATH,
    LINUX_DURABLE_WORKFLOW,
    MACOS_DURABLE_WORKFLOW,
    MSRV_WORKFLOW,
    RESULT_SCHEMA_PATH,
    EVIDENCE_SCHEMA_PATH,
    ROOT / "scripts/h02_blocker_closure_evidence_v1.py",
    ROOT / "tests/platform/test_h02_blocker_closure_evidence_v1.py",
    ROOT / "probes/h02/openraft-tokio/src/bin/blocker_closure_lab.rs",
    ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/durable.rs",
    ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/os_clock.rs",
    ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/os_clock_cluster.rs",
    DURABLE_MAIN,
    DURABLE_STORE,
    DURABLE_CLUSTER,
    OPENRAFT_PROBE_MAIN,
]


class ValidationFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationFailure(message)


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)}: expected mapping")
    return value


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)}: expected object")
    return value


def require_tokens(path: Path, tokens: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for token in tokens:
        if token not in text:
            fail(f"{path.relative_to(ROOT)} missing marker: {token}")


def validate_plan() -> None:
    plan = load_yaml(PLAN_PATH)
    if plan.get("schema") != "heptabao.h02-os-durable-clock-blocker-closure.v1":
        fail("unexpected blocker-closure plan schema")
    if plan.get("plan_id") != "HEPTABAO-PLAN-2026-08-28" or str(plan.get("revision")) != "1.2":
        fail("plan identity drift")
    if plan.get("status") != "IMPLEMENTED_PENDING_EXACT_HEAD_REMOTE_EXECUTION":
        fail("plan status must distinguish implemented code from exact-head execution")
    if plan.get("qualification") is not False or plan.get("selection_effect") != "NONE" or plan.get("authority_effect") != "NONE":
        fail("plan grants qualification, selection or authority")

    binding = plan.get("candidate_binding", {})
    if binding.get("version") != "0.10.0-alpha.33" or binding.get("effective_rust_floor") != "1.88.0":
        fail("candidate or effective Rust floor drift")
    if binding.get("state") != "IDENTIFIED_NOT_SELECTED":
        fail("candidate state must remain identified and unselected")

    matrix = plan.get("execution_matrix", {})
    if matrix.get("bounded_msrv_failures") != ["1.85.0", "1.86.0", "1.87.0"]:
        fail("bounded MSRV failure set drift")
    if matrix.get("effective_toolchains") != ["1.88.0", "1.98.0"]:
        fail("effective toolchain matrix drift")
    if len(matrix.get("seeds", [])) != 3 or matrix.get("effective_entries_per_environment") != 6:
        fail("effective seed matrix must contain six entries per environment")
    if matrix.get("scheduling") != "SERIAL_PER_RUNNER":
        fail("blocker closure matrix must be serialized per runner")
    if matrix.get("exact_head_passes") != 0:
        fail("source plan cannot claim exact-head passes")

    integrated = plan.get("durable_storage", {}).get("integrated_openraft_store", {})
    if integrated.get("openraft_storage_integrated") is not True:
        fail("integrated OpenRaft storage implementation is not represented")
    required_traits = {"RaftLogReader", "RaftLogStorage", "RaftSnapshotBuilder", "RaftStateMachine"}
    if set(integrated.get("implements", [])) != required_traits:
        fail("integrated storage trait set drift")
    limits = integrated.get("scope_limit", {})
    if limits.get("production_selected") is not False or limits.get("kernel_power_cut") is not False:
        fail("durable implementation overclaims production selection or kernel power-cut evidence")

    technical = plan.get("remaining_technical_gaps")
    external = plan.get("remaining_external_gaps")
    if not isinstance(technical, list) or len(technical) < 5:
        fail("remaining technical gaps are not explicit")
    if not isinstance(external, list) or len(external) < 4:
        fail("remaining external gaps are not explicit")


def validate_manifest_and_lock() -> None:
    require_tokens(
        MANIFEST_PATH,
        [
            'rust-version = "1.88"',
            'name = "heptabao-h02-openraft-blocker-closure-lab"',
            'name = "heptabao-h02-openraft-durable-store-lab"',
            'openraft = { version = "=0.10.0-alpha.33"',
            'openraft-memstore = { version = "=0.10.0-alpha.33"',
            'openraft-rt = "=0.10.0-alpha.33"',
            'openraft-rt-tokio = "=0.10.0-alpha.33"',
            'openraft-macros = "=0.10.0-alpha.33"',
            '[patch.crates-io]',
            'git = "https://github.com/drmingdrmer/validit.git"',
            'rev = "7016fa5e072a86092928144b3a3040381e6964e9"',
        ],
    )
    manifest = MANIFEST_PATH.read_text(encoding="utf-8")
    for mutable_selector in ("branch =", "tag ="):
        if mutable_selector in manifest:
            fail(f"mutable source selector forbidden: {mutable_selector}")
    if not LOCK_PATH.read_text(encoding="utf-8").startswith("# This file is automatically @generated by Cargo."):
        fail("committed Cargo.lock is missing or malformed")


def validate_integrated_store() -> None:
    require_tokens(
        DURABLE_STORE,
        [
            "RaftLogStorage",
            "RaftStateMachine",
            "RaftSnapshotBuilder",
            "sync_all",
            "IOFlushed",
            "INITIALIZATION_MARKER_FILE",
            "pub fn create(",
            "pub fn open_existing(",
            "pub fn adopt_legacy(",
            "discard_stale_previous_after_validation",
            "fresh_create_and_existing_reopen_are_explicit",
            "missing_initialized_log_generation_fails_closed",
            "missing_initialized_state_generation_fails_closed",
            "deleted_store_directory_is_not_silently_recreated_on_reopen",
            "legacy_generation_requires_explicit_validated_adoption",
            "state_legacy_generation_requires_explicit_validated_adoption",
            "valid_current_generation_discards_one_stale_previous",
            "corrupt_current_generation_never_falls_back_to_previous",
            "multiple_previous_generations_are_ambiguous_and_fail_closed",
            "corrupt_initialization_marker_fails_closed",
            "marker_domain_or_authoritative_file_drift_is_rejected",
            "interrupted_marker_previous_file_is_recovered",
            "non_regular_authoritative_generation_is_rejected",
            "symlinked_storage_root_is_rejected",
            "symlinked_initialization_marker_is_rejected",
            "symlinked_authoritative_generation_is_rejected",
            "symlink_metadata",
        ],
    )
    require_tokens(
        DURABLE_CLUSTER,
        [
            "enum StoreLifecycle",
            "StoreLifecycle::CreateNew",
            "StoreLifecycle::ReopenExisting",
            "DurableLogStore::create",
            "DurableStateMachine::create",
            "DurableLogStore::open_existing",
            "DurableStateMachine::open_existing",
        ],
    )
    require_tokens(
        OPENRAFT_PROBE_MAIN,
        [
            "{CANDIDATE_ID}",
            "{VERSION}",
            "{PROFILE_ID}",
            "{case_id}",
            "{status}",
            "{assertions}",
            "{detail}",
        ],
    )
    probe_main = OPENRAFT_PROBE_MAIN.read_text(encoding="utf-8")
    if '"candidate_id":"{}"' in probe_main or 'case_id\":\"{}' in probe_main:
        fail("obsolete positional JSON format arguments remain in the OpenRaft probe")

    require_tokens(
        DURABLE_MAIN,
        [
            '"raft_log_storage_implemented"',
            '"raft_state_machine_implemented"',
            '"full_cluster_disk_restart"',
            '"kernel_power_loss"',
            '"production_selected"',
            "DurableStateMachine::open_existing",
            "DurableLogStore::open_existing",
        ],
    )


def validate_workflows() -> None:
    workflow = load_yaml(WORKFLOW_PATH)
    jobs = workflow.get("jobs", {})
    if set(jobs) != {"validate-plan", "closure-sequential", "authority-sentinel"}:
        fail(f"unexpected blocker workflow jobs: {sorted(jobs)}")
    sequential = jobs["closure-sequential"]
    if "strategy" in sequential:
        fail("closure workflow must not fan out a runner-starving matrix")
    env = sequential.get("env", {})
    if env.get("TOOLCHAINS") != "1.88.0 1.98.0":
        fail("blocker workflow effective toolchain list drift")
    if len(str(env.get("SEEDS", "")).split()) != 3:
        fail("blocker workflow seed list drift")

    require_tokens(
        WORKFLOW_PATH,
        [
            "heptabao-h02-openraft-blocker-closure-lab",
            "h02_blocker_closure_evidence_v1.py",
            "qualification=false",
            "authority=NONE",
        ],
    )
    require_tokens(
        LINUX_DURABLE_WORKFLOW,
        [
            'BOUNDARY_TOOLCHAINS: "1.85.0 1.86.0 1.87.0"',
            'EFFECTIVE_TOOLCHAINS: "1.88.0 1.98.0"',
            "--ignore-rust-version",
            "let expressions in this position are unstable",
            "cargo clippy --locked --all-targets",
        ],
    )
    require_tokens(
        MACOS_DURABLE_WORKFLOW,
        [
            'TOOLCHAINS: "1.88.0 1.98.0"',
            'runs-on: macos-15',
            "RUNNER_ARCH",
            '"independent_attestation": False',
        ],
    )
    require_tokens(
        MSRV_WORKFLOW,
        [
            'BOUNDARY_TOOLCHAINS: "1.85.0 1.86.0 1.87.0"',
            'EFFECTIVE_TOOLCHAINS: "1.88.0 1.98.0"',
            '"effective_msrv": "1.88.0"',
        ],
    )


def validate_schemas() -> None:
    result_schema = load_json(RESULT_SCHEMA_PATH)
    evidence_schema = load_json(EVIDENCE_SCHEMA_PATH)
    Draft202012Validator.check_schema(result_schema)
    Draft202012Validator.check_schema(evidence_schema)
    if result_schema.get("properties", {}).get("qualification", {}).get("const") is not False:
        fail("raw result schema does not force qualification=false")
    if evidence_schema.get("properties", {}).get("authority_effect", {}).get("const") != "NONE":
        fail("evidence schema does not force authority_effect=NONE")


def main() -> int:
    try:
        missing = [str(path.relative_to(ROOT)) for path in REQUIRED_FILES if not path.is_file()]
        if missing:
            fail(f"missing blocker closure files: {missing}")
        validate_plan()
        validate_manifest_and_lock()
        validate_integrated_store()
        validate_workflows()
        validate_schemas()
    except (ValidationFailure, OSError, ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"H02 blocker closure validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "H02 blocker closure validation passed: implementation bound; "
        "effective Rust floor=1.88; exact-head passes=0; qualification=false; authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
