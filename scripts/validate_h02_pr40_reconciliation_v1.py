#!/usr/bin/env python3
"""Fail-closed validation for the PR40 reconciliation package."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
STATUS = ROOT / "planning/HEPTABAO_PR40_RECONCILIATION_STATUS_V1.yaml"
STATUS_SCHEMA = ROOT / "schemas/heptabao_pr40_reconciliation_status_v1.schema.json"
DOC = ROOT / "docs/plan/HEPTABAO_PLAN_V1_2_1_PR40_RECONCILIATION_AND_TECHNICAL_CLOSURE.md"
BLOCKERS = ROOT / "planning/HEPTABAO_BLOCKER_REGISTER_V1.yaml"
MANIFEST = ROOT / "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml"
AUTHORITY = ROOT / "planning/AUTHORITY_FLAGS_V2.yaml"
STORE = ROOT / "probes/h02/openraft-tokio/src/bin/durable_store_lab/store.rs"
PROBE_MAIN = ROOT / "probes/h02/openraft-tokio/src/main.rs"
FAULT_MAIN = ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab.rs"
FAULT_CLUSTER = ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/cluster.rs"
FAULT_DURABLE = ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/durable.rs"
FAULT_GUARD = ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/hostile_snapshot_guard.rs"
MATRIX_RUNNER = ROOT / "scripts/h02_exact_head_matrix_v1.py"
MATRIX_SCHEMA = ROOT / "schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json"
FALLBACK_WORKFLOW = ROOT / ".github/workflows/h02-final-gap-closure-arm64.yml"


class Failure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: expected mapping")
    return value


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: expected object")
    return value


def require_tokens(path: Path, tokens: tuple[str, ...]) -> None:
    text = path.read_text(encoding="utf-8")
    try:
        display = path.relative_to(ROOT)
    except ValueError:
        display = path
    for token in tokens:
        require(token in text, f"{display} missing token: {token}")


def validate_status() -> None:
    schema = load_json(STATUS_SCHEMA)
    Draft202012Validator.check_schema(schema)
    status = load_yaml(STATUS)
    errors = sorted(Draft202012Validator(schema).iter_errors(status), key=lambda item: list(item.path))
    require(not errors, f"status schema errors: {[error.message for error in errors]}")
    require(status["qualification"] is False, "status attempted qualification")
    require(status["compatibility_claim"] is False, "status attempted compatibility")
    require(status["selected_candidates"] == [], "status selected a candidate")
    require(status["selection_effect"] == "NONE", "status attempted selection")
    require(status["authority_effect"] == "NONE", "status attempted authority")


def validate_durable_guard() -> None:
    require_tokens(
        STORE,
        (
            "INITIALIZATION_MAGIC",
            "INITIALIZATION_MARKER_FILE",
            "PersistentInitializationMarker",
            "recover_interrupted_replace",
            "missing_initialized_log_generation_fails_closed",
            "missing_initialized_state_generation_fails_closed",
            "legacy_generation_requires_explicit_validated_adoption",
            "corrupt_initialization_marker_fails_closed",
            "marker_domain_or_authoritative_file_drift_is_rejected",
            "interrupted_marker_previous_file_is_recovered",
            "non_regular_authoritative_generation_is_rejected",
            "symlinked_storage_root_is_rejected",
            "symlinked_initialization_marker_is_rejected",
            "symlinked_authoritative_generation_is_rejected",
            "symlink_metadata",
        ),
    )
    source = STORE.read_text(encoding="utf-8")
    require("PersistentLogState::default()" in source, "fresh-store path is missing")
    require("initialized raft log store is missing its authoritative generation" in source, "missing log generation is not fail-closed")
    require("initialized state machine is missing its authoritative generation" in source, "missing state generation is not fail-closed")


def validate_strict_lint_and_guard_binding() -> None:
    probe = PROBE_MAIN.read_text(encoding="utf-8")
    for token in ("{CANDIDATE_ID}", "{VERSION}", "{PROFILE_ID}", "{case_id}", "{status}", "{assertions}", "{detail}"):
        require(token in probe, f"OpenRaft probe missing inline format capture: {token}")
    require("CANDIDATE_ID, VERSION, PROFILE_ID, seed" not in probe, "obsolete positional meta arguments remain")
    require("case_id, status, assertions, detail" not in probe, "obsolete positional case arguments remain")

    cluster = FAULT_CLUSTER.read_text(encoding="utf-8")
    require("pub async fn execute_hostile_snapshot_child(" not in cluster, "obsolete unguarded helper remains")
    durable = FAULT_DURABLE.read_text(encoding="utf-8")
    require("let outcome = async {" in durable, "durable fault path does not use a direct async block")
    require("let outcome = (|| async {" not in durable, "immediately invoked async closure remains")

    require(FAULT_GUARD.is_file(), "guarded stale-snapshot implementation is missing")
    require_tokens(
        FAULT_GUARD,
        ("execute_hostile_snapshot_child_guarded", "guarded_state_unchanged", "metrics_unchanged", "state_machine_unchanged"),
    )
    require_tokens(
        FAULT_MAIN,
        ('include!("openraft_fault_lab/hostile_snapshot_guard.rs")', "fn exit_code_for_status", 'Some("EXECUTED_FAIL") => 1'),
    )


def validate_matrix_inheritance() -> None:
    require_tokens(
        MATRIX_RUNNER,
        (
            "terminates timed-out process groups",
            'git_text("rev-parse", "HEAD^{tree}")',
            "output directory must be outside the repository",
            "os.killpg(process.pid, signal.SIGKILL)",
            "start_new_session=(os.name == \"posix\")",
            '"duplicate_entry_ids"',
            '"runner_errors"',
            "current_source_errors",
        ),
    )
    schema = load_json(MATRIX_SCHEMA)
    Draft202012Validator.check_schema(schema)
    properties = schema.get("properties", {})
    require(properties.get("qualification", {}).get("const") is False, "matrix schema qualification drift")
    require(properties.get("authority_effect", {}).get("const") == "NONE", "matrix schema authority drift")


def validate_blocker_links() -> None:
    register = load_yaml(BLOCKERS)
    blockers = {item.get("id"): item for item in register.get("blockers", []) if isinstance(item, dict)}
    for blocker_id in ("HB-BLK-REPO-007", "HB-BLK-REPO-008", "HB-BLK-REPO-010", "HB-BLK-REPO-011"):
        require(blocker_id in blockers, f"missing blocker {blocker_id}")
        require(blockers[blocker_id].get("state") != "CLOSED", f"{blocker_id} was self-closed")

    b7 = " ".join(str(item) for item in blockers["HB-BLK-REPO-007"].get("closure_criteria", []))
    for token in ("initialized-store", "missing initialized", "legacy", "non-regular", "external rollback anchor"):
        require(token.lower() in b7.lower(), f"HB-BLK-REPO-007 lacks criterion: {token}")

    b8_evidence = set(blockers["HB-BLK-REPO-008"].get("evidence", []))
    require("tests/platform/test_h02_openraft_fault_lab_source_binding_v1.py" in b8_evidence, "HB-BLK-REPO-008 lacks source-binding test")

    b10 = " ".join(str(item) for item in blockers["HB-BLK-REPO-010"].get("closure_criteria", []))
    for token in ("inline capture", "direct async", "obsolete unguarded", "Clippy -D warnings"):
        require(token.lower() in b10.lower(), f"HB-BLK-REPO-010 lacks criterion: {token}")


def validate_manifest_and_doc() -> None:
    manifest = load_yaml(MANIFEST)
    paths = {item.get("path") for item in manifest.get("documents", []) if isinstance(item, dict)}
    for path in (
        "docs/plan/HEPTABAO_PLAN_V1_2_1_PR40_RECONCILIATION_AND_TECHNICAL_CLOSURE.md",
        "planning/HEPTABAO_PR40_RECONCILIATION_STATUS_V1.yaml",
        "schemas/heptabao_pr40_reconciliation_status_v1.schema.json",
    ):
        require(path in paths, f"normative manifest does not index {path}")
    require_tokens(
        DOC,
        (
            "cedb6c95a5323f7004551087d75e2f57a1ec484a",
            "initialized-generation guard",
            "24 toolchain/seed/probe entries",
            "EXTERNAL_ACTION_REQUIRED",
            "qualification=false",
            "authority_effect=NONE",
        ),
    )


def validate_workflow_boundary() -> None:
    require_tokens(
        FALLBACK_WORKFLOW,
        (
            "permissions:\n  contents: read",
            "persist-credentials: false",
            "python3 scripts/validate_h02_pr40_reconciliation_v1.py",
            "Execute all 24 application entries without early abort",
            "Upload complete diagnostics before final gate",
            "Require complete schema-valid exact-head PASS",
        ),
    )
    forbidden = (
        re.compile(r"(?mi)^\s*contents\s*:\s*write\s*$"),
        re.compile(r"(?mi)^\s*persist-credentials\s*:\s*true\s*$"),
        re.compile(r"(?mi)^\s*git\s+(?:commit|push|rebase)\b"),
    )
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            require(not pattern.search(text), f"write-capable CI mutation found in {path.name}")


def validate_authority() -> None:
    authority = load_yaml(AUTHORITY)
    flags = authority.get("flags", {})
    require(isinstance(flags, dict), "authority flags missing")
    for key, value in flags.items():
        if key != "implementation_started":
            require(value is False, f"authority flag enabled: {key}")
    require(authority.get("active_grants") == [], "active authority grant exists")


def validate() -> None:
    required = (
        STATUS, STATUS_SCHEMA, DOC, BLOCKERS, MANIFEST, AUTHORITY, STORE, PROBE_MAIN,
        FAULT_MAIN, FAULT_CLUSTER, FAULT_DURABLE, FAULT_GUARD, MATRIX_RUNNER,
        MATRIX_SCHEMA, FALLBACK_WORKFLOW,
    )
    for path in required:
        require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")
    validate_status()
    validate_durable_guard()
    validate_strict_lint_and_guard_binding()
    validate_matrix_inheritance()
    validate_blocker_links()
    validate_manifest_and_doc()
    validate_workflow_boundary()
    validate_authority()


def main() -> int:
    try:
        validate()
    except (Failure, OSError, ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"PR40 reconciliation validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "PR40 reconciliation validation passed: initialized-generation fail-closed=true; "
        "strict-lint/source-binding=true; 24-entry runner inherited=true; "
        "qualification=false selection=NONE authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
