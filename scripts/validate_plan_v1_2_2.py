#!/usr/bin/env python3
"""Fail-closed validator for the V1.2.2 unified repository closure package."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
STATUS = ROOT / "planning/HEPTABAO_V1_2_2_UNIFIED_CLOSURE_STATUS_V1.yaml"
SCHEMA = ROOT / "schemas/heptabao_v1_2_2_unified_closure_status_v1.schema.json"
DOC = ROOT / "docs/plan/HEPTABAO_PLAN_V1_2_2_UNIFIED_REPOSITORY_CLOSURE.md"
MANIFEST = ROOT / "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml"
AUTHORITY = ROOT / "planning/AUTHORITY_FLAGS_V2.yaml"
STORE = ROOT / "probes/h02/openraft-tokio/src/bin/durable_store_lab/store.rs"
CLUSTER = ROOT / "probes/h02/openraft-tokio/src/bin/durable_store_lab/cluster.rs"
DURABLE_MAIN = ROOT / "probes/h02/openraft-tokio/src/bin/durable_store_lab.rs"
MATRIX = ROOT / "scripts/h02_exact_head_matrix_v1.py"
WORKFLOWS = ROOT / ".github/workflows"

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
    schema = load_json(SCHEMA)
    Draft202012Validator.check_schema(schema)
    value = load_yaml(STATUS)
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda item: list(item.path))
    require(not errors, f"status schema errors: {[error.message for error in errors]}")

def validate_composition() -> None:
    require_tokens(STORE, (
        "pub fn create(", "pub fn open_existing(", "pub fn adopt_legacy(",
        "discard_stale_previous_after_validation",
        "fresh_create_and_existing_reopen_are_explicit",
        "missing_initialized_log_generation_fails_closed",
        "missing_initialized_state_generation_fails_closed",
        "deleted_store_directory_is_not_silently_recreated_on_reopen",
        "legacy_generation_requires_explicit_validated_adoption",
        "valid_current_generation_discards_one_stale_previous",
        "corrupt_current_generation_never_falls_back_to_previous",
        "multiple_previous_generations_are_ambiguous_and_fail_closed",
        "symlinked_storage_root_is_rejected",
        "symlinked_initialization_marker_is_rejected",
        "symlinked_authoritative_generation_is_rejected",
    ))
    require_tokens(CLUSTER, (
        "StoreLifecycle::CreateNew", "StoreLifecycle::ReopenExisting",
        "DurableLogStore::create", "DurableStateMachine::create",
        "DurableLogStore::open_existing", "DurableStateMachine::open_existing",
    ))
    require_tokens(DURABLE_MAIN, ("DurableLogStore::open_existing", "DurableStateMachine::open_existing"))
    require_tokens(MATRIX, (
        "process_started", "application_status", "command_digest",
        "killpg", "HEAD tree changed during matrix execution",
    ))

def validate_manifest() -> None:
    manifest = load_yaml(MANIFEST)
    paths = {item.get("path") for item in manifest.get("documents", []) if isinstance(item, dict)}
    for path in (
        "docs/plan/HEPTABAO_PLAN_V1_2_2_UNIFIED_REPOSITORY_CLOSURE.md",
        "planning/HEPTABAO_V1_2_2_UNIFIED_CLOSURE_STATUS_V1.yaml",
        "schemas/heptabao_v1_2_2_unified_closure_status_v1.schema.json",
    ):
        require(path in paths, f"normative manifest does not index {path}")

def validate_workflows() -> None:
    forbidden = (
        re.compile(r"(?mi)^\s*contents\s*:\s*write\s*$"),
        re.compile(r"(?mi)^\s*persist-credentials\s*:\s*true\s*$"),
        re.compile(r"(?mi)^\s*git\s+(?:commit|push|rebase)\b"),
    )
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            require(not pattern.search(text), f"write-capable CI mutation found in {path.name}")

def validate_authority() -> None:
    value = load_yaml(AUTHORITY)
    flags = value.get("flags", {})
    require(isinstance(flags, dict), "authority flags missing")
    for key, enabled in flags.items():
        if key != "implementation_started":
            require(enabled is False, f"authority flag enabled: {key}")
    require(value.get("active_grants") == [], "active authority grant exists")

def validate() -> None:
    for path in (STATUS, SCHEMA, DOC, MANIFEST, AUTHORITY, STORE, CLUSTER, DURABLE_MAIN, MATRIX):
        require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")
    validate_status()
    validate_composition()
    validate_manifest()
    validate_workflows()
    validate_authority()

def main() -> int:
    try:
        validate()
    except (Failure, OSError, ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"V1.2.2 unified closure validation FAILED: {error}", file=sys.stderr)
        return 1
    print("V1.2.2 unified closure validation passed: local implementation composed; remote execution=UNEXECUTED; qualification=false selection=NONE authority=NONE")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
