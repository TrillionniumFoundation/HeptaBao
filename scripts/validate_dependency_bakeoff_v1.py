#!/usr/bin/env python3
"""Fail-closed validation for the H02 dependency bakeoff seed."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "planning" / "HEPTABAO_H02_DEPENDENCY_BAKEOFF_V1.yaml"
CORRECTION_PATH = ROOT / "planning" / "HEPTABAO_H02_BAKEOFF_COVERAGE_CORRECTION_V1.yaml"
STATUS_PATH = ROOT / "qualifications" / "H02" / "H02-IMPLEMENTATION-STATUS.json"
CANDIDATE_SCHEMA_PATH = ROOT / "schemas" / "heptabao_dependency_candidate_v1.schema.json"
SELECTION_SCHEMA_PATH = ROOT / "schemas" / "heptabao_dependency_selection_receipt_v1.schema.json"

EXPECTED_CAPABILITIES = {
    "ASYNC_RUNTIME",
    "HTTP_SERVER",
    "HTTP_CLIENT",
    "TLS",
    "CRYPTO_PROVIDER",
    "SECURE_MEMORY",
    "SERIALIZATION",
    "HCL_PARSING",
    "POSTGRES",
    "RAFT",
    "GRPC",
    "TEMPLATE_CEL",
    "TELEMETRY",
    "CLI",
    "LINUX_SANDBOX",
    "FUZZ_MODEL_TOOLING",
}


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


def validate() -> tuple[int, int]:
    catalog = load_yaml(CATALOG_PATH)
    correction = load_yaml(CORRECTION_PATH)
    status = load_json(STATUS_PATH)
    candidate_schema = load_json(CANDIDATE_SCHEMA_PATH)
    selection_schema = load_json(SELECTION_SCHEMA_PATH)
    candidate_validator = Draft202012Validator(candidate_schema, format_checker=FormatChecker())
    Draft202012Validator.check_schema(selection_schema)

    if catalog.get("schema") != "heptabao.dependency-bakeoff.v1":
        fail("unexpected dependency catalog schema")
    if catalog.get("status") != "CANDIDATE_IDENTIFICATION_ACTIVE_NO_SELECTION":
        fail("dependency catalog must remain candidate-identification only")
    if catalog.get("prototype_selection_receipts") != []:
        fail("prototype selection receipts must be empty")
    if catalog.get("production_selection_authority") is not False:
        fail("production dependency authority must remain false")
    if catalog.get("authority_effect") != "NONE":
        fail("dependency catalog authority_effect must be NONE")

    candidates = catalog.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        fail("candidate list is empty")

    ids: set[str] = set()
    capabilities: set[str] = set()
    state_counts: dict[str, int] = {}
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            fail(f"candidate[{index}] is not an object")
        errors = sorted(candidate_validator.iter_errors(candidate), key=lambda error: list(error.path))
        if errors:
            rendered = "; ".join(error.message for error in errors[:5])
            fail(f"candidate[{index}] schema failure: {rendered}")
        candidate_id = candidate["candidate_id"]
        if candidate_id in ids:
            fail(f"duplicate candidate ID: {candidate_id}")
        ids.add(candidate_id)
        capabilities.add(candidate["capability"])
        state = candidate["state"]
        state_counts[state] = state_counts.get(state, 0) + 1

        if state != "IDENTIFIED":
            fail(f"{candidate_id}: seed candidates must remain IDENTIFIED")
        if candidate["project"]["license_status"] != "PENDING":
            fail(f"{candidate_id}: license cannot be pre-approved without evidence")
        if any(value is not None for value in candidate["pin"].values()):
            fail(f"{candidate_id}: release/commit/source pin was asserted without evidence")
        if any(value is not None for value in candidate["criteria"].values()):
            fail(f"{candidate_id}: score was asserted before evidence collection")

        evidence = candidate["evidence"]
        boolean_fields = [
            "source_and_release_pinned",
            "license_reviewed",
            "maintenance_reviewed",
            "security_advisories_reviewed",
            "unsafe_inventory_reviewed",
            "minimum_rust_version_verified",
            "api_and_replacement_seam_reviewed",
            "deterministic_tests_available",
            "benchmark_profile_available",
            "qualification_plan_available",
        ]
        enabled = [field for field in boolean_fields if evidence[field] is True]
        if enabled:
            fail(f"{candidate_id}: unproven evidence flags enabled: {enabled}")
        if evidence["evidence_refs"] != []:
            fail(f"{candidate_id}: evidence_refs must be empty at seed stage")
        if any(evidence[field] != 0 for field in ("critical_findings_open", "high_findings_open", "unclassified_findings")):
            fail(f"{candidate_id}: findings cannot be classified before review")
        if candidate["qualification"]["selection_receipt"] is not None:
            fail(f"{candidate_id}: selection receipt must be null")
        if candidate["authority_effect"] != "NONE":
            fail(f"{candidate_id}: authority_effect must be NONE")

    if capabilities != EXPECTED_CAPABILITIES:
        fail(
            "capability coverage mismatch: "
            f"missing={sorted(EXPECTED_CAPABILITIES - capabilities)} "
            f"unknown={sorted(capabilities - EXPECTED_CAPABILITIES)}"
        )

    canonical = correction.get("canonical_coverage")
    if correction.get("status") != "CANONICAL_COVERAGE_CORRECTION" or not isinstance(canonical, dict):
        fail("coverage correction is absent or not canonical")
    if canonical.get("candidate_count") != len(candidates):
        fail("canonical candidate count does not match candidate array")
    if canonical.get("capability_count") != len(capabilities):
        fail("canonical capability count does not match candidate array")
    if canonical.get("identified") != state_counts.get("IDENTIFIED", 0):
        fail("canonical identified count mismatch")
    for field in ("selected_for_prototype", "evidence_collecting", "rejected"):
        if canonical.get(field) != 0:
            fail(f"canonical {field} must remain zero")

    status_counts = status.get("candidate_counts", {})
    if status_counts.get("identified") != len(candidates):
        fail("H02 status identified count mismatch")
    if any(status_counts.get(field) != 0 for field in ("evidence_collecting", "eligible_for_bakeoff", "rejected", "selected_for_prototype")):
        fail("H02 status asserts a non-seed candidate state")
    if status.get("selection_receipts") != []:
        fail("H02 status selection receipts must be empty")
    if status.get("qualification", {}).get("status") != "NOT_QUALIFIED":
        fail("H02 must remain NOT_QUALIFIED")
    enabled_authority = [name for name, value in status.get("authority_flags", {}).items() if value]
    if enabled_authority:
        fail(f"unexpected H02 authority flags: {enabled_authority}")
    if status.get("authority_effect") != "NONE":
        fail("H02 status authority_effect must be NONE")

    negative = copy.deepcopy(candidates[0])
    negative["state"] = "SELECTED_FOR_PROTOTYPE"
    if not list(candidate_validator.iter_errors(negative)):
        fail("candidate schema accepted a selected candidate without pins/reviews/tests/receipt")

    return len(candidates), len(capabilities)


def main() -> int:
    try:
        candidate_count, capability_count = validate()
    except (ValidationFailure, OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"H02 dependency bakeoff validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "H02 dependency bakeoff validation passed: "
        f"candidates={candidate_count} capabilities={capability_count} selected=0 authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
