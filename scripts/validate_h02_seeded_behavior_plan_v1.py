#!/usr/bin/env python3
"""Cross-file validation for the H02 seeded behavior harness."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "planning" / "HEPTABAO_H02_SEEDED_BEHAVIOR_HARNESS_V1.yaml"
EVIDENCE_SCHEMA_PATH = ROOT / "schemas" / "heptabao_h02_seeded_behavior_evidence_v1.schema.json"
REPRO_SCHEMA_PATH = ROOT / "schemas" / "heptabao_h02_independent_reproduction_v1.schema.json"
HARNESS_PATH = ROOT / "scripts" / "h02_seeded_behavior_harness_v1.py"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "h02-seeded-behavior-harness.yml"

EXPECTED = {
    "RUNTIME": "HB-H02-BEHAVIOR-RUNTIME-REFERENCE",
    "TLS": "HB-H02-BEHAVIOR-TLS-REFERENCE",
    "RAFT": "HB-H02-BEHAVIOR-RAFT-REFERENCE",
}


class ValidationFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationFailure(message)


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain a mapping")
    return value


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain an object")
    return value


def load_harness():
    spec = importlib.util.spec_from_file_location("h02_seeded_behavior_harness_v1_validation", HARNESS_PATH)
    if spec is None or spec.loader is None:
        fail("unable to import behavior harness")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def validate() -> None:
    for path in (PLAN_PATH, EVIDENCE_SCHEMA_PATH, REPRO_SCHEMA_PATH, HARNESS_PATH, WORKFLOW_PATH):
        if not path.is_file():
            fail(f"missing required file: {path.relative_to(ROOT)}")

    plan = load_yaml(PLAN_PATH)
    if plan.get("schema") != "heptabao.h02-seeded-behavior-harness.v1":
        fail("unexpected plan schema")
    if plan.get("qualification") is not False or plan.get("selection_effect") != "NONE" or plan.get("authority_effect") != "NONE":
        fail("plan attempted to grant qualification, selection or authority")
    profiles = plan.get("profiles")
    if not isinstance(profiles, list) or len(profiles) != 3:
        fail("exactly three reference profiles are required")

    harness = load_harness()
    observed: dict[str, str] = {}
    total_cases = 0
    for profile in profiles:
        domain = profile.get("domain")
        profile_id = profile.get("profile_id")
        if domain not in EXPECTED or profile_id != EXPECTED[domain]:
            fail(f"unexpected profile/domain binding: {domain!r} {profile_id!r}")
        if profile.get("execution_kind") != "REFERENCE_MODEL":
            fail(f"{profile_id}: reference profile must use REFERENCE_MODEL")
        if profile.get("state") != "IMPLEMENTED_LOCAL_UNATTESTED":
            fail(f"{profile_id}: unexpected state")
        cases = profile.get("required_cases")
        if not isinstance(cases, list) or len(cases) != 6 or len(set(cases)) != 6:
            fail(f"{profile_id}: exactly six unique cases are required")
        expected_cases = list(harness.CASES[domain.lower()])
        if cases != expected_cases:
            fail(f"{profile_id}: plan and executable case order differ")
        observed[domain] = profile_id
        total_cases += len(cases)

    if observed != EXPECTED:
        fail(f"profile set mismatch: {observed!r}")
    state = plan.get("current_state", {})
    if state.get("reference_models_implemented") != 3 or state.get("behavior_cases_implemented") != total_cases:
        fail("current-state counts do not match the executable plan")
    if state.get("candidate_adapters_executed") != 0 or state.get("candidates_selected") != 0:
        fail("candidate execution or selection was claimed prematurely")

    evidence_schema = load_json(EVIDENCE_SCHEMA_PATH)
    reproduction_schema = load_json(REPRO_SCHEMA_PATH)
    Draft202012Validator.check_schema(evidence_schema)
    Draft202012Validator.check_schema(reproduction_schema)
    if evidence_schema["properties"]["qualification"].get("const") is not False:
        fail("evidence schema must force qualification=false")
    if evidence_schema["properties"]["selection_effect"].get("const") != "NONE":
        fail("evidence schema must force selection_effect=NONE")
    if evidence_schema["properties"]["authority_effect"].get("const") != "NONE":
        fail("evidence schema must force authority_effect=NONE")
    if reproduction_schema["properties"]["review_status"].get("const") != "PENDING":
        fail("independent reproduction bundle must remain unreviewed")

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    required_workflow_fragments = (
        "validate_h02_seeded_behavior_plan_v1.py",
        "test_h02_seeded_behavior_harness_v1.py",
        "h02_seeded_behavior_harness_v1.py run",
        "h02_seeded_behavior_harness_v1.py replay",
        "attested=false",
    )
    for fragment in required_workflow_fragments:
        if fragment not in workflow:
            fail(f"workflow missing fail-closed fragment: {fragment}")


def main() -> int:
    try:
        validate()
    except (ValidationFailure, OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"H02 seeded behavior plan validation FAILED: {error}", file=sys.stderr)
        return 1
    print("H02 seeded behavior plan validation passed: profiles=3 cases=18 candidate_adapters=0 authority=NONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
