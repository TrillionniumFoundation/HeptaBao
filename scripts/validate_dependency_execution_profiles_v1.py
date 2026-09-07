#!/usr/bin/env python3
"""Validate that H02 candidate profiles are complete specifications but remain unexecuted."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from yaml12_loader import safe_load_yaml12

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "planning" / "HEPTABAO_H02_EXECUTION_PROFILES_V1.yaml"
SCHEMA_PATH = ROOT / "schemas" / "heptabao_dependency_execution_profiles_v1.schema.json"
CATALOG_PATH = ROOT / "planning" / "HEPTABAO_H02_DEPENDENCY_BAKEOFF_V1.yaml"

EXPECTED_CLASSES = {
    "RUNTIME_CORRECTNESS",
    "TLS_SECURITY",
    "RAFT_CORRECTNESS",
    "ARTIFACT_PROVENANCE",
}


class ValidationFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationFailure(message)


def load_yaml(path: Path) -> dict[str, Any]:
    value = safe_load_yaml12(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)}: expected mapping")
    return value


def validate() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    document = load_yaml(PROFILE_PATH)
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document))
    if errors:
        fail("; ".join(error.message for error in errors))

    catalog = load_yaml(CATALOG_PATH)
    candidate_ids = {candidate["candidate_id"] for candidate in catalog["candidates"]}
    classes: set[str] = set()
    case_ids: set[str] = set()
    for profile in document["profiles"]:
        classes.add(profile["class"])
        unknown = set(profile["candidates"]) - candidate_ids
        if unknown:
            fail(f"{profile['profile_id']}: unknown candidates {sorted(unknown)}")
        if profile["state"] != "SPECIFIED_UNEXECUTED" or profile["evidence_refs"] != []:
            fail(f"{profile['profile_id']}: profile attempted to claim execution")
        for case in profile["cases"]:
            if case["id"] in case_ids:
                fail(f"duplicate case ID: {case['id']}")
            case_ids.add(case["id"])
            if case["failure_effect"] != "FAIL_CLOSED_NO_SELECTION":
                fail(f"{case['id']}: critical failure must block selection")

    if classes != EXPECTED_CLASSES:
        fail(f"profile classes mismatch: {sorted(classes)}")
    if document["qualification"] is not False:
        fail("profile specification cannot self-qualify")
    if document["selection_effect"] != "NONE" or document["authority_effect"] != "NONE":
        fail("profile specification cannot grant selection or authority")
    return len(document["profiles"])


def main() -> int:
    try:
        count = validate()
    except (OSError, ValueError, json.JSONDecodeError, ValidationFailure) as error:
        print(f"H02 execution-profile validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "H02 execution-profile validation passed: "
        f"profiles={count} executed=0 selection=0 qualification=false authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
