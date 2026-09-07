#!/usr/bin/env python3
"""Fail-closed validation for the HeptaBao V1.2.1 operational deepening.

This layer extends, but never weakens, ``validate_plan_v1_2``.  It validates
external-action handoffs, blocker closure receipts, one-to-one blocker coverage
and the exact CI entry point.  It cannot grant qualification or authority.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import validate_plan_v1_2 as base

ROOT = SCRIPT_DIR.parent

EXPECTED_EXTERNAL = {
    "HB-BLK-CTRL-001": ("HB-EAP-CTRL-001", "REPOSITORY_SETTING"),
    "HB-BLK-EXT-001": ("HB-EAP-EXT-001", "EXTERNAL_GOVERNANCE"),
    "HB-BLK-EXT-002": ("HB-EAP-EXT-002", "EXTERNAL_LEGAL"),
    "HB-BLK-EXT-003": ("HB-EAP-EXT-003", "EXTERNAL_SECURITY"),
    "HB-BLK-EXT-004": ("HB-EAP-EXT-004", "EXTERNAL_SIGNING"),
    "HB-BLK-EXT-005": ("HB-EAP-EXT-005", "EXTERNAL_ORACLE"),
    "HB-BLK-EXT-006": ("HB-EAP-EXT-006", "EXTERNAL_STORAGE_LAB"),
    "HB-BLK-EXT-007": ("HB-EAP-EXT-007", "EXTERNAL_REPRODUCTION"),
}
EXPECTED_REPOSITORY = {f"HB-BLK-REPO-{value:03d}" for value in range(1, 14)}
REQUIRED_NORMATIVE_PATHS = {
    "docs/plan/HEPTABAO_PLAN_V1_2_1_EXECUTION_DEEPENING.md",
    "docs/execution/HEPTABAO_BLOCKER_CLOSURE_OPERATING_CONTRACT_V1.md",
    "docs/governance/HEPTABAO_REPOSITORY_CONTROL_PLANE_ENFORCEMENT_SPEC_V1.md",
    "planning/HEPTABAO_EXTERNAL_ACTION_PACKAGE_CATALOG_V1.yaml",
    "schemas/heptabao_external_action_package_catalog_v1.schema.json",
    "schemas/heptabao_blocker_closure_receipt_v1.schema.json",
}


def fail(message: str) -> None:
    raise base.ValidationFailure(message)


def load_yaml(path: str) -> dict[str, Any]:
    value = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path}: expected mapping")
    return value


def load_json(path: str) -> dict[str, Any]:
    value = json.loads((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path}: expected object")
    return value


def validate_blocker_register_deepening(
    document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    register = copy.deepcopy(
        document or load_yaml("planning/HEPTABAO_BLOCKER_REGISTER_V1.yaml")
    )
    base.validate_blockers(register)

    if register.get("revision") != "1.2.1":
        fail("blocker register must carry the V1.2.1 operational revision")
    if register.get("closure_receipt_schema") != (
        "schemas/heptabao_blocker_closure_receipt_v1.schema.json"
    ):
        fail("blocker register does not bind the closure receipt schema")
    if register.get("external_action_catalog") != (
        "planning/HEPTABAO_EXTERNAL_ACTION_PACKAGE_CATALOG_V1.yaml"
    ):
        fail("blocker register does not bind the external action catalog")
    if register.get("authority_effect") != "NONE":
        fail("blocker register may not grant authority")

    blockers = register["blockers"]
    by_id = {entry["id"]: entry for entry in blockers}
    repository_ids = {
        identifier
        for identifier, entry in by_id.items()
        if entry.get("class") == "REPOSITORY_CONTROLLED"
    }
    external_ids = set(by_id) - repository_ids
    if repository_ids != EXPECTED_REPOSITORY:
        fail(
            "repository blocker set drift: "
            f"missing={sorted(EXPECTED_REPOSITORY-repository_ids)!r} "
            f"unexpected={sorted(repository_ids-EXPECTED_REPOSITORY)!r}"
        )
    if external_ids != set(EXPECTED_EXTERNAL):
        fail(
            "external blocker set drift: "
            f"missing={sorted(set(EXPECTED_EXTERNAL)-external_ids)!r} "
            f"unexpected={sorted(external_ids-set(EXPECTED_EXTERNAL))!r}"
        )

    for identifier in sorted(repository_ids):
        blocker = by_id[identifier]
        if blocker.get("action_package_id") is not None:
            fail(f"{identifier}: repository blocker may not claim an external action package")
        execution = blocker.get("required_execution")
        if not isinstance(execution, list) or not execution:
            fail(f"{identifier}: required exact-head execution set is missing")
        if blocker.get("closure_receipt_required") is not True:
            fail(f"{identifier}: closure receipt must be required")
        if blocker.get("state") == "CLOSED":
            fail(f"{identifier}: checked-in source cannot pre-close without a verified receipt graph")

    for identifier, (package_id, expected_class) in EXPECTED_EXTERNAL.items():
        blocker = by_id[identifier]
        if blocker.get("class") != expected_class:
            fail(f"{identifier}: external blocker class drift")
        if blocker.get("action_package_id") != package_id:
            fail(f"{identifier}: external action package binding drift")
        if blocker.get("state") != "EXTERNAL_ACTION_REQUIRED":
            fail(f"{identifier}: external blocker must remain EXTERNAL_ACTION_REQUIRED")
        if blocker.get("closure_receipt_required") is not True:
            fail(f"{identifier}: closure receipt must be required")

    return register


def validate_external_action_packages(
    document: dict[str, Any] | None = None,
    blocker_register: dict[str, Any] | None = None,
) -> dict[str, Any]:
    catalog = copy.deepcopy(
        document
        or load_yaml("planning/HEPTABAO_EXTERNAL_ACTION_PACKAGE_CATALOG_V1.yaml")
    )
    schema = load_json(
        "schemas/heptabao_external_action_package_catalog_v1.schema.json"
    )
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(catalog),
        key=lambda item: list(item.path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.path) or "<root>"
        fail(f"external action catalog invalid at {location}: {first.message}")

    register = blocker_register or validate_blocker_register_deepening()
    blockers = {entry["id"]: entry for entry in register["blockers"]}
    packages = catalog["packages"]
    ids = [entry["id"] for entry in packages]
    blocker_ids = [entry["blocker_id"] for entry in packages]
    if len(ids) != len(set(ids)):
        fail("external action catalog contains duplicate package IDs")
    if len(blocker_ids) != len(set(blocker_ids)):
        fail("external action catalog maps more than one package to a blocker")
    if set(blocker_ids) != set(EXPECTED_EXTERNAL):
        fail("external action package coverage is not exactly one-to-one")

    completion_objects: set[str] = set()
    for package in packages:
        identifier = package["id"]
        blocker_id = package["blocker_id"]
        expected_package, expected_class = EXPECTED_EXTERNAL[blocker_id]
        if identifier != expected_package or package["class"] != expected_class:
            fail(f"{blocker_id}: action package identity/class drift")
        blocker = blockers[blocker_id]
        if blocker["action_package_id"] != identifier:
            fail(f"{blocker_id}: blocker/catalog cross-reference mismatch")
        if package["state"] != "EXTERNAL_ACTION_REQUIRED":
            fail(f"{identifier}: repository source may not self-close an external package")
        if package["authority_effect"] != "NONE":
            fail(f"{identifier}: external action package may not grant authority")

        step_ids = [step["id"] for step in package["ordered_procedure"]]
        expected_steps = [f"STEP-{value:02d}" for value in range(1, len(step_ids) + 1)]
        if step_ids != expected_steps:
            fail(f"{identifier}: ordered procedure IDs must be contiguous")
        evidence_ids = [entry["id"] for entry in package["evidence_requirements"]]
        if len(evidence_ids) != len(set(evidence_ids)):
            fail(f"{identifier}: duplicate evidence requirement ID")

        completion = package["handoff"]["expected_completion_object"]
        if completion in completion_objects:
            fail(f"{identifier}: completion object type is not unique")
        completion_objects.add(completion)

        forbidden = " ".join(package["forbidden_substitutions"]).lower()
        if not any(token in forbidden for token in ("not", "cannot", "insufficient", "不能", "不是")):
            fail(f"{identifier}: forbidden substitutions do not state fail-closed boundaries")

    return catalog


def validate_closure_receipt_schema(
    schema_document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    schema = copy.deepcopy(
        schema_document
        or load_json("schemas/heptabao_blocker_closure_receipt_v1.schema.json")
    )
    Draft202012Validator.check_schema(schema)
    properties = schema.get("properties", {})
    if properties.get("schema", {}).get("const") != "heptabao.blocker-closure-receipt.v1":
        fail("blocker closure receipt schema identity drift")
    for field, expected in (
        ("qualification", False),
        ("compatibility_claim", False),
        ("selection_effect", "NONE"),
        ("authority_effect", "NONE"),
    ):
        if properties.get(field, {}).get("const") != expected:
            fail(f"blocker closure receipt {field} is not fail-closed")
    closed_rule = json.dumps(schema.get("allOf", []), sort_keys=True)
    for token in (
        '"CLOSED"',
        '"failed": {"const": 0}',
        '"blocked": {"const": 0}',
        '"unknown": {"const": 0}',
        '"unexecuted": {"const": 0}',
    ):
        if token not in closed_rule:
            fail(f"blocker closure CLOSED condition missing: {token}")
    return schema


def validate_normative_extensions(
    manifest_document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = copy.deepcopy(
        manifest_document
        or load_yaml("planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml")
    )
    base.validate_manifest(manifest)
    by_path = {entry["path"]: entry for entry in manifest["documents"]}
    missing = REQUIRED_NORMATIVE_PATHS - set(by_path)
    if missing:
        fail(f"V1.2.1 normative paths missing: {sorted(missing)!r}")
    for path in REQUIRED_NORMATIVE_PATHS:
        entry = by_path[path]
        if entry["kind"] != "NORMATIVE":
            fail(f"{path}: V1.2.1 extension is not normative")
        if entry["authority_effect"] != "NONE":
            fail(f"{path}: V1.2.1 extension may not grant authority")
    return manifest


def validate_v121_docs() -> None:
    required = {
        "docs/plan/HEPTABAO_PLAN_V1_2_1_EXECUTION_DEEPENING.md": [
            "REMEDIATION_IMPLEMENTED",
            "EXACT_HEAD_EXECUTED",
            "HB-EAP-EXT-007",
            "authority_effect",
        ],
        "docs/execution/HEPTABAO_BLOCKER_CLOSURE_OPERATING_CONTRACT_V1.md": [
            "BASE_DRIFT",
            "closure receipt",
            "runner_id=0",
            "stale snapshot",
        ],
        "docs/governance/HEPTABAO_REPOSITORY_CONTROL_PLANE_ENFORCEMENT_SPEC_V1.md": [
            "administrator bypass",
            "negative control",
            "CODEOWNERS",
            "contents: read",
        ],
        "README.md": [
            "V1.2.1",
            "HEPTABAO_EXTERNAL_ACTION_PACKAGE_CATALOG_V1.yaml",
        ],
    }
    for path, tokens in required.items():
        text = (ROOT / path).read_text(encoding="utf-8")
        for token in tokens:
            if token.lower() not in text.lower():
                fail(f"{path}: required V1.2.1 concept missing: {token}")
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    if (
        "not yet a deployable secrets server" not in readme
        and "not a production-deployable secrets server" not in readme
    ):
        fail("README.md: non-production deployability boundary is missing")


def validate_workflow_entry(workflow_text: str | None = None) -> None:
    text = workflow_text or (
        ROOT / ".github/workflows/plan-v1.2.1-operational-integrity.yml"
    ).read_text(encoding="utf-8")
    required = [
        "python3 scripts/validate_plan_v1_2.py",
        "python3 scripts/validate_plan_v1_2_1.py",
        "permissions:\n  contents: read",
        "persist-credentials: false",
        "tests/plan/test_plan_v1_2_1.py",
        "authority-sentinel:",
    ]
    for token in required:
        if token not in text:
            fail(f"V1.2.1 operational workflow is missing token: {token}")
    for label, pattern in base.FORBIDDEN_WORKFLOW_PATTERNS.items():
        if pattern.search(text):
            fail(f"V1.2.1 operational workflow contains forbidden {label}")


def run_all() -> dict[str, Any]:
    base_result = base.run_all()
    register = validate_blocker_register_deepening()
    catalog = validate_external_action_packages(blocker_register=register)
    validate_closure_receipt_schema()
    manifest = validate_normative_extensions()
    validate_v121_docs()
    validate_workflow_entry()
    return {
        "documents": len(manifest["documents"]),
        "work_packages": base_result["work_packages"],
        "blockers": len(register["blockers"]),
        "external_action_packages": len(catalog["packages"]),
        "qualification": False,
        "authority_effect": "NONE",
    }


def main() -> int:
    try:
        result = run_all()
    except (
        base.ValidationFailure,
        OSError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as error:
        print(f"HeptaBao Plan V1.2.1 validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "HeptaBao Plan V1.2.1 validation passed: "
        f"documents={result['documents']} "
        f"work_packages={result['work_packages']} "
        f"blockers={result['blockers']} "
        f"external_action_packages={result['external_action_packages']} "
        "qualification=false authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
