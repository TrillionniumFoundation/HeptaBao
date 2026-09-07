#!/usr/bin/env python3
"""Fail-closed semantic validation for HeptaBao Plan V1.1.

This validator checks execution topology, work-package identity, authority defaults,
compatibility criticality, request/migration invariants and evidence schemas.  It
intentionally does not grant qualification or authority; it can only reject an
invalid planning tree.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_1.md",
    "docs/plan/HEPTABAO_PLAN_V1_1_AMENDMENT.md",
    "planning/HEPTABAO_PROGRAM_GATE_MATRIX_V1_1.yaml",
    "planning/HEPTABAO_WORK_PACKAGE_CATALOG_V1_1.yaml",
    "planning/HEPTABAO_COMPATIBILITY_PROFILES_V1.yaml",
    "planning/HEPTABAO_AUTHORITY_POLICY_V1.yaml",
    "planning/AUTHORITY_FLAGS_V2.yaml",
    "schemas/heptabao_qualification_receipt_v2.schema.json",
    "schemas/heptabao_compatibility_claim_v1.schema.json",
    "schemas/heptabao_authority_grant_v1.schema.json",
    "schemas/heptabao_receipt_revocation_v1.schema.json",
    "specs/HEPTABAO_OPERATION_REGISTRY_V1.yaml",
    "specs/HEPTABAO_REQUEST_PIPELINE_STATE_MACHINE_V1.yaml",
    "specs/HEPTABAO_AUDIT_COMMIT_EFFECT_ORDERING_V1.md",
    "specs/HEPTABAO_MIGRATION_AUTHORITY_STATE_MACHINE_V1.yaml",
]

EXPECTED_GATES = [f"H{i:02d}" for i in range(28)]
WP_PATTERN = re.compile(r"^(H(?:0[0-9]|1[0-9]|2[0-7])-WP\d{2,3}):([a-z0-9][a-z0-9-]*)$")
SHA256_ZERO = "0" * 64
SHA40_ZERO = "0" * 40
SHA40_ONE = "1" * 40


class ValidationFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationFailure(message)


def load_yaml(path: str) -> dict[str, Any]:
    value = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path}: expected a mapping")
    return value


def load_json(path: str) -> dict[str, Any]:
    value = json.loads((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path}: expected an object")
    return value


def require_files() -> None:
    missing = [path for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    if missing:
        fail(f"missing required files: {', '.join(missing)}")


def validate_gate_matrix() -> set[str]:
    matrix = load_yaml("planning/HEPTABAO_PROGRAM_GATE_MATRIX_V1_1.yaml")
    if matrix.get("schema") != "heptabao.program-gate-matrix.v1_1":
        fail("unexpected program-gate schema")
    if matrix.get("status") != "NORMATIVE_EXECUTION_INPUT":
        fail("program-gate matrix is not normative execution input")

    resolution = matrix.get("stage_resolution", {})
    if resolution.get("active_authority_gate") != "H00":
        fail("H00 must remain the active authority gate")

    phases = matrix.get("phases")
    if not isinstance(phases, dict) or list(phases) != EXPECTED_GATES:
        fail("program gates must be exactly ordered H00..H27")
    if phases["H00"].get("state") != "ACTIVE":
        fail("H00 must be ACTIVE")
    for gate in EXPECTED_GATES[1:]:
        if phases[gate].get("state") != "PLANNED":
            fail(f"{gate} must remain PLANNED")

    semantics = matrix.get("dependency_semantics", {})
    for key in ("work_start_requires", "qualification_requires", "release_requires", "missing_or_ambiguous"):
        if key not in semantics:
            fail(f"dependency semantic missing: {key}")
    if semantics.get("missing_or_ambiguous") != "FAIL_CLOSED":
        fail("ambiguous dependencies must fail closed")

    blockers = matrix.get("global_blockers")
    if not isinstance(blockers, list) or len(blockers) < 8:
        fail("global blocker registry is too shallow")

    active = resolution.get("active_work_packages")
    if active != ["H00-WP01", "H00-WP02", "H00-WP03", "H00-WP04"]:
        fail("unexpected active H00 work-package set")
    return set(active)


def validate_work_packages(active: set[str]) -> set[str]:
    catalog = load_yaml("planning/HEPTABAO_WORK_PACKAGE_CATALOG_V1_1.yaml")
    if catalog.get("schema") != "heptabao.work-package-catalog.v1_1":
        fail("unexpected work-package schema")
    gates = catalog.get("gates")
    if not isinstance(gates, dict) or list(gates) != EXPECTED_GATES:
        fail("work-package catalog must contain ordered H00..H27 gates")

    ids: set[str] = set()
    for gate, body in gates.items():
        packages = body.get("packages") if isinstance(body, dict) else None
        if not isinstance(packages, list) or not packages:
            fail(f"{gate}: work-package list is empty")
        for item in packages:
            if not isinstance(item, str):
                fail(f"{gate}: non-string work-package entry")
            match = WP_PATTERN.fullmatch(item)
            if not match:
                fail(f"{gate}: invalid work-package entry: {item}")
            wp_id = match.group(1)
            if not wp_id.startswith(f"{gate}-"):
                fail(f"{wp_id}: gate prefix mismatch")
            if wp_id in ids:
                fail(f"duplicate work-package ID: {wp_id}")
            ids.add(wp_id)

    if len(ids) < 250:
        fail(f"work-package decomposition is too coarse: {len(ids)} < 250")
    if not active.issubset(ids):
        fail(f"active work packages are absent from catalog: {sorted(active - ids)}")
    return ids


def validate_authority_defaults() -> None:
    flags = load_yaml("planning/AUTHORITY_FLAGS_V2.yaml")
    if flags.get("schema") != "heptabao.authority-flags.v2":
        fail("unexpected authority-flags schema")
    values = flags.get("flags")
    if not isinstance(values, dict):
        fail("authority flags missing")
    for name, value in values.items():
        expected = name == "implementation_started"
        if value is not expected:
            fail(f"authority flag {name!r} expected {expected}, got {value!r}")
    if flags.get("active_grants") != []:
        fail("active grants must be empty during H00")

    policy = load_yaml("planning/HEPTABAO_AUTHORITY_POLICY_V1.yaml")
    if policy.get("default") != "DENY":
        fail("authority policy must default DENY")
    text = "\n".join(str(rule) for rule in policy.get("rules", []))
    for phrase in ("grant no", "signed", "revocable", "Revocation"):
        if phrase.lower() not in text.lower():
            fail(f"authority policy missing concept: {phrase}")


def validate_profiles() -> None:
    profiles = load_yaml("planning/HEPTABAO_COMPATIBILITY_PROFILES_V1.yaml")
    coverage = profiles.get("criticality_coverage")
    if not isinstance(coverage, dict) or len(coverage) < 5:
        fail("criticality coverage registry is incomplete")
    for criticality, rule in coverage.items():
        if rule.get("required_percent") != 100 or rule.get("waiver_allowed") is not False:
            fail(f"{criticality}: critical coverage must be 100% and non-waivable")
    profile_map = profiles.get("profiles")
    if not isinstance(profile_map, dict) or "HB-P12-FULL-C5" not in profile_map:
        fail("full C5 compatibility profile is missing")
    for profile_id, body in profile_map.items():
        if body.get("production_supported") is not False:
            fail(f"{profile_id}: planning profiles must not grant production support")


def validate_operation_registry() -> None:
    registry = load_yaml("specs/HEPTABAO_OPERATION_REGISTRY_V1.yaml")
    for key in ("unknown_operation", "unknown_field", "unknown_internal_operation"):
        if registry.get(key) != "DENY":
            fail(f"operation registry {key} must DENY")
    required = registry.get("required_metadata")
    samples = registry.get("sample_operations")
    if not isinstance(required, list) or len(required) < 20:
        fail("operation metadata contract is incomplete")
    if not isinstance(samples, dict) or len(samples) < 7:
        fail("operation registry lacks representative classes")
    required_set = set(required)
    for operation_id, body in samples.items():
        missing = required_set - set(body)
        if missing:
            fail(f"{operation_id}: missing operation metadata {sorted(missing)}")
        if body.get("response_unknown_policy") == "SAFE_NOT_SENT" and body.get("external_effect") is True:
            fail(f"{operation_id}: external effect cannot use SAFE_NOT_SENT")


def validate_state_machines() -> None:
    pipeline = load_yaml("specs/HEPTABAO_REQUEST_PIPELINE_STATE_MACHINE_V1.yaml")
    states = pipeline.get("states")
    transitions = pipeline.get("transitions")
    if not isinstance(states, dict) or not isinstance(transitions, list):
        fail("request pipeline state machine is malformed")
    for transition in transitions:
        if not isinstance(transition, list) or len(transition) != 3:
            fail(f"invalid request transition: {transition!r}")
        source, _event, target = transition
        if source not in states or target not in states:
            fail(f"request transition references unknown state: {transition!r}")
    invariant_text = "\n".join(pipeline.get("invariants", []))
    for phrase in ("before dispatch", "blind retry", "Response audit", "stale owner"):
        if phrase.lower() not in invariant_text.lower():
            fail(f"request-pipeline invariant missing: {phrase}")

    migration = load_yaml("specs/HEPTABAO_MIGRATION_AUTHORITY_STATE_MACHINE_V1.yaml")
    mstates = migration.get("states")
    if not isinstance(mstates, dict):
        fail("migration state map missing")
    for state, body in mstates.items():
        if body.get("source_writer") is True and body.get("target_writer") is True:
            fail(f"{state}: source and target writers overlap")
    if mstates.get("MANUAL_HOLD", {}).get("source_writer") is not False or mstates.get("MANUAL_HOLD", {}).get("target_writer") is not False:
        fail("manual hold must have no writer")


def approval(role: str, number: int) -> dict[str, str]:
    return {
        "role": role,
        "identity": f"reviewer-{number}",
        "decision": "APPROVE",
        "timestamp_utc": "2026-08-28T00:00:00Z",
        "signature_ref": f"signature-{number}",
    }


def qualification_instance(*, failed: int, high_open: int) -> dict[str, Any]:
    passed = 1 if failed == 0 else 0
    return {
        "schema": "heptabao.qualification-receipt.v2",
        "plan_binding": {
            "plan_id": "HEPTABAO-PLAN-2026-08-28",
            "revision": "1.1",
            "plan_digest_sha256": SHA256_ZERO,
        },
        "gate_id": "H00",
        "receipt_id": "HB-QR-ABCDEFGH",
        "status": "QUALIFIED",
        "generated_at_utc": "2026-08-28T00:00:00Z",
        "valid_until_utc": "2026-09-28T00:00:00Z",
        "source": {
            "repository": "ProfHepta/HeptaBao",
            "commit_sha": SHA40_ZERO,
            "tree_sha": SHA40_ONE,
            "clean_tree": True,
            "ref": "refs/heads/test",
        },
        "environment": {
            "runner_image": "test",
            "os": "linux",
            "arch": "x86_64",
            "rustc": "1.98.0",
            "cargo": "1.98.0",
            "python": "3.13",
            "dependency_lock_sha256": SHA256_ZERO,
            "config_digest_sha256": SHA256_ZERO,
        },
        "dependency_receipts": [],
        "evidence": [{"id": "e1", "kind": "test", "path": "evidence/e1", "sha256": SHA256_ZERO}],
        "test_summary": {
            "total": 1,
            "passed": passed,
            "failed": failed,
            "skipped": 0,
            "unknown": 0,
            "required_lanes": [{"id": "plan", "status": "PASS", "evidence_ref": "e1"}],
        },
        "findings": {
            "critical_open": 0,
            "high_open": high_open,
            "medium_open": 0,
            "low_open": 0,
            "unclassified": 0,
            "accepted_risks": [],
        },
        "exit_gates": [{"id": "h00-plan", "status": "PASS", "evidence_ref": "e1"}],
        "approvals": [approval("program", 1), approval("security", 2), approval("domain", 3)],
        "signature": {
            "algorithm": "ed25519",
            "key_id": "test-key",
            "signature_ref": "signature-main",
            "payload_sha256": SHA256_ZERO,
        },
        "authority_effect": "NONE",
    }


def validate_evidence_schemas() -> None:
    qualification = load_json("schemas/heptabao_qualification_receipt_v2.schema.json")
    validator = Draft202012Validator(qualification, format_checker=FormatChecker())
    positive = qualification_instance(failed=0, high_open=0)
    positive_errors = list(validator.iter_errors(positive))
    if positive_errors:
        fail("positive qualification fixture rejected: " + "; ".join(error.message for error in positive_errors))
    negative = qualification_instance(failed=1, high_open=1)
    if not list(validator.iter_errors(negative)):
        fail("false QUALIFIED receipt with failed tests/high finding was accepted")

    claim = load_json("schemas/heptabao_compatibility_claim_v1.schema.json")
    if claim.get("properties", {}).get("authority_effect", {}).get("const") != "NONE":
        fail("compatibility claim must have authority_effect NONE")
    grant = load_json("schemas/heptabao_authority_grant_v1.schema.json")
    if "scope" not in grant.get("required", []) or "expires_at_utc" not in grant.get("required", []):
        fail("authority grant must require scope and expiry")
    revocation = load_json("schemas/heptabao_receipt_revocation_v1.schema.json")
    if "target" not in revocation.get("required", []) or "effective_at_utc" not in revocation.get("required", []):
        fail("revocation schema must require target and effective time")


def scan_secret_hygiene() -> None:
    forbidden = [
        "-----BEGIN " + "PRIVATE KEY-----",
        "-----BEGIN OPENSSH " + "PRIVATE KEY-----",
        "gh" + "p_",
        "xox" + "b-",
        "AK" + "IA" + "IOSFODNN7EXAMPLE",
    ]
    skip_prefixes = (".git/", "bootstrap/plan-v1-1-generator/")
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        if relative.startswith(skip_prefixes):
            continue
        if path.suffix.lower() not in {".md", ".yaml", ".yml", ".json", ".py", ".rs", ".toml", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for marker in forbidden:
            if marker in text:
                fail(f"possible secret/private-key marker in {relative}: {marker}")


def main() -> int:
    try:
        require_files()
        active = validate_gate_matrix()
        packages = validate_work_packages(active)
        validate_authority_defaults()
        validate_profiles()
        validate_operation_registry()
        validate_state_machines()
        validate_evidence_schemas()
        scan_secret_hygiene()
    except (ValidationFailure, OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"HeptaBao V1.1 validation FAILED: {error}", file=sys.stderr)
        return 1

    print(
        "HeptaBao V1.1 validation passed: "
        f"gates={len(EXPECTED_GATES)} work_packages={len(packages)} "
        "authority=fail-closed schemas=semantic"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
