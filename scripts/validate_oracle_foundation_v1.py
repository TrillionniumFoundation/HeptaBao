#!/usr/bin/env python3
"""Fail-closed validation for the sanitized HeptaBao H01 Oracle foundation."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
ZERO = "0" * 64
WP_PREFIX = "H"

REQUIRED = [
    "oracle/README.md",
    "oracle/baselines/openbao-v2.6.2.yaml",
    "oracle/inventory/openbao-v2.6.2/surface-catalog.yaml",
    "oracle/inventory/openbao-v2.6.2/endpoint-seed.yaml",
    "oracle/inventory/openbao-v2.6.2/endpoint-seed-coverage-correction-v1.yaml",
    "oracle/normalization/HEPTABAO_ORACLE_NORMALIZATION_POLICY_V1.yaml",
    "schemas/heptabao_oracle_surface_inventory_v1.schema.json",
    "schemas/heptabao_oracle_endpoint_inventory_v1.schema.json",
    "schemas/heptabao_oracle_fixture_manifest_v1.schema.json",
    "scripts/oracle_normalize_v1.py",
    "tests/oracle/test_normalize_v1.py",
    "planning/HEPTABAO_H01_WORK_PACKAGE_STATUS_V1.yaml",
    "qualifications/H01/H01-IMPLEMENTATION-STATUS.json",
]


class ValidationFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationFailure(message)


def yaml_map(path: str) -> dict[str, Any]:
    value = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path}: expected mapping")
    return value


def json_map(path: str) -> dict[str, Any]:
    value = json.loads((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path}: expected object")
    return value


def require_files() -> None:
    missing = [path for path in REQUIRED if not (ROOT / path).is_file()]
    if missing:
        fail("missing H01 files: " + ", ".join(missing))


def validate_baseline() -> None:
    baseline = yaml_map("oracle/baselines/openbao-v2.6.2.yaml")
    expected = {
        "schema": "heptabao.oracle-baseline.v1",
        "baseline_id": "HB-ORACLE-OPENBAO-V2_6_2",
        "status": "FROZEN_RESEARCH_BASELINE_NOT_COMPATIBILITY_AUTHORITY",
        "authority_effect": "NONE",
        "qualification_status": "NOT_QUALIFIED",
    }
    for key, value in expected.items():
        if baseline.get(key) != value:
            fail(f"baseline {key} mismatch: {baseline.get(key)!r}")
    release = baseline.get("release", {})
    if release.get("tag") != "v2.6.2":
        fail("Oracle tag mismatch")
    if release.get("commit_sha") != "dd9c19c37a878cf4a81b18efb8d6f0599c7da923":
        fail("Oracle commit mismatch")
    if release.get("tree_sha") != "308de7e6da19d8b994c5710ffd715ce4cedde448":
        fail("Oracle tree mismatch")
    artifact = baseline.get("artifacts", {}).get("distribution_source", {})
    if artifact.get("sha256") != "a7784550a9db16f24e99d65a18c9b12a433707c79ef4c1f34262d3f48171c7a9":
        fail("Oracle distribution artifact digest mismatch")
    if artifact.get("use") != "restricted Oracle/specification lane only until provenance transfer approval":
        fail("Oracle source artifact is not restricted")
    if "production authority" not in baseline.get("not_claimed", []):
        fail("baseline must explicitly disclaim production authority")


def load_validator(path: str) -> Draft202012Validator:
    schema = json_map(path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def catalog_work_packages() -> set[str]:
    catalog = yaml_map("planning/HEPTABAO_WORK_PACKAGE_CATALOG_V1_1.yaml")
    result: set[str] = set()
    for gate_body in catalog["gates"].values():
        for entry in gate_body["packages"]:
            result.add(str(entry).split(":", 1)[0])
    return result


def profile_ids() -> set[str]:
    profiles = yaml_map("planning/HEPTABAO_COMPATIBILITY_PROFILES_V1.yaml")
    return set(profiles["profiles"])


def validate_surface_catalog(work_packages: set[str], profiles: set[str]) -> int:
    path = "oracle/inventory/openbao-v2.6.2/surface-catalog.yaml"
    value = yaml_map(path)
    errors = list(load_validator("schemas/heptabao_oracle_surface_inventory_v1.schema.json").iter_errors(value))
    if errors:
        fail(path + ": " + "; ".join(error.message for error in errors))
    ids: set[str] = set()
    count = 0
    categories = value["categories"]
    required_categories = {
        "core_system",
        "auth_methods",
        "secret_engines",
        "database_providers",
        "audit_devices",
        "storage_backends",
        "plugin_classes",
        "cluster_ha",
        "client_operator",
        "namespace_workflow",
        "migration",
    }
    if {category["id"] for category in categories} != required_categories:
        fail("surface category set is incomplete or unexpected")
    for category in categories:
        for item in category["items"]:
            count += 1
            item_id = item["id"]
            if item_id in ids:
                fail(f"duplicate surface ID: {item_id}")
            ids.add(item_id)
            missing_wp = set(item["owner_work_packages"]) - work_packages
            if missing_wp:
                fail(f"{item_id}: unknown work packages {sorted(missing_wp)}")
            missing_profiles = set(item["support_profiles"]) - profiles
            if missing_profiles:
                fail(f"{item_id}: unknown profiles {sorted(missing_profiles)}")
            if item["inventory_status"] != "IDENTIFIED":
                fail(f"{item_id}: H01 seed must remain IDENTIFIED")
            if item["fixture_status"] not in {"NONE", "PLANNED"}:
                fail(f"{item_id}: no fixture capture/review is currently evidenced")
            if item["criticality"].endswith("CRITICAL") and not item["owner_work_packages"]:
                fail(f"{item_id}: unowned critical surface")
    if count != 60:
        fail(f"surface item count mismatch: {count} != 60")
    coverage = value["coverage"]
    if coverage != {
        "total_items": 60,
        "identified": 60,
        "captured": 0,
        "reviewed": 0,
        "qualified": 0,
        "unowned_critical": 0,
        "unclassified": 0,
    }:
        fail(f"surface coverage mismatch: {coverage}")
    if value["authority_effect"] != "NONE" or value["status"] != "SEED":
        fail("surface seed must have no authority and remain SEED")
    return count


def validate_endpoint_seed(work_packages: set[str]) -> int:
    path = "oracle/inventory/openbao-v2.6.2/endpoint-seed.yaml"
    value = yaml_map(path)
    errors = list(load_validator("schemas/heptabao_oracle_endpoint_inventory_v1.schema.json").iter_errors(value))
    if errors:
        fail(path + ": " + "; ".join(error.message for error in errors))
    entries = value["entries"]
    ids: set[str] = set()
    allowed_classes = set(yaml_map("specs/HEPTABAO_OPERATION_REGISTRY_V1.yaml")["operation_classes"])
    for entry in entries:
        endpoint_id = entry["id"]
        if endpoint_id in ids:
            fail(f"duplicate endpoint ID: {endpoint_id}")
        ids.add(endpoint_id)
        if entry["operation_class"] not in allowed_classes:
            fail(f"{endpoint_id}: unknown operation class")
        if set(entry["owner_work_packages"]) - work_packages:
            fail(f"{endpoint_id}: unknown work-package reference")
        if entry["observation_status"] != "IDENTIFIED" or entry["fixture_status"] != "PLANNED":
            fail(f"{endpoint_id}: seed cannot claim capture/review/qualification")
        if entry["operation_class"] == "PURE_READ" and entry["side_effects"] != ["NONE"]:
            fail(f"{endpoint_id}: PURE_READ has side effects")
        if entry["operation_class"] in {"EXTERNAL_EFFECT", "LEASE_ISSUING_READ"} and entry["response_unknown_policy"] == "SAFE_NOT_SENT":
            fail(f"{endpoint_id}: external/lease effect uses unsafe response policy")
        if entry["secret_response"] and entry["response_audit"] not in {"REQUIRED_BEFORE_SECRET_RELEASE", "CEREMONY_REQUIRED"}:
            fail(f"{endpoint_id}: secret response lacks pre-release audit gate")
        if entry["criticality"].endswith("CRITICAL") and not entry["owner_work_packages"]:
            fail(f"{endpoint_id}: unowned critical endpoint")
    actual = len(entries)
    correction = yaml_map("oracle/inventory/openbao-v2.6.2/endpoint-seed-coverage-correction-v1.yaml")
    if correction.get("target_inventory_id") != value["inventory_id"]:
        fail("endpoint count correction targets the wrong inventory")
    if correction.get("previous_value") != value["coverage"]["total_seeded"]:
        fail("endpoint count correction previous value does not bind embedded coverage")
    if correction.get("corrected_value") != actual or actual != 51:
        fail(f"endpoint count/correction mismatch: actual={actual}, correction={correction.get('corrected_value')}")
    if correction.get("semantic_effect") != "METADATA_ONLY" or correction.get("compatibility_authority_effect") != "NONE":
        fail("endpoint count correction has unsafe semantic/authority effect")
    if correction.get("review_status") != "PENDING_COMPATIBILITY_AND_SECURITY_REVIEW":
        fail("endpoint count correction cannot claim review")
    coverage = value["coverage"]
    for key in ("captured", "reviewed", "qualified", "unowned_critical", "unclassified"):
        if coverage[key] != 0:
            fail(f"endpoint coverage {key} must remain zero")
    if value["status"] != "SEED" or value["authority_effect"] != "NONE":
        fail("endpoint inventory must remain authority-free SEED")
    return actual


def validate_normalization_policy() -> int:
    policy = yaml_map("oracle/normalization/HEPTABAO_ORACLE_NORMALIZATION_POLICY_V1.yaml")
    if policy.get("schema") != "heptabao.oracle-normalization-policy.v1":
        fail("normalization policy schema mismatch")
    if policy.get("policy_id") != "HB-ORACLE-NORMALIZATION-V1":
        fail("normalization policy ID mismatch")
    defaults = policy.get("defaults", {})
    expected = {
        "unknown_fields": "PRESERVE",
        "unknown_arrays": "PRESERVE_ORDER",
        "unmatched_secret_key": "REJECT",
        "authority_effect": "NONE",
    }
    for key, value in expected.items():
        if defaults.get(key) != value:
            fail(f"unsafe normalizer default {key}: {defaults.get(key)!r}")
    rules = policy.get("rules")
    if not isinstance(rules, list) or len(rules) < 25:
        fail("normalization policy is too shallow")
    paths: set[str] = set()
    secret_rules = 0
    for rule in rules:
        path = rule.get("path")
        if path in paths:
            fail(f"duplicate normalization rule path: {path}")
        paths.add(path)
        if not {"compatibility", "security"}.issubset(rule.get("approved_roles", [])):
            fail(f"normalization rule lacks required approvals: {path}")
        if rule.get("operation") == "remove" and rule.get("security_relevance") != "NON_SECURITY":
            fail(f"unsafe remove rule: {path}")
        if rule.get("operation") == "secret_placeholder":
            secret_rules += 1
            if not rule.get("secret_kind"):
                fail(f"secret rule lacks kind: {path}")
    if secret_rules < 15:
        fail("normalization policy lacks secret-bearing coverage")
    placeholder = policy.get("secret_placeholder", {})
    if placeholder.get("retain_raw_value") is not False or placeholder.get("digest_algorithm") != "sha256":
        fail("normalization placeholder is unsafe")
    return len(rules)


def synthetic_fixture() -> dict[str, Any]:
    return {
        "schema": "heptabao.oracle-fixture-manifest.v1",
        "fixture_id": "HB-FIXTURE-SYNTHETIC001",
        "baseline": {
            "baseline_id": "HB-ORACLE-OPENBAO-V2_6_2",
            "product": "OpenBao",
            "version": "v2.6.2",
            "commit_sha": "dd9c19c37a878cf4a81b18efb8d6f0599c7da923",
            "artifact_sha256": ZERO,
        },
        "capture": {
            "captured_at_utc": "2026-08-28T00:00:00Z",
            "tool": "synthetic",
            "tool_version": "1",
            "environment_digest_sha256": ZERO,
            "config_digest_sha256": ZERO,
            "seed": "synthetic",
            "operator_identity": "synthetic-operator",
        },
        "request": {
            "operation_id": "sys.health.read",
            "method": "GET",
            "canonical_path": "/v1/sys/health",
            "namespace_profile": "root",
            "mount_profile": "system",
            "request_schema_digest_sha256": ZERO,
            "request_body_sha256": ZERO,
        },
        "raw_artifact": {
            "restricted_reference": "restricted://synthetic/raw",
            "sha256": ZERO,
            "stored_in_implementation_repo": False,
            "contains_live_secret": False,
        },
        "sanitized_artifact": {
            "path": "oracle/fixtures/synthetic/output.json",
            "sha256": ZERO,
            "canonical_json_sha256": ZERO,
            "secret_scan_passed": True,
        },
        "normalization": {
            "policy_id": "HB-ORACLE-NORMALIZATION-V1",
            "policy_sha256": ZERO,
            "normalizer_version": "1",
            "changes": [],
            "ignored_security_fields": 0,
        },
        "observable_side_effects": [
            {
                "kind": "NONE",
                "observer": "synthetic",
                "before_digest_sha256": ZERO,
                "after_digest_sha256": ZERO,
                "classification": "NOT_APPLICABLE",
            }
        ],
        "security_classification": {
            "criticality": "OPERATOR_CRITICAL",
            "contains_secret_placeholder": False,
            "contains_raw_secret": False,
            "unclassified_fields": 0,
        },
        "reviews": [
            {
                "role": "compatibility",
                "identity": "synthetic-compatibility",
                "decision": "APPROVE",
                "timestamp_utc": "2026-08-28T00:00:00Z",
                "signature_ref": "synthetic-signature-1",
            },
            {
                "role": "security",
                "identity": "synthetic-security",
                "decision": "APPROVE",
                "timestamp_utc": "2026-08-28T00:00:00Z",
                "signature_ref": "synthetic-signature-2",
            },
        ],
        "signature": {
            "algorithm": "ed25519",
            "key_id": "synthetic",
            "signature_ref": "synthetic-main-signature",
            "payload_sha256": ZERO,
        },
        "authority_effect": "NONE",
    }


def validate_fixture_schema_semantics() -> None:
    validator = load_validator("schemas/heptabao_oracle_fixture_manifest_v1.schema.json")
    positive = synthetic_fixture()
    errors = list(validator.iter_errors(positive))
    if errors:
        fail("positive fixture manifest rejected: " + "; ".join(error.message for error in errors))
    raw_in_repo = synthetic_fixture()
    raw_in_repo["raw_artifact"]["stored_in_implementation_repo"] = True
    if not list(validator.iter_errors(raw_in_repo)):
        fail("fixture schema accepted raw artifact in implementation repository")
    live_secret = synthetic_fixture()
    live_secret["raw_artifact"]["contains_live_secret"] = True
    if not list(validator.iter_errors(live_secret)):
        fail("fixture schema accepted live secret capture")
    ignored_security = synthetic_fixture()
    ignored_security["normalization"]["ignored_security_fields"] = 1
    if not list(validator.iter_errors(ignored_security)):
        fail("fixture schema accepted ignored security field")


def validate_status(surface_count: int, endpoint_count: int) -> None:
    status = json_map("qualifications/H01/H01-IMPLEMENTATION-STATUS.json")
    if status.get("work_status") != "SAFE_PUBLIC_AND_SYNTHETIC_FOUNDATION_ACTIVE":
        fail("unexpected H01 work status")
    delivered = status.get("delivered", {})
    if delivered.get("surface_catalog_items") != surface_count or delivered.get("endpoint_seed_items") != endpoint_count:
        fail("H01 implementation status count mismatch")
    if delivered.get("synthetic_side_effect_contracts") != 1:
        fail("H01 status must bind exactly one synthetic side-effect contract")
    capture = status.get("capture_evidence", {})
    if any(capture.get(key) != 0 for key in ("raw_restricted_fixtures", "black_box_sanitized_fixtures", "signed_provenance_transfers", "reviewed_normalization_rules", "qualified_fixtures")):
        fail("H01 status falsely claims capture/review/qualification evidence")
    if capture.get("synthetic_contract_fixtures") != 1:
        fail("H01 status must bind exactly one synthetic contract fixture")
    if status.get("qualification", {}).get("status") != "NOT_QUALIFIED":
        fail("H01 must remain NOT_QUALIFIED")
    if status.get("authority_effect") != "NONE":
        fail("H01 status has an authority effect")
    for name, value in status.get("authority_flags", {}).items():
        if value is not False:
            fail(f"H01 authority flag unexpectedly enabled: {name}")


def scan_forbidden_material() -> None:
    markers = [
        "-----BEGIN " + "PRIVATE KEY-----",
        "-----BEGIN OPENSSH " + "PRIVATE KEY-----",
        "hvs" + ".",
        "hvb" + ".",
        "gh" + "p_",
    ]
    roots = [ROOT / "oracle", ROOT / "tests/oracle"]
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for marker in markers:
                if marker in text:
                    fail(f"forbidden secret/private-key marker in {path.relative_to(ROOT)}")


def main() -> int:
    try:
        require_files()
        validate_baseline()
        work_packages = catalog_work_packages()
        profiles = profile_ids()
        surfaces = validate_surface_catalog(work_packages, profiles)
        endpoints = validate_endpoint_seed(work_packages)
        rules = validate_normalization_policy()
        validate_fixture_schema_semantics()
        validate_status(surfaces, endpoints)
        scan_forbidden_material()
    except (ValidationFailure, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"HeptaBao H01 Oracle validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "HeptaBao H01 Oracle validation passed: "
        f"surfaces={surfaces} endpoints={endpoints} normalization_rules={rules} "
        "captured=0 qualified=0 authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
