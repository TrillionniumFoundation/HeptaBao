#!/usr/bin/env python3
"""Cross-file validation for the stacked H01/H02 next-foundation branch."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from yaml12_loader import safe_load_yaml12

ROOT = Path(__file__).resolve().parents[1]

CONFIG_FILES = [
    "oracle/inventory/openbao-v2.6.2/config-core-seed.yaml",
    "oracle/inventory/openbao-v2.6.2/config-listener-seed.yaml",
    "oracle/inventory/openbao-v2.6.2/config-storage-seal-ops-seed.yaml",
    "oracle/inventory/openbao-v2.6.2/config-client-environment-seed.yaml",
]
CLI_FILE = "oracle/inventory/openbao-v2.6.2/cli-command-seed.yaml"
REGRESSION_FILE = "oracle/advisories/openbao-v2.6-regression-registry.yaml"
SIDE_EFFECT_INPUT = "oracle/fixtures/synthetic/h01-side-effect-health.input.json"
SIDE_EFFECT_OUTPUT = "oracle/fixtures/synthetic/h01-side-effect-health.observation.json"
SIDE_EFFECT_PROVENANCE = "oracle/fixtures/synthetic/h01-side-effect-health.provenance.yaml"
H01_STATUS = "qualifications/H01/H01-IMPLEMENTATION-STATUS.json"
H02_STATUS = "qualifications/H02/H02-IMPLEMENTATION-STATUS.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ValidationFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationFailure(message)


def yaml_map(path: str) -> dict[str, Any]:
    value = safe_load_yaml12((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path}: expected mapping")
    return value


def json_map(path: str) -> dict[str, Any]:
    value = json.loads((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path}: expected object")
    return value


def validator(path: str) -> Draft202012Validator:
    schema = json_map(path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def schema_validate(path: str, schema_path: str, value: dict[str, Any]) -> None:
    errors = sorted(validator(schema_path).iter_errors(value), key=lambda error: list(error.path))
    if errors:
        rendered = "; ".join(error.message for error in errors[:8])
        fail(f"{path}: {rendered}")


def work_package_ids() -> set[str]:
    catalog = yaml_map("planning/HEPTABAO_WORK_PACKAGE_CATALOG_V1_1.yaml")
    result: set[str] = set()
    for gate_body in catalog["gates"].values():
        for entry in gate_body["packages"]:
            result.add(str(entry).split(":", 1)[0])
    return result


def validate_config_inventories(work_packages: set[str]) -> int:
    ids: set[str] = set()
    key_paths: set[str] = set()
    total = 0
    schema_path = "schemas/heptabao_oracle_config_inventory_v1.schema.json"
    for path in CONFIG_FILES:
        value = yaml_map(path)
        schema_validate(path, schema_path, value)
        if value["status"] != "SEED" or value["authority_effect"] != "NONE":
            fail(f"{path}: inventory must remain authority-free SEED")
        entries = value["entries"]
        coverage = value["coverage"]
        if coverage["total_seeded"] != len(entries):
            fail(f"{path}: total_seeded does not match entries")
        if coverage["unknown_semantics"] != len(entries):
            fail(f"{path}: every seed entry must remain unknown until captured")
        for field in ("captured", "reviewed", "qualified", "unowned_critical"):
            if coverage[field] != 0:
                fail(f"{path}: {field} must remain zero")
        for entry in entries:
            total += 1
            entry_id = entry["id"]
            key_path = entry["key_path"]
            if entry_id in ids:
                fail(f"duplicate config ID: {entry_id}")
            if key_path in key_paths:
                fail(f"duplicate config key path: {key_path}")
            ids.add(entry_id)
            key_paths.add(key_path)
            missing_wp = set(entry["owner_work_packages"]) - work_packages
            if missing_wp:
                fail(f"{entry_id}: unknown work packages {sorted(missing_wp)}")
            if entry["observation_status"] != "IDENTIFIED":
                fail(f"{entry_id}: seed must remain IDENTIFIED")
            if entry["fixture_status"] not in {"NONE", "PLANNED"}:
                fail(f"{entry_id}: no capture/review/qualification is evidenced")
            if entry["secret_bearing"] == "YES" and entry["fixture_status"] != "NONE":
                fail(f"{entry_id}: raw secret-bearing configuration cannot have a repository fixture")
            if entry["failure_policy"] == "UNKNOWN" and entry["criticality"].endswith("CRITICAL"):
                fail(f"{entry_id}: critical seed lacks conservative failure-policy classification")
    if total != 52:
        fail(f"config seed count mismatch: {total} != 52")
    return total


def validate_cli_inventory(work_packages: set[str]) -> int:
    value = yaml_map(CLI_FILE)
    schema_validate(CLI_FILE, "schemas/heptabao_oracle_cli_inventory_v1.schema.json", value)
    if value["status"] != "SEED" or value["authority_effect"] != "NONE":
        fail("CLI inventory must remain authority-free SEED")
    commands = value["commands"]
    coverage = value["coverage"]
    if coverage["total_seeded"] != len(commands):
        fail("CLI total_seeded does not match command count")
    for field in ("captured", "reviewed", "qualified", "unowned_critical"):
        if coverage[field] != 0:
            fail(f"CLI coverage {field} must remain zero")
    if coverage["unknown_semantics"] != len(commands):
        fail("all CLI seed semantics must remain unknown before capture")

    ids: set[str] = set()
    command_paths: set[tuple[str, ...]] = set()
    operator_critical = 0
    for command in commands:
        command_id = command["id"]
        path = tuple(command["command_path"])
        if command_id in ids:
            fail(f"duplicate CLI command ID: {command_id}")
        if path in command_paths:
            fail(f"duplicate CLI command path: {' '.join(path)}")
        ids.add(command_id)
        command_paths.add(path)
        if command["criticality"] == "OPERATOR_CRITICAL":
            operator_critical += 1
        missing_wp = set(command["owner_work_packages"]) - work_packages
        if missing_wp:
            fail(f"{command_id}: unknown work packages {sorted(missing_wp)}")
        if command["observation_status"] != "IDENTIFIED":
            fail(f"{command_id}: seed must remain IDENTIFIED")
        if command["fixture_status"] not in {"NONE", "PLANNED"}:
            fail(f"{command_id}: CLI seed cannot claim capture or review")
        if command["secret_bearing"] == "YES" and command["fixture_status"] != "NONE":
            fail(f"{command_id}: secret-bearing CLI output cannot be committed as a repository fixture")
        if command["operation_class"] == "PURE_READ" and set(command["side_effect_domains"]) != {"NONE"}:
            fail(f"{command_id}: PURE_READ declares non-empty side effects")
        if command["operation_class"] == "UNKNOWN" and command["criticality"] == "STANDARD":
            fail(f"{command_id}: unknown operation class cannot be standard criticality")
    if len(commands) != 30:
        fail(f"CLI seed count mismatch: {len(commands)} != 30")
    if coverage["operator_critical_total"] != operator_critical:
        fail(
            "CLI operator-critical coverage mismatch: "
            f"declared={coverage['operator_critical_total']} actual={operator_critical}"
        )
    if coverage["operator_critical_captured"] != 0:
        fail("no operator-critical CLI capture exists yet")
    return len(commands)


def validate_regression_registry(work_packages: set[str]) -> int:
    value = yaml_map(REGRESSION_FILE)
    schema_validate(
        REGRESSION_FILE,
        "schemas/heptabao_oracle_regression_registry_v1.schema.json",
        value,
    )
    if value["status"] != "SEED" or value["authority_effect"] != "NONE":
        fail("regression registry must remain authority-free SEED")
    latest = value["latest_release_observation"]
    if latest["tag"] != "v2.6.2" or latest["commit_sha"] != "dd9c19c37a878cf4a81b18efb8d6f0599c7da923":
        fail("regression registry latest release baseline mismatch")
    entries = value["entries"]
    ids: set[str] = set()
    for entry in entries:
        entry_id = entry["id"]
        if entry_id in ids:
            fail(f"duplicate regression ID: {entry_id}")
        ids.add(entry_id)
        missing_wp = set(entry["required_work_packages"]) - work_packages
        if missing_wp:
            fail(f"{entry_id}: unknown work packages {sorted(missing_wp)}")
        if entry["fixture_status"] != "PLANNED":
            fail(f"{entry_id}: regression fixture must remain PLANNED")
        if entry["review_status"] != "PENDING" or entry["disposition"] != "PENDING":
            fail(f"{entry_id}: regression cannot claim review/disposition")
        if entry["authority_effect"] != "NONE":
            fail(f"{entry_id}: regression authority must be NONE")
    coverage = value["coverage"]
    if coverage["identified"] != len(entries) or coverage["fixture_planned"] != len(entries):
        fail("regression coverage count mismatch")
    for field in ("fixture_implemented", "reviewed", "qualified", "unowned_critical", "unclassified"):
        if coverage[field] != 0:
            fail(f"regression coverage {field} must remain zero")
    if len(entries) != 21:
        fail(f"regression seed count mismatch: {len(entries)} != 21")
    return len(entries)


def load_side_effect_module() -> Any:
    path = ROOT / "scripts" / "oracle_side_effect_diff_v1.py"
    spec = importlib.util.spec_from_file_location("oracle_side_effect_diff_v1", path)
    if spec is None or spec.loader is None:
        fail("cannot load oracle_side_effect_diff_v1.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_synthetic_side_effect() -> int:
    input_value = json_map(SIDE_EFFECT_INPUT)
    output_value = json_map(SIDE_EFFECT_OUTPUT)
    schema_validate(
        SIDE_EFFECT_OUTPUT,
        "schemas/heptabao_oracle_side_effect_observation_v1.schema.json",
        output_value,
    )
    module = load_side_effect_module()
    recomputed = module.build_observation(input_value)
    if recomputed != output_value:
        fail("synthetic side-effect observation is not reproducible from its input")
    digest = output_value["sanitized_capture_digest_sha256"]
    if SHA256_RE.fullmatch(digest) is None:
        fail("synthetic side-effect digest is invalid")
    if output_value["capture_kind"] != "SYNTHETIC_CONTRACT":
        fail("synthetic fixture incorrectly claims black-box Oracle capture")
    if output_value["raw_capture_digest_sha256"] is not None:
        fail("synthetic fixture must have no raw Oracle digest")
    if output_value["review_status"] != "PENDING":
        fail("synthetic fixture review must remain pending")
    if output_value["authority_effect"] != "NONE" or output_value["secret_material_present"] is not False:
        fail("synthetic side-effect fixture has unsafe authority/secret classification")

    provenance = yaml_map(SIDE_EFFECT_PROVENANCE)
    expected = {
        "status": "SYNTHETIC_LOCAL_NO_ORACLE_EVIDENCE_NO_TRANSFER",
        "raw_oracle_capture": False,
        "openbao_process_executed": False,
        "secret_material_present": False,
        "implementation_consumable": True,
        "compatibility_evidence": False,
        "qualification_evidence": False,
        "review_status": "PENDING",
        "transfer_record": None,
        "authority_effect": "NONE",
    }
    for key, expected_value in expected.items():
        if provenance.get(key) != expected_value:
            fail(f"synthetic provenance {key} mismatch: {provenance.get(key)!r}")
    if provenance.get("sanitized_capture_digest_sha256") != digest:
        fail("synthetic provenance does not bind the observation digest")
    return 1


def validate_statuses(config_count: int, cli_count: int, regression_count: int) -> None:
    h01 = json_map(H01_STATUS)
    if h01["qualification"]["status"] != "NOT_QUALIFIED":
        fail("H01 must remain NOT_QUALIFIED")
    if any(h01["authority_flags"].values()):
        fail("H01 authority flags must all remain false")
    if h01["authority_effect"] != "NONE":
        fail("H01 authority_effect must be NONE")
    delivered = h01["delivered"]
    expected_counts = {
        "config_seed_items": config_count,
        "cli_seed_items": cli_count,
        "regression_seed_items": regression_count,
        "synthetic_side_effect_contracts": 1,
    }
    for key, expected_value in expected_counts.items():
        if delivered.get(key) != expected_value:
            fail(f"H01 delivered {key} mismatch: {delivered.get(key)!r} != {expected_value}")
    capture = h01["capture_evidence"]
    for key in (
        "raw_restricted_fixtures",
        "black_box_sanitized_fixtures",
        "signed_provenance_transfers",
        "reviewed_normalization_rules",
        "qualified_fixtures",
    ):
        if capture.get(key) != 0:
            fail(f"H01 capture evidence {key} must remain zero")

    h02 = json_map(H02_STATUS)
    if h02["qualification"]["status"] != "NOT_QUALIFIED":
        fail("H02 must remain NOT_QUALIFIED")
    if any(h02["authority_flags"].values()):
        fail("H02 authority flags must all remain false")
    if h02["candidate_counts"]["identified"] != 25:
        fail("H02 identified candidate count mismatch")
    if h02["candidate_counts"]["selected_for_prototype"] != 0:
        fail("H02 cannot select a candidate without a signed receipt")
    if h02["selection_receipts"] != [] or h02["authority_effect"] != "NONE":
        fail("H02 selection/authority must remain empty and NONE")


def main() -> int:
    try:
        work_packages = work_package_ids()
        config_count = validate_config_inventories(work_packages)
        cli_count = validate_cli_inventory(work_packages)
        regression_count = validate_regression_registry(work_packages)
        synthetic_count = validate_synthetic_side_effect()
        validate_statuses(config_count, cli_count, regression_count)
    except (ValidationFailure, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"H01/H02 next-foundation validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "H01/H02 next-foundation validation passed: "
        f"config={config_count} cli={cli_count} regressions={regression_count} "
        f"synthetic_side_effects={synthetic_count} H02_candidates=25 selected=0 authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
