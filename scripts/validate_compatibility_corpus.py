#!/usr/bin/env python3
"""Validate the exact OpenBao compatibility denominator and fixture mapping."""
from __future__ import annotations

import ast
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "qa/openbao-acceptance/complete_surface_corpus_v1.json"
ACCEPTANCE_PATH = ROOT / "qa/openbao-acceptance/acceptance.py"
EXPECTED_SCHEMA = "heptabao.compatibility-corpus.v1"
FALSE_CLAIMS: dict[str, Any] = {
    "complete_fixture_coverage": False,
    "independent_observation_complete": False,
    "compatibility_claim": False,
    "production_authority": False,
    "authority_effect": "NONE",
}
VALID_FIXTURE_STATES = {"IMPLEMENTED_SCOPED", "DEFINED_NOT_IMPLEMENTED"}


def _mapping(path: Path, label: str) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a mapping")
    return value


def _json_mapping(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a mapping")
    return value


def acceptance_cases(path: Path = ACCEPTANCE_PATH) -> set[str]:
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in module.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "CASES" for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if not isinstance(value, dict):
                raise ValueError("acceptance CASES must be a mapping")
            result: set[str] = set()
            for module_name, names in value.items():
                if not isinstance(module_name, str) or not isinstance(names, list):
                    raise ValueError("acceptance CASES contains an invalid module")
                for name in names:
                    if not isinstance(name, str):
                        raise ValueError("acceptance CASES contains a non-string case")
                    case_id = f"{module_name}.{name}"
                    if case_id in result:
                        raise ValueError(f"acceptance CASES duplicates {case_id}")
                    result.add(case_id)
            return result
    raise ValueError("acceptance.py does not define CASES")


def inventory_surfaces(inventory: dict[str, Any]) -> tuple[dict[str, dict[str, str]], int]:
    categories = inventory.get("categories")
    if not isinstance(categories, list) or not categories:
        raise ValueError("surface inventory categories must be a nonempty list")
    surfaces: dict[str, dict[str, str]] = {}
    for category in categories:
        if not isinstance(category, dict) or not isinstance(category.get("id"), str):
            raise ValueError("surface inventory category is invalid")
        items = category.get("items")
        if not isinstance(items, list):
            raise ValueError(f"surface inventory category {category.get('id')} has invalid items")
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("surface inventory item is invalid")
            surface_id = item.get("id")
            criticality = item.get("criticality")
            if not isinstance(surface_id, str) or not isinstance(criticality, str):
                raise ValueError("surface inventory item lacks id or criticality")
            if surface_id in surfaces:
                raise ValueError(f"surface inventory duplicates {surface_id}")
            surfaces[surface_id] = {
                "category": category["id"],
                "criticality": criticality,
            }
    return surfaces, len(categories)


def validate(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    corpus_path = root / CORPUS_PATH.relative_to(ROOT)
    acceptance_path = root / ACCEPTANCE_PATH.relative_to(ROOT)
    if not corpus_path.is_file():
        return [f"missing compatibility corpus: {corpus_path.relative_to(root).as_posix()}"]
    try:
        corpus = _json_mapping(corpus_path, "compatibility corpus")
        inventory_section = corpus.get("inventory")
        if not isinstance(inventory_section, dict):
            return ["compatibility corpus inventory must be a mapping"]
        inventory_value = inventory_section.get("path")
        if not isinstance(inventory_value, str):
            return ["compatibility corpus inventory path must be a string"]
        inventory_path = root / inventory_value
        inventory = _mapping(inventory_path, "surface inventory")
        inventory_by_id, category_count = inventory_surfaces(inventory)
        expected_cases = acceptance_cases(acceptance_path)
    except (OSError, ValueError, json.JSONDecodeError, SyntaxError, yaml.YAMLError) as error:
        return [str(error)]

    if corpus.get("schema") != EXPECTED_SCHEMA:
        errors.append(f"compatibility corpus schema must be {EXPECTED_SCHEMA}")
    target = corpus.get("target")
    if not isinstance(target, dict):
        errors.append("compatibility corpus target must be a mapping")
    else:
        if target.get("product") != "OpenBao" or target.get("version") != "2.6.2":
            errors.append("compatibility corpus target must be exact OpenBao 2.6.2")
        if target.get("baseline_id") != inventory.get("baseline_id"):
            errors.append("compatibility corpus baseline does not match the inventory")

    actual_inventory_digest = hashlib.sha256(inventory_path.read_bytes()).hexdigest()
    if inventory_section.get("sha256") != actual_inventory_digest:
        errors.append("compatibility corpus inventory SHA-256 is stale or invalid")
    if inventory_section.get("surface_count") != len(inventory_by_id):
        errors.append("compatibility corpus surface count does not match the inventory")
    if inventory_section.get("category_count") != category_count:
        errors.append("compatibility corpus category count does not match the inventory")

    entries = corpus.get("surfaces")
    if not isinstance(entries, list):
        return errors + ["compatibility corpus surfaces must be a list"]
    seen_surfaces: set[str] = set()
    seen_cases: set[str] = set()
    fixture_states: Counter[str] = Counter()
    for index, entry in enumerate(entries):
        label = f"compatibility corpus surface[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{label} must be a mapping")
            continue
        surface_id = entry.get("surface_id")
        if not isinstance(surface_id, str) or surface_id not in inventory_by_id:
            errors.append(f"{label} references an unknown surface")
            continue
        if surface_id in seen_surfaces:
            errors.append(f"compatibility corpus duplicates surface {surface_id}")
        seen_surfaces.add(surface_id)
        expected = inventory_by_id[surface_id]
        if entry.get("category") != expected["category"]:
            errors.append(f"{surface_id} category does not match inventory")
        if entry.get("criticality") != expected["criticality"]:
            errors.append(f"{surface_id} criticality does not match inventory")
        minimum = entry.get("minimum_observations")
        if not isinstance(minimum, int) or isinstance(minimum, bool) or not 1 <= minimum <= 65_535:
            errors.append(f"{surface_id} minimum_observations is invalid")
        state = entry.get("fixture_state")
        if state not in VALID_FIXTURE_STATES:
            errors.append(f"{surface_id} fixture_state is invalid")
            continue
        fixture_states[state] += 1
        cases = entry.get("fixture_case_ids")
        if not isinstance(cases, list) or not all(isinstance(case, str) for case in cases):
            errors.append(f"{surface_id} fixture_case_ids must be a string list")
            continue
        if len(cases) != len(set(cases)):
            errors.append(f"{surface_id} contains duplicate fixture cases")
        if state == "IMPLEMENTED_SCOPED":
            if not cases:
                errors.append(f"{surface_id} is implemented without an executable case")
            if minimum != len(cases):
                errors.append(f"{surface_id} minimum must equal its exact scoped case count")
        elif cases:
            errors.append(f"{surface_id} has cases but remains DEFINED_NOT_IMPLEMENTED")
        for case in cases:
            if case not in expected_cases:
                errors.append(f"{surface_id} references unknown acceptance case {case}")
            if case in seen_cases:
                errors.append(f"acceptance case {case} is mapped to multiple surfaces")
            seen_cases.add(case)
        if entry.get("independent_observation_state") != "EXTERNAL_REQUIRED":
            errors.append(f"{surface_id} must remain EXTERNAL_REQUIRED before exact-head execution")

    inventory_ids = set(inventory_by_id)
    if seen_surfaces != inventory_ids:
        missing = sorted(inventory_ids - seen_surfaces)
        extra = sorted(seen_surfaces - inventory_ids)
        if missing:
            errors.append("compatibility corpus is missing surfaces: " + ", ".join(missing))
        if extra:
            errors.append("compatibility corpus has extra surfaces: " + ", ".join(extra))
    if seen_cases != expected_cases:
        missing_cases = sorted(expected_cases - seen_cases)
        extra_cases = sorted(seen_cases - expected_cases)
        if missing_cases:
            errors.append("acceptance cases missing from corpus: " + ", ".join(missing_cases))
        if extra_cases:
            errors.append("corpus contains extra acceptance cases: " + ", ".join(extra_cases))

    summary = corpus.get("coverage_summary")
    if not isinstance(summary, dict):
        errors.append("compatibility corpus coverage_summary must be a mapping")
    else:
        expected_summary = {
            "implemented_surface_count": fixture_states["IMPLEMENTED_SCOPED"],
            "defined_not_implemented_surface_count": fixture_states["DEFINED_NOT_IMPLEMENTED"],
            "fixture_case_count": len(seen_cases),
            "independently_observed_current_exact_head_surface_count": 0,
        }
        for key, expected in expected_summary.items():
            if summary.get(key) != expected:
                errors.append(f"compatibility corpus summary {key} must equal {expected}")

    claims = corpus.get("claims")
    if not isinstance(claims, dict):
        errors.append("compatibility corpus claims must be a mapping")
    else:
        for key, expected in FALSE_CLAIMS.items():
            if claims.get(key) != expected:
                errors.append(f"compatibility corpus must keep {key}={expected!r}")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(f"compatibility-corpus: ERROR: {error}", file=sys.stderr)
        return 1
    print("compatibility-corpus: PASS (60 surfaces, 44 scoped cases, 0 exact-head independent surfaces)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
