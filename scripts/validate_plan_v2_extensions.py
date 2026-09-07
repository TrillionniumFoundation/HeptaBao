#!/usr/bin/env python3
"""Cross-document validation for the extended HeptaBao V1.1 planning graph."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
GATES = [f"H{i:02d}" for i in range(28)]
ADR_IDS = [f"ADR-{i:04d}" for i in range(1, 13)]
REQ_PATTERN = re.compile(r"^HB-REQ-H(?:0[0-9]|1[0-9]|2[0-7])-\d{3}$")
WP_PATTERN = re.compile(r"^(H(?:0[0-9]|1[0-9]|2[0-7])-WP\d{2,3}):")


class ValidationFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationFailure(message)


def load(path: str) -> dict[str, Any]:
    value = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path}: expected mapping")
    return value


def work_package_ids() -> set[str]:
    catalog = load("planning/HEPTABAO_WORK_PACKAGE_CATALOG_V1_1.yaml")
    result: set[str] = set()
    for gate, body in catalog["gates"].items():
        if gate not in GATES:
            fail(f"unknown work-package gate: {gate}")
        for item in body["packages"]:
            match = WP_PATTERN.match(item)
            if not match:
                fail(f"invalid work-package entry: {item}")
            result.add(match.group(1))
    return result


def validate_requirements(wp_ids: set[str]) -> None:
    registry = load("planning/HEPTABAO_TRACEABILITY_REQUIREMENTS_V1_1.yaml")
    gates = registry.get("gates")
    if not isinstance(gates, dict) or list(gates) != GATES:
        fail("traceability registry must contain ordered H00..H27")

    ids: set[str] = set()
    count = 0
    required_fields = {
        "id",
        "criticality",
        "statement",
        "owner_domain",
        "source_refs",
        "invariant_refs",
        "work_packages",
        "acceptance",
        "test_lanes",
        "evidence_required",
        "waiver_allowed",
    }
    for gate, requirements in gates.items():
        if not isinstance(requirements, list) or len(requirements) < 2:
            fail(f"{gate}: requires at least two traced requirements")
        for requirement in requirements:
            count += 1
            missing = required_fields - set(requirement)
            if missing:
                fail(f"{gate}: requirement missing fields {sorted(missing)}")
            req_id = requirement["id"]
            if not isinstance(req_id, str) or not REQ_PATTERN.fullmatch(req_id):
                fail(f"invalid requirement ID: {req_id!r}")
            if req_id in ids:
                fail(f"duplicate requirement ID: {req_id}")
            ids.add(req_id)
            if requirement["waiver_allowed"] is not False:
                fail(f"{req_id}: V1.1 critical requirements are non-waivable")
            references = set(requirement["work_packages"])
            missing_wp = references - wp_ids
            if missing_wp:
                fail(f"{req_id}: unknown work-package references {sorted(missing_wp)}")
            for field in ("source_refs", "invariant_refs", "acceptance", "test_lanes", "evidence_required"):
                value = requirement[field]
                if not isinstance(value, list) or not value:
                    fail(f"{req_id}: {field} must be a non-empty list")
    if count < 56:
        fail(f"traceability registry too shallow: {count} < 56")


def validate_risks() -> None:
    register = load("planning/HEPTABAO_RISK_REGISTER_V2.yaml")
    risks = register.get("risks")
    if not isinstance(risks, list) or len(risks) < 32:
        fail("risk register must contain at least 32 governed risks")
    ids: set[str] = set()
    fields = {"id", "category", "event", "impact", "inherent", "controls", "KRI", "trigger", "contingency", "residual", "owner_role", "gates", "status"}
    for risk in risks:
        missing = fields - set(risk)
        if missing:
            fail(f"risk missing fields: {sorted(missing)}")
        risk_id = risk["id"]
        if risk_id in ids:
            fail(f"duplicate risk ID: {risk_id}")
        ids.add(risk_id)
        for score_name in ("inherent", "residual"):
            score = risk[score_name]
            if score["score"] != score["probability"] * score["impact"]:
                fail(f"{risk_id}: invalid {score_name} score")
        unknown_gates = set(risk["gates"]) - set(GATES)
        if unknown_gates:
            fail(f"{risk_id}: unknown gate refs {sorted(unknown_gates)}")
        if not risk["controls"]:
            fail(f"{risk_id}: controls are empty")


def validate_domain_ownership() -> None:
    registry = load("planning/HEPTABAO_DOMAIN_OWNERSHIP_V1.yaml")
    domains = registry.get("domains")
    if not isinstance(domains, dict) or len(domains) < 25:
        fail("domain ownership registry is incomplete")
    for domain, body in domains.items():
        writer = body.get("writer")
        if not isinstance(writer, str) or not writer:
            fail(f"{domain}: exactly one scalar writer is required")
        if isinstance(writer, (list, dict)):
            fail(f"{domain}: multiple/structured writers are forbidden")


def validate_capacity() -> None:
    model = load("planning/HEPTABAO_CAPACITY_AND_BUDGET_MODEL_V1.yaml")
    staffing = model.get("standard_staffing", {})
    tracks = staffing.get("tracks")
    if staffing.get("dedicated_fte") != 34:
        fail("standard dedicated FTE must be the single V1.1 baseline of 34")
    if not isinstance(tracks, dict) or sum(tracks.values()) != 34:
        fail("staffing track allocation must sum to 34 FTE")
    standard = model.get("scenarios", {}).get("standard", {})
    if standard.get("full_c5_window") != "M60-M84":
        fail("standard C5 capacity window must be M60-M84")
    if len(model.get("reforecast_triggers", [])) < 8:
        fail("capacity model has insufficient reforecast triggers")


def validate_review_roles_and_authority() -> None:
    roles = load("planning/HEPTABAO_REVIEW_ROLE_REGISTRY_V1.yaml")
    status = roles.get("status")
    assignments = [identity for role in roles.get("roles", {}).values() for identity in role.get("assigned_identities", [])]
    flags = load("planning/AUTHORITY_FLAGS_V2.yaml")
    active_grants = flags.get("active_grants")
    if status == "BLOCKED_PENDING_INDEPENDENT_IDENTITIES":
        if assignments:
            fail("blocked review registry unexpectedly has assigned identities")
        if active_grants != []:
            fail("authority grants cannot exist while independent identities are blocked")
        for name, value in flags["flags"].items():
            if name != "implementation_started" and value is not False:
                fail(f"{name}: authority enabled while review identities are blocked")


def validate_adrs() -> None:
    registry = load("planning/HEPTABAO_ADR_REGISTRY_V1.yaml")
    adrs = registry.get("adrs")
    if not isinstance(adrs, list) or [adr.get("id") for adr in adrs] != ADR_IDS:
        fail("ADR registry must contain sequential ADR-0001..ADR-0012")
    for adr in adrs:
        if adr.get("status") not in {"ACCEPTED", "SUPERSEDED", "PROPOSED", "REJECTED"}:
            fail(f"{adr.get('id')}: invalid ADR status")
        if not adr.get("decision") or not adr.get("required_roles"):
            fail(f"{adr.get('id')}: decision or required roles missing")


def main() -> int:
    try:
        required = [
            "planning/HEPTABAO_TRACEABILITY_REQUIREMENTS_V1_1.yaml",
            "planning/HEPTABAO_RISK_REGISTER_V2.yaml",
            "planning/HEPTABAO_DOMAIN_OWNERSHIP_V1.yaml",
            "planning/HEPTABAO_CAPACITY_AND_BUDGET_MODEL_V1.yaml",
            "planning/HEPTABAO_REVIEW_ROLE_REGISTRY_V1.yaml",
            "planning/HEPTABAO_ADR_REGISTRY_V1.yaml",
        ]
        missing = [path for path in required if not (ROOT / path).is_file()]
        if missing:
            fail(f"missing extended planning files: {missing}")
        wp_ids = work_package_ids()
        validate_requirements(wp_ids)
        validate_risks()
        validate_domain_ownership()
        validate_capacity()
        validate_review_roles_and_authority()
        validate_adrs()
    except (ValidationFailure, OSError, ValueError, yaml.YAMLError) as error:
        print(f"HeptaBao V1.1 extended validation FAILED: {error}", file=sys.stderr)
        return 1
    print("HeptaBao V1.1 extended validation passed: requirements>=56 risks>=32 domains>=25 ADRs=12 staffing=34")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
