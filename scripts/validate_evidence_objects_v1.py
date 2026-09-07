#!/usr/bin/env python3
"""Semantic checks for HeptaBao receipts, claims, grants, revocations and releases."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
ZERO = "0" * 64
SHA40 = "0" * 40

SCHEMAS = {
    "heptabao.qualification-receipt.v2": "schemas/heptabao_qualification_receipt_v2.schema.json",
    "heptabao.compatibility-claim.v1": "schemas/heptabao_compatibility_claim_v1.schema.json",
    "heptabao.authority-grant.v1": "schemas/heptabao_authority_grant_v1.schema.json",
    "heptabao.receipt-revocation.v1": "schemas/heptabao_receipt_revocation_v1.schema.json",
    "heptabao.release-attestation.v1": "schemas/heptabao_release_attestation_v1.schema.json",
}

OBJECT_ROOTS = {
    "heptabao.qualification-receipt.v2": ROOT / "qualifications" / "receipts",
    "heptabao.compatibility-claim.v1": ROOT / "compatibility" / "claims",
    "heptabao.authority-grant.v1": ROOT / "authority" / "grants",
    "heptabao.receipt-revocation.v1": ROOT / "authority" / "revocations",
    "heptabao.release-attestation.v1": ROOT / "releases" / "attestations",
}


class SemanticError(RuntimeError):
    pass


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise SemanticError(f"timestamp lacks timezone: {value}")
    return parsed.astimezone(timezone.utc)


def distinct_approvals(value: dict[str, Any], minimum: int) -> set[str]:
    approvals = value.get("approvals", [])
    identities = {entry["identity"] for entry in approvals if entry.get("decision") == "APPROVE"}
    if len(identities) < minimum:
        raise SemanticError(f"requires at least {minimum} distinct approving identities")
    return identities


def validate_time_window(value: dict[str, Any], issued_key: str = "issued_at_utc") -> None:
    issued = parse_time(value[issued_key])
    if "not_before_utc" in value and parse_time(value["not_before_utc"]) < issued:
        raise SemanticError("not-before precedes issuance")
    expires = parse_time(value["expires_at_utc"] if "expires_at_utc" in value else value["valid_until_utc"])
    if expires <= issued:
        raise SemanticError("expiry must be strictly after issuance")


def validate_qualification(value: dict[str, Any]) -> None:
    validate_time_window(value, "generated_at_utc")
    if value["authority_effect"] != "NONE":
        raise SemanticError("qualification authority_effect must be NONE")
    if value["status"] == "QUALIFIED":
        if value["test_summary"]["failed"] or value["test_summary"]["unknown"]:
            raise SemanticError("QUALIFIED receipt has failed/unknown tests")
        findings = value["findings"]
        if findings["critical_open"] or findings["high_open"] or findings["unclassified"]:
            raise SemanticError("QUALIFIED receipt has blocking findings")
        if any(lane["status"] != "PASS" for lane in value["test_summary"]["required_lanes"]):
            raise SemanticError("QUALIFIED receipt has a non-PASS required lane")
        if any(gate["status"] != "PASS" for gate in value["exit_gates"]):
            raise SemanticError("QUALIFIED receipt has a non-PASS exit gate")
        distinct_approvals(value, 3)


def validate_claim(value: dict[str, Any]) -> None:
    validate_time_window(value)
    if value["authority_effect"] != "NONE":
        raise SemanticError("compatibility claim authority_effect must be NONE")
    distinct_approvals(value, 3)
    if not value["qualification_receipts"]:
        raise SemanticError("compatibility claim lacks qualification receipts")
    if value["revocation_status"] != "ACTIVE":
        raise SemanticError("only ACTIVE claims may be consumed")


def authority_policy() -> dict[str, Any]:
    return yaml.safe_load((ROOT / "planning/HEPTABAO_AUTHORITY_POLICY_V1.yaml").read_text(encoding="utf-8"))


def validate_grant(value: dict[str, Any]) -> None:
    validate_time_window(value)
    if value["revocation_status"] != "ACTIVE":
        raise SemanticError("only ACTIVE grants may authorize")
    identities = distinct_approvals(value, 3)
    roles = {entry["role"] for entry in value["approvals"] if entry.get("decision") == "APPROVE"}
    policy = authority_policy()["authority_kinds"][value["authority_kind"]]
    missing_roles = set(policy["required_roles"]) - roles
    if missing_roles:
        raise SemanticError(f"grant missing required roles: {sorted(missing_roles)}")
    issued = parse_time(value["issued_at_utc"])
    expires = parse_time(value["expires_at_utc"])
    if (expires - issued).total_seconds() > policy["max_ttl_days"] * 86400:
        raise SemanticError("grant TTL exceeds authority policy")
    if len(identities) != len({entry["identity"] for entry in value["approvals"]}):
        raise SemanticError("duplicate approval identity")
    if not value["qualification_receipts"]:
        raise SemanticError("grant lacks qualification receipts")
    scope = value["scope"]
    if not scope["domains"] or not scope["operations"]:
        raise SemanticError("grant scope is empty")


def validate_revocation(value: dict[str, Any]) -> None:
    parse_time(value["effective_at_utc"])
    distinct_approvals(value, 2)
    if value["target"]["id"] == value["revocation_id"]:
        raise SemanticError("revocation cannot target itself")


def validate_release(value: dict[str, Any]) -> None:
    distinct_approvals(value, 4)
    if value["revocation_check"]["active_revocations_affecting_release"] != 0:
        raise SemanticError("release has active revocations")
    channel = value["release"]["channel"]
    if channel in {"general-availability", "lts"}:
        canary = value["canary"]
        if not canary["required"] or not canary["completed"] or canary["duration_days"] < 90:
            raise SemanticError("GA/LTS requires completed 90-day canary")
        support = value["support"]
        if not all(support.values()):
            raise SemanticError("GA/LTS requires all support controls")
    if not value["qualification_receipts"] or not value["compatibility_claims"] or not value["authority_grants"]:
        raise SemanticError("release is missing receipt/claim/grant bindings")


SEMANTIC_VALIDATORS = {
    "heptabao.qualification-receipt.v2": validate_qualification,
    "heptabao.compatibility-claim.v1": validate_claim,
    "heptabao.authority-grant.v1": validate_grant,
    "heptabao.receipt-revocation.v1": validate_revocation,
    "heptabao.release-attestation.v1": validate_release,
}


def approval(role: str, identity: str) -> dict[str, str]:
    return {
        "role": role,
        "identity": identity,
        "decision": "APPROVE",
        "timestamp_utc": "2026-08-28T00:00:00Z",
        "signature_ref": f"signature-{identity}",
    }


def synthetic_grant() -> dict[str, Any]:
    return {
        "schema": "heptabao.authority-grant.v1",
        "grant_id": "HB-AG-SYNTHETIC001",
        "plan_binding": {"plan_id": "HEPTABAO-PLAN-2026-08-28", "revision": "1.1", "plan_digest_sha256": ZERO},
        "authority_kind": "implementation_stage_promotion",
        "scope": {"profile_id": "HB-P0-DEV-MEMORY", "version": "0.1.0", "environment": "development", "domains": ["governance"], "operations": ["activate-H01"]},
        "qualification_receipts": [{"receipt_id": "HB-QR-SYNTHETIC001", "sha256": ZERO}],
        "issued_at_utc": "2026-08-28T00:00:00Z",
        "not_before_utc": "2026-08-28T00:00:00Z",
        "expires_at_utc": "2026-09-27T00:00:00Z",
        "approvals": [approval("program", "program-1"), approval("security", "security-1"), approval("domain", "domain-1")],
        "signature": {"algorithm": "ed25519", "key_id": "synthetic", "signature_ref": "synthetic-signature", "payload_sha256": ZERO},
        "revocation_status": "ACTIVE",
        "revocation_ref": None,
    }


def run_negative_semantics(validators: dict[str, Draft202012Validator]) -> None:
    grant = synthetic_grant()
    schema_errors = list(validators[grant["schema"]].iter_errors(grant))
    if schema_errors:
        raise SemanticError("synthetic valid grant rejected by schema: " + "; ".join(error.message for error in schema_errors))
    validate_grant(grant)

    duplicate = synthetic_grant()
    duplicate["approvals"][1]["identity"] = duplicate["approvals"][0]["identity"]
    try:
        validate_grant(duplicate)
    except SemanticError:
        pass
    else:
        raise SemanticError("duplicate grant approvers were accepted")

    long_ttl = synthetic_grant()
    long_ttl["expires_at_utc"] = "2028-08-28T00:00:00Z"
    try:
        validate_grant(long_ttl)
    except SemanticError:
        pass
    else:
        raise SemanticError("overlong authority grant was accepted")


def main() -> int:
    try:
        validators: dict[str, Draft202012Validator] = {}
        for schema_name, relative in SCHEMAS.items():
            schema = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            validators[schema_name] = Draft202012Validator(schema, format_checker=FormatChecker())

        run_negative_semantics(validators)

        count = 0
        for schema_name, root in OBJECT_ROOTS.items():
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("*.json")):
                value = json.loads(path.read_text(encoding="utf-8"))
                if value.get("schema") != schema_name:
                    raise SemanticError(f"{path.relative_to(ROOT)}: unexpected schema {value.get('schema')!r}")
                errors = list(validators[schema_name].iter_errors(value))
                if errors:
                    raise SemanticError(f"{path.relative_to(ROOT)}: " + "; ".join(error.message for error in errors))
                SEMANTIC_VALIDATORS[schema_name](value)
                count += 1
    except (OSError, ValueError, KeyError, TypeError, SemanticError) as error:
        print(f"HeptaBao evidence validation FAILED: {error}", file=sys.stderr)
        return 1

    print(f"HeptaBao evidence validation passed: repository_objects={count} semantic_negative_tests=2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
