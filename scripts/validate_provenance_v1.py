#!/usr/bin/env python3
"""Validate HeptaBao clean-room provenance records and negative semantics."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/heptabao_source_provenance_record_v1.schema.json"
RECORD_ROOT = ROOT / "provenance"
ZERO = "0" * 64


def review(role: str, number: int) -> dict[str, str]:
    return {
        "role": role,
        "identity": f"synthetic-reviewer-{number}",
        "decision": "APPROVE",
        "timestamp_utc": "2026-08-28T00:00:00Z",
        "signature_ref": f"synthetic-signature-{number}",
    }


def base_record(material_class: str, implementation_consumable: bool) -> dict[str, Any]:
    return {
        "schema": "heptabao.source-provenance-record.v1",
        "record_id": "HB-SP-SYNTHETIC001",
        "material_class": material_class,
        "source": {
            "product": "Synthetic Public Standard",
            "uri_or_reference": "synthetic://standard/v1",
            "version_or_ref": "v1",
            "retrieved_at_utc": "2026-08-28T00:00:00Z",
        },
        "capture": {
            "tool": "synthetic-capture",
            "tool_version": "1",
            "operator_identity": "synthetic-operator",
            "environment_digest_sha256": ZERO,
        },
        "raw_artifact": {
            "restricted_reference": "restricted://synthetic/raw",
            "sha256": ZERO,
            "contains_real_secrets": False,
        },
        "sanitized_artifact": {
            "repository_path": "provenance/synthetic/fixture.json",
            "sha256": ZERO,
            "secret_scan_passed": True,
        },
        "normalization": {
            "policy_id": "synthetic-normalizer-v1",
            "policy_sha256": ZERO,
            "ignored_fields": [],
            "security_reviewed": True,
        },
        "license_disposition": {
            "status": "PUBLIC_FACT_ONLY",
            "license_ids": [],
            "notes": "Synthetic validator fixture",
            "reviewer_identity": "synthetic-legal",
        },
        "security_disposition": {
            "secret_scan": "PASS",
            "sensitive_metadata_review": "PASS",
            "implementation_detail_review": "NOT_APPLICABLE",
            "reviewer_identity": "synthetic-security",
        },
        "transfer": {
            "from_lane": "oracle_specification",
            "to_lane": "independent_implementation",
            "implementation_consumable": implementation_consumable,
            "scope": ["synthetic-validation"],
            "expires_at_utc": "2026-09-28T00:00:00Z",
        },
        "reviews": [review("compatibility", 1), review("security", 2)],
        "signature": {
            "algorithm": "ed25519",
            "key_id": "synthetic-key",
            "signature_ref": "synthetic-record-signature",
            "payload_sha256": ZERO,
        },
    }


def validate_record(validator: Draft202012Validator, path: Path) -> list[str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    return [error.message for error in validator.iter_errors(value)]


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    positive = base_record("PUBLIC_STANDARD", True)
    positive_errors = [error.message for error in validator.iter_errors(positive)]
    if positive_errors:
        print("positive provenance fixture rejected: " + "; ".join(positive_errors), file=sys.stderr)
        return 1

    raw_to_implementation = base_record("BLACK_BOX_RAW_OBSERVATION", True)
    if not list(validator.iter_errors(raw_to_implementation)):
        print("raw Oracle observation was incorrectly allowed into implementation lane", file=sys.stderr)
        return 1

    upstream_source_to_implementation = base_record("UPSTREAM_SOURCE_RESEARCH", True)
    if not list(validator.iter_errors(upstream_source_to_implementation)):
        print("upstream source research was incorrectly marked implementation-consumable", file=sys.stderr)
        return 1

    pending_license = base_record("SANITIZED_ORACLE_FIXTURE", True)
    pending_license["license_disposition"]["status"] = "PENDING"
    if not list(validator.iter_errors(pending_license)):
        print("pending legal disposition was incorrectly allowed into implementation lane", file=sys.stderr)
        return 1

    record_count = 0
    if RECORD_ROOT.is_dir():
        for path in sorted(RECORD_ROOT.rglob("*.json")):
            errors = validate_record(validator, path)
            if errors:
                print(f"{path.relative_to(ROOT)}: " + "; ".join(errors), file=sys.stderr)
                return 1
            record_count += 1

    print(f"HeptaBao provenance validation passed: repository_records={record_count} negative_transfers_rejected=3")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
