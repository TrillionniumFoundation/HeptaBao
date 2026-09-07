#!/usr/bin/env python3
"""Validate H02 official metadata captures without allowing dependency selection."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from yaml12_loader import safe_load_yaml12

ROOT = Path(__file__).resolve().parents[1]
CAPTURE_ROOT = ROOT / "planning" / "evidence" / "h02"
SCHEMA_PATH = ROOT / "schemas" / "heptabao_dependency_research_capture_v1.schema.json"
CATALOG_PATH = ROOT / "planning" / "HEPTABAO_H02_DEPENDENCY_BAKEOFF_V1.yaml"

EXPECTED = {
    "HB-DEP-ASYNC-TOKIO": {
        "file": "HB-DEP-ASYNC-TOKIO-0001.capture.yaml",
        "capability": "ASYNC_RUNTIME",
        "tag": "tokio-1.53.1",
        "version": "1.53.1",
        "commit_sha": "75fef53d0a8590c2d1dbb63672aa7b7d1ef51155",
        "tree_sha": "26def82f663c2936cbd062e54c8cf8db81fc2a1c",
        "manifest_blob_sha": "e260bbc5bd9f47243ff40ad36b994ba5cf1bd96d",
        "declared_license": "MIT",
        "declared_rust_version": "1.71",
    },
    "HB-DEP-TLS-RUSTLS": {
        "file": "HB-DEP-TLS-RUSTLS-0001.capture.yaml",
        "capability": "TLS",
        "tag": "v/0.23.43",
        "version": "0.23.43",
        "commit_sha": "fcf61cdbba30913cfd5b40aefa83989c6233812d",
        "tree_sha": "1e54feebaf4f88da54958096809fbd4649aa7ec1",
        "manifest_blob_sha": "030ebe7e3f86f4dd16b1aaf87aca74f1a62759a2",
        "declared_license": "Apache-2.0 OR ISC OR MIT",
        "declared_rust_version": "1.71",
    },
    "HB-DEP-RAFT-OPENRAFT": {
        "file": "HB-DEP-RAFT-OPENRAFT.capture.yaml",
        "capability": "RAFT",
        "tag": "v0.10.0-alpha.33",
        "version": "0.10.0-alpha.33",
        "commit_sha": "2be3f99a23c0ec734aefc18d1c8e756b35567c35",
        "tree_sha": "84c2f86b6bdffb3f25ffbc7a9341ef7295a5ac28",
        "manifest_blob_sha": "4fa4ab541c8940cf324b94e950c8f1118433aa32",
        "declared_license": "MIT OR Apache-2.0",
        "declared_rust_version": None,
    },
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
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    catalog = load_yaml(CATALOG_PATH)
    candidates = {candidate["candidate_id"]: candidate for candidate in catalog["candidates"]}
    if catalog["prototype_selection_receipts"] != []:
        fail("catalog unexpectedly contains a prototype selection receipt")
    if catalog["production_selection_authority"] is not False or catalog["authority_effect"] != "NONE":
        fail("catalog has unexpected dependency authority")

    observed: set[str] = set()
    for candidate_id, expected in EXPECTED.items():
        path = CAPTURE_ROOT / expected["file"]
        if not path.is_file():
            fail(f"missing research capture: {path.relative_to(ROOT)}")
        capture = load_yaml(path)
        errors = list(validator.iter_errors(capture))
        if errors:
            fail(f"{path.relative_to(ROOT)}: " + "; ".join(error.message for error in errors))
        if capture["candidate_id"] != candidate_id:
            fail(f"{path.name}: candidate ID must match canonical catalog ID")
        if candidate_id in observed:
            fail(f"duplicate research capture for {candidate_id}")
        observed.add(candidate_id)

        candidate = candidates.get(candidate_id)
        if candidate is None:
            fail(f"research capture references unknown candidate {candidate_id}")
        if candidate["capability"] != capture["capability"] or capture["capability"] != expected["capability"]:
            fail(f"{candidate_id}: capability mismatch")
        if candidate["state"] != "IDENTIFIED":
            fail(f"{candidate_id}: metadata capture must not change candidate state")
        if any(value is not None for value in candidate["pin"].values()):
            fail(f"{candidate_id}: catalog pin must remain null until reviewed evidence is promoted")
        if any(value is not None for value in candidate["criteria"].values()):
            fail(f"{candidate_id}: catalog scores must remain null")
        if candidate["qualification"]["selection_receipt"] is not None:
            fail(f"{candidate_id}: selection receipt must remain null")

        release = capture["release"]
        manifest = capture["manifest_observation"]
        for field in ("tag", "version", "commit_sha", "tree_sha"):
            if release[field] != expected[field]:
                fail(f"{candidate_id}: {field} drift")
        if manifest["manifest_blob_sha"] != expected["manifest_blob_sha"]:
            fail(f"{candidate_id}: manifest blob drift")
        if manifest["declared_license"] != expected["declared_license"]:
            fail(f"{candidate_id}: declared license drift")
        if manifest["declared_rust_version"] != expected["declared_rust_version"]:
            fail(f"{candidate_id}: declared Rust version drift")

        integrity = capture["source_integrity"]
        if integrity["source_archive_sha256"] is not None or integrity["crate_package_checksum"] is not None:
            fail(f"{candidate_id}: official Git metadata capture cannot claim byte verification")
        if capture["selection_state"] != "IDENTIFIED" or capture["authority_effect"] != "NONE":
            fail(f"{candidate_id}: research capture attempted selection or authority")
        reviews = capture["review_status"]
        if reviews["independent_review"] != "PENDING":
            fail(f"{candidate_id}: independent review cannot be self-approved")
        if any(value in {"APPROVED", "EXECUTED_PASS", "EXECUTED", "REJECTED"} for value in reviews.values()):
            fail(f"{candidate_id}: official metadata capture cannot claim completed review/execution")
        if not capture["remaining_evidence"]:
            fail(f"{candidate_id}: remaining evidence list is empty")

    extra = sorted(
        path.name
        for path in CAPTURE_ROOT.glob("*.capture.yaml")
        if path.name not in {item["file"] for item in EXPECTED.values()}
    )
    if extra:
        fail(f"unregistered research-capture files: {extra}")
    return len(observed)


def main() -> int:
    try:
        count = validate()
    except (OSError, ValueError, json.JSONDecodeError, ValidationFailure) as error:
        print(f"H02 dependency research-capture validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "H02 dependency research-capture validation passed: "
        f"captures={count} canonical_ids=true state=IDENTIFIED review=PENDING "
        "byte_verification=0 selection=0 authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
