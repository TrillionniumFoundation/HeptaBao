#!/usr/bin/env python3
"""Validate H02 crates.io-index evidence without allowing selection or qualification."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from yaml12_loader import safe_load_yaml12

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "planning" / "evidence" / "h02" / "registry"
SCHEMA_PATH = ROOT / "schemas" / "heptabao_dependency_registry_evidence_v1.schema.json"
CATALOG_PATH = ROOT / "planning" / "HEPTABAO_H02_DEPENDENCY_BAKEOFF_V1.yaml"
RESEARCH_ROOT = ROOT / "planning" / "evidence" / "h02"

EXPECTED: dict[str, dict[str, Any]] = {
    "HB-DEP-ASYNC-TOKIO": {
        "file": "HB-DEP-ASYNC-TOKIO.registry.yaml",
        "package": "tokio",
        "version": "1.53.1",
        "capability": "ASYNC_RUNTIME",
        "tag": "tokio-1.53.1",
        "commit_sha": "75fef53d0a8590c2d1dbb63672aa7b7d1ef51155",
        "tree_sha": "26def82f663c2936cbd062e54c8cf8db81fc2a1c",
        "index_path": "to/ki/tokio",
        "index_blob_sha": "b525c7ca48219b6d3f36ad4594b9df2004fa8281",
        "checksum": "202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed",
    },
    "HB-DEP-TLS-RUSTLS": {
        "file": "HB-DEP-TLS-RUSTLS.registry.yaml",
        "package": "rustls",
        "version": "0.23.43",
        "capability": "TLS",
        "tag": "v/0.23.43",
        "commit_sha": "fcf61cdbba30913cfd5b40aefa83989c6233812d",
        "tree_sha": "1e54feebaf4f88da54958096809fbd4649aa7ec1",
        "index_path": "ru/st/rustls",
        "index_blob_sha": "1cdf91587227cdf12d253a0a8e8048c1fc1128fb",
        "checksum": "0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06",
    },
    "HB-DEP-RAFT-OPENRAFT": {
        "file": "HB-DEP-RAFT-OPENRAFT.registry.yaml",
        "package": "openraft",
        "version": "0.10.0-alpha.33",
        "capability": "RAFT",
        "tag": "v0.10.0-alpha.33",
        "commit_sha": "2be3f99a23c0ec734aefc18d1c8e756b35567c35",
        "tree_sha": "84c2f86b6bdffb3f25ffbc7a9341ef7295a5ac28",
        "index_path": "op/en/openraft",
        "index_blob_sha": "db74d6c8621154a5700f716e6f4020783b9a1e7e",
        "checksum": "ba6e911fb3c97faeecb8324b803a37d77a7387d02ee7019fc2a9777569e7f7b8",
    },
}

RESEARCH_FILES = {
    "HB-DEP-ASYNC-TOKIO": "HB-DEP-ASYNC-TOKIO-0001.capture.yaml",
    "HB-DEP-TLS-RUSTLS": "HB-DEP-TLS-RUSTLS-0001.capture.yaml",
    "HB-DEP-RAFT-OPENRAFT": "HB-DEP-RAFT-OPENRAFT.capture.yaml",
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
        fail("prototype selection receipts must remain empty")
    if catalog["production_selection_authority"] is not False or catalog["authority_effect"] != "NONE":
        fail("catalog authority must remain fail closed")

    observed: set[str] = set()
    for candidate_id, expected in EXPECTED.items():
        if candidate_id not in candidates:
            fail(f"canonical candidate missing from catalog: {candidate_id}")
        candidate = candidates[candidate_id]
        if candidate["state"] != "IDENTIFIED":
            fail(f"{candidate_id}: registry evidence cannot promote candidate state")
        if any(value is not None for value in candidate["pin"].values()):
            fail(f"{candidate_id}: reviewed catalog pin is premature")
        if any(value is not None for value in candidate["criteria"].values()):
            fail(f"{candidate_id}: candidate scores must remain null")
        if candidate["qualification"]["selection_receipt"] is not None:
            fail(f"{candidate_id}: selection receipt must remain null")

        path = EVIDENCE_ROOT / expected["file"]
        evidence = load_yaml(path)
        errors = list(validator.iter_errors(evidence))
        if errors:
            fail(f"{path.relative_to(ROOT)}: " + "; ".join(error.message for error in errors))

        if evidence["candidate_id"] != candidate_id or candidate_id in observed:
            fail(f"{candidate_id}: duplicate or mismatched registry evidence")
        observed.add(candidate_id)
        if evidence["capability"] != expected["capability"] or candidate["capability"] != expected["capability"]:
            fail(f"{candidate_id}: capability mismatch")

        release = evidence["release_binding"]
        for field in ("tag", "commit_sha", "tree_sha"):
            if release[field] != expected[field]:
                fail(f"{candidate_id}: release {field} drift")

        source = evidence["registry_source"]
        if source["commit_sha"] != "777d86659770fa5d3eac37c83f3772de7faf0a83":
            fail(f"{candidate_id}: crates.io-index commit drift")
        if source["path"] != expected["index_path"] or source["blob_sha"] != expected["index_blob_sha"]:
            fail(f"{candidate_id}: crates.io-index path/blob drift")

        entry = evidence["registry_entry"]
        if entry["package"] != expected["package"] or entry["version"] != expected["version"]:
            fail(f"{candidate_id}: package/version mismatch")
        if entry["checksum_sha256"] != expected["checksum"]:
            fail(f"{candidate_id}: registry checksum drift")
        if entry["yanked"] is not False:
            fail(f"{candidate_id}: yanked package cannot remain an active candidate")

        byte = evidence["byte_verification"]
        if byte != {
            "status": "UNEXECUTED",
            "crate_download_sha256": None,
            "matches_registry_checksum": False,
            "source_archive_sha256": None,
            "source_archive_digest_kind": "NOT_CAPTURED",
            "package_vcs_commit_sha": None,
            "independent_reproduction_count": 0,
        }:
            fail(f"{candidate_id}: registry metadata attempted to claim byte verification")

        if any(value in {"APPROVED", "REJECTED"} for value in evidence["review_status"].values()):
            fail(f"{candidate_id}: registry capture cannot self-approve review")
        if evidence["selection_state"] != "IDENTIFIED" or evidence["qualification"] is not False:
            fail(f"{candidate_id}: registry capture attempted promotion")
        if evidence["authority_effect"] != "NONE":
            fail(f"{candidate_id}: registry capture attempted authority")

        research = load_yaml(RESEARCH_ROOT / RESEARCH_FILES[candidate_id])
        if research["candidate_id"] != candidate_id:
            fail(f"{candidate_id}: research capture is not bound to the canonical catalog ID")
        if research["release"]["commit_sha"] != release["commit_sha"]:
            fail(f"{candidate_id}: research and registry release commits diverge")

    extra = sorted(
        path.name
        for path in EVIDENCE_ROOT.glob("*.registry.yaml")
        if path.name not in {value["file"] for value in EXPECTED.values()}
    )
    if extra:
        fail(f"unregistered registry evidence files: {extra}")
    return len(observed)


def main() -> int:
    try:
        count = validate()
    except (OSError, ValueError, json.JSONDecodeError, ValidationFailure) as error:
        print(f"H02 dependency registry-evidence validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "H02 dependency registry-evidence validation passed: "
        f"captures={count} bytes_verified=0 independent_reproduction=0 "
        "selection=0 qualification=false authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
