#!/usr/bin/env python3
"""Authoritative repository-side admission wrapper for V2.5 external evidence."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Sequence

from heptabao_external_evidence_io_v2_5 import (
    EvidenceIoError,
    load_json_file,
    sha256_hex,
    verify_artifacts,
)
from validate_external_evidence_v2_5 import EvidenceError, load_trust_store, validate_document

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--trust-store", required=True, type=Path)
    parser.add_argument("--expected-trust-store-sha256", required=True)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-gate", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    if not HEX40.fullmatch(args.expected_commit) or not HEX40.fullmatch(args.expected_tree):
        print("REJECTED: expected commit/tree must be lowercase Git object IDs", file=sys.stderr)
        return 2
    if not HEX64.fullmatch(args.expected_trust_store_sha256):
        print("REJECTED: trust-store digest must be lowercase SHA-256", file=sys.stderr)
        return 2
    try:
        evidence_raw, evidence = load_json_file(args.evidence)
        del evidence_raw
        trust_raw, trust_document = load_json_file(args.trust_store)
        observed_trust_digest = sha256_hex(trust_raw)
        if observed_trust_digest != args.expected_trust_store_sha256:
            raise EvidenceIoError("external trust-store SHA-256 does not match the expected root")
        trusted_keys = load_trust_store(trust_document)
        verify_artifacts(evidence, args.artifact_root)
        admission = validate_document(
            evidence,
            expected_repository=args.expected_repository,
            expected_commit=args.expected_commit,
            expected_tree=args.expected_tree,
            trusted_keys=trusted_keys,
            expected_gate=args.expected_gate,
        )
    except (EvidenceIoError, EvidenceError, OSError, json.JSONDecodeError) as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "ADMISSIBLE_EVIDENCE_NOT_AUTHORITY",
                "gate_id": admission.gate_id,
                "subject_commit": admission.subject_commit,
                "canonical_payload_sha256": admission.canonical_payload_sha256,
                "trust_store_sha256": args.expected_trust_store_sha256,
                "artifact_count": admission.artifact_count,
                "case_count": admission.case_count,
                "signer_count": admission.signer_count,
                "authority_effect": "NONE",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
