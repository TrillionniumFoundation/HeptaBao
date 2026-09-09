#!/usr/bin/env python3
"""Fail-closed admission for HeptaBao external/control evidence.

This validator deliberately cannot create qualification or authority.  It only
checks that a separately produced evidence object is complete, source-bound,
role-separated, internally consistent and free of failed/unknown cases.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SCHEMA_ID = "HEPTABAO_EXTERNAL_EVIDENCE_V2_5"
AUTHORITY_EFFECT = "NONE"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,191}$")

REQUIRED_CASES: dict[str, frozenset[str]] = {
    "HB-BLK-CTRL-001": frozenset({
        "main-ruleset-enforced", "required-checks-enforced",
        "non-admin-bypass-denied", "force-push-denied", "deletion-denied",
    }),
    "HB-BLK-EXT-001": frozenset({
        "program-review", "product-security-review", "storage-distributed-review",
        "reviewer-independence", "current-head-binding",
    }),
    "HB-BLK-EXT-002": frozenset({
        "license-disposition", "trademark-disposition", "patent-disposition",
        "export-control-disposition", "clean-room-disposition",
    }),
    "HB-BLK-EXT-003": frozenset({
        "private-disclosure-channel", "24x7-roster", "incident-drill",
        "credential-revocation-drill", "forensic-retention-drill",
    }),
    "HB-BLK-EXT-004": frozenset({
        "isolated-release-signer", "kms-hsm-custody", "key-rotation-ceremony",
        "emergency-revocation", "transparency-checkpoint",
    }),
    "HB-BLK-EXT-005": frozenset({
        "restricted-oracle-capture", "deterministic-sanitization",
        "role-separated-transfer", "oracle-artifact-rehash",
        "candidate-artifact-rehash", "complete-surface-differential",
    }),
    "HB-BLK-EXT-006": frozenset({
        "power-cut-campaign", "torn-write-campaign", "fsync-loss-campaign",
        "disk-stall-campaign", "filesystem-corruption-campaign",
        "multi-platform-destructive-campaign",
    }),
    "HB-BLK-EXT-007": frozenset({
        "independent-source-acquisition", "independent-toolchain",
        "independent-runner", "independent-cache-root",
        "independent-signing-root", "exact-output-reproduction",
    }),
}

ROLE_BY_GATE: dict[str, frozenset[str]] = {
    "HB-BLK-CTRL-001": frozenset({"repository-administrator", "control-auditor"}),
    "HB-BLK-EXT-001": frozenset({"program-reviewer", "security-reviewer", "storage-reviewer"}),
    "HB-BLK-EXT-002": frozenset({"legal-counsel", "license-counsel"}),
    "HB-BLK-EXT-003": frozenset({"incident-commander", "security-operations"}),
    "HB-BLK-EXT-004": frozenset({"release-custodian", "hsm-custodian"}),
    "HB-BLK-EXT-005": frozenset({"oracle-custodian", "compatibility-reviewer"}),
    "HB-BLK-EXT-006": frozenset({"platform-qualifier", "storage-qualifier"}),
    "HB-BLK-EXT-007": frozenset({"independent-reproducer"}),
}

TOP_KEYS = frozenset({
    "schema_id", "gate_id", "subject", "issuer", "separation", "artifacts",
    "cases", "signatures", "created_at", "expires_at", "authority_effect",
    "claims",
})
SUBJECT_KEYS = frozenset({"repository", "commit", "tree", "profile"})
ISSUER_KEYS = frozenset({"actor_id", "role", "organization", "public_key_id"})
SEPARATION_KEYS = frozenset({
    "source_author_ids", "implementation_control_root", "evidence_control_root",
    "runner_control_root", "signing_control_root",
})
ARTIFACT_KEYS = frozenset({"path", "sha256", "bytes", "media_type"})
CASE_KEYS = frozenset({"id", "status", "artifact_sha256", "observed_at"})
SIGNATURE_KEYS = frozenset({
    "signer_actor_id", "role", "public_key_id", "signed_at", "algorithm",
    "signature", "payload_sha256",
})
CLAIM_KEYS = frozenset({
    "qualification", "compatibility_claim", "production_authority",
    "migration_authority", "release_authority",
})


class EvidenceError(ValueError):
    """The evidence object is not admissible."""


@dataclass(frozen=True)
class Admission:
    gate_id: str
    subject_commit: str
    canonical_payload_sha256: str
    artifact_count: int
    case_count: int
    signer_count: int


def _object(value: Any, where: str, keys: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{where} must be an object")
    unknown = set(value) - keys
    missing = keys - set(value)
    if unknown:
        raise EvidenceError(f"{where} contains unknown keys: {sorted(unknown)}")
    if missing:
        raise EvidenceError(f"{where} is missing keys: {sorted(missing)}")
    return value


def _sequence(value: Any, where: str, *, minimum: int = 1, maximum: int = 4096) -> Sequence[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise EvidenceError(f"{where} must contain {minimum}..{maximum} entries")
    return value


def _token(value: Any, where: str) -> str:
    if not isinstance(value, str) or not TOKEN.fullmatch(value):
        raise EvidenceError(f"{where} is invalid")
    return value


def _timestamp(value: Any, where: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvidenceError(f"{where} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EvidenceError(f"{where} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise EvidenceError(f"{where} must be UTC")
    return parsed


def _canonical_payload(document: Mapping[str, Any]) -> bytes:
    payload = dict(document)
    payload["signatures"] = []
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _validate_signature_encoding(value: Any) -> None:
    if not isinstance(value, str) or not 32 <= len(value) <= 8192:
        raise EvidenceError("signature encoding is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise EvidenceError("signature must be canonical base64") from exc
    if len(decoded) < 24:
        raise EvidenceError("signature is too short")


def _distinct(values: Iterable[str], where: str) -> list[str]:
    result = list(values)
    if len(set(result)) != len(result):
        raise EvidenceError(f"{where} contains duplicates")
    return result


def validate_document(
    document: Any,
    *,
    expected_repository: str,
    expected_commit: str,
    expected_tree: str,
    expected_gate: str | None = None,
    now: dt.datetime | None = None,
) -> Admission:
    top = _object(document, "evidence", TOP_KEYS)
    if top["schema_id"] != SCHEMA_ID:
        raise EvidenceError("unsupported schema_id")
    gate_id = _token(top["gate_id"], "gate_id")
    if gate_id not in REQUIRED_CASES:
        raise EvidenceError("unknown gate_id")
    if expected_gate is not None and gate_id != expected_gate:
        raise EvidenceError("gate_id does not match the requested gate")
    if top["authority_effect"] != AUTHORITY_EFFECT:
        raise EvidenceError("external evidence cannot grant authority")

    claims = _object(top["claims"], "claims", CLAIM_KEYS)
    if any(value is not False for value in claims.values()):
        raise EvidenceError("evidence object cannot self-assert qualification or authority")

    subject = _object(top["subject"], "subject", SUBJECT_KEYS)
    if subject["repository"] != expected_repository:
        raise EvidenceError("repository binding mismatch")
    if subject["commit"] != expected_commit or not HEX40.fullmatch(str(subject["commit"])):
        raise EvidenceError("commit binding mismatch")
    if subject["tree"] != expected_tree or not HEX40.fullmatch(str(subject["tree"])):
        raise EvidenceError("tree binding mismatch")
    _token(subject["profile"], "subject.profile")

    created_at = _timestamp(top["created_at"], "created_at")
    expires_at = _timestamp(top["expires_at"], "expires_at")
    if expires_at <= created_at or expires_at - created_at > dt.timedelta(days=93):
        raise EvidenceError("invalid evidence validity window")
    current = now or dt.datetime.now(dt.timezone.utc)
    if current < created_at - dt.timedelta(minutes=10) or current >= expires_at:
        raise EvidenceError("evidence is not currently valid")

    issuer = _object(top["issuer"], "issuer", ISSUER_KEYS)
    issuer_id = _token(issuer["actor_id"], "issuer.actor_id")
    issuer_role = _token(issuer["role"], "issuer.role")
    if issuer_role not in ROLE_BY_GATE[gate_id]:
        raise EvidenceError("issuer role is not eligible for this gate")
    _token(issuer["organization"], "issuer.organization")
    _token(issuer["public_key_id"], "issuer.public_key_id")

    separation = _object(top["separation"], "separation", SEPARATION_KEYS)
    authors = _distinct(
        (_token(item, "separation.source_author_ids[]") for item in _sequence(
            separation["source_author_ids"], "separation.source_author_ids", maximum=128
        )),
        "source_author_ids",
    )
    if issuer_id in authors:
        raise EvidenceError("issuer is a source author")
    roots = [
        _token(separation[name], f"separation.{name}")
        for name in (
            "implementation_control_root", "evidence_control_root",
            "runner_control_root", "signing_control_root",
        )
    ]
    if len(set(roots)) != len(roots):
        raise EvidenceError("implementation, evidence, runner and signing roots must be distinct")

    artifacts = _sequence(top["artifacts"], "artifacts", maximum=1024)
    artifact_digests: set[str] = set()
    artifact_paths: set[str] = set()
    for index, raw in enumerate(artifacts):
        artifact = _object(raw, f"artifacts[{index}]", ARTIFACT_KEYS)
        path = artifact["path"]
        if (
            not isinstance(path, str) or not path or len(path) > 512
            or path.startswith(("/", "~")) or ".." in Path(path).parts
            or "\\" in path
        ):
            raise EvidenceError("artifact path is not a bounded relative path")
        digest = artifact["sha256"]
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise EvidenceError("artifact sha256 is invalid")
        size = artifact["bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 1 << 40:
            raise EvidenceError("artifact size is invalid")
        _token(artifact["media_type"], "artifact.media_type")
        if path in artifact_paths or digest in artifact_digests:
            raise EvidenceError("artifacts must have unique paths and digests")
        artifact_paths.add(path)
        artifact_digests.add(digest)

    cases = _sequence(top["cases"], "cases", maximum=4096)
    case_ids: set[str] = set()
    for index, raw in enumerate(cases):
        case = _object(raw, f"cases[{index}]", CASE_KEYS)
        case_id = _token(case["id"], "case.id")
        if case_id in case_ids:
            raise EvidenceError("duplicate case id")
        case_ids.add(case_id)
        if case["status"] != "PASS":
            raise EvidenceError("every required case must be PASS")
        if case["artifact_sha256"] not in artifact_digests:
            raise EvidenceError("case references an unbound artifact")
        observed = _timestamp(case["observed_at"], "case.observed_at")
        if observed < created_at - dt.timedelta(days=7) or observed > created_at:
            raise EvidenceError("case observation lies outside the admitted window")
    required = REQUIRED_CASES[gate_id]
    if case_ids != required:
        raise EvidenceError(
            f"case denominator mismatch: missing={sorted(required-case_ids)} extra={sorted(case_ids-required)}"
        )

    canonical_digest = hashlib.sha256(_canonical_payload(top)).hexdigest()
    signatures = _sequence(top["signatures"], "signatures", minimum=2, maximum=32)
    signer_ids: set[str] = set()
    signer_key_ids: set[str] = set()
    eligible_roles = ROLE_BY_GATE[gate_id]
    observed_roles: set[str] = set()
    for index, raw in enumerate(signatures):
        signature = _object(raw, f"signatures[{index}]", SIGNATURE_KEYS)
        signer = _token(signature["signer_actor_id"], "signature.signer_actor_id")
        role = _token(signature["role"], "signature.role")
        key_id = _token(signature["public_key_id"], "signature.public_key_id")
        if signer in authors or signer == issuer_id:
            raise EvidenceError("signature is not role-separated from source and issuer")
        if signer in signer_ids or key_id in signer_key_ids:
            raise EvidenceError("signers and signing keys must be unique")
        if role not in eligible_roles:
            raise EvidenceError("signature role is not eligible for this gate")
        signed_at = _timestamp(signature["signed_at"], "signature.signed_at")
        if signed_at < created_at or signed_at >= expires_at:
            raise EvidenceError("signature timestamp is outside the evidence validity window")
        if signature["algorithm"] not in {"ed25519", "ecdsa-p256-sha256"}:
            raise EvidenceError("signature algorithm is not admitted")
        if signature["payload_sha256"] != canonical_digest:
            raise EvidenceError("signature payload digest mismatch")
        _validate_signature_encoding(signature["signature"])
        signer_ids.add(signer)
        signer_key_ids.add(key_id)
        observed_roles.add(role)
    if len(signer_ids) < 2:
        raise EvidenceError("at least two independent signers are required")
    if gate_id == "HB-BLK-EXT-001" and not {
        "program-reviewer", "security-reviewer", "storage-reviewer"
    }.issubset(observed_roles):
        raise EvidenceError("review gate requires program, security and storage roles")

    return Admission(
        gate_id=gate_id,
        subject_commit=expected_commit,
        canonical_payload_sha256=canonical_digest,
        artifact_count=len(artifacts),
        case_count=len(cases),
        signer_count=len(signatures),
    )


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-gate", choices=sorted(REQUIRED_CASES))
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    if not HEX40.fullmatch(args.expected_commit) or not HEX40.fullmatch(args.expected_tree):
        print("expected commit/tree must be lowercase 40-character Git object IDs", file=sys.stderr)
        return 2
    try:
        document = json.loads(args.evidence.read_text(encoding="utf-8"))
        admission = validate_document(
            document,
            expected_repository=args.expected_repository,
            expected_commit=args.expected_commit,
            expected_tree=args.expected_tree,
            expected_gate=args.expected_gate,
        )
    except (OSError, json.JSONDecodeError, EvidenceError) as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "ADMISSIBLE_EVIDENCE_NOT_AUTHORITY",
        "gate_id": admission.gate_id,
        "subject_commit": admission.subject_commit,
        "canonical_payload_sha256": admission.canonical_payload_sha256,
        "artifact_count": admission.artifact_count,
        "case_count": admission.case_count,
        "signer_count": admission.signer_count,
        "authority_effect": AUTHORITY_EFFECT,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
