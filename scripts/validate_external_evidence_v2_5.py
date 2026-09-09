#!/usr/bin/env python3
"""Fail-closed validation core for HeptaBao external/control evidence.

The core checks exact source binding, closed case and signer denominators,
separation of duties, canonical payload binding, and (when a trust store is
supplied) strict Ed25519 signatures.  It creates neither evidence nor authority.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, NamedTuple, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from heptabao_ed25519_v2_5 import (
    Ed25519Error,
    decode_point,
    verify as verify_ed25519,
)

SCHEMA_ID = "HEPTABAO_EXTERNAL_EVIDENCE_V2_5"
TRUST_SCHEMA_ID = "HEPTABAO_EXTERNAL_TRUST_STORE_V2_5"
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

REQUIRED_ROLE_COUNTS: dict[str, dict[str, int]] = {
    "HB-BLK-CTRL-001": {
        "repository-administrator": 1,
        "control-auditor": 1,
    },
    "HB-BLK-EXT-001": {
        "program-reviewer": 1,
        "security-reviewer": 1,
        "storage-reviewer": 1,
    },
    "HB-BLK-EXT-002": {
        "legal-counsel": 1,
        "license-counsel": 1,
    },
    "HB-BLK-EXT-003": {
        "incident-commander": 1,
        "security-operations": 1,
    },
    "HB-BLK-EXT-004": {
        "release-custodian": 1,
        "hsm-custodian": 1,
    },
    "HB-BLK-EXT-005": {
        "oracle-custodian": 1,
        "compatibility-reviewer": 1,
    },
    "HB-BLK-EXT-006": {
        "platform-qualifier": 1,
        "storage-qualifier": 1,
    },
    "HB-BLK-EXT-007": {
        "independent-reproducer": 2,
    },
}
ROLE_BY_GATE: dict[str, frozenset[str]] = {
    gate: frozenset(counts) for gate, counts in REQUIRED_ROLE_COUNTS.items()
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
TRUST_TOP_KEYS = frozenset({"schema_id", "authority_effect", "keys"})
TRUST_KEY_KEYS = frozenset({
    "public_key_id", "actor_id", "role", "algorithm", "public_key",
    "valid_from", "valid_until", "revoked",
})


class EvidenceError(ValueError):
    """The evidence object or enrolled trust store is not admissible."""


class Admission(NamedTuple):
    gate_id: str
    subject_commit: str
    canonical_payload_sha256: str
    artifact_count: int
    case_count: int
    signer_count: int


class TrustedKey(NamedTuple):
    public_key_id: str
    actor_id: str
    role: str
    algorithm: str
    public_key: bytes
    valid_from: dt.datetime
    valid_until: dt.datetime
    revoked: bool


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


def _sequence(
    value: Any,
    where: str,
    *,
    minimum: int = 1,
    maximum: int = 4096,
) -> Sequence[Any]:
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
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _decode_base64(
    value: Any,
    where: str,
    *,
    exact_bytes: int | None = None,
    minimum_bytes: int | None = None,
) -> bytes:
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{where} encoding is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise EvidenceError(f"{where} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise EvidenceError(f"{where} must be canonical base64")
    if exact_bytes is not None and len(decoded) != exact_bytes:
        raise EvidenceError(f"{where} must contain exactly {exact_bytes} bytes")
    if minimum_bytes is not None and len(decoded) < minimum_bytes:
        raise EvidenceError(f"{where} is too short")
    return decoded


def _validate_signature_encoding(value: Any) -> None:
    if not isinstance(value, str) or not 32 <= len(value) <= 8192:
        raise EvidenceError("signature encoding is invalid")
    _decode_base64(value, "signature", minimum_bytes=24)


def _distinct(values: Iterable[str], where: str) -> list[str]:
    result = list(values)
    if len(set(result)) != len(result):
        raise EvidenceError(f"{where} contains duplicates")
    return result


def load_trust_store(document: Any) -> dict[str, TrustedKey]:
    """Validate and materialize an externally pinned Ed25519 trust store."""
    top = _object(document, "trust_store", TRUST_TOP_KEYS)
    if top["schema_id"] != TRUST_SCHEMA_ID:
        raise EvidenceError("unsupported trust-store schema_id")
    if top["authority_effect"] != AUTHORITY_EFFECT:
        raise EvidenceError("trust store cannot grant authority")

    records: dict[str, TrustedKey] = {}
    actor_role_key: set[tuple[str, str, bytes]] = set()
    public_keys: set[bytes] = set()
    for index, raw in enumerate(
        _sequence(top["keys"], "trust_store.keys", maximum=4096)
    ):
        key = _object(raw, f"trust_store.keys[{index}]", TRUST_KEY_KEYS)
        public_key_id = _token(
            key["public_key_id"],
            f"trust_store.keys[{index}].public_key_id",
        )
        actor_id = _token(
            key["actor_id"],
            f"trust_store.keys[{index}].actor_id",
        )
        role = _token(key["role"], f"trust_store.keys[{index}].role")
        algorithm = key["algorithm"]
        if algorithm != "ed25519":
            raise EvidenceError("trust-store algorithm must be ed25519")
        public_key = _decode_base64(
            key["public_key"],
            "trust-store public key",
            exact_bytes=32,
        )
        try:
            decode_point(public_key)
        except Ed25519Error as exc:
            raise EvidenceError("trust-store public key is not strict Ed25519") from exc
        valid_from = _timestamp(key["valid_from"], "trust-store valid_from")
        valid_until = _timestamp(key["valid_until"], "trust-store valid_until")
        if valid_from >= valid_until:
            raise EvidenceError("trust-store key validity interval is empty")
        revoked = key["revoked"]
        if not isinstance(revoked, bool):
            raise EvidenceError("trust-store revoked must be boolean")
        if public_key_id in records:
            raise EvidenceError("duplicate trust-store public_key_id")
        identity = (actor_id, role, public_key)
        if identity in actor_role_key or public_key in public_keys:
            raise EvidenceError("duplicate trust-store identity or public key")
        records[public_key_id] = TrustedKey(
            public_key_id=public_key_id,
            actor_id=actor_id,
            role=role,
            algorithm=algorithm,
            public_key=public_key,
            valid_from=valid_from,
            valid_until=valid_until,
            revoked=revoked,
        )
        actor_role_key.add(identity)
        public_keys.add(public_key)
    return records


def _verify_trusted_signature(
    *,
    signature: Mapping[str, Any],
    trusted_keys: Mapping[str, TrustedKey],
    signed_at: dt.datetime,
    canonical_payload: bytes,
) -> None:
    key_id = str(signature["public_key_id"])
    trusted = trusted_keys.get(key_id)
    if trusted is None:
        raise EvidenceError(f"untrusted signing key: {key_id}")
    if (
        trusted.actor_id != signature["signer_actor_id"]
        or trusted.role != signature["role"]
        or trusted.algorithm != signature["algorithm"]
    ):
        raise EvidenceError("signature identity does not match trust store")
    if trusted.revoked:
        raise EvidenceError(f"revoked signing key: {key_id}")
    if not (trusted.valid_from <= signed_at < trusted.valid_until):
        raise EvidenceError(f"signing key was not valid at signature time: {key_id}")
    signature_bytes = _decode_base64(
        signature["signature"],
        "Ed25519 signature",
        exact_bytes=64,
    )
    try:
        verify_ed25519(trusted.public_key, signature_bytes, canonical_payload)
    except Ed25519Error as exc:
        raise EvidenceError(f"invalid Ed25519 signature: {key_id}") from exc


def validate_document(
    document: Any,
    *,
    expected_repository: str,
    expected_commit: str,
    expected_tree: str,
    expected_gate: str | None = None,
    trusted_keys: Mapping[str, TrustedKey] | None = None,
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
        raise EvidenceError(
            "evidence object cannot self-assert qualification or authority"
        )

    subject = _object(top["subject"], "subject", SUBJECT_KEYS)
    if subject["repository"] != expected_repository:
        raise EvidenceError("repository binding mismatch")
    if (
        subject["commit"] != expected_commit
        or not HEX40.fullmatch(str(subject["commit"]))
    ):
        raise EvidenceError("commit binding mismatch")
    if (
        subject["tree"] != expected_tree
        or not HEX40.fullmatch(str(subject["tree"]))
    ):
        raise EvidenceError("tree binding mismatch")
    _token(subject["profile"], "subject.profile")

    created_at = _timestamp(top["created_at"], "created_at")
    expires_at = _timestamp(top["expires_at"], "expires_at")
    if (
        expires_at <= created_at
        or expires_at - created_at > dt.timedelta(days=93)
    ):
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
        (
            _token(item, "separation.source_author_ids[]")
            for item in _sequence(
                separation["source_author_ids"],
                "separation.source_author_ids",
                maximum=128,
            )
        ),
        "source_author_ids",
    )
    if issuer_id in authors:
        raise EvidenceError("issuer is a source author")
    roots = [
        _token(separation[name], f"separation.{name}")
        for name in (
            "implementation_control_root",
            "evidence_control_root",
            "runner_control_root",
            "signing_control_root",
        )
    ]
    if len(set(roots)) != len(roots):
        raise EvidenceError(
            "implementation, evidence, runner and signing roots must be distinct"
        )

    artifacts = _sequence(top["artifacts"], "artifacts", maximum=1024)
    artifact_digests: set[str] = set()
    artifact_paths: set[str] = set()
    for index, raw in enumerate(artifacts):
        artifact = _object(raw, f"artifacts[{index}]", ARTIFACT_KEYS)
        path = artifact["path"]
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 512
            or path.startswith(("/", "~"))
            or ".." in Path(path).parts
            or "\\" in path
        ):
            raise EvidenceError("artifact path is not a bounded relative path")
        digest = artifact["sha256"]
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise EvidenceError("artifact sha256 is invalid")
        size = artifact["bytes"]
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 1 <= size <= 1 << 40
        ):
            raise EvidenceError("artifact size is invalid")
        _token(artifact["media_type"], "artifact.media_type")
        if path in artifact_paths or digest in artifact_digests:
            raise EvidenceError("artifacts must have unique paths and digests")
        artifact_paths.add(path)
        artifact_digests.add(digest)

    cases = _sequence(top["cases"], "cases", maximum=4096)
    case_ids: set[str] = set()
    referenced_digests: set[str] = set()
    for index, raw in enumerate(cases):
        case = _object(raw, f"cases[{index}]", CASE_KEYS)
        case_id = _token(case["id"], "case.id")
        if case_id in case_ids:
            raise EvidenceError("duplicate case id")
        case_ids.add(case_id)
        if case["status"] != "PASS":
            raise EvidenceError("every required case must be PASS")
        digest = case["artifact_sha256"]
        if digest not in artifact_digests:
            raise EvidenceError("case references an unbound artifact")
        referenced_digests.add(digest)
        observed = _timestamp(case["observed_at"], "case.observed_at")
        if observed < created_at - dt.timedelta(days=7) or observed > created_at:
            raise EvidenceError(
                "case observation lies outside the admitted window"
            )
    required = REQUIRED_CASES[gate_id]
    if case_ids != required:
        raise EvidenceError(
            "case denominator mismatch: "
            f"missing={sorted(required-case_ids)} "
            f"extra={sorted(case_ids-required)}"
        )
    if referenced_digests != artifact_digests:
        raise EvidenceError(
            "declared artifact digests and case-referenced artifact digests differ"
        )

    canonical_payload = _canonical_payload(top)
    canonical_digest = hashlib.sha256(canonical_payload).hexdigest()
    signatures = _sequence(
        top["signatures"],
        "signatures",
        minimum=sum(REQUIRED_ROLE_COUNTS[gate_id].values()),
        maximum=32,
    )
    signer_ids: set[str] = set()
    signer_key_ids: set[str] = set()
    observed_counts: dict[str, int] = {}
    for index, raw in enumerate(signatures):
        signature = _object(raw, f"signatures[{index}]", SIGNATURE_KEYS)
        signer = _token(
            signature["signer_actor_id"],
            "signature.signer_actor_id",
        )
        role = _token(signature["role"], "signature.role")
        key_id = _token(
            signature["public_key_id"],
            "signature.public_key_id",
        )
        if signer in authors or signer == issuer_id:
            raise EvidenceError(
                "signature is not role-separated from source and issuer"
            )
        if signer in signer_ids or key_id in signer_key_ids:
            raise EvidenceError("signers and signing keys must be unique")
        if role not in ROLE_BY_GATE[gate_id]:
            raise EvidenceError("signature role is not eligible for this gate")
        signed_at = _timestamp(signature["signed_at"], "signature.signed_at")
        if signed_at < created_at or signed_at >= expires_at:
            raise EvidenceError(
                "signature timestamp is outside the evidence validity window"
            )
        algorithm = signature["algorithm"]
        if trusted_keys is None:
            if algorithm not in {"ed25519", "ecdsa-p256-sha256"}:
                raise EvidenceError("signature algorithm is not admitted")
            _validate_signature_encoding(signature["signature"])
        else:
            if algorithm != "ed25519":
                raise EvidenceError(
                    "authoritative admission accepts only enrolled Ed25519 keys"
                )
        if signature["payload_sha256"] != canonical_digest:
            raise EvidenceError("signature payload digest mismatch")
        if trusted_keys is not None:
            _verify_trusted_signature(
                signature=signature,
                trusted_keys=trusted_keys,
                signed_at=signed_at,
                canonical_payload=canonical_payload,
            )
        signer_ids.add(signer)
        signer_key_ids.add(key_id)
        observed_counts[role] = observed_counts.get(role, 0) + 1

    required_counts = REQUIRED_ROLE_COUNTS[gate_id]
    if observed_counts != required_counts:
        raise EvidenceError(
            "signer role denominator mismatch for "
            f"{gate_id}: observed={observed_counts}, required={required_counts}"
        )

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
    if (
        not HEX40.fullmatch(args.expected_commit)
        or not HEX40.fullmatch(args.expected_tree)
    ):
        print(
            "expected commit/tree must be lowercase 40-character Git object IDs",
            file=sys.stderr,
        )
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
        "status": "STRUCTURALLY_ADMISSIBLE_NOT_CRYPTOGRAPHICALLY_ADMITTED",
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
