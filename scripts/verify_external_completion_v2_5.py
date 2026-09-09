#!/usr/bin/env python3
"""Fail-closed verifier for independently produced HeptaBao completion evidence.

This module verifies structure, immutable source binding, a closed case
 denominator, artifact bytes, trust-store custody and strict Ed25519 signatures.
It is a verifier only: it cannot create evidence, keys, signatures or authority.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

SCHEMA = "heptabao.external-completion.v2.5"
TRUST_SCHEMA = "heptabao.external-trust-store.v2.5"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024 * 1024
MAX_ARTIFACTS = 4096
MAX_SIGNATURES = 128
HEX40 = set("0123456789abcdef")
HEX64 = set("0123456789abcdef")

# Ed25519 constants from RFC 8032.
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_IDENTITY = (0, 1)


def _inv(value: int) -> int:
    return pow(value % _Q, _Q - 2, _Q)


def _recover_x(y: int, sign: int) -> int:
    xx = ((y * y - 1) * _inv(_D * y * y + 1)) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if (x * x - xx) % _Q != 0:
        raise ValueError("point is not on the Ed25519 curve")
    if (x & 1) != sign:
        x = _Q - x
    return x


def _decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("Ed25519 point must be 32 bytes")
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("non-canonical Ed25519 point")
    point = (_recover_x(y, sign), y)
    if _point_add(point, _IDENTITY) != point:
        raise ValueError("invalid Ed25519 point")
    if point == _IDENTITY or _scalar_mul(_L, point) != _IDENTITY:
        raise ValueError("Ed25519 point is not in the prime-order subgroup")
    return point


def _point_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = (_D * x1 * x2 * y1 * y2) % _Q
    x3 = ((x1 * y2 + y1 * x2) * _inv(1 + product)) % _Q
    y3 = ((y1 * y2 + x1 * x2) * _inv(1 - product)) % _Q
    return x3, y3


def _scalar_mul(scalar: int, point: tuple[int, int]) -> tuple[int, int]:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result

_BASE_Y = (4 * _inv(5)) % _Q
_BASE = (_recover_x(_BASE_Y, 0), _BASE_Y)


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Strictly verify an Ed25519 signature without accepting small-order points."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        r_encoded = signature[:32]
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        public = _decode_point(public_key)
        r_point = _decode_point(r_encoded)
        challenge = int.from_bytes(
            hashlib.sha512(r_encoded + public_key + message).digest(), "little"
        ) % _L
        return _scalar_mul(s, _BASE) == _point_add(
            r_point, _scalar_mul(challenge, public)
        )
    except (ArithmeticError, ValueError):
        return False


class EvidenceError(ValueError):
    """Raised when evidence cannot be admitted."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _read_regular_json(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EvidenceError(f"cannot inspect JSON input {path}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise EvidenceError(f"JSON input is not a regular non-symlink file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > MAX_JSON_BYTES:
        raise EvidenceError(f"JSON input has invalid size: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceError(f"cannot open JSON input {path}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise EvidenceError(f"JSON input changed before open: {path}")
        raw = b""
        while len(raw) <= MAX_JSON_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_JSON_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        if len(raw) != metadata.st_size or len(raw) > MAX_JSON_BYTES:
            raise EvidenceError(f"JSON input changed or exceeded its bound: {path}")
        closed = os.fstat(descriptor)
        if (
            closed.st_size != opened.st_size
            or closed.st_mtime_ns != opened.st_mtime_ns
            or closed.st_ctime_ns != opened.st_ctime_ns
        ):
            raise EvidenceError(f"JSON input changed during read: {path}")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid UTF-8 JSON input {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"JSON root must be an object: {path}")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _parse_time(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvidenceError(f"{field} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EvidenceError(f"invalid {field}") from exc
    if parsed.tzinfo is None:
        raise EvidenceError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _hex(value: Any, length: int, field: str) -> str:
    if not isinstance(value, str) or len(value) != length:
        raise EvidenceError(f"{field} must be {length} lowercase hexadecimal characters")
    if any(character not in HEX64 for character in value):
        raise EvidenceError(f"{field} must be lowercase hexadecimal")
    return value


def _closed_keys(value: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise EvidenceError(f"unknown {context} fields: {sorted(unknown)}")


_REQUIRED_CASES: dict[str, frozenset[str]] = {
    "HB-BLK-CTRL-001": frozenset(
        {
            "direct-push-member-denied",
            "direct-push-admin-denied",
            "missing-check-merge-denied",
            "insufficient-approvals-denied",
            "unresolved-conversation-denied",
            "force-push-denied",
            "branch-delete-denied",
        }
    ),
    "HB-BLK-EXT-001": frozenset(
        {
            "program-review-pass",
            "security-review-pass",
            "storage-review-pass",
            "critical-findings-zero",
            "high-findings-zero",
        }
    ),
    "HB-BLK-EXT-002": frozenset(
        {
            "license-disposition-signed",
            "trademark-disposition-signed",
            "patent-disposition-signed",
            "export-disposition-signed",
        }
    ),
    "HB-BLK-EXT-003": frozenset(
        {
            "disclosure-channel-operational",
            "oncall-coverage-verified",
            "incident-drill-pass",
            "revocation-drill-pass",
        }
    ),
    "HB-BLK-EXT-004": frozenset(
        {
            "hsm-key-generated",
            "signer-custody-separated",
            "rotation-ceremony-pass",
            "emergency-revocation-pass",
            "transparency-checkpoint-published",
        }
    ),
    "HB-BLK-EXT-005": frozenset(
        {
            "oracle-capture-complete",
            "sanitized-fixtures-complete",
            "side-effects-covered",
            "cli-client-covered",
            "transfer-signed",
        }
    ),
    "HB-BLK-EXT-006": frozenset(
        {
            "linux-amd64-pass",
            "linux-arm64-pass",
            "windows-amd64-pass",
            "macos-arm64-pass",
            "power-cut-pass",
            "fsync-loss-pass",
            "corruption-recovery-pass",
            "rolling-upgrade-pass",
            "disaster-recovery-pass",
        }
    ),
    "HB-BLK-EXT-007": frozenset(
        {
            "clean-room-build-a-pass",
            "clean-room-build-b-pass",
            "artifact-digest-match",
            "test-reproduction-pass",
        }
    ),
}

_REQUIRED_ROLE_COUNTS: dict[str, dict[str, int]] = {
    "HB-BLK-CTRL-001": {"repository-administrator": 1, "control-auditor": 1},
    "HB-BLK-EXT-001": {
        "program-reviewer": 1,
        "security-reviewer": 1,
        "storage-reviewer": 1,
    },
    "HB-BLK-EXT-002": {"legal-counsel": 1, "license-counsel": 1},
    "HB-BLK-EXT-003": {"incident-commander": 1, "security-operations": 1},
    "HB-BLK-EXT-004": {"release-custodian": 1, "hsm-custodian": 1},
    "HB-BLK-EXT-005": {"oracle-custodian": 1, "compatibility-reviewer": 1},
    "HB-BLK-EXT-006": {"platform-qualifier": 1, "storage-qualifier": 1},
    "HB-BLK-EXT-007": {"independent-reproducer": 2},
}


def _validate_relative_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise EvidenceError("artifact path must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise EvidenceError(f"unsafe artifact path: {value}")
    return path


def _hash_artifact(root: Path, relative: PurePosixPath, expected_size: int) -> str:
    if expected_size < 0 or expected_size > MAX_ARTIFACT_BYTES:
        raise EvidenceError(f"artifact size outside bound: {relative}")
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        raise EvidenceError("artifact root must be a real directory")
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or current.is_symlink():
            raise EvidenceError(f"artifact parent is not a real directory: {relative}")
    path = root.joinpath(*relative.parts)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise EvidenceError(f"artifact is not a regular non-symlink file: {relative}")
    if metadata.st_size != expected_size:
        raise EvidenceError(f"artifact size mismatch: {relative}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    observed = 0
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise EvidenceError(f"artifact changed before open: {relative}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > expected_size or observed > MAX_ARTIFACT_BYTES:
                raise EvidenceError(f"artifact exceeded declared size: {relative}")
            digest.update(chunk)
        closed = os.fstat(descriptor)
        if observed != expected_size:
            raise EvidenceError(f"artifact truncated during read: {relative}")
        if (
            closed.st_size != opened.st_size
            or closed.st_mtime_ns != opened.st_mtime_ns
            or closed.st_ctime_ns != opened.st_ctime_ns
        ):
            raise EvidenceError(f"artifact changed during read: {relative}")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _validate_trust_store(
    trust: dict[str, Any], expected_digest: str, trust_path: Path
) -> dict[str, dict[str, Any]]:
    _closed_keys(trust, {"schema", "generated_at", "keys"}, "trust-store")
    if trust.get("schema") != TRUST_SCHEMA:
        raise EvidenceError("unexpected trust-store schema")
    actual_digest = hashlib.sha256(trust_path.read_bytes()).hexdigest()
    if actual_digest != expected_digest:
        raise EvidenceError("trust-store digest does not match the out-of-band pin")
    _parse_time(trust.get("generated_at"), "trust-store generated_at")
    keys = trust.get("keys")
    if not isinstance(keys, list) or not keys or len(keys) > MAX_SIGNATURES:
        raise EvidenceError("trust-store keys must be a bounded non-empty list")
    by_id: dict[str, dict[str, Any]] = {}
    material_seen: set[str] = set()
    for entry in keys:
        if not isinstance(entry, dict):
            raise EvidenceError("trust-store key entry must be an object")
        _closed_keys(
            entry,
            {
                "key_id",
                "actor",
                "role",
                "public_key_hex",
                "valid_from",
                "valid_through",
                "revoked",
            },
            "trust-store key",
        )
        key_id = entry.get("key_id")
        actor = entry.get("actor")
        role = entry.get("role")
        if not all(isinstance(item, str) and item for item in (key_id, actor, role)):
            raise EvidenceError("trust-store key identity fields must be non-empty strings")
        public_key = _hex(entry.get("public_key_hex"), 64, "public_key_hex")
        if key_id in by_id or public_key in material_seen:
            raise EvidenceError("duplicate trust-store key identity or key material")
        if not isinstance(entry.get("revoked"), bool):
            raise EvidenceError("trust-store revoked must be boolean")
        start = _parse_time(entry.get("valid_from"), "valid_from")
        end = _parse_time(entry.get("valid_through"), "valid_through")
        if start >= end:
            raise EvidenceError("trust-store key validity interval is empty")
        by_id[key_id] = entry
        material_seen.add(public_key)
    return by_id


def _unsigned_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    copy = json.loads(json.dumps(evidence))
    for gate in copy["gates"]:
        gate.pop("signatures", None)
    return copy


def verify(
    evidence_path: Path,
    trust_store_path: Path,
    artifact_root: Path,
    expected_repository: str,
    expected_commit: str,
    expected_tree: str,
    expected_profile: str,
    expected_trust_store_sha256: str,
) -> dict[str, Any]:
    evidence = _read_regular_json(evidence_path)
    trust_store = _read_regular_json(trust_store_path)
    expected_trust_store_sha256 = _hex(
        expected_trust_store_sha256, 64, "expected trust-store SHA-256"
    )
    trust_keys = _validate_trust_store(
        trust_store, expected_trust_store_sha256, trust_store_path
    )

    _closed_keys(
        evidence,
        {"schema", "repository", "commit", "tree", "profile", "issued_at", "artifacts", "gates"},
        "evidence",
    )
    if evidence.get("schema") != SCHEMA:
        raise EvidenceError("unexpected evidence schema")
    if evidence.get("repository") != expected_repository:
        raise EvidenceError("evidence repository binding mismatch")
    if evidence.get("commit") != expected_commit or evidence.get("tree") != expected_tree:
        raise EvidenceError("evidence source binding mismatch")
    if evidence.get("profile") != expected_profile:
        raise EvidenceError("evidence profile binding mismatch")
    _hex(expected_commit, 40, "expected commit")
    _hex(expected_tree, 40, "expected tree")
    issued_at = _parse_time(evidence.get("issued_at"), "issued_at")

    artifacts = evidence.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) > MAX_ARTIFACTS:
        raise EvidenceError("artifacts must be a bounded list")
    artifact_by_path: dict[str, dict[str, Any]] = {}
    for item in artifacts:
        if not isinstance(item, dict):
            raise EvidenceError("artifact entry must be an object")
        _closed_keys(item, {"path", "bytes", "sha256"}, "artifact")
        relative = _validate_relative_path(item.get("path"))
        relative_text = relative.as_posix()
        if relative_text in artifact_by_path:
            raise EvidenceError(f"duplicate artifact path: {relative_text}")
        size = item.get("bytes")
        if not isinstance(size, int) or isinstance(size, bool):
            raise EvidenceError("artifact bytes must be an integer")
        expected_digest = _hex(item.get("sha256"), 64, "artifact sha256")
        actual_digest = _hash_artifact(artifact_root, relative, size)
        if actual_digest != expected_digest:
            raise EvidenceError(f"artifact digest mismatch: {relative_text}")
        artifact_by_path[relative_text] = item

    gates = evidence.get("gates")
    if not isinstance(gates, list) or len(gates) != len(_REQUIRED_CASES):
        raise EvidenceError("evidence must contain exactly the required gates")
    gate_by_id: dict[str, dict[str, Any]] = {}
    referenced_artifacts: set[str] = set()
    for gate in gates:
        if not isinstance(gate, dict):
            raise EvidenceError("gate must be an object")
        _closed_keys(gate, {"id", "cases", "signatures"}, "gate")
        gate_id = gate.get("id")
        if gate_id not in _REQUIRED_CASES or gate_id in gate_by_id:
            raise EvidenceError(f"unknown or duplicate gate: {gate_id}")
        cases = gate.get("cases")
        if not isinstance(cases, list):
            raise EvidenceError(f"gate cases must be a list: {gate_id}")
        case_ids: set[str] = set()
        for case in cases:
            if not isinstance(case, dict):
                raise EvidenceError("case must be an object")
            _closed_keys(case, {"id", "result", "artifacts"}, "case")
            case_id = case.get("id")
            if not isinstance(case_id, str) or not case_id or case_id in case_ids:
                raise EvidenceError(f"invalid or duplicate case ID in {gate_id}")
            if case.get("result") != "PASS":
                raise EvidenceError(f"non-PASS case in {gate_id}: {case_id}")
            refs = case.get("artifacts")
            if not isinstance(refs, list) or not refs:
                raise EvidenceError(f"case has no artifact evidence: {case_id}")
            for ref in refs:
                relative = _validate_relative_path(ref).as_posix()
                if relative not in artifact_by_path:
                    raise EvidenceError(f"case references undeclared artifact: {relative}")
                referenced_artifacts.add(relative)
            case_ids.add(case_id)
        if case_ids != set(_REQUIRED_CASES[gate_id]):
            missing = sorted(set(_REQUIRED_CASES[gate_id]) - case_ids)
            extra = sorted(case_ids - set(_REQUIRED_CASES[gate_id]))
            raise EvidenceError(
                f"closed case denominator mismatch for {gate_id}: missing={missing}, extra={extra}"
            )
        gate_by_id[gate_id] = gate

    if referenced_artifacts != set(artifact_by_path):
        raise EvidenceError("declared artifacts and case-referenced artifacts differ")

    unsigned = _unsigned_evidence(evidence)
    total_signatures = 0
    signer_actors: dict[str, set[str]] = {}
    signer_keys: set[str] = set()
    for gate_id, gate in gate_by_id.items():
        signatures = gate.get("signatures")
        if not isinstance(signatures, list) or not signatures:
            raise EvidenceError(f"gate has no signatures: {gate_id}")
        counts: dict[str, int] = {}
        actors: set[str] = set()
        for signature in signatures:
            if not isinstance(signature, dict):
                raise EvidenceError("signature must be an object")
            _closed_keys(signature, {"key_id", "actor", "role", "signature_hex"}, "signature")
            key_id = signature.get("key_id")
            actor = signature.get("actor")
            role = signature.get("role")
            if not all(isinstance(item, str) and item for item in (key_id, actor, role)):
                raise EvidenceError("signature identity fields must be non-empty strings")
            if actor in actors or key_id in signer_keys:
                raise EvidenceError("signers and signing keys must be distinct")
            trusted = trust_keys.get(key_id)
            if trusted is None:
                raise EvidenceError(f"untrusted signing key: {key_id}")
            if trusted["actor"] != actor or trusted["role"] != role:
                raise EvidenceError("signature identity does not match trust store")
            if trusted["revoked"]:
                raise EvidenceError(f"revoked signing key: {key_id}")
            valid_from = _parse_time(trusted["valid_from"], "valid_from")
            valid_through = _parse_time(trusted["valid_through"], "valid_through")
            if not (valid_from <= issued_at <= valid_through):
                raise EvidenceError(f"signing key was not valid at issuance: {key_id}")
            signature_bytes = bytes.fromhex(_hex(signature.get("signature_hex"), 128, "signature_hex"))
            message = _canonical(
                {
                    "evidence": unsigned,
                    "gate_id": gate_id,
                    "key_id": key_id,
                    "actor": actor,
                    "role": role,
                }
            )
            public_key = bytes.fromhex(trusted["public_key_hex"])
            if not verify_ed25519(public_key, message, signature_bytes):
                raise EvidenceError(f"invalid Ed25519 signature: {key_id}")
            actors.add(actor)
            signer_keys.add(key_id)
            counts[role] = counts.get(role, 0) + 1
            total_signatures += 1
            if total_signatures > MAX_SIGNATURES:
                raise EvidenceError("signature count exceeds bound")
        if counts != _REQUIRED_ROLE_COUNTS[gate_id]:
            raise EvidenceError(
                f"role denominator mismatch for {gate_id}: observed={counts}, required={_REQUIRED_ROLE_COUNTS[gate_id]}"
            )
        signer_actors[gate_id] = actors

    # Independent roles may not collapse to one human across unrelated gates.
    all_actors = set().union(*signer_actors.values())
    if len(all_actors) < 12:
        raise EvidenceError("insufficient separation of accountable actors")

    return {
        "schema": "heptabao.external-completion-admission.v2.5",
        "admitted": True,
        "repository": expected_repository,
        "commit": expected_commit,
        "tree": expected_tree,
        "profile": expected_profile,
        "evidence_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
        "trust_store_sha256": expected_trust_store_sha256,
        "gate_count": len(gate_by_id),
        "case_count": sum(len(gate["cases"]) for gate in gate_by_id.values()),
        "artifact_count": len(artifact_by_path),
        "signature_count": total_signatures,
        "authority_effect": "NONE_UNTIL_SEPARATE_GRANT",
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-profile", required=True)
    parser.add_argument("--expected-trust-store-sha256", required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        result = verify(
            evidence_path=arguments.evidence,
            trust_store_path=arguments.trust_store,
            artifact_root=arguments.artifact_root,
            expected_repository=arguments.expected_repository,
            expected_commit=arguments.expected_commit,
            expected_tree=arguments.expected_tree,
            expected_profile=arguments.expected_profile,
            expected_trust_store_sha256=arguments.expected_trust_store_sha256,
        )
    except (EvidenceError, OSError, ValueError) as exc:
        print(json.dumps({"admitted": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
