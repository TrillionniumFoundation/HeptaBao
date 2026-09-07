#!/usr/bin/env python3
"""Compute and fail-closed validate secret-free Oracle side-effect deltas.

The input is a JSON object containing `before`, `after` and `declared_policy`.
The command never connects to OpenBao. It is suitable for synthetic contracts
and for sanitized observations produced by a restricted Oracle lane.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

COUNTERS = (
    "mount_revision",
    "policy_revision",
    "token_count",
    "lease_count",
    "audit_event_count",
    "plugin_process_count",
    "raft_commit_index",
    "external_effect_receipt_count",
)
TRANSITIONS = ("sealed", "active")
POLICY_FIELDS = {
    "mount_revision": "allow_mount_revision",
    "policy_revision": "allow_policy_revision",
    "token_count": "allow_token_count",
    "lease_count": "allow_lease_count",
    "audit_event_count": "allow_audit_event_count",
    "plugin_process_count": "allow_plugin_process_count",
    "raft_commit_index": "allow_raft_commit_index",
    "external_effect_receipt_count": "allow_external_effect_receipt_count",
    "sealed_changed": "allow_seal_transition",
    "active_changed": "allow_active_transition",
}
FORBIDDEN_KEY = re.compile(
    r"(^|_)(client_?token|root_?token|unseal_?share|recovery_?key|private_?key|"
    r"secret_?value|authorization|refresh_?token|access_?token|password)($|_)",
    re.IGNORECASE,
)
FORBIDDEN_VALUE_MARKERS = (
    "-----BEGIN " + "PRIVATE KEY-----",
    "-----BEGIN OPENSSH " + "PRIVATE KEY-----",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ObservationError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def scan_secret_free(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if FORBIDDEN_KEY.search(str(key)):
                raise ObservationError(f"forbidden secret-bearing key at {path}.{key}")
            scan_secret_free(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_secret_free(child, f"{path}[{index}]")
    elif isinstance(value, str):
        for marker in FORBIDDEN_VALUE_MARKERS:
            if marker in value:
                raise ObservationError(f"forbidden secret-like value marker at {path}")


def validate_snapshot(snapshot: Any, label: str) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise ObservationError(f"{label} must be an object")
    expected = set(COUNTERS) | set(TRANSITIONS)
    if set(snapshot) != expected:
        missing = sorted(expected - set(snapshot))
        unknown = sorted(set(snapshot) - expected)
        raise ObservationError(f"{label} shape mismatch: missing={missing} unknown={unknown}")
    result: dict[str, Any] = {}
    for field in COUNTERS:
        value = snapshot[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ObservationError(f"{label}.{field} must be a non-negative integer")
        result[field] = value
    for field in TRANSITIONS:
        value = snapshot[field]
        if not isinstance(value, bool):
            raise ObservationError(f"{label}.{field} must be boolean")
        result[field] = value
    return result


def validate_policy(policy: Any) -> dict[str, bool]:
    expected = set(POLICY_FIELDS.values())
    if not isinstance(policy, dict) or set(policy) != expected:
        actual = set(policy) if isinstance(policy, dict) else set()
        raise ObservationError(
            f"declared_policy shape mismatch: missing={sorted(expected - actual)} "
            f"unknown={sorted(actual - expected)}"
        )
    result: dict[str, bool] = {}
    for field in sorted(expected):
        value = policy[field]
        if not isinstance(value, bool):
            raise ObservationError(f"declared_policy.{field} must be boolean")
        result[field] = value
    return result


def compute_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    delta = {field: after[field] - before[field] for field in COUNTERS}
    delta["sealed_changed"] = before["sealed"] != after["sealed"]
    delta["active_changed"] = before["active"] != after["active"]
    return delta


def validate_delta(delta: dict[str, Any], policy: dict[str, bool]) -> None:
    for field, policy_field in POLICY_FIELDS.items():
        value = delta[field]
        changed = value if isinstance(value, bool) else value != 0
        if changed and not policy[policy_field]:
            raise ObservationError(f"unexpected side effect: {field} changed but {policy_field}=false")


def validate_raw_capture_digest(document: dict[str, Any]) -> str | None:
    digest = document.get("raw_capture_digest_sha256")
    capture_kind = document["capture_kind"]
    if capture_kind == "SYNTHETIC_CONTRACT":
        if digest is not None:
            raise ObservationError("synthetic contract must not carry a raw Oracle capture digest")
        return None
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise ObservationError("black-box Oracle capture requires raw_capture_digest_sha256")
    return digest


def build_observation(document: dict[str, Any]) -> dict[str, Any]:
    scan_secret_free(document)
    required = {
        "baseline_id",
        "observation_id",
        "operation_id",
        "capture_kind",
        "status",
        "artifact_signature_verified",
        "before",
        "after",
        "declared_policy",
        "provenance_ref",
        "review_status",
    }
    allowed = required | {"raw_capture_digest_sha256"}
    unknown = set(document) - allowed
    missing = required - set(document)
    if missing or unknown:
        raise ObservationError(f"input shape mismatch: missing={sorted(missing)} unknown={sorted(unknown)}")
    if document["baseline_id"] != "HB-ORACLE-OPENBAO-V2_6_2":
        raise ObservationError("unexpected baseline_id")
    if document["capture_kind"] not in {"SYNTHETIC_CONTRACT", "BLACK_BOX_ORACLE"}:
        raise ObservationError("unsupported capture_kind")
    if document["capture_kind"] == "BLACK_BOX_ORACLE":
        if document["artifact_signature_verified"] is not True:
            raise ObservationError("black-box Oracle capture requires verified artifact signature")
        if document["status"] == "SYNTHETIC_CONTRACT":
            raise ObservationError("black-box Oracle capture cannot use synthetic status")
    elif document["status"] != "SYNTHETIC_CONTRACT":
        raise ObservationError("synthetic capture must use SYNTHETIC_CONTRACT status")
    if document["review_status"] not in {"PENDING", "APPROVED", "REJECTED", "SUPERSEDED"}:
        raise ObservationError("unsupported review_status")
    if document["status"] in {"REVIEWED", "QUALIFIED"} and document["review_status"] != "APPROVED":
        raise ObservationError("reviewed or qualified observation requires approved review")

    raw_capture_digest = validate_raw_capture_digest(document)
    before = validate_snapshot(document["before"], "before")
    after = validate_snapshot(document["after"], "after")
    policy = validate_policy(document["declared_policy"])
    delta = compute_delta(before, after)
    validate_delta(delta, policy)

    # The sanitized digest binds the raw-capture digest (or explicit null for a
    # synthetic contract). A reviewer therefore cannot swap the underlying raw
    # observation while retaining the same sanitized observation digest.
    sanitized_core = {
        "baseline_id": document["baseline_id"],
        "observation_id": document["observation_id"],
        "operation_id": document["operation_id"],
        "capture_kind": document["capture_kind"],
        "status": document["status"],
        "artifact_signature_verified": document["artifact_signature_verified"],
        "secret_material_present": False,
        "before": before,
        "after": after,
        "declared_policy": policy,
        "delta": delta,
        "provenance_ref": document["provenance_ref"],
        "review_status": document["review_status"],
        "authority_effect": "NONE",
        "raw_capture_digest_sha256": raw_capture_digest,
    }
    digest = sha256(sanitized_core)
    return {
        "schema": "heptabao.oracle-side-effect-observation.v1",
        **sanitized_core,
        "sanitized_capture_digest_sha256": digest,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = json.loads(args.input.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ObservationError("input root must be an object")
        observation = build_observation(value)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(observation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, ObservationError) as error:
        print(f"Oracle side-effect validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "Oracle side-effect validation passed: "
        f"observation={observation['observation_id']} "
        f"digest={observation['sanitized_capture_digest_sha256']} authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
