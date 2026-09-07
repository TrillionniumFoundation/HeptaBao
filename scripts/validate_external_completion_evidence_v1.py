#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPOSITORY_ID = 1349115072
REPOSITORY_FULL_NAME = "TrillionniumFoundation/HeptaBao"
ALLOWED_BLOCKERS = {"HB-BLK-CTRL-001", *{f"HB-BLK-EXT-{i:03d}" for i in range(1, 8)}}
REQUIRED_ROLES = {
    "HB-BLK-CTRL-001": {"repository_administrator", "independent_control_reviewer"},
    "HB-BLK-EXT-001": {"program_reviewer", "security_reviewer", "storage_reviewer"},
    "HB-BLK-EXT-002": {"legal_signer", "independent_program_reviewer"},
    "HB-BLK-EXT-003": {"security_operations", "backup_incident_commander", "independent_observer"},
    "HB-BLK-EXT-004": {"root_key_custodian", "crypto_reviewer", "independent_observer"},
    "HB-BLK-EXT-005": {"oracle_operator", "sanitization_operator", "transfer_custodian", "compatibility_reviewer"},
    "HB-BLK-EXT-006": {"storage_lab_operator", "storage_reviewer"},
    "HB-BLK-EXT-007": {"independent_reproduction_operator", "independent_reproduction_reviewer"},
}
SEPARATION_KEYS = {
    "HB-BLK-EXT-007": {
        "credential_root", "runner_admin", "cache_admin", "artifact_custody", "signing_root", "network_egress"
    },
    "HB-BLK-EXT-006": {"runner_admin", "artifact_custody", "signing_root", "power_cut_control"},
    "HB-BLK-EXT-005": {"raw_capture_acl", "implementation_acl", "artifact_custody", "signing_root"},
    "HB-BLK-EXT-004": {"root_custody", "delegated_custody", "observer_custody", "transparency_custody"},
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PLACEHOLDERS = {"todo", "tbd", "unknown", "unexecuted", "placeholder", "example", "none", "n/a"}


def fail(message: str) -> None:
    raise ValueError(message)


def non_placeholder(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value.strip()) < 2:
        fail(f"{field}: missing")
    lowered = value.strip().lower()
    if lowered in PLACEHOLDERS or any(token in lowered for token in ("<", ">", "replace-me")):
        fail(f"{field}: placeholder")
    return value


def parse_time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        fail(f"{field}: invalid date-time: {error}")
    if parsed.tzinfo is None:
        fail(f"{field}: timezone required")
    return parsed.astimezone(timezone.utc)


def validate_envelope(
    data: dict[str, Any], *, require_closure: bool = False, expected_source: dict[str, str] | None = None,
    now: datetime | None = None,
) -> None:
    if data.get("schema") != "heptabao.external-completion-evidence.v1":
        fail("schema mismatch")
    blocker = data.get("blocker_id")
    if blocker not in ALLOWED_BLOCKERS:
        fail("unsupported blocker")
    repository = data.get("repository")
    if repository != {"id": REPOSITORY_ID, "full_name": REPOSITORY_FULL_NAME}:
        fail("repository identity mismatch")
    if data.get("claims") != {
        "qualification": False,
        "compatibility_claim": False,
        "selected_candidates": [],
        "selection_effect": "NONE",
        "production_authority": False,
        "migration_authority": False,
        "release_authority": False,
        "authority_effect": "NONE",
    }:
        fail("authority drift")
    state = data.get("state")
    if state not in {"UNEXECUTED", "EXECUTED_PENDING_REVIEW", "ACCEPTED", "REJECTED", "REVOKED"}:
        fail("invalid state")
    source = data.get("source")
    if not isinstance(source, dict):
        fail("source missing")
    if require_closure:
        if state != "ACCEPTED":
            fail("closure requires ACCEPTED")
        for key in ("commit", "tree", "merge_commit", "merge_tree"):
            value = source.get(key)
            if not isinstance(value, str) or not HEX40.fullmatch(value):
                fail(f"source.{key}: exact SHA required")
            if expected_source and value != expected_source.get(key):
                fail(f"source.{key}: expected-source mismatch")
        for key in ("plan_digest", "manifest_digest"):
            if not isinstance(source.get(key), str) or not DIGEST.fullmatch(source[key]):
                fail(f"source.{key}: exact digest required")
        scope = data.get("scope")
        if not isinstance(scope, list) or not scope:
            fail("closure scope empty")
        for index, value in enumerate(scope):
            non_placeholder(value, f"scope[{index}]")
        actors = data.get("actors")
        if not isinstance(actors, list):
            fail("actors missing")
        roles: set[str] = set()
        actor_ids: set[str] = set()
        for index, actor in enumerate(actors):
            if not isinstance(actor, dict):
                fail(f"actors[{index}]: object required")
            stable_id = non_placeholder(actor.get("stable_id"), f"actors[{index}].stable_id")
            role = non_placeholder(actor.get("role"), f"actors[{index}].role")
            non_placeholder(actor.get("organization"), f"actors[{index}].organization")
            if stable_id in actor_ids:
                fail("actor identities must be distinct")
            actor_ids.add(stable_id)
            roles.add(role)
            if role.startswith("independent_") or role.endswith("_reviewer") or role == "independent_observer":
                if actor.get("independent") is not True:
                    fail(f"{role}: independence not affirmed")
                conflicts = actor.get("conflicts")
                if not isinstance(conflicts, list) or conflicts:
                    fail(f"{role}: unresolved conflicts")
        missing_roles = REQUIRED_ROLES[blocker] - roles
        if missing_roles:
            fail(f"missing roles: {sorted(missing_roles)}")
        separation = data.get("separation")
        if not isinstance(separation, dict):
            fail("separation missing")
        for key in SEPARATION_KEYS.get(blocker, set()):
            non_placeholder(separation.get(key), f"separation.{key}")
        checks = data.get("checks")
        if not isinstance(checks, list) or not checks:
            fail("checks missing")
        case_ids: set[str] = set()
        for index, check in enumerate(checks):
            case_id = non_placeholder(check.get("case_id"), f"checks[{index}].case_id")
            if case_id in case_ids:
                fail("duplicate check case")
            case_ids.add(case_id)
            if check.get("status") != "PASS":
                fail(f"{case_id}: non-PASS status")
            if not isinstance(check.get("evidence_digest"), str) or not DIGEST.fullmatch(check["evidence_digest"]):
                fail(f"{case_id}: evidence digest missing")
        artifacts = data.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            fail("artifacts missing")
        for index, artifact in enumerate(artifacts):
            non_placeholder(artifact.get("name"), f"artifacts[{index}].name")
            if not isinstance(artifact.get("digest"), str) or not DIGEST.fullmatch(artifact["digest"]):
                fail(f"artifacts[{index}].digest invalid")
            non_placeholder(artifact.get("custody_uri"), f"artifacts[{index}].custody_uri")
            if artifact.get("classification") not in {"PUBLIC", "SANITIZED", "RESTRICTED_REFERENCE"}:
                fail(f"artifacts[{index}].classification invalid")
        for finding in data.get("findings", []):
            if finding.get("severity") in {"CRITICAL", "HIGH", "UNCLASSIFIED"} and finding.get("state") != "CLOSED":
                fail("critical/high/unclassified finding remains open")
        signatures = data.get("signatures")
        if not isinstance(signatures, list) or len(signatures) < 2:
            fail("at least two signatures required")
        current = now or datetime.now(timezone.utc)
        signed_ids: set[str] = set()
        for index, signature in enumerate(signatures):
            signer_id = non_placeholder(signature.get("signer_id"), f"signatures[{index}].signer_id")
            if signer_id in signed_ids:
                fail("signer identities must be distinct")
            signed_ids.add(signer_id)
            non_placeholder(signature.get("role"), f"signatures[{index}].role")
            non_placeholder(signature.get("key_id"), f"signatures[{index}].key_id")
            non_placeholder(signature.get("algorithm"), f"signatures[{index}].algorithm")
            non_placeholder(signature.get("signature"), f"signatures[{index}].signature")
            signed_at = parse_time(signature.get("signed_at"), f"signatures[{index}].signed_at")
            expires_at = parse_time(signature.get("expires_at"), f"signatures[{index}].expires_at")
            if signed_at > current or expires_at <= current or expires_at <= signed_at:
                fail("signature freshness invalid")
            if signature.get("verification") != "VALID":
                fail("signature not valid and current")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--require-closure", action="store_true")
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-tree")
    parser.add_argument("--expected-merge-commit")
    parser.add_argument("--expected-merge-tree")
    args = parser.parse_args()
    expected = None
    if args.require_closure:
        expected = {
            "commit": args.expected_commit,
            "tree": args.expected_tree,
            "merge_commit": args.expected_merge_commit,
            "merge_tree": args.expected_merge_tree,
        }
        if any(value is None for value in expected.values()):
            parser.error("all expected source identities are required with --require-closure")
    for raw_path in args.paths:
        path = Path(raw_path)
        value = json.loads(path.read_text(encoding="utf-8"))
        validate_envelope(value, require_closure=args.require_closure, expected_source=expected)
        print(f"PASS {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
