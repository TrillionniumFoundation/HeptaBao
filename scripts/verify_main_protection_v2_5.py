#!/usr/bin/env python3
"""Verify that HeptaBao main protection has no administrator or ruleset bypass.

The verifier consumes immutable JSON snapshots captured by an independently
controlled credential. A passing configuration snapshot is necessary but does
not replace hostile push/merge/delete enforcement evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Iterable

MAX_JSON_BYTES = 2 * 1024 * 1024


class ProtectionError(ValueError):
    """Raised when repository protection is incomplete or ambiguous."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProtectionError(f"duplicate JSON member: {key}")
        value[key] = item
    return value


def _read_json(path: Path) -> tuple[dict[str, Any] | list[Any], str]:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ProtectionError(f"snapshot is not a regular non-symlink file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > MAX_JSON_BYTES:
        raise ProtectionError(f"snapshot size is outside the bound: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise ProtectionError(f"snapshot changed before open: {path}")
        raw = bytearray()
        while len(raw) <= MAX_JSON_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_JSON_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        closed = os.fstat(descriptor)
        if len(raw) != metadata.st_size or len(raw) > MAX_JSON_BYTES:
            raise ProtectionError(f"snapshot changed or exceeded its bound: {path}")
        if (
            closed.st_size != opened.st_size
            or closed.st_mtime_ns != opened.st_mtime_ns
            or closed.st_ctime_ns != opened.st_ctime_ns
        ):
            raise ProtectionError(f"snapshot changed during read: {path}")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtectionError(f"invalid snapshot JSON: {path}: {exc}") from exc
    if not isinstance(value, (dict, list)):
        raise ProtectionError(f"snapshot root must be an object or list: {path}")
    return value, hashlib.sha256(raw).hexdigest()


def _enabled(value: Any, context: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, dict) and isinstance(value.get("enabled"), bool):
        return value["enabled"]
    raise ProtectionError(f"{context} has no explicit boolean enabled state")


def _required_check_names(value: Any) -> set[str]:
    if not isinstance(value, dict):
        raise ProtectionError("required_status_checks must be an object")
    if value.get("strict") is not True:
        raise ProtectionError("required status checks must be strict")
    names: set[str] = set()
    contexts = value.get("contexts", [])
    checks = value.get("checks", [])
    if contexts is not None:
        if not isinstance(contexts, list) or not all(isinstance(item, str) for item in contexts):
            raise ProtectionError("required status contexts must be a string list")
        names.update(contexts)
    if checks is not None:
        if not isinstance(checks, list):
            raise ProtectionError("required status checks list is invalid")
        for item in checks:
            if not isinstance(item, dict) or not isinstance(item.get("context"), str):
                raise ProtectionError("required status check entry is invalid")
            names.add(item["context"])
    if not names:
        raise ProtectionError("no required status checks are configured")
    return names


def _ruleset_applies_to_main(ruleset: dict[str, Any]) -> bool:
    if ruleset.get("enforcement") != "active":
        return False
    target = ruleset.get("target")
    if target not in {"branch", None}:
        return False
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, dict):
        return True
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict):
        return True
    include = ref_name.get("include", [])
    exclude = ref_name.get("exclude", [])
    if not isinstance(include, list) or not isinstance(exclude, list):
        raise ProtectionError("ruleset ref_name conditions are invalid")
    candidates = {"refs/heads/main", "~DEFAULT_BRANCH"}
    included = not include or any(item in candidates for item in include)
    excluded = any(item in candidates for item in exclude)
    return included and not excluded


def verify(
    branch_protection: dict[str, Any],
    rulesets: list[Any],
    required_checks: set[str],
) -> dict[str, Any]:
    if not isinstance(branch_protection, dict):
        raise ProtectionError("branch-protection snapshot must be an object")
    observed_checks = _required_check_names(branch_protection.get("required_status_checks"))
    missing_checks = sorted(required_checks - observed_checks)
    if missing_checks:
        raise ProtectionError(f"missing required checks: {missing_checks}")

    if not _enabled(branch_protection.get("enforce_admins"), "enforce_admins"):
        raise ProtectionError("administrators are not bound by branch protection")

    reviews = branch_protection.get("required_pull_request_reviews")
    if not isinstance(reviews, dict):
        raise ProtectionError("pull-request reviews are not required")
    if reviews.get("dismiss_stale_reviews") is not True:
        raise ProtectionError("stale approvals are not dismissed")
    if reviews.get("require_code_owner_reviews") is not True:
        raise ProtectionError("Code Owner review is not required")
    if reviews.get("require_last_push_approval") is not True:
        raise ProtectionError("last-push approval is not required")
    count = reviews.get("required_approving_review_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 2:
        raise ProtectionError("at least two approvals are required")
    bypass = reviews.get("bypass_pull_request_allowances")
    if bypass is not None:
        if not isinstance(bypass, dict):
            raise ProtectionError("pull-request bypass allowances are malformed")
        for category in ("users", "teams", "apps"):
            if bypass.get(category) not in (None, []):
                raise ProtectionError(f"pull-request bypass allowance is non-empty: {category}")

    if not _enabled(
        branch_protection.get("required_conversation_resolution"),
        "required_conversation_resolution",
    ):
        raise ProtectionError("review conversations need not be resolved")
    if not _enabled(branch_protection.get("required_linear_history"), "required_linear_history"):
        raise ProtectionError("linear history is not required")
    if _enabled(branch_protection.get("allow_force_pushes"), "allow_force_pushes"):
        raise ProtectionError("force pushes are allowed")
    if _enabled(branch_protection.get("allow_deletions"), "allow_deletions"):
        raise ProtectionError("branch deletion is allowed")
    if "lock_branch" in branch_protection and _enabled(
        branch_protection.get("lock_branch"), "lock_branch"
    ):
        raise ProtectionError("main is permanently locked rather than protected by review")

    if not isinstance(rulesets, list):
        raise ProtectionError("rulesets snapshot must be a list")
    active_ids: list[int | str] = []
    for raw in rulesets:
        if not isinstance(raw, dict):
            raise ProtectionError("ruleset entry must be an object")
        if not _ruleset_applies_to_main(raw):
            continue
        active_ids.append(raw.get("id", "unknown"))
        bypass_actors = raw.get("bypass_actors", [])
        if bypass_actors not in (None, []):
            raise ProtectionError(
                f"active main ruleset has bypass actors: {raw.get('id', 'unknown')}"
            )

    return {
        "schema": "heptabao.main-protection-verification.v2.5",
        "configuration_pass": True,
        "required_checks": sorted(required_checks),
        "observed_checks": sorted(observed_checks),
        "active_main_rulesets": active_ids,
        "hostile_enforcement_required": True,
        "authority_effect": "NONE",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--branch-protection", type=Path, required=True)
    parser.add_argument("--rulesets", type=Path, required=True)
    parser.add_argument("--expected-branch-protection-sha256", required=True)
    parser.add_argument("--expected-rulesets-sha256", required=True)
    parser.add_argument("--required-check", action="append", required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        protection, protection_digest = _read_json(arguments.branch_protection)
        rulesets, rulesets_digest = _read_json(arguments.rulesets)
        if protection_digest != arguments.expected_branch_protection_sha256:
            raise ProtectionError("branch-protection snapshot digest does not match its pin")
        if rulesets_digest != arguments.expected_rulesets_sha256:
            raise ProtectionError("rulesets snapshot digest does not match its pin")
        if not isinstance(protection, dict) or not isinstance(rulesets, list):
            raise ProtectionError("snapshot root types are invalid")
        result = verify(protection, rulesets, set(arguments.required_check))
        result["branch_protection_sha256"] = protection_digest
        result["rulesets_sha256"] = rulesets_digest
    except (OSError, ProtectionError, ValueError) as exc:
        print(json.dumps({"configuration_pass": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
