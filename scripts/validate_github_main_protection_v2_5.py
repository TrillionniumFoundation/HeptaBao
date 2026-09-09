#!/usr/bin/env python3
"""Validate a captured GitHub ``main`` protection snapshot fail closed.

The output is a repository-control observation, not authority.  Hostile API
operations proving that bypass, force push and deletion are denied remain
separate signed cases in ``HB-BLK-CTRL-001``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from heptabao_external_evidence_io_v2_5 import EvidenceIoError, load_json_file


class ProtectionError(ValueError):
    """The captured protection state does not satisfy the required policy."""


def _object(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ProtectionError(f"{where} must be an object")
    return value


def _enabled(value: Any, where: str, expected: bool = True) -> None:
    item = _object(value, where)
    if item.get("enabled") is not expected:
        raise ProtectionError(f"{where}.enabled must be {str(expected).lower()}")


def validate_snapshot(
    branch: Any,
    protection: Any,
    *,
    expected_repository_url: str,
    required_contexts: set[str],
) -> dict[str, Any]:
    branch = _object(branch, "branch")
    protection = _object(protection, "protection")
    if branch.get("name") != "main":
        raise ProtectionError("snapshot is not for main")
    if branch.get("protected") is not True:
        raise ProtectionError("main is not marked protected")
    protection_url = branch.get("protection_url")
    if (
        not isinstance(protection_url, str)
        or protection_url != expected_repository_url.rstrip("/")
        + "/branches/main/protection"
    ):
        raise ProtectionError("branch protection URL binding mismatch")
    if not required_contexts:
        raise ProtectionError("at least one required status context is required")

    status = _object(
        protection.get("required_status_checks"), "required_status_checks"
    )
    if status.get("strict") is not True:
        raise ProtectionError("required status checks must be strict")
    observed_contexts = status.get("contexts")
    if not isinstance(observed_contexts, list) or any(
        not isinstance(item, str) or not item for item in observed_contexts
    ):
        raise ProtectionError("required status contexts are invalid")
    if len(observed_contexts) != len(set(observed_contexts)):
        raise ProtectionError("required status contexts contain duplicates")
    missing_contexts = required_contexts - set(observed_contexts)
    if missing_contexts:
        raise ProtectionError(
            f"required status contexts are missing: {sorted(missing_contexts)}"
        )

    _enabled(protection.get("enforce_admins"), "enforce_admins")
    reviews = _object(
        protection.get("required_pull_request_reviews"),
        "required_pull_request_reviews",
    )
    if reviews.get("dismiss_stale_reviews") is not True:
        raise ProtectionError("stale reviews must be dismissed")
    if reviews.get("require_code_owner_reviews") is not True:
        raise ProtectionError("Code Owner review must be required")
    count = reviews.get("required_approving_review_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 2:
        raise ProtectionError("at least two approving reviews are required")
    if reviews.get("require_last_push_approval") is not True:
        raise ProtectionError("last-push approval separation is required")
    for name in (
        "bypass_pull_request_allowances",
        "dismissal_restrictions",
    ):
        allowance = reviews.get(name)
        if allowance not in (None, {}) and any(
            allowance.get(key) for key in ("users", "teams", "apps")
        ):
            raise ProtectionError(f"{name} must not grant bypass actors")

    _enabled(
        protection.get("required_conversation_resolution"),
        "required_conversation_resolution",
    )
    _enabled(
        protection.get("required_linear_history"),
        "required_linear_history",
    )
    _enabled(
        protection.get("allow_force_pushes"),
        "allow_force_pushes",
        expected=False,
    )
    _enabled(
        protection.get("allow_deletions"),
        "allow_deletions",
        expected=False,
    )
    if protection.get("lock_branch", {}).get("enabled") is True:
        raise ProtectionError("main must not be permanently locked")

    return {
        "status": "GITHUB_MAIN_PROTECTION_POLICY_SATISFIED_NOT_AUTHORITY",
        "branch": "main",
        "strict": True,
        "required_contexts": sorted(required_contexts),
        "approval_count": count,
        "enforce_admins": True,
        "force_pushes_allowed": False,
        "deletions_allowed": False,
        "authority_effect": "NONE",
    }


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--branch-snapshot", required=True, type=Path)
    parser.add_argument("--protection-snapshot", required=True, type=Path)
    parser.add_argument("--expected-repository-url", required=True)
    parser.add_argument(
        "--required-status-context", action="append", default=[]
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    try:
        _branch_raw, branch = load_json_file(args.branch_snapshot)
        _protection_raw, protection = load_json_file(
            args.protection_snapshot
        )
        result = validate_snapshot(
            branch,
            protection,
            expected_repository_url=args.expected_repository_url,
            required_contexts=set(args.required_status_context),
        )
    except (OSError, EvidenceIoError, ProtectionError) as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
