#!/usr/bin/env python3
"""Collect fail-closed evidence for the H02 OpenRaft hostile-fault and linearizability lab."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "heptabao.h02-openraft-fault-lab-evidence.v1"
HOSTILE_SCHEMA = "heptabao.h02-openraft-hostile-snapshot-result.v1"
HISTORY_SCHEMA = "heptabao.h02-linearizability-history.v1"
LINEAR_RESULT_SCHEMA = "heptabao.h02-linearizability-result.v1"
EXPECTED_CANDIDATE = "HB-DEP-RAFT-OPENRAFT"
EXPECTED_VERSION = "0.10.0-alpha.33"
EXPECTED_PROFILE = "HB-H02-FAULT-LAB-OPENRAFT-0_10_0_ALPHA_33"
PROMOTION_EFFECT = "BLOCK_PENDING_DURABLE_STORE_OS_DISK_CLOCK_AND_INDEPENDENT_REPRODUCTION"


class EvidenceError(ValueError):
    """The evidence inputs are malformed or contradict one another."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _require_authority_closed(value: dict[str, Any], label: str) -> None:
    if value.get("qualification") is not False:
        raise EvidenceError(f"{label}.qualification must remain false")
    if value.get("selection_effect") != "NONE":
        raise EvidenceError(f"{label}.selection_effect must remain NONE")
    if value.get("authority_effect") != "NONE":
        raise EvidenceError(f"{label}.authority_effect must remain NONE")


def _validate_binding(value: dict[str, Any], label: str, seed: str) -> None:
    if value.get("candidate_id") != EXPECTED_CANDIDATE:
        raise EvidenceError(f"{label}.candidate_id mismatch")
    if value.get("version") != EXPECTED_VERSION:
        raise EvidenceError(f"{label}.version mismatch")
    if value.get("profile_id") != EXPECTED_PROFILE:
        raise EvidenceError(f"{label}.profile_id mismatch")
    if value.get("seed") != seed:
        raise EvidenceError(f"{label}.seed mismatch")
    _require_authority_closed(value, label)


def _expected_checker_exit(status: str) -> int:
    try:
        return {"EXECUTED_PASS": 0, "EXECUTED_FAIL": 1, "BLOCKED": 2}[status]
    except KeyError as exc:
        raise EvidenceError(f"unknown linearizability status: {status}") from exc


def _expected_hostile_exit(status: str) -> int:
    if status in {"EXECUTED_PASS", "EXECUTED_FAIL"}:
        return 0
    if status == "BLOCKED":
        return 2
    raise EvidenceError(f"unknown hostile snapshot status: {status}")


def build_blocked_skeleton(args: argparse.Namespace, reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "plan_id": "HEPTABAO-PLAN-2026-08-28",
        "revision": "1.2",
        "status": "BLOCKED",
        "candidate": {
            "candidate_id": EXPECTED_CANDIDATE,
            "version": EXPECTED_VERSION,
            "profile_id": EXPECTED_PROFILE,
            "seed": args.seed,
            "toolchain": args.toolchain,
            "target": args.target,
        },
        "source": {
            "repository": args.repository,
            "branch": args.branch,
            "commit": args.source_commit,
            "tree": args.source_tree,
            "clean_tree": bool(args.clean_tree),
        },
        "executor": {
            "environment_id": args.environment_id,
            "executor_kind": args.executor_kind,
            "runner_id": args.runner_id,
            "runner_name": args.runner_name,
        },
        "artifacts": {},
        "execution": {
            "build_exit_code": args.build_exit_code,
            "hostile_exit_code": args.hostile_exit_code,
            "history_exit_code": args.history_exit_code,
            "checker_exit_code": args.checker_exit_code,
        },
        "results": {"hostile_snapshot": None, "linearizability": None},
        "reason": reason,
        "qualification": False,
        "selection_effect": "NONE",
        "promotion_effect": PROMOTION_EFFECT,
        "authority_effect": "NONE",
    }


def collect(args: argparse.Namespace) -> dict[str, Any]:
    try:
        hostile = _load_json(args.hostile_result)
        history = _load_json(args.history)
        linear = _load_json(args.linearizability_result)
        if not isinstance(hostile, dict) or hostile.get("schema") != HOSTILE_SCHEMA:
            raise EvidenceError("hostile result schema mismatch")
        if not isinstance(history, dict) or history.get("schema") != HISTORY_SCHEMA:
            raise EvidenceError("history schema mismatch")
        if not isinstance(linear, dict) or linear.get("schema") != LINEAR_RESULT_SCHEMA:
            raise EvidenceError("linearizability result schema mismatch")

        _validate_binding(hostile, "hostile_result", args.seed)
        _validate_binding(history, "history", args.seed)
        _require_authority_closed(linear, "linearizability_result")
        if history.get("durability_class") != "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM":
            raise EvidenceError("history durability class mismatch")
        if hostile.get("durability_class") != "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM":
            raise EvidenceError("hostile result durability class mismatch")
        if history.get("execution_scope") != "REAL_OPENRAFT_READINDEX_SINGLE_REGISTER_HISTORY":
            raise EvidenceError("history execution scope mismatch")
        if hostile.get("execution_scope") != "ISOLATED_CHILD_REAL_OPENRAFT_STALE_COMMITTED_SNAPSHOT_INJECTION":
            raise EvidenceError("hostile result execution scope mismatch")

        history_digest = canonical_sha256(history)
        if linear.get("history_sha256") != history_digest:
            raise EvidenceError("linearizability result is not bound to the supplied history")
        if not isinstance(linear.get("operation_count"), int) or linear["operation_count"] != len(history.get("operations", [])):
            raise EvidenceError("linearizability operation count mismatch")
        if args.build_exit_code != 0:
            raise EvidenceError("Rust build/test phase did not succeed")

        hostile_status = hostile.get("status")
        linear_status = linear.get("status")
        expected_hostile_exit = _expected_hostile_exit(hostile_status)
        expected_checker_exit = _expected_checker_exit(linear_status)
        if hostile_status == "BLOCKED":
            if args.hostile_exit_code not in {0, expected_hostile_exit}:
                raise EvidenceError("hostile result/exit-code mismatch")
        elif args.hostile_exit_code != expected_hostile_exit:
            raise EvidenceError("hostile result/exit-code mismatch")
        if args.history_exit_code != 0:
            raise EvidenceError("history generator did not execute successfully")
        if args.checker_exit_code != expected_checker_exit:
            raise EvidenceError("checker result/exit-code mismatch")
        if not args.clean_tree:
            raise EvidenceError("source tree is not clean")
        if not args.manifest.is_file() or args.manifest.stat().st_size == 0:
            raise EvidenceError("manifest is missing or empty")
        if not args.cargo_lock.is_file() or args.cargo_lock.stat().st_size == 0:
            raise EvidenceError("Cargo.lock is missing or empty")

        if hostile_status == "BLOCKED" or linear_status == "BLOCKED":
            status, reason = "BLOCKED", "at least one required fault-lab component was blocked"
        elif hostile_status == "EXECUTED_FAIL" or linear_status == "EXECUTED_FAIL":
            status, reason = "EXECUTED_FAIL", "at least one required safety or linearizability assertion failed"
        elif hostile_status == "EXECUTED_PASS" and linear_status == "EXECUTED_PASS":
            status, reason = "EXECUTED_PASS", "hostile snapshot rejection and external single-register linearizability checks passed"
        else:
            raise EvidenceError("unreachable result-state combination")

        result = build_blocked_skeleton(args, reason)
        result["status"] = status
        result["artifacts"] = {
            "manifest_sha256": file_sha256(args.manifest),
            "cargo_lock_sha256": file_sha256(args.cargo_lock),
            "hostile_result_sha256": file_sha256(args.hostile_result),
            "history_sha256": history_digest,
            "linearizability_result_sha256": file_sha256(args.linearizability_result),
        }
        result["results"] = {
            "hostile_snapshot": {
                "status": hostile_status,
                "phase_reached": hostile.get("phase_reached"),
                "outcome": hostile.get("outcome"),
                "child_exit_code": hostile.get("child_exit_code"),
            },
            "linearizability": {
                "status": linear_status,
                "linearizable": linear.get("linearizable"),
                "operation_count": linear.get("operation_count"),
                "witness_order": linear.get("witness_order", []),
                "explored_states": linear.get("explored_states"),
            },
        }
        result["scope"] = {
            "real_openraft_candidate": True,
            "isolated_hostile_snapshot_child": True,
            "stale_committed_snapshot_injection": True,
            "real_readindex_history": True,
            "external_checker": True,
            "production_durable_storage": False,
            "os_process_suspend": False,
            "disk_stall_torn_write_corruption": False,
            "clock_fault": False,
            "independent_reproduction": False,
        }
        return result
    except (OSError, json.JSONDecodeError, EvidenceError) as exc:
        return build_blocked_skeleton(args, str(exc))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def command_collect(args: argparse.Namespace) -> int:
    result = collect(args)
    _write_json(args.output, result)
    print(f"{result['status']} reason={result['reason']}")
    return {"EXECUTED_PASS": 0, "EXECUTED_FAIL": 1, "BLOCKED": 2}[result["status"]]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--hostile-result", type=Path, required=True)
    collect_parser.add_argument("--history", type=Path, required=True)
    collect_parser.add_argument("--linearizability-result", type=Path, required=True)
    collect_parser.add_argument("--build-exit-code", type=int, required=True)
    collect_parser.add_argument("--hostile-exit-code", type=int, required=True)
    collect_parser.add_argument("--history-exit-code", type=int, required=True)
    collect_parser.add_argument("--checker-exit-code", type=int, required=True)
    collect_parser.add_argument("--seed", required=True)
    collect_parser.add_argument("--toolchain", required=True)
    collect_parser.add_argument("--target", default="x86_64-unknown-linux-gnu")
    collect_parser.add_argument("--manifest", type=Path, required=True)
    collect_parser.add_argument("--cargo-lock", type=Path, required=True)
    collect_parser.add_argument("--repository", default="ProfHepta/HeptaBao")
    collect_parser.add_argument("--source-commit", required=True)
    collect_parser.add_argument("--source-tree", required=True)
    collect_parser.add_argument("--branch", required=True)
    collect_parser.add_argument("--clean-tree", action="store_true")
    collect_parser.add_argument("--environment-id", required=True)
    collect_parser.add_argument("--executor-kind", required=True)
    collect_parser.add_argument("--runner-id", required=True)
    collect_parser.add_argument("--runner-name", required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    collect_parser.set_defaults(func=command_collect)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
