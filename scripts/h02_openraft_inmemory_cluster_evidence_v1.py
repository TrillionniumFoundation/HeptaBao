#!/usr/bin/env python3
"""Collect fail-closed evidence from the exact OpenRaft in-memory cluster probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path
from typing import Any

PLAN_ID = "HEPTABAO-PLAN-2026-08-28"
REVISION = "1.1"
PROFILE_ID = "HB-H02-BEHAVIOR-RAFT-OPENRAFT-INMEMORY-0_10_0_ALPHA_33"
CANDIDATE_ID = "HB-DEP-RAFT-OPENRAFT"
EFFECTIVE_TOOLCHAINS = ("1.88.0", "1.98.0")
SNAPSHOT_CASE_ID = "raft-committed-snapshot-conflict-rejected"
CASES = [
    "raft-deterministic-apply-and-restart",
    SNAPSHOT_CASE_ID,
    "raft-joint-membership-single-writer",
    "raft-process-pause-plus-partition",
    "raft-quorum-loss-fail-closed",
    "raft-incomplete-run-replay-diagnostics",
]
LIMITATIONS = [
    "openraft-memstore is test-only in-memory storage and creates no production durability claim",
    "the named snapshot case executes an in-process stale committed-snapshot injection; the isolated hostile child remains the process-fatal availability boundary",
    "operating-system process suspension, durable disk faults and clock faults are evaluated by separate blocker probes",
    "no second independent attested environment or independent specialist review exists",
]


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def parse_jsonl(
    path: Path,
) -> tuple[
    dict[str, Any] | None,
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    if not path.is_file():
        return None, [], []
    meta = None
    cases: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append({"line": number, "error": f"invalid-json:{exc.msg}"})
            continue
        kind = value.get("kind")
        if kind == "meta" and meta is None:
            meta = value
        elif kind == "case":
            cases.append(value)
        elif kind == "harness_error":
            errors.append(value)
        else:
            errors.append({"line": number, "error": f"unexpected-kind:{kind}"})
    return meta, cases, errors


def case_map(cases: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for value in cases:
        case_id = value.get("case_id")
        if not isinstance(case_id, str) or case_id in result:
            continue
        result[case_id] = value
    return result


def snapshot_semantics(detail: Any) -> tuple[bool, list[str]]:
    if not isinstance(detail, dict):
        return False, ["snapshot-detail-not-object"]
    failures: list[str] = []
    if detail.get("full_snapshot_rpc_seen") is not True:
        failures.append("full-snapshot-rpc-not-observed")
    if detail.get("committed_index_monotonic") is not True:
        failures.append("committed-index-not-monotonic")
    if detail.get("lagging_node_converged") is not True:
        failures.append("lagging-node-not-converged")
    if detail.get("hostile_snapshot_conflict_injection") != "EXECUTED_REJECTED":
        failures.append("hostile-snapshot-not-executed-and-rejected")
    if detail.get("hostile_snapshot_phase_reached") is not True:
        failures.append("hostile-snapshot-phase-not-reached")
    if detail.get("hostile_guarded_state_unchanged") is not True:
        failures.append("hostile-snapshot-guarded-state-changed")
    observation = detail.get("hostile_snapshot_observation")
    if not isinstance(observation, dict):
        failures.append("hostile-snapshot-observation-missing")
    else:
        if observation.get("outcome") != "REJECTED":
            failures.append("hostile-snapshot-outcome-not-rejected")
        if observation.get("guarded_state_unchanged") is not True:
            failures.append("hostile-snapshot-observation-state-changed")
    return not failures, failures


def collect(args: argparse.Namespace) -> dict[str, Any]:
    output_path = Path(args.adapter_output)
    replay_path = Path(args.replay_output)
    meta, raw_cases, errors = parse_jsonl(output_path)
    replay_meta, replay_cases, replay_errors = parse_jsonl(replay_path)
    errors.extend(replay_errors)

    expected_meta = {
        "candidate_id": CANDIDATE_ID,
        "version": "0.10.0-alpha.33",
        "profile_id": PROFILE_ID,
        "domain": "RAFT",
        "seed": args.seed.lower(),
        "durability_class": "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
        "qualification": False,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
    }
    if meta is None:
        errors.append({"error": "missing-meta"})
    else:
        for key, expected in expected_meta.items():
            if meta.get(key) != expected:
                errors.append(
                    {
                        "error": f"meta-mismatch:{key}",
                        "got": meta.get(key),
                        "expected": expected,
                    }
                )

    replay_match = False
    if output_path.is_file() and replay_path.is_file():
        replay_match = canonical({"meta": meta, "cases": raw_cases}) == canonical(
            {"meta": replay_meta, "cases": replay_cases}
        )
        if not replay_match:
            errors.append({"error": "same-seed-replay-mismatch"})

    by_id = case_map(raw_cases)
    evidence_cases: list[dict[str, Any]] = []
    for case_id in CASES:
        raw_case = by_id.get(case_id)
        if raw_case is None:
            status = "BLOCKED"
            assertions = 1
            details: Any = {"reason": "missing-required-case"}
        else:
            raw_status = raw_case.get("status")
            status = (
                raw_status
                if raw_status
                in {"PASS", "FAIL", "BLOCKED", "UNEXECUTED", "UNKNOWN"}
                else "UNKNOWN"
            )
            assertions = raw_case.get("assertion_count")
            if not isinstance(assertions, int) or assertions < 1:
                assertions = 1
                status = "UNKNOWN"
            details = raw_case.get("detail", {})
            if case_id == SNAPSHOT_CASE_ID and status == "PASS":
                semantic_pass, semantic_failures = snapshot_semantics(details)
                if not semantic_pass:
                    status = "FAIL"
                    details = {
                        "reported_detail": details,
                        "semantic_failures": semantic_failures,
                    }
        evidence_cases.append(
            {
                "case_id": case_id,
                "status": status,
                "assertion_count": assertions,
                "details_sha256": sha256_bytes(canonical(details)),
            }
        )

    if args.execution_exit_code != 0 or errors:
        for case in evidence_cases:
            if case["status"] == "PASS":
                case["status"] = "BLOCKED"

    counts = {
        name: sum(case["status"] == label for case in evidence_cases)
        for name, label in [
            ("passed", "PASS"),
            ("failed", "FAIL"),
            ("blocked", "BLOCKED"),
            ("unexecuted", "UNEXECUTED"),
            ("unknown", "UNKNOWN"),
        ]
    }
    if args.execution_exit_code != 0 or errors:
        status = "BLOCKED"
    elif counts["failed"]:
        status = "EXECUTED_FAIL"
    elif counts["blocked"] or counts["unexecuted"] or counts["unknown"]:
        status = "BLOCKED"
    elif counts["passed"] == len(CASES) and replay_match:
        status = "EXECUTED_PASS"
    else:
        status = "UNKNOWN"

    snapshot_case = by_id.get(SNAPSHOT_CASE_ID, {})
    snapshot_detail = (
        snapshot_case.get("detail", {}) if isinstance(snapshot_case, dict) else {}
    )
    snapshot_ok, _ = snapshot_semantics(snapshot_detail)
    full_snapshot_rpc = bool(
        isinstance(snapshot_detail, dict)
        and snapshot_detail.get("full_snapshot_rpc_seen")
    )

    seed_value = int(args.seed, 16)
    manifest = Path(args.manifest)
    lockfile = Path(args.cargo_lock)
    return {
        "schema": "heptabao.h02-openraft-cluster-evidence.v1",
        "plan_id": PLAN_ID,
        "revision": REVISION,
        "status": status,
        "profile_id": PROFILE_ID,
        "candidate": {
            "candidate_id": CANDIDATE_ID,
            "package": "openraft",
            "version": "0.10.0-alpha.33",
            "bound": True,
        },
        "source": {
            "repository": "ProfHepta/HeptaBao",
            "commit_sha": args.source_commit,
            "tree_sha": args.source_tree,
            "branch": args.branch,
            "clean_tree": args.clean_tree,
        },
        "environment": {
            "environment_id": args.environment_id,
            "executor_kind": args.executor_kind,
            "runner_id": args.runner_id,
            "runner_name": args.runner_name,
            "os": platform.system(),
            "architecture": platform.machine(),
            "rust_toolchain": args.toolchain,
            "target": "x86_64-unknown-linux-gnu",
            "attested": False,
        },
        "seed": {"decimal": seed_value, "hex": f"0x{seed_value:016x}"},
        "dependencies": {
            "openraft": "0.10.0-alpha.33",
            "openraft_memstore": "0.10.0-alpha.33",
            "tokio": "1.53.1",
            "cargo_lock_sha256": (
                sha256_file(lockfile) if lockfile.is_file() else "0" * 64
            ),
            "manifest_sha256": (
                sha256_file(manifest) if manifest.is_file() else "0" * 64
            ),
        },
        "scope": {
            "real_raft_nodes": 3,
            "real_network_factory": True,
            "real_log_store": True,
            "real_state_machine": True,
            "real_membership_change": True,
            "real_client_write": True,
            "real_read_index": True,
            "real_full_snapshot_rpc": full_snapshot_rpc and snapshot_ok,
            "durability_class": "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
        },
        "cases": evidence_cases,
        "summary": {"total": 6, **counts},
        "replay_match": replay_match,
        "limitations": LIMITATIONS,
        "review_status": "PENDING",
        "qualification": False,
        "selection_effect": "NONE",
        "promotion_effect": "BLOCK_PENDING_DURABLE_STORE_AND_HOSTILE_FAULTS",
        "authority_effect": "NONE",
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    sub = value.add_subparsers(dest="command", required=True)
    command = sub.add_parser("collect")
    command.add_argument("--adapter-output", required=True)
    command.add_argument("--replay-output", required=True)
    command.add_argument("--execution-exit-code", type=int, required=True)
    command.add_argument("--seed", required=True)
    command.add_argument("--toolchain", choices=EFFECTIVE_TOOLCHAINS, required=True)
    command.add_argument("--manifest", required=True)
    command.add_argument("--cargo-lock", required=True)
    command.add_argument("--source-commit", required=True)
    command.add_argument("--source-tree", required=True)
    command.add_argument("--branch", required=True)
    command.add_argument("--clean-tree", action="store_true")
    command.add_argument("--environment-id", required=True)
    command.add_argument(
        "--executor-kind",
        choices=[
            "local-container",
            "github-hosted",
            "self-hosted",
            "offline-lab",
        ],
        required=True,
    )
    command.add_argument("--runner-id")
    command.add_argument("--runner-name")
    command.add_argument("--output", required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    evidence = collect(args)
    Path(args.output).write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(evidence["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
