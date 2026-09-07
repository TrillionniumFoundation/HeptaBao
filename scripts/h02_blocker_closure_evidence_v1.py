#!/usr/bin/env python3
"""Build fail-closed H02 OS/durable/clock blocker-closure evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "heptabao.h02-blocker-closure-evidence.v1"
RESULT_SCHEMA = "heptabao.h02-blocker-closure-result.v1"
PROMOTION_EFFECT = "BLOCK_PENDING_OPENRAFT_DURABLE_STORE_INTEGRATION_PER_NODE_KERNEL_CLOCK_AND_EXTERNAL_APPROVALS"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def component_pass(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("status") == "EXECUTED_PASS"
        and value.get("qualification") is False
        and value.get("selection_effect") == "NONE"
        and value.get("authority_effect") == "NONE"
    )


def technical_pass(result: Any, execution_exit_code: int, clean_tree: bool) -> bool:
    if not isinstance(result, dict):
        return False
    if result.get("schema") != RESULT_SCHEMA:
        return False
    if result.get("candidate_id") != "HB-DEP-RAFT-OPENRAFT" or result.get("version") != "0.10.0-alpha.33":
        return False
    if result.get("status") != "EXECUTED_PASS" or execution_exit_code != 0 or not clean_tree:
        return False
    if result.get("qualification") is not False:
        return False
    if result.get("selection_effect") != "NONE" or result.get("authority_effect") != "NONE":
        return False
    if result.get("promotion_effect") != PROMOTION_EFFECT:
        return False
    components = result.get("components")
    if not isinstance(components, dict):
        return False
    if not all(component_pass(components.get(name)) for name in ("os_suspend", "durable_faults", "clock_faults")):
        return False
    scope = result.get("scope")
    return isinstance(scope, dict) and all(
        scope.get(name) is True
        for name in (
            "os_process_suspend_executed",
            "heptabao_file_wal_faults_executed",
            "openraft_real_writes_and_readindex_under_wall_projection",
        )
    )


def classify(result: Any, execution_exit_code: int, clean_tree: bool) -> str:
    if technical_pass(result, execution_exit_code, clean_tree):
        return "EXECUTED_PASS"
    if isinstance(result, dict) and result.get("status") == "EXECUTED_FAIL" and execution_exit_code == 0:
        return "EXECUTED_FAIL"
    return "BLOCKED"


def build_evidence(
    *,
    result: Any,
    execution_exit_code: int,
    seed: str,
    toolchain: str,
    manifest: Path,
    cargo_lock: Path,
    source_commit: str,
    source_tree: str,
    branch: str,
    clean_tree: bool,
    environment_id: str,
    executor_kind: str,
    runner_id: str,
    runner_name: str,
) -> dict[str, Any]:
    status = classify(result, execution_exit_code, clean_tree)
    scope = result.get("scope", {}) if isinstance(result, dict) else {}
    return {
        "schema": SCHEMA,
        "plan_id": "HEPTABAO-PLAN-2026-08-28",
        "revision": "1.1",
        "status": status,
        "candidate": {
            "candidate_id": "HB-DEP-RAFT-OPENRAFT",
            "version": "0.10.0-alpha.33",
            "profile_id": "HB-H02-BLOCKER-CLOSURE-OPENRAFT-0_10_0_ALPHA_33",
        },
        "source": {
            "repository": "ProfHepta/HeptaBao",
            "branch": branch,
            "commit": source_commit,
            "tree": source_tree,
            "clean_tree": clean_tree,
            "manifest_sha256": sha256_file(manifest),
            "cargo_lock_sha256": sha256_file(cargo_lock),
        },
        "execution": {
            "seed": seed,
            "toolchain": toolchain,
            "target": "x86_64-unknown-linux-gnu",
            "exit_code": execution_exit_code,
            "environment_id": environment_id,
            "executor_kind": executor_kind,
            "runner_id": runner_id,
            "runner_name": runner_name,
        },
        "result": result,
        "result_sha256": hashlib.sha256(canonical_bytes(result)).hexdigest(),
        "technical_scope": {
            "os_suspend": scope.get("os_process_suspend_executed") is True,
            "file_wal_faults": scope.get("heptabao_file_wal_faults_executed") is True,
            "real_openraft_clock_projection": scope.get("openraft_real_writes_and_readindex_under_wall_projection") is True,
        },
        "remaining_external_gaps": {
            "openraft_durable_store_integration": scope.get("openraft_durable_store_integrated") is not True,
            "per_node_kernel_clock_skew": scope.get("per_node_kernel_clock_skew") is not True,
            "second_independent_attested_environment": True,
            "independent_approvals": scope.get("independent_external_approvals") is not True,
            "signed_selection_receipt": True,
        },
        "review_status": "PENDING",
        "qualification": False,
        "selection_effect": "NONE",
        "promotion_effect": PROMOTION_EFFECT,
        "authority_effect": "NONE",
    }


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def command_collect(args: argparse.Namespace) -> int:
    result = load_json(Path(args.result))
    evidence = build_evidence(
        result=result,
        execution_exit_code=args.execution_exit_code,
        seed=args.seed,
        toolchain=args.toolchain,
        manifest=Path(args.manifest),
        cargo_lock=Path(args.cargo_lock),
        source_commit=args.source_commit,
        source_tree=args.source_tree,
        branch=args.branch,
        clean_tree=args.clean_tree,
        environment_id=args.environment_id,
        executor_kind=args.executor_kind,
        runner_id=args.runner_id,
        runner_name=args.runner_name,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(evidence["status"], evidence["promotion_effect"])
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)
    collect = sub.add_parser("collect")
    collect.add_argument("--result", required=True)
    collect.add_argument("--execution-exit-code", required=True, type=int)
    collect.add_argument("--seed", required=True)
    collect.add_argument("--toolchain", required=True)
    collect.add_argument("--manifest", required=True)
    collect.add_argument("--cargo-lock", required=True)
    collect.add_argument("--source-commit", required=True)
    collect.add_argument("--source-tree", required=True)
    collect.add_argument("--branch", required=True)
    collect.add_argument("--clean-tree", action="store_true")
    collect.add_argument("--environment-id", required=True)
    collect.add_argument("--executor-kind", required=True)
    collect.add_argument("--runner-id", required=True)
    collect.add_argument("--runner-name", required=True)
    collect.add_argument("--output", required=True)
    collect.set_defaults(func=command_collect)
    return root


def main() -> int:
    args = parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
