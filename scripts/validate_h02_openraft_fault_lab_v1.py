#!/usr/bin/env python3
"""Validate the active H02 OpenRaft hostile-fault and linearizability slice."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "planning/HEPTABAO_H02_OPENRAFT_HOSTILE_FAULTS_LINEARIZABILITY_V1.yaml"
QUEUE = ROOT / "planning/HEPTABAO_H02_EXECUTION_QUEUE_V3.yaml"
MANIFEST = ROOT / "probes/h02/openraft-tokio/Cargo.toml"
LOCK = ROOT / "probes/h02/openraft-tokio/Cargo.lock"
MAIN = ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab.rs"
CLUSTER = ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/cluster.rs"
HOSTILE_GUARD = ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/hostile_snapshot_guard.rs"
NETWORK = ROOT / "probes/h02/openraft-tokio/src/bin/inmemory_cluster/network.rs"
CHECKER = ROOT / "scripts/h02_linearizability_checker_v1.py"
COLLECTOR = ROOT / "scripts/h02_openraft_fault_lab_evidence_v1.py"
WORKFLOW = ROOT / ".github/workflows/h02-openraft-fault-lab.yml"
SCHEMAS = [
    ROOT / "schemas/heptabao_h02_linearizability_history_v1.schema.json",
    ROOT / "schemas/heptabao_h02_linearizability_result_v1.schema.json",
    ROOT / "schemas/heptabao_h02_openraft_hostile_snapshot_result_v1.schema.json",
    ROOT / "schemas/heptabao_h02_openraft_fault_lab_evidence_v1.schema.json",
]
TESTS = [
    ROOT / "tests/platform/test_h02_linearizability_checker_v1.py",
    ROOT / "tests/platform/test_h02_openraft_fault_lab_evidence_v1.py",
]


class Failure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: expected mapping")
    return value


def load_schema(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: expected object")
    Draft202012Validator.check_schema(value)
    return value


def require_tokens(path: Path, tokens: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for token in tokens:
        require(token in text, f"{path.relative_to(ROOT)} missing token: {token}")


def main() -> int:
    try:
        required = [
    PLAN,
    QUEUE,
    MANIFEST,
    LOCK,
    MAIN,
    CLUSTER,
    HOSTILE_GUARD,
    NETWORK,
    CHECKER,
    COLLECTOR,
    WORKFLOW,
    *SCHEMAS,
    *TESTS,
]
        for path in required:
            require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")

        plan = load_yaml(PLAN)
        require(plan["schema"] == "heptabao.h02-openraft-hostile-faults-linearizability.v1", "plan schema drift")
        require(str(plan["revision"]) == "1.3", "plan revision mismatch")
        require(
            plan["status"] == "IMPLEMENTED_PENDING_EXACT_HEAD_REMOTE_EXECUTION_NOT_QUALIFIED",
            "plan status must distinguish implementation from exact-head execution",
        )
        require(plan["qualification"] is False, "plan cannot self-qualify")
        require(plan["selection_effect"] == plan["authority_effect"] == "NONE", "authority must remain NONE")
        require(plan["stack"]["parent_pr"] == 24, "stack parent PR mismatch")
        require(plan["stack"]["active_branch"] == "codex/h02-durable-multiprocess-closure-v2", "active branch mismatch")
        matrix = plan["execution_matrix"]
        require(matrix["toolchains"] == ["1.88.0", "1.98.0"], "effective toolchain matrix drift")
        require(matrix["entries"] == 6, "expected 2 effective toolchains x 3 seeds")
        require(matrix["exact_head_remote_executions"] == 0, "source plan cannot claim exact-head executions")
        require(matrix["scheduling"] == "SERIAL_ON_ONE_RUNNER", "fault matrix must be serialized")
        require(plan["historical_local_validation"]["total_python_tests"]["passed"] == 27, "expected historical 27 Python tests")
        require(len(plan["promotion_blockers"]) >= 9, "promotion blocker set is too shallow")
        require(all(value is False for value in plan["authority_flags"].values()), "all authority flags must be false")
        for key, value in plan["related_implemented_closure_layers"].items():
            require(value is True, f"related closure layer must remain explicitly implemented: {key}")

        queue = load_yaml(QUEUE)
        require(str(queue["revision"]) == "1.3", "execution queue revision mismatch")
        require(queue["status"] == "ACTIVE_FAIL_CLOSED", "queue must remain active and fail closed")
        require(queue["qualification"] is False, "queue cannot self-qualify")
        require(queue["authority_effect"] == queue["selection_effect"] == "NONE", "queue authority must remain NONE")
        require(queue["stack"]["parent_pr"] == 24, "queue parent PR mismatch")
        observations = queue.get("verified_runner_observations", [])
        require(isinstance(observations, list) and len(observations) >= 2, "executable failure observations must remain visible")
        require(all(item.get("steps_received") is True for item in observations), "verified observations must have executed steps")
        classifications = {item.get("classification") for item in observations}
        require("EXECUTED_FAIL_STALE_LOCK_GRAPH" in classifications, "stale-lock failure evidence missing")
        require("EXECUTED_FAIL_EFFECTIVE_MSRV_BOUNDARY" in classifications, "MSRV failure evidence missing")
        require(len(queue.get("hard_blocks", [])) >= 8, "queue hard blocks are too shallow")
        require(all(value is False for value in queue["authority_flags"].values()), "queue authority flags must remain false")

        manifest = MANIFEST.read_text(encoding="utf-8")
        for token in [
            'rust-version = "1.88"',
            'name = "heptabao-h02-openraft-fault-lab"',
            'path = "src/bin/openraft_fault_lab.rs"',
            'openraft = { version = "=0.10.0-alpha.33"',
            'openraft-memstore = { version = "=0.10.0-alpha.33"',
            'openraft-rt = "=0.10.0-alpha.33"',
            'openraft-rt-tokio = "=0.10.0-alpha.33"',
            'openraft-macros = "=0.10.0-alpha.33"',
            'tokio = { version = "=1.53.1"',
            '"process"',
            '[patch.crates-io]',
            'git = "https://github.com/drmingdrmer/validit.git"',
            'rev = "7016fa5e072a86092928144b3a3040381e6964e9"',
        ]:
            require(token in manifest, f"manifest binding missing: {token}")
        for mutable_selector in ("branch =", "tag ="):
            require(mutable_selector not in manifest, f"mutable source selector forbidden: {mutable_selector}")
        require(LOCK.stat().st_size > 0, "committed Cargo.lock is empty")

        source = "\n".join(
    [
        MAIN.read_text(encoding="utf-8"),
        CLUSTER.read_text(encoding="utf-8"),
        HOSTILE_GUARD.read_text(encoding="utf-8"),
        NETWORK.read_text(encoding="utf-8"),
    ]
)
        for token in [
            "hostile-snapshot-child",
            "ABOUT_TO_INSTALL_STALE_COMMITTED_SNAPSHOT",
            "current_exe",
            "kill_on_drop",
            "install_full_snapshot",
            "snapshot.meta.last_log_id",
            "execute_hostile_snapshot_child_guarded",
            "guarded_state_unchanged",
            "metrics_unchanged",
            "state_machine_unchanged",
            "get_snapshot",
            "tokio::spawn",
            "ensure_linearizable(ReadPolicy::ReadIndex)",
            "REAL_OPENRAFT_READINDEX_SINGLE_REGISTER_HISTORY",
            "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
            "RaftNetworkFactory<TypeConfig>",
            "RaftNetworkV2<TypeConfig>",
        ]:
            require(token in source, f"fault-lab source token missing: {token}")
        for marker in ["PRIVATE KEY", "root_token", "unseal_share"]:
            require(marker not in source, f"secret marker in source: {marker}")
        cluster_source = CLUSTER.read_text(encoding="utf-8")
        require(
            "pub async fn execute_hostile_snapshot_child(" not in cluster_source,
            "obsolete unguarded stale-snapshot helper must not remain compiled",
        )
        require(
            'include!("openraft_fault_lab/hostile_snapshot_guard.rs")'
            in MAIN.read_text(encoding="utf-8"),
            "fault-lab main must compile the guarded stale-snapshot implementation",
        )

        require_tokens(
            CHECKER,
            [
                "bounded-real-time-precedence-backtracking",
                "MAX_OPERATIONS = 64",
                'earlier["complete"] < later["invoke"]',
                "qualification must remain false",
                "selection_effect must remain NONE",
                "authority_effect must remain NONE",
            ],
        )
        require_tokens(
            COLLECTOR,
            [
                "linearizability result is not bound to the supplied history",
                "hostile result/exit-code mismatch",
                "Rust build/test phase did not succeed",
                "history generator did not execute successfully",
                "source tree is not clean",
                "BLOCK_PENDING_DURABLE_STORE_OS_DISK_CLOCK_AND_INDEPENDENT_REPRODUCTION",
            ],
        )

        schemas = [load_schema(path) for path in SCHEMAS]
        for schema in schemas:
            properties = schema.get("properties", {})
            require(properties.get("qualification", {}).get("const") is False, "schema qualification must be false")
            require(properties.get("authority_effect", {}).get("const") == "NONE", "schema authority must be NONE")
        require(schemas[-1]["properties"]["promotion_effect"]["const"].startswith("BLOCK_"), "combined evidence promotion must remain blocked")

        for path in [CHECKER, COLLECTOR, *TESTS]:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")

        workflow = load_yaml(WORKFLOW)
        jobs = workflow.get("jobs", {})
        require(set(jobs) == {"validate-plan", "fault-sequential", "authority-sentinel"}, "workflow jobs drift")
        sequential = jobs["fault-sequential"]
        require("strategy" not in sequential, "fault workflow must not use a runner-starving matrix")
        require(sequential.get("env", {}).get("TOOLCHAINS") == "1.88.0 1.98.0", "workflow toolchain drift")
        require(len(str(sequential.get("env", {}).get("SEEDS", "")).split()) == 3, "workflow seed set drift")
        require_tokens(
            WORKFLOW,
            [
                "Execute all six fault-lab entries and retain every outcome",
                "0x5eed20260828cafe",
                "0x8badf00d12345678",
                "0xd15ea5e5cafef00d",
                "hostile-snapshot-parent",
                "linearizability-history",
                "h02_linearizability_checker_v1.py",
                "h02_openraft_fault_lab_evidence_v1.py",
                "if: ${{ always() }}",
                "qualification=false",
                "authority=NONE",
            ],
        )

        print(
            "H02 hostile-fault/linearizability validation passed: implementation bound; "
            "effective toolchains=1.88/1.98; exact-head executions=0; authority=NONE"
        )
        return 0
    except (Failure, OSError, ValueError, json.JSONDecodeError, yaml.YAMLError, KeyError) as exc:
        print(f"H02 OpenRaft hostile-fault/linearizability validation FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
