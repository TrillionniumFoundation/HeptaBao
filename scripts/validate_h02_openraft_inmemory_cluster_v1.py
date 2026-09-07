#!/usr/bin/env python3
"""Semantic validation for the active OpenRaft in-memory cluster slice."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "planning/HEPTABAO_H02_OPENRAFT_INMEMORY_CLUSTER_V1.yaml"
SCHEMA = ROOT / "schemas/heptabao_h02_openraft_cluster_evidence_v1.schema.json"
MANIFEST = ROOT / "probes/h02/openraft-tokio/Cargo.toml"
LOCK = ROOT / "probes/h02/openraft-tokio/Cargo.lock"
MAIN = ROOT / "probes/h02/openraft-tokio/src/bin/inmemory_cluster.rs"
CLUSTER = ROOT / "probes/h02/openraft-tokio/src/bin/inmemory_cluster/cluster.rs"
NETWORK = ROOT / "probes/h02/openraft-tokio/src/bin/inmemory_cluster/network.rs"
COLLECTOR = ROOT / "scripts/h02_openraft_inmemory_cluster_evidence_v1.py"
WORKFLOW = ROOT / ".github/workflows/h02-openraft-inmemory-cluster.yml"

REQUIRED_CASES = {
    "raft-deterministic-apply-and-restart",
    "raft-committed-snapshot-conflict-rejected",
    "raft-joint-membership-single-writer",
    "raft-process-pause-plus-partition",
    "raft-quorum-loss-fail-closed",
    "raft-incomplete-run-replay-diagnostics",
}


class Failure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: expected mapping")
    return value


def require_tokens(path: Path, tokens: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for token in tokens:
        require(token in text, f"{path.relative_to(ROOT)} missing token: {token}")


def main() -> int:
    try:
        for path in [PLAN, SCHEMA, MANIFEST, LOCK, MAIN, CLUSTER, NETWORK, COLLECTOR, WORKFLOW]:
            require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")

        plan = load_yaml(PLAN)
        require(plan["schema"] == "heptabao.h02-openraft-inmemory-cluster.v1", "plan schema drift")
        require(str(plan["revision"]) == "1.2", "plan revision drift")
        require(
            plan["status"] == "IMPLEMENTED_PENDING_EXACT_HEAD_REMOTE_EXECUTION_NOT_QUALIFIED",
            "plan status must separate implementation from execution",
        )
        require(plan["qualification"] is False, "plan cannot self-qualify")
        require(plan["selection_effect"] == plan["authority_effect"] == "NONE", "authority must remain NONE")
        require(plan["candidate"]["state"] == "IDENTIFIED_NOT_SELECTED", "candidate must remain unselected")
        require(plan["candidate"]["effective_rust_floor"] == "1.88.0", "effective Rust floor drift")
        matrix = plan["execution_matrix"]
        require(matrix["toolchains"] == ["1.88.0", "1.98.0"], "effective toolchain matrix drift")
        require(matrix["entries"] == 6, "expected 2 effective toolchains x 3 seeds")
        require(matrix["exact_head_remote_executions"] == 0, "source plan cannot claim exact-head execution")
        require(matrix["scheduling"] == "SERIAL_ON_ONE_RUNNER", "cluster matrix must be serialized")
        require({item["case_id"] for item in plan["cases"]} == REQUIRED_CASES, "case set mismatch")
        require(len(plan["promotion_blockers"]) >= 8, "promotion blocker set is too shallow")
        closure = plan["related_implemented_closure_layers"]
        for key in (
            "hostile_snapshot_child_process",
            "external_linearizability_checker",
            "Linux_process_suspend",
            "storage_fault_seam",
            "integrated_RaftLogStorage_and_RaftStateMachine",
            "application_wall_clock_projection",
            "bounded_effective_MSRV",
        ):
            require(closure.get(key) is True, f"implemented closure layer not represented: {key}")

        manifest = MANIFEST.read_text(encoding="utf-8")
        for token in [
            'rust-version = "1.88"',
            'default-run = "heptabao-h02-probe-openraft-tokio"',
            'name = "heptabao-h02-openraft-inmemory-cluster"',
            'openraft = { version = "=0.10.0-alpha.33"',
            'openraft-memstore = { version = "=0.10.0-alpha.33"',
            'openraft-rt = "=0.10.0-alpha.33"',
            'openraft-rt-tokio = "=0.10.0-alpha.33"',
            'openraft-macros = "=0.10.0-alpha.33"',
            'tokio = { version = "=1.53.1"',
            '[patch.crates-io]',
            'git = "https://github.com/drmingdrmer/validit.git"',
            'rev = "7016fa5e072a86092928144b3a3040381e6964e9"',
        ]:
            require(token in manifest, f"manifest binding missing: {token}")
        for mutable_selector in ("branch =", "tag =", 'path = "../../../'):
            require(mutable_selector not in manifest, f"mutable or external path source forbidden: {mutable_selector}")
        require(LOCK.stat().st_size > 0, "committed lockfile is empty")

        source = "\n".join(
            [MAIN.read_text(encoding="utf-8"), CLUSTER.read_text(encoding="utf-8"), NETWORK.read_text(encoding="utf-8")]
        )
        required_source = [
            "RaftNetworkFactory<TypeConfig>",
            "RaftNetworkV2<TypeConfig>",
            "append_entries",
            "pre_vote",
            "full_snapshot",
            "install_full_snapshot",
            "Raft::<TypeConfig",
            "new_mem_store",
            ".initialize(",
            ".add_learner(",
            ".change_membership(",
            ".client_write(",
            ".ensure_linearizable(",
            ".trigger().snapshot()",
            ".shutdown().await",
            "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
        ]
        for token in required_source:
            require(token in source, f"real cluster source token missing: {token}")
        require('include_bytes!("../../../fixtures' not in source, "cluster probe must not embed secret fixtures")
        for marker in ["PRIVATE KEY", "root_token", "unseal_share"]:
            require(marker not in source, f"secret marker in source: {marker}")

        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        require(schema["properties"]["qualification"]["const"] is False, "schema qualification must be false")
        require(schema["properties"]["authority_effect"]["const"] == "NONE", "schema authority must be NONE")
        require(schema["properties"]["promotion_effect"]["const"].startswith("BLOCK_"), "promotion must remain blocked")

        workflow = load_yaml(WORKFLOW)
        jobs = workflow.get("jobs", {})
        require(set(jobs) == {"validate-plan", "cluster-sequential", "authority-sentinel"}, "workflow jobs drift")
        sequential = jobs["cluster-sequential"]
        require("strategy" not in sequential, "cluster workflow must not use a runner-starving matrix")
        require(sequential.get("env", {}).get("TOOLCHAINS") == "1.88.0 1.98.0", "workflow toolchains drift")
        require(len(str(sequential.get("env", {}).get("SEEDS", "")).split()) == 3, "workflow seed set drift")
        require_tokens(
            WORKFLOW,
            [
                "Execute all six entries serially and retain every outcome",
                "0x5eed20260828cafe",
                "0x8badf00d12345678",
                "0xd15ea5e5cafef00d",
                "if: ${{ always() }}",
                "qualification=false",
                "authority=NONE",
            ],
        )

        print(
            "H02 OpenRaft in-memory cluster validation passed: implementation bound; "
            "effective toolchains=1.88/1.98; exact-head executions=0; authority=NONE"
        )
        return 0
    except (Failure, OSError, ValueError, json.JSONDecodeError, yaml.YAMLError, KeyError) as exc:
        print(f"H02 OpenRaft in-memory cluster validation FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
