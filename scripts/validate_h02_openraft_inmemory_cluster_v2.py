#!/usr/bin/env python3
"""Validate the additive current V2 profile and exact six-entry evidence set."""
from __future__ import annotations

import argparse
import copy
import hashlib
import types
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "planning/HEPTABAO_H02_OPENRAFT_INMEMORY_CLUSTER_V2.yaml"
SCHEMA = ROOT / "schemas/heptabao_h02_openraft_cluster_evidence_v2.schema.json"
WORKFLOW = ROOT / ".github/workflows/h02-openraft-inmemory-cluster-v2.yml"

TRIGGER_PATHS = (
    ".github/workflows/h02-openraft-inmemory-cluster-v2.yml",
    ".github/workflows/h02-openraft-inmemory-cluster.yml",
    "scripts/h02_openraft_inmemory_cluster_evidence_v2.py",
    "scripts/validate_h02_openraft_inmemory_cluster_v2.py",
    "scripts/h02_openraft_inmemory_cluster_evidence_v1.py",
    "scripts/validate_h02_openraft_inmemory_cluster_v1.py",
    "schemas/heptabao_h02_openraft_cluster_evidence_v2.schema.json",
    "schemas/heptabao_h02_openraft_cluster_evidence_v1.schema.json",
    "planning/HEPTABAO_H02_OPENRAFT_INMEMORY_CLUSTER_V2.yaml",
    "planning/HEPTABAO_H02_OPENRAFT_INMEMORY_CLUSTER_V1.yaml",
    "tests/platform/test_h02_openraft_inmemory_cluster_v2.py",
    "tests/platform/test_h02_openraft_inmemory_cluster_v1.py",
    "probes/h02/openraft-tokio/Cargo.toml",
    "probes/h02/openraft-tokio/Cargo.lock",
    "probes/h02/openraft-tokio/build.rs",
    "probes/h02/openraft-tokio/src/**",
    "probes/h02/openraft-tokio/tests/**",
    "probes/h02/openraft-tokio/examples/**",
    "probes/h02/openraft-tokio/benches/**",
    "requirements-plan.txt",
    ".cargo/config",
    ".cargo/config.toml",
    "scripts/validate_workflow_trust.py",
    "scripts/validate_workflow_trust_v1.py",
    "scripts/workflow_trust_v2.py",
    "scripts/workflow_trust_action_registry_v2.json",
    "scripts/validate_acceptance_immutability.py",
)


def load_module(name: str, filename: str, expected_sha256: str | None = None) -> Any:
    path = ROOT / "scripts" / filename
    captured = path.read_bytes()
    if expected_sha256 is not None and hashlib.sha256(captured).hexdigest() != expected_sha256:
        raise RuntimeError("historical V1 validator bytes changed")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    # Execute exactly the captured/verified bytes, bypassing .pyc and later path changes.
    exec(compile(captured, str(path), "exec"), module.__dict__)
    return module


historical = load_module("_inmemory_v1_artifact_validator", "validate_h02_openraft_inmemory_cluster_v1.py", "e24f8a7e76ba29a5c8ba9041a34948799d0f59ab70aabbe26a48b36eafa5ae26")
collector = load_module("_inmemory_v2_collector", "h02_openraft_inmemory_cluster_evidence_v2.py")
Failure = historical.Failure
require = historical.require


def validate_workflow_triggers(workflow: dict[str, Any]) -> None:
    events = workflow.get("on")
    require(isinstance(events, dict) and set(events) == {"workflow_dispatch", "pull_request"},
            "V2 requires only manual and scoped pull_request triggers")
    require(events["workflow_dispatch"] in (None, {}), "V2 manual trigger options drift")
    require(events["pull_request"] == {"paths": list(TRIGGER_PATHS)},
            "V2 pull_request path scope must match the exact execution inputs")


def validate_source_contract() -> None:
    require(collector.EFFECTIVE_TOOLCHAINS == ("1.88.0", "1.99.0"), "V2 current toolchain contract drift")
    # The unchanged V1 validator still validates its unchanged 1.88/1.98 lane.
    require(historical.main() == 0, "historical V1 artifact validation failed")
    plan = yaml.safe_load(PLAN.read_text(encoding="utf-8"))
    expected = copy.deepcopy(yaml.safe_load(historical.PLAN.read_text(encoding="utf-8")))
    expected.update({
        "schema": "heptabao.h02-openraft-inmemory-cluster.v2",
        "revision": "2.0",
        "execution_profile_id": collector.EXECUTION_PROFILE_ID,
        "historical_profile": "planning/HEPTABAO_H02_OPENRAFT_INMEMORY_CLUSTER_V1.yaml",
    })
    expected["execution_matrix"].update({
        "toolchains": list(collector.EFFECTIVE_TOOLCHAINS),
        "historical_evidence_effect": "NOT_CURRENT_EXECUTION",
        "workflow": ".github/workflows/h02-openraft-inmemory-cluster-v2.yml",
    })
    require(plan == expected, "V2 plan must preserve V1 case/seed/MSRV/authority semantics")
    require(plan["execution_matrix"]["seeds"] == list(collector.SEEDS), "V2 seed drift")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    properties = schema["properties"]
    require(properties["environment"]["properties"]["rust_toolchain"]["enum"] == list(collector.EFFECTIVE_TOOLCHAINS), "V2 schema current compiler drift")
    require(properties["schema"]["const"] == "heptabao.h02-openraft-cluster-evidence.v2", "V2 schema identity drift")
    require(properties["execution_profile_id"]["const"] == collector.EXECUTION_PROFILE_ID, "V2 profile drift")
    for field in ("qualification", "selection_effect", "promotion_effect", "authority_effect"):
        require(properties[field] == json.loads(historical.SCHEMA.read_text())["properties"][field], f"V2 authority drift: {field}")
    # Use the existing GitHub/YAML-1.2 parser so `on` is never a YAML-1.1 boolean,
    # and duplicate keys/aliases cannot hide a broader event or path list.
    workflow_parser = load_module("_inmemory_workflow_parser", "validate_workflow_trust_v1.py")
    workflow = workflow_parser.parse_workflow(WORKFLOW.read_text(encoding="utf-8"))
    validate_workflow_triggers(workflow)
    jobs = workflow.get("jobs", {})
    require(set(jobs) == {"validate-plan", "cluster-sequential", "authority-sentinel"}, "V2 workflow jobs drift")
    sequential = jobs["cluster-sequential"]
    require("strategy" not in sequential, "V2 execution must remain serial")
    require(sequential["env"]["TOOLCHAINS"].split() == list(collector.EFFECTIVE_TOOLCHAINS), "V2 workflow current compiler drift")
    require(sequential["env"]["SEEDS"].split() == list(collector.SEEDS), "V2 workflow seed drift")
    require(workflow["permissions"] == {"contents": "read"}, "V2 workflow permissions drift")
    text = WORKFLOW.read_text(encoding="utf-8")
    for token in (
        "scripts/h02_openraft_inmemory_cluster_evidence_v2.py collect",
        "scripts/validate_h02_openraft_inmemory_cluster_v2.py",
        "tests/platform/test_h02_openraft_inmemory_cluster_v2.py",
        "--evidence-root", "--source-commit", "--source-tree", "--require-pass",
        "--run-id", "--run-attempt", "--runner-name", "--execution-root", "--execution-context",
        "ref: ${{ github.event.pull_request.head.sha || github.sha }}",
        "persist-credentials: false", "if: ${{ always() }}",
    ):
        require(token in text, f"V2 workflow missing {token}")
    require("1.98.0" not in text, "stale current compiler in V2 workflow")


def validate_evidence_directory(root: Path, source_commit: str, source_tree: str, *,
                                run_id: str, run_attempt: str, runner_name: str,
                                execution_root: Path, require_pass: bool = False) -> None:
    require(execution_root.is_absolute(), "expected execution root must be absolute")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", source_commit)), "invalid expected source commit")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", source_tree)), "invalid expected source tree")
    expected = {f"{toolchain}-{seed[2:]}": (toolchain, seed) for toolchain in collector.EFFECTIVE_TOOLCHAINS for seed in collector.SEEDS}
    require(root.is_dir() and not root.is_symlink(), "missing or symlinked evidence root")
    directories = {path.name for path in root.iterdir() if path.is_dir()}
    require(directories == set(expected), "missing, extra or stale compiler/seed entry")
    validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    for name, (toolchain, seed) in sorted(expected.items()):
        entry = root / name
        require(not entry.is_symlink(), f"symlinked entry: {name}")
        for filename in ("cluster-output.jsonl", "cluster-replay.jsonl", "Cargo.toml", "Cargo.lock", "execution-exit-code.txt", "rustc-version.txt", "execution-context.json", "cluster-evidence.json"):
            path = entry / filename
            require(path.is_file() and not path.is_symlink(), f"missing or symlinked entry input: {name}/{filename}")
        value = json.loads((entry / "cluster-evidence.json").read_text(encoding="utf-8"))
        errors = list(validator.iter_errors(value))
        require(not errors, f"{name}: invalid V2 evidence: {[error.message for error in errors]}")
        require(value["source"]["commit_sha"] == source_commit and value["source"]["tree_sha"] == source_tree, f"{name}: stale source binding")
        context = value["execution"]["context"]
        collector.validate_context(context, toolchain, seed, str(execution_root / toolchain / "Cargo.toml"), run_id, run_attempt, runner_name)
        expected_environment = collector.environment_id(run_id, run_attempt, runner_name, toolchain, seed)
        require(value["environment"]["environment_id"] == expected_environment, f"{name}: wrong run/attempt environment")
        require(value["environment"]["runner_name"] == runner_name and value["environment"]["runner_id"] == collector.RUNNER_ID, f"{name}: wrong runner identity")
        require(value["environment"]["executor_kind"] == "github-hosted", f"{name}: wrong executor kind")
        require(value["environment"]["rust_toolchain"] == toolchain, f"{name}: compiler does not match entry")
        require(value["seed"] == {"hex": seed, "decimal": int(seed, 16)}, f"{name}: seed does not match entry")
        require(collector.sha256_file(entry / "Cargo.toml") == collector.sha256_file(historical.MANIFEST), f"{name}: archived manifest differs from source")
        args = argparse.Namespace(
            adapter_output=str(entry / "cluster-output.jsonl"), replay_output=str(entry / "cluster-replay.jsonl"),
            manifest=str(entry / "Cargo.toml"), cargo_lock=str(entry / "Cargo.lock"), rustc_version=str(entry / "rustc-version.txt"),
            execution_context=str(entry / "execution-context.json"),
            execution_exit_code=int((entry / "execution-exit-code.txt").read_text().strip()),
            toolchain=toolchain, seed=seed, source_commit=source_commit, source_tree=source_tree,
            branch=value["source"]["branch"], clean_tree=value["source"]["clean_tree"],
            environment_id=value["environment"]["environment_id"], executor_kind=value["environment"]["executor_kind"],
            runner_id=value["environment"]["runner_id"], runner_name=value["environment"]["runner_name"],
        )
        recollected = collector.collect(args)
        # Producer OS/architecture are observations, not this validating machine's OS.
        recollected["environment"]["os"] = value["environment"]["os"]
        recollected["environment"]["architecture"] = value["environment"]["architecture"]
        require(value == recollected, f"{name}: digest or raw-observation semantic mismatch")
        if require_pass:
            require(value["status"] == "EXECUTED_PASS", f"{name}: entry did not execute and pass")
            require((entry / "Cargo.lock").stat().st_size > 0, f"{name}: empty execution lock")
    print("V2 exact six-entry evidence validated; qualification=false selection=NONE authority=NONE")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--source-tree")
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    parser.add_argument("--runner-name")
    parser.add_argument("--execution-root", type=Path)
    parser.add_argument("--require-pass", action="store_true")
    args = parser.parse_args()
    if args.evidence_root and not all((args.source_commit, args.source_tree, args.run_id, args.run_attempt, args.runner_name, args.execution_root)):
        parser.error("--evidence-root requires source commit/tree and expected run-id/run-attempt/runner-name/execution-root")
    if not args.evidence_root and (args.source_commit or args.source_tree or args.run_id or args.run_attempt or args.runner_name or args.execution_root or args.require_pass):
        parser.error("evidence options require --evidence-root")
    try:
        validate_source_contract()
        if args.evidence_root:
            validate_evidence_directory(args.evidence_root, args.source_commit, args.source_tree,
                                        run_id=args.run_id, run_attempt=args.run_attempt, runner_name=args.runner_name,
                                        execution_root=args.execution_root, require_pass=args.require_pass)
        print("H02 in-memory V2 profile: MSRV=1.88 current=1.99; source plan exact-head executions=0; authority=NONE")
        return 0
    except (Failure, OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as error:
        print(f"H02 in-memory V2 validation FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
