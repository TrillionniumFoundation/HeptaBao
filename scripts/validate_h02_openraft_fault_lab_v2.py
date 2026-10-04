#!/usr/bin/env python3
"""Validate source admission and re-derive every exact six-entry V2 receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import types
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative, expected=None):
    path = ROOT / relative
    captured = path.read_bytes()
    if expected is not None and hashlib.sha256(captured).hexdigest() != expected:
        raise ValueError(f"historical helper changed: {relative}")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(captured, str(path), "exec"), module.__dict__)
    return module


collector = load("_fault_v2_collector", "scripts/h02_openraft_fault_lab_evidence_v2.py")
historical = load("_fault_v1_validator", "scripts/validate_h02_openraft_fault_lab_v1.py", "a3b26e08f6e7ab641a29cae53f8c98d599492c93213328a9bd47b9fe9ca30776")
require = collector.require
PLAN = ROOT / "planning/HEPTABAO_H02_OPENRAFT_HOSTILE_FAULTS_LINEARIZABILITY_V2.yaml"
SCHEMA = ROOT / "schemas/heptabao_h02_openraft_fault_lab_evidence_v2.schema.json"
WORKFLOW = ROOT / ".github/workflows/h02-openraft-fault-lab-v2.yml"


def validate_source_contract():
    require(collector.TOOLCHAINS == ("1.88.0", "1.99.0"), "exact current compiler pair drift")
    require(collector.SEEDS == ("0x5eed20260828cafe", "0x8badf00d12345678", "0xd15ea5e5cafef00d"), "historical seed set drift")
    require(collector.STAGES == ("rustc", "test", "hostile", "history", "checker"), "stage topology drift")
    require(historical.main() == 0, "historical V1 source validation failed")
    trust = load("_fault_current_trust", "scripts/validate_workflow_trust.py")
    trust.validate_text(WORKFLOW.read_text(), WORKFLOW.name)
    workflow_parser = load("_fault_v2_yaml", "scripts/validate_workflow_trust_v1.py")
    plan = workflow_parser.parse_workflow(PLAN.read_text())
    workflow = workflow_parser.parse_workflow(WORKFLOW.read_text())
    require(plan["schema"] == "heptabao.h02-openraft-hostile-faults-linearizability.v2" and plan["revision"] == "2.0" and plan["execution_profile_id"] == collector.PROFILE, "V2 plan/profile identity drift")
    require(plan["qualification"] is False and plan["selection_effect"] == plan["authority_effect"] == "NONE", "plan authority drift")
    require(collector.EXIT == {"EXECUTED_PASS": 0, "EXECUTED_FAIL": 1, "BLOCKED": 2} and plan["hostile_snapshot_case"]["native_parent_exit_codes"] == collector.EXIT, "native status/exit mapping drift")
    matrix = plan["execution_matrix"]
    require(matrix["toolchains"] == list(collector.TOOLCHAINS) and matrix["seeds"] == list(collector.SEEDS) and matrix["entries"] == 6, "six-entry matrix drift")
    require(matrix["entry_stages"] == list(collector.STAGES) and matrix["exact_head_remote_executions"] == 0, "execution stage/source-only contract drift")
    require(matrix["cargo_input_policy"] == collector.CONFIG_POLICY == "HB-H02-FAULT-V2-ISOLATED-CARGO-CONFIG-FREE-V1" and matrix["inherited_environment"] == ["PATH", "RUSTUP_HOME"], "Cargo input-control policy drift")
    require(matrix["dependency_graph"] == "COPY_COMMITTED_CARGO_LOCK_AND_REQUIRE_LOCKED_UNCHANGED", "committed dependency graph drift")
    require(plan["candidate"]["profile_id"] == collector.checker.EXPECTED_PROFILE and plan["candidate"]["effective_rust_floor"] == "1.88.0", "native profile/effective floor drift")
    schema = collector.strict_json(SCHEMA)
    Draft202012Validator.check_schema(schema)
    require(collector.SCHEMA == "heptabao.h02-openraft-fault-lab-evidence.v2" and schema["properties"]["schema"] == {"const": collector.SCHEMA}, "aggregate schema identity drift")
    require(schema["properties"]["revision"] == {"const": "2.0"}, "aggregate revision drift")
    for key, expected in (("qualification", False), ("selection_effect", "NONE"), ("authority_effect", "NONE"), ("promotion_effect", collector.checker.BLOCK_PROMOTION)):
        require(schema["properties"][key] == {"const": expected}, f"aggregate authority drift: {key}")
    require(schema["properties"]["execution"]["properties"]["configuration_policy"] == {"const": collector.CONFIG_POLICY}, "Cargo configuration schema drift")
    require(schema["properties"]["execution_profile_id"] == {"const": collector.PROFILE}, "aggregate profile drift")
    require(schema["properties"]["execution"]["properties"]["toolchain"] == {"enum": list(collector.TOOLCHAINS)}, "aggregate compiler drift")
    for name, kind in (("hostile", "hostile"), ("linear", "checker")):
        raw = collector.strict_json(ROOT / "schemas" / collector.RAW_SCHEMAS[kind])
        raw.pop("$id"); raw.pop("$schema")
        require(schema["$defs"][name] == raw, "aggregate must preserve complete raw schema")
    events = workflow["on"]
    require(set(events) == {"pull_request", "workflow_dispatch"} and events["workflow_dispatch"] in (None, {}), "manual/scoped PR events drift")
    paths = events["pull_request"].get("paths", [])
    require(events["pull_request"] == {"paths": paths} and len(paths) == len(set(paths)), "PR filter shape/duplicate drift")
    require(set(paths) == set(TRIGGER_PATHS), "PR paths must equal actual execution/validation input set")
    require(workflow["permissions"] == {"contents": "read"}, "workflow authority drift")
    require(set(workflow["jobs"]) == {"validate-plan", "fault-sequential", "authority-sentinel"}, "workflow jobs drift")
    job = workflow["jobs"]["fault-sequential"]
    require("strategy" not in job, "matrix must stay serial")
    require(job.get("env") == {"TOOLCHAINS": " ".join(collector.TOOLCHAINS), "SEEDS": " ".join(collector.SEEDS)}, "workflow compiler/seed environment drift")
    for index, expected in EXECUTION_SHELL.items():
        step = job["steps"][index]
        require(step.get("if") == "${{ always() }}" and step.get("shell") == "bash" and step.get("run") == expected,
                f"exact execution/validation command wiring drift at step {index}")
    text = WORKFLOW.read_text()
    require("generate-lockfile" not in text and "1.98.0" not in text, "historical compiler/generated graph in successor")
    for token in ("--expected-commit", "--execution-root", "--evidence-root", "--source-root", "--source-commit", "--source-tree", "--run-id", "--run-attempt", "--runner-name", "--require-pass", "persist-credentials: false", "ref: ${{ github.event.pull_request.head.sha || github.sha }}"):
        require(token in text, f"workflow missing binding: {token}")
    require(job["steps"][6].get("if") == "${{ always() }}" and "actions/upload-artifact@" in job["steps"][6].get("uses", ""), "retain evidence before final gate")
    require("--require-pass" in job["steps"][7].get("run", ""), "final gate missing")
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if "run" in step:
                subprocess.run(["bash", "-n"], input=step["run"], text=True, check=True, capture_output=True)
    for path in (ROOT / "schemas").glob("*fault_lab*schema.json"):
        Draft202012Validator.check_schema(collector.strict_json(path))


def validate_evidence_directory(root: Path, source_commit: str, source_tree: str, *, run_id: str, run_attempt: str, runner_name: str, execution_root: Path, require_pass: bool = False, producer_source_root: Path | None = None, producer_evidence_root: Path | None = None, runtime_environment: dict[str, str] | None = None):
    root = root.absolute()
    producer_source_root = ROOT if producer_source_root is None else producer_source_root
    producer_evidence_root = root if producer_evidence_root is None else producer_evidence_root
    require(producer_source_root.is_absolute() and producer_evidence_root.is_absolute(), "producer source/evidence roots must be absolute independent inputs")
    require(execution_root.is_absolute(), "execution root must be absolute")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", source_commit)) and bool(re.fullmatch(r"[0-9a-f]{40}", source_tree)), "expected source identity malformed")
    require(root.is_dir() and not root.is_symlink(), "missing/symlinked evidence root")
    expected = {collector.entry_name(t, s): (t, s) for t in collector.TOOLCHAINS for s in collector.SEEDS}
    require({p.name for p in root.iterdir()} == set(expected), "missing/extra/duplicate matrix entries")
    validator = collector.StrictValidator(collector.strict_json(SCHEMA))
    source = {"repository": "TrillionniumFoundation/HeptaBao", "commit": source_commit, "tree": source_tree, "clean_tree": True,
              "manifest_sha256": collector.file_sha(ROOT / collector.PROBE / "Cargo.toml"), "cargo_lock_sha256": collector.file_sha(ROOT / collector.PROBE / "Cargo.lock")}
    for name, (toolchain, seed) in expected.items():
        entry = root / name
        require(entry.is_dir() and not entry.is_symlink(), f"invalid entry directory: {name}")
        value = collector.strict_json(entry / "fault-lab-evidence.json")
        validator.validate(value)
        context = collector.strict_json(entry / "execution-context.json")
        # Expected compiler, run, runner, argv, manifest and lock are independent
        # inputs. Self-consistent relabeling of a captured receipt is insufficient.
        collector.validate_context(context, toolchain, seed, execution_root / name / "probe", producer_evidence_root / name, source, run_id, run_attempt, runner_name, producer_source_root, runtime_environment)
        require(value["source"] == source, f"{name}: source identity/committed graph drift")
        for stage, code in context["return_codes"].items():
            stdout = collector.RAW_FILES.get(stage, f"{stage}.stdout") if stage != "checker" else "checker.stdout"
            for filename in (stdout, f"{stage}.stderr"):
                path = entry / filename
                require(not path.is_symlink(), f"symlinked stage file: {name}/{filename}")
                require(code is None or path.is_file(), f"missing executed-stage output: {name}/{filename}")
        require(collector.canonical(value) == collector.canonical(collector.collect(entry, context)), f"{name}: receipt differs from actual raw files/recomputed checker")
        if require_pass:
            require(value["status"] == "EXECUTED_PASS" and not value["problems"], f"{name}: {value['status']}: {value['problems']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path)
    for name in ("source-commit", "source-tree", "run-id", "run-attempt", "runner-name"):
        parser.add_argument("--" + name)
    parser.add_argument("--execution-root", type=Path)
    parser.add_argument("--producer-source-root", type=Path)
    parser.add_argument("--producer-evidence-root", type=Path)
    parser.add_argument("--producer-path")
    parser.add_argument("--producer-rustup-home")
    parser.add_argument("--require-pass", action="store_true")
    args = parser.parse_args()
    validate_source_contract()
    require((args.producer_path is None) == (args.producer_rustup_home is None), "both independently expected producer runtime values are required together")
    runtime_environment = None if args.producer_path is None else {"PATH": args.producer_path, "RUSTUP_HOME": args.producer_rustup_home}
    if args.evidence_root is not None:
        require(all(getattr(args, field) is not None for field in ("source_commit", "source_tree", "run_id", "run_attempt", "runner_name", "execution_root")), "all independent execution bindings are required")
        validate_evidence_directory(args.evidence_root, args.source_commit, args.source_tree, run_id=args.run_id, run_attempt=args.run_attempt, runner_name=args.runner_name, execution_root=args.execution_root, require_pass=args.require_pass, producer_source_root=args.producer_source_root, producer_evidence_root=args.producer_evidence_root, runtime_environment=runtime_environment)
    print("V2 source/evidence contract valid; qualification=false authority=NONE")
    return 0


EXECUTION_SHELL = {4: 'set -euo pipefail\n'
    'python scripts/h02_openraft_fault_lab_evidence_v2.py run \\\n'
    '  --execution-root "$RUNNER_TEMP/h02-fault-v2-work" \\\n'
    '  --evidence-root "$RUNNER_TEMP/h02-fault-v2-evidence" \\\n'
    '  --source-root "$GITHUB_WORKSPACE" \\\n'
    '  --expected-commit "${{ github.event.pull_request.head.sha || github.sha }}" \\\n'
    '  --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT" \\\n'
    '  --runner-name "$RUNNER_NAME"\n',
 5: 'set -euo pipefail\n'
    'python scripts/validate_h02_openraft_fault_lab_v2.py \\\n'
    '  --evidence-root "$RUNNER_TEMP/h02-fault-v2-evidence" \\\n'
    '  --producer-source-root "$GITHUB_WORKSPACE" \\\n'
    '  --producer-evidence-root "$RUNNER_TEMP/h02-fault-v2-evidence" \\\n'
    '  --source-commit "$(git rev-parse HEAD)" \\\n'
    '  --source-tree "$(git rev-parse \'HEAD^{tree}\')" \\\n'
    '  --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT" \\\n'
    '  --runner-name "$RUNNER_NAME" --execution-root "$RUNNER_TEMP/h02-fault-v2-work"\n',
 7: 'set -euo pipefail\n'
    'python scripts/validate_h02_openraft_fault_lab_v2.py \\\n'
    '  --evidence-root "$RUNNER_TEMP/h02-fault-v2-evidence" \\\n'
    '  --producer-source-root "$GITHUB_WORKSPACE" \\\n'
    '  --producer-evidence-root "$RUNNER_TEMP/h02-fault-v2-evidence" \\\n'
    '  --source-commit "$(git rev-parse HEAD)" \\\n'
    '  --source-tree "$(git rev-parse \'HEAD^{tree}\')" \\\n'
    '  --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT" \\\n'
    '  --runner-name "$RUNNER_NAME" --execution-root "$RUNNER_TEMP/h02-fault-v2-work" \\\n'
    '  --require-pass\n'}

# Exact admission paths are reviewed alongside the workflow.
TRIGGER_PATHS = ('.github/workflows/h02-openraft-fault-lab-v2.yml',
 'planning/HEPTABAO_H02_OPENRAFT_HOSTILE_FAULTS_LINEARIZABILITY_V2.yaml',
 'scripts/h02_openraft_fault_lab_evidence_v2.py',
 'scripts/validate_h02_openraft_fault_lab_v2.py',
 'scripts/h02_linearizability_checker_v1.py',
 '.github/workflows/h02-openraft-fault-lab.yml',
 'planning/HEPTABAO_H02_OPENRAFT_HOSTILE_FAULTS_LINEARIZABILITY_V1.yaml',
 'planning/HEPTABAO_H02_EXECUTION_QUEUE_V3.yaml',
 'scripts/validate_h02_openraft_fault_lab_v1.py',
 'scripts/h02_openraft_fault_lab_evidence_v1.py',
 'schemas/heptabao_h02_openraft_fault_lab_evidence_v1.schema.json',
 'tests/platform/test_h02_linearizability_checker_v1.py',
 'tests/platform/test_h02_openraft_fault_lab_evidence_v1.py',
 'schemas/heptabao_h02_openraft_fault_lab_evidence_v2.schema.json',
 'schemas/heptabao_h02_openraft_hostile_snapshot_result_v1.schema.json',
 'schemas/heptabao_h02_linearizability_history_v1.schema.json',
 'schemas/heptabao_h02_linearizability_result_v1.schema.json',
 'tests/platform/test_h02_openraft_fault_lab_evidence_v2.py',
 'probes/h02/openraft-tokio/Cargo.toml',
 'probes/h02/openraft-tokio/Cargo.lock',
 'probes/h02/openraft-tokio/build.rs',
 'probes/h02/openraft-tokio/src/**',
 'probes/h02/openraft-tokio/tests/**',
 'probes/h02/openraft-tokio/examples/**',
 'probes/h02/openraft-tokio/benches/**',
 'requirements-plan.txt',
 'scripts/validate_workflow_trust.py',
 'scripts/validate_workflow_trust_v1.py',
 'scripts/workflow_trust_v2.py',
 'scripts/workflow_trust_action_registry_v2.json',
 'scripts/validate_acceptance_immutability.py')

if __name__ == "__main__":
    raise SystemExit(main())
