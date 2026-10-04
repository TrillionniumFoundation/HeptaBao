#!/usr/bin/env python3
"""Emit fresh current-profile evidence using the unchanged V1 observation engine.

This wrapper consumes raw probe output only. It never imports or upgrades a V1
receipt. Its private engine instance leaves V1 imports and source bytes unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import types
import json
import re
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ENGINE_SHA256 = "b1c97544e483559125b9a6bff5b4fea2aa43349cf4401725ea35f242b3208786"
ENGINE = ROOT / "scripts/h02_openraft_inmemory_cluster_evidence_v1.py"
ENGINE_BYTES = ENGINE.read_bytes()
if hashlib.sha256(ENGINE_BYTES).hexdigest() != ENGINE_SHA256:
    raise RuntimeError("historical V1 observation engine bytes changed")
engine = types.ModuleType("_inmemory_v2_observation_engine")
engine.__file__ = str(ENGINE)
# Execute the verified buffer, never a second path read or cached bytecode.
exec(compile(ENGINE_BYTES, str(ENGINE), "exec"), engine.__dict__)

EFFECTIVE_TOOLCHAINS = ("1.88.0", "1.99.0")
SEEDS = ("0x5eed20260828cafe", "0x8badf00d12345678", "0xd15ea5e5cafef00d")
EXECUTION_PROFILE_ID = "HB-H02-OPENRAFT-INMEMORY-CURRENT-V2"
CASES = engine.CASES
SNAPSHOT_CASE_ID = engine.SNAPSHOT_CASE_ID
sha256_file = engine.sha256_file


def parse_jsonl(path: Path) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[dict[str, Any]]]:
    """Retain malformed/duplicate records as failures without discarding evidence."""
    if not path.is_file():
        return None, [], []
    meta, cases, errors = None, [], []
    seen = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            errors.append({"line": number, "error": "invalid-json"})
            continue
        if not isinstance(value, dict):
            errors.append({"line": number, "error": "record-not-object"})
            continue
        kind = value.get("kind")
        if kind == "meta" and meta is None:
            meta = value
        elif kind == "case":
            case_id = value.get("case_id")
            if not isinstance(case_id, str) or case_id not in CASES or case_id in seen:
                errors.append({"line": number, "error": "unexpected-or-duplicate-case"})
                continue
            seen.add(case_id)
            if type(value.get("assertion_count")) is not int:
                errors.append({"line": number, "error": "assertion-count-not-integer"})
            cases.append(value)
        else:
            errors.append({"line": number, "error": "unexpected-record"})
    return meta, cases, errors


# Narrow parser extension in this private instance; no shared V1 module mutation.
engine.parse_jsonl = parse_jsonl


COMMAND_PROFILE_ID = "HB-H02-OPENRAFT-INMEMORY-COMMANDS-V2"
COMMON_STAGES = ("rustc", "lock", "test")
STAGES = COMMON_STAGES + ("probe", "replay")
RUNNER_ID = "github-api-enrichment-pending"


def environment_id(run_id: str, run_attempt: str, runner_name: str, toolchain: str, seed: str) -> str:
    return f"github-{run_id}-{run_attempt}-{runner_name}-{toolchain}-{seed}"


def command_profile(toolchain: str, seed: str, manifest: str) -> dict[str, list[str]]:
    if toolchain not in EFFECTIVE_TOOLCHAINS or seed not in SEEDS:
        raise ValueError("command profile toolchain/seed drift")
    prefix = ["rustup", "run", toolchain]
    probe = prefix + ["cargo", "run", "--quiet", "--locked", "--manifest-path", manifest,
                      "--bin", "heptabao-h02-openraft-inmemory-cluster", "--", "--seed", seed]
    return {
        "rustc": prefix + ["rustc", "--version", "--verbose"],
        "lock": prefix + ["cargo", "generate-lockfile", "--manifest-path", manifest],
        "test": prefix + ["cargo", "test", "--locked", "--all-targets", "--manifest-path", manifest],
        "probe": probe,
        "replay": list(probe),
    }


def new_context(toolchain: str, seed: str, manifest: str, run_id: str, run_attempt: str, runner_name: str) -> dict[str, Any]:
    if not re.fullmatch(r"[1-9][0-9]*", run_id) or not re.fullmatch(r"[1-9][0-9]*", run_attempt) or not runner_name:
        raise ValueError("invalid execution run/attempt/runner identity")
    if not Path(manifest).is_absolute():
        raise ValueError("execution manifest must be absolute")
    argv = command_profile(toolchain, seed, manifest)
    return {
        "schema": "heptabao.h02-inmemory-execution-context.v2",
        "command_profile_id": COMMAND_PROFILE_ID,
        "run_id": run_id, "run_attempt": run_attempt, "runner_name": runner_name,
        "runner_id": RUNNER_ID, "executor_kind": "github-hosted",
        "toolchain": toolchain, "seed": seed, "manifest": manifest,
        "argv": argv, "argv_sha256": engine.sha256_bytes(engine.canonical(argv)),
        "return_codes": {stage: None for stage in STAGES},
    }


def validate_context(value: dict[str, Any], toolchain: str, seed: str, manifest: str,
                     run_id: str, run_attempt: str, runner_name: str) -> None:
    expected = new_context(toolchain, seed, manifest, run_id, run_attempt, runner_name)
    outcomes = value.get("return_codes")
    if not isinstance(outcomes, dict) or set(outcomes) != set(STAGES):
        raise ValueError("execution context stage set drift")
    if any(code is not None and (type(code) is not int or not 0 <= code <= 255) for code in outcomes.values()):
        raise ValueError("invalid execution stage return code")
    expected["return_codes"] = outcomes
    if value != expected:
        raise ValueError("execution context run/attempt/runner or canonical command mismatch")
    prior_failed = False
    for stage in STAGES:
        code = outcomes[stage]
        if prior_failed and code is not None:
            raise ValueError("execution stage present after failed or unexecuted prerequisite")
        prior_failed = prior_failed or code != 0


def context_status(value: dict[str, Any]) -> int:
    for stage in STAGES:
        code = value["return_codes"][stage]
        if code != 0:
            return 125 if code is None else code
    return 0


def execute_stage(context_path: Path, stage: str, stdout: Path, stderr: Path) -> int:
    value = json.loads(context_path.read_text(encoding="utf-8"))
    validate_context(value, value["toolchain"], value["seed"], value["manifest"],
                     value["run_id"], value["run_attempt"], value["runner_name"])
    if value["return_codes"][stage] is not None:
        raise ValueError("execution stage already recorded")
    if any(value["return_codes"][prior] != 0 for prior in STAGES[:STAGES.index(stage)]):
        raise ValueError("execution prerequisite did not pass")
    with stdout.open("wb") as out, stderr.open("wb") as err:
        try:
            result = subprocess.run(value["argv"][stage], stdout=out, stderr=err, check=False)
            status = result.returncode if result.returncode >= 0 else 128 - result.returncode
        except OSError as error:
            err.write(str(error).encode())
            status = 125
    value["return_codes"][stage] = min(status, 255)
    context_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return value["return_codes"][stage]


def collect(args: argparse.Namespace) -> dict[str, Any]:
    if args.toolchain not in EFFECTIVE_TOOLCHAINS:
        raise ValueError("V2 toolchain must be exactly 1.88.0 or 1.99.0")
    if args.seed not in SEEDS:
        raise ValueError("V2 seed is outside the unchanged three-seed matrix")
    context_path = Path(args.execution_context)
    context = json.loads(context_path.read_text(encoding="utf-8"))
    validate_context(context, args.toolchain, args.seed, context["manifest"],
                     context["run_id"], context["run_attempt"], args.runner_name)
    if args.environment_id != environment_id(context["run_id"], context["run_attempt"], args.runner_name, args.toolchain, args.seed):
        raise ValueError("environment identity does not match execution context")
    if args.runner_id != RUNNER_ID or args.executor_kind != "github-hosted":
        raise ValueError("execution runner identity mismatch")
    if args.execution_exit_code != context_status(context):
        raise ValueError("execution context stage outcomes do not match exit code")
    rustc = Path(args.rustc_version)
    release = None
    if rustc.is_file():
        lines = rustc.read_text(encoding="utf-8").splitlines()
        releases = [line.removeprefix("release: ") for line in lines if line.startswith("release: ")]
        if len(releases) != 1 or releases[0] != args.toolchain or not lines or not lines[0].startswith(f"rustc {args.toolchain} "):
            raise ValueError("observed rustc release does not match the exact current toolchain")
        release = releases[0]
    value = engine.collect(args)
    if release is None and value["status"] == "EXECUTED_PASS":
        value["status"] = "BLOCKED"
        for case in value["cases"]:
            case["status"] = "BLOCKED"
        value["summary"].update({"passed": 0, "blocked": 6})
    value.update({
        "schema": "heptabao.h02-openraft-cluster-evidence.v2",
        "revision": "2.0",
        "execution_profile_id": EXECUTION_PROFILE_ID,
        "execution": {
            "exit_code": args.execution_exit_code,
            "context": context,
            "context_sha256": sha256_file(context_path),
            "observed_rustc_release": release,
            "rustc_verbose_sha256": sha256_file(rustc) if rustc.is_file() else "0" * 64,
            "adapter_output_sha256": sha256_file(Path(args.adapter_output)) if Path(args.adapter_output).is_file() else "0" * 64,
            "replay_output_sha256": sha256_file(Path(args.replay_output)) if Path(args.replay_output).is_file() else "0" * 64,
        },
    })
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    sub = value.add_subparsers(dest="command", required=True)
    context = sub.add_parser("context")
    for name in ("manifest", "run-id", "run-attempt", "runner-name", "output"):
        context.add_argument(f"--{name}", required=True)
    context.add_argument("--toolchain", choices=EFFECTIVE_TOOLCHAINS, required=True)
    context.add_argument("--seed", choices=SEEDS, required=True)
    context.add_argument("--build-context", type=Path)
    execute = sub.add_parser("execute")
    execute.add_argument("--context", type=Path, required=True)
    execute.add_argument("--stage", choices=STAGES, required=True)
    execute.add_argument("--stdout", type=Path, required=True)
    execute.add_argument("--stderr", type=Path, required=True)
    command = sub.add_parser("collect")
    for name in ("adapter-output", "replay-output", "rustc-version", "execution-context", "manifest", "cargo-lock", "source-commit", "source-tree", "branch", "environment-id", "output"):
        command.add_argument(f"--{name}", required=True)
    command.add_argument("--execution-exit-code", type=int, required=True)
    command.add_argument("--seed", choices=SEEDS, required=True)
    command.add_argument("--toolchain", choices=EFFECTIVE_TOOLCHAINS, required=True)
    command.add_argument("--clean-tree", action="store_true")
    command.add_argument("--executor-kind", choices=["local-container", "github-hosted", "self-hosted", "offline-lab"], required=True)
    command.add_argument("--runner-id")
    command.add_argument("--runner-name")
    return value


def main() -> int:
    args = parser().parse_args()
    if args.command == "execute":
        return execute_stage(args.context, args.stage, args.stdout, args.stderr)
    if args.command == "context":
        value = new_context(args.toolchain, args.seed, args.manifest, args.run_id, args.run_attempt, args.runner_name)
        if args.build_context:
            build = json.loads(args.build_context.read_text(encoding="utf-8"))
            validate_context(build, args.toolchain, SEEDS[0], args.manifest, args.run_id, args.run_attempt, args.runner_name)
            if any(build["return_codes"][stage] is not None for stage in ("probe", "replay")):
                raise ValueError("build context contains per-seed execution")
            value["return_codes"].update({stage: build["return_codes"][stage] for stage in COMMON_STAGES})
        Path(args.output).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    evidence = collect(args)
    Path(args.output).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(evidence["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
