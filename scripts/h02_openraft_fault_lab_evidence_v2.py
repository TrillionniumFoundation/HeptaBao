#!/usr/bin/env python3
"""Run/collect the additive fault-lab profile; never upgrade historical receipts."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import types
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError, validators

StrictValidator = validators.extend(Draft202012Validator, type_checker=Draft202012Validator.TYPE_CHECKER.redefine("integer", lambda checker, value: type(value) is int))

ROOT = Path(__file__).resolve().parents[1]
TOOLCHAINS = ("1.88.0", "1.99.0")
SEEDS = ("0x5eed20260828cafe", "0x8badf00d12345678", "0xd15ea5e5cafef00d")
PROFILE = "HB-H02-OPENRAFT-FAULT-LAB-CURRENT-V2"
SCHEMA = "heptabao.h02-openraft-fault-lab-evidence.v2"
STAGES = ("rustc", "test", "hostile", "history", "checker")
EXIT = {"EXECUTED_PASS": 0, "EXECUTED_FAIL": 1, "BLOCKED": 2}
RAW_FILES = {"hostile": "hostile-result.json", "history": "linearizability-history.json", "checker": "linearizability-result.json"}
RAW_SCHEMAS = {"hostile": "heptabao_h02_openraft_hostile_snapshot_result_v1.schema.json", "history": "heptabao_h02_linearizability_history_v1.schema.json", "checker": "heptabao_h02_linearizability_result_v1.schema.json"}
PROBE = "probes/h02/openraft-tokio"
RUNNER_ID = "github-api-enrichment-pending"
CONFIG_POLICY = "HB-H02-FAULT-V2-ISOLATED-CARGO-CONFIG-FREE-V1"


def load_verified(name: str, relative: str, sha256: str | None = None):
    path = ROOT / relative
    captured = path.read_bytes()
    if sha256 is not None and hashlib.sha256(captured).hexdigest() != sha256:
        raise ValueError(f"historical helper changed: {relative}")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    # Execute exactly the verified bytes, not cached bytecode or another path read.
    exec(compile(captured, str(path), "exec"), module.__dict__)
    return module


checker = load_verified("_fault_v2_checker", "scripts/h02_linearizability_checker_v1.py", "c70b875ae90b2675ed24de5a49a05c154abbadf106112e5ce260932620ea4b69")
canonical = checker.canonical_bytes


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str | None:
    return sha(path.read_bytes()) if path.is_file() and not path.is_symlink() else None


def strict_json(path: Path) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    def constant(value):
        raise ValueError(f"non-finite JSON number: {value}")
    if path.is_symlink():
        raise ValueError(f"symlinked input: {path.name}")
    def floating(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite JSON number")
        return number
    return json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_constant=constant, parse_float=floating)


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def entry_name(toolchain: str, seed: str) -> str:
    require(toolchain in TOOLCHAINS and seed in SEEDS, "compiler/seed outside six-entry matrix")
    return f"{toolchain}-{seed[2:]}"


def command_profile(toolchain: str, seed: str, work: Path, entry: Path, source_root: Path = ROOT) -> dict[str, list[str]]:
    entry_name(toolchain, seed)
    require(work.is_absolute() and entry.is_absolute() and source_root.is_absolute(), "execution paths must be absolute")
    prefix = ["rustup", "run", toolchain]
    manifest = str(work / "Cargo.toml")
    native = prefix + ["cargo", "run", "--quiet", "--locked", "--target", "x86_64-unknown-linux-gnu", "--manifest-path", manifest, "--bin", "heptabao-h02-openraft-fault-lab", "--"]
    return {
        "rustc": prefix + ["rustc", "--version", "--verbose"],
        "test": prefix + ["cargo", "test", "--locked", "--all-targets", "--target", "x86_64-unknown-linux-gnu", "--manifest-path", manifest],
        "hostile": native + ["--mode", "hostile-snapshot-parent", "--seed", seed],
        "history": native + ["--mode", "linearizability-history", "--seed", seed],
        "checker": ["python", str(source_root / "scripts/h02_linearizability_checker_v1.py"), "check", "--history", str(entry / RAW_FILES["history"]), "--output", str(entry / RAW_FILES["checker"])],
    }


def source_snapshot(root: Path) -> dict[str, Any]:
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)
    commit = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    return {"repository": "TrillionniumFoundation/HeptaBao", "commit": commit, "tree": tree,
            "clean_tree": git("status", "--porcelain", "--untracked-files=all") == b"",
            "manifest_sha256": sha(git("show", f"HEAD:{PROBE}/Cargo.toml")),
            "cargo_lock_sha256": sha(git("show", f"HEAD:{PROBE}/Cargo.lock"))}


def runtime_base_environment(environment: dict[str, str] | None = None) -> dict[str, str]:
    environment = os.environ if environment is None else environment
    path = environment.get("PATH", "")
    rustup = environment.get("RUSTUP_HOME") or str(Path(environment.get("HOME", "")) / ".rustup")
    require(bool(path) and all(Path(item).is_absolute() for item in path.split(os.pathsep)), "PATH must contain only absolute trusted runner directories")
    require(Path(rustup).is_absolute(), "RUSTUP_HOME must be an absolute trusted runner installation")
    return {"PATH": path, "RUSTUP_HOME": rustup}


def controlled_environment(work: Path, toolchain: str, base: dict[str, str]) -> dict[str, str]:
    require(set(base) == {"PATH", "RUSTUP_HOME"} and runtime_base_environment(base) == base, "runtime environment base drift")
    root = work.parents[1]
    return {**base, "HOME": str(root / "home"), "CARGO_HOME": str(root / "cargo-home"),
            "TMPDIR": str(root / "tmp"), "CARGO_TARGET_DIR": str(root / ("target-" + toolchain)),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}


def cargo_configuration_paths(work: Path, cargo_home: Path) -> list[str]:
    # These are Cargo's actual cwd/ancestor and CARGO_HOME discovery paths.
    return [str(directory / ".cargo" / filename) for directory in (work, *work.parents)
            for filename in ("config", "config.toml")] + [str(cargo_home / filename) for filename in ("config", "config.toml")]


def configuration_absent(context: dict) -> bool:
    cwd = Path(context["cwd"])
    for directory in (cwd, *cwd.parents, Path(context["environment"]["CARGO_HOME"])):
        try:
            if stat.S_ISLNK(directory.lstat().st_mode):
                return False
        except FileNotFoundError:
            pass
        except OSError:
            return False
    for raw in context["configuration_paths"]:
        path = Path(raw)
        try:
            if path.parent.is_symlink():
                return False
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return False
        return False
    return True


def new_context(toolchain: str, seed: str, work: Path, entry: Path, source: dict, run_id: str, run_attempt: str, runner_name: str, source_root: Path = ROOT, runtime_environment: dict[str, str] | None = None) -> dict:
    require(bool(re.fullmatch(r"[1-9][0-9]*", run_id)) and bool(re.fullmatch(r"[1-9][0-9]*", run_attempt)) and bool(runner_name), "invalid run/attempt/runner identity")
    argv = command_profile(toolchain, seed, work, entry, source_root)
    environment = controlled_environment(work, toolchain, runtime_base_environment() if runtime_environment is None else runtime_environment)
    return {"schema": "heptabao.h02-fault-lab-execution-context.v2", "execution_profile_id": PROFILE,
            "toolchain": toolchain, "seed": seed, "run_id": run_id, "run_attempt": run_attempt,
            "runner_name": runner_name, "runner_id": RUNNER_ID, "executor_kind": "github-hosted",
            "environment_id": f"github-{run_id}-{run_attempt}-{runner_name}-{toolchain}-{seed}",
            "source_before": source, "source_after": None, "cwd": str(work),
            "environment": environment, "environment_sha256": sha(canonical(environment)),
            "configuration_policy": CONFIG_POLICY, "configuration_paths": cargo_configuration_paths(work, Path(environment["CARGO_HOME"])),
            "configuration_checks": dict.fromkeys(STAGES), "argv": argv, "argv_sha256": sha(canonical(argv)),
            "return_codes": dict.fromkeys(STAGES), "setup_error": None}


def validate_context(value: dict, toolchain: str, seed: str, work: Path, entry: Path, source: dict, run_id: str, run_attempt: str, runner_name: str, source_root: Path = ROOT, runtime_environment: dict[str, str] | None = None) -> None:
    expected = new_context(toolchain, seed, work, entry, source, run_id, run_attempt, runner_name, source_root, runtime_environment)
    require(isinstance(value, dict), "context is not an object")
    outcomes = value.get("return_codes")
    require(isinstance(outcomes, dict) and set(outcomes) == set(STAGES), "execution stage set drift")
    require(all(code is None or type(code) is int and 0 <= code <= 255 for code in outcomes.values()), "invalid stage return code")
    setup_error = value.get("setup_error")
    require(setup_error is None or isinstance(setup_error, str) and bool(setup_error), "invalid setup diagnostic")
    require(setup_error is None or all(code is None for code in outcomes.values()), "native stages after setup failure")
    expected["setup_error"] = setup_error
    expected["return_codes"] = outcomes
    checks = value.get("configuration_checks")
    require(isinstance(checks, dict) and set(checks) == set(STAGES), "configuration stage set drift")
    for stage in STAGES:
        check = checks[stage]
        require((check is None and outcomes[stage] is None) or
                (outcomes[stage] is not None and isinstance(check, dict) and set(check) == {"before", "after"}
                 and all(type(item) is bool for item in check.values())), "invalid configuration observation")
    expected["configuration_checks"] = checks
    expected["source_after"] = value.get("source_after")
    require(value == expected, "context identity/argv/profile drift")
    if outcomes["rustc"] != 0:
        require(all(outcomes[key] is None for key in STAGES[1:]), "stages present after rustc failure")
    if outcomes["test"] != 0:
        require(all(outcomes[key] is None for key in ("hostile", "history", "checker")), "native stages present after build failure")
    if outcomes["history"] != 0:
        require(outcomes["checker"] is None, "checker present after history failure")


def validate_raw(kind: str, value: Any, seed: str) -> None:
    StrictValidator(strict_json(ROOT / "schemas" / RAW_SCHEMAS[kind])).validate(value)
    if kind != "checker":
        require(value["seed"] == seed, f"{kind} seed mismatch")
    if kind == "hostile":
        validate_hostile_detail(value)


def validate_hostile_detail(value: dict) -> None:
    code, phase, status = value["child_exit_code"], value["phase_reached"], value["status"]
    # Linux ExitStatus::code() is an unsigned 8-bit exit status, or None for
    # signal termination. The unchanged parent never reports child_signal.
    require(code is None or type(code) is int and 0 <= code <= 255, "child exit outside native Linux domain")
    require(value["child_signal"] is None, "native parent does not report child_signal")
    detail = value["detail"]
    if set(detail) == {"reason"}:
        require(status == "BLOCKED" and phase is False and code is None
                and value["stdout_lines"] == value["stderr_bytes"] == 0
                and isinstance(detail["reason"], str) and bool(detail["reason"]),
                "early setup/spawn/parent-timeout shape mismatch")
        return
    fields = {"reason", "child_reported_outcome", "child_reported_detail", "stderr_tail", "availability_note", "os_process_suspend", "disk_and_clock_faults"}
    require(set(detail) == fields, "native parent detail fields mismatch")
    require(all(isinstance(detail[key], str) and detail[key] for key in ("reason", "availability_note", "os_process_suspend", "disk_and_clock_faults")) and isinstance(detail["stderr_tail"], str), "native parent detail type mismatch")
    require(detail["os_process_suspend"] == detail["disk_and_clock_faults"] == "NOT_EXECUTED_PROMOTION_BLOCKER", "promotion blockers changed")
    outcome, child = detail["child_reported_outcome"], detail["child_reported_detail"]
    require(outcome is None or isinstance(outcome, str), "child outcome must be string or null")
    if code != 0:
        expected = "EXECUTED_PASS" if phase else "BLOCKED"
        require(status == expected, f"native abnormal-exit decision requires {expected}")
        return
    # Reproduce the unchanged parent's successful-child decision table. In
    # particular, ACCEPTED cannot be relabeled BLOCKED by resealing hashes.
    expected = {"REJECTED": "EXECUTED_PASS", "ACCEPTED": "EXECUTED_FAIL"}.get(outcome, "BLOCKED")
    require(status == expected, f"native child outcome requires {expected}")
    if status == "BLOCKED":
        if outcome == "TIMED_OUT_AFTER_INJECTION":
            require(phase is True and isinstance(child, str) and bool(child), "child timeout shape mismatch")
        elif outcome is None:
            require(child is None, "absent child result must have null detail")
        else:
            require(isinstance(child, (str, dict)) or child is None, "unrecognized child result detail shape mismatch")
        return
    require(phase is True, "executed hostile result must reach injection phase")
    if isinstance(child, str):
        require(outcome == "REJECTED" and bool(child), "explicit rejection detail must be nonempty")
        return
    require(isinstance(child, dict) and set(child) == {"classification", "candidate_response", "guarded_state_unchanged", "metrics_unchanged", "state_machine_unchanged", "before", "after"}, "guard detail shape mismatch")
    flags = [child[key] for key in ("guarded_state_unchanged", "metrics_unchanged", "state_machine_unchanged")]
    require(all(type(flag) is bool for flag in flags) and flags[0] == (flags[1] and flags[2]), "guard boolean contradiction")
    surfaces = {"last_log_index", "local_committed", "cluster_committed", "last_applied", "snapshot", "purged", "state_machine_last_applied", "client_status"}
    for side in ("before", "after"):
        state = child[side]
        require(isinstance(state, dict) and set(state) == surfaces, "guarded surface shape mismatch")
        index = state["last_log_index"]
        require(index is None or type(index) is int and 0 <= index <= 2**64 - 1, "last_log_index must be native u64 or null")
        require(all(state[key] is None or isinstance(state[key], str) for key in surfaces - {"last_log_index", "client_status"}), "log-id surfaces must be native strings or null")
        # openraft-memstore alpha.33 stores/memstore/src/lib.rs at the pinned
        # release commit defines client_status as HashMap<String, String>.
        require(isinstance(state["client_status"], dict) and all(isinstance(key, str) and isinstance(item, str) for key, item in state["client_status"].items()), "client_status must be native string-to-string map")
    require(isinstance(child["candidate_response"], str), "candidate response type mismatch")
    if outcome == "REJECTED":
        require(all(flags) and child["classification"] == "IGNORED_STALE_NO_STATE_CHANGE" and canonical(child["before"]) == canonical(child["after"]), "forged no-op safety claim")
    else:
        require(not flags[0] and child["classification"] == "STALE_SNAPSHOT_STATE_REGRESSION", "forged regression claim")
        # Membership participates in native comparison but is not rendered here;
        # visible before/after equality alone cannot invalidate a real FAIL.


def diagnostic(error: Exception) -> str:
    # Receipts must be reproducible after downloading to a different directory.
    # Keep logical component + errno, not the verifier's local filesystem path.
    if isinstance(error, OSError):
        return f"{error.__class__.__name__}: errno={error.errno}"
    return f"{error.__class__.__name__}: {str(error).splitlines()[0]}"


def collect(entry: Path, context: dict) -> dict:
    """Keep verified safety failures even when another component is unavailable."""
    problems = [context["setup_error"]] if context.get("setup_error") else []
    results = {"hostile_snapshot": None, "linearizability": None}
    codes = context["return_codes"]
    source = context["source_before"]
    artifacts = {name: file_sha(entry / name) for name in ("Cargo.toml", "Cargo.lock", "execution-context.json", "rustc.stdout", *RAW_FILES.values(), *(f"{s}.stderr" for s in STAGES), "test.stdout", "checker.stdout")}
    try:
        require(source["clean_tree"] is True and context["source_after"] == source, "source changed or tree not clean")
        require(artifacts["Cargo.toml"] == source["manifest_sha256"], "committed manifest missing or changed")
        require(artifacts["Cargo.lock"] == source["cargo_lock_sha256"], "committed Cargo.lock missing or changed")
        require(all(context["configuration_checks"][stage] == {"before": True, "after": True}
                    for stage, code in codes.items() if code is not None), "Cargo configuration isolation did not hold")
        require(codes["rustc"] == codes["test"] == 0, "compiler/build stage did not pass")
        rustc = (entry / "rustc.stdout").read_text().splitlines()
        require(rustc and rustc[0].startswith(f"rustc {context['toolchain']} ") and [line for line in rustc if line.startswith("release: ")] == [f"release: {context['toolchain']}"], "actual compiler release mismatch")
        require([line for line in rustc if line.startswith("host: ")] == ["host: x86_64-unknown-linux-gnu"], "actual compiler host target mismatch")
    except (OSError, ValueError, KeyError) as exc:
        problems.append(diagnostic(exc))
    for kind, label in (("hostile", "hostile_snapshot"), ("checker", "linearizability")):
        try:
            require(codes["rustc"] == codes["test"] == 0, "native result without successful build")
            value = strict_json(entry / RAW_FILES[kind])
            validate_raw(kind, value, context["seed"])
            require(codes[kind] == EXIT[value["status"]], f"{kind} status/exit mismatch")
            if kind == "checker":
                require(codes["history"] == 0, "history generator did not pass")
                history = strict_json(entry / RAW_FILES["history"])
                validate_raw("history", history, context["seed"])
                # Same-history deterministic re-evaluation, never comparison across runs.
                require(canonical(value) == canonical(checker.evaluate(history)), "checker result differs from recomputed actual history")
            results[label] = value
        except (OSError, ValueError, KeyError, TypeError, ValidationError) as exc:
            # Schema failures are retained as blocking diagnostics, not rewritten data.
            problems.append(f"{kind}: {diagnostic(exc)}")
    statuses = [value["status"] if value is not None else "BLOCKED" for value in results.values()]
    status = "EXECUTED_FAIL" if "EXECUTED_FAIL" in statuses else "EXECUTED_PASS" if not problems and statuses == ["EXECUTED_PASS", "EXECUTED_PASS"] else "BLOCKED"
    return {"schema": SCHEMA, "revision": "2.0", "execution_profile_id": PROFILE,
            "entry_id": entry_name(context["toolchain"], context["seed"]), "status": status,
            "source": source, "execution": context, "artifacts": artifacts, "results": results, "problems": problems,
            "qualification": False, "selection_effect": "NONE", "authority_effect": "NONE",
            "promotion_effect": checker.BLOCK_PROMOTION}


def execute(context: dict, stage: str, entry: Path) -> int:
    filename = RAW_FILES.get(stage, f"{stage}.stdout") if stage != "checker" else "checker.stdout"
    with (entry / filename).open("wb") as stdout, (entry / f"{stage}.stderr").open("wb") as stderr:
        before = configuration_absent(context)
        try:
            require(before, "Cargo configuration absence not established before stage; command not executed")
            # No inherited Cargo/Rust/Python/loader overrides enter the process.
            result = subprocess.run(context["argv"][stage], stdout=stdout, stderr=stderr, check=False, cwd=context["cwd"], env=dict(context["environment"]))
            code = result.returncode if result.returncode >= 0 else 128 - result.returncode
        except (OSError, ValueError) as exc:
            stderr.write(str(exc).encode())
            code = 125
        context["configuration_checks"][stage] = {"before": before, "after": configuration_absent(context)}
    context["return_codes"][stage] = min(code, 255)
    write(entry / "execution-context.json", context)
    return context["return_codes"][stage]


def copy_committed_probe(root: Path, work: Path, commit: str) -> None:
    """Materialize HEAD blobs only; ignored files cannot become build inputs."""
    records = subprocess.check_output(["git", "-C", str(root), "ls-tree", "-rz", commit, "--", PROBE]).split(b"\0")
    work.mkdir(parents=True)
    for record in filter(None, records):
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, object_sha = metadata.decode().split()
        require(bool(re.fullmatch(r"[0-9a-f]{40}", object_sha)), "malformed committed object identity")
        require(kind == "blob" and mode in {"100644", "100755"}, "probe contains nonregular committed input")
        path = raw_path.decode("utf-8")
        relative = Path(path).relative_to(PROBE)
        require(".." not in relative.parts, "invalid committed probe path")
        destination = work / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = subprocess.check_output(["git", "-C", str(root), "show", f"{commit}:{path}"])
        require(hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest() == object_sha, "committed blob content mismatch")
        destination.write_bytes(content)
        destination.chmod(int(mode[-3:], 8))


def run(args) -> int:
    root, evidence, execution = args.source_root.resolve(), args.evidence_root.resolve(), args.execution_root.resolve()
    require(ROOT == root, "runner must execute the exact checked-out source")
    require(not evidence.exists() and not execution.exists(), "fresh execution/evidence roots required")
    require(not evidence.is_relative_to(root) and not execution.is_relative_to(root), "evidence/work must be outside source tree")
    before = source_snapshot(root)
    require(before["commit"] == args.expected_commit and before["clean_tree"], "checkout is not expected clean source")
    evidence.mkdir(parents=True); execution.mkdir(parents=True)
    # Fresh, shared per-run Cargo cache starts config-free; it may cache public
    # dependencies, but any later config file blocks the next command/final gate.
    for directory in ("home", "cargo-home", "tmp"):
        (execution / directory).mkdir()
    runtime_environment = runtime_base_environment()
    for toolchain in TOOLCHAINS:
        for seed in SEEDS:
            name = entry_name(toolchain, seed)
            entry, work = evidence / name, execution / name / "probe"
            entry.mkdir(); work.parent.mkdir()
            context = new_context(toolchain, seed, work, entry, before, args.run_id, args.run_attempt, args.runner_name, runtime_environment=runtime_environment)
            try:
                copy_committed_probe(root, work, before["commit"])
                require(file_sha(work / "Cargo.toml") == before["manifest_sha256"], "copied committed manifest mismatch before execution")
                require(file_sha(work / "Cargo.lock") == before["cargo_lock_sha256"], "copied committed lock mismatch before execution")
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                context["setup_error"] = diagnostic(exc)
            write(entry / "execution-context.json", context)
            if context["setup_error"] is None and execute(context, "rustc", entry) == 0 and execute(context, "test", entry) == 0:
                execute(context, "hostile", entry)
                if execute(context, "history", entry) == 0:
                    execute(context, "checker", entry)
            for name_ in ("Cargo.toml", "Cargo.lock"):
                if (work / name_).is_file():
                    shutil.copyfile(work / name_, entry / name_)
            try:
                context["source_after"] = source_snapshot(root)
            except (OSError, ValueError, subprocess.SubprocessError):
                context["source_after"] = None
            write(entry / "execution-context.json", context)
            write(entry / "fault-lab-evidence.json", collect(entry, context))
    # Failure status never short-circuits another entry or artifact upload.
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("run")
    for name in ("execution-root", "evidence-root", "source-root"):
        command.add_argument("--" + name, type=Path, required=True)
    for name in ("expected-commit", "run-id", "run-attempt", "runner-name"):
        command.add_argument("--" + name, required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
