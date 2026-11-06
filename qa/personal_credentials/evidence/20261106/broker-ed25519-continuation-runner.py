#!/usr/bin/env python3
"""Complete ordinary CLI builds before first test execution; retain initial evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import time

original = Path("/home/qq/heptabao-broker-ed25519-c447536-run.py")
assert hashlib.sha256(original.read_bytes()).hexdigest() == "de6b79f3f261a44f6be80a14af96fac8ea3e058e33ac3be490739fa471e7814e"
shared = runpy.run_path(str(original))
SOURCE, OUTPUT, COMMIT, TREE, LOCK, ROOTS = (shared[name] for name in ("SOURCE", "OUTPUT", "COMMIT", "TREE", "LOCK", "ROOTS"))
sha, atomic = shared["sha"], shared["atomic"]
CLI_NAMES, TEST_NAMES = shared["CLI_NAMES"], shared["TEST_NAMES"]


def main():
    os.umask(0o077)
    initial = OUTPUT / "receipt.failed.json"
    assert sha(initial) == "53edc60020e3e538b2d23644f83912c6be0f3ceeeff43db15486921d17c54396"
    receipt = json.loads(initial.read_text())
    assert not receipt["artifacts"] and not receipt["tests"]
    assert receipt["commands"][-1]["label"] == "compile-cli-and-tests" and receipt["commands"][-1]["exit_code"] == 0
    receipt["continuation"] = {"initial_failed_receipt_sha256": sha(initial), "script_sha256": sha(Path(__file__)),
        "reason": "cargo_test_no_run_did_not_emit_ordinary_browser_and_sync_binaries",
        "tests_executed_before_continuation": 0, "started_unix_ns": time.time_ns()}
    receipt.pop("error_type", None); receipt.pop("finished_unix_ns", None)
    receipt["result"] = "continuing_before_test_execution"
    logs = OUTPUT / "logs"
    env = dict(os.environ, **receipt["environment"])
    env.pop("HEPTABAO_BROKER_TEST_BINARY", None)

    def run(label, argv, extra_env=None, timeout=600):
        assert not (logs / (label + ".stdout")).exists(), "stage_already_recorded"
        started = time.time_ns()
        with (logs / (label + ".stdout")).open("xb") as out, (logs / (label + ".stderr")).open("xb") as err:
            result = subprocess.run(argv, cwd=SOURCE, env=dict(env, **(extra_env or {})), stdout=out,
                                    stderr=err, timeout=timeout, check=False)
        receipt["commands"].append({"label": label, "argv": list(map(str, argv)), "cwd": str(SOURCE),
            "environment_additions": extra_env or {}, "started_unix_ns": started, "finished_unix_ns": time.time_ns(),
            "exit_code": result.returncode, "stdout_sha256": sha(logs / (label + ".stdout")),
            "stderr_sha256": sha(logs / (label + ".stderr"))})
        atomic(OUTPUT / "receipt.running.json", receipt)
        print(json.dumps({"stage": label, "exit_code": result.returncode}, sort_keys=True), flush=True)
        assert result.returncode == 0, "stage_failed"
        return (logs / (label + ".stdout")).read_bytes()

    def source_state(label):
        assert not run(label + "-git", ["git", "status", "--porcelain=v1", "--untracked-files=all"])
        values = run(label + "-head", ["git", "rev-parse", "HEAD", "HEAD^{tree}"]).decode().splitlines()
        assert values == [COMMIT, TREE] and sha(SOURCE / "Cargo.lock") == LOCK
        return {"head": COMMIT, "tree": TREE, "cargo_lock_sha256": LOCK, "status_clean": True}

    def executable_rows(raw):
        rows = [json.loads(line) for line in raw.splitlines() if line.startswith(b"{")]
        return [row for row in rows if row.get("reason") == "compiler-artifact" and row.get("executable")]

    try:
        receipt["source_before_continuation"] = source_state("before-continuation")
        old_compile = logs / "compile-cli-and-tests.stdout"
        assert sha(old_compile) == "7c2cc2e6d34335ae2ac96b9530b671860d6655415dfe9340933bc264673031e5"
        test_rows = executable_rows(old_compile.read_bytes())
        target = OUTPUT / "target/debug"
        receipt["continuation"]["cli_before_normal_build"] = {name: sha(target / name) if (target / name).is_file() else None for name in sorted(CLI_NAMES)}
        cli_rows = executable_rows(run("compile-normal-cli", ["cargo", "+1.98.0", "build", "--locked", "--offline", *ROOTS,
                                      "--bins", "--message-format=json"]))
        cli_dir, test_dir = OUTPUT / "bin-qualified", OUTPUT / "test-qualified"
        assert cli_dir.is_dir() and not any(cli_dir.iterdir()) and test_dir.is_dir() and not any(test_dir.iterdir())
        for name in sorted(CLI_NAMES):
            matches = [row for row in cli_rows if row["target"]["name"] == name and not row["profile"]["test"]]
            assert len(matches) == 1
            source, copied = Path(matches[0]["executable"]), cli_dir / name
            before = receipt["continuation"]["cli_before_normal_build"][name]
            shutil.copyfile(source, copied); copied.chmod(0o500)
            assert sha(source) == sha(copied)
            reused = matches[0].get("fresh") is True and before == sha(copied)
            receipt["artifacts"][name] = {"original_path": str(source), "retained_path": str(copied), "sha256": sha(copied),
                "bytes": copied.stat().st_size, "copied_unix_ns": time.time_ns(), "compiler_artifact": matches[0],
                "artifact_record_command": "compile-normal-cli", "prior_sha256": before,
                "producing_command": "compile-cli-and-tests" if reused else "compile-normal-cli",
                "reused_identical_prior_artifact": reused}
        for name in TEST_NAMES:
            matches = [row for row in test_rows if row["target"]["name"] == name
                       and "heptabao-credential-broker" in row["package_id"] and row["profile"]["test"]]
            assert len(matches) == 1
            source, copied = Path(matches[0]["executable"]), test_dir / name
            shutil.copyfile(source, copied); copied.chmod(0o500)
            assert sha(source) == sha(copied)
            receipt["tests"][name] = {"original_path": str(source), "retained_path": str(copied), "sha256": sha(copied),
                "compiler_artifact": matches[0], "producing_command": "compile-cli-and-tests"}
        receipt["source_after_build"] = source_state("fixed-build")
        atomic(OUTPUT / "receipt.running.json", receipt)
        print(json.dumps({"stage": "fixed_binaries_ready", "bin_dir": str(cli_dir),
                          "cli_sha256": {key: value["sha256"] for key, value in receipt["artifacts"].items()}}, sort_keys=True), flush=True)
        cli = cli_dir / "heptabao-credential-broker"
        for name, expected in TEST_NAMES.items():
            record = receipt["tests"][name]; executable = Path(record["retained_path"])
            record["before_execution"] = {"test_sha256": sha(executable), "cli_sha256": sha(cli),
                "original_cli_sha256": sha(Path(receipt["artifacts"][cli.name]["original_path"]))}
            text = run("execute-" + name, [str(executable), "--test-threads=1"],
                       extra_env={"HEPTABAO_BROKER_TEST_BINARY": str(cli)}, timeout=180).decode()
            record["after_execution"] = {"test_sha256": sha(executable), "cli_sha256": sha(cli),
                "original_cli_sha256": sha(Path(receipt["artifacts"][cli.name]["original_path"]))}
            assert record["before_execution"] == record["after_execution"]
            passed = re.findall(r"^test ([A-Za-z0-9_]+) \.\.\. ok$", text, re.MULTILINE)
            assert len(passed) == expected and f"test result: ok. {expected} passed; 0 failed; 0 ignored;" in text
            record.update({"passed": len(passed), "test_names": passed, "failed": 0, "ignored": 0,
                           "actual_cli_path": str(cli), "actual_cli_sha256": sha(cli)})
        receipt["source_after_tests"] = source_state("verified-tests")
        old_bin = Path(str(shared["OLD_SOURCE"]) + "-build-a1b6ff4/bin-final")
        receipt["old_retained_binary_sha256_after"] = {name: sha(old_bin / name) for name in sorted(CLI_NAMES)}
        assert receipt["old_retained_binary_sha256_before"] == receipt["old_retained_binary_sha256_after"]
        for record in receipt["artifacts"].values():
            assert sha(Path(record["original_path"])) == sha(Path(record["retained_path"])) == record["sha256"]
            record["verified_after_tests"] = True
        receipt["result"] = "passed_11_existing_and_2_algorithm_policy_integration_tests"
        receipt["finished_unix_ns"] = time.time_ns()
        atomic(OUTPUT / "receipt.final.json", receipt)
        print(json.dumps({"ok": True, "broker_tests": 13, "receipt": str(OUTPUT / "receipt.final.json"),
                          "receipt_sha256": sha(OUTPUT / "receipt.final.json"), "bin_dir": str(cli_dir)}, sort_keys=True), flush=True)
    except Exception as error:
        receipt["result"] = "failed_continuation"; receipt["error_type"] = type(error).__name__
        receipt["finished_unix_ns"] = time.time_ns()
        atomic(OUTPUT / "receipt.resume.failed.json", receipt)
        print(json.dumps({"ok": False, "error_type": type(error).__name__,
                          "receipt": str(OUTPUT / "receipt.resume.failed.json")}, sort_keys=True), flush=True)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
