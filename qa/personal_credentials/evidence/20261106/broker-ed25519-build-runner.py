#!/usr/bin/env python3
"""Private fixed-source qualification, with no credentials or device operations."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

COMMIT = "c447536ae0343731d84c18291d2dcd712b3bea08"
TREE = "50835fd4df6e7bdd2b551941a3fa012281c931c2"
LOCK = "ef3b19cf8b1b360f7888f11e3e5b1523e464762d6c24ce7e92b64d0d7d5c99a9"
BUNDLE_SHA = "4973eb63705f49f1950568c838d67e403463a3753d5eca8c5c91bb6f482a1d8e"
SOURCE = Path("/home/qq/heptabao-broker-ed25519-c447536")
OUTPUT = Path("/home/qq/heptabao-broker-ed25519-c447536-build")
BUNDLE = Path("/home/qq/heptabao-broker-ed25519-c447536.bundle")
OLD_SOURCE = Path("/home/qq/heptabao-personal-credentials-20261106-r1")
ROOTS = ["-p", "heptabao-credential-broker", "-p", "heptabao-personal-vault", "-p", "heptabao-personal-edge"]
CLI_NAMES = {"heptabao-credential-broker", "heptabao-vault", "heptabao-browser", "heptabao-sync"}
TEST_NAMES = {"process_e2e": 11, "algorithm_policy": 2}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic(path, value):
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main():
    os.umask(0o077)
    assert not SOURCE.exists() and not OUTPUT.exists(), "qualification_path_preexists"
    assert sha(BUNDLE) == BUNDLE_SHA, "source_bundle_changed"
    OUTPUT.mkdir(mode=0o700)
    logs = OUTPUT / "logs"
    logs.mkdir(mode=0o700)
    # Tests create their own random 0700 child directories. Keep their parent
    # short so AF_UNIX addresses fit the platform's sockaddr_un limit.
    temporary = Path("/tmp")
    env = dict(os.environ, PATH="/home/qq/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
               CARGO_BUILD_JOBS="2", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
               CARGO_INCREMENTAL="0", CARGO_TARGET_DIR=str(OUTPUT / "target"), TMPDIR=str(temporary))
    env.pop("HEPTABAO_BROKER_TEST_BINARY", None)
    tracked_env = {name: env[name] for name in ("PATH", "CARGO_BUILD_JOBS", "CARGO_PROFILE_DEV_DEBUG",
                  "CARGO_PROFILE_TEST_DEBUG", "CARGO_INCREMENTAL", "CARGO_TARGET_DIR", "TMPDIR")}
    receipt = {"schema": 1, "scope": "synthetic_three_crate_build_and_13_broker_integration_tests",
               "production_qualified": False, "source_expected_commit": COMMIT,
               "source_expected_tree": TREE, "source_bundle_sha256": BUNDLE_SHA,
               "builder_sha256": sha(Path(__file__)), "environment": tracked_env,
               "started_unix_ns": time.time_ns(), "commands": [], "artifacts": {}, "tests": {},
               "old_qualification_directory_not_modified": str(OLD_SOURCE),
               "scope_limit": "No P0/server tests; no claim that the workspace is vulnerability-free."}
    old_bin = Path(str(OLD_SOURCE) + "-build-a1b6ff4/bin-final")
    receipt["old_retained_binary_sha256_before"] = {name: sha(old_bin / name) for name in sorted(CLI_NAMES)}

    def run(label, argv, cwd=SOURCE, required=True, extra_env=None, timeout=600):
        started = time.time_ns()
        command_env = dict(env, **(extra_env or {}))
        with (logs / (label + ".stdout")).open("wb") as stdout, (logs / (label + ".stderr")).open("wb") as stderr:
            result = subprocess.run(argv, cwd=cwd, env=command_env, stdout=stdout, stderr=stderr,
                                    timeout=timeout, check=False)
        record = {"label": label, "argv": list(map(str, argv)), "cwd": str(cwd),
                  "environment_additions": extra_env or {}, "started_unix_ns": started,
                  "finished_unix_ns": time.time_ns(), "exit_code": result.returncode,
                  "stdout_sha256": sha(logs / (label + ".stdout")),
                  "stderr_sha256": sha(logs / (label + ".stderr"))}
        receipt["commands"].append(record)
        atomic(OUTPUT / "receipt.running.json", receipt)
        print(json.dumps({"stage": label, "exit_code": result.returncode}, sort_keys=True), flush=True)
        if required and result.returncode:
            raise RuntimeError("qualification_stage_failed_" + label)
        return (logs / (label + ".stdout")).read_bytes(), result.returncode

    def source_state(label):
        raw, _ = run(label + "-git", ["git", "status", "--porcelain=v1", "--untracked-files=all"])
        assert not raw, "source_worktree_not_clean"
        head, _ = run(label + "-head", ["git", "rev-parse", "HEAD", "HEAD^{tree}"])
        values = head.decode().splitlines()
        assert values == [COMMIT, TREE], "source_identity_changed"
        assert sha(SOURCE / "Cargo.lock") == LOCK, "lockfile_changed"
        return {"head": values[0], "tree": values[1], "status_clean": True, "cargo_lock_sha256": LOCK}

    try:
        run("clone-isolated", ["git", "clone", "--no-hardlinks", str(OLD_SOURCE), str(SOURCE)], cwd=OUTPUT)
        run("import-frozen-source", ["git", "fetch", str(BUNDLE), "HEAD"])
        run("checkout-frozen-source", ["git", "checkout", "--detach", COMMIT])
        receipt["source_before"] = source_state("before")
        version, _ = run("rustc-version", ["rustc", "+1.98.0", "-vV"])
        receipt["rustc_vV"] = version.decode()
        assert receipt["rustc_vV"].startswith("rustc 1.98.0 "), "wrong_rustc"
        for name in ("cargo", "rustc"):
            path_bytes, _ = run(name + "-executable", ["rustup", "which", "--toolchain", "1.98.0", name])
            path = Path(path_bytes.decode().strip())
            receipt.setdefault("tools", {})[name] = {"path": str(path), "sha256": sha(path)}
        for name in ("ssh-keygen", "git"):
            path = Path(shutil.which(name, path=env["PATH"]))
            receipt.setdefault("tools", {})[name] = {"path": str(path), "sha256": sha(path)}
        for target in ("x86_64-unknown-linux-gnu", "aarch64-apple-darwin"):
            raw, status = run("selected-graph-" + target,
                ["cargo", "+1.98.0", "tree", "--locked", "--offline", "--target", target,
                 "--edges", "normal", "--prefix", "depth", "--format", "{p} [{f}]", *ROOTS],
                required=target == "x86_64-unknown-linux-gnu")
            graph = raw.decode()
            value = {"exit_code": status, "sha256": hashlib.sha256(raw).hexdigest(),
                     "rsa_selected": None if status else "rsa v0.9.10" in graph,
                     "crypto_bigint_selected": None if status else "crypto-bigint v0.5.5" in graph,
                     "ssh_key_lines": [line for line in graph.splitlines() if "ssh-key v" in line]}
            receipt.setdefault("selected_normal_graphs", {})[target] = value
            if not status:
                assert not value["rsa_selected"] and not value["crypto_bigint_selected"], "unneeded_crypto_still_selected"
        raw, status = run("workspace-graph-observation",
            ["cargo", "+1.98.0", "tree", "--locked", "--offline", "--target", "x86_64-unknown-linux-gnu",
             "--edges", "normal", "--prefix", "depth", "--format", "{p} [{f}]", "--workspace"], required=False)
        receipt["workspace_normal_graph"] = {"exit_code": status,
            "rsa_selected": None if status else "rsa v0.9.10" in raw.decode(),
            "crypto_bigint_selected": None if status else "crypto-bigint v0.5.5" in raw.decode(),
            "scope": "observation_only_not_a_workspace_test_or_clean_audit",
            "server_manifest_sha256": sha(SOURCE / "crates/heptabao-server/Cargo.toml"),
            "server_ssh_key_declaration": next(line for line in (SOURCE / "crates/heptabao-server/Cargo.toml").read_text().splitlines() if line.startswith("ssh-key ="))}
        run("fmt", ["cargo", "+1.98.0", "fmt", *ROOTS, "--", "--check"])
        run("clippy", ["cargo", "+1.98.0", "clippy", "--locked", "--offline", *ROOTS, "--all-targets", "--", "-D", "warnings"])
        compile_log, _ = run("compile-cli-and-tests", ["cargo", "+1.98.0", "test", "--locked", "--offline", *ROOTS,
                             "--tests", "--no-run", "--message-format=json"])
        artifacts = [json.loads(line) for line in compile_log.splitlines() if line.startswith(b"{")]
        executables = [row for row in artifacts if row.get("reason") == "compiler-artifact" and row.get("executable")]
        cli_dir, test_dir = OUTPUT / "bin-qualified", OUTPUT / "test-qualified"
        cli_dir.mkdir(mode=0o700); test_dir.mkdir(mode=0o700)
        for name in sorted(CLI_NAMES):
            matches = [row for row in executables if row["target"]["name"] == name and not row["profile"]["test"]]
            assert len(matches) == 1, "missing_cli_artifact"
            original, copied = Path(matches[0]["executable"]), cli_dir / name
            shutil.copyfile(original, copied); copied.chmod(0o500)
            assert sha(original) == sha(copied), "copied_cli_changed"
            receipt["artifacts"][name] = {"original_path": str(original), "retained_path": str(copied),
                "sha256": sha(copied), "bytes": copied.stat().st_size, "producing_command": "compile-cli-and-tests",
                "compiler_artifact": matches[0], "copied_unix_ns": time.time_ns()}
        for name in TEST_NAMES:
            matches = [row for row in executables if row["target"]["name"] == name
                       and "heptabao-credential-broker" in row["package_id"] and row["profile"]["test"]]
            assert len(matches) == 1, "missing_test_artifact"
            original, copied = Path(matches[0]["executable"]), test_dir / name
            shutil.copyfile(original, copied); copied.chmod(0o500)
            assert sha(original) == sha(copied), "copied_test_changed"
            receipt["tests"][name] = {"original_path": str(original), "retained_path": str(copied),
                "sha256": sha(copied), "compiler_artifact": matches[0], "producing_command": "compile-cli-and-tests"}
        receipt["source_after_build"] = source_state("after-build")
        atomic(OUTPUT / "receipt.running.json", receipt)
        print(json.dumps({"stage": "fixed_binaries_ready", "bin_dir": str(cli_dir),
                          "cli_sha256": {name: row["sha256"] for name, row in receipt["artifacts"].items()}}, sort_keys=True), flush=True)
        cli = cli_dir / "heptabao-credential-broker"
        for name, expected in TEST_NAMES.items():
            record = receipt["tests"][name]
            executable = Path(record["retained_path"])
            record["before_execution"] = {"test_sha256": sha(executable), "cli_sha256": sha(cli),
                                          "original_cli_sha256": sha(Path(receipt["artifacts"][cli.name]["original_path"]))}
            raw, _ = run("execute-" + name, [str(executable), "--test-threads=1"],
                         extra_env={"HEPTABAO_BROKER_TEST_BINARY": str(cli)}, timeout=180)
            record["after_execution"] = {"test_sha256": sha(executable), "cli_sha256": sha(cli),
                                         "original_cli_sha256": sha(Path(receipt["artifacts"][cli.name]["original_path"]))}
            assert record["before_execution"] == record["after_execution"], "execution_artifact_changed"
            text = raw.decode()
            passed = re.findall(r"^test ([A-Za-z0-9_]+) \.\.\. ok$", text, re.MULTILINE)
            assert len(passed) == expected and f"test result: ok. {expected} passed; 0 failed; 0 ignored;" in text, "test_count_not_confirmed"
            record.update({"passed": len(passed), "test_names": passed, "failed": 0, "ignored": 0,
                           "actual_cli_path": str(cli), "actual_cli_sha256": sha(cli)})
        receipt["source_after_tests"] = source_state("after-tests")
        receipt["old_retained_binary_sha256_after"] = {name: sha(old_bin / name) for name in sorted(CLI_NAMES)}
        assert receipt["old_retained_binary_sha256_before"] == receipt["old_retained_binary_sha256_after"], "old_qualification_binary_changed"
        for record in receipt["artifacts"].values():
            assert sha(Path(record["original_path"])) == sha(Path(record["retained_path"])) == record["sha256"], "final_cli_changed"
            record["verified_after_tests"] = True
        receipt["result"] = "passed_11_existing_and_2_algorithm_policy_integration_tests"
        receipt["finished_unix_ns"] = time.time_ns()
        atomic(OUTPUT / "receipt.final.json", receipt)
        print(json.dumps({"ok": True, "broker_tests": 13, "receipt": str(OUTPUT / "receipt.final.json"),
                          "receipt_sha256": sha(OUTPUT / "receipt.final.json"), "bin_dir": str(cli_dir)}, sort_keys=True), flush=True)
    except Exception as error:
        receipt["result"] = "failed"
        receipt["error_type"] = type(error).__name__
        receipt["finished_unix_ns"] = time.time_ns()
        atomic(OUTPUT / "receipt.failed.json", receipt)
        print(json.dumps({"ok": False, "error_type": type(error).__name__,
                          "receipt": str(OUTPUT / "receipt.failed.json")}, sort_keys=True), flush=True)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
