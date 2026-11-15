#!/usr/bin/env python3
"""Run three additional exact HTTP tests from the completed host libtest build.

No Cargo command is issued. The completed original host cohort, native artifact,
source closure and resource profile are explicit input pins. Process custody and
the existing target lock are delegated to the pinned native-only R3 helper.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import sys
import types


SCHEMA = "heptabao.native-snapshot-http3-config.v1"
PROFILE_PATH = "qa/openbao-acceptance/native_candidate_host_run.py"
FEATURES = "experimental-native-v6-ha,private-ha-forward-diagnostic"
COMMAND_SECONDS = 1800
CASES = (
    ("snapshot-json-accept-history", "http::snapshot_accept_tests::native_snapshot_https_json_accept_download_restore_and_cold_keep_exact_history"),
    ("snapshot-json-accept-refusals", "http::snapshot_accept_tests::native_snapshot_https_json_accept_keeps_actor_namespace_seal_and_archive_refusals"),
    ("snapshot-json-accept-framing", "http::snapshot::tests::binary_route_only_supports_chunking_and_snapshot_accept_remains_binary"),
)
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON field: " + key)
        result[key] = value
    return result


def json_bytes(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def canonical_file(path, limit=64 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical absolute input path required")
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "regular bounded input file required")
    return path, path.read_bytes()


def pinned_file(path, digest, limit=64 * 1024 * 1024):
    need(isinstance(digest, str) and HEX64.fullmatch(digest), "explicit SHA256 pin required")
    path, raw = canonical_file(path, limit)
    need(sha(raw) == digest, "input SHA256 differs: " + str(path))
    return path, raw


def load_module(path, raw, name):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    # Executing verified bytes avoids import cache writes inside the source tree.
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def command_row(producer, label):
    rows = [row for row in producer["commands"] if row.get("label") == label]
    need(len(rows) == 1 and rows[0].get("status") != "running", "unique completed producer command required: " + label)
    return rows[0]


def producer_log(directory, row, retained):
    name = row["log"]
    need(Path(name).name == name and name.endswith(".log"), "producer log must be a direct retained file")
    path, raw = pinned_file(directory / name, row["log_sha256"])
    retained[path] = sha(raw)
    return raw.decode("utf-8", errors="strict")


def listed_exact(text, name):
    names = re.findall(r"^([^\r\n]+): test$", text, re.MULTILINE)
    totals = re.findall(r"^(\d+) tests?, (\d+) benchmarks?$", text, re.MULTILINE)
    need(names == [name] and totals == [("1", "0")], "discovery must report the exact single test and zero benchmarks")
    return names


def observed_result(text, name):
    names = re.findall(r"^test ([^\s]+) \.\.\.", text, re.MULTILINE)
    started = re.findall(r"^running (\d+) tests?$", text, re.MULTILINE)
    rows = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; \d+ filtered out; finished in [^\r\n]+$", text, re.MULTILINE)
    if names != [name] or started != ["1"] or len(rows) != 1:
        return None
    status, passed, failed, ignored, measured = rows[0]
    counts = [int(passed), int(failed), int(ignored), int(measured)]
    if sum(counts) != 1 or (status == "ok" and counts[1]) or (status == "FAILED" and not counts[1]):
        return None
    return {"status": status, "passed": counts[0], "failed": counts[1], "ignored": counts[2], "measured": counts[3]}


def load_context(config):
    need(config.get("schema") == SCHEMA, "unsupported explicit execution config")
    for key in ("source_commit", "source_tree"):
        need(isinstance(config.get(key), str) and HEX40.fullmatch(config[key]), "explicit source identity required")
    source = Path(config["source"])
    target = Path(config["target_dir"])
    output = Path(config["output"])
    for path in (source, target):
        need(path.is_absolute() and path.resolve(strict=True) == path and path.is_dir(), "existing canonical source and target directories required")
    need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent and not output.exists() and not output.is_symlink(), "new output directory in an existing canonical parent required")
    for left, right in ((source, target), (source, output), (target, output)):
        need(left != right and left not in right.parents and right not in left.parents, "source, target and output must be disjoint")
    retained = {}
    manifest_path, manifest_raw = pinned_file(config["manifest"], config["manifest_sha256"])
    retained[manifest_path] = sha(manifest_raw)
    manifest = json_bytes(manifest_raw)
    need(manifest.get("commit") == config["source_commit"] and manifest.get("tree") == config["source_tree"], "manifest identity differs from explicit source pins")
    profile_path, profile_raw = pinned_file(source / PROFILE_PATH, config["source_runner_sha256"])
    entries = [item for item in manifest["files"] if item.get("path") == PROFILE_PATH]
    blob = hashlib.sha1(b"blob " + str(len(profile_raw)).encode() + b"\0" + profile_raw).hexdigest()
    need(len(entries) == 1 and entries[0]["sha"] == blob, "source verifier differs from manifest blob")
    profile = load_module(profile_path, profile_raw, "http3_source_profile")
    helper_path, helper_raw = pinned_file(config["owned_runner"], config["owned_runner_sha256"])
    retained[helper_path] = sha(helper_raw)
    helper = load_module(helper_path, helper_raw, "http3_owned_process_helper")
    need(helper.COMMAND_BUDGET == COMMAND_SECONDS and helper.LOCK_NAME == "heptabao-owned-candidate-run.lock", "existing command budget and target lock required")
    need(profile.SERVER_FEATURES == FEATURES and sum(row[3] for row in profile.GROUPS) == 55, "original 55-test profile required")
    summary_path, summary_raw = pinned_file(config["producer_summary"], config["producer_summary_sha256"])
    retained[summary_path] = sha(summary_raw)
    producer = json_bytes(summary_raw)
    need(producer.get("runner_completed") is True and producer.get("source_unchanged") is True and producer.get("finished_utc"), "original host cohort must have completed before additional tests")
    need(producer.get("source") == str(source) and producer.get("source_commit") == config["source_commit"] and producer.get("source_tree") == config["source_tree"] and producer.get("manifest_sha256") == config["manifest_sha256"] and producer.get("runner_sha256") == config["source_runner_sha256"], "producer source or build runner identity differs")
    need(producer.get("hostname") == platform.node() and producer.get("machine") == platform.machine(), "same physical producer and executor required")
    expected_source = {"commit": config["source_commit"], "tree": config["source_tree"], "verified_files": len(manifest["files"])}
    for key in ("source_before", "source_after"):
        need({k: producer.get(key, {}).get(k) for k in expected_source} == expected_source, "producer source closure evidence differs")
    need(producer.get("selected_groups") == [row[0] for row in profile.GROUPS], "original host selectors differ")
    for label, _owner, _selector, _count in profile.GROUPS:
        command_row(producer, label + "-list")
        command_row(producer, label)
    build = config["build_profile"]
    need(build.get("server_features") == FEATURES and build.get("rust_release") == "1.98.0" and producer.get("compiler_resource_profile") == build.get("compiler_resource_profile"), "explicit original compiler profile differs")
    compile_row = command_row(producer, "compile-server-tests")
    expected_argv = [build["cargo"], "test", "--locked", "--offline", "-p", "heptabao-server", "--lib", "--features", FEATURES, "--no-run"]
    need(compile_row.get("argv") == expected_argv and compile_row.get("status") == "passed" and compile_row.get("exit_code") == 0, "actual original server libtest compilation required")
    compile_text = producer_log(summary_path.parent, compile_row, retained)
    matches = re.findall(r"^\s*Executable unittests src/lib\.rs \(([^\r\n()]+)\)\s*$", compile_text, re.MULTILINE)
    libtest = Path(config["libtest"])
    need(matches == [str(libtest)] and libtest.is_absolute() and libtest.resolve(strict=True) == libtest and libtest.parent == target / "debug/deps" and re.fullmatch(r"heptabao_server-[0-9a-f]{16,64}", libtest.name), "unique compiled libtest must be inside the exact owned target")
    info = libtest.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 and HEX64.fullmatch(config["libtest_sha256"]), "explicit executable libtest identity required")
    for name in ("cargo", "rustc"):
        row = command_row(producer, name + "-version")
        need(row.get("argv") == [build[name], "--version", "--verbose"] and row.get("status") == "passed" and row.get("exit_code") == 0, "actual pinned compiler version command required")
        text = producer_log(summary_path.parent, row, retained)
        need(re.search(r"^" + name + r" 1\.98\.0\b", text, re.MULTILINE), "actual Rust release differs")
    return source, target, output, manifest, profile, helper, producer, libtest, retained


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--config-sha256", required=True)
    args = parser.parse_args(argv)
    config_path, config_raw = pinned_file(args.config, args.config_sha256)
    config = json_bytes(config_raw)
    source, target, output, manifest, profile, helper, producer, libtest, retained = load_context(config)
    retained[config_path] = sha(config_raw)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    temp = output / "tmp"
    temp.mkdir(mode=0o700)
    summary = {"schema": "heptabao.native-snapshot-http3-run.v1", "status": "running", "started_utc": helper.utc(),
               "controller_sha256": helper.sha256_file(Path(__file__)), "config_sha256": sha(config_raw),
               "source": str(source), "source_commit": config["source_commit"], "source_tree": config["source_tree"],
               "manifest_sha256": config["manifest_sha256"], "source_runner_sha256": config["source_runner_sha256"],
               "owned_runner_sha256": config["owned_runner_sha256"], "target_dir": str(target), "target_lock_acquired": False,
               "producer_summary_sha256": config["producer_summary_sha256"], "producer_original_status": producer["status"],
               "build_profile": config["build_profile"], "libtest": str(libtest), "libtest_sha256": config["libtest_sha256"],
               "hostname": platform.node(), "platform": platform.platform(), "machine": platform.machine(), "uname": list(os.uname()),
               "runner_pid": os.getpid(), "required_additional_test_count": 3, "original_host_test_count": 55,
               "original_full34_required_checks": 31, "original_command_deadline_seconds": COMMAND_SECONDS,
               "compiler_invocations": 0, "commands": [], "tests": [],
               "verified_input_pins": [{"path": str(path), "sha256": digest} for path, digest in retained.items()],
               "physical_lan_fault_validation_performed": False, "real_credential_validation_performed": False,
               "production_cutover_performed": False, "full_openbao_271_replacement_proven": False}
    save = lambda: helper.write_json(output / "summary.json", summary)
    save()
    lock = None

    def interrupted(signum, _frame):
        raise KeyboardInterrupt("additional test controller received signal " + str(signum))

    old_handlers = {value: signal.signal(value, interrupted) for value in (signal.SIGINT, signal.SIGTERM)}
    try:
        lock = helper.acquire_target_lock(target, {"pid": os.getpid(), "source_commit": config["source_commit"], "output": str(output), "scope": "three additional exact HTTP tests"})
        summary["target_lock_acquired"] = True
        summary["source_before"] = profile.verify_tree(source, manifest)
        need(all(helper.sha256_file(path) == digest for path, digest in retained.items()), "explicit input pins changed before execution")
        summary["libtest_before_sha256"] = helper.sha256_file(libtest)
        need(summary["libtest_before_sha256"] == config["libtest_sha256"], "libtest bytes differ from explicit build artifact pin")
        inputs = output / "inputs"
        inputs.mkdir(mode=0o700)
        for name, path in (("config.json", config_path), ("producer-summary.json", Path(config["producer_summary"]))):
            (inputs / name).write_bytes(path.read_bytes())
        for label in ("cargo-version", "rustc-version", "compile-server-tests"):
            row = command_row(producer, label)
            path = Path(config["producer_summary"]).parent / row["log"]
            (inputs / ("producer-" + row["log"])).write_bytes(path.read_bytes())
        cwd = source / "crates/heptabao-server"
        environment = {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C",
                       "TMPDIR": str(temp), "CARGO_MANIFEST_DIR": str(cwd), "CARGO_TARGET_TMPDIR": str(temp), "RUST_TEST_THREADS": "1"}
        summary["runtime_environment"] = environment
        for label, exact_name in CASES:
            row = {"label": label, "exact_name": exact_name, "expected_count": 1, "status": "pending"}
            summary["tests"].append(row)
            listing = helper.run_logged(label + "-list", [libtest, exact_name, "--exact", "--list", "--color=never"], cwd, environment, output, summary["commands"], save, budget=COMMAND_SECONDS)
            try:
                need(listing["status"] == "passed", "discovery command did not complete successfully")
                row["actual_selected_test_names"] = listed_exact((output / listing["log"]).read_text(), exact_name)
            except ValueError as error:
                row.update(status="blocked", reason=str(error))
                save()
                continue
            executed = helper.run_logged(label, [libtest, exact_name, "--exact", "--nocapture", "--test-threads=1", "--color=never"], cwd, environment, output, summary["commands"], save, budget=COMMAND_SECONDS)
            result = observed_result((output / executed["log"]).read_text(), exact_name)
            passed = executed["status"] == "passed" and result == {"status": "ok", "passed": 1, "failed": 0, "ignored": 0, "measured": 0}
            row.update(status="passed" if passed else "failed", observed_test_result=result, exit_code=executed.get("exit_code"), log_sha256=executed["log_sha256"])
            save()
        summary["runner_completed"] = True
    except BaseException as error:
        summary.update(error_type=type(error).__name__, error=str(error))
    finally:
        if lock is not None:
            try:
                summary["source_after"] = profile.verify_tree(source, manifest)
                summary["source_unchanged"] = bool(summary.get("source_before"))
                summary["libtest_after_sha256"] = helper.sha256_file(libtest)
                summary["libtest_unchanged"] = summary.get("libtest_before_sha256") == config["libtest_sha256"] == summary["libtest_after_sha256"]
                summary["input_pins_unchanged"] = all(pinned_file(path, digest)[0] == path for path, digest in retained.items())
            except BaseException as error:
                summary.update(final_verification_error=str(error))
            finally:
                lock.close()
        passed = (summary.get("runner_completed") is True and not summary.get("error") and not summary.get("final_verification_error")
                  and summary.get("source_unchanged") is True and summary.get("libtest_unchanged") is True and summary.get("input_pins_unchanged") is True
                  and len(summary["tests"]) == 3 and all(row["status"] == "passed" for row in summary["tests"]))
        summary.update(status="passed_three_additional_exact_http_tests" if passed else "failed_or_blocked", finished_utc=helper.utc(),
                       actual_passed_test_count=sum((row.get("observed_test_result") or {}).get("passed", 0) for row in summary["tests"]))
        save()
        for value, handler in old_handlers.items():
            signal.signal(value, handler)
    print(json.dumps({"status": summary["status"], "summary": str(output / "summary.json"), "actual_passed_test_count": summary["actual_passed_test_count"], "required_additional_test_count": 3}), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
