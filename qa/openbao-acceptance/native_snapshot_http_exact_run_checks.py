#!/usr/bin/env python3
"""Local adapter checks; synthetic metadata is never Rust acceptance evidence."""

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest


HERE = Path(__file__).resolve().parent
ADAPTER = types.ModuleType("http3_adapter")
ADAPTER.__file__ = str(HERE / "native_snapshot_http_exact_run.py")
exec(compile(Path(ADAPTER.__file__).read_bytes(), ADAPTER.__file__, "exec"), ADAPTER.__dict__)
HELPER = Path(os.environ["HEPTABAO_HTTP3_CHECK_OWNED_RUNNER"])
PROFILE = Path(os.environ["HEPTABAO_HTTP3_CHECK_SOURCE_RUNNER"])


def encode(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def tree_digest(files):
    node = {}
    for name, blob in files:
        target = node
        parts = name.split("/")
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = blob

    def digest(current):
        values = []
        for name, value in current.items():
            directory = isinstance(value, dict)
            actual = digest(value) if directory else value
            values.append((name.encode() + (b"/" if directory else b""), (b"40000" if directory else b"100644") + b" " + name.encode() + b"\0" + bytes.fromhex(actual)))
        raw = b"".join(value for _, value in sorted(values))
        return hashlib.sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return digest(node)


class AdapterChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="heptabao-http3-adapter-")
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        self.target = self.root / "target"
        self.producer_dir = self.root / "producer"
        for path in (self.source / "qa/openbao-acceptance", self.source / "crates/heptabao-server", self.target / "debug/deps", self.producer_dir):
            path.mkdir(parents=True)
        raw = PROFILE.read_bytes()
        (self.source / ADAPTER.PROFILE_PATH).write_bytes(raw)
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        self.profile = ADAPTER.load_module(PROFILE, raw, "synthetic_producer_profile")
        tree = tree_digest([(ADAPTER.PROFILE_PATH, blob)])
        manifest = {"commit": "a" * 40, "tree": tree, "files": [{"path": ADAPTER.PROFILE_PATH, "mode": "100644", "sha": blob}]}
        manifest_raw = encode(manifest)
        manifest_path = self.root / "manifest.json"
        manifest_path.write_bytes(manifest_raw)
        self.artifact = self.target / "debug/deps/heptabao_server-0123456789abcdef"
        self.artifact.write_bytes(b"synthetic never-executed artifact\n")
        self.artifact.chmod(0o700)
        resource = {"cargo_build_jobs": "2", "cmake_build_parallel_level": "2", "test_debug": None, "dev_debug": None, "incremental": None}
        build = {"cargo": "/synthetic/toolchain/bin/cargo", "rustc": "/synthetic/toolchain/bin/rustc", "rust_release": "1.98.0", "server_features": ADAPTER.FEATURES, "compiler_resource_profile": resource}
        source_evidence = {"commit": manifest["commit"], "tree": tree, "verified_files": 1}
        self.producer = {"status": "synthetic_completed_for_adapter_checks_only", "runner_completed": True, "source_unchanged": True, "finished_utc": "synthetic",
                         "source": str(self.source), "source_commit": manifest["commit"], "source_tree": tree, "manifest_sha256": ADAPTER.sha(manifest_raw),
                         "runner_sha256": ADAPTER.sha(raw), "hostname": ADAPTER.platform.node(), "machine": ADAPTER.platform.machine(),
                         "source_before": source_evidence, "source_after": source_evidence, "compiler_resource_profile": resource,
                         "selected_groups": [row[0] for row in self.profile.GROUPS], "commands": []}
        commands = self.producer["commands"]
        for name in ("cargo", "rustc"):
            log = name + "-version.log"
            content = (name + " 1.98.0 (synthetic adapter fixture)\n").encode()
            (self.producer_dir / log).write_bytes(content)
            commands.append({"label": name + "-version", "status": "passed", "exit_code": 0, "argv": [build[name], "--version", "--verbose"], "log": log, "log_sha256": ADAPTER.sha(content)})
        compile_log = ("  Executable unittests src/lib.rs (" + str(self.artifact) + ")\n").encode()
        (self.producer_dir / "compile-server-tests.log").write_bytes(compile_log)
        commands.append({"label": "compile-server-tests", "status": "passed", "exit_code": 0,
                         "argv": [build["cargo"], "test", "--locked", "--offline", "-p", "heptabao-server", "--lib", "--features", ADAPTER.FEATURES, "--no-run"],
                         "log": "compile-server-tests.log", "log_sha256": ADAPTER.sha(compile_log)})
        for label, _owner, _selector, _count in self.profile.GROUPS:
            commands.extend({"label": label + suffix, "status": "passed"} for suffix in ("-list", ""))
        self.config = {"schema": ADAPTER.SCHEMA, "source": str(self.source), "source_commit": manifest["commit"], "source_tree": tree,
                       "manifest": str(manifest_path), "manifest_sha256": ADAPTER.sha(manifest_raw), "target_dir": str(self.target), "output": str(self.root / "output"),
                       "source_runner_sha256": ADAPTER.sha(raw), "owned_runner": str(HELPER), "owned_runner_sha256": ADAPTER.sha(HELPER.read_bytes()),
                       "producer_summary": str(self.producer_dir / "summary.json"), "libtest": str(self.artifact), "libtest_sha256": ADAPTER.sha(self.artifact.read_bytes()), "build_profile": build}
        self.refresh_producer()

    def refresh_producer(self):
        raw = encode(self.producer)
        Path(self.config["producer_summary"]).write_bytes(raw)
        self.config["producer_summary_sha256"] = ADAPTER.sha(raw)

    def run_adapter(self):
        raw = encode(self.config)
        path = self.root / "config.json"
        path.write_bytes(raw)
        return ADAPTER.main(["--config", str(path), "--config-sha256", ADAPTER.sha(raw)])

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_discovery_rejects_empty_wrong_duplicate_and_benchmark(self):
        name = ADAPTER.CASES[0][1]
        self.assertEqual(ADAPTER.listed_exact(name + ": test\n\n1 test, 0 benchmarks\n", name), [name])
        for text in ("0 tests, 0 benchmarks\n", "wrong: test\n1 test, 0 benchmarks\n", name + ": test\n" + name + ": test\n2 tests, 0 benchmarks\n", name + ": test\n1 test, 1 benchmark\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                ADAPTER.listed_exact(text, name)

    def test_execution_requires_exact_name_and_actual_single_terminal_result(self):
        name = ADAPTER.CASES[0][1]
        good = f"\nrunning 1 test\ntest {name} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.01s\n"
        self.assertEqual(ADAPTER.observed_result(good, name), {"status": "ok", "passed": 1, "failed": 0, "ignored": 0, "measured": 0})
        for text in (good.replace(name, "wrong"), good.replace("running 1 test", "running 0 tests"), good.replace("1 passed", "0 passed"), good + good):
            with self.subTest(text=text):
                self.assertIsNone(ADAPTER.observed_result(text, name))
        failed = good.replace("... ok", "... FAILED").replace("result: ok. 1 passed; 0 failed", "result: FAILED. 0 passed; 1 failed")
        self.assertEqual(ADAPTER.observed_result(failed, name)["failed"], 1)
        ignored = good.replace("... ok", "... ignored").replace("1 passed; 0 failed; 0 ignored", "0 passed; 0 failed; 1 ignored")
        self.assertEqual(ADAPTER.observed_result(ignored, name)["ignored"], 1)

    def test_producer_source_profile_and_completed_cohort_are_required(self):
        ADAPTER.load_context(self.config)
        variants = (("source_commit", "b" * 40), ("runner_completed", False), ("compiler_resource_profile", {"cargo_build_jobs": "8"}))
        for key, value in variants:
            original = self.producer[key]
            self.producer[key] = value
            self.refresh_producer()
            with self.subTest(key=key), self.assertRaises(ValueError):
                ADAPTER.load_context(self.config)
            self.producer[key] = original
        self.refresh_producer()
        row = ADAPTER.command_row(self.producer, "compile-server-tests")
        row["argv"] = row["argv"] + ["--no-default-features"]
        self.refresh_producer()
        with self.assertRaises(ValueError):
            ADAPTER.load_context(self.config)

    def test_changed_input_pin_and_multiple_artifact_paths_are_refused(self):
        old = self.config["owned_runner_sha256"]
        self.config["owned_runner_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            ADAPTER.load_context(self.config)
        self.config["owned_runner_sha256"] = old
        row = ADAPTER.command_row(self.producer, "compile-server-tests")
        path = self.producer_dir / row["log"]
        raw = path.read_bytes() * 2
        path.write_bytes(raw)
        row["log_sha256"] = ADAPTER.sha(raw)
        self.refresh_producer()
        with self.assertRaises(ValueError):
            ADAPTER.load_context(self.config)

    def test_changed_native_artifact_blocks_before_any_command(self):
        self.config["libtest_sha256"] = "0" * 64
        self.assertEqual(self.run_adapter(), 1)
        summary = json.loads((self.root / "output/summary.json").read_text())
        self.assertEqual(summary["commands"], [])
        self.assertEqual(summary["status"], "failed_or_blocked")
        self.assertFalse(summary["libtest_unchanged"])

    def test_busy_target_preserves_receipt_and_starts_no_commands(self):
        helper = ADAPTER.load_context(self.config)[5]
        receipt = {"owner": "synthetic existing host cohort"}
        lock = helper.acquire_target_lock(self.target, receipt)
        original = (self.target / helper.LOCK_NAME).read_bytes()
        try:
            self.assertEqual(self.run_adapter(), 1)
            summary = json.loads((self.root / "output/summary.json").read_text())
            self.assertFalse(summary["target_lock_acquired"])
            self.assertEqual(summary["commands"], [])
            self.assertEqual((self.target / helper.LOCK_NAME).read_bytes(), original)
        finally:
            lock.close()

    def test_reused_helper_reaps_one_actual_synthetic_python_child(self):
        helper = ADAPTER.load_context(self.config)[5]
        output = self.root / "owned-child-check"
        output.mkdir()
        records = []
        report = os.environ.get("HEPTABAO_HTTP3_CHECK_REPORT")
        def save():
            if report:
                helper.write_json(Path(report) / "owned-child-command.json", records)
        row = helper.run_logged("synthetic-python-child", [sys.executable, "-I", "-c", "print('synthetic owned child; no Rust test executed')"], self.root,
                                {"PATH": "/usr/bin:/bin"}, output, records, save, budget=15)
        if report:
            (Path(report) / "owned-child.log").write_bytes((output / row["log"]).read_bytes())
        self.assertEqual(row["status"], "passed")
        self.assertTrue(row["cleanup"]["leader_reaped"])
        self.assertTrue(row["cleanup"]["original_group_observed_without_live_members"])
        self.assertFalse(row["cleanup"]["unexpected_live_descendants_after_exit"])
        self.assertEqual(row["cleanup"]["signals"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
