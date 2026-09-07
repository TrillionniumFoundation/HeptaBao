from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = load_module("h02_openraft_fault_lab_evidence_v1", "scripts/h02_openraft_fault_lab_evidence_v1.py")
checker = load_module("h02_linearizability_checker_v1", "scripts/h02_linearizability_checker_v1.py")


def history_value(seed: str = "0x5eed20260828cafe"):
    return {
        "schema": checker.HISTORY_SCHEMA,
        "model": "single-register-v1",
        "candidate_id": checker.EXPECTED_CANDIDATE,
        "version": checker.EXPECTED_VERSION,
        "profile_id": checker.EXPECTED_PROFILE,
        "seed": seed,
        "initial_value": None,
        "operations": [
            {"id": "w1", "client": "writer", "kind": "write", "invoke": 1, "complete": 2, "input": "A", "output": None, "status": "ok", "node_id": 1, "error": None},
            {"id": "r1", "client": "reader", "kind": "read", "invoke": 3, "complete": 4, "input": None, "output": "A", "status": "ok", "node_id": 1, "error": None},
        ],
        "execution_scope": "REAL_OPENRAFT_READINDEX_SINGLE_REGISTER_HISTORY",
        "durability_class": "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
        "qualification": False,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
        "metadata": {"test": True},
    }


def hostile_value(status: str = "EXECUTED_PASS", seed: str = "0x5eed20260828cafe"):
    return {
        "schema": collector.HOSTILE_SCHEMA,
        "candidate_id": collector.EXPECTED_CANDIDATE,
        "version": collector.EXPECTED_VERSION,
        "profile_id": collector.EXPECTED_PROFILE,
        "seed": seed,
        "status": status,
        "phase_reached": status != "BLOCKED",
        "outcome": {
            "EXECUTED_PASS": "REJECTED_OR_ABORTED_AFTER_INJECTION",
            "EXECUTED_FAIL": "ACCEPTED",
            "BLOCKED": "SETUP_OR_EXECUTION_BLOCKED",
        }[status],
        "child_exit_code": 0 if status != "BLOCKED" else 2,
        "execution_scope": "ISOLATED_CHILD_REAL_OPENRAFT_STALE_COMMITTED_SNAPSHOT_INJECTION",
        "durability_class": "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
        "qualification": False,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
    }


class CollectorHarness:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.seed = "0x5eed20260828cafe"
        self.manifest = self.root / "Cargo.toml"
        self.lock = self.root / "Cargo.lock"
        self.manifest.write_text("[package]\nname='x'\n", encoding="utf-8")
        self.lock.write_text("# lock\n", encoding="utf-8")

    def close(self):
        self.temp.cleanup()

    def collect(self, *, hostile=None, history=None, linear=None, build_exit=0, hostile_exit=0, history_exit=0, checker_exit=0, clean_tree=True, lock_path=None):
        hostile = hostile if hostile is not None else hostile_value(seed=self.seed)
        history = history if history is not None else history_value(seed=self.seed)
        linear = linear if linear is not None else checker.evaluate(history)

        hostile_path = self.root / "hostile.json"
        history_path = self.root / "history.json"
        linear_path = self.root / "linear.json"
        hostile_path.write_text(json.dumps(hostile), encoding="utf-8")
        history_path.write_text(json.dumps(history), encoding="utf-8")
        linear_path.write_text(json.dumps(linear), encoding="utf-8")

        args = argparse.Namespace(
            hostile_result=hostile_path,
            history=history_path,
            linearizability_result=linear_path,
            build_exit_code=build_exit,
            hostile_exit_code=hostile_exit,
            history_exit_code=history_exit,
            checker_exit_code=checker_exit,
            seed=self.seed,
            toolchain="1.85.0",
            target="x86_64-unknown-linux-gnu",
            manifest=self.manifest,
            cargo_lock=lock_path if lock_path is not None else self.lock,
            repository="ProfHepta/HeptaBao",
            source_commit="a" * 40,
            source_tree="b" * 40,
            branch="codex/test",
            clean_tree=clean_tree,
            environment_id="unit-test",
            executor_kind="local-unattested",
            runner_id="unit-test",
            runner_name="unit-test",
            output=self.root / "out.json",
        )
        return collector.collect(args)


class FaultLabEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.harness = CollectorHarness()

    def tearDown(self):
        self.harness.close()

    def test_pass_requires_both_components(self):
        result = self.harness.collect()
        self.assertEqual("EXECUTED_PASS", result["status"])
        self.assertTrue(result["results"]["linearizability"]["linearizable"])
        self.assertEqual("NONE", result["authority_effect"])
        self.assertFalse(result["qualification"])

    def test_hostile_acceptance_is_executed_failure(self):
        result = self.harness.collect(hostile=hostile_value("EXECUTED_FAIL"))
        self.assertEqual("EXECUTED_FAIL", result["status"])
        self.assertIn("safety", result["reason"])

    def test_non_linearizable_history_is_executed_failure(self):
        history = history_value()
        history["operations"][1]["output"] = None
        linear = checker.evaluate(history)
        result = self.harness.collect(history=history, linear=linear, checker_exit=1)
        self.assertEqual("EXECUTED_FAIL", result["status"])

    def test_checker_exit_mismatch_blocks(self):
        result = self.harness.collect(checker_exit=1)
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("exit-code mismatch", result["reason"])

    def test_history_digest_mismatch_blocks(self):
        history = history_value()
        linear = checker.evaluate(history)
        linear["history_sha256"] = "0" * 64
        result = self.harness.collect(history=history, linear=linear)
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("not bound", result["reason"])

    def test_forged_authority_blocks_and_output_remains_closed(self):
        hostile = hostile_value()
        hostile["qualification"] = True
        result = self.harness.collect(hostile=hostile)
        self.assertEqual("BLOCKED", result["status"])
        self.assertFalse(result["qualification"])
        self.assertEqual("NONE", result["selection_effect"])
        self.assertEqual("NONE", result["authority_effect"])

    def test_dirty_tree_blocks(self):
        result = self.harness.collect(clean_tree=False)
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("not clean", result["reason"])

    def test_seed_mismatch_blocks(self):
        result = self.harness.collect(hostile=hostile_value(seed="0x8badf00d12345678"))
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("seed mismatch", result["reason"])

    def test_missing_lock_blocks(self):
        result = self.harness.collect(lock_path=self.harness.root / "missing.lock")
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("Cargo.lock", result["reason"])

    def test_rust_build_failure_blocks(self):
        result = self.harness.collect(build_exit=101)
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("build/test", result["reason"])

    def test_history_generator_failure_blocks(self):
        result = self.harness.collect(history_exit=101)
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("generator", result["reason"])

    def test_blocked_hostile_component_blocks(self):
        result = self.harness.collect(hostile=hostile_value("BLOCKED"), hostile_exit=2)
        self.assertEqual("BLOCKED", result["status"])

    def test_unknown_hostile_status_blocks(self):
        hostile = hostile_value()
        hostile["status"] = "PASSISH"
        result = self.harness.collect(hostile=hostile)
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("unknown hostile", result["reason"])

    def test_artifact_digests_are_present_on_pass(self):
        result = self.harness.collect()
        self.assertRegex(result["artifacts"]["manifest_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["artifacts"]["cargo_lock_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
