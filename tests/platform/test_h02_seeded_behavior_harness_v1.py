from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "h02_seeded_behavior_harness_v1.py"
SPEC = importlib.util.spec_from_file_location("h02_seeded_behavior_harness_v1", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
harness = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = harness
SPEC.loader.exec_module(harness)

SOURCE_COMMIT = "1" * 40
SOURCE_TREE = "2" * 40
SEED = 0x5EED20260828CAFE


def evidence(domain: str, *, environment_id: str = "environment-one", runner_id: str | None = None, attested: bool = False):
    return harness.build_evidence(
        domain=domain,
        seed=SEED,
        source_commit=SOURCE_COMMIT,
        source_tree=SOURCE_TREE,
        branch="codex/h02-seeded-behavior-harnesses",
        clean_tree=True,
        environment_id=environment_id,
        executor_kind="offline-lab" if attested else "local-container",
        runner_id=runner_id,
        runner_name=runner_id,
        attested=attested,
    )


class SeededBehaviorHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema = json.loads((ROOT / "schemas" / "heptabao_h02_seeded_behavior_evidence_v1.schema.json").read_text(encoding="utf-8"))
        reproduction = json.loads((ROOT / "schemas" / "heptabao_h02_independent_reproduction_v1.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator.check_schema(reproduction)
        cls.evidence_validator = Draft202012Validator(schema, format_checker=FormatChecker())
        cls.reproduction_validator = Draft202012Validator(reproduction, format_checker=FormatChecker())

    def assert_schema_valid(self, value) -> None:
        errors = sorted(self.evidence_validator.iter_errors(value), key=lambda error: list(error.path))
        self.assertEqual([], [error.message for error in errors])

    def test_all_reference_domains_execute_and_replay(self) -> None:
        for domain in ("runtime", "tls", "raft"):
            value = evidence(domain)
            self.assertEqual("EXECUTED_PASS", value["status"])
            self.assertEqual(6, value["summary"]["passed"])
            self.assertEqual(0, value["summary"]["failed"])
            self.assertFalse(value["candidate"]["bound"])
            self.assertFalse(value["qualification"])
            self.assertEqual("NONE", value["selection_effect"])
            self.assertEqual("NONE", value["authority_effect"])
            self.assert_schema_valid(value)
            harness.replay(value)

    def test_same_seed_is_deterministic(self) -> None:
        for domain in ("runtime", "tls", "raft"):
            first = evidence(domain)
            second = evidence(domain)
            self.assertEqual(first["trace_sha256"], second["trace_sha256"])
            self.assertEqual(first["final_state_sha256"], second["final_state_sha256"])
            self.assertEqual(first["cases"], second["cases"])

    def test_different_seed_changes_trace(self) -> None:
        for domain in ("runtime", "tls", "raft"):
            first = evidence(domain)
            second = harness.build_evidence(
                domain=domain,
                seed=SEED + 1,
                source_commit=SOURCE_COMMIT,
                source_tree=SOURCE_TREE,
                branch="codex/h02-seeded-behavior-harnesses",
                clean_tree=True,
                environment_id="environment-two",
                executor_kind="local-container",
                runner_id=None,
                runner_name=None,
                attested=False,
            )
            self.assertNotEqual(first["trace_sha256"], second["trace_sha256"])

    def test_replay_rejects_tampered_trace(self) -> None:
        value = evidence("runtime")
        value["trace_sha256"] = "f" * 64
        with self.assertRaises(harness.Failure):
            harness.replay(value)

    def test_runtime_model_has_no_resource_leak(self) -> None:
        value = evidence("runtime")
        leak_case = next(case for case in value["cases"] if case["case_id"] == "runtime-zero-task-resource-leak")
        self.assertEqual("PASS", leak_case["status"])

    def test_tls_trace_contains_no_secret_markers(self) -> None:
        value = evidence("tls")
        serialized = json.dumps(value, sort_keys=True)
        self.assertNotIn("BEGIN PRIVATE KEY", serialized)
        self.assertNotIn("root_token", serialized.lower())

    def test_raft_quorum_loss_and_snapshot_conflict_pass(self) -> None:
        value = evidence("raft")
        by_id = {case["case_id"]: case["status"] for case in value["cases"]}
        self.assertEqual("PASS", by_id["raft-quorum-loss-fail-closed"])
        self.assertEqual("PASS", by_id["raft-committed-snapshot-conflict-rejected"])

    def test_schema_rejects_false_pass_with_unknown(self) -> None:
        value = evidence("runtime")
        value["summary"]["unknown"] = 1
        self.assertTrue(list(self.evidence_validator.iter_errors(value)))

    def test_schema_rejects_reference_model_candidate_binding(self) -> None:
        value = evidence("runtime")
        value["candidate"] = {
            "bound": True,
            "candidate_id": "HB-DEP-ASYNC-TOKIO",
            "version": "1.53.1",
            "feature_profile_sha256": "a" * 64,
        }
        self.assertTrue(list(self.evidence_validator.iter_errors(value)))

    def test_merge_requires_distinct_attested_environments(self) -> None:
        left = evidence("runtime", environment_id="offline-lab-a", runner_id="runner-a", attested=True)
        right = evidence("runtime", environment_id="offline-lab-a", runner_id="runner-b", attested=True)
        with self.assertRaises(harness.Failure):
            harness.merge(left, right)

        right = evidence("runtime", environment_id="offline-lab-b", runner_id="runner-a", attested=True)
        with self.assertRaises(harness.Failure):
            harness.merge(left, right)

        right = evidence("runtime", environment_id="offline-lab-b", runner_id="runner-b", attested=False)
        with self.assertRaises(harness.Failure):
            harness.merge(left, right)

    def test_merge_produces_non_authoritative_bundle(self) -> None:
        left = evidence("raft", environment_id="offline-lab-a", runner_id="runner-a", attested=True)
        right = evidence("raft", environment_id="offline-lab-b", runner_id="runner-b", attested=True)
        bundle = harness.merge(left, right)
        self.assertEqual("INDEPENDENTLY_REPRODUCED_UNREVIEWED", bundle["status"])
        self.assertFalse(bundle["qualification"])
        self.assertEqual("NONE", bundle["selection_effect"])
        self.assertEqual("NONE", bundle["authority_effect"])
        errors = sorted(self.reproduction_validator.iter_errors(bundle), key=lambda error: list(error.path))
        self.assertEqual([], [error.message for error in errors])

    def test_cli_run_and_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            result = harness.main([
                "run",
                "--domain", "runtime",
                "--seed", hex(SEED),
                "--source-commit", SOURCE_COMMIT,
                "--source-tree", SOURCE_TREE,
                "--branch", "codex/h02-seeded-behavior-harnesses",
                "--environment-id", "local-cli-environment",
                "--executor-kind", "local-container",
                "--output-dir", str(output),
            ])
            self.assertEqual(0, result)
            evidence_path = next(output.glob("runtime-*.json"))
            self.assertEqual(0, harness.main(["replay", "--evidence", str(evidence_path)]))


if __name__ == "__main__":
    unittest.main()
