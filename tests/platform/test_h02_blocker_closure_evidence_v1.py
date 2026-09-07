from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "h02_blocker_closure_evidence_v1",
    ROOT / "scripts/h02_blocker_closure_evidence_v1.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SCHEMA = json.loads(
    (ROOT / "schemas/heptabao_h02_blocker_closure_evidence_v1.schema.json").read_text(
        encoding="utf-8"
    )
)
RESULT_SCHEMA = json.loads(
    (ROOT / "schemas/heptabao_h02_blocker_closure_result_v1.schema.json").read_text(
        encoding="utf-8"
    )
)
REGISTRY = Registry().with_resource(
    RESULT_SCHEMA["$id"], Resource.from_contents(RESULT_SCHEMA)
)
VALIDATOR = Draft202012Validator(SCHEMA, registry=REGISTRY)


def component() -> dict:
    return {
        "status": "EXECUTED_PASS",
        "qualification": False,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
    }


def valid_result() -> dict:
    return {
        "schema": "heptabao.h02-blocker-closure-result.v1",
        "candidate_id": "HB-DEP-RAFT-OPENRAFT",
        "version": "0.10.0-alpha.33",
        "seed": "0x5eed20260828cafe",
        "status": "EXECUTED_PASS",
        "components": {
            "os_suspend": component(),
            "durable_faults": component(),
            "clock_faults": component(),
        },
        "scope": {
            "os_process_suspend_executed": True,
            "heptabao_file_wal_faults_executed": True,
            "openraft_real_writes_and_readindex_under_wall_projection": True,
            "openraft_durable_store_integrated": False,
            "per_node_kernel_clock_skew": False,
            "independent_external_approvals": False,
        },
        "promotion_effect": MODULE.PROMOTION_EFFECT,
        "qualification": False,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
    }


class BlockerClosureEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.manifest = self.root / "Cargo.toml"
        self.lock = self.root / "Cargo.lock"
        self.manifest.write_text("[package]\nname='probe'\nversion='0.0.0'\n", encoding="utf-8")
        self.lock.write_text("version = 4\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def build(self, result: dict, *, exit_code: int = 0, clean_tree: bool = True) -> dict:
        return MODULE.build_evidence(
            result=result,
            execution_exit_code=exit_code,
            seed="0x5eed20260828cafe",
            toolchain="1.88.0",
            manifest=self.manifest,
            cargo_lock=self.lock,
            source_commit="a" * 40,
            source_tree="b" * 40,
            branch="codex/test",
            clean_tree=clean_tree,
            environment_id="test-environment",
            executor_kind="local-unattested",
            runner_id="test-runner-id",
            runner_name="test-runner",
        )

    def test_01_complete_result_is_technical_pass_without_authority(self) -> None:
        evidence = self.build(valid_result())
        self.assertEqual("EXECUTED_PASS", evidence["status"])
        self.assertFalse(evidence["qualification"])
        self.assertEqual("NONE", evidence["selection_effect"])
        self.assertEqual("NONE", evidence["authority_effect"])
        self.assertEqual("PENDING", evidence["review_status"])

    def test_02_nonzero_execution_is_blocked(self) -> None:
        self.assertEqual("BLOCKED", self.build(valid_result(), exit_code=9)["status"])

    def test_03_dirty_source_is_blocked(self) -> None:
        self.assertEqual("BLOCKED", self.build(valid_result(), clean_tree=False)["status"])

    def test_04_missing_component_is_blocked(self) -> None:
        result = valid_result()
        del result["components"]["clock_faults"]
        self.assertEqual("BLOCKED", self.build(result)["status"])

    def test_05_nested_authority_drift_is_blocked(self) -> None:
        result = valid_result()
        result["components"]["os_suspend"]["authority_effect"] = "GRANTED"
        self.assertEqual("BLOCKED", self.build(result)["status"])

    def test_06_raw_qualification_drift_is_blocked(self) -> None:
        result = valid_result()
        result["qualification"] = True
        self.assertEqual("BLOCKED", self.build(result)["status"])

    def test_07_explicit_executed_failure_remains_failure(self) -> None:
        result = valid_result()
        result["status"] = "EXECUTED_FAIL"
        result["components"]["durable_faults"]["status"] = "EXECUTED_FAIL"
        self.assertEqual("EXECUTED_FAIL", self.build(result)["status"])

    def test_08_result_digest_changes_with_result(self) -> None:
        first = self.build(valid_result())["result_sha256"]
        changed = valid_result()
        changed["seed"] = "0x8badf00d12345678"
        second = self.build(changed)["result_sha256"]
        self.assertNotEqual(first, second)

    def test_09_unclosed_external_gaps_stay_explicit(self) -> None:
        gaps = self.build(valid_result())["remaining_external_gaps"]
        self.assertTrue(gaps["openraft_durable_store_integration"])
        self.assertTrue(gaps["per_node_kernel_clock_skew"])
        self.assertTrue(gaps["second_independent_attested_environment"])
        self.assertTrue(gaps["independent_approvals"])
        self.assertTrue(gaps["signed_selection_receipt"])

    def test_10_serialized_json_round_trip(self) -> None:
        evidence = self.build(valid_result())
        self.assertEqual(evidence, json.loads(json.dumps(evidence)))

    def test_11_schema_accepts_effective_floor_and_rejects_boundary_floor(self) -> None:
        evidence = self.build(valid_result())
        errors = list(VALIDATOR.iter_errors(evidence))
        self.assertEqual([], [error.message for error in errors])
        evidence["execution"]["toolchain"] = "1.85.0"
        self.assertTrue(list(VALIDATOR.iter_errors(evidence)))


if __name__ == "__main__":
    unittest.main()
