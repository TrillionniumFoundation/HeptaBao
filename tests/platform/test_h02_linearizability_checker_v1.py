from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "h02_linearizability_checker_v1.py"
SPEC = importlib.util.spec_from_file_location("h02_linearizability_checker_v1", MODULE_PATH)
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def op(op_id, kind, invoke, complete, *, input_value=None, output_value=None, status="ok", client="client-a"):
    return {
        "id": op_id,
        "client": client,
        "kind": kind,
        "invoke": invoke,
        "complete": complete,
        "input": input_value,
        "output": output_value,
        "status": status,
        "node_id": 1,
        "error": None,
    }


def history(operations):
    return {
        "schema": checker.HISTORY_SCHEMA,
        "model": "single-register-v1",
        "candidate_id": checker.EXPECTED_CANDIDATE,
        "version": checker.EXPECTED_VERSION,
        "profile_id": checker.EXPECTED_PROFILE,
        "seed": "0x5eed20260828cafe",
        "initial_value": None,
        "operations": operations,
        "execution_scope": "REAL_OPENRAFT_READINDEX_SINGLE_REGISTER_HISTORY",
        "durability_class": "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
        "qualification": False,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
        "metadata": {"source": "unit-test"},
    }


class LinearizabilityCheckerTests(unittest.TestCase):
    def test_sequential_write_then_read_passes(self):
        value = history([op("w1", "write", 1, 2, input_value="A"), op("r1", "read", 3, 4, output_value="A")])
        result = checker.evaluate(value)
        self.assertEqual("EXECUTED_PASS", result["status"])
        self.assertTrue(result["linearizable"])
        self.assertEqual(["w1", "r1"], result["witness_order"])

    def test_overlapping_read_can_linearize_before_writes(self):
        value = history([
            op("w1", "write", 1, 6, input_value="A"),
            op("w2", "write", 2, 7, input_value="B", client="client-b"),
            op("r1", "read", 3, 5, output_value=None, client="reader"),
        ])
        result = checker.evaluate(value)
        self.assertEqual("EXECUTED_PASS", result["status"])
        self.assertEqual("r1", result["witness_order"][0])

    def test_read_after_completed_write_returning_old_value_fails(self):
        value = history([op("w1", "write", 1, 2, input_value="A"), op("r1", "read", 3, 4, output_value=None)])
        result = checker.evaluate(value)
        self.assertEqual("EXECUTED_FAIL", result["status"])
        self.assertFalse(result["linearizable"])

    def test_real_time_order_between_two_writes_is_enforced(self):
        value = history([
            op("w1", "write", 1, 2, input_value="A"),
            op("w2", "write", 3, 4, input_value="B"),
            op("r1", "read", 5, 6, output_value="A"),
        ])
        self.assertEqual("EXECUTED_FAIL", checker.evaluate(value)["status"])

    def test_write_previous_value_output_is_checked(self):
        passing = history([
            op("w1", "write", 1, 2, input_value="A", output_value=None),
            op("w2", "write", 3, 4, input_value="B", output_value="A"),
            op("r1", "read", 5, 6, output_value="B"),
        ])
        failing = deepcopy(passing)
        failing["operations"][1]["output"] = "wrong"
        self.assertEqual("EXECUTED_PASS", checker.evaluate(passing)["status"])
        self.assertEqual("EXECUTED_FAIL", checker.evaluate(failing)["status"])

    def test_duplicate_operation_id_blocks(self):
        value = history([op("same", "write", 1, 2, input_value="A"), op("same", "read", 3, 4, output_value="A")])
        result = checker.evaluate(value)
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("duplicate operation id", result["reason"])

    def test_invalid_interval_blocks(self):
        result = checker.evaluate(history([op("w1", "write", 2, 2, input_value="A")]))
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("invoke < complete", result["reason"])

    def test_unknown_operation_kind_blocks(self):
        result = checker.evaluate(history([op("x", "compare-and-swap", 1, 2, input_value="A")]))
        self.assertEqual("BLOCKED", result["status"])

    def test_failed_operation_blocks_instead_of_being_dropped(self):
        result = checker.evaluate(history([op("w1", "write", 1, 2, input_value="A", status="failed")]))
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("failed/unknown operations block", result["reason"])

    def test_too_many_operations_blocks(self):
        operations = [op(f"w{index}", "write", index * 2 + 1, index * 2 + 2, input_value=str(index)) for index in range(checker.MAX_OPERATIONS + 1)]
        result = checker.evaluate(history(operations))
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("exceed maximum", result["reason"])

    def test_forged_authority_fields_block(self):
        value = history([op("w1", "write", 1, 2, input_value="A")])
        value["qualification"] = True
        result = checker.evaluate(value)
        self.assertEqual("BLOCKED", result["status"])
        self.assertFalse(result["qualification"])
        self.assertEqual("NONE", result["authority_effect"])

    def test_digest_is_canonical_and_stable(self):
        value = history([op("w1", "write", 1, 2, input_value="A")])
        reordered = json.loads(json.dumps(value, sort_keys=True))
        self.assertEqual(checker.canonical_sha256(value), checker.canonical_sha256(reordered))

    def test_cli_writes_fail_closed_result_and_exit_code(self):
        value = history([op("w1", "write", 1, 2, input_value="A"), op("r1", "read", 3, 4, output_value=None)])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            history_path = root / "history.json"
            result_path = root / "result.json"
            history_path.write_text(json.dumps(value), encoding="utf-8")
            code = checker.main(["check", "--history", str(history_path), "--output", str(result_path)])
            result = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(1, code)
        self.assertEqual("EXECUTED_FAIL", result["status"])
        self.assertFalse(result["qualification"])
        self.assertEqual("NONE", result["selection_effect"])
        self.assertEqual("NONE", result["authority_effect"])


if __name__ == "__main__":
    unittest.main()
