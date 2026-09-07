from __future__ import annotations

import copy
import importlib.util
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CLASSIFIER = load(
    "classify_p0_transport_evidence_v1",
    "scripts/classify_p0_transport_evidence_v1.py",
)
VALIDATOR = load(
    "validate_p0_transport_evidence_v2",
    "scripts/validate_p0_transport_evidence_v2.py",
)
RUNNER = load(
    "p0_transport_exact_v1",
    "scripts/p0_transport_exact_v1.py",
)


def raw_report() -> dict:
    return {
        "schema": "heptabao.p0-transport-exact-result.v1",
        "source": {
            "repository": "TrillionniumFoundation/HeptaBao",
            "commit": "a" * 40,
            "tree": "b" * 40,
            "clean_tree": True,
        },
        "result": "PASS",
        "counts": {"pass": 14, "fail": 0, "blocked": 0, "unexecuted": 0},
        "cases": [
            {"case_id": case_id, "status": "PASS", "evidence": {}}
            for case_id in sorted(CLASSIFIER.EXPECTED_CASES)
        ],
        "qualification": False,
        "compatibility_claim": False,
        "authority_effect": "NONE",
    }


class P0TransportEvidenceClassificationTests(unittest.TestCase):
    def test_complete_raw_result_is_classified_and_validated(self) -> None:
        result = CLASSIFIER.classify(raw_report())
        VALIDATOR.validate(
            result,
            expected_commit="a" * 40,
            expected_tree="b" * 40,
            expected_repository="TrillionniumFoundation/HeptaBao",
        )
        self.assertEqual(result["counts"]["executed_pass"], 11)
        self.assertEqual(result["counts"]["source_bound_pass"], 2)
        self.assertEqual(result["counts"]["best_effort_source_bound_pass"], 1)

    def test_historical_repository_name_is_rejected_for_current_execution(self) -> None:
        raw = raw_report()
        raw["source"]["repository"] = "ProfHepta/HeptaBao"
        with self.assertRaises(CLASSIFIER.ClassificationError):
            CLASSIFIER.classify(raw)

        result = CLASSIFIER.classify(raw_report())
        result["source"]["repository"] = "ProfHepta/HeptaBao"
        with self.assertRaises(VALIDATOR.EvidenceValidationError):
            VALIDATOR.validate(result)

    def test_source_bound_case_cannot_be_relabelled_as_runtime(self) -> None:
        result = CLASSIFIER.classify(raw_report())
        case = next(
            entry
            for entry in result["cases"]
            if entry["case_id"] == "P0-TRANSPORT-012"
        )
        case["evidence_class"] = "RUNTIME_SOCKET_OBSERVED"
        case["execution_status"] = "EXECUTED_PASS"
        with self.assertRaises(VALIDATOR.EvidenceValidationError):
            VALIDATOR.validate(result)

    def test_missing_case_fails_closed(self) -> None:
        raw = raw_report()
        raw["cases"] = raw["cases"][:-1]
        with self.assertRaises(CLASSIFIER.ClassificationError):
            CLASSIFIER.classify(raw)

    def test_authority_or_qualification_drift_fails_closed(self) -> None:
        result = CLASSIFIER.classify(raw_report())
        for field, value in (("qualification", True), ("authority_effect", "PRODUCTION")):
            mutated = copy.deepcopy(result)
            mutated[field] = value
            with self.assertRaises(VALIDATOR.EvidenceValidationError):
                VALIDATOR.validate(mutated)

    def test_runtime_count_cannot_be_inflated_to_fourteen(self) -> None:
        result = CLASSIFIER.classify(raw_report())
        result["counts"]["executed_pass"] = 14
        with self.assertRaises(VALIDATOR.EvidenceValidationError):
            VALIDATOR.validate(result)

    def test_source_tree_and_clean_checkout_are_required(self) -> None:
        raw = raw_report()
        raw["source"].pop("tree")
        with self.assertRaises(CLASSIFIER.ClassificationError):
            CLASSIFIER.classify(raw)
        result = CLASSIFIER.classify(raw_report())
        result["source"]["clean_tree"] = False
        with self.assertRaises(VALIDATOR.EvidenceValidationError):
            VALIDATOR.validate(result)

    def test_explicit_failed_execution_is_preserved_but_never_passes(self) -> None:
        raw = raw_report()
        raw["result"] = "FAIL"
        raw["reason"] = "listener did not start"
        raw["counts"] = {"pass": 0, "fail": 0, "blocked": 0, "unexecuted": 14}
        for case in raw["cases"]:
            case["status"] = "UNEXECUTED"
        result = CLASSIFIER.classify(raw)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["counts"]["unexecuted"], 14)
        VALIDATOR.validate_failed(
            result,
            expected_commit="a" * 40,
            expected_tree="b" * 40,
            expected_repository="TrillionniumFoundation/HeptaBao",
        )
        with self.assertRaises(VALIDATOR.EvidenceValidationError):
            VALIDATOR.validate(result)

    def test_partial_failed_execution_preserves_known_pass_prefix(self) -> None:
        raw = raw_report()
        raw["result"] = "FAIL"
        raw["reason"] = "P0-TRANSPORT-004 deadline assertion failed"
        for case in raw["cases"]:
            case_id = case["case_id"]
            if case_id in {"P0-TRANSPORT-001", "P0-TRANSPORT-002", "P0-TRANSPORT-003"}:
                case["status"] = "PASS"
            elif case_id == "P0-TRANSPORT-004":
                case["status"] = "FAIL"
            else:
                case["status"] = "UNEXECUTED"
        raw["counts"] = {"pass": 3, "fail": 1, "blocked": 0, "unexecuted": 10}

        result = CLASSIFIER.classify(raw)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(
            result["counts"],
            {
                "executed_pass": 3,
                "source_bound_pass": 0,
                "best_effort_source_bound_pass": 0,
                "fail": 1,
                "blocked": 0,
                "unexecuted": 10,
                "total": 14,
            },
        )
        self.assertEqual(
            result["evidence_model"]["runtime_observed_case_ids"],
            ["P0-TRANSPORT-001", "P0-TRANSPORT-002", "P0-TRANSPORT-003"],
        )
        self.assertEqual(
            result["evidence_model"]["classification"],
            "PARTIAL_EXECUTION_FAILURE",
        )
        VALIDATOR.validate_failed(
            result,
            expected_commit="a" * 40,
            expected_tree="b" * 40,
            expected_repository="TrillionniumFoundation/HeptaBao",
        )

        # A partial PASS label must retain its canonical class and execution
        # status; changing it to a generic source/runtime label is an
        # overclaim even on a failed artifact.
        mutated = copy.deepcopy(result)
        first = next(
            case for case in mutated["cases"] if case["case_id"] == "P0-TRANSPORT-001"
        )
        first["execution_status"] = "UNEXECUTED"
        with self.assertRaises(VALIDATOR.EvidenceValidationError):
            VALIDATOR.validate_failed(mutated)

    def test_failed_result_with_only_pass_cases_is_rejected(self) -> None:
        raw = raw_report()
        raw["result"] = "FAIL"
        raw["reason"] = "runner reported failure after matrix"
        raw["counts"] = {"pass": 14, "fail": 0, "blocked": 0, "unexecuted": 0}
        with self.assertRaises(CLASSIFIER.ClassificationError):
            CLASSIFIER.classify(raw)

    def test_failed_result_rejects_noncontiguous_pass_after_failure(self) -> None:
        raw = raw_report()
        raw["result"] = "FAIL"
        raw["reason"] = "probe failed"
        for case in raw["cases"]:
            case["status"] = "PASS" if case["case_id"] != "P0-TRANSPORT-004" else "FAIL"
        raw["counts"] = {"pass": 13, "fail": 1, "blocked": 0, "unexecuted": 0}
        with self.assertRaises(CLASSIFIER.ClassificationError):
            CLASSIFIER.classify(raw)

    def test_raw_producer_counts_are_bound_and_strictly_integer(self) -> None:
        result = CLASSIFIER.classify(raw_report())
        mutated = copy.deepcopy(result)
        mutated["raw_counts"]["pass"] = True
        with self.assertRaises(VALIDATOR.EvidenceValidationError):
            VALIDATOR.validate(mutated)
        mutated = CLASSIFIER.classify(raw_report())
        mutated["raw_counts"]["pass"] = 13
        with self.assertRaises(VALIDATOR.EvidenceValidationError):
            VALIDATOR.validate(mutated)

    def test_runner_startup_failure_is_unexecuted(self) -> None:
        previous = RUNNER._ACTIVE_RESULTS
        try:
            RUNNER._ACTIVE_RESULTS = None
            cases = RUNNER.failure_cases(ConnectionResetError("listener reset"))
        finally:
            RUNNER._ACTIVE_RESULTS = previous
        self.assertEqual(len(cases), 14)
        self.assertTrue(all(case["status"] == "UNEXECUTED" for case in cases))

    def test_runner_socket_failure_preserves_pass_prefix(self) -> None:
        previous = RUNNER._ACTIVE_RESULTS
        try:
            RUNNER._ACTIVE_RESULTS = [
                {
                    "case_id": case_id,
                    "status": "PASS",
                    "evidence": {},
                }
                for case_id in RUNNER.P0_CASE_ORDER[:3]
            ]
            cases = RUNNER.failure_cases(ConnectionResetError("peer reset"))
        finally:
            RUNNER._ACTIVE_RESULTS = previous
        self.assertEqual([case["status"] for case in cases[:4]], ["PASS", "PASS", "PASS", "FAIL"])
        self.assertTrue(cases[3]["evidence"]["executed_before_failure"])
        self.assertTrue(all(case["status"] == "UNEXECUTED" for case in cases[4:]))

    def test_runner_initialized_empty_matrix_marks_first_attempt_failed(self) -> None:
        previous = RUNNER._ACTIVE_RESULTS
        try:
            RUNNER._ACTIVE_RESULTS = []
            cases = RUNNER.failure_cases(ConnectionResetError("first probe reset"))
        finally:
            RUNNER._ACTIVE_RESULTS = previous
        self.assertEqual(cases[0]["status"], "FAIL")
        self.assertFalse(cases[0]["evidence"]["executed_before_failure"])
        self.assertTrue(all(case["status"] == "UNEXECUTED" for case in cases[1:]))


if __name__ == "__main__":
    unittest.main()
