#!/usr/bin/env python3
"""Validate classified P0 transport evidence and its exact-source binding."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Mapping

from classify_p0_transport_evidence_v1 import (
    BEST_EFFORT_SOURCE_BOUND,
    CLASS_BY_CASE,
    EXACT_HEAD_COMPILED_SOURCE_BOUND,
    EXPECTED_CASES,
    RUNTIME_OBSERVED,
    STATUS_BY_CLASS,
    FAILURE_STATUSES,
)


class EvidenceValidationError(RuntimeError):
    """Raised when classified evidence is incomplete or overclaims execution."""


SHA40 = re.compile(r"^[0-9a-f]{40}$")
FAILURE_EVIDENCE_RESULT = "FAIL_WITH_EXPLICIT_EVIDENCE_CLASSIFICATION"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceValidationError(message)


def _validate_raw_counts(report: Mapping[str, Any], statuses: list[Any]) -> None:
    """Bind the retained producer counts to the explicit case statuses."""

    raw_counts = report.get("raw_counts")
    require(isinstance(raw_counts, Mapping), "raw P0 producer counts are missing")
    expected = {
        "pass": statuses.count("PASS"),
        "fail": statuses.count("FAIL"),
        "blocked": statuses.count("BLOCKED"),
        "unexecuted": statuses.count("UNEXECUTED") + statuses.count("UNKNOWN"),
    }
    require(set(raw_counts) == set(expected), "raw P0 producer count fields drift")
    for key, value in raw_counts.items():
        require(
            type(value) is int and value >= 0,
            f"raw P0 producer count {key!r} must be a non-negative JSON integer",
        )
    require(dict(raw_counts) == expected, "raw P0 producer counts drift")


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceValidationError(f"duplicate JSON object member: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-standard JSON constant: {value}")


def strict_json(raw: str, label: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError, EvidenceValidationError) as error:
        raise EvidenceValidationError(f"{label} is not unambiguous JSON: {error}") from error


def validate(
    report: dict[str, Any],
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_repository: str | None = None,
) -> None:
    require(
        report.get("schema") == "heptabao.p0-transport-exact-result.v2",
        "classified schema drift",
    )
    require(report.get("result") == "PASS", "classified result must be PASS")
    require(
        report.get("evidence_result")
        == "PASS_WITH_EXPLICIT_EVIDENCE_CLASSIFICATION",
        "classified evidence result drift",
    )
    require(report.get("qualification") is False, "evidence cannot self-qualify")
    require(
        report.get("compatibility_claim") is False,
        "evidence cannot claim compatibility",
    )
    require(report.get("authority_effect") == "NONE", "authority effect drift")

    source = report.get("source")
    require(isinstance(source, dict), "source binding missing")
    require(source.get("repository") == "TrillionniumFoundation/HeptaBao", "source repository identity missing or drifted")
    for field in ("commit", "tree"):
        value = source.get(field)
        require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
                f"source {field} must be a lowercase 40-hex SHA")
    require(source.get("clean_tree") is True, "source checkout must be clean")
    if expected_commit is not None:
        require(source.get("commit") == expected_commit, "source commit binding drift")
    if expected_tree is not None:
        require(source.get("tree") == expected_tree, "source tree binding drift")
    if expected_repository is not None:
        require(
            source.get("repository") == expected_repository,
            "source repository binding drift",
        )

    cases = report.get("cases")
    require(isinstance(cases, list), "classified cases missing")
    by_id = {
        case.get("case_id"): case
        for case in cases
        if isinstance(case, dict) and isinstance(case.get("case_id"), str)
    }
    require(len(by_id) == len(cases), "classified case IDs are missing or duplicated")
    require(set(by_id) == EXPECTED_CASES, "classified case coverage drift")
    _validate_raw_counts(report, [case.get("status") for case in by_id.values()])
    for case_id, evidence_class in CLASS_BY_CASE.items():
        case = by_id[case_id]
        require(case.get("status") == "PASS", f"{case_id} bounded gate is not PASS")
        require(
            case.get("evidence_class") == evidence_class,
            f"{case_id} evidence class drift",
        )
        require(
            case.get("execution_status") == STATUS_BY_CLASS[evidence_class],
            f"{case_id} execution status overclaim",
        )

    counts = report.get("counts")
    require(
        counts
        == {
            "executed_pass": len(RUNTIME_OBSERVED),
            "source_bound_pass": len(EXACT_HEAD_COMPILED_SOURCE_BOUND),
            "best_effort_source_bound_pass": len(BEST_EFFORT_SOURCE_BOUND),
            "fail": 0,
            "blocked": 0,
            "unexecuted": 0,
            "total": len(EXPECTED_CASES),
        },
        "classified evidence counts drift",
    )
    require(counts["executed_pass"] == 11, "runtime pass count must be 11, not 14")

    model = report.get("evidence_model")
    require(isinstance(model, dict), "evidence model missing")
    require(
        model.get("runtime_observed_case_ids") == sorted(RUNTIME_OBSERVED),
        "runtime-observed set drift",
    )
    require(
        model.get("exact_head_compiled_source_bound_case_ids")
        == sorted(EXACT_HEAD_COMPILED_SOURCE_BOUND),
        "compiled source-bound set drift",
    )
    require(
        model.get("best_effort_source_bound_case_ids")
        == sorted(BEST_EFFORT_SOURCE_BOUND),
        "best-effort source-bound set drift",
    )
    require(
        model.get("source_presence_is_runtime_execution") is False,
        "source presence cannot be represented as runtime execution",
    )


def validate_failed(
    report: dict[str, Any],
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_repository: str | None = None,
) -> None:
    """Validate an explicit failed execution without converting it to PASS.

    The normal ``validate`` function intentionally accepts only a complete
    PASS artifact because completion receipts must never be emitted for a
    failed gate.  The workflow still needs a structural validator for the
    machine-readable failure artifact, however, so diagnostics cannot be
    silently lost when a process dies before the first probe.  This function
    validates that failure shape and is expected to be followed by a non-zero
    process exit.
    """

    require(
        report.get("schema") == "heptabao.p0-transport-exact-result.v2",
        "classified schema drift",
    )
    require(report.get("result") == "FAIL", "failed artifact result must be FAIL")
    require(
        report.get("evidence_result") == FAILURE_EVIDENCE_RESULT,
        "failed evidence result drift",
    )
    require(report.get("qualification") is False, "evidence cannot self-qualify")
    require(report.get("compatibility_claim") is False, "evidence cannot claim compatibility")
    require(report.get("authority_effect") == "NONE", "authority effect drift")
    reason = report.get("reason")
    require(isinstance(reason, str) and reason.strip(), "failed artifact reason is missing")

    source = report.get("source")
    require(isinstance(source, dict), "source binding missing")
    require(source.get("repository") == "TrillionniumFoundation/HeptaBao", "source repository identity drift")
    for field in ("commit", "tree"):
        value = source.get(field)
        require(
            isinstance(value, str) and SHA40.fullmatch(value) is not None,
            f"source {field} must be a lowercase 40-hex SHA",
        )
    require(type(source.get("clean_tree")) is bool, "source clean_tree flag is malformed")
    if expected_commit is not None:
        require(source.get("commit") == expected_commit, "source commit binding drift")
    if expected_tree is not None:
        require(source.get("tree") == expected_tree, "source tree binding drift")
    if expected_repository is not None:
        require(source.get("repository") == expected_repository, "source repository binding drift")

    cases = report.get("cases")
    require(isinstance(cases, list), "failed classified cases are missing")
    by_id: dict[str, dict[str, Any]] = {}
    for case in cases:
        require(isinstance(case, dict), "failed classified case is malformed")
        case_id = case.get("case_id")
        require(isinstance(case_id, str) and case_id in EXPECTED_CASES, "failed case ID is not canonical")
        require(case_id not in by_id, f"failed case ID is duplicated: {case_id}")
        by_id[case_id] = case
    require(set(by_id) == EXPECTED_CASES, "failed classified case coverage drift")
    statuses = [case.get("status") for case in by_id.values()]
    first_failure_seen = False
    for case_id in sorted(EXPECTED_CASES):
        status = by_id[case_id].get("status")
        require(isinstance(status, str), f"failed case {case_id} status is not a string")
        if status == "PASS":
            require(
                not first_failure_seen,
                "failed evidence contains a PASS after its failure boundary",
            )
        else:
            first_failure_seen = True
    _validate_raw_counts(report, statuses)
    # A failed run may retain cases that completed before the first failing
    # assertion.  Those PASS records are useful evidence and must remain
    # classed as the bounded runtime/source observation; only the remaining
    # cases use the explicit failure vocabulary.  Reject an all-PASS FAIL
    # artifact because it has no observable failure boundary.
    require(
        any(status in FAILURE_STATUSES for status in statuses),
        "failed evidence has no explicit failed/blocked/unexecuted case",
    )
    for case_id, evidence_class in CLASS_BY_CASE.items():
        case = by_id[case_id]
        status = case.get("status")
        require(isinstance(status, str), f"failed case {case_id} status is not a string")
        require(
            status == "PASS" or status in FAILURE_STATUSES,
            f"failed case {case_id} has an invalid status",
        )
        require(case.get("evidence_class") == evidence_class, f"failed case {case_id} class drift")
        expected_execution_status = (
            STATUS_BY_CLASS[evidence_class] if status == "PASS" else status
        )
        require(
            case.get("execution_status") == expected_execution_status,
            f"failed case {case_id} execution status drift",
        )

    counts = report.get("counts")
    require(isinstance(counts, dict), "failed evidence counts are missing")
    expected_counts = {
        "executed_pass": sum(
            case.get("status") == "PASS" and case_id in RUNTIME_OBSERVED
            for case_id, case in by_id.items()
        ),
        "source_bound_pass": sum(
            case.get("status") == "PASS" and case_id in EXACT_HEAD_COMPILED_SOURCE_BOUND
            for case_id, case in by_id.items()
        ),
        "best_effort_source_bound_pass": sum(
            case.get("status") == "PASS" and case_id in BEST_EFFORT_SOURCE_BOUND
            for case_id, case in by_id.items()
        ),
        "fail": sum(case.get("status") == "FAIL" for case in by_id.values()),
        "blocked": sum(case.get("status") == "BLOCKED" for case in by_id.values()),
        "unexecuted": sum(case.get("status") in {"UNEXECUTED", "UNKNOWN"} for case in by_id.values()),
        "total": len(EXPECTED_CASES),
    }
    # ``UNKNOWN`` is represented in the case status vocabulary but has no
    # dedicated count in the historical v2 shape; count it as unexecuted and
    # reject any other/omitted totals.
    require(counts == expected_counts, "failed evidence counts drift")
    require(
        counts["executed_pass"]
        + counts["source_bound_pass"]
        + counts["best_effort_source_bound_pass"]
        + counts["fail"]
        + counts["blocked"]
        + counts["unexecuted"]
        == len(EXPECTED_CASES),
        "failed evidence disposition counts do not cover every case",
    )

    model = report.get("evidence_model")
    require(isinstance(model, dict), "failed evidence model is missing")
    expected_classification = (
        "PARTIAL_EXECUTION_FAILURE"
        if any(status == "PASS" for status in statuses)
        else "EXECUTION_FAILED_BEFORE_COMPLETE_MATRIX"
    )
    require(
        model.get("classification") == expected_classification,
        "failed evidence classification drift",
    )
    expected_runtime_ids = sorted(
        case_id
        for case_id, case in by_id.items()
        if case.get("status") == "PASS" and case_id in RUNTIME_OBSERVED
    )
    expected_source_ids = sorted(
        case_id
        for case_id, case in by_id.items()
        if case.get("status") == "PASS" and case_id in EXACT_HEAD_COMPILED_SOURCE_BOUND
    )
    expected_best_effort_ids = sorted(
        case_id
        for case_id, case in by_id.items()
        if case.get("status") == "PASS" and case_id in BEST_EFFORT_SOURCE_BOUND
    )
    require(
        model.get("runtime_observed_case_ids") == expected_runtime_ids,
        "failed runtime-observed case model drift",
    )
    require(
        model.get("exact_head_compiled_source_bound_case_ids") == expected_source_ids,
        "failed source-bound case model drift",
    )
    require(
        model.get("best_effort_source_bound_case_ids") == expected_best_effort_ids,
        "failed best-effort case model drift",
    )
    require(
        model.get("runtime_transport_pass_count") == counts["executed_pass"],
        "failed runtime pass count drift",
    )
    require(
        model.get("source_bound_pass_count")
        == counts["source_bound_pass"] + counts["best_effort_source_bound_pass"],
        "failed source-bound pass count drift",
    )
    require(model.get("source_presence_is_runtime_execution") is False, "source presence overclaim")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-tree")
    parser.add_argument("--expected-repository")
    args = parser.parse_args()
    try:
        report = strict_json(args.input.read_text(encoding="utf-8"), "classified P0 input")
        require(isinstance(report, dict), "evidence must be one JSON object")
        if report.get("result") == "FAIL":
            validate_failed(
                report,
                expected_commit=args.expected_commit,
                expected_tree=args.expected_tree,
                expected_repository=args.expected_repository,
            )
            print("P0 classified failure artifact is structurally valid; gate remains FAIL")
            return 1
        validate(
            report,
            expected_commit=args.expected_commit,
            expected_tree=args.expected_tree,
            expected_repository=args.expected_repository,
        )
    except (OSError, json.JSONDecodeError, EvidenceValidationError) as error:
        print(f"P0 classified evidence validation FAILED: {error}")
        return 1
    print(
        "P0 classified evidence validation passed: executed=11 source-bound=2 "
        "best-effort-source-bound=1 qualification=false authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
