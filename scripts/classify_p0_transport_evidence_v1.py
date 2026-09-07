#!/usr/bin/env python3
"""Classify exact-head P0 transport evidence without overstating runtime coverage."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

RUNTIME_OBSERVED = {
    "P0-TRANSPORT-001",
    "P0-TRANSPORT-002",
    "P0-TRANSPORT-003",
    "P0-TRANSPORT-004",
    "P0-TRANSPORT-005",
    "P0-TRANSPORT-006",
    "P0-TRANSPORT-007",
    "P0-TRANSPORT-008",
    "P0-TRANSPORT-009",
    "P0-TRANSPORT-010",
    "P0-TRANSPORT-013",
}
EXACT_HEAD_COMPILED_SOURCE_BOUND = {
    "P0-TRANSPORT-011",
    "P0-TRANSPORT-012",
}
BEST_EFFORT_SOURCE_BOUND = {"P0-TRANSPORT-014"}
EXPECTED_CASES = (
    RUNTIME_OBSERVED | EXACT_HEAD_COMPILED_SOURCE_BOUND | BEST_EFFORT_SOURCE_BOUND
)
P0_CASE_ORDER = tuple(f"P0-TRANSPORT-{index:03d}" for index in range(1, 15))

CLASS_BY_CASE = {
    **{case_id: "RUNTIME_SOCKET_OBSERVED" for case_id in RUNTIME_OBSERVED},
    **{
        case_id: "EXACT_HEAD_COMPILED_SOURCE_BOUND"
        for case_id in EXACT_HEAD_COMPILED_SOURCE_BOUND
    },
    **{
        case_id: "BEST_EFFORT_CONTROLLED_DROP_SOURCE_BOUND"
        for case_id in BEST_EFFORT_SOURCE_BOUND
    },
}
STATUS_BY_CLASS = {
    "RUNTIME_SOCKET_OBSERVED": "EXECUTED_PASS",
    "EXACT_HEAD_COMPILED_SOURCE_BOUND": "SOURCE_BOUND_PASS",
    "BEST_EFFORT_CONTROLLED_DROP_SOURCE_BOUND": "SOURCE_BOUND_BEST_EFFORT_PASS",
}
FAILURE_STATUSES = {"FAIL", "BLOCKED", "UNKNOWN", "UNEXECUTED"}
PASS_STATUS = "PASS"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class ClassificationError(RuntimeError):
    """Raised when raw evidence cannot be classified without ambiguity."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ClassificationError(message)


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ClassificationError(f"duplicate JSON object member: {key}")
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
    except (TypeError, ValueError, json.JSONDecodeError, ClassificationError) as error:
        raise ClassificationError(f"{label} is not unambiguous JSON: {error}") from error


def classify(report: dict[str, Any]) -> dict[str, Any]:
    require(
        report.get("schema") == "heptabao.p0-transport-exact-result.v1",
        "raw P0 transport schema drift",
    )
    result_status = report.get("result")
    require(isinstance(result_status, str), "raw P0 transport result is not a string")
    require(result_status in {"PASS", "FAIL"}, "raw P0 transport result is malformed")
    require(report.get("qualification") is False, "raw result cannot self-qualify")
    require(
        report.get("compatibility_claim") is False,
        "raw result cannot claim compatibility",
    )
    require(report.get("authority_effect") == "NONE", "raw authority effect drift")

    source = report.get("source")
    require(isinstance(source, dict), "raw P0 source binding missing")
    require(source.get("repository") == "TrillionniumFoundation/HeptaBao", "raw P0 repository identity drift")
    for field in ("commit", "tree"):
        value = source.get(field)
        require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
                f"raw P0 source {field} is malformed")
    # A successful matrix must be bound to a clean checkout.  On an explicit
    # FAIL report the runner may have failed before it could establish (or
    # retain) a clean-tree observation; preserve that fact as failure evidence
    # instead of turning it into an implicit PASS or dropping the artifact.
    require(
        type(source.get("clean_tree")) is bool,
        "raw P0 source clean_tree flag is malformed",
    )
    if result_status == "PASS":
        require(source.get("clean_tree") is True, "raw P0 source tree must be clean")

    cases = report.get("cases")
    require(isinstance(cases, list), "raw P0 transport cases missing")
    case_ids = [case.get("case_id") for case in cases if isinstance(case, dict)]
    require(len(case_ids) == len(cases), "every raw case must be a mapping with case_id")
    require(
        all(isinstance(case_id, str) for case_id in case_ids),
        "every raw P0 case_id must be a string",
    )
    require(len(case_ids) == len(set(case_ids)), "raw P0 transport case IDs are duplicated")
    require(set(case_ids) == EXPECTED_CASES, "raw P0 transport case coverage drift")
    by_case_id = {case["case_id"]: case for case in cases}

    classified_cases: list[dict[str, Any]] = []
    for raw_case in cases:
        case = dict(raw_case)
        case_id = case["case_id"]
        status = case.get("status")
        if result_status == "PASS":
            require(status == PASS_STATUS, f"{case_id} did not pass its bounded gate")
        else:
            # A failed run may have completed a strict prefix before a later
            # assertion failed.  Preserve those known PASS observations while
            # requiring every remaining case to carry an explicit failure
            # disposition; silently converting a known pass to UNEXECUTED
            # loses useful evidence, while treating an omitted case as PASS
            # would be fail-open.
            require(isinstance(status, str), f"{case_id} status is not a string")
            require(
                status == PASS_STATUS or status in FAILURE_STATUSES,
                f"{case_id} has an unknown failure status",
            )
        evidence_class = CLASS_BY_CASE[case_id]
        case["evidence_class"] = evidence_class
        case["execution_status"] = (
            STATUS_BY_CLASS[evidence_class] if status == PASS_STATUS else status
        )
        classified_cases.append(case)

    statuses = [case.get("status") for case in classified_cases]
    ordered_statuses = [by_case_id[case_id].get("status") for case_id in P0_CASE_ORDER]
    if result_status == "FAIL":
        first_failure_seen = False
        for status in ordered_statuses:
            if status == PASS_STATUS:
                require(
                    not first_failure_seen,
                    "failed raw P0 result contains a PASS after its failure boundary",
                )
            else:
                first_failure_seen = True
    if result_status == "FAIL":
        # A FAIL object with fourteen PASS cases is ambiguous and could be
        # mistaken for a completion receipt by a permissive consumer.  Require
        # at least one explicit non-PASS disposition; all such objects remain
        # non-authoritative and the workflow still exits non-zero.
        require(
            any(status in FAILURE_STATUSES for status in statuses),
            "failed raw P0 result has no explicit failed/blocked/unexecuted case",
        )
    raw_counts = report.get("counts")
    require(isinstance(raw_counts, dict), "raw P0 counts must be an object")
    expected_raw_counts = {
        "pass": statuses.count(PASS_STATUS),
        "fail": statuses.count("FAIL"),
        "blocked": statuses.count("BLOCKED"),
        "unexecuted": statuses.count("UNEXECUTED") + statuses.count("UNKNOWN"),
    }
    for key, value in raw_counts.items():
        require(
            type(value) is int and value >= 0,
            f"raw P0 count {key!r} must be a non-negative JSON integer",
        )
    require(
        raw_counts == expected_raw_counts,
        "raw P0 counts do not match case dispositions",
    )

    result = dict(report)
    result["schema"] = "heptabao.p0-transport-exact-result.v2"
    result["cases"] = classified_cases
    result["raw_counts"] = report.get("counts")
    if result_status == "PASS":
        counts = {
            "executed_pass": len(RUNTIME_OBSERVED),
            "source_bound_pass": len(EXACT_HEAD_COMPILED_SOURCE_BOUND),
            "best_effort_source_bound_pass": len(BEST_EFFORT_SOURCE_BOUND),
            "fail": 0,
            "blocked": 0,
            "unexecuted": 0,
            "total": len(EXPECTED_CASES),
        }
    else:
        counts = {
            "executed_pass": sum(
                status == PASS_STATUS and case["case_id"] in RUNTIME_OBSERVED
                for status, case in zip(statuses, classified_cases)
            ),
            "source_bound_pass": sum(
                status == PASS_STATUS and case["case_id"] in EXACT_HEAD_COMPILED_SOURCE_BOUND
                for status, case in zip(statuses, classified_cases)
            ),
            "best_effort_source_bound_pass": sum(
                status == PASS_STATUS and case["case_id"] in BEST_EFFORT_SOURCE_BOUND
                for status, case in zip(statuses, classified_cases)
            ),
            "fail": statuses.count("FAIL"),
            "blocked": statuses.count("BLOCKED"),
            # The v2 count shape predates an explicit ``unknown`` bucket;
            # preserve that conservative status inside ``unexecuted`` rather
            # than allowing it to disappear from the total.
            "unexecuted": statuses.count("UNEXECUTED") + statuses.count("UNKNOWN"),
            "total": len(EXPECTED_CASES),
        }
        require(
            counts["executed_pass"]
            + counts["source_bound_pass"]
            + counts["best_effort_source_bound_pass"]
            + counts["fail"]
            + counts["blocked"]
            + counts["unexecuted"]
            == len(EXPECTED_CASES),
            "failed raw P0 result contains unsupported case statuses",
        )
        result["reason"] = str(report.get("reason") or "P0 transport execution failed")
    result["evidence_model"] = {
        "classification": (
            "MIXED_RUNTIME_AND_EXACT_HEAD_SOURCE_BOUND"
            if result_status == "PASS"
            else (
                "PARTIAL_EXECUTION_FAILURE"
                if any(status == PASS_STATUS for status in statuses)
                else "EXECUTION_FAILED_BEFORE_COMPLETE_MATRIX"
            )
        ),
        # Keep only the class partitions that were actually observed before a
        # failure.  This makes a partial/failed run machine-readable without
        # allowing it to satisfy the PASS contract.
        "runtime_observed_case_ids": sorted(
            case["case_id"]
            for case in classified_cases
            if case.get("status") == PASS_STATUS and case["case_id"] in RUNTIME_OBSERVED
        ),
        "exact_head_compiled_source_bound_case_ids": sorted(
            case["case_id"]
            for case in classified_cases
            if case.get("status") == PASS_STATUS
            and case["case_id"] in EXACT_HEAD_COMPILED_SOURCE_BOUND
        ),
        "best_effort_source_bound_case_ids": sorted(
            case["case_id"]
            for case in classified_cases
            if case.get("status") == PASS_STATUS and case["case_id"] in BEST_EFFORT_SOURCE_BOUND
        ),
        "runtime_transport_pass_count": counts["executed_pass"],
        "source_bound_pass_count": counts["source_bound_pass"]
        + counts["best_effort_source_bound_pass"],
        "source_presence_is_runtime_execution": False,
    }
    result["result"] = result_status
    result["evidence_result"] = (
        "PASS_WITH_EXPLICIT_EVIDENCE_CLASSIFICATION"
        if result_status == "PASS"
        else "FAIL_WITH_EXPLICIT_EVIDENCE_CLASSIFICATION"
    )
    result["counts"] = counts
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        raw = strict_json(args.input.read_text(encoding="utf-8"), "raw P0 input")
        require(isinstance(raw, dict), "raw result must be one JSON object")
        result = classify(raw)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, json.JSONDecodeError, ClassificationError) as error:
        print(f"P0 transport evidence classification FAILED: {error}")
        return 1
    if result.get("result") == "PASS":
        print(
            "P0 transport evidence classified: runtime=11 source-bound=2 "
            "best-effort-source-bound=1 authority=NONE"
        )
    else:
        print(
            "P0 transport evidence classified: result=FAIL "
            "complete matrix was not established authority=NONE"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
