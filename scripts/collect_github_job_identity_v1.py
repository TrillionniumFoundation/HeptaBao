#!/usr/bin/env python3
"""Collect and validate the numeric identity of the current GitHub job.

The Actions runner exposes a logical ``GITHUB_JOB`` name, but not the numeric
job/runner IDs or the provider's step table.  This small collector consumes the
read-only Actions REST response captured by the workflow, selects exactly one
matrix job, and emits a normalized identity artifact.  It deliberately fails
closed when the API response is unavailable, stale, queued, runner-less or
ambiguous.  No qualification or authority claim is made here.

The collector also emits a digest-only manifest of the local evidence/log files
already written by the workflow.  File contents remain in the ordinary
pre-gate artifact; the manifest gives the technical receipt a stable binding
without copying potentially sensitive log text into the receipt itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

SCHEMA_ID = "heptabao.github-actions-job-identity.v1"
LOG_MANIFEST_SCHEMA_ID = "heptabao.github-actions-log-manifest.v1"
REPOSITORY = "TrillionniumFoundation/HeptaBao"
WORKFLOW_NAME = "plan-v1.3.1-head-and-merge-closure"
JOB_NAME = "full-technical-matrix"
CANONICAL_RUNNER_LABEL = "ubuntu-24.04"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
NON_NEGATIVE_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")

# These are the steps that must have completed successfully before this
# collector runs.  The collector step itself is intentionally excluded because
# the API reports the current job as ``in_progress`` while this command runs;
# receipt emission and upload steps occur after the snapshot.
CANONICAL_REQUIRED_STEP_NAMES = (
    "Set up job",
    "Checkout exact head or GitHub synthetic merge",
    "Bind source, ancestry and ordinary owner ratification",
    "Install exact Python dependencies",
    "Validate Gate A inherited contracts and Python regression",
    "Resolve active canonical project state from exact source",
    "Install exact Rust toolchains",
    "Format, test and strictly lint root workspace",
    "Execute and classify P0 socket and audit evidence",
    "Compile, lint and execute all H02 entries without early evidence loss",
    "Upload complete diagnostics before final H02 gate",
    "Require complete H02 24-entry PASS",
)

STEP_STATUSES = {"queued", "in_progress", "completed"}
PROVIDER_STEP_STATUSES = STEP_STATUSES | {"pending"}
STEP_CONCLUSIONS = {
    "success",
    "failure",
    "cancelled",
    "skipped",
    "neutral",
    "timed_out",
    "action_required",
}
JOB_STATUSES = {"queued", "in_progress", "completed"}
JOB_CONCLUSIONS = STEP_CONCLUSIONS


class CollectionError(RuntimeError):
    """Raised when the provider response cannot support an exact identity."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CollectionError(message)


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CollectionError(f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-standard JSON constant: {value}")


def strict_json(raw: str | bytes, label: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError, CollectionError) as error:
        raise CollectionError(f"{label} is not unambiguous JSON: {error}") from error


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def canonical_digest(value: Any) -> str:
    return digest(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    )


def check_positive_decimal(value: Any, label: str) -> str:
    require(
        type(value) is int and value > 0,
        f"{label} must be a positive numeric API value",
    )
    rendered = str(value)
    require(POSITIVE_DECIMAL.fullmatch(rendered) is not None, f"{label} is malformed")
    return rendered


def check_expected_decimal(value: Any, expected: str, label: str) -> str:
    require(
        isinstance(expected, str) and POSITIVE_DECIMAL.fullmatch(expected) is not None,
        f"expected {label} must be a positive decimal string",
    )
    rendered = check_positive_decimal(value, label)
    require(rendered == expected, f"{label} does not match the workflow context")
    return rendered


def check_non_negative_decimal(value: Any, label: str) -> str:
    require(
        type(value) is int and value >= 0,
        f"{label} must be a non-negative numeric API value",
    )
    rendered = str(value)
    require(NON_NEGATIVE_DECIMAL.fullmatch(rendered) is not None, f"{label} is malformed")
    return rendered


def check_non_empty(value: Any, label: str) -> str:
    require(isinstance(value, str) and value.strip(), f"{label} is unavailable")
    return value


def check_time(value: Any, label: str, *, allow_null: bool = True) -> str | None:
    if value is None and allow_null:
        return None
    require(isinstance(value, str) and value.strip(), f"{label} is unavailable")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CollectionError(f"{label} is not an ISO-8601 timestamp") from error
    # GitHub's documented REST representation may use ``Z`` or an explicit
    # numeric offset.  Reject naive values, but preserve the provider spelling
    # and compare aware instants for ordering.
    require(
        parsed.tzinfo is not None and parsed.utcoffset() is not None,
        f"{label} must include a timezone offset",
    )
    return value


def normalize_step(value: Mapping[str, Any], index: int) -> dict[str, Any]:
    number = value.get("number")
    require(type(number) is int and number >= 1, f"job step {index} number is malformed")
    name = check_non_empty(value.get("name"), f"job step {index} name")
    provider_status = value.get("status")
    require(
        provider_status in PROVIDER_STEP_STATUSES,
        f"job step {name} status is malformed",
    )
    # The live Actions jobs API exposes not-yet-started steps as ``pending``.
    # The HeptaBao receipt schema intentionally has one canonical pre-execution
    # state, ``queued``. Preserve the exact provider response through
    # ``api_response_digest`` and normalize only the receipt-facing status.
    status = "queued" if provider_status == "pending" else provider_status
    conclusion = value.get("conclusion")
    require(
        conclusion is None or conclusion in STEP_CONCLUSIONS,
        f"job step {name} conclusion is malformed",
    )
    started_at = check_time(value.get("started_at"), f"job step {name} started_at")
    completed_at = check_time(value.get("completed_at"), f"job step {name} completed_at")
    if status == "completed":
        require(conclusion is not None, f"completed job step {name} has no conclusion")
        require(started_at is not None and completed_at is not None, f"completed job step {name} has no timestamps")
        start_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
        require(end_dt >= start_dt, f"completed job step {name} ends before it starts")
    elif status == "in_progress":
        require(conclusion is None, f"in-progress job step {name} has a conclusion")
        require(started_at is not None, f"in-progress job step {name} has no start timestamp")
        require(completed_at is None, f"in-progress job step {name} has a completion timestamp")
    else:
        require(conclusion is None, f"queued job step {name} has a conclusion")
        require(started_at is None, f"queued job step {name} has a start timestamp")
        require(completed_at is None, f"queued job step {name} has a completion timestamp")

    if status == "completed" and conclusion == "success":
        outcome = "PASS"
    elif status == "completed" and conclusion in {"failure"}:
        outcome = "FAIL"
    elif status == "completed" and conclusion in {"cancelled", "timed_out", "action_required"}:
        outcome = "BLOCKED"
    elif status == "completed" and conclusion in {"skipped", "neutral"}:
        outcome = "SKIPPED"
    elif status == "in_progress":
        outcome = "IN_PROGRESS"
    else:
        outcome = "QUEUED"
    return {
        "number": number,
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "started_at": started_at,
        "completed_at": completed_at,
        "outcome": outcome,
    }


def _select_job(
    payload: Mapping[str, Any],
    *,
    expected_run_id: str,
    expected_run_attempt: str,
    expected_job_name: str,
    expected_workflow_name: str,
    expected_head_sha: str,
) -> Mapping[str, Any]:
    jobs = payload.get("jobs")
    require(isinstance(jobs, list), "Actions API response jobs list is missing")
    require(jobs, "Actions API returned no jobs; execution is unassigned")
    total_count = payload.get("total_count")
    require(
        type(total_count) is int and total_count == len(jobs),
        "Actions API response is incomplete or paginated",
    )
    candidates: list[Mapping[str, Any]] = []
    for index, value in enumerate(jobs):
        require(isinstance(value, Mapping), f"Actions API job {index} is malformed")
        if value.get("name") != expected_job_name:
            continue
        if value.get("workflow_name") != expected_workflow_name:
            continue
        if value.get("head_sha") != expected_head_sha:
            continue
        if type(value.get("run_id")) is not int or str(value["run_id"]) != expected_run_id:
            continue
        if type(value.get("run_attempt")) is not int or str(value["run_attempt"]) != expected_run_attempt:
            continue
        candidates.append(value)
    require(len(candidates) == 1, f"Actions API job identity is ambiguous: {len(candidates)} matches")
    return candidates[0]


def build_log_manifest(
    log_root: Path,
    manifest_path: Path,
    *,
    excluded_paths: tuple[Path, ...] = (),
) -> tuple[dict[str, Any], bytes]:
    root = log_root.resolve()
    require(root.is_dir(), f"log root does not exist: {root}")
    # Refuse to overwrite an existing alias or non-regular target.  Resolving
    # first would silently follow a symlink and let an attacker replace a
    # previously captured manifest outside the evidence root.
    require(not manifest_path.is_symlink(), "log manifest path must not be a symlink")
    if manifest_path.exists():
        require(manifest_path.is_file(), "log manifest path must be a regular file")
    target = manifest_path.resolve()
    excluded = {path.resolve() for path in excluded_paths} | {target}
    files: list[dict[str, Any]] = []
    # Sort by the serialized POSIX-relative path, not ``Path`` component
    # ordering. Component ordering places ``h02/matrix/...`` before the sibling
    # file ``h02/matrix-runner.log``, while the normative manifest verifier
    # compares the actual wire strings. One ordering must govern both sides.
    candidates = sorted(
        root.rglob("*"),
        key=lambda candidate: candidate.relative_to(root).as_posix(),
    )
    for path in candidates:
        if path.resolve() in excluded:
            continue
        if path.is_symlink():
            raise CollectionError(f"log manifest refuses symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        files.append({"path": relative, "size": len(raw), "digest": digest(raw)})
    require(files, "log manifest has no captured evidence files")
    value = {
        "schema": LOG_MANIFEST_SCHEMA_ID,
        "scope": "runner-temp-evidence-before-technical-receipt",
        "file_count": len(files),
        "files": files,
    }
    raw = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(raw)
    return value, raw


def collect(
    raw_api: bytes,
    *,
    expected_run_id: str,
    expected_run_attempt: str,
    expected_job: str,
    expected_job_name: str,
    expected_source_kind: str,
    expected_head_sha: str,
    expected_workflow_name: str,
    expected_runner_name: str,
    expected_runner_os: str,
    expected_runner_arch: str,
    log_root: Path,
    log_manifest: Path,
    output_path: Path | None = None,
) -> dict[str, Any]:
    require(POSITIVE_DECIMAL.fullmatch(expected_run_id or "") is not None, "expected run ID is malformed")
    require(POSITIVE_DECIMAL.fullmatch(expected_run_attempt or "") is not None, "expected run attempt is malformed")
    require(expected_source_kind in {"head", "merge"}, "expected source kind is malformed")
    require(SHA40.fullmatch(expected_head_sha or "") is not None, "expected head SHA is malformed")
    for value, label in (
        (expected_job, "expected job"),
        (expected_job_name, "expected job name"),
        (expected_workflow_name, "expected workflow name"),
        (expected_runner_name, "expected runner name"),
        (expected_runner_os, "expected runner OS"),
        (expected_runner_arch, "expected runner architecture"),
    ):
        check_non_empty(value, label)
    require(expected_job == JOB_NAME, "expected job is not the canonical matrix job")
    require(
        expected_job_name == f"{JOB_NAME} ({expected_source_kind})",
        "expected job name is not canonical for source lane",
    )
    require(expected_workflow_name == WORKFLOW_NAME, "expected workflow name is not canonical")

    payload = strict_json(raw_api, "Actions API response")
    require(isinstance(payload, Mapping), "Actions API response must be one object")
    job = _select_job(
        payload,
        expected_run_id=expected_run_id,
        expected_run_attempt=expected_run_attempt,
        expected_job_name=expected_job_name,
        expected_workflow_name=expected_workflow_name,
        expected_head_sha=expected_head_sha,
    )
    job_id = check_positive_decimal(job.get("id"), "job.id")
    check_expected_decimal(job.get("run_id"), expected_run_id, "job.run_id")
    check_expected_decimal(job.get("run_attempt"), expected_run_attempt, "job.run_attempt")
    job_status = job.get("status")
    require(job_status in JOB_STATUSES, "job.status is unavailable or unsupported")
    # A receipt snapshot is emitted only after this matrix job has acquired a
    # runner.  Preserve the provider's queued state in raw diagnostics, but
    # never normalize it into a completion identity that downstream tooling
    # could mistake for executable evidence.
    require(job_status in {"in_progress", "completed"}, "job is still queued/unassigned")
    job_conclusion = job.get("conclusion")
    require(
        job_conclusion is None or job_conclusion in JOB_CONCLUSIONS,
        "job.conclusion is unavailable or unsupported",
    )
    if job_status == "completed":
        require(job_conclusion == "success", "completed job did not conclude success")
    else:
        require(job_conclusion is None, "non-completed job has a stale conclusion")
    job_started_at = check_time(job.get("started_at"), "job.started_at")
    job_completed_at = check_time(job.get("completed_at"), "job.completed_at")
    require(job_started_at is not None, "job.started_at is unavailable")
    if job_status == "completed":
        require(job_completed_at is not None, "completed job has no completed_at")
        start_dt = datetime.fromisoformat(job_started_at.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(job_completed_at.replace("Z", "+00:00"))
        require(end_dt >= start_dt, "completed job ends before it starts")
    else:
        require(job_completed_at is None, "in-progress job has a completed_at")

    runner_id = check_positive_decimal(job.get("runner_id"), "job.runner_id")
    runner_name = check_non_empty(job.get("runner_name"), "job.runner_name")
    runner_group = check_non_empty(job.get("runner_group_name"), "job.runner_group_name")
    runner_group_id = check_non_negative_decimal(job.get("runner_group_id"), "job.runner_group_id")
    require(runner_name == expected_runner_name, "API runner name does not match runner context")
    labels = job.get("labels")
    require(
        isinstance(labels, list)
        and labels
        and all(isinstance(label, str) and label.strip() for label in labels)
        and len(labels) == len(set(labels)),
        "job.labels are malformed",
    )
    # ``runs-on`` is part of the execution policy.  Keep the provider's exact
    # label projection instead of trusting RUNNER_OS/RUNNER_ARCH, and require
    # the canonical hosted image used by this workflow.
    require(
        CANONICAL_RUNNER_LABEL in labels,
        f"job.labels do not include canonical runner image {CANONICAL_RUNNER_LABEL!r}",
    )

    raw_steps = job.get("steps")
    require(isinstance(raw_steps, list) and raw_steps, "Actions API returned no job steps")
    steps = [normalize_step(step, index) for index, step in enumerate(raw_steps)]
    numbers = [step["number"] for step in steps]
    names = [step["name"] for step in steps]
    require(len(numbers) == len(set(numbers)), "Actions API returned duplicate step numbers")
    require(len(names) == len(set(names)), "Actions API returned duplicate step names")
    require(numbers == sorted(numbers), "Actions API step numbers are not in execution order")
    require(
        names[: len(CANONICAL_REQUIRED_STEP_NAMES)]
        == list(CANONICAL_REQUIRED_STEP_NAMES),
        "Actions API required steps are not the canonical execution prefix",
    )
    by_name = {step["name"]: step for step in steps}
    for required_name in CANONICAL_REQUIRED_STEP_NAMES:
        required_step = by_name.get(required_name)
        require(required_step is not None, f"required workflow step is absent from API response: {required_name}")
        require(required_step["outcome"] == "PASS", f"required workflow step did not pass: {required_name}")

    manifest_value, manifest_raw = build_log_manifest(
        log_root,
        log_manifest,
        excluded_paths=tuple(path for path in (output_path,) if path is not None),
    )
    del manifest_value  # the digest is the receipt-facing binding
    return {
        "schema": SCHEMA_ID,
        "run_id": expected_run_id,
        "run_attempt": expected_run_attempt,
        "job": expected_job,
        "job_id": job_id,
        "job_name": expected_job_name,
        "workflow_name": expected_workflow_name,
        "job_status": job_status,
        "job_conclusion": job_conclusion,
        "runner_id": runner_id,
        "runner_name": runner_name,
        "runner_labels": labels,
        "runner_group_id": runner_group_id,
        "runner_group": runner_group,
        "os": expected_runner_os,
        "arch": expected_runner_arch,
        "head_sha": expected_head_sha,
        "source_kind": expected_source_kind,
        "job_started_at": job_started_at,
        "job_completed_at": job_completed_at,
        "required_step_names": list(CANONICAL_REQUIRED_STEP_NAMES),
        "steps": steps,
        "step_outcomes_digest": canonical_digest(steps),
        "api_response_digest": digest(raw_api),
        "raw_log_manifest_digest": digest(manifest_raw),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--log-root", type=Path, required=True)
    parser.add_argument("--log-manifest", type=Path, required=True)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--expected-run-attempt", required=True)
    parser.add_argument("--expected-job", required=True)
    parser.add_argument("--expected-job-name", required=True)
    parser.add_argument("--expected-source-kind", choices=("head", "merge"), required=True)
    parser.add_argument("--expected-head-sha", required=True)
    parser.add_argument("--expected-workflow-name", default=WORKFLOW_NAME)
    parser.add_argument("--expected-runner-name", required=True)
    parser.add_argument("--expected-runner-os", required=True)
    parser.add_argument("--expected-runner-arch", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        raw = args.input.read_bytes()
        value = collect(
            raw,
            expected_run_id=args.expected_run_id,
            expected_run_attempt=args.expected_run_attempt,
            expected_job=args.expected_job,
            expected_job_name=args.expected_job_name,
            expected_source_kind=args.expected_source_kind,
            expected_head_sha=args.expected_head_sha,
            expected_workflow_name=args.expected_workflow_name,
            expected_runner_name=args.expected_runner_name,
            expected_runner_os=args.expected_runner_os,
            expected_runner_arch=args.expected_runner_arch,
            log_root=args.log_root,
            log_manifest=args.log_manifest,
            output_path=args.output,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except (OSError, TypeError, ValueError, CollectionError) as error:
        print(f"GitHub job identity collection FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "GitHub job identity collected: "
        f"job_id={value['job_id']} runner_id={value['runner_id']} "
        f"steps={len(value['steps'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
