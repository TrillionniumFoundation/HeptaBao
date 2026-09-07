#!/usr/bin/env python3
"""Aggregate the exact-head and synthetic-merge technical receipts.

This command is deliberately a *post-run* arbitration step.  It does not
select a candidate, grant authority, or turn technical execution into an
independent review.  For a pull request it accepts exactly two receipts: one
for the immutable PR head and one for GitHub's distinct synthetic merge
commit.  Each receipt is revalidated, including its digest-bound P0, H02 and
GitHub identity artifacts, before the two immutable source bindings are
compared.

The input directory is normally populated by ``actions/download-artifact``.
The command therefore treats missing, duplicate, stale, superseded or
ancestor-only artifacts as failures.  A failure object is written when the
CLI has enough well-formed arguments to do so, and the process exits non-zero;
there is no failure-to-success fallback.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/heptabao_v1_3_1_lane_arbitration_v1.schema.json"
RECEIPT_VALIDATOR_PATH = ROOT / "scripts/validate_v1_3_1_technical_completion_receipt_v1.py"
SCHEMA_ID = "heptabao.v1-3-1-lane-arbitration.v1"
SCHEMA_URI = "https://heptabao.dev/schemas/heptabao_v1_3_1_lane_arbitration_v1.schema.json"
DRAFT202012_SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema"
RECEIPT_SCHEMA_ID = "heptabao.v1-3-1-technical-completion-receipt.v1"
REPOSITORY = "TrillionniumFoundation/HeptaBao"
WORKFLOW_NAME = "plan-v1.3.1-head-and-merge-closure"
JOB_NAME = "full-technical-matrix"
RUNNER_LABEL = "ubuntu-24.04"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
PR_NUMBER = re.compile(r"^(?:[1-9][0-9]*|workflow_dispatch)$")
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ArbitrationError(RuntimeError):
    """Raised when lane evidence cannot be safely aggregated."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArbitrationError(message)


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArbitrationError(f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-standard JSON constant: {value}")


def strict_json(raw: str | bytes, label: str) -> Any:
    """Parse unambiguous JSON (duplicate keys and NaN are rejected)."""

    try:
        return json.loads(
            raw,
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except (TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError, ArbitrationError) as error:
        raise ArbitrationError(f"{label} is not unambiguous JSON: {error}") from error


def sha256_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    # Keep the schema trust root lexical.  Resolving a symlink before reading
    # would allow an otherwise valid replacement outside the checked-out
    # repository to become the validator's authority.
    path = _guard_path_components(Path(path), "arbitration schema")
    try:
        value = strict_json(path.read_bytes(), f"arbitration schema {path}")
    except OSError as error:
        raise ArbitrationError(f"cannot read arbitration schema: {error}") from error
    require(isinstance(value, dict), "arbitration schema must be one object")
    # Pin the schema identity before validating any output.  A syntactically
    # valid but permissive replacement checked into the arbitration checkout
    # must not become a new trust root merely because Draft2020-12 accepts it.
    require(
        value.get("$schema") == DRAFT202012_SCHEMA_URI,
        "arbitration schema Draft 2020-12 identity drift",
    )
    require(value.get("$id") == SCHEMA_URI, "arbitration schema URI drift")
    properties = value.get("properties")
    require(isinstance(properties, Mapping), "arbitration schema properties are malformed")
    schema_property = properties.get("schema")
    require(
        isinstance(schema_property, Mapping)
        and schema_property.get("const") == SCHEMA_ID,
        "arbitration schema const identity drift",
    )
    try:
        Draft202012Validator.check_schema(value)
    except Exception as error:  # jsonschema has several schema-specific errors
        raise ArbitrationError(f"arbitration schema is not Draft 2020-12: {error}") from error
    return value


def _validate_schema(value: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "$"
        raise ArbitrationError(f"arbitration schema violation at {location}: {first.message}")


def _load_receipt_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "heptabao_v1_3_1_receipt_validator_for_arbitration", RECEIPT_VALIDATOR_PATH
    )
    require(spec is not None and spec.loader is not None, "cannot load technical receipt validator")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise ArbitrationError(f"cannot import technical receipt validator: {error}") from error
    return module


# The aggregate job checks out GitHub's synthetic merge commit.  Re-running
# the receipt validator from that checkout for the head lane would let a
# merge-only change alter the meaning of an exact-head receipt.  Materialize
# the small executable/schema surface from each receipt's own immutable commit
# and import the validator from there instead.  The Git object/tree binding is
# checked separately; these bytes are the code that interprets the receipt.
_SOURCE_VALIDATOR_SURFACE = (
    "scripts/validate_v1_3_1_technical_completion_receipt_v1.py",
    "scripts/validate_v1_3_1_technical_completion_receipt_v1_core.py",
    "scripts/h02_exact_head_matrix_v1.py",
    "schemas/heptabao_v1_3_1_technical_completion_receipt_v1.schema.json",
    "schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json",
    "schemas/heptabao_github_actions_job_identity_v1.schema.json",
    "schemas/heptabao_github_actions_log_manifest_v1.schema.json",
    "probes/h02/openraft-tokio/Cargo.toml",
    "probes/h02/openraft-tokio/Cargo.lock",
)


def _materialize_validator_surface(git_root: Path, commit: str) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    """Copy validator inputs from one immutable Git commit into a temp root."""

    temporary = tempfile.TemporaryDirectory(prefix="heptabao-receipt-source-")
    source_root = Path(temporary.name)
    try:
        for relative in _SOURCE_VALIDATOR_SURFACE:
            destination = source_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                content = subprocess.check_output(
                    ["git", "-C", str(git_root), "show", f"{commit}:{relative}"],
                    stderr=subprocess.STDOUT,
                )
            except (OSError, subprocess.CalledProcessError) as error:
                raise ArbitrationError(
                    f"cannot materialize {relative} from source commit {commit}"
                ) from error
            destination.write_bytes(content)
    except Exception:
        temporary.cleanup()
        raise
    return temporary, source_root


def _load_receipt_validator_at(source_root: Path, commit: str) -> Any:
    """Import the receipt validator whose files came from ``commit``."""

    path = source_root / "scripts/validate_v1_3_1_technical_completion_receipt_v1.py"
    module_name = f"heptabao_receipt_validator_{commit[:16]}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    require(spec is not None and spec.loader is not None, "cannot load source receipt validator")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise ArbitrationError(
            f"cannot import receipt validator from source commit {commit}: {error}"
        ) from error
    return module


_RECEIPT_VALIDATOR: Any | None = None


def receipt_validator() -> Any:
    global _RECEIPT_VALIDATOR
    if _RECEIPT_VALIDATOR is None:
        _RECEIPT_VALIDATOR = _load_receipt_validator()
    return _RECEIPT_VALIDATOR


def _guard_path_components(path: Path, label: str) -> Path:
    """Reject traversal and symlink aliases before opening an artifact path.

    Checking only the leaf with ``Path.is_symlink`` is insufficient: a
    regular file below a symlinked directory transparently resolves outside
    the downloaded evidence root.  Walk each lexical component first, while
    retaining the caller's absolute/relative spelling for subsequent lookup.
    """

    candidate = Path(path)
    require(candidate.parts, f"{label} path is empty")
    require(
        all(part not in {"..", ""} for part in candidate.parts),
        f"{label} path contains traversal components",
    )
    if candidate.is_absolute():
        current = Path(candidate.anchor)
        parts = candidate.parts[1:]
    else:
        current = Path(".")
        parts = candidate.parts
    for part in parts:
        if part == ".":
            continue
        current = current / part
        try:
            aliased = current.is_symlink()
        except (OSError, ValueError) as error:
            raise ArbitrationError(
                f"cannot inspect {label} path component {current}: {error}"
            ) from error
        require(not aliased, f"{label} path contains a symlink component: {current}")
    return candidate


def _regular_file(path: Path, label: str) -> None:
    _guard_path_components(path, label)
    require(not path.is_symlink(), f"{label} must not be a symlink")
    require(path.is_file(), f"{label} is missing or not a regular file")


def _companion(
    receipt_path: Path,
    relative: str,
    *,
    input_root: Path | None = None,
) -> Path:
    """Find one companion artifact within the receipt's downloaded artifact."""

    candidate = _companion_path(receipt_path, relative, input_root=input_root)
    _regular_file(candidate, f"receipt companion {relative}")
    return candidate


def _companion_dir(
    receipt_path: Path,
    relative: str,
    *,
    input_root: Path | None = None,
) -> Path:
    candidate = _companion_path(receipt_path, relative, input_root=input_root)
    require(
        not candidate.is_symlink(),
        f"receipt companion directory {relative} must not be a symlink",
    )
    require(candidate.is_dir(), f"receipt companion directory {relative} is missing")
    return candidate


def _receipt_artifact_boundary(receipt_path: Path, input_root: Path | None) -> Path:
    """Return the highest directory that may contain this receipt's companions.

    ``actions/download-artifact`` normally creates one immediate child directory
    per artifact below ``input_root``.  A receipt and all of its companions must
    stay inside that one artifact directory.  For a flattened download the
    boundary is ``input_root`` itself.  When no input root is supplied (focused
    unit use), the receipt's immediate parent is the only allowed boundary.
    """

    receipt_path = _guard_path_components(receipt_path, "receipt")
    if input_root is None:
        return receipt_path.parent

    input_root = _guard_path_components(input_root, "receipt input root")
    require(not input_root.is_symlink(), "receipt input root must not be a symlink")
    try:
        root = input_root.resolve(strict=True)
        receipt = receipt_path.resolve(strict=True)
        relative_receipt = receipt.relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise ArbitrationError(
            f"receipt path is not contained by the downloaded input root: {receipt_path}"
        ) from error
    require(relative_receipt.parts, "receipt path must not equal the input root")
    if len(relative_receipt.parts) == 1:
        return root
    return root / relative_receipt.parts[0]


def _companion_path(
    receipt_path: Path,
    relative: str,
    *,
    input_root: Path | None = None,
) -> Path:
    """Resolve one companion without escaping into sibling artifacts or host paths."""

    receipt_path = _guard_path_components(receipt_path, "receipt")
    relative_path = Path(relative)
    require(not relative_path.is_absolute(), "receipt companion path must be relative")
    _guard_path_components(relative_path, "receipt companion")
    boundary = _receipt_artifact_boundary(receipt_path, input_root)
    boundary = _guard_path_components(boundary, "receipt artifact boundary")
    require(not boundary.is_symlink(), "receipt artifact boundary must not be a symlink")
    require(boundary.is_dir(), "receipt artifact boundary is missing")

    try:
        receipt = receipt_path.resolve(strict=True)
        boundary_resolved = boundary.resolve(strict=True)
        receipt.relative_to(boundary_resolved)
    except (OSError, RuntimeError, ValueError) as error:
        raise ArbitrationError(
            f"receipt path escapes its downloaded artifact boundary: {receipt_path}"
        ) from error

    candidates: list[Path] = []
    ancestor = receipt.parent
    while True:
        candidate = _guard_path_components(ancestor / relative_path, "receipt companion")
        try:
            candidate.relative_to(boundary_resolved)
        except ValueError as error:
            raise ArbitrationError(
                f"receipt companion path escapes artifact boundary: {relative}"
            ) from error
        if candidate.is_symlink():
            raise ArbitrationError(f"receipt companion {relative} must not be a symlink")
        if candidate.exists():
            candidates.append(candidate)
        if ancestor == boundary_resolved:
            break
        parent = ancestor.parent
        require(parent != ancestor, "receipt artifact boundary was not reached")
        ancestor = parent

    require(len(candidates) == 1, f"receipt companion {relative} is missing or ambiguous")
    return candidates[0]


def discover_receipts(input_root: Path) -> list[Path]:
    input_root = _guard_path_components(input_root, "receipt input root")
    require(not input_root.is_symlink(), "receipt input root must not be a symlink")
    root = input_root.resolve()
    require(root.is_dir(), "input root is not a directory")
    paths = sorted(root.rglob("technical-completion-receipt.json"))
    require(paths, "no technical completion receipts were downloaded")
    for path in paths:
        _regular_file(path, f"receipt {path}")
    # Distinct paths are required even when two files happen to have the same
    # bytes; duplicate content is rejected later as a supersession/duplicate
    # key rather than silently selecting one.
    return paths


def _check_sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None, f"{label} is not lowercase 40-hex")
    return value


def _check_pr(value: Any) -> str:
    require(isinstance(value, str) and PR_NUMBER.fullmatch(value) is not None, "pull-request number is malformed")
    return value


def _check_digest(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256_DIGEST.fullmatch(value) is not None, f"{label} is malformed")
    return value


def _check_json_integer(value: Any, label: str, *, minimum: int | None = None) -> int:
    """Require a provider JSON integer and reject Python ``bool`` values."""

    require(type(value) is int, f"{label} must be a JSON integer")
    if minimum is not None:
        require(value >= minimum, f"{label} is below the minimum")
    return value


def _decimal_to_int(value: Any, label: str) -> int:
    """Parse one expected decimal-string binding without coercion."""

    require(
        isinstance(value, str) and POSITIVE_DECIMAL.fullmatch(value) is not None,
        f"{label} is malformed",
    )
    return int(value)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        # The workflow passes a child directory, so escaping it indicates an
        # unexpected artifact layout and must fail closed.
        raise ArbitrationError(f"receipt path escapes input root: {path}")


def _runner_record(runner: Mapping[str, Any], *, validator_module: Any | None = None) -> dict[str, Any]:
    """Copy and type-check the complete provider execution identity.

    The technical receipt schema intentionally requires these fields.  The
    aggregate repeats the shape so a future permissive receipt validator cannot
    hide a runner-less or stale job behind a successful lane result.
    """

    allowed = (
        "run_id",
        "run_attempt",
        "job",
        "job_id",
        "job_name",
        "workflow_name",
        "runner_id",
        "runner_group",
        "runner_group_id",
        "name",
        "runner_labels",
        "os",
        "arch",
        "job_status",
        "job_conclusion",
        "head_sha",
        "source_kind",
        "job_started_at",
        "job_completed_at",
        "required_step_names",
        "steps",
        "step_outcomes_digest",
        "api_response_digest",
        "raw_log_manifest_digest",
        "artifact_digest",
    )
    require(set(runner) == set(allowed), "runner identity fields drift")
    for field in ("run_id", "run_attempt", "job_id", "runner_id"):
        value = runner.get(field)
        require(
            isinstance(value, str) and POSITIVE_DECIMAL.fullmatch(value) is not None,
            f"runner.{field} is malformed",
        )
    group_id = runner.get("runner_group_id")
    require(
        isinstance(group_id, str) and re.fullmatch(r"(?:0|[1-9][0-9]*)", group_id) is not None,
        "runner.runner_group_id is malformed",
    )
    for field in ("job", "job_name", "workflow_name", "runner_group", "name", "os", "arch"):
        require(isinstance(runner.get(field), str) and runner[field].strip(), f"runner.{field} is malformed")
    require(runner.get("workflow_name") == WORKFLOW_NAME, "runner.workflow_name is not canonical")
    require(runner.get("job") == JOB_NAME, "runner.job is not canonical")
    require(
        runner.get("job_name") == f"{JOB_NAME} ({runner.get('source_kind')})",
        "runner.job_name is not canonical for source lane",
    )
    require(runner.get("job_status") in {"in_progress", "completed"}, "runner.job_status is malformed or queued")
    conclusion = runner.get("job_conclusion")
    require(conclusion is None or isinstance(conclusion, str), "runner.job_conclusion is malformed")
    _check_sha(runner.get("head_sha"), "runner.head_sha")
    require(runner.get("source_kind") in {"head", "merge"}, "runner.source_kind is malformed")
    labels = runner.get("runner_labels")
    require(
        isinstance(labels, list)
        and labels
        and len(labels) == len(set(labels))
        and all(isinstance(label, str) and label.strip() for label in labels),
        "runner.runner_labels is malformed",
    )
    require(RUNNER_LABEL in labels, "runner labels do not bind the canonical runner image")
    require(runner.get("os") == "Linux", "runner.os is not canonical")
    require(runner.get("arch") == "X64", "runner.arch is not canonical")
    for field in ("job_started_at", "job_completed_at"):
        value = runner.get(field)
        require(value is None or (isinstance(value, str) and value.strip()), f"runner.{field} is malformed")
    names = runner.get("required_step_names")
    require(
        isinstance(names, list)
        and bool(names)
        and len(names) == len(set(names))
        and all(isinstance(name, str) and name.strip() for name in names),
        "runner.required_step_names is malformed",
    )
    steps = runner.get("steps")
    require(isinstance(steps, list) and bool(steps), "runner.steps is malformed")
    for index, step in enumerate(steps):
        require(isinstance(step, Mapping), f"runner.steps[{index}] is malformed")
        require(type(step.get("number")) is int and step["number"] >= 1, f"runner.steps[{index}].number is malformed")
        require(isinstance(step.get("name"), str) and step["name"].strip(), f"runner.steps[{index}].name is malformed")
        require(step.get("status") in {"queued", "in_progress", "completed"}, f"runner.steps[{index}].status is malformed")
        require(step.get("conclusion") is None or isinstance(step.get("conclusion"), str), f"runner.steps[{index}].conclusion is malformed")
        require(step.get("outcome") in {"PASS", "FAIL", "BLOCKED", "SKIPPED", "IN_PROGRESS", "QUEUED"}, f"runner.steps[{index}].outcome is malformed")
    for field in ("step_outcomes_digest", "api_response_digest", "raw_log_manifest_digest", "artifact_digest"):
        _check_digest(runner.get(field), f"runner.{field}")
    # Reuse the canonical intrinsic checker as a defense-in-depth boundary.
    # ``_validate_one`` invokes it with the complete receipt, but keeping the
    # aggregate-side check here prevents a future mocked/permissive validator
    # from admitting a queued or partially successful runner record.
    active_validator = validator_module if validator_module is not None else receipt_validator()
    try:
        active_validator._validate_runner_intrinsic(
            runner,
            {"kind": runner.get("source_kind"), "head": runner.get("head_sha")},
        )
    except Exception as error:
        raise ArbitrationError(f"runner intrinsic identity validation failed: {error}") from error
    return {field: runner[field] for field in allowed}


def _git_tree(root: Path, commit: str) -> str:
    """Resolve one commit's tree from the arbitration checkout."""

    try:
        value = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", f"{commit}^{{tree}}"],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ArbitrationError(f"cannot resolve Git tree for {commit}") from error
    require(SHA40.fullmatch(value) is not None, f"Git tree for {commit} is malformed")
    return value


def _git_parents(root: Path, commit: str) -> tuple[str, ...]:
    """Return the exact commit/parent tuple from one immutable Git object.

    ``git rev-list --parents -n1 <synthetic_merge_sha>`` (spelled as separate
    argv entries below) prints the requested commit followed by
    each of its parents on one line.  Keep the parser deliberately strict:
    extra output, abbreviated IDs, malformed IDs or a non-commit object are
    all hard failures rather than an opportunity to infer ancestry.
    """

    try:
        raw = subprocess.check_output(
            ["git", "-C", str(root), "rev-list", "--parents", "-n1", commit],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ArbitrationError(f"cannot resolve Git parents for {commit}") from error
    lines = raw.splitlines()
    require(len(lines) == 1, f"Git parent output for {commit} is not one record")
    fields = tuple(lines[0].split())
    require(fields and all(SHA40.fullmatch(value) for value in fields), f"Git parents for {commit} are malformed")
    return fields


def _validate_merge_parent_binding(
    root: Path,
    synthetic_merge_sha: str,
    base_sha: str,
    head_sha: str,
) -> tuple[str, str, str]:
    """Require a PR synthetic merge with exact ``base`` then ``head`` parents.

    GitHub's pull-request merge ref is an event-produced commit.  Checking
    only its tree (or merely that it differs from the head) would allow an
    arbitrary one-parent commit to be relabeled as that merge.  The ordered
    parent tuple is therefore checked in the trusted aggregate checkout.
    """

    synthetic_merge_sha = _check_sha(synthetic_merge_sha, "synthetic merge SHA")
    base_sha = _check_sha(base_sha, "base SHA")
    head_sha = _check_sha(head_sha, "head SHA")
    parents = _git_parents(root, synthetic_merge_sha)
    require(
        len(parents) == 3,
        "synthetic merge commit must have exactly two parents",
    )
    require(
        parents[0] == synthetic_merge_sha,
        "synthetic merge Git object identity drift",
    )
    require(
        parents[1] == base_sha,
        "synthetic merge first parent is not the event base",
    )
    require(
        parents[2] == head_sha,
        "synthetic merge second parent is not the event head",
    )
    return parents


def _validate_final_jobs_api(
    path: Path,
    records: Sequence[Mapping[str, Any]],
    *,
    expected_run_id: str | None = None,
    expected_run_attempt: str | None = None,
    validators_by_lane: Mapping[str, Any] | None = None,
) -> str:
    """Bind each receipt to the *completed* provider job after all gates.

    The collector intentionally snapshots a job while its receipt step is
    running (status ``in_progress``).  This second API snapshot is therefore
    checked separately: the exact numeric job/runner identity must remain the
    same, while the final job must be completed successfully.  A runner-less,
    stale or partially successful job can never be promoted by aggregation.
    """

    _regular_file(path, "final GitHub jobs API response")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ArbitrationError(f"cannot read final GitHub jobs API response: {error}") from error
    payload = strict_json(raw, "final GitHub jobs API response")
    require(isinstance(payload, Mapping), "final GitHub jobs API response must be one object")
    jobs = payload.get("jobs")
    require(isinstance(jobs, list), "final GitHub jobs API jobs list is missing")
    total_count = _check_json_integer(
        payload.get("total_count"),
        "final GitHub jobs API total_count",
        minimum=0,
    )
    require(
        total_count == len(jobs),
        "final GitHub jobs API response is incomplete or paginated",
    )
    expected_run_id_int = (
        _decimal_to_int(expected_run_id, "expected run ID")
        if expected_run_id is not None
        else None
    )
    expected_run_attempt_int = (
        _decimal_to_int(expected_run_attempt, "expected run attempt")
        if expected_run_attempt is not None
        else None
    )
    seen: set[str] = set()
    for record in records:
        runner = record.get("runner")
        require(isinstance(runner, Mapping), "aggregate runner record is missing")
        source_kind = runner.get("source_kind")
        validator = (
            validators_by_lane.get(source_kind)
            if validators_by_lane is not None
            else None
        )
        if validator is None:
            validator = receipt_validator()
        job_id = runner.get("job_id")
        require(isinstance(job_id, str) and POSITIVE_DECIMAL.fullmatch(job_id), "aggregate job ID is malformed")
        require(job_id not in seen, "final GitHub jobs API job IDs are duplicated")
        seen.add(job_id)
        try:
            numeric_job_id = int(job_id)
        except ValueError as error:
            raise ArbitrationError("aggregate job ID is not numeric") from error
        matches = [
            job
            for job in jobs
            if isinstance(job, Mapping)
            and type(job.get("id")) is int
            and job.get("id") >= 1
            and job.get("id") == numeric_job_id
        ]
        require(len(matches) == 1, f"final GitHub jobs API does not contain exactly one job {job_id}")
        job = matches[0]
        # The receipt's normalized numeric run identity is the lane-local
        # binding even when this helper is used without workflow-level
        # ``expected_run_id``/``expected_run_attempt`` arguments.  Checking
        # only that the provider returned some positive integers would allow a
        # different workflow run/attempt to be rebound to an otherwise valid
        # receipt.
        receipt_run_id = _decimal_to_int(
            runner.get("run_id"), f"receipt job {job_id} run ID"
        )
        receipt_run_attempt = _decimal_to_int(
            runner.get("run_attempt"), f"receipt job {job_id} run attempt"
        )
        if expected_run_id_int is not None:
            require(
                receipt_run_id == expected_run_id_int,
                f"receipt job {job_id} run ID does not match expected run",
            )
        if expected_run_attempt_int is not None:
            require(
                receipt_run_attempt == expected_run_attempt_int,
                f"receipt job {job_id} run attempt does not match expected attempt",
            )
        actual_run_id = _check_json_integer(
            job.get("run_id"), f"final job {job_id} run_id", minimum=1
        )
        require(
            actual_run_id == receipt_run_id,
            f"final job {job_id} run ID does not match receipt",
        )
        actual_run_attempt = _check_json_integer(
            job.get("run_attempt"), f"final job {job_id} run_attempt", minimum=1
        )
        require(
            actual_run_attempt == receipt_run_attempt,
            f"final job {job_id} run attempt does not match receipt",
        )
        require(job.get("name") == runner.get("job_name"), f"final job {job_id} name drift")
        require(job.get("workflow_name") == WORKFLOW_NAME, f"final job {job_id} workflow name drift")
        require(job.get("head_sha") == runner.get("head_sha"), f"final job {job_id} head SHA drift")
        runner_id = _check_json_integer(job.get("runner_id"), f"final job {job_id} runner_id", minimum=1)
        require(runner_id == int(str(runner.get("runner_id"))), f"final job {job_id} runner ID drift")
        require(job.get("runner_name") == runner.get("name"), f"final job {job_id} runner name drift")
        runner_group_id = _check_json_integer(
            job.get("runner_group_id"), f"final job {job_id} runner_group_id", minimum=0
        )
        require(
            runner_group_id == int(str(runner.get("runner_group_id"))),
            f"final job {job_id} runner group ID drift",
        )
        require(job.get("runner_group_name") == runner.get("runner_group"), f"final job {job_id} runner group drift")
        require(job.get("status") == "completed", f"final job {job_id} is not completed")
        require(job.get("conclusion") == "success", f"final job {job_id} did not conclude success")
        require(
            job.get("started_at") == runner.get("job_started_at"),
            f"final job {job_id} start timestamp drift",
        )
        final_started_at = validator._check_timestamp(
            job.get("started_at"), f"final job {job_id} started_at", allow_null=False
        )
        final_completed_at = validator._check_timestamp(
            job.get("completed_at"), f"final job {job_id} completed_at", allow_null=False
        )
        require(
            validator._timestamp_instant(final_completed_at, f"final job {job_id} completed_at")
            >= validator._timestamp_instant(final_started_at, f"final job {job_id} started_at"),
            f"final job {job_id} completes before it starts",
        )
        labels = job.get("labels")
        require(
            isinstance(labels, list)
            and labels
            and all(isinstance(label, str) and label.strip() for label in labels)
            and len(labels) == len(set(labels))
            and RUNNER_LABEL in labels,
            f"final job {job_id} runner labels are not canonical",
        )
        require(labels == runner.get("runner_labels"), f"final job {job_id} runner labels drift")
        raw_steps = job.get("steps")
        require(isinstance(raw_steps, list) and raw_steps, f"final job {job_id} steps are missing")
        normalized: list[dict[str, Any]] = []
        numbers: set[int] = set()
        names: set[str] = set()
        for index, raw_step in enumerate(raw_steps):
            require(isinstance(raw_step, Mapping), f"final job {job_id} step {index} is malformed")
            number = raw_step.get("number")
            require(type(number) is int and number >= 1 and number not in numbers, f"final job {job_id} step number is malformed")
            name = raw_step.get("name")
            require(isinstance(name, str) and name.strip() and name not in names, f"final job {job_id} step name is malformed")
            numbers.add(number)
            names.add(name)
            status = raw_step.get("status")
            conclusion = raw_step.get("conclusion")
            outcome = validator._step_outcome(status, conclusion)
            # A successful completed job must not hide a failed/skipped step.
            require(outcome == "PASS", f"final job {job_id} step did not pass: {name}")
            started_at = validator._check_timestamp(raw_step.get("started_at"), f"final job {job_id} step {name} started_at")
            completed_at = validator._check_timestamp(raw_step.get("completed_at"), f"final job {job_id} step {name} completed_at")
            require(started_at is not None and completed_at is not None, f"final job {job_id} step {name} timestamps are incomplete")
            normalized.append({
                "number": number,
                "name": name,
                "status": status,
                "conclusion": conclusion,
                "started_at": started_at,
                "completed_at": completed_at,
                "outcome": outcome,
            })
        require(
            [step["number"] for step in normalized]
            == sorted(step["number"] for step in normalized),
            f"final job {job_id} steps are not in execution order",
        )
        # Bind the final provider step table to the receipt snapshot's
        # immutable prefix.  The receipt is captured while the collector step
        # is still running; subsequent receipt/cleanup steps may legitimately
        # extend the table and statuses/timestamps may change, but GitHub must
        # not be allowed to insert, reorder or rename a step before the
        # snapshot boundary while retaining the same required-name set.
        snapshot_steps = runner.get("steps")
        require(
            isinstance(snapshot_steps, list) and snapshot_steps,
            f"final job {job_id} receipt step prefix is missing",
        )
        require(
            len(normalized) >= len(snapshot_steps),
            f"final job {job_id} has no complete receipt step prefix",
        )
        for index, (snapshot_step, final_step) in enumerate(
            zip(snapshot_steps, normalized)
        ):
            require(
                isinstance(snapshot_step, Mapping)
                and snapshot_step.get("number") == final_step["number"]
                and snapshot_step.get("name") == final_step["name"],
                f"final job {job_id} receipt step prefix drift at index {index}",
            )
        required = runner.get("required_step_names")
        require(required == list(validator.CANONICAL_REQUIRED_STEP_NAMES), f"final job {job_id} required step list drift")
        require(
            [step["name"] for step in normalized[: len(required)]] == list(required),
            f"final job {job_id} required steps are not the canonical execution prefix",
        )
        by_name = {step["name"]: step for step in normalized}
        for name in required:
            require(name in by_name and by_name[name]["outcome"] == "PASS", f"final job {job_id} required step did not pass: {name}")
    return sha256_digest(raw)


def _validate_one(
    path: Path,
    *,
    input_root: Path,
    repository: str,
    pull_request_number: str,
    head_sha: str,
    base_sha: str,
    synthetic_merge_sha: str,
    expected_run_id: str | None,
    expected_run_attempt: str | None,
    expected_head_owner: str | None,
    git_root: Path | None = None,
) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ArbitrationError(f"cannot read receipt {path}: {error}") from error
    value = strict_json(raw, f"receipt {path}")
    require(isinstance(value, dict), f"receipt {path} must contain one object")
    require(value.get("schema") == RECEIPT_SCHEMA_ID, f"receipt {path} schema identity drift")
    source = value.get("source")
    arbitration = value.get("arbitration")
    runner = value.get("runner")
    require(isinstance(source, Mapping), f"receipt {path} source is missing")
    require(isinstance(arbitration, Mapping), f"receipt {path} arbitration is missing")
    require(isinstance(runner, Mapping), f"receipt {path} runner is missing")
    kind = source.get("kind")
    require(kind in {"head", "merge"}, f"receipt {path} source kind is malformed")
    commit = _check_sha(source.get("commit"), f"receipt {path} source.commit")
    tree = _check_sha(source.get("tree"), f"receipt {path} source.tree")
    source_head = _check_sha(source.get("head"), f"receipt {path} source.head")
    source_base = source.get("base")
    require(isinstance(source_base, str) and (source_base == "" or SHA40.fullmatch(source_base)), f"receipt {path} source.base is malformed")
    event_merge = _check_sha(source.get("event_merge"), f"receipt {path} source.event_merge")
    require(source.get("repository") == repository == REPOSITORY, f"receipt {path} repository identity drift")
    require(source_head == head_sha, f"receipt {path} does not bind the requested immutable head")
    require(source_base == base_sha, f"receipt {path} base SHA drift")
    require(event_merge == synthetic_merge_sha, f"receipt {path} synthetic merge binding drift")
    if kind == "head":
        require(commit == head_sha, f"receipt {path} head lane is not exact-head")
    else:
        require(commit == synthetic_merge_sha, f"receipt {path} merge lane is not the event synthetic merge")
        require(commit != head_sha, f"receipt {path} synthetic merge must differ from head")

    expected_key = f"{pull_request_number}:{head_sha}:{kind}"
    require(arbitration.get("key") == expected_key, f"receipt {path} arbitration key drift")
    require(arbitration.get("pull_request_number") == pull_request_number, f"receipt {path} PR identity drift")
    require(arbitration.get("head_sha") == head_sha, f"receipt {path} arbitration head drift")
    require(arbitration.get("source_kind") == kind, f"receipt {path} arbitration lane drift")
    expected_lanes = ["head"] if pull_request_number == "workflow_dispatch" else ["head", "merge"]
    require(arbitration.get("required_lanes") == expected_lanes, f"receipt {path} required lane set drift")

    p0 = _companion(path, "p0/classified-result.json", input_root=input_root)
    h02 = _companion(path, "h02/matrix/matrix-summary.json", input_root=input_root)
    h02_evidence_dir = _companion_dir(path, "h02/matrix", input_root=input_root)
    identity = _companion(
        path,
        "root/github-identity-verification.json",
        input_root=input_root,
    )
    github_job = _companion(path, "root/github-job-identity.json", input_root=input_root)
    github_job_api = _companion(path, "root/github-job-api.json", input_root=input_root)
    raw_log_manifest = _companion(path, "root/raw-log-manifest.json", input_root=input_root)
    source_validator_tmp: tempfile.TemporaryDirectory[str] | None = None
    try:
        if git_root is not None:
            source_validator_tmp, source_root = _materialize_validator_surface(git_root, commit)
            validator = _load_receipt_validator_at(source_root, commit)
        else:
            validator = receipt_validator()
    except Exception:
        if source_validator_tmp is not None:
            source_validator_tmp.cleanup()
        raise
    try:
        runner_record = _runner_record(runner, validator_module=validator)
        require(runner_record["head_sha"] == head_sha, f"receipt {path} runner head binding drift")
        require(runner_record["source_kind"] == kind, f"receipt {path} runner lane binding drift")
        if expected_run_id is not None:
            require(runner_record.get("run_id") == expected_run_id, f"receipt {path} belongs to a superseded workflow run")
        if expected_run_attempt is not None:
            require(runner_record.get("run_attempt") == expected_run_attempt, f"receipt {path} belongs to a superseded workflow attempt")

        # Locate all three digest-bound artifacts and invoke the source-lane
        # receipt validator.  This rechecks every gate and every non-authority
        # sentinel using code and schemas materialized from this commit.
        # Validate dependency bytes against the lane's own immutable source
        # commit.  The aggregate checkout is normally the synthetic merge;
        # using its Cargo.lock for the exact-head receipt would silently bind
        # that lane to a different tree when the base has changed.
        dependency_tmp: tempfile.TemporaryDirectory[str] | None = None
        if git_root is not None:
            dependency_tmp = tempfile.TemporaryDirectory(prefix="heptabao-lane-deps-")
            dependency_dir = Path(dependency_tmp.name)
            for relative in ("probes/h02/openraft-tokio/Cargo.toml", "probes/h02/openraft-tokio/Cargo.lock"):
                destination = dependency_dir / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    content = subprocess.check_output(
                        ["git", "-C", str(git_root), "show", f"{commit}:{relative}"],
                        stderr=subprocess.STDOUT,
                    )
                except (OSError, subprocess.CalledProcessError) as error:
                    raise ArbitrationError(f"cannot read {relative} from source commit {commit}") from error
                destination.write_bytes(content)
            manifest_for_lane = dependency_dir / "probes/h02/openraft-tokio/Cargo.toml"
            lock_for_lane = dependency_dir / "probes/h02/openraft-tokio/Cargo.lock"
        else:
            manifest_for_lane = ROOT / "probes/h02/openraft-tokio/Cargo.toml"
            lock_for_lane = ROOT / "probes/h02/openraft-tokio/Cargo.lock"
        try:
            validator.validate(
                value,
                expected_source_kind=kind,
                expected_commit=commit,
                expected_tree=tree,
                expected_head=head_sha,
                expected_base=base_sha,
                expected_event_merge=synthetic_merge_sha,
                expected_head_owner=expected_head_owner,
                expected_arbitration_key=expected_key,
                p0_artifact=p0,
                h02_artifact=h02,
                h02_evidence_dir=h02_evidence_dir,
                h02_manifest_path=manifest_for_lane,
                h02_lock_path=lock_for_lane,
                github_identity_artifact=identity,
                github_job_artifact=github_job,
                github_job_api=github_job_api,
                raw_log_manifest=raw_log_manifest,
            )
        finally:
            if dependency_tmp is not None:
                dependency_tmp.cleanup()
    except Exception as error:
        raise ArbitrationError(f"receipt {path} technical validation failed: {error}") from error
    finally:
        if source_validator_tmp is not None:
            source_validator_tmp.cleanup()

    # Technical validator already enforces these; repeat at aggregate boundary
    # so a future permissive validator cannot turn this object into authority.
    require(value.get("qualification") is False, f"receipt {path} qualification claim is not false")
    require(value.get("compatibility_claim") is False, f"receipt {path} compatibility claim is not false")
    require(value.get("selected_candidates") == [], f"receipt {path} selected candidates are not empty")
    require(value.get("selection_effect") == "NONE", f"receipt {path} selection effect drift")
    for field in ("production_authority", "migration_authority", "release_authority"):
        require(value.get(field) is False, f"receipt {path} {field} is not false")
    require(value.get("authority_effect") == "NONE", f"receipt {path} authority effect drift")

    return {
        "lane": kind,
        "receipt_path": _relative(path, input_root),
        "receipt_digest": sha256_digest(raw),
        "arbitration_key": expected_key,
        "source_commit": commit,
        "source_tree": tree,
        "source_head": source_head,
        "source_base": source_base,
        "event_merge": event_merge,
        "runner": runner_record,
        "technical_status": "PASS",
        "qualification": False,
        "compatibility_claim": False,
        "production_authority": False,
        "migration_authority": False,
        "release_authority": False,
        "authority_effect": "NONE",
        # Internal-only reference used to apply the same source-lane helper
        # semantics to the post-run provider snapshot.  ``arbitrate`` removes
        # it before serializing the public aggregate schema.
        "_validator_module": validator,
    }


def _empty_supersession() -> dict[str, Any]:
    return {
        "policy": "CANCEL_OLDER_RUN_AND_RETAIN_HISTORY",
        "duplicate_keys": [],
        "superseded_receipts": [],
        "ancestor_only_rejected": True,
        "selection_basis": "EXACT_HEAD_AND_SYNTHETIC_MERGE_ONLY",
    }


def _failure_class(message: str) -> str:
    """Map a hard failure to the execution-policy category.

    This is diagnostic metadata only.  Every category exits non-zero and can
    never be interpreted as technical success.
    """

    lowered = message.lower()
    # Duplicate/supersession evidence is a distinct arbitration failure.  Test
    # this before the broad "expected exactly"/"incomplete" bucket so a
    # duplicate artifact cannot be mislabeled merely as an unexecuted lane.
    if "duplicate" in lowered:
        return "DUPLICATE"
    if any(token in lowered for token in ("no technical", "expected exactly", "incomplete", "unexecuted")):
        return "UNEXECUTED"
    if "blocked" in lowered or ("runner" in lowered and "unassigned" in lowered):
        return "BLOCKED"
    if "unknown" in lowered:
        return "UNKNOWN"
    if "technical validation failed" in lowered or "not pass" in lowered or "counts drift" in lowered:
        return "TECHNICAL_FAIL"
    if "superseded" in lowered or "stale" in lowered:
        return "SUPERSEDED"
    if any(token in lowered for token in ("source", "head", "base", "merge", "ancestor")):
        return "SOURCE_MISMATCH"
    return "MALFORMED"


def _failure_object(
    *,
    repository: str,
    pull_request_number: str,
    head_sha: str,
    base_sha: str,
    synthetic_merge_sha: str,
    reasons: Sequence[str],
    failure_class: str,
    receipts: Sequence[Mapping[str, Any]] = (),
    supersession: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    # The all-zero tree is an explicit unknown sentinel for an invalid/partial
    # aggregate.  PASS objects can never contain it because a head receipt is
    # required and supplies the real immutable tree.
    return {
        "schema": SCHEMA_ID,
        "repository": repository,
        "pull_request_number": pull_request_number,
        "head_sha": head_sha,
        "head_tree": "0" * 40,
        "merge_tree": "0" * 40,
        "base_sha": base_sha,
        "synthetic_merge_sha": synthetic_merge_sha,
        "required_lanes": ["head"] if pull_request_number == "workflow_dispatch" else ["head", "merge"],
        "status": "FAIL",
        "failure_class": failure_class,
        "receipts": list(receipts),
        "failure_reasons": list(dict.fromkeys(str(reason) for reason in reasons if str(reason).strip())) or ["lane arbitration failed"],
        "supersession": dict(supersession or _empty_supersession()),
        "qualification": False,
        "compatibility_claim": False,
        "selected_candidates": [],
        "selection_effect": "NONE",
        "production_authority": False,
        "migration_authority": False,
        "release_authority": False,
        "authority_effect": "NONE",
    }


def arbitrate(
    input_root: Path,
    *,
    repository: str,
    pull_request_number: str,
    head_sha: str,
    base_sha: str,
    synthetic_merge_sha: str,
    expected_run_id: str | None = None,
    expected_run_attempt: str | None = None,
    expected_head_owner: str | None = None,
    expected_head_tree: str | None = None,
    expected_merge_tree: str | None = None,
    git_root: Path | None = None,
    require_git_tree_binding: bool = False,
    final_jobs_api: Path | None = None,
    require_final_jobs_api: bool = False,
    require_merge_parent_binding: bool = False,
    schema: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate and aggregate all downloaded lane receipts.

    Raises :class:`ArbitrationError` on every incomplete or conflicting input;
    callers that need a machine-readable failure should use :func:`run`.
    """

    require(repository == REPOSITORY, "repository identity must be TrillionniumFoundation/HeptaBao")
    _check_pr(pull_request_number)
    head_sha = _check_sha(head_sha, "head SHA")
    synthetic_merge_sha = _check_sha(synthetic_merge_sha, "synthetic merge SHA")
    require(synthetic_merge_sha != head_sha, "synthetic merge SHA must differ from head SHA on a PR") if pull_request_number != "workflow_dispatch" else None
    require(isinstance(base_sha, str) and (base_sha == "" or SHA40.fullmatch(base_sha)), "base SHA is malformed")
    if pull_request_number != "workflow_dispatch":
        require(base_sha != "", "pull-request arbitration requires a base SHA")
    else:
        require(base_sha == "", "workflow_dispatch arbitration cannot carry a base SHA")
        require(synthetic_merge_sha == head_sha, "workflow_dispatch must bind synthetic_merge_sha to head SHA")
    if expected_run_id is not None:
        require(POSITIVE_DECIMAL.fullmatch(expected_run_id) is not None, "expected run ID is malformed")
    if expected_run_attempt is not None:
        require(POSITIVE_DECIMAL.fullmatch(expected_run_attempt) is not None, "expected run attempt is malformed")
    if expected_head_owner is not None:
        require(isinstance(expected_head_owner, str) and expected_head_owner.strip(), "expected head owner is malformed")
    if expected_head_tree is not None:
        _check_sha(expected_head_tree, "expected head tree")
    if expected_merge_tree is not None:
        _check_sha(expected_merge_tree, "expected merge tree")
    if require_git_tree_binding:
        require(git_root is not None, "Git tree binding requires an arbitration checkout")
    if final_jobs_api is not None:
        require(
            require_git_tree_binding and expected_head_tree is not None and expected_merge_tree is not None,
            "post-run arbitration requires explicit head/merge Git-tree bindings",
        )
    if require_final_jobs_api:
        require(
            final_jobs_api is not None,
            "post-run arbitration requires a final GitHub jobs API response",
        )
    if require_merge_parent_binding and pull_request_number != "workflow_dispatch":
        require(
            git_root is not None,
            "merge-parent binding requires an arbitration checkout",
        )
        _validate_merge_parent_binding(
            Path(git_root),
            synthetic_merge_sha,
            base_sha,
            head_sha,
        )

    input_root = input_root.resolve()
    paths = discover_receipts(input_root)
    expected_count = 1 if pull_request_number == "workflow_dispatch" else 2
    require(len(paths) == expected_count, f"expected exactly {expected_count} lane receipts, found {len(paths)}")

    records: list[dict[str, Any]] = []
    reasons: list[str] = []
    for path in paths:
        try:
            records.append(
                _validate_one(
                    path,
                    input_root=input_root,
                    repository=repository,
                    pull_request_number=pull_request_number,
                    head_sha=head_sha,
                    base_sha=base_sha,
                    synthetic_merge_sha=synthetic_merge_sha,
                    expected_run_id=expected_run_id,
                    expected_run_attempt=expected_run_attempt,
                    expected_head_owner=expected_head_owner,
                    git_root=git_root,
                )
            )
        except ArbitrationError:
            raise

    lanes = [record["lane"] for record in records]
    # ``_validate_one`` may return an internal source-lane validator module.
    # Remove that non-schema object before any aggregate record is serialized,
    # while retaining a lane-indexed map for the final provider snapshot.
    validators_by_lane: dict[str, Any] = {}
    for record in records:
        internal_validator = record.pop("_validator_module", None)
        if internal_validator is not None:
            validators_by_lane[record["lane"]] = internal_validator
    keys = [record["arbitration_key"] for record in records]
    digests = [record["receipt_digest"] for record in records]
    run_keys = [
        ":".join(
            str(record["runner"].get(field, ""))
            for field in ("run_id", "run_attempt", "job_id", "job")
        )
        for record in records
    ]
    require(len(set(lanes)) == len(lanes), "duplicate source lane receipts are forbidden")
    require(len(set(keys)) == len(keys), "duplicate arbitration keys are forbidden")
    require(len(set(digests)) == len(digests), "duplicate receipt digests are forbidden")
    require(len(set(run_keys)) == len(run_keys), "duplicate workflow execution identities are forbidden")
    expected_lanes = ["head"] if pull_request_number == "workflow_dispatch" else ["head", "merge"]
    require(sorted(lanes) == sorted(expected_lanes), "required head/merge lane set is incomplete or unexpected")

    head_record = next(record for record in records if record["lane"] == "head")
    require(head_record["source_commit"] == head_sha, "head record is not exact immutable head")
    head_tree = head_record["source_tree"]
    if expected_head_tree is not None:
        require(head_tree == expected_head_tree, "immutable head tree does not match expected tree")
    if require_git_tree_binding:
        actual_head_tree = _git_tree(Path(git_root), head_sha)
        require(head_tree == actual_head_tree, "head receipt tree does not match the checked-out Git object")
    merge_tree = head_tree
    if pull_request_number != "workflow_dispatch":
        merge_record = next(record for record in records if record["lane"] == "merge")
        require(merge_record["source_commit"] == synthetic_merge_sha, "merge record is not event synthetic merge")
        require(merge_record["source_commit"] != head_record["source_commit"], "head and merge source commits must differ")
        require(merge_record["source_head"] == head_record["source_head"] == head_sha, "lane head bindings disagree")
        require(merge_record["source_base"] == head_record["source_base"] == base_sha, "lane base bindings disagree")
        require(merge_record["event_merge"] == head_record["event_merge"] == synthetic_merge_sha, "lane synthetic merge bindings disagree")
        merge_tree = merge_record["source_tree"]
        if expected_merge_tree is not None:
            require(merge_tree == expected_merge_tree, "synthetic merge receipt tree does not match expected tree")
        if require_git_tree_binding:
            actual_merge_tree = _git_tree(Path(git_root), synthetic_merge_sha)
            require(merge_tree == actual_merge_tree, "merge receipt tree does not match the checked-out Git object")

    final_jobs_api_digest: str | None = None
    if final_jobs_api is not None:
        try:
            final_jobs_api_digest = _validate_final_jobs_api(
                Path(final_jobs_api),
                records,
                expected_run_id=expected_run_id,
                expected_run_attempt=expected_run_attempt,
                validators_by_lane=validators_by_lane,
            )
        except ArbitrationError:
            raise
        except Exception as error:
            raise ArbitrationError(f"final GitHub jobs API validation failed: {error}") from error

    result = {
        "schema": SCHEMA_ID,
        "repository": repository,
        "pull_request_number": pull_request_number,
        "head_sha": head_sha,
        "head_tree": head_tree,
        "merge_tree": merge_tree,
        "base_sha": base_sha,
        "synthetic_merge_sha": synthetic_merge_sha,
        "required_lanes": expected_lanes,
        "status": "PASS",
        "failure_class": "NONE",
        "receipts": records,
        "failure_reasons": [],
        "supersession": _empty_supersession(),
        "qualification": False,
        "compatibility_claim": False,
        "selected_candidates": [],
        "selection_effect": "NONE",
        "production_authority": False,
        "migration_authority": False,
        "release_authority": False,
        "authority_effect": "NONE",
    }
    if final_jobs_api_digest is not None:
        result["final_jobs_api_digest"] = final_jobs_api_digest
    active_schema = schema if schema is not None else _load_schema()
    _validate_schema(result, active_schema)
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", type=Path, required=True, help="directory containing downloaded lane artifacts")
    parser.add_argument("--output", type=Path, required=True, help="aggregate JSON output path")
    parser.add_argument("--repository", default=REPOSITORY)
    parser.add_argument("--pull-request-number", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--synthetic-merge-sha", required=True)
    parser.add_argument("--expected-run-id")
    parser.add_argument("--expected-run-attempt")
    parser.add_argument("--expected-head-owner")
    parser.add_argument("--expected-head-tree")
    parser.add_argument("--expected-merge-tree")
    parser.add_argument(
        "--git-root",
        type=Path,
        default=ROOT,
        help="checkout used to verify each receipt commit's Git tree",
    )
    parser.add_argument(
        "--require-git-tree-binding",
        action="store_true",
        help="require source trees to match immutable Git objects in --git-root",
    )
    parser.add_argument(
        "--final-jobs-api",
        type=Path,
        help="post-run Actions jobs response proving each numeric job completed successfully",
    )
    parser.add_argument(
        "--require-final-jobs-api",
        action="store_true",
        help="fail closed unless the post-run Actions jobs response is supplied and passes",
    )
    parser.add_argument(
        "--require-merge-parent-binding",
        action="store_true",
        help="fail closed unless the synthetic merge has exactly base then head parents",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    # Validate enough scalar arguments for a schema-valid failure object.  If
    # even those are malformed, still write a minimal diagnostic where safe.
    try:
        result = arbitrate(
            args.input_root,
            repository=args.repository,
            pull_request_number=args.pull_request_number,
            head_sha=args.head_sha,
            base_sha=args.base_sha,
            synthetic_merge_sha=args.synthetic_merge_sha,
            expected_run_id=args.expected_run_id,
            expected_run_attempt=args.expected_run_attempt,
            expected_head_owner=args.expected_head_owner,
            expected_head_tree=args.expected_head_tree,
            expected_merge_tree=args.expected_merge_tree,
            git_root=args.git_root,
            require_git_tree_binding=args.require_git_tree_binding,
            final_jobs_api=args.final_jobs_api,
            require_final_jobs_api=args.require_final_jobs_api,
            require_merge_parent_binding=args.require_merge_parent_binding,
        )
    except Exception as error:
        try:
            repository = args.repository
            pull_request_number = args.pull_request_number if PR_NUMBER.fullmatch(args.pull_request_number) else "workflow_dispatch"
            head_sha = args.head_sha if SHA40.fullmatch(args.head_sha) else "0" * 40
            base_sha = args.base_sha if args.base_sha == "" or SHA40.fullmatch(args.base_sha) else ""
            merge_sha = args.synthetic_merge_sha if SHA40.fullmatch(args.synthetic_merge_sha) else head_sha
            result = _failure_object(
                repository=repository,
                pull_request_number=pull_request_number,
                head_sha=head_sha,
                base_sha=base_sha,
                synthetic_merge_sha=merge_sha,
                reasons=[str(error)],
                failure_class=_failure_class(str(error)),
            )
            _validate_schema(result, _load_schema())
        except Exception:
            # Do not hide the original failure; a malformed invocation is a
            # hard error and may legitimately have no schema-valid output.
            print(f"V1.3.1 lane arbitration FAILED: {error}", file=sys.stderr)
            return 1
        print(f"V1.3.1 lane arbitration FAILED: {error}", file=sys.stderr)
    else:
        print("V1.3.1 lane arbitration passed: exact head + synthetic merge receipts bound; authority=NONE")

    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as error:
        print(f"cannot write lane arbitration output: {error}", file=sys.stderr)
        return 1
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
