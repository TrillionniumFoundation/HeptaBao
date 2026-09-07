#!/usr/bin/env python3
"""Fail-closed validation for the V1.3.1 technical completion receipt.

The receipt is deliberately a technical execution record, not a qualification,
compatibility claim, candidate selection or authority grant.  Schema validation
alone cannot bind its opaque artifact digests to the files produced by CI, so
the command-line interface requires the classified P0 result, the H02 matrix
summary and the GitHub identity-verification artifact.  Callers may also bind
every source, runner and expected head-owner identity supplied by the
pull-request event.  H02 entries are additionally revalidated against the
canonical runner tuple (ID, kind, toolchain, seed, binary, argv and digest).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/heptabao_v1_3_1_technical_completion_receipt_v1.schema.json"
JOB_IDENTITY_SCHEMA_PATH = ROOT / "schemas/heptabao_github_actions_job_identity_v1.schema.json"
LOG_MANIFEST_SCHEMA_PATH = ROOT / "schemas/heptabao_github_actions_log_manifest_v1.schema.json"
SCHEMA_ID = "heptabao.v1-3-1-technical-completion-receipt.v1"
SCHEMA_URI = "https://heptabao.dev/schemas/heptabao_v1_3_1_technical_completion_receipt_v1.schema.json"
REPOSITORY = "TrillionniumFoundation/HeptaBao"
REPOSITORY_ID = 1349115072
REPOSITORY_OWNER = "TrillionniumFoundation"
RATIFIER_LOGIN = "ProfHepta"
RATIFIER_ID = 102159240
WORKFLOW_NAME = "plan-v1.3.1-head-and-merge-closure"
JOB_NAME = "full-technical-matrix"
RUNNER_LABEL = "ubuntu-24.04"

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
NON_NEGATIVE_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")
ARBITRATION_PR = re.compile(r"^(?:[1-9][0-9]*|workflow_dispatch)$")

JOB_IDENTITY_SCHEMA_ID = "heptabao.github-actions-job-identity.v1"
LOG_MANIFEST_SCHEMA_ID = "heptabao.github-actions-log-manifest.v1"
DRAFT202012_SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema"
JOB_IDENTITY_SCHEMA_URI = "https://heptabao.dev/schemas/heptabao_github_actions_job_identity_v1.schema.json"
LOG_MANIFEST_SCHEMA_URI = "https://heptabao.dev/schemas/heptabao_github_actions_log_manifest_v1.schema.json"
H02_SCHEMA_URI = "https://heptabao.dev/schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json"
JOB_STATUSES = {"queued", "in_progress", "completed"}
JOB_CONCLUSIONS = {
    "success",
    "failure",
    "cancelled",
    "skipped",
    "neutral",
    "timed_out",
    "action_required",
}
STEP_STATUSES = JOB_STATUSES
STEP_CONCLUSIONS = JOB_CONCLUSIONS
STEP_OUTCOMES = {"PASS", "FAIL", "BLOCKED", "SKIPPED", "IN_PROGRESS", "QUEUED"}
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

P0_SCHEMA_ID = "heptabao.p0-transport-exact-result.v2"
P0_EVIDENCE_RESULT = "PASS_WITH_EXPLICIT_EVIDENCE_CLASSIFICATION"
P0_COUNTS = {
    "executed_pass": 11,
    "source_bound_pass": 2,
    "best_effort_source_bound_pass": 1,
    "fail": 0,
    "blocked": 0,
    "unexecuted": 0,
    "total": 14,
}
P0_RUNTIME_CASES = {
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
P0_SOURCE_CASES = {"P0-TRANSPORT-011", "P0-TRANSPORT-012"}
P0_BEST_EFFORT_CASES = {"P0-TRANSPORT-014"}
P0_CASES = P0_RUNTIME_CASES | P0_SOURCE_CASES | P0_BEST_EFFORT_CASES

H02_SCHEMA_ID = "heptabao.h02-exact-head-matrix-summary.v1"
H02_COUNTS = {"pass": 24, "fail": 0, "blocked": 0, "unknown": 0, "unexecuted": 0}
H02_TOOLCHAINS = ("1.88.0", "1.98.0")
H02_SEEDS = (
    "0x5eed20260828cafe",
    "0x8badf00d12345678",
    "0xd15ea5e5cafef00d",
)
H02_KINDS = ("inmemory", "hostile", "blocker", "durable")
H02_ENTRY_IDS = {
    f"{kind}-{toolchain}-{seed.removeprefix('0x')}"
    for toolchain in H02_TOOLCHAINS
    for seed in H02_SEEDS
    for kind in H02_KINDS
}
H02_MANIFEST_PATH = "probes/h02/openraft-tokio/Cargo.toml"
H02_LOCK_PATH = "probes/h02/openraft-tokio/Cargo.lock"
H02_BINARY_BY_KIND = {
    "inmemory": "heptabao-h02-openraft-inmemory-cluster",
    "hostile": "heptabao-h02-openraft-fault-lab",
    "blocker": "heptabao-h02-openraft-blocker-closure-lab",
    "durable": "heptabao-h02-openraft-durable-store-lab",
}
H02_ENTRY_ID_PATTERN = re.compile(
    r"^(?P<kind>inmemory|hostile|blocker|durable)-"
    r"(?P<toolchain>1\.88\.0|1\.98\.0)-(?P<seed>[0-9a-f]{16})$"
)

RUNNER_FIELDS = (
    "run_id",
    "run_attempt",
    "job",
    "job_id",
    "job_name",
    "workflow_name",
    "job_status",
    "job_conclusion",
    "name",
    "runner_labels",
    "runner_id",
    "runner_group_id",
    "runner_group",
    "os",
    "arch",
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
# The normalized Actions artifact follows the provider vocabulary for the
# runner name (``runner_name``), while the technical receipt keeps the shorter
# ``name`` field for compatibility with the execution-policy record.  Keep this
# list explicit: deriving it from RUNNER_FIELDS would silently omit the
# artifact's schema marker and accept the wrong provider field.
JOB_IDENTITY_ARTIFACT_FIELDS = (
    "schema",
    "run_id",
    "run_attempt",
    "job",
    "job_id",
    "job_name",
    "workflow_name",
    "job_status",
    "job_conclusion",
    "runner_id",
    "runner_name",
    "runner_labels",
    "runner_group_id",
    "runner_group",
    "os",
    "arch",
    "head_sha",
    "source_kind",
    "job_started_at",
    "job_completed_at",
    "required_step_names",
    "steps",
    "step_outcomes_digest",
    "api_response_digest",
    "raw_log_manifest_digest",
)
REQUIRED_LOG_MANIFEST_PATHS = {
    "p0/classified-result.json",
    "h02/matrix/matrix-summary.json",
    "root/github-identity-verification.json",
    "root/github-job-api.json",
}
GITHUB_IDENTITY_ARTIFACT_FIELDS = (
    "source_sha",
    "repository_id",
    "repository_full_name",
    "expected_head_owner",
    "head_owner",
    "expected_ratifier_login",
    "expected_ratifier_id",
    "author_login",
    "committer_login",
    "author_id",
    "committer_id",
    "verification",
    "identity_verified",
    "signature_required",
)
GITHUB_IDENTITY_FIELDS = ("artifact_digest",) + GITHUB_IDENTITY_ARTIFACT_FIELDS
ARBITRATION_FIELDS = (
    "key",
    "pull_request_number",
    "head_sha",
    "source_kind",
    "required_lanes",
)


class ValidationError(RuntimeError):
    """Raised when a receipt or its execution artifacts cannot be trusted."""


# A descriptive alias keeps imports readable for callers that distinguish this
# validator from the jsonschema package's own ValidationError class.
ReceiptValidationError = ValidationError


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON object members instead of silently choosing one."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    """Reject non-standard JSON constants accepted by ``json.loads``."""

    raise ValueError(f"non-standard JSON constant: {value}")


def _strict_json(raw: str | bytes, label: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_json_constant,
        )
    except (
        TypeError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
        ValidationError,
    ) as error:
        raise ValidationError(f"{label} is not unambiguous JSON: {error}") from error


def _guard_path_components(path: Path, label: str) -> Path:
    """Reject traversal and symlink components before opening ``path``.

    Checking only ``Path.is_symlink()`` on the leaf is insufficient: a
    regular file below a symlinked directory transparently resolves outside
    the downloaded evidence root.  Walk the lexical components with ``lstat``
    semantics (``Path.is_symlink``) and fail closed on any alias or ``..``
    component.  The helper deliberately does not require an absolute path;
    repository-relative schema/dependency paths remain valid.
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
            raise ValidationError(f"cannot inspect {label} path component {current}: {error}") from error
        require(not aliased, f"{label} path contains a symlink component: {current}")
    return candidate


def _schema_identity(
    value: Mapping[str, Any], *, expected_id: str, expected_uri: str, label: str
) -> None:
    """Bind one loaded schema to its exact Draft-2020-12 identity."""

    properties = value.get("properties")
    require(isinstance(properties, Mapping), f"{label} properties are malformed")
    schema_property = properties.get("schema")
    require(isinstance(schema_property, Mapping), f"{label} schema property is malformed")
    require(
        value.get("$schema") == DRAFT202012_SCHEMA_URI,
        f"{label} $schema identity drift",
    )
    require(value.get("$id") == expected_uri, f"{label} $id identity drift")
    const = schema_property.get("const")
    require(const == expected_id, f"{label} schema identity drift: {const!r}")


def load_schema(
    path: Path = SCHEMA_PATH,
    *,
    expected_id: str = SCHEMA_ID,
    expected_uri: str = SCHEMA_URI,
) -> dict[str, Any]:
    """Load and meta-validate the receipt schema."""

    path = _guard_path_components(Path(path), "receipt schema")
    try:
        value = _strict_json(path.read_bytes(), f"receipt schema {path}")
    except OSError as error:
        raise ValidationError(f"cannot load receipt schema {path}: {error}") from error
    require(isinstance(value, dict), "receipt schema must be one JSON object")
    try:
        Draft202012Validator.check_schema(value)
    except Exception as error:  # jsonschema raises several schema-specific types
        raise ValidationError(f"receipt schema is not valid Draft 2020-12: {error}") from error
    _schema_identity(value, expected_id=expected_id, expected_uri=expected_uri, label="receipt schema")
    return value


def load_artifact_schema(
    path: Path,
    expected_id: str,
    *,
    expected_uri: str | None = None,
) -> dict[str, Any]:
    """Load and meta-validate one auxiliary receipt-artifact schema."""

    path = _guard_path_components(Path(path), "artifact schema")
    try:
        value = _strict_json(path.read_bytes(), f"artifact schema {path}")
    except OSError as error:
        raise ValidationError(f"cannot load artifact schema {path}: {error}") from error
    require(isinstance(value, dict), "artifact schema must be one JSON object")
    require(value.get("$id"), "artifact schema has no stable ID")
    try:
        Draft202012Validator.check_schema(value)
    except Exception as error:  # jsonschema raises several schema-specific types
        raise ValidationError(f"artifact schema is not valid Draft 2020-12: {error}") from error
    # The schema's top-level const is the executable identity, not merely its
    # filename.  A swapped permissive schema must fail before artifact checks.
    if expected_uri is None:
        expected_uri = {
            JOB_IDENTITY_SCHEMA_ID: JOB_IDENTITY_SCHEMA_URI,
            LOG_MANIFEST_SCHEMA_ID: LOG_MANIFEST_SCHEMA_URI,
        }.get(expected_id, "")
    require(expected_uri, f"artifact schema URI is not registered: {expected_id}")
    _schema_identity(value, expected_id=expected_id, expected_uri=expected_uri, label="artifact schema")
    return value


def _schema_validate(receipt: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(receipt), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "$"
        raise ValidationError(f"receipt schema violation at {location}: {first.message}")


def _check_sha40(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None, f"{label} must be lowercase 40-hex")
    return value


def _check_optional_sha40(value: Any, label: str) -> str:
    require(value == "" or (isinstance(value, str) and SHA40.fullmatch(value) is not None), f"{label} must be empty or lowercase 40-hex")
    return value


def _check_positive_decimal(value: Any, label: str) -> str:
    require(isinstance(value, str) and POSITIVE_DECIMAL.fullmatch(value) is not None, f"{label} must be a positive decimal string")
    return value


def _check_non_negative_decimal(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and NON_NEGATIVE_DECIMAL.fullmatch(value) is not None,
        f"{label} must be a non-negative decimal string",
    )
    return value


def _check_json_integer(value: Any, label: str, *, minimum: int | None = None) -> int:
    """Require a JSON integer, explicitly excluding Python's ``bool``.

    ``bool`` is an ``int`` subclass in Python and compares equal to ``0`` or
    ``1``.  Provider/API and count fields are numeric evidence, so accepting a
    boolean here would let a self-consistent forged payload pass an equality
    check even though it is not a JSON integer.
    """

    require(type(value) is int, f"{label} must be a JSON integer")
    if minimum is not None:
        require(value >= minimum, f"{label} is below the minimum")
    return value


def _check_non_empty(value: Any, label: str) -> str:
    require(isinstance(value, str) and value.strip(), f"{label} must be non-empty")
    return value


def _validate_source_intrinsic(source: Mapping[str, Any]) -> None:
    # The schema already fixes these values; repeat the checks here so a caller
    # cannot accidentally substitute a permissive schema and turn this into an
    # authority-bearing assertion.
    require(source.get("repository") == REPOSITORY, "receipt repository identity drift")
    kind = source.get("kind")
    require(kind in {"head", "merge"}, "receipt source kind must be head or merge")
    commit = _check_sha40(source.get("commit"), "source.commit")
    _check_sha40(source.get("tree"), "source.tree")
    head = _check_sha40(source.get("head"), "source.head")
    base = _check_optional_sha40(source.get("base"), "source.base")
    event_merge = _check_sha40(source.get("event_merge"), "source.event_merge")

    if kind == "head":
        require(commit == head, "head lane must execute the event head commit")
        # A dispatch has no pull-request base.  In that mode GITHUB_SHA must
        # still identify the checked-out commit rather than an unbound ref.
        if base == "":
            require(event_merge == commit, "dispatch head receipt must bind event_merge to commit")
    else:
        require(base != "", "merge lane requires a non-empty event base")
        require(commit != head, "merge lane must execute a commit distinct from the head")
        require(event_merge == commit, "merge lane event_merge must equal the synthetic merge commit")


def _check_timestamp(value: Any, label: str, *, allow_null: bool = True) -> str | None:
    if value is None and allow_null:
        return None
    require(isinstance(value, str) and value.strip(), f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError(f"{label} must be an ISO-8601 timestamp") from error
    # GitHub's documented REST representation may use ``Z`` or an explicit
    # numeric offset.  Require an aware instant, but preserve the provider's
    # spelling and compare instants (rather than rejecting a valid offset).
    require(
        parsed.tzinfo is not None and parsed.utcoffset() is not None,
        f"{label} must include a timezone offset",
    )
    return value


def _timestamp_instant(value: str, label: str) -> datetime:
    """Parse a previously checked timestamp for aware instant ordering."""

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None, f"{label} must be timezone-aware")
    return parsed


def _step_outcome(status: Any, conclusion: Any) -> str:
    require(status in STEP_STATUSES, "runner step status is malformed")
    require(
        conclusion is None or conclusion in STEP_CONCLUSIONS,
        "runner step conclusion is malformed",
    )
    if status == "completed":
        require(conclusion is not None, "completed runner step has no conclusion")
        if conclusion == "success":
            return "PASS"
        if conclusion == "failure":
            return "FAIL"
        if conclusion in {"cancelled", "timed_out", "action_required"}:
            return "BLOCKED"
        if conclusion in {"skipped", "neutral"}:
            return "SKIPPED"
    if status == "in_progress":
        require(conclusion is None, "in-progress runner step has a conclusion")
        return "IN_PROGRESS"
    require(conclusion is None, "queued runner step has a conclusion")
    return "QUEUED"


def _validate_runner_intrinsic(runner: Mapping[str, Any], source: Mapping[str, Any]) -> None:
    require(set(runner) == set(RUNNER_FIELDS), "receipt runner fields drift")
    _check_positive_decimal(runner.get("run_id"), "runner.run_id")
    _check_positive_decimal(runner.get("run_attempt"), "runner.run_attempt")
    _check_positive_decimal(runner.get("job_id"), "runner.job_id")
    _check_positive_decimal(runner.get("runner_id"), "runner.runner_id")
    _check_non_negative_decimal(runner.get("runner_group_id"), "runner.runner_group_id")
    for field in ("job", "job_name", "workflow_name", "name", "runner_group", "os", "arch"):
        _check_non_empty(runner.get(field), f"runner.{field}")
    require(runner.get("workflow_name") == WORKFLOW_NAME, "runner.workflow_name is not canonical")
    require(runner.get("job") == JOB_NAME, "runner.job is not canonical")
    require(
        runner.get("job_name") == f"{JOB_NAME} ({source.get('kind')})",
        "runner.job_name is not canonical for source lane",
    )
    job_status = runner.get("job_status")
    require(job_status in JOB_STATUSES, "runner.job_status is malformed")
    job_conclusion = runner.get("job_conclusion")
    require(
        job_conclusion is None or job_conclusion in JOB_CONCLUSIONS,
        "runner.job_conclusion is malformed",
    )
    # A receipt is emitted only after this job has acquired a runner and the
    # required gates have passed.  A queued job cannot carry executable step
    # evidence, even if a permissive JSON schema happens to accept it.
    require(job_status in {"in_progress", "completed"}, "runner job is still queued")
    if job_status == "completed":
        require(job_conclusion == "success", "completed runner job must conclude success")
        require(runner.get("job_completed_at") is not None, "completed runner job has no completion timestamp")
    else:
        require(job_conclusion is None, "non-completed runner job has a conclusion")
        require(runner.get("job_completed_at") is None, "non-completed runner job has a completion timestamp")
    job_started_at = _check_timestamp(
        runner.get("job_started_at"), "runner.job_started_at", allow_null=False
    )
    job_completed_at = _check_timestamp(runner.get("job_completed_at"), "runner.job_completed_at")
    if job_completed_at is not None:
        require(
            _timestamp_instant(job_completed_at, "runner.job_completed_at")
            >= _timestamp_instant(job_started_at, "runner.job_started_at"),
            "runner job completes before it starts",
        )

    head_sha = _check_sha40(runner.get("head_sha"), "runner.head_sha")
    require(head_sha == source.get("head"), "runner head SHA does not match source.head")
    source_kind = runner.get("source_kind")
    require(source_kind in {"head", "merge"}, "runner.source_kind is malformed")
    require(source_kind == source.get("kind"), "runner source kind does not match source.kind")

    labels = runner.get("runner_labels")
    require(
        isinstance(labels, list)
        and labels
        and all(isinstance(label, str) and label.strip() for label in labels)
        and len(labels) == len(set(labels)),
        "runner.runner_labels are malformed",
    )
    require(RUNNER_LABEL in labels, "runner labels do not bind the canonical runner image")
    require(runner.get("os") == "Linux", "runner.os is not the canonical Linux image")
    require(runner.get("arch") == "X64", "runner.arch is not the canonical X64 image")

    required_names = runner.get("required_step_names")
    require(
        required_names == list(CANONICAL_REQUIRED_STEP_NAMES),
        "runner required step list drift",
    )
    steps = runner.get("steps")
    require(isinstance(steps, list) and steps, "runner steps are missing")
    seen_numbers: set[int] = set()
    seen_names: set[str] = set()
    normalized_steps: list[dict[str, Any]] = []
    for index, value in enumerate(steps):
        require(isinstance(value, Mapping), f"runner step {index} is malformed")
        require(
            set(value)
            == {
                "number",
                "name",
                "status",
                "conclusion",
                "started_at",
                "completed_at",
                "outcome",
            },
            f"runner step {index} fields drift",
        )
        number = value.get("number")
        require(type(number) is int and number >= 1, f"runner step {index} number is malformed")
        name = _check_non_empty(value.get("name"), f"runner step {index} name")
        require(number not in seen_numbers, f"runner step number is duplicated: {number}")
        require(name not in seen_names, f"runner step name is duplicated: {name}")
        seen_numbers.add(number)
        seen_names.add(name)
        status = value.get("status")
        conclusion = value.get("conclusion")
        outcome = _step_outcome(status, conclusion)
        require(value.get("outcome") == outcome, f"runner step outcome drift: {name}")
        started_at = _check_timestamp(value.get("started_at"), f"runner step {name} started_at")
        completed_at = _check_timestamp(value.get("completed_at"), f"runner step {name} completed_at")
        if status == "completed":
            require(started_at is not None and completed_at is not None, f"completed runner step {name} lacks timestamps")
            require(
                _timestamp_instant(completed_at, f"runner step {name} completed_at")
                >= _timestamp_instant(started_at, f"runner step {name} started_at"),
                f"runner step {name} completes before it starts",
            )
        else:
            require(completed_at is None, f"non-completed runner step {name} has completion timestamp")
        normalized_steps.append(
            {
                "number": number,
                "name": name,
                "status": status,
                "conclusion": conclusion,
                "started_at": started_at,
                "completed_at": completed_at,
                "outcome": outcome,
            }
        )
    by_name = {step["name"]: step for step in normalized_steps}
    require(
        [step["number"] for step in normalized_steps]
        == sorted(step["number"] for step in normalized_steps),
        "runner step numbers are not in execution order",
    )
    require(
        [step["name"] for step in normalized_steps[: len(CANONICAL_REQUIRED_STEP_NAMES)]]
        == list(CANONICAL_REQUIRED_STEP_NAMES),
        "runner required steps are not the canonical execution prefix",
    )
    for required_name in CANONICAL_REQUIRED_STEP_NAMES:
        required_step = by_name.get(required_name)
        require(required_step is not None, f"required runner step is absent: {required_name}")
        require(required_step["outcome"] == "PASS", f"required runner step did not pass: {required_name}")
    require(
        runner.get("step_outcomes_digest") == _canonical_digest(normalized_steps),
        "runner step outcomes digest drift",
    )
    for field in ("api_response_digest", "raw_log_manifest_digest", "artifact_digest"):
        require(
            isinstance(runner.get(field), str)
            and SHA256_DIGEST.fullmatch(runner[field]) is not None,
            f"runner.{field} is malformed",
        )


def _validate_arbitration_intrinsic(
    arbitration: Mapping[str, Any], source: Mapping[str, Any]
) -> None:
    """Bind a lane receipt to the local workflow arbitration key.

    GitHub's run/job listing API is intentionally not consulted here.  The
    workflow already has the immutable event values needed to construct this
    key; recording and recomputing them locally lets downstream tooling group
    head/merge receipts without treating an external API response as a trust
    root.
    """

    require(set(arbitration) == set(ARBITRATION_FIELDS), "receipt arbitration fields drift")
    pull_request_number = arbitration.get("pull_request_number")
    require(
        isinstance(pull_request_number, str)
        and ARBITRATION_PR.fullmatch(pull_request_number) is not None,
        "arbitration.pull_request_number is malformed",
    )
    head_sha = _check_sha40(arbitration.get("head_sha"), "arbitration.head_sha")
    require(head_sha == source.get("head"), "arbitration head SHA does not match source.head")
    source_kind = arbitration.get("source_kind")
    require(source_kind in {"head", "merge"}, "arbitration source kind is malformed")
    require(source_kind == source.get("kind"), "arbitration source kind does not match source.kind")

    required_lanes = arbitration.get("required_lanes")
    expected_lanes = ["head"] if pull_request_number == "workflow_dispatch" else ["head", "merge"]
    require(required_lanes == expected_lanes, "arbitration required lane set drift")

    key = arbitration.get("key")
    expected_key = f"{pull_request_number}:{head_sha}:{source_kind}"
    require(
        isinstance(key, str) and key == expected_key,
        "arbitration key does not match its immutable components",
    )


def _validate_github_identity_intrinsic(
    identity: Mapping[str, Any], source: Mapping[str, Any]
) -> None:
    """Validate the API identity payload embedded in the receipt.

    The workflow obtains this payload from the GitHub commit/PR APIs.  Keeping
    the checks here as well prevents a caller from replacing the schema with a
    permissive variant or from binding an identity artifact to a different
    source head.  The signature sentinel is intentionally *false*: signing
    custody remains an external control boundary and is never inferred from a
    REST verification response.
    """

    require(
        set(identity) == set(GITHUB_IDENTITY_FIELDS),
        "receipt GitHub identity fields drift",
    )
    digest = identity.get("artifact_digest")
    require(
        isinstance(digest, str) and SHA256_DIGEST.fullmatch(digest) is not None,
        "GitHub identity artifact digest is malformed",
    )
    source_sha = _check_sha40(identity.get("source_sha"), "github_identity.source_sha")
    require(
        source_sha == source.get("head"),
        "GitHub identity artifact source SHA must equal receipt source.head",
    )

    repository_id = identity.get("repository_id")
    require(
        type(repository_id) is int and repository_id == REPOSITORY_ID,
        "GitHub identity repository ID drift",
    )
    repository_full_name = _check_non_empty(
        identity.get("repository_full_name"), "github_identity.repository_full_name"
    )
    require(
        repository_full_name == REPOSITORY == source.get("repository"),
        "GitHub identity repository full name drift",
    )

    owner = _check_non_empty(
        identity.get("expected_head_owner"), "github_identity.expected_head_owner"
    )
    head_owner = _check_non_empty(identity.get("head_owner"), "github_identity.head_owner")
    require(
        owner == head_owner == REPOSITORY_OWNER,
        "GitHub repository owner fields disagree",
    )

    expected_ratifier_login = _check_non_empty(
        identity.get("expected_ratifier_login"),
        "github_identity.expected_ratifier_login",
    )
    expected_ratifier_id = identity.get("expected_ratifier_id")
    require(
        expected_ratifier_login == RATIFIER_LOGIN
        and type(expected_ratifier_id) is int
        and expected_ratifier_id == RATIFIER_ID,
        "GitHub designated ratifier policy drift",
    )
    author_login = _check_non_empty(identity.get("author_login"), "github_identity.author_login")
    committer_login = _check_non_empty(identity.get("committer_login"), "github_identity.committer_login")
    require(
        author_login == committer_login == expected_ratifier_login,
        "GitHub author/committer do not match designated ratifier",
    )

    for field in ("author_id", "committer_id"):
        value = identity.get(field)
        # bool is an int subclass; reject it explicitly because the API emits
        # numeric account IDs and a boolean would be an ambiguous forgery.
        require(
            type(value) is int and value == expected_ratifier_id,
            f"github_identity.{field} does not match designated ratifier account ID",
        )

    verification = identity.get("verification")
    require(isinstance(verification, Mapping), "GitHub identity verification object is missing")
    require(
        type(verification.get("verified")) is bool,
        "github_identity.verification.verified must be boolean",
    )
    reason = verification.get("reason")
    require(
        reason is None or (isinstance(reason, str) and reason.strip()),
        "github_identity.verification.reason must be a string or null",
    )
    require(identity.get("identity_verified") is True, "GitHub identity verification did not pass")
    require(identity.get("signature_required") is False, "GitHub signature requirement sentinel drift")


def _validate_github_identity_artifact(
    artifact: Mapping[str, Any],
    raw: bytes,
    receipt: Mapping[str, Any],
    expected_head_owner: str | None = None,
) -> None:
    """Bind the raw GitHub API identity artifact to the receipt.

    The artifact intentionally omits its own digest; the digest lives in the
    receipt and is computed over the exact bytes uploaded by the workflow.
    Every remaining field is copied into the receipt and compared recursively,
    so changing an API login, account ID or verification reason invalidates the
    receipt even when the file remains valid JSON.
    """

    identity = receipt.get("github_identity")
    require(isinstance(identity, Mapping), "receipt GitHub identity section is missing")
    _verify_digest(identity.get("artifact_digest"), raw, "GitHub identity")
    expected_fields = set(GITHUB_IDENTITY_ARTIFACT_FIELDS)
    require(
        set(artifact) == expected_fields,
        "GitHub identity artifact fields drift",
    )
    for field in GITHUB_IDENTITY_ARTIFACT_FIELDS:
        require(
            artifact.get(field) == identity.get(field),
            f"GitHub identity field does not match receipt: {field}",
        )

    source = receipt.get("source")
    require(isinstance(source, Mapping), "receipt source is missing for GitHub identity binding")
    _validate_github_identity_intrinsic(identity, source)
    if expected_head_owner is not None:
        _check_non_empty(expected_head_owner, "expected head owner")
        require(
            identity.get("expected_head_owner") == expected_head_owner,
            "GitHub identity owner does not match expected head owner",
        )


def _validate_gates_intrinsic(gates: Mapping[str, Any]) -> None:
    require(gates.get("plan_python") == "PASS", "plan/python gate is not PASS")
    require(gates.get("root_rust_1_98") == "PASS", "root Rust 1.98 gate is not PASS")
    p0 = gates.get("p0")
    h02 = gates.get("h02")
    require(isinstance(p0, Mapping), "P0 gate is missing")
    require(isinstance(h02, Mapping), "H02 gate is missing")
    for key, expected in P0_GATE_VALUES.items():
        actual = _check_json_integer(p0.get(key), f"P0 gate {key}", minimum=0)
        require(actual == expected, "P0 gate counts or classification drift")
    for key, expected in H02_GATE_VALUES.items():
        actual = _check_json_integer(h02.get(key), f"H02 gate {key}", minimum=0)
        require(actual == expected, "H02 gate counts drift")
    require(SHA256_DIGEST.fullmatch(str(p0.get("artifact_digest"))) is not None, "P0 artifact digest is malformed")
    require(SHA256_DIGEST.fullmatch(str(h02.get("artifact_digest"))) is not None, "H02 artifact digest is malformed")


P0_GATE_FIELDS = (
    "runtime_socket_observed",
    "exact_head_compiled_source_bound",
    "best_effort_source_bound",
)
P0_GATE_VALUES = {"runtime_socket_observed": 11, "exact_head_compiled_source_bound": 2, "best_effort_source_bound": 1}
H02_GATE_FIELDS = ("executed_entries", "pass")
H02_GATE_VALUES = {"executed_entries": 24, "pass": 24}


def _validate_authority_intrinsic(receipt: Mapping[str, Any]) -> None:
    sentinels = {
        "independent_review": False,
        "qualification": False,
        "compatibility_claim": False,
        "selected_candidates": [],
        "selection_effect": "NONE",
        "production_authority": False,
        "migration_authority": False,
        "release_authority": False,
        "authority_effect": "NONE",
    }
    for key, expected in sentinels.items():
        require(receipt.get(key) == expected, f"authority sentinel drift: {key}")


def _read_artifact(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    candidate = _guard_path_components(Path(path), label)
    require(not candidate.is_symlink(), f"{label} artifact must not be a symlink")
    require(candidate.is_file(), f"{label} artifact is missing or not a regular file")
    try:
        raw = candidate.read_bytes()
        value = _strict_json(raw, f"{label} artifact")
    except OSError as error:
        raise ValidationError(f"{label} artifact is not readable JSON: {error}") from error
    require(isinstance(value, dict), f"{label} artifact must contain one JSON object")
    require(raw, f"{label} artifact is empty")
    return value, raw


def _verify_digest(expected: Any, raw: bytes, label: str) -> None:
    actual = sha256_digest(raw)
    require(expected == actual, f"{label} artifact digest does not match receipt")


def sha256_digest(raw: bytes) -> str:
    """Return the digest representation used by all V1.3.1 artifacts."""

    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_digest(value: Any) -> str:
    return sha256_digest(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    )


def _read_bytes(path: Path, label: str) -> bytes:
    candidate = _guard_path_components(Path(path), label)
    require(not candidate.is_symlink(), f"{label} must not be a symlink")
    require(candidate.is_file(), f"{label} is missing or not a regular file")
    try:
        raw = candidate.read_bytes()
    except OSError as error:
        raise ValidationError(f"cannot read {label}: {error}") from error
    require(raw, f"{label} is empty")
    return raw


def _validate_log_manifest(path: Path, expected_digest: Any) -> None:
    """Verify the digest-only local log inventory bound by the receipt."""

    path = _guard_path_components(Path(path), "raw log manifest")
    raw = _read_bytes(path, "raw log manifest")
    _verify_digest(expected_digest, raw, "raw log manifest")
    value = _strict_json(raw, "raw log manifest")
    require(isinstance(value, Mapping), "raw log manifest must be one object")
    schema = load_artifact_schema(
        LOG_MANIFEST_SCHEMA_PATH,
        LOG_MANIFEST_SCHEMA_ID,
        expected_uri=LOG_MANIFEST_SCHEMA_URI,
    )
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.path),
    )
    require(not errors, f"raw log manifest schema violation: {errors[0].message if errors else ''}")
    files = value.get("files")
    require(isinstance(files, list) and files, "raw log manifest files are missing")
    file_count = _check_json_integer(value.get("file_count"), "raw log manifest file_count", minimum=1)
    require(file_count == len(files), "raw log manifest file count drift")
    # The collector writes this file at
    # ``<evidence>/root/raw-log-manifest.json``.  Locate that evidence root
    # from the required layout and re-read every listed file.  Checking only
    # the manifest's own digest would allow a changed sidecar to be paired
    # with an unchanged inventory.
    evidence_root: Path | None = None
    for ancestor in (path.parent.parent, path.parent, *path.parents):
        candidate_root = _guard_path_components(ancestor, "raw log manifest evidence root").resolve()
        if (
            (candidate_root / "root/github-identity-verification.json").is_file()
            and (candidate_root / "p0/classified-result.json").is_file()
        ):
            evidence_root = candidate_root
            break
    require(evidence_root is not None, "raw log manifest evidence root cannot be resolved")

    paths: list[str] = []
    for entry in files:
        require(isinstance(entry, Mapping), "raw log manifest entry is malformed")
        file_path = entry.get("path")
        require(isinstance(file_path, str) and file_path.strip(), "raw log manifest path is malformed")
        require(not file_path.startswith("/"), "raw log manifest path is absolute")
        parts = Path(file_path).parts
        require(".." not in parts and file_path != ".", "raw log manifest path escapes evidence root")
        require(
            isinstance(entry.get("digest"), str)
            and SHA256_DIGEST.fullmatch(entry["digest"]) is not None,
            "raw log manifest file digest is malformed",
        )
        size = entry.get("size")
        require(
            type(size) is int and size >= 0,
            "raw log manifest file size is malformed",
        )
        relative_path = Path(file_path)
        require(not relative_path.is_absolute(), "raw log manifest path is absolute")
        require(".." not in relative_path.parts, "raw log manifest path escapes evidence root")
        file_candidate = _guard_path_components(
            evidence_root / relative_path, f"raw log manifest file {file_path}"
        )
        require(not file_candidate.is_symlink(), f"raw log manifest file is a symlink: {file_path}")
        resolved_file = file_candidate.resolve()
        try:
            resolved_file.relative_to(evidence_root)
        except ValueError as error:
            raise ValidationError(f"raw log manifest path escapes evidence root: {file_path}") from error
        require(resolved_file.is_file(), f"raw log manifest file is missing: {file_path}")
        try:
            file_raw = resolved_file.read_bytes()
        except OSError as error:
            raise ValidationError(f"raw log manifest file cannot be read: {file_path}") from error
        require(
            len(file_raw) == size,
            f"raw log manifest file size drift: {file_path}",
        )
        actual_digest = sha256_digest(file_raw)
        require(actual_digest == entry.get("digest"), f"raw log manifest file digest drift: {file_path}")
        paths.append(file_path)
    require(paths == sorted(paths), "raw log manifest paths are not canonicalized")
    require(len(paths) == len(set(paths)), "raw log manifest contains duplicate paths")
    require(REQUIRED_LOG_MANIFEST_PATHS <= set(paths), "raw log manifest omits required evidence files")

    # The manifest is a snapshot taken immediately before the technical
    # receipt is emitted.  Receipt/job-validation files are intentionally
    # created after that snapshot; every other regular file in the evidence
    # root must be represented exactly once.  This closes the gap where an
    # unlisted sidecar could be uploaded without ever being digest-bound.
    try:
        manifest_relative = path.resolve().relative_to(evidence_root).as_posix()
    except ValueError as error:
        raise ValidationError("raw log manifest is outside its evidence root") from error
    post_capture_paths = {
        manifest_relative,
        "root/github-job-identity.json",
        "technical-completion-receipt.json",
        "root/technical-receipt-validation.log",
    }
    observed: set[str] = set()
    for candidate in sorted(evidence_root.rglob("*")):
        candidate = _guard_path_components(candidate, "raw log manifest evidence entry")
        if candidate.is_symlink():
            raise ValidationError(f"raw log manifest evidence contains a symlink: {candidate}")
        if candidate.is_dir():
            continue
        require(
            candidate.is_file(),
            f"raw log manifest evidence contains a non-regular entry: {candidate}",
        )
        relative = candidate.relative_to(evidence_root).as_posix()
        observed.add(relative)
    missing = set(paths) - observed
    unexpected = observed - set(paths) - post_capture_paths
    require(not missing, f"raw log manifest inventory is missing files: {sorted(missing)}")
    require(not unexpected, f"raw log manifest inventory has unlisted files: {sorted(unexpected)}")


def _validate_job_identity_artifact(
    artifact: Mapping[str, Any],
    raw: bytes,
    api_raw: bytes,
    receipt: Mapping[str, Any],
    source: Mapping[str, Any],
    log_manifest: Path,
) -> None:
    """Bind normalized Actions API identity, raw API bytes and local logs."""

    runner = receipt.get("runner")
    require(isinstance(runner, Mapping), "receipt runner is missing for job identity binding")
    _verify_digest(runner.get("artifact_digest"), raw, "GitHub job identity")
    schema = load_artifact_schema(
        JOB_IDENTITY_SCHEMA_PATH,
        JOB_IDENTITY_SCHEMA_ID,
        expected_uri=JOB_IDENTITY_SCHEMA_URI,
    )
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(artifact),
        key=lambda error: list(error.path),
    )
    require(not errors, f"GitHub job identity schema violation: {errors[0].message if errors else ''}")
    require(
        set(artifact) == set(JOB_IDENTITY_ARTIFACT_FIELDS),
        "GitHub job identity artifact fields drift",
    )
    # ``schema`` identifies the auxiliary artifact and is not copied into the
    # receipt.  ``runner_name`` is the one provider-vocabulary rename; all
    # remaining fields have the same spelling in both records.
    require(artifact.get("schema") == JOB_IDENTITY_SCHEMA_ID, "GitHub job identity schema drift")
    require(artifact.get("workflow_name") == WORKFLOW_NAME, "GitHub job identity workflow name is not canonical")
    require(artifact.get("job") == JOB_NAME, "GitHub job identity job is not canonical")
    require(
        artifact.get("job_name") == f"{JOB_NAME} ({source.get('kind')})",
        "GitHub job identity job name is not canonical for source lane",
    )
    for artifact_field, receipt_field in (
        ("runner_name", "name"),
        *(
            (field, field)
            for field in JOB_IDENTITY_ARTIFACT_FIELDS
            if field not in {"schema", "runner_name"}
        ),
    ):
        require(
            artifact.get(artifact_field) == runner.get(receipt_field),
            f"GitHub job identity field does not match receipt: {artifact_field}",
        )

    _verify_digest(artifact.get("api_response_digest"), api_raw, "GitHub Actions API response")
    api_value = _strict_json(api_raw, "GitHub Actions API response")
    require(isinstance(api_value, Mapping), "GitHub Actions API response must be one object")
    jobs = api_value.get("jobs")
    require(isinstance(jobs, list), "GitHub Actions API jobs list is missing")
    # The workflow requests one page with ``per_page=100``.  A self-consistent
    # but truncated response must not be accepted merely because it still
    # contains the selected job; ``total_count`` is the provider's pagination
    # completeness witness for this bounded job set.
    total_count = _check_json_integer(api_value.get("total_count"), "GitHub Actions API total_count", minimum=0)
    require(
        total_count == len(jobs),
        "GitHub Actions API response is incomplete or paginated",
    )
    require(jobs, "GitHub Actions API jobs list is empty")
    try:
        job_id_int = int(str(artifact["job_id"]))
        run_id_int = int(str(artifact["run_id"]))
        run_attempt_int = int(str(artifact["run_attempt"]))
    except (TypeError, ValueError) as error:
        raise ValidationError("GitHub job identity numeric fields are malformed") from error
    matches = [
        job
        for job in jobs
        if isinstance(job, Mapping)
        and type(job.get("id")) is int
        and job.get("id") >= 1
        and job.get("id") == job_id_int
    ]
    require(len(matches) == 1, "GitHub Actions API response does not contain exactly one bound job")
    api_job = matches[0]
    for field, expected in (
        ("run_id", run_id_int),
        ("run_attempt", run_attempt_int),
    ):
        actual = _check_json_integer(api_job.get(field), f"GitHub API job {field}", minimum=1)
        require(actual == expected, f"GitHub API job {field} does not match normalized identity")
    for field, expected in (
        ("name", artifact["job_name"]),
        ("workflow_name", artifact["workflow_name"]),
        ("head_sha", artifact["head_sha"]),
        ("runner_name", artifact["runner_name"]),
    ):
        require(api_job.get(field) == expected, f"GitHub API job {field} does not match normalized identity")
    runner_id = _check_json_integer(
        api_job.get("runner_id"), "GitHub API job runner_id", minimum=1
    )
    require(runner_id == int(str(artifact["runner_id"])), "GitHub API runner ID drift")
    runner_group_id = _check_json_integer(
        api_job.get("runner_group_id"), "GitHub API job runner_group_id", minimum=0
    )
    require(
        runner_group_id == int(str(artifact["runner_group_id"])),
        "GitHub API runner group ID drift",
    )
    require(api_job.get("runner_group_name") == artifact["runner_group"], "GitHub API runner group drift")
    require(api_job.get("status") == artifact["job_status"], "GitHub API job status drift")
    require(api_job.get("conclusion") == artifact["job_conclusion"], "GitHub API job conclusion drift")
    require(api_job.get("started_at") == artifact["job_started_at"], "GitHub API job start timestamp drift")
    require(api_job.get("completed_at") == artifact["job_completed_at"], "GitHub API job completion timestamp drift")
    api_job_started = _check_timestamp(api_job.get("started_at"), "GitHub API job started_at", allow_null=False)
    api_job_completed = _check_timestamp(api_job.get("completed_at"), "GitHub API job completed_at")
    if api_job_completed is not None:
        require(
            _timestamp_instant(api_job_completed, "GitHub API job completed_at")
            >= _timestamp_instant(api_job_started, "GitHub API job started_at"),
            "GitHub API job completes before it starts",
        )
    labels = api_job.get("labels")
    require(
        isinstance(labels, list)
        and labels
        and all(isinstance(label, str) and label.strip() for label in labels)
        and len(labels) == len(set(labels)),
        "GitHub API runner labels are missing or malformed",
    )
    require(
        RUNNER_LABEL in labels,
        "GitHub API runner labels do not include the canonical image label",
    )
    require(
        artifact.get("runner_labels") == labels,
        "GitHub API runner labels do not match normalized identity",
    )
    raw_steps = api_job.get("steps")
    require(isinstance(raw_steps, list) and raw_steps, "GitHub API job steps are missing")
    normalized_steps: list[dict[str, Any]] = []
    numbers: set[int] = set()
    names: set[str] = set()
    for index, raw_step in enumerate(raw_steps):
        require(isinstance(raw_step, Mapping), f"GitHub API job step {index} is malformed")
        number = raw_step.get("number")
        require(type(number) is int and number >= 1, f"GitHub API job step {index} number is malformed")
        name = _check_non_empty(raw_step.get("name"), f"GitHub API job step {index} name")
        require(number not in numbers, f"GitHub API job step number is duplicated: {number}")
        require(name not in names, f"GitHub API job step name is duplicated: {name}")
        numbers.add(number)
        names.add(name)
        provider_status = raw_step.get("status")
        # The live GitHub jobs API spells a not-yet-started step ``pending``.
        # The normalized receipt has one canonical pre-execution state,
        # ``queued``. Preserve the exact API bytes/digest, but compare the
        # artifact against the same canonical status used by the collector.
        status = "queued" if provider_status == "pending" else provider_status
        conclusion = raw_step.get("conclusion")
        outcome = _step_outcome(status, conclusion)
        started_at = _check_timestamp(raw_step.get("started_at"), f"GitHub API job step {name} started_at")
        completed_at = _check_timestamp(raw_step.get("completed_at"), f"GitHub API job step {name} completed_at")
        if status == "completed":
            require(started_at is not None and completed_at is not None, f"GitHub API completed step {name} lacks timestamps")
            require(
                _timestamp_instant(completed_at, f"GitHub API job step {name} completed_at")
                >= _timestamp_instant(started_at, f"GitHub API job step {name} started_at"),
                f"GitHub API job step {name} completes before it starts",
            )
        else:
            require(completed_at is None, f"GitHub API non-completed step {name} has completion timestamp")
        normalized_steps.append(
            {
                "number": number,
                "name": name,
                "status": status,
                "conclusion": conclusion,
                "started_at": started_at,
                "completed_at": completed_at,
                "outcome": outcome,
            }
        )
    require(normalized_steps == artifact.get("steps"), "GitHub API job step table does not match normalized identity")
    require(
        [step["number"] for step in normalized_steps]
        == sorted(step["number"] for step in normalized_steps),
        "GitHub API job steps are not in execution order",
    )
    require(
        [step["name"] for step in normalized_steps[: len(CANONICAL_REQUIRED_STEP_NAMES)]]
        == list(CANONICAL_REQUIRED_STEP_NAMES),
        "GitHub API required steps are not the canonical execution prefix",
    )
    require(artifact.get("required_step_names") == list(CANONICAL_REQUIRED_STEP_NAMES), "GitHub required step list drift")
    by_name = {step["name"]: step for step in normalized_steps}
    for required_name in CANONICAL_REQUIRED_STEP_NAMES:
        require(required_name in by_name, f"GitHub API job omits required step: {required_name}")
        require(by_name[required_name]["outcome"] == "PASS", f"GitHub API required step did not pass: {required_name}")
    require(artifact.get("step_outcomes_digest") == _canonical_digest(normalized_steps), "GitHub API step digest drift")
    require(artifact.get("head_sha") == source.get("head"), "GitHub job identity head SHA does not match receipt source")
    require(artifact.get("source_kind") == source.get("kind"), "GitHub job identity source kind does not match receipt source")
    _validate_log_manifest(log_manifest, artifact.get("raw_log_manifest_digest"))


_H02_RUNNER_MODULE: Any | None = None


def _load_h02_runner() -> Any:
    """Load the canonical H02 tuple definitions from the repository runner."""

    global _H02_RUNNER_MODULE
    if _H02_RUNNER_MODULE is not None:
        return _H02_RUNNER_MODULE
    path = _guard_path_components(
        ROOT / "scripts/h02_exact_head_matrix_v1.py", "canonical H02 runner"
    )
    try:
        spec = importlib.util.spec_from_file_location("heptabao_h02_matrix_contract", path)
        require(spec is not None and spec.loader is not None, "cannot load canonical H02 runner")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as error:
        raise ValidationError(f"cannot load canonical H02 runner: {error}") from error
    _H02_RUNNER_MODULE = module
    return module


def _validate_h02_entry_tuple(entry: Mapping[str, Any], *, expected_manifest: Path) -> None:
    """Recompute one H02 tuple against the exact-head runner definitions."""

    entry_id = entry.get("entry_id")
    require(isinstance(entry_id, str), "H02 entry_id must be a string")
    match = H02_ENTRY_ID_PATTERN.fullmatch(entry_id)
    require(match is not None, f"H02 entry_id is not canonical: {entry_id!r}")
    kind = match.group("kind")
    toolchain = match.group("toolchain")
    seed = "0x" + match.group("seed")
    require(toolchain in H02_TOOLCHAINS, "H02 entry toolchain is not canonical")
    require(seed in H02_SEEDS, "H02 entry seed is not canonical")
    require(entry.get("kind") == kind, "H02 entry kind does not match entry_id")
    require(entry.get("toolchain") == toolchain, "H02 entry toolchain does not match entry_id")
    require(entry.get("seed") == seed, "H02 entry seed does not match entry_id")
    require(entry.get("binary") == H02_BINARY_BY_KIND[kind], "H02 entry binary is not canonical")

    runner = _load_h02_runner()
    require(
        {probe.kind: probe.binary for probe in runner.PROBES} == H02_BINARY_BY_KIND,
        "H02 runner binary definitions drift from receipt canonical matrix",
    )
    try:
        runner.validate_entry_tuple(
            entry,
            expected_manifest=expected_manifest,
            require_runner_flags=True,
        )
    except runner.ValidationError as error:
        raise ValidationError(f"H02 entry tuple drift: {error}") from error


def _validate_p0_artifact(
    artifact: Mapping[str, Any],
    raw: bytes,
    receipt: Mapping[str, Any],
) -> None:
    require(artifact.get("schema") == P0_SCHEMA_ID, "P0 artifact schema drift")
    require(artifact.get("result") == "PASS", "P0 artifact result is not PASS")
    require(artifact.get("evidence_result") == P0_EVIDENCE_RESULT, "P0 evidence classification drift")
    require(artifact.get("qualification") is False, "P0 artifact qualification must remain false")
    require(artifact.get("compatibility_claim") is False, "P0 artifact compatibility claim must remain false")
    require(artifact.get("authority_effect") == "NONE", "P0 artifact authority effect must remain NONE")
    counts = artifact.get("counts")
    require(isinstance(counts, Mapping), "P0 artifact counts are missing")
    for key, expected in P0_COUNTS.items():
        actual = _check_json_integer(counts.get(key), f"P0 artifact counts.{key}", minimum=0)
        require(actual == expected, "P0 artifact counts drift")

    cases = artifact.get("cases")
    require(isinstance(cases, list) and len(cases) == 14, "P0 artifact must contain 14 cases")
    ids = [case.get("case_id") if isinstance(case, Mapping) else None for case in cases]
    require(all(isinstance(case_id, str) for case_id in ids), "P0 artifact case IDs are malformed")
    require(set(ids) == P0_CASES and len(set(ids)) == len(ids), "P0 artifact case coverage drift")
    for case in cases:
        require(isinstance(case, Mapping), "P0 artifact case must be an object")
        case_id = case["case_id"]
        require(case.get("status") == "PASS", f"P0 case {case_id} is not PASS")
        if case_id in P0_RUNTIME_CASES:
            require(case.get("evidence_class") == "RUNTIME_SOCKET_OBSERVED", f"P0 case {case_id} runtime class drift")
            require(case.get("execution_status") == "EXECUTED_PASS", f"P0 case {case_id} execution status drift")
        elif case_id in P0_SOURCE_CASES:
            require(case.get("evidence_class") == "EXACT_HEAD_COMPILED_SOURCE_BOUND", f"P0 case {case_id} source class drift")
            require(case.get("execution_status") == "SOURCE_BOUND_PASS", f"P0 case {case_id} execution status drift")
        else:
            require(case.get("evidence_class") == "BEST_EFFORT_CONTROLLED_DROP_SOURCE_BOUND", f"P0 case {case_id} best-effort class drift")
            require(case.get("execution_status") == "SOURCE_BOUND_BEST_EFFORT_PASS", f"P0 case {case_id} execution status drift")

    model = artifact.get("evidence_model")
    require(isinstance(model, Mapping), "P0 evidence model is missing")
    require(model.get("runtime_observed_case_ids") == sorted(P0_RUNTIME_CASES), "P0 runtime case model drift")
    require(model.get("exact_head_compiled_source_bound_case_ids") == sorted(P0_SOURCE_CASES), "P0 source-bound case model drift")
    require(model.get("best_effort_source_bound_case_ids") == sorted(P0_BEST_EFFORT_CASES), "P0 best-effort case model drift")
    require(model.get("source_presence_is_runtime_execution") is False, "P0 source presence cannot be runtime execution")

    source = artifact.get("source")
    receipt_source = receipt["source"]
    require(isinstance(source, Mapping), "P0 artifact source binding is missing")
    require(source.get("repository") == REPOSITORY, "P0 artifact repository identity drift")
    require(source.get("commit") == receipt_source["commit"], "P0 artifact commit does not match receipt")
    require(source.get("tree") == receipt_source["tree"], "P0 artifact tree does not match receipt")
    require(source.get("clean_tree") is True, "P0 artifact source tree is not clean")
    _verify_digest(receipt["gates"]["p0"]["artifact_digest"], raw, "P0")


def _resolve_h02_evidence_file(root: Path, declared: Any, label: str) -> Path:
    """Resolve one matrix sidecar beneath an explicit evidence root.

    Artifact downloads are untrusted input. Reject absolute/traversing paths,
    symlinks and non-regular files before reading bytes, so a digest cannot be
    rebound to a different file through an alias.
    """

    root = _guard_path_components(Path(root), "H02 evidence root")
    require(not root.is_symlink(), "H02 evidence root must not be a symlink")
    require(root.is_dir(), "H02 evidence root is missing or not a directory")
    require(isinstance(declared, str) and declared.strip(), f"{label} path is missing")
    relative = Path(declared)
    require(not relative.is_absolute(), f"{label} path must be relative")
    require(".." not in relative.parts, f"{label} path may not contain '..'")
    candidate = _guard_path_components(root / relative, label)
    require(not candidate.is_symlink(), f"{label} file must not be a symlink")
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise ValidationError(f"{label} path escapes evidence root") from error
    require(resolved.is_file(), f"{label} file is missing or not a regular file")
    return resolved


def _validate_h02_file_bindings(
    artifact: Mapping[str, Any],
    *,
    evidence_dir: Path,
    manifest_path: Path,
    lock_path: Path,
) -> None:
    """Recompute dependency and all H02 sidecar digests from disk."""

    dependency = artifact.get("dependency_binding")
    require(isinstance(dependency, Mapping), "H02 dependency binding is missing")
    require(
        dependency.get("manifest_path") == H02_MANIFEST_PATH,
        "H02 manifest path is not canonical",
    )
    require(
        dependency.get("lock_path") == H02_LOCK_PATH,
        "H02 lock path is not canonical",
    )

    # The summary's dependency paths are repository-relative names. Bind the
    # bytes in the validator checkout, rejecting symlink substitutions.
    for path, expected, label in (
        (manifest_path, dependency.get("manifest_digest"), "H02 manifest"),
        (lock_path, dependency.get("lock_digest"), "H02 Cargo.lock"),
    ):
        path = _guard_path_components(Path(path), label)
        require(not path.is_symlink(), f"{label} must not be a symlink")
        require(path.is_file(), f"{label} is missing or not a regular file")
        try:
            actual = sha256_digest(path.read_bytes())
        except OSError as error:
            raise ValidationError(f"{label} cannot be read: {error}") from error
        require(expected == actual, f"{label} digest does not match actual checkout bytes")

    entries = artifact.get("entries")
    require(isinstance(entries, list), "H02 entries are missing")
    seen: set[Path] = set()
    for entry in entries:
        require(isinstance(entry, Mapping), "H02 entry must be an object")
        entry_id = entry.get("entry_id")
        require(isinstance(entry_id, str) and entry_id, "H02 entry_id is missing")
        for suffix, path_field, digest_field in (
            ("stdout", "stdout_path", "stdout_digest"),
            ("stderr", "stderr_path", "stderr_digest"),
            ("exit", "exit_path", "exit_digest"),
        ):
            expected_name = f"{entry_id}.{suffix}"
            declared = entry.get(path_field)
            require(
                declared == expected_name,
                f"H02 entry {entry_id} {path_field} must be {expected_name!r}",
            )
            path = _resolve_h02_evidence_file(
                evidence_dir, declared, f"H02 entry {entry_id} {suffix}"
            )
            require(path not in seen, f"H02 entry artifact path is duplicated: {path}")
            seen.add(path)
            expected_digest = entry.get(digest_field)
            require(
                isinstance(expected_digest, str)
                and SHA256_DIGEST.fullmatch(expected_digest) is not None,
                f"H02 entry {entry_id} {digest_field} is malformed",
            )
            try:
                raw = path.read_bytes()
            except OSError as error:
                raise ValidationError(
                    f"H02 entry {entry_id} {suffix} file cannot be read: {error}"
                ) from error
            require(
                sha256_digest(raw) == expected_digest,
                f"H02 entry {entry_id} {suffix} digest does not match actual bytes",
            )
            if suffix == "exit":
                exit_code = entry.get("exit_code")
                require(
                    exit_code is None or type(exit_code) is int,
                    f"H02 entry {entry_id} exit_code is not a JSON integer or null",
                )
                expected_bytes = (
                    b"UNAVAILABLE\n"
                    if exit_code is None
                    else f"{exit_code}\n".encode("utf-8")
                )
                require(
                    raw == expected_bytes,
                    f"H02 entry {entry_id} exit sidecar content does not match exit_code",
                )
    require(len(seen) == 3 * len(entries), "H02 entry artifact paths are not unique")


def _validate_h02_artifact(
    artifact: Mapping[str, Any],
    raw: bytes,
    receipt: Mapping[str, Any],
    *,
    evidence_dir: Path | None = None,
    manifest_path: Path | None = None,
    lock_path: Path | None = None,
) -> None:
    require(artifact.get("schema") == H02_SCHEMA_ID, "H02 artifact schema drift")
    # Validate the complete nested summary against its canonical schema before
    # applying the stricter completion-only invariants below.
    schema = load_schema(
        ROOT / "schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json",
        expected_id=H02_SCHEMA_ID,
        expected_uri=H02_SCHEMA_URI,
    )
    errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(artifact), key=lambda error: list(error.path))
    require(not errors, f"H02 artifact schema violation: {errors[0].message if errors else ''}")

    require(artifact.get("result") == "PASS", "H02 artifact result is not PASS")
    counts = artifact.get("counts")
    require(isinstance(counts, Mapping), "H02 artifact counts are missing")
    for key, expected in H02_COUNTS.items():
        actual = _check_json_integer(counts.get(key), f"H02 artifact counts.{key}", minimum=0)
        require(actual == expected, "H02 artifact counts drift")
    require(artifact.get("runner_errors") == [], "H02 runner errors must be empty")
    for key, expected in (("qualification", False), ("compatibility_claim", False), ("selection_effect", "NONE"), ("authority_effect", "NONE")):
        require(artifact.get(key) == expected, f"H02 artifact authority sentinel drift: {key}")

    source = artifact.get("source_binding")
    receipt_source = receipt["source"]
    require(isinstance(source, Mapping), "H02 source binding is missing")
    require(source.get("repository") == REPOSITORY, "H02 artifact repository identity drift")
    require(source.get("commit") == receipt_source["commit"], "H02 artifact commit does not match receipt")
    require(source.get("tree") == receipt_source["tree"], "H02 artifact tree does not match receipt")
    require(source.get("clean_tree") is True, "H02 artifact source tree is not clean")

    dependency = artifact.get("dependency_binding")
    require(isinstance(dependency, Mapping), "H02 dependency binding is missing")

    # Keep the manifest/lock names declared by the untrusted summary separate
    # from the files supplied by the caller.  The aggregate validator checks a
    # receipt from two different checkouts (head and synthetic merge); it
    # materializes each lane's Cargo.toml/Cargo.lock with ``git show`` and
    # passes those files here.  Reusing the declared relative string as the
    # filesystem path would silently read the aggregate checkout instead and
    # either reject a legitimate head/merge delta or bind the digest to the
    # wrong source tree.
    declared_manifest_path = dependency.get("manifest_path")
    declared_lock_path = dependency.get("lock_path")
    require(
        declared_manifest_path == H02_MANIFEST_PATH,
        "H02 manifest path is not canonical",
    )
    require(
        declared_lock_path == H02_LOCK_PATH,
        "H02 lock path is not canonical",
    )

    # ``expected_manifest`` is also lane-specific.  The tuple checker accepts
    # the canonical repository-relative spelling (and the validator checkout's
    # canonical absolute spelling) in addition to this supplied path, so a
    # receipt produced in a separate runner workspace remains portable while
    # an aggregate job can still bind the dependency bytes to this lane's
    # immutable commit.
    manifest_file = (
        Path(manifest_path)
        if manifest_path is not None
        else ROOT / declared_manifest_path
    )
    lock_file = Path(lock_path) if lock_path is not None else ROOT / declared_lock_path
    expected_manifest = manifest_file

    matrix = artifact.get("matrix")
    require(isinstance(matrix, Mapping), "H02 matrix section is missing")
    required_entry_count = _check_json_integer(
        matrix.get("required_entry_count"),
        "H02 matrix required_entry_count",
        minimum=0,
    )
    executed_entry_count = _check_json_integer(
        matrix.get("executed_entry_count"),
        "H02 matrix executed_entry_count",
        minimum=0,
    )
    require(required_entry_count == 24, "H02 required entry count drift")
    require(executed_entry_count == 24, "H02 executed entry count drift")
    require(matrix.get("toolchains") == list(H02_TOOLCHAINS), "H02 toolchain set drift")
    require(matrix.get("seeds") == list(H02_SEEDS), "H02 seed set drift")
    require(matrix.get("kinds") == list(H02_KINDS), "H02 probe-kind set drift")
    for field in ("missing_entry_ids", "unexpected_entry_ids", "duplicate_entry_ids"):
        require(matrix.get(field) == [], f"H02 {field} must be empty")

    entries = artifact.get("entries")
    require(isinstance(entries, list) and len(entries) == 24, "H02 artifact must contain 24 entries")
    ids = [entry.get("entry_id") if isinstance(entry, Mapping) else None for entry in entries]
    require(all(isinstance(entry_id, str) for entry_id in ids), "H02 entry IDs are malformed")
    require(set(ids) == H02_ENTRY_IDS and len(set(ids)) == len(ids), "H02 entry coverage drift")
    for entry in entries:
        require(isinstance(entry, Mapping), "H02 entry must be an object")
        _validate_h02_entry_tuple(entry, expected_manifest=expected_manifest)
        require(entry.get("process_started") is True, f"H02 entry {entry.get('entry_id')} did not start")
        exit_code = entry.get("exit_code")
        require(
            type(exit_code) is int and exit_code == 0,
            f"H02 entry {entry.get('entry_id')} exit code is not zero",
        )
        require(entry.get("timed_out") is False, f"H02 entry {entry.get('entry_id')} timed out")
        require(entry.get("conclusion") == "PASS", f"H02 entry {entry.get('entry_id')} conclusion drift")
        require(entry.get("application_status") == "EXECUTED_PASS", f"H02 entry {entry.get('entry_id')} application status drift")
        require(entry.get("validation_errors") == [], f"H02 entry {entry.get('entry_id')} has validation errors")

    require(
        evidence_dir is not None,
        "H02 evidence directory is required for digest-bound completion validation",
    )
    _validate_h02_file_bindings(
        artifact,
        evidence_dir=Path(evidence_dir),
        manifest_path=manifest_file,
        lock_path=lock_file,
    )
    _verify_digest(receipt["gates"]["h02"]["artifact_digest"], raw, "H02")


def validate(
    receipt: Mapping[str, Any],
    *,
    expected_source_kind: str | None = None,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_head: str | None = None,
    expected_base: str | None = None,
    expected_event_merge: str | None = None,
    expected_head_owner: str | None = None,
    expected_arbitration_key: str | None = None,
    expected_runner: Mapping[str, Any] | None = None,
    p0_artifact: Path | None = None,
    h02_artifact: Path | None = None,
    h02_evidence_dir: Path | None = None,
    h02_manifest_path: Path | None = None,
    h02_lock_path: Path | None = None,
    github_identity_artifact: Path | None = None,
    github_job_artifact: Path | None = None,
    github_job_api: Path | None = None,
    raw_log_manifest: Path | None = None,
    require_artifacts: bool = True,
    schema: Mapping[str, Any] | None = None,
) -> None:
    """Validate one receipt and (by default) all digest-bound artifacts.

    ``require_artifacts=False`` is provided only for unit-level structural
    inspection.  The command-line entry point always requires artifacts so a
    forged digest cannot be presented as a technical completion.
    """

    require(isinstance(receipt, Mapping), "receipt must be one JSON object")
    active_schema = schema if schema is not None else load_schema()
    require(isinstance(active_schema, Mapping), "receipt schema must be one object")
    _schema_identity(
        active_schema,
        expected_id=SCHEMA_ID,
        expected_uri=SCHEMA_URI,
        label="receipt schema",
    )
    _schema_validate(receipt, active_schema)
    require(receipt.get("schema") == SCHEMA_ID, "receipt schema ID drift")

    source = receipt["source"]
    runner = receipt["runner"]
    gates = receipt["gates"]
    require(isinstance(source, Mapping), "receipt source must be an object")
    require(isinstance(runner, Mapping), "receipt runner must be an object")
    require(isinstance(gates, Mapping), "receipt gates must be an object")
    _validate_source_intrinsic(source)
    _validate_runner_intrinsic(runner, source)
    arbitration = receipt.get("arbitration")
    require(isinstance(arbitration, Mapping), "receipt arbitration section is missing")
    _validate_arbitration_intrinsic(arbitration, source)
    identity = receipt.get("github_identity")
    require(isinstance(identity, Mapping), "receipt GitHub identity section is missing")
    _validate_github_identity_intrinsic(identity, source)
    _validate_gates_intrinsic(gates)
    _validate_authority_intrinsic(receipt)

    if expected_source_kind is not None:
        require(expected_source_kind in {"head", "merge"}, "expected source kind must be head or merge")
        require(source["kind"] == expected_source_kind, "receipt source kind does not match expected event lane")
    for label, expected, actual in (
        ("commit", expected_commit, source["commit"]),
        ("tree", expected_tree, source["tree"]),
        ("head", expected_head, source["head"]),
        ("base", expected_base, source["base"]),
        ("event_merge", expected_event_merge, source["event_merge"]),
    ):
        if expected is None:
            continue
        if label == "base":
            _check_optional_sha40(expected, f"expected source.{label}")
        else:
            _check_sha40(expected, f"expected source.{label}")
        require(actual == expected, f"receipt source.{label} does not match expected value")

    if expected_arbitration_key is not None:
        require(
            isinstance(expected_arbitration_key, str)
            and expected_arbitration_key == arbitration["key"],
            "receipt arbitration key does not match expected workflow key",
        )

    if expected_runner is not None:
        unknown = set(expected_runner) - set(RUNNER_FIELDS)
        require(not unknown, f"unknown expected runner fields: {sorted(unknown)}")
        for field, expected in expected_runner.items():
            # API-derived expectations are intentionally allowed to include
            # nulls and structured step lists.  Comparing the complete value
            # (rather than coercing everything to a string) prevents a caller
            # from making ``None``/list fields unverifiable while retaining
            # exact equality for numeric identity strings and timestamps.
            require(field in runner, f"receipt runner.{field} is missing")
            require(runner[field] == expected, f"receipt runner.{field} does not match expected value")

    supplied_artifacts = {
        "p0": p0_artifact is not None,
        "h02": h02_artifact is not None,
        "github_identity": github_identity_artifact is not None,
    }
    require(
        len(set(supplied_artifacts.values())) == 1,
        "P0, H02 and GitHub identity artifacts must be supplied together",
    )
    supplied_job_artifacts = {
        "github_job": github_job_artifact is not None,
        "github_job_api": github_job_api is not None,
        "raw_log_manifest": raw_log_manifest is not None,
    }
    require(
        len(set(supplied_job_artifacts.values())) == 1,
        "GitHub job identity, API response and raw log manifest must be supplied together",
    )
    if require_artifacts:
        require(
            p0_artifact is not None
            and h02_artifact is not None
            and github_identity_artifact is not None,
            "digest-bound P0, H02 and GitHub identity artifacts are required",
        )
        require(
            github_job_artifact is not None
            and github_job_api is not None
            and raw_log_manifest is not None,
            "numeric GitHub job identity and step/log artifacts are required",
        )
    if (
        p0_artifact is not None
        and h02_artifact is not None
        and github_identity_artifact is not None
    ):
        p0, p0_raw = _read_artifact(p0_artifact, "P0")
        h02, h02_raw = _read_artifact(h02_artifact, "H02")
        github_identity, github_identity_raw = _read_artifact(
            github_identity_artifact, "GitHub identity"
        )
        _validate_p0_artifact(p0, p0_raw, receipt)
        resolved_h02_evidence_dir = (
            Path(h02_evidence_dir)
            if h02_evidence_dir is not None
            else Path(h02_artifact).parent
        )
        _validate_h02_artifact(
            h02,
            h02_raw,
            receipt,
            evidence_dir=resolved_h02_evidence_dir,
            manifest_path=h02_manifest_path,
            lock_path=h02_lock_path,
        )
        _validate_github_identity_artifact(
            github_identity,
            github_identity_raw,
            receipt,
            expected_head_owner=expected_head_owner,
        )
        if github_job_artifact is not None and github_job_api is not None and raw_log_manifest is not None:
            github_job, github_job_raw = _read_artifact(
                github_job_artifact, "GitHub job identity"
            )
            github_job_api_raw = _read_bytes(github_job_api, "GitHub Actions API response")
            _validate_job_identity_artifact(
                github_job,
                github_job_raw,
                github_job_api_raw,
                receipt,
                source,
                raw_log_manifest,
            )
    elif expected_head_owner is not None:
        _check_non_empty(expected_head_owner, "expected head owner")
        require(
            identity.get("expected_head_owner") == expected_head_owner,
            "GitHub identity owner does not match expected head owner",
        )


def load_receipt(path: Path) -> dict[str, Any]:
    path = _guard_path_components(Path(path), "receipt")
    require(not path.is_symlink(), "receipt must not be a symlink")
    require(path.is_file(), "receipt is missing or not a regular file")
    try:
        value = _strict_json(path.read_bytes(), f"receipt {path}")
    except OSError as error:
        raise ValidationError(f"cannot read receipt {path}: {error}") from error
    require(isinstance(value, dict), "receipt must contain one JSON object")
    return value


def _runner_expectations(args: argparse.Namespace) -> dict[str, str] | None:
    fields = {
        "run_id": args.expected_run_id,
        "run_attempt": args.expected_run_attempt,
        "job": args.expected_job,
        "job_id": args.expected_job_id,
        "job_name": args.expected_job_name,
        "workflow_name": args.expected_workflow_name,
        "name": args.expected_runner_name,
        "runner_id": args.expected_runner_id,
        "runner_group_id": args.expected_runner_group_id,
        "runner_group": args.expected_runner_group,
        "os": args.expected_runner_os,
        "arch": args.expected_runner_arch,
        "head_sha": args.expected_head,
        "source_kind": args.expected_source_kind,
    }
    present = [value is not None for value in fields.values()]
    require(all(present), "all expected numeric runner identity fields are required together")
    return {key: value for key, value in fields.items()}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="technical-completion-receipt.json")
    parser.add_argument("--expected-source-kind", choices=("head", "merge"), required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-base", required=True, help="40-hex base SHA, or empty for workflow_dispatch")
    parser.add_argument("--expected-event-merge", required=True)
    parser.add_argument(
        "--expected-arbitration-key",
        required=True,
        help="workflow arbitration key formed from PR/dispatch, head SHA and source lane",
    )
    parser.add_argument(
        "--expected-head-owner",
        help="expected GitHub PR head repository owner login",
    )
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--expected-run-attempt", required=True)
    parser.add_argument("--expected-job", required=True)
    parser.add_argument("--expected-job-id", required=True)
    parser.add_argument("--expected-job-name", required=True)
    parser.add_argument("--expected-workflow-name", default="plan-v1.3.1-head-and-merge-closure")
    parser.add_argument("--expected-runner-name", required=True)
    parser.add_argument("--expected-runner-id", required=True)
    parser.add_argument("--expected-runner-group-id", required=True)
    parser.add_argument("--expected-runner-group", required=True)
    parser.add_argument("--expected-runner-os", required=True)
    parser.add_argument("--expected-runner-arch", required=True)
    parser.add_argument("--p0-artifact", type=Path, required=True)
    parser.add_argument("--h02-artifact", type=Path, required=True)
    parser.add_argument(
        "--h02-evidence-dir",
        type=Path,
        help="directory containing matrix-summary.json and all 72 H02 sidecars; defaults to summary parent",
    )
    parser.add_argument(
        "--h02-manifest",
        type=Path,
        help="checkout Cargo.toml used for dependency digest verification",
    )
    parser.add_argument(
        "--h02-lock",
        type=Path,
        help="checkout Cargo.lock used for dependency digest verification",
    )
    parser.add_argument("--github-identity-artifact", type=Path, required=True)
    parser.add_argument("--github-job-artifact", type=Path, required=True)
    parser.add_argument("--github-job-api", type=Path, required=True)
    parser.add_argument("--raw-log-manifest", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        receipt = load_receipt(args.input)
        validate(
            receipt,
            expected_source_kind=args.expected_source_kind,
            expected_commit=args.expected_commit,
            expected_tree=args.expected_tree,
            expected_head=args.expected_head,
            expected_base=args.expected_base,
            expected_event_merge=args.expected_event_merge,
            expected_head_owner=args.expected_head_owner,
            expected_arbitration_key=args.expected_arbitration_key,
            expected_runner=_runner_expectations(args),
            p0_artifact=args.p0_artifact,
            h02_artifact=args.h02_artifact,
            h02_evidence_dir=args.h02_evidence_dir,
            h02_manifest_path=args.h02_manifest,
            h02_lock_path=args.h02_lock,
            github_identity_artifact=args.github_identity_artifact,
            github_job_artifact=args.github_job_artifact,
            github_job_api=args.github_job_api,
            raw_log_manifest=args.raw_log_manifest,
            require_artifacts=True,
        )
    except (OSError, TypeError, ValueError, ValidationError) as error:
        print(f"V1.3.1 technical completion receipt validation FAILED: {error}", file=sys.stderr)
        return 1
    print("V1.3.1 technical completion receipt validation passed: exact source/gates bound; qualification=false; authority=NONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
