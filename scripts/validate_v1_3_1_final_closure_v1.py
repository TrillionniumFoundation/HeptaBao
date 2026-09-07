#!/usr/bin/env python3
"""Validate the final V1.3.1 repository-controlled closure inputs."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker


CURRENT_PLAN = "docs/plan/HEPTABAO_PLAN_V1_3_1_REPOSITORY_GAP_CLOSURE.md"
CURRENT_STATE = "planning/HEPTABAO_V1_3_1_GAP_CLOSURE_STATUS.yaml"
CURRENT_STATE_INPUT = "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
CURRENT_MANIFEST = "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml"
PLAN_ID = "HEPTABAO-PLAN-2026-08-28"
ACTIVE_MANIFEST_SCHEMA = "heptabao.normative-document-manifest-extension.v1_3_1"
ACTIVE_MANIFEST_PARENT = "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3.yaml"
ACTIVE_MANIFEST_SCHEMA_PATH = "schemas/heptabao_normative_document_manifest_v1_3_1.schema.json"
ACTIVE_MANIFEST_SCHEMA_URI = "https://heptabao.dev/schemas/heptabao_normative_document_manifest_v1_3_1.schema.json"
LANE_ARBITRATION_SCHEMA_PATH = "schemas/heptabao_v1_3_1_lane_arbitration_v1.schema.json"
LANE_ARBITRATION_SCHEMA_URI = "https://heptabao.dev/schemas/heptabao_v1_3_1_lane_arbitration_v1.schema.json"
LANE_ARBITRATION_SCRIPT_PATH = "scripts/arbitrate_v1_3_1_lanes_v1.py"
JOB_IDENTITY_SCHEMA_PATH = "schemas/heptabao_github_actions_job_identity_v1.schema.json"
JOB_IDENTITY_SCHEMA_URI = "https://heptabao.dev/schemas/heptabao_github_actions_job_identity_v1.schema.json"
JOB_IDENTITY_SCRIPT_PATH = "scripts/collect_github_job_identity_v1.py"
DRAFT202012_SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema"
FINAL_INPUT_STATUS = "REPOSITORY_CONTROLLED_SOURCE_CLOSURE_IMPLEMENTED_EXACT_HEAD_AND_MERGE_EXECUTION_REQUIRED"
HISTORICAL_MANIFEST = "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml"
HISTORICAL_PLAN = "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_2.md"
HISTORICAL_STATE_INPUT = "planning/HEPTABAO_CANONICAL_PROJECT_STATE_V1.yaml"
RATIFICATION_SUBJECT = "chore(provenance): owner-ratify V1.3.1 canonical source tree"
CURRENT_REPOSITORY_ID = 1349115072
CURRENT_REPOSITORY = "TrillionniumFoundation/HeptaBao"
CURRENT_REPOSITORY_OWNER = "TrillionniumFoundation"
DESIGNATED_RATIFIER_LOGIN = "ProfHepta"
DESIGNATED_RATIFIER_ACCOUNT_ID = 102159240
CANONICAL_WORKFLOW = ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
EXPECTED_HISTORICAL_WORKFLOWS = {
    ".github/workflows/plan-v1.3-gap-closure.yml",
    ".github/workflows/plan-v1.3.1-final-exact.yml",
}

# The canonical closure workflow is intentionally only a pull-request lane
# plus an explicit manual dispatch lane.  Keep this set narrow so a future
# push/schedule/workflow-call trigger cannot silently create an evidence lane
# whose source identity is not covered by the arbitration contract.
EXPECTED_WORKFLOW_EVENTS = frozenset({"pull_request", "workflow_dispatch"})

# GitHub accepts a finite set of permission names.  Every permission granted
# by this workflow must be read-only (or explicitly disabled); any write
# grant, including the shorthand ``write-all``, is rejected below.
KNOWN_WORKFLOW_PERMISSIONS = frozenset(
    {
        "actions",
        "artifact-metadata",
        "attestations",
        "checks",
        "code-quality",
        "contents",
        "deployments",
        "discussions",
        "id-token",
        "issues",
        "metadata",
        "models",
        "packages",
        "pages",
        "pull-requests",
        "repository-projects",
        "security-events",
        "statuses",
        "vulnerability-alerts",
    }
)


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)
CANONICAL_VALIDATOR_INVOCATIONS = (
    "scripts/validate_plan_v2.py",
    "scripts/validate_plan_v2_extensions.py",
    "scripts/validate_plan_v1_2.py",
    "scripts/validate_plan_v1_2_1.py",
    "scripts/validate_plan_v1_2_2.py",
    "scripts/validate_plan_v1_3.py",
    "scripts/validate_plan_v1_3_1.py",
    "scripts/validate_v1_3_1_final_closure_v1.py",
    "scripts/validate_provenance_v1.py",
    "scripts/validate_evidence_objects_v1.py",
    "scripts/validate_oracle_foundation_v1.py",
    "scripts/validate_repository_identity_v1.py",
    "scripts/validate_dependency_bakeoff_v1.py",
    "scripts/validate_dependency_execution_profiles_v1.py",
    "scripts/validate_dependency_registry_evidence_v1.py",
    "scripts/validate_dependency_research_captures_v1.py",
    "scripts/validate_h01_h02_next_v1.py",
    "scripts/validate_h02_seeded_behavior_plan_v1.py",
    "scripts/validate_h02_candidate_adapters_v1.py",
    "scripts/validate_h02_openraft_inmemory_cluster_v1.py",
    "scripts/validate_h02_openraft_fault_lab_v1.py",
    "scripts/validate_h02_blocker_closure_v1.py",
    "scripts/validate_h02_exact_head_matrix_contract_v1.py",
    "scripts/validate_h02_pr40_reconciliation_v1.py",
    "scripts/validate_rust_source_surface_v1.py",
    "scripts/validate_v1_3_1_technical_completion_receipt_v1.py",
    "scripts/validate_p0_transport_evidence_v2.py",
)
CANONICAL_RESOLUTION_INVOCATIONS = (
    "scripts/render_canonical_project_state_v1.py",
)
CANONICAL_ARBITRATION_INVOCATIONS = (
    "scripts/arbitrate_v1_3_1_lanes_v1.py",
)
CANONICAL_EXECUTION_INVOCATIONS = (
    "scripts/p0_transport_exact_v1.py",
    "scripts/classify_p0_transport_evidence_v1.py",
    "scripts/h02_exact_head_matrix_v1.py",
)


class FinalClosureValidationError(RuntimeError):
    """Raised when final repository-closure semantics drift or overclaim."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FinalClosureValidationError(message)


def _guard_path_components(
    path: Path, label: str, *, reject_traversal: bool = True
) -> Path:
    """Reject lexical traversal and symlink aliases before a repository read.

    ``Path.is_symlink()`` on only the leaf is not sufficient for repository
    inputs: a regular file below a symlinked directory can resolve outside the
    checkout.  Walk every lexical component with lstat-like checks so the
    closure validator never follows an untrusted alias.  The helper accepts
    relative paths because the caller may validate a temporary checkout.
    """

    candidate = Path(path)
    parts = candidate.parts
    if reject_traversal:
        require(not any(part == ".." for part in parts), f"{label} path contains traversal components")
    if candidate.is_absolute():
        current = Path(candidate.anchor)
        parts_to_check = parts[1:]
    else:
        current = Path(".")
        parts_to_check = parts
    for part in parts_to_check:
        if part in {"", "."}:
            continue
        current = current / part
        try:
            aliased = current.is_symlink()
        except (OSError, ValueError) as error:
            raise FinalClosureValidationError(
                f"cannot inspect {label} path component {current}: {error}"
            ) from error
        require(not aliased, f"{label} path contains a symlink component: {current}")
    return candidate


def _safe_repo_path(root: Path, relative: str, label: str) -> Path:
    """Resolve one repository-relative path without following aliases."""

    require(isinstance(relative, str) and relative.strip(), f"{label} path is missing")
    relative_path = Path(relative)
    require(not relative_path.is_absolute(), f"{label} path must be relative")
    require(".." not in relative_path.parts, f"{label} path contains traversal components")
    base = _guard_path_components(Path(root), f"{label} repository root")
    candidate = _guard_path_components(base / relative_path, label)
    try:
        candidate.resolve().relative_to(base.resolve())
    except (OSError, RuntimeError, ValueError) as error:
        raise FinalClosureValidationError(f"{label} path escapes repository root") from error
    return candidate


def read_text(root: Path, relative: str) -> str:
    path = _safe_repo_path(root, relative, "final-closure file")
    require(not path.is_symlink() and path.is_file(), f"missing final-closure file: {relative}")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise FinalClosureValidationError(f"cannot read final-closure file {relative}: {error}") from error


def read_yaml(root: Path, relative: str) -> dict[str, Any]:
    value = yaml.load(read_text(root, relative), Loader=UniqueKeyLoader)
    require(isinstance(value, dict), f"{relative} must contain one mapping")
    return value


def validate_active_manifest_schema(root: Path, manifest: dict[str, Any]) -> None:
    """Validate every active-manifest document record, fail-closed.

    The inherited V1.2 validator intentionally remains unchanged.  This
    revision has a separate schema because its revision/pointer/effective
    fields differ; legacy workflows are explicitly represented as HISTORICAL
    records and can never satisfy the active technical lane.
    """

    schema_path = _safe_repo_path(root, ACTIVE_MANIFEST_SCHEMA_PATH, "active manifest schema")
    require(schema_path.is_file(), f"active manifest schema missing: {ACTIVE_MANIFEST_SCHEMA_PATH}")
    try:
        schema = json.loads(
            schema_path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise FinalClosureValidationError(f"active manifest schema is not JSON: {error}") from error
    require(isinstance(schema, dict), "active manifest schema must be one object")
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        raise FinalClosureValidationError(f"active manifest schema is not Draft 2020-12: {error}") from error
    require(
        schema.get("$schema") == DRAFT202012_SCHEMA_URI,
        "active manifest schema Draft 2020-12 identity drift",
    )
    require(
        schema.get("$id") == ACTIVE_MANIFEST_SCHEMA_URI,
        "active manifest schema URI drift",
    )
    schema_properties = schema.get("properties")
    require(isinstance(schema_properties, Mapping), "active manifest schema properties are malformed")
    schema_identity = schema_properties.get("schema")
    require(isinstance(schema_identity, Mapping), "active manifest schema identity property is malformed")
    require(
        schema_identity.get("const") == ACTIVE_MANIFEST_SCHEMA,
        "active manifest schema identity drift",
    )
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(manifest),
        key=lambda error: list(error.path),
    )
    require(not errors, f"active manifest schema violation: {errors[0].message if errors else ''}")

    documents = manifest.get("documents")
    require(isinstance(documents, list) and documents, "active manifest document list is empty")
    ids = [entry["id"] for entry in documents]
    paths = [entry["path"] for entry in documents]
    require(len(ids) == len(set(ids)), "active manifest document IDs are duplicated")
    require(len(paths) == len(set(paths)), "active manifest document paths are duplicated")
    for entry in documents:
        require(set(entry) == {"id", "path", "kind", "owner_role", "digest", "effective_revision", "authority_effect"}, "active manifest document fields drift")
        require(entry["digest"] == "RESOLVE_FROM_EXACT_SOURCE", f"active manifest digest is static: {entry['path']}")
        require(entry["authority_effect"] == "NONE", f"active manifest authority drift: {entry['path']}")
        target = _safe_repo_path(root, entry["path"], "active manifest document")
        require(not target.is_symlink() and target.is_file(), f"active manifest path missing or symlinked: {entry['path']}")
        if entry["path"] == CANONICAL_WORKFLOW:
            require(entry["kind"] == "NORMATIVE", "canonical workflow must be NORMATIVE")
        if entry["path"] in EXPECTED_HISTORICAL_WORKFLOWS:
            require(entry["kind"] == "HISTORICAL", f"legacy workflow kind drift: {entry['path']}")

    history = manifest.get("historical_inheritance")
    require(isinstance(history, dict), "active manifest historical inheritance missing")
    legacy = history.get("inherited_legacy_workflows")
    require(isinstance(legacy, list) and legacy, "inherited legacy workflow classification missing")
    legacy_paths = [item.get("path") for item in legacy if isinstance(item, dict)]
    require(len(legacy_paths) == len(legacy), "inherited legacy workflow entry is malformed")
    require(set(legacy_paths) == EXPECTED_HISTORICAL_WORKFLOWS, "inherited legacy workflow set drift")
    require(len(legacy_paths) == len(set(legacy_paths)), "inherited legacy workflow paths are duplicated")
    for item in legacy:
        require(isinstance(item, dict), "inherited legacy workflow entry is malformed")
        require(item.get("kind") == "HISTORICAL", "inherited legacy workflow is not HISTORICAL")
        require(item.get("authority_effect") == "NONE", "historical workflow grants authority")
        legacy_path = item.get("path")
        require(isinstance(legacy_path, str) and legacy_path in paths, "historical workflow is not indexed")
        matching = [entry for entry in documents if entry["path"] == legacy_path]
        require(len(matching) == 1 and matching[0]["kind"] == "HISTORICAL", "legacy workflow document kind drift")


def _strict_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-standard JSON constant: {value}")


def validate_lane_arbitration_contract(root: Path, workflow: str) -> None:
    """Check the strict post-run aggregate schema and executable markers."""

    schema_path = _safe_repo_path(root, LANE_ARBITRATION_SCHEMA_PATH, "lane arbitration schema")
    require(schema_path.is_file(), f"lane arbitration schema missing: {LANE_ARBITRATION_SCHEMA_PATH}")
    try:
        schema = json.loads(
            schema_path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise FinalClosureValidationError(f"lane arbitration schema is not JSON: {error}") from error
    require(isinstance(schema, dict), "lane arbitration schema must be one object")
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        raise FinalClosureValidationError(f"lane arbitration schema is not Draft 2020-12: {error}") from error
    schema_properties = schema.get("properties")
    require(isinstance(schema_properties, Mapping), "lane arbitration schema properties are malformed")
    schema_identity = schema_properties.get("schema")
    require(isinstance(schema_identity, Mapping), "lane arbitration schema identity property is malformed")
    require(
        schema_identity.get("const") == "heptabao.v1-3-1-lane-arbitration.v1",
        "lane arbitration schema identity drift",
    )
    require(
        schema.get("$schema") == DRAFT202012_SCHEMA_URI,
        "lane arbitration schema Draft 2020-12 identity drift",
    )
    require(
        schema.get("$id") == LANE_ARBITRATION_SCHEMA_URI,
        "lane arbitration schema URI drift",
    )
    required = set(schema.get("required", []))
    require(
        {"status", "failure_class", "receipts", "supersession", "authority_effect"} <= required,
        "lane arbitration schema omits fail-closed fields",
    )
    script = read_text(root, LANE_ARBITRATION_SCRIPT_PATH)
    compile(script, str(_safe_repo_path(root, LANE_ARBITRATION_SCRIPT_PATH, "lane arbitration script")), "exec")
    require_tokens(
        script,
        (
            "discover_receipts",
            "exactly two",
            "synthetic merge",
            "expected_run_id",
            "superseded workflow run",
            "duplicate arbitration keys",
            "technical validation failed",
            "_git_parents",
            "exactly two parents",
            "require_merge_parent_binding",
            "failure_class",
            'status": "PASS"',
            '"qualification": False',
            '"authority_effect": "NONE"',
            "strict_json",
        ),
        "lane arbitration executable",
    )
    require_tokens(
        workflow,
        (
            "needs: full-technical-matrix",
            "if: ${{ always() }}",
            "actions/download-artifact@",
            "pattern: v1.3.1-*-technical-receipt-",
            "--expected-run-id",
            "--expected-run-attempt",
            "Bind final GitHub job states and lane Git trees",
            "final-jobs-api.candidate.json",
            "--require-merge-parent-binding",
            "for poll in $(seq 1 30); do",
            'get("status") != "completed"',
            "timed out waiting for completed head/merge jobs",
            "lane-arbitration.json",
            "arbitration-validation.log",
            "arbitration_output.invalid.json",
            "Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value)",
            'if [[ "$arbitration_valid" -ne 0 ]]',
            "schema-shaped diagnostic",
            "Upload lane arbitration evidence",
        ),
        "lane arbitration workflow",
    )


def validate_job_identity_contract(root: Path, workflow: str) -> None:
    """Check that provider identity collection is executable and bound."""

    schema_path = _safe_repo_path(root, JOB_IDENTITY_SCHEMA_PATH, "job identity schema")
    require(schema_path.is_file(), f"job identity schema missing: {JOB_IDENTITY_SCHEMA_PATH}")
    try:
        schema = json.loads(
            schema_path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise FinalClosureValidationError(f"job identity schema is not strict JSON: {error}") from error
    require(isinstance(schema, dict), "job identity schema must be one object")
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        raise FinalClosureValidationError(f"job identity schema is not Draft 2020-12: {error}") from error
    schema_properties = schema.get("properties")
    require(isinstance(schema_properties, Mapping), "job identity schema properties are malformed")
    schema_identity = schema_properties.get("schema")
    require(isinstance(schema_identity, Mapping), "job identity schema identity property is malformed")
    require(
        schema_identity.get("const") == "heptabao.github-actions-job-identity.v1",
        "job identity schema identity drift",
    )
    require(
        schema.get("$schema") == DRAFT202012_SCHEMA_URI,
        "job identity schema Draft 2020-12 identity drift",
    )
    require(
        schema.get("$id") == JOB_IDENTITY_SCHEMA_URI,
        "job identity schema URI drift",
    )
    required = set(schema.get("required", []))
    require(
        {"job_id", "runner_id", "runner_name", "runner_labels", "steps", "api_response_digest", "raw_log_manifest_digest"}
        <= required,
        "job identity schema omits provider-bound fields",
    )
    script = read_text(root, JOB_IDENTITY_SCRIPT_PATH)
    compile(script, str(_safe_repo_path(root, JOB_IDENTITY_SCRIPT_PATH, "job identity script")), "exec")
    require_tokens(
        script,
        (
            "strict_json",
            "check_positive_decimal",
            "runner_id",
            "runner_labels",
            "ubuntu-24.04",
            "CANONICAL_REQUIRED_STEP_NAMES",
            "build_log_manifest",
            "api_response_digest",
        ),
        "GitHub job identity collector",
    )
    require_tokens(
        workflow,
        (
            "Capture numeric GitHub job/runner identity and step outcomes",
            "collect_github_job_identity_v1.py",
            "github-job-api.json",
            "github-job-identity.json",
            "raw-log-manifest.json",
            "--expected-run-id",
            "--expected-run-attempt",
            "--expected-head-sha",
        ),
        "GitHub job identity workflow",
    )


def require_tokens(text: str, tokens: tuple[str, ...], label: str) -> None:
    missing = [token for token in tokens if token not in text]
    require(not missing, f"{label} missing markers: {missing}")


def _workflow_run_lines(workflow_value: dict[str, Any]) -> list[str]:
    """Return executable-looking lines from all workflow ``run`` blocks.

    Text-marker checks alone can be satisfied by a comment or an ``echo``.
    The canonical workflow is small enough that we can parse its YAML and
    inspect the actual job/step structure as a second, semantic boundary.
    Full-line shell comments are excluded; heredoc bodies remain available for
    the Python snippets that are intentionally part of the workflow.
    """

    jobs = workflow_value.get("jobs")
    require(isinstance(jobs, dict), "workflow jobs must be a mapping")
    lines: list[str] = []
    for job_name, job in jobs.items():
        require(isinstance(job, dict), f"workflow job {job_name!r} is malformed")
        steps = job.get("steps", [])
        require(isinstance(steps, list), f"workflow job {job_name!r} steps are malformed")
        for index, step in enumerate(steps):
            require(isinstance(step, dict), f"workflow job {job_name!r} step {index} is malformed")
            run = step.get("run")
            if not isinstance(run, str):
                continue
            lines.extend(
                line
                for line in run.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
    return lines


def _require_executable_invocation(
    lines: list[str], pattern: str, label: str
) -> None:
    """Require one shell command, rather than a marker in a string/comment.

    The workflow is intentionally small and uses stable command forms.  A
    line-anchored regular expression is a useful second boundary here: it
    rejects replacing an actual validator call with ``echo``/``printf`` while
    avoiding a false claim that arbitrary shell text was parsed as a command.
    """

    matcher = re.compile(pattern)
    matches = [line for line in lines if matcher.search(line)]
    require(len(matches) == 1, f"{label} must have exactly one executable invocation (found {len(matches)})")


def _workflow_trigger_declaration(
    workflow_value: Mapping[str, Any], workflow_text: str | None = None
) -> Any:
    """Return the parsed GitHub ``on`` declaration.

    PyYAML's YAML 1.1 resolver parses the unquoted key ``on`` as the boolean
    ``True``.  Accept that one parser artefact, but reject a missing trigger or
    a second boolean-looking key rather than accidentally treating arbitrary
    YAML as a valid workflow.
    """

    if workflow_text is not None:
        # Distinguish the genuine YAML key ``on`` from a boolean key such as
        # ``true``.  PyYAML's YAML 1.1 resolver gives both a boolean mapping
        # key, but GitHub's workflow parser does not treat ``true`` as the
        # workflow trigger declaration.
        raw_on_keys = re.findall(
            r"(?m)^[ \t]*(?:on|['\"]on['\"])[ \t]*:", workflow_text
        )
        require(
            len(raw_on_keys) == 1,
            "canonical workflow must contain exactly one literal on trigger key",
        )
    has_string_key = "on" in workflow_value
    yaml11_keys = [key for key in workflow_value if key is True]
    has_yaml11_key = bool(yaml11_keys)
    require(
        has_string_key or has_yaml11_key,
        "canonical workflow trigger declaration is missing",
    )
    require(
        not (has_string_key and has_yaml11_key),
        "canonical workflow trigger declaration is ambiguous",
    )
    return workflow_value["on"] if has_string_key else workflow_value[yaml11_keys[0]]


def _validate_workflow_triggers(
    workflow_value: Mapping[str, Any], workflow_text: str | None = None
) -> None:
    """Require exactly the source events covered by lane arbitration.

    GitHub permits shorthand arrays (for example ``on: [push]``).  Accept the
    shorthand only when it names exactly the two covered events; a mapping is
    accepted with null or mapping-valued event configuration.  Every
    unsupported event (push, schedule, workflow_call, etc.) fails closed.
    """

    declaration = _workflow_trigger_declaration(workflow_value, workflow_text)
    if isinstance(declaration, list):
        require(
            declaration
            and all(isinstance(event_name, str) for event_name in declaration)
            and len(declaration) == len(set(declaration))
            and set(declaration) == EXPECTED_WORKFLOW_EVENTS,
            "canonical workflow trigger list must contain exactly pull_request and workflow_dispatch",
        )
        return
    require(
        isinstance(declaration, Mapping),
        "canonical workflow trigger declaration must be a mapping",
    )
    event_names = set(declaration)
    require(
        event_names == EXPECTED_WORKFLOW_EVENTS,
        "canonical workflow trigger set must be exactly pull_request and workflow_dispatch",
    )
    for event_name, configuration in declaration.items():
        require(
            isinstance(event_name, str) and event_name in EXPECTED_WORKFLOW_EVENTS,
            "canonical workflow trigger name is malformed",
        )
        require(
            configuration is None or isinstance(configuration, Mapping),
            f"canonical workflow trigger configuration is malformed: {event_name}",
        )


def _validate_permission_map(permissions: Any, label: str) -> None:
    """Reject every write-capable or syntactically unsupported permission."""

    # GitHub's read-all shorthand is read-only and therefore safe for this
    # contract; write-all is explicitly rejected instead of being mistaken
    # for a mapping below.
    if permissions == "read-all":
        return
    require(permissions != "write-all", f"{label} permissions cannot use write-all")
    require(isinstance(permissions, Mapping), f"{label} permissions must be a mapping")
    for name, grant in permissions.items():
        require(
            isinstance(name, str) and name in KNOWN_WORKFLOW_PERMISSIONS,
            f"{label} permission name is unsupported: {name!r}",
        )
        if name == "id-token":
            # GitHub exposes OIDC only as write/none; ``read`` is not a valid
            # grant and must not be accepted merely because it is non-write.
            require(
                grant == "none",
                f"{label} permission 'id-token' must be none for a read-only workflow",
            )
            continue
        require(
            grant in {"read", "none"},
            f"{label} permission {name!r} must be read or none",
        )


def _validate_workflow_permissions(workflow_value: Mapping[str, Any]) -> None:
    """Validate workflow-level and every explicitly scoped job permission."""

    _validate_permission_map(workflow_value.get("permissions"), "workflow")
    jobs = workflow_value.get("jobs")
    require(isinstance(jobs, Mapping), "workflow jobs must be a mapping")
    for job_name, job in jobs.items():
        require(isinstance(job, Mapping), f"workflow job {job_name!r} is malformed")
        if "permissions" in job:
            _validate_permission_map(job.get("permissions"), f"job {job_name!r}")


def validate_workflow_semantics(workflow: str) -> None:
    """Validate executable workflow structure, not only textual markers."""

    try:
        value = yaml.load(workflow, Loader=UniqueKeyLoader)
    except yaml.YAMLError as error:
        raise FinalClosureValidationError(f"canonical workflow YAML is invalid: {error}") from error
    require(isinstance(value, dict), "canonical workflow must be one mapping")
    _validate_workflow_triggers(value, workflow)
    _validate_workflow_permissions(value)
    workflow_concurrency = value.get("concurrency")
    require(isinstance(workflow_concurrency, Mapping), "workflow concurrency is missing")
    require(
        workflow_concurrency.get("group")
        == "plan-v1.3.1-head-and-merge-closure-v2-${{ github.event.pull_request.number || github.ref }}",
        "workflow concurrency epoch/group drift",
    )
    require(
        workflow_concurrency.get("cancel-in-progress") is True,
        "workflow concurrency must cancel superseded runs",
    )
    jobs = value.get("jobs")
    require(isinstance(jobs, dict), "canonical workflow jobs are missing")
    matrix_job = jobs.get("full-technical-matrix")
    require(isinstance(matrix_job, dict), "canonical matrix job is missing")
    require(matrix_job.get("runs-on") == "ubuntu-24.04", "canonical matrix runner image drift")
    strategy = matrix_job.get("strategy")
    require(isinstance(strategy, dict), "canonical matrix strategy is missing")
    require(strategy.get("fail-fast") is False, "canonical matrix must disable fail-fast")
    require(
        strategy.get("max-parallel") == 1,
        "canonical matrix must serialize heavy source-lane admission",
    )
    matrix = strategy.get("matrix")
    require(isinstance(matrix, dict), "canonical source-kind matrix is missing")
    source_expression = matrix.get("source_kind")
    require(isinstance(source_expression, str), "canonical source-kind expression is missing")
    require("github.event_name == 'pull_request'" in source_expression, "pull-request lane expression drift")
    require('"head","merge"' in source_expression.replace(" ", ""), "head/merge lane expression drift")

    steps = matrix_job.get("steps")
    require(isinstance(steps, list) and steps, "canonical matrix steps are missing")
    names: list[str] = []
    by_name: dict[str, dict[str, Any]] = {}
    for index, step in enumerate(steps):
        require(isinstance(step, dict), f"canonical matrix step {index} is malformed")
        name = step.get("name")
        require(isinstance(name, str) and name.strip(), f"canonical matrix step {index} has no name")
        require(name not in by_name, f"canonical matrix step name is duplicated: {name}")
        names.append(name)
        by_name[name] = step

    required_steps = (
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
        "Capture numeric GitHub job/runner identity and step outcomes",
        "Emit exact-source technical completion receipt",
        "Validate digest-bound technical completion receipt",
        "Upload final technical receipt",
    )
    for name in required_steps:
        require(name in by_name, f"canonical workflow step is missing: {name}")
    positions = [names.index(name) for name in required_steps]
    require(
        positions == sorted(positions),
        "canonical workflow evidence steps are out of order",
    )

    # Every post-gate evidence step must run after earlier failures.  This
    # keeps failure receipts, provider identity snapshots and raw diagnostics
    # observable instead of silently replacing them with skipped steps.
    for name in (
        "Execute and classify P0 socket and audit evidence",
        "Compile, lint and execute all H02 entries without early evidence loss",
        "Upload complete diagnostics before final H02 gate",
        "Require complete H02 24-entry PASS",
        "Capture numeric GitHub job/runner identity and step outcomes",
        "Emit exact-source technical completion receipt",
        "Verify technical receipt remains non-authoritative",
        "Validate digest-bound technical completion receipt",
        "Upload final technical receipt",
    ):
        require(by_name[name].get("if") == "${{ always() }}", f"{name} must use always()")
    h02_run = by_name["Compile, lint and execute all H02 entries without early evidence loss"].get("run")
    require(isinstance(h02_run, str), "H02 always-run step has no shell body")
    require(
        'mkdir -p "$evidence" "$evidence/matrix"' in h02_run,
        "H02 always-run step must initialize diagnostics directories before redirects",
    )
    gate_a_run = by_name["Validate Gate A inherited contracts and Python regression"].get("run")
    require(isinstance(gate_a_run, str), "Gate A step has no shell body")
    require(
        "loader.flatten_mapping(node)" in gate_a_run,
        "Gate A YAML scanner must expand safe merge keys before duplicate checking",
    )
    p0_run = by_name["Execute and classify P0 socket and audit evidence"].get("run")
    require(isinstance(p0_run, str), "P0 evidence step has no shell body")
    require(
        'mkdir -p "$evidence"' in p0_run,
        "P0 evidence step must initialize diagnostics directory before redirects",
    )
    checkout = by_name["Checkout exact head or GitHub synthetic merge"]
    require(isinstance(checkout.get("uses"), str) and "actions/checkout@" in checkout["uses"], "canonical checkout action is missing")
    checkout_with = checkout.get("with", {})
    require(isinstance(checkout_with, Mapping), "canonical checkout options are malformed")
    require(checkout_with.get("persist-credentials") is False, "canonical checkout must not persist credentials")
    # Every declared validator/executor must occur in an executable run line,
    # exactly once.  This rejects a stale token left only in a comment or an
    # accidental duplicate invocation hidden behind the same YAML step.
    lines = _workflow_run_lines(value)
    executable_text = "\n".join(lines)
    all_invocations = (
        *CANONICAL_VALIDATOR_INVOCATIONS,
        *CANONICAL_RESOLUTION_INVOCATIONS,
        *CANONICAL_EXECUTION_INVOCATIONS,
        *CANONICAL_ARBITRATION_INVOCATIONS,
        "scripts/collect_github_job_identity_v1.py",
    )
    for invocation in all_invocations:
        occurrences = sum(line.count(invocation) for line in lines)
        require(occurrences == 1, f"workflow invocation must occur exactly once in executable lines: {invocation} (found {occurrences})")

    # The Gate-A validators are intentionally enumerated once and executed by
    # one loop.  Merely retaining their paths in the array is not sufficient:
    # replacing the loop body with ``echo "$script"`` would otherwise pass a
    # token-count check without running any validator.
    _require_executable_invocation(
        lines,
        r'^\s*for\s+script\s+in\s+"\$\{validators\[@\]\}";\s*do\s*$',
        "Gate-A validator loop",
    )
    _require_executable_invocation(
        lines,
        r'^\s*python3\s+"\$script"\s*\|\s*tee\s+-a\s+"\$evidence/validators\.log"\s*$',
        "Gate-A validator execution",
    )

    # Every non-loop executable is checked by its command prefix.  This keeps
    # the exact-once inventory meaningful even if a path token is moved into
    # an echo, heredoc string or unrelated diagnostic command.
    for invocation in (
        "scripts/validate_rust_source_surface_v1.py",
        "scripts/render_canonical_project_state_v1.py",
        "scripts/p0_transport_exact_v1.py",
        "scripts/classify_p0_transport_evidence_v1.py",
        "scripts/validate_p0_transport_evidence_v2.py",
        "scripts/h02_exact_head_matrix_v1.py",
        "scripts/collect_github_job_identity_v1.py",
        "scripts/validate_v1_3_1_technical_completion_receipt_v1.py",
        "scripts/arbitrate_v1_3_1_lanes_v1.py",
    ):
        escaped = re.escape(invocation)
        _require_executable_invocation(
            lines,
            rf'^\s*(?:if\s+)?python3\s+{escaped}(?:\s|\\|$)',
            f"{invocation} executable invocation",
        )
    aggregate = jobs.get("arbitrate-head-and-merge-evidence")
    require(isinstance(aggregate, dict), "canonical aggregate job is missing")
    require(aggregate.get("needs") == "full-technical-matrix", "aggregate job dependency drift")
    require(
        aggregate.get("if") == "${{ !cancelled() }}",
        "aggregate job must run after technical failure but skip cancelled predecessors",
    )
    require(aggregate.get("runs-on") == "ubuntu-24.04", "aggregate runner image drift")
    aggregate_steps = aggregate.get("steps")
    require(isinstance(aggregate_steps, list), "aggregate steps are missing")
    aggregate_names = [step.get("name") for step in aggregate_steps if isinstance(step, dict)]
    require("Install arbitration Python dependencies" in aggregate_names, "aggregate dependency setup step is missing")
    require("Verify arbitration dependency lock" in aggregate_names, "aggregate dependency lock step is missing")
    for name in (
        "Checkout exact workflow source for arbitration",
        "Download current-run technical receipts",
        "Bind final GitHub job states and lane Git trees",
        "Aggregate exact head and synthetic merge receipts",
        "Upload lane arbitration evidence",
    ):
        require(name in aggregate_names, f"aggregate evidence step is missing: {name}")
    aggregate_by_name = {
        step.get("name"): step
        for step in aggregate_steps
        if isinstance(step, dict) and isinstance(step.get("name"), str)
    }
    for name in (
        "Bind final GitHub job states and lane Git trees",
        "Aggregate exact head and synthetic merge receipts",
        "Upload lane arbitration evidence",
    ):
        require(
            aggregate_by_name[name].get("if") == "${{ always() }}",
            f"aggregate evidence step must use always(): {name}",
        )
    bind_run = aggregate_by_name["Bind final GitHub job states and lane Git trees"].get("run")
    require(isinstance(bind_run, str), "aggregate GitHub binding step has no shell body")
    require_tokens(
        bind_run,
        (
            "for poll in $(seq 1 30)",
            "final-jobs-api.candidate.json",
            "total_count",
            "status",
        ),
        "aggregate provider-state polling",
    )
    aggregate_run = aggregate_by_name["Aggregate exact head and synthetic merge receipts"].get("run")
    require(isinstance(aggregate_run, str), "aggregate arbitration step has no shell body")
    require_tokens(
        aggregate_run,
        (
            "arbitration-validation.log",
            "Draft202012Validator",
            "format_checker=FormatChecker()",
            "--require-merge-parent-binding",
            "arbitration_output.invalid.json",
            "arbitration_valid",
            "schema-shaped diagnostic",
        ),
        "aggregate schema-valid failure path",
    )


def validate_current_bindings(
    root: Path,
    final_input: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    """Ensure the active revision cannot inherit a stale status pointer.

    The V1.2 manifest is deliberately read-only historical input.  V1.3.1
    must override its pointers explicitly while retaining the old values for
    audit traceability.
    """

    expected = {
        "current_plan": CURRENT_PLAN,
        "current_state": CURRENT_STATE,
        "current_state_input": CURRENT_STATE_INPUT,
        "normative_manifest": CURRENT_MANIFEST,
    }
    for label, document in (("manifest", manifest), ("final closure input", final_input)):
        for key, value in expected.items():
            require(document.get(key) == value, f"{label} {key} does not point to the active V1.3.1 object")

    gap_status = read_yaml(root, CURRENT_STATE)
    for key, value in expected.items():
        require(gap_status.get(key) == value, f"gap-closure status {key} does not point to the active V1.3.1 object")
    require(gap_status.get("normative_manifest") == CURRENT_MANIFEST, "gap-closure status manifest pointer drift")
    gap_claims = gap_status.get("claims")
    require(isinstance(gap_claims, dict), "gap-closure status claims mapping missing")
    for key in ("qualification", "compatibility_claim", "production_authority", "migration_authority", "release_authority"):
        require(gap_claims.get(key) is False, f"gap-closure status {key} drift")
    require(gap_claims.get("selected_candidates") == [], "gap-closure status candidate selection drift")
    require(gap_claims.get("selection_effect") == "NONE", "gap-closure status selection effect drift")
    require(gap_claims.get("authority_effect") == "NONE", "gap-closure status authority effect drift")

    require(manifest.get("normative_manifest") == CURRENT_MANIFEST, "manifest must point at the active manifest")
    inheritance = manifest.get("historical_inheritance")
    require(isinstance(inheritance, dict), "historical manifest inheritance metadata missing")
    require(inheritance.get("parent_manifest") == "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3.yaml", "historical parent manifest drift")
    require(inheritance.get("inherited_current_plan") == HISTORICAL_PLAN, "inherited historical plan pointer drift")
    require(inheritance.get("inherited_current_state_input") == HISTORICAL_STATE_INPUT, "inherited historical state pointer drift")
    require(inheritance.get("retained_for_audit") is True, "historical inheritance must remain audit-retained")

    # Read the old manifest to prove that the historical pointer was retained,
    # rather than silently rewritten to make the new pointer appear current.
    historical = read_yaml(root, HISTORICAL_MANIFEST)
    require(historical.get("current_plan") == HISTORICAL_PLAN, "historical manifest current_plan was rewritten")
    require(historical.get("current_state_input") == HISTORICAL_STATE_INPUT, "historical manifest current_state_input was rewritten")

    documents = manifest.get("documents")
    require(isinstance(documents, list), "active manifest documents missing")
    paths = [entry.get("path") for entry in documents if isinstance(entry, dict)]
    require(len(paths) == len(set(paths)), "active manifest contains duplicate document paths")
    require(
        any(
            isinstance(entry, dict)
            and entry.get("path") == CANONICAL_WORKFLOW
            and entry.get("kind") == "NORMATIVE"
            for entry in documents
        ),
        "active canonical workflow is not indexed as NORMATIVE",
    )
    for legacy_path in EXPECTED_HISTORICAL_WORKFLOWS:
        matching = [entry for entry in documents if isinstance(entry, dict) and entry.get("path") == legacy_path]
        require(len(matching) == 1 and matching[0].get("kind") == "HISTORICAL", f"legacy workflow kind drift: {legacy_path}")
    # Every active-manifest path is part of the source binding.  A missing or
    # symlinked entry must fail the static closure check rather than waiting
    # for a later renderer invocation.
    for path in paths:
        target = _safe_repo_path(root, path, "active manifest document")
        require(not target.is_symlink() and target.is_file(), f"active manifest document missing or symlinked: {path}")
    for path in (CURRENT_PLAN, CURRENT_STATE, CURRENT_STATE_INPUT):
        require(path in paths, f"active manifest does not index {path}")


def validate_ratification_authenticity(
    final_input: dict[str, Any],
    protocol: str,
    workflow: str,
) -> None:
    """Validate source-level ratification rules without self-attesting them."""

    ratification = final_input.get("ratification_authenticity")
    require(isinstance(ratification, dict), "ratification authenticity metadata missing")
    require(ratification.get("source_of_truth") == "EXACT_HEAD_GIT_METADATA", "ratification source must be exact-head Git metadata")
    require(ratification.get("required_subject") == RATIFICATION_SUBJECT, "ratification subject drift")
    require(
        ratification.get("author_identity_policy")
        == "DESIGNATED_ACCOUNT_NON_AUTOMATION_IDENTITY",
        "author identity policy drift",
    )
    require(
        ratification.get("committer_identity_policy")
        == "DESIGNATED_ACCOUNT_NON_AUTOMATION_IDENTITY",
        "committer identity policy drift",
    )
    require(
        ratification.get("designated_ratifier_login") == DESIGNATED_RATIFIER_LOGIN,
        "designated ratifier login drift",
    )
    require(
        ratification.get("designated_ratifier_account_id")
        == DESIGNATED_RATIFIER_ACCOUNT_ID,
        "designated ratifier account ID drift",
    )
    require(
        ratification.get("repository_owner_may_differ_from_ratifier") is True,
        "repository owner and ratifier roles must remain explicitly separated",
    )
    forbidden = ratification.get("forbidden_identity_fragments")
    require(forbidden == ["github-actions", "[bot]"], "ratification automation deny-list drift")
    require(ratification.get("required_parent_count") == 1, "ratification must have exactly one parent")
    require(ratification.get("require_parent_tree_equality") is True, "ratification must preserve the parent tree")
    require(ratification.get("verification") == "REQUIRED_EXACT_HEAD", "ratification cannot be source-self-attested")
    require(ratification.get("static_commit_author_tree_claims") is False, "static ratification claims must remain disabled")
    require(ratification.get("independent_review") is False, "ratification metadata cannot claim independent review")
    for forbidden_key in ("commit", "head_sha", "tree", "author", "committer"):
        require(forbidden_key not in ratification, f"ratification metadata contains a static {forbidden_key} claim")

    require_tokens(
        protocol,
        (
            "ratification_authenticity",
            "both the Git author and committer identities",
            "no static document may predeclare the moving commit or tree",
            "repository owner and ratifier are intentionally permitted to differ",
            "not a cryptographic signature",
        ),
        "ratification protocol",
    )
    require_tokens(
        workflow,
        (
            "ratification_subject=\"$(git show -s --format=%s \"$HEAD_SHA\")\"",
            "ratification_author=\"$(git show -s --format='%an <%ae>' \"$HEAD_SHA\")\"",
            "ratification_committer=\"$(git show -s --format='%cn <%ce>' \"$HEAD_SHA\")\"",
            "github-actions",
            "[bot]",
            "git rev-list --parents -n 1 \"$HEAD_SHA\"",
            "git rev-parse \"$HEAD_SHA^{tree}\"",
            "GH_TOKEN: ${{ github.token }}",
            "pull-requests: read",
            "https://api.github.com/repos/$GITHUB_REPOSITORY/commits/$HEAD_SHA",
            "author_login",
            "committer_login",
            "EXPECTED_REPOSITORY_ID",
            "EXPECTED_REPOSITORY",
            "EXPECTED_RATIFIER_LOGIN",
            "EXPECTED_RATIFIER_ID",
            "repository_id",
            "repository_full_name",
            "expected_ratifier_login",
            "expected_ratifier_id",
            "identity_verified",
            "signature_required",
            "jobs:",
            "concurrency:",
            "plan-v1.3.1-lane-${{ github.event.pull_request.number || github.ref }}-${{ github.event.pull_request.head.sha || github.sha }}-${{ matrix.source_kind }}",
        ),
        "ratification workflow",
    )


def validate_workflow_coverage(
    root: Path,
    final_input: dict[str, Any],
    manifest: dict[str, Any],
    workflow: str,
) -> None:
    """Check the declared gate/lane coverage and duplicate arbitration contract."""

    coverage = final_input.get("workflow_coverage")
    require(isinstance(coverage, dict), "workflow coverage metadata missing")
    canonical = coverage.get("canonical_workflow")
    require(canonical == ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml", "canonical workflow pointer drift")
    require(coverage.get("pull_request_source_lanes") == ["head", "merge"], "pull-request source lane coverage drift")
    require(
        coverage.get("required_gate_groups")
        == ["plan_python", "root_rust_1_98", "p0_classified", "h02_24_entry_matrix"],
        "required workflow gate coverage drift",
    )

    required_invocations = coverage.get("required_validator_invocations")
    require(isinstance(required_invocations, list) and required_invocations, "required validator invocation list missing")
    require(
        required_invocations == list(CANONICAL_VALIDATOR_INVOCATIONS),
        "required validator invocation union drift",
    )
    require(
        len(required_invocations) == len(set(required_invocations)),
        "required validator invocation list contains duplicates",
    )
    required_resolutions = coverage.get("required_resolution_invocations")
    require(
        required_resolutions == list(CANONICAL_RESOLUTION_INVOCATIONS),
        "required source-resolution invocation drift",
    )
    for invocation in required_resolutions:
        require(invocation in workflow, f"canonical workflow does not invoke {invocation}")
        target = _safe_repo_path(root, invocation, "source-resolution target")
        require(target.is_file(), f"source-resolution target missing: {invocation}")
    required_arbitrations = coverage.get("required_arbitration_invocations")
    require(
        required_arbitrations == list(CANONICAL_ARBITRATION_INVOCATIONS),
        "required lane-arbitration invocation drift",
    )
    for invocation in required_arbitrations:
        require(isinstance(invocation, str) and invocation.startswith("scripts/"), "arbitration invocation path is invalid")
        require(invocation in workflow, f"canonical workflow does not invoke {invocation}")
        target = _safe_repo_path(root, invocation, "lane-arbitration target")
        require(target.is_file(), f"lane-arbitration target missing: {invocation}")
    renderer = read_text(root, "scripts/render_canonical_project_state_v1.py")
    require_tokens(
        renderer,
        (
            "DEFAULT_STATE_INPUT",
            "DEFAULT_MANIFEST",
            'value.add_argument("--state-input"',
            'value.add_argument("--manifest"',
            "HISTORICAL_REPOSITORY",
            "CURRENT_REPOSITORY",
            "ACTIVE_STATE_INPUT",
            "expected_repository",
            "def validate_inputs(",
            '"resolution_inputs"',
            '"state_input_sha256"',
            '"manifest_sha256"',
        ),
        "canonical renderer active-input resolution",
    )
    for invocation in required_invocations:
        require(isinstance(invocation, str) and invocation.startswith("scripts/"), "workflow invocation path is invalid")
        require(invocation in workflow, f"canonical workflow does not invoke {invocation}")
        target = _safe_repo_path(root, invocation, "workflow invocation target")
        require(target.is_file(), f"workflow invocation target missing: {invocation}")

    required_executions = coverage.get("required_execution_invocations")
    require(
        required_executions == list(CANONICAL_EXECUTION_INVOCATIONS),
        "required execution invocation union drift",
    )
    require(isinstance(required_executions, list), "required execution invocation list is malformed")
    require(
        len(required_executions) == len(set(required_executions)),
        "required execution invocation list contains duplicates",
    )
    for invocation in required_executions:
        require(isinstance(invocation, str) and invocation.startswith("scripts/"), "workflow execution path is invalid")
        require(invocation in workflow, f"canonical workflow does not execute {invocation}")
        target = _safe_repo_path(root, invocation, "workflow execution target")
        require(target.is_file(), f"workflow execution target missing: {invocation}")

    required_paths = coverage.get("required_manifest_paths")
    require(isinstance(required_paths, list) and required_paths, "required workflow manifest coverage missing")
    require(
        len(required_paths) == len(set(required_paths)),
        "required workflow manifest path list contains duplicates",
    )
    manifest_paths = {
        entry.get("path")
        for entry in manifest.get("documents", [])
        if isinstance(entry, dict)
    }
    for path in required_paths:
        require(path in manifest_paths, f"workflow coverage path is not indexed: {path}")
        target = _safe_repo_path(root, path, "workflow coverage target")
        require(target.is_file(), f"workflow coverage target missing: {path}")

    arbitration = coverage.get("duplicate_arbitration")
    require(isinstance(arbitration, dict), "duplicate arbitration metadata missing")
    require(
        arbitration.get("run_key_components") == ["pull_request_number", "head_sha"],
        "duplicate run key must bind PR number and head SHA",
    )
    require(arbitration.get("lane_key_component") == "source_kind", "duplicate lane key must bind source kind")
    require(
        arbitration.get("workflow_concurrency_epoch") == "v2",
        "workflow concurrency epoch drift",
    )
    require(
        arbitration.get("matrix_max_parallel") == 1,
        "canonical matrix admission parallelism drift",
    )
    require(
        arbitration.get("cancelled_predecessor_aggregate") == "SKIP",
        "cancelled predecessor aggregate policy drift",
    )
    require(arbitration.get("newer_head_policy") == "CANCEL_OLDER_RUN_AND_RETAIN_HISTORY", "new-head arbitration policy drift")
    require(arbitration.get("ancestor_evidence") == "REJECT", "ancestor evidence must be rejected")
    require(arbitration.get("duplicate_entry_ids") == "FAIL", "duplicate matrix IDs must fail closed")
    require(arbitration.get("lane_completion") == "REQUIRE_HEAD_AND_SYNTHETIC_MERGE", "both source lanes must be required")

    require_tokens(
        workflow,
        (
            "concurrency:",
            "cancel-in-progress: true",
            "SOURCE_SHA",
            "HEAD_SHA",
            "source_kind",
            "duplicate_entry_ids",
            "if: ${{ always() }}",
            "summary[\"matrix\"][\"executed_entry_count\"] == 24",
            "--github-identity-artifact",
            "--expected-arbitration-key \"$ARBITRATION_KEY\"",
            "--state-input planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml",
            "--manifest planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml",
            "arbitrate_v1_3_1_lanes_v1.py",
            "download-artifact",
            "lane-arbitration.json",
            "EXACT_HEAD_AND_SYNTHETIC_MERGE_ONLY",
            "Bind final GitHub job states and lane Git trees",
            "--expected-head-tree",
            "--expected-merge-tree",
            "--require-git-tree-binding",
            "--require-merge-parent-binding",
            "--final-jobs-api",
            "--require-final-jobs-api",
            "final-jobs-api.json",
            "final-jobs-api.candidate.json",
            "for poll in $(seq 1 30)",
            "timed out waiting for completed head/merge jobs",
            "binding-errors.txt",
            "arbitration-validation.log",
            "arbitration_output.invalid.json",
            "Draft202012Validator",
            "merge_tree",
        ),
        "workflow coverage and duplicate arbitration",
    )


def validate(root: Path) -> None:
    # Check the caller-supplied checkout before resolving it.  Resolving first
    # would erase a symlinked repository-root component and let all subsequent
    # reads escape the path the caller intended to validate.  A ``..`` in the
    # root argument remains compatible with ordinary CLI usage; child paths
    # are still rejected for traversal by ``_safe_repo_path``.
    root = Path(root)
    _guard_path_components(root, "repository root", reject_traversal=False)
    require(not root.is_symlink(), "repository root must not be a symlink")
    root = root.resolve()
    status = read_yaml(root, "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml")
    require(
        status.get("schema") == "heptabao.v1-3-1-final-closure-input.v1",
        "final closure schema drift",
    )
    require(status.get("plan_id") == PLAN_ID, "final closure plan ID drift")
    require(status.get("revision") == "1.3.1-final-closure", "revision drift")
    require(status.get("status") == FINAL_INPUT_STATUS, "final closure status drift")
    integration = status.get("canonical_integration")
    require(isinstance(integration, dict), "canonical integration missing")
    require(integration.get("repository_id") == CURRENT_REPOSITORY_ID, "canonical repository ID drift")
    require(integration.get("repository") == CURRENT_REPOSITORY, "canonical repository drift")
    require(integration.get("repository_owner") == CURRENT_REPOSITORY_OWNER, "canonical repository owner drift")
    require(integration.get("branch") == "codex/plan-v1.3-gap-closure-v2", "canonical branch drift")
    require(integration.get("pull_request") == 45, "canonical PR drift")
    require(
        integration.get("source_identity")
        == "RESOLVE_FROM_EVENT_AND_GIT_NOT_FROM_STATIC_DOCUMENT",
        "source identity must be resolved from execution",
    )
    require(
        integration.get("synthetic_merge_identity")
        == "RESOLVE_FROM_PULL_REQUEST_EVENT_AND_VERIFY_TWO_PARENTS",
        "synthetic merge identity must be event and ancestry bound",
    )

    closure = status.get("repository_controlled_closure")
    require(isinstance(closure, dict), "repository closure mapping missing")
    require(closure.get("p0_runtime_observed_cases") == 11, "P0 runtime count drift")
    require(
        closure.get("p0_exact_head_compiled_source_bound_cases") == 2,
        "P0 compiled source-bound count drift",
    )
    require(
        closure.get("p0_best_effort_source_bound_cases") == 1,
        "P0 best-effort source-bound count drift",
    )
    for key in (
        "p0_runtime_vs_source_evidence_classification",
        "h02_legacy_log_bytes_vote_commit_entries_membership_equivalence",
        "h02_legacy_log_reopen_reader_replay",
        "h02_legacy_state_applied_membership_reopen_equivalence",
        "exact_head_and_distinct_synthetic_merge_workflow",
        "machine_readable_technical_receipt",
        "head_merge_lane_arbitration_aggregate",
    ):
        require(closure.get(key) == "IMPLEMENTED_SOURCE", f"{key} is not implemented")
    require(
        closure.get("ordinary_owner_source_ratification") == "REQUIRED_FINAL_COMMIT",
        "owner ratification must be verified at exact head rather than self-asserted",
    )

    external = status.get("external_open")
    require(
        external
        == [
            "HB-BLK-CTRL-001",
            "HB-BLK-EXT-001",
            "HB-BLK-EXT-002",
            "HB-BLK-EXT-003",
            "HB-BLK-EXT-004",
            "HB-BLK-EXT-005",
            "HB-BLK-EXT-006",
            "HB-BLK-EXT-007",
        ],
        "external blocker coverage drift",
    )
    claims = status.get("claims")
    require(isinstance(claims, dict), "claims mapping missing")
    require(claims.get("qualification") is False, "qualification drift")
    require(claims.get("compatibility_claim") is False, "compatibility drift")
    require(claims.get("selected_candidates") == [], "selection drift")
    require(claims.get("selection_effect") == "NONE", "selection effect drift")
    require(claims.get("production_authority") is False, "production authority drift")
    require(claims.get("migration_authority") is False, "migration authority drift")
    require(claims.get("release_authority") is False, "release authority drift")
    require(claims.get("authority_effect") == "NONE", "authority effect drift")

    matrix = read_yaml(root, "planning/HEPTABAO_P0_TRANSPORT_TEST_MATRIX_V2.yaml")
    cases = matrix.get("cases")
    require(isinstance(cases, list) and len(cases) == 14, "P0 matrix count drift")
    by_id = {
        case.get("id"): case
        for case in cases
        if isinstance(case, dict) and isinstance(case.get("id"), str)
    }
    require(len(by_id) == 14, "P0 matrix IDs missing or duplicated")
    expected_runtime = {f"P0-TRANSPORT-{index:03d}" for index in range(1, 11)} | {
        "P0-TRANSPORT-013"
    }
    expected_compiled = {"P0-TRANSPORT-011", "P0-TRANSPORT-012"}
    expected_best_effort = {"P0-TRANSPORT-014"}
    require(
        {
            case_id
            for case_id, case in by_id.items()
            if case.get("evidence_class") == "RUNTIME_SOCKET_OBSERVED"
        }
        == expected_runtime,
        "runtime-observed P0 case classification drift",
    )
    require(
        {
            case_id
            for case_id, case in by_id.items()
            if case.get("evidence_class") == "EXACT_HEAD_COMPILED_SOURCE_BOUND"
        }
        == expected_compiled,
        "compiled source-bound P0 case classification drift",
    )
    require(
        {
            case_id
            for case_id, case in by_id.items()
            if case.get("evidence_class")
            == "BEST_EFFORT_CONTROLLED_DROP_SOURCE_BOUND"
        }
        == expected_best_effort,
        "best-effort source-bound P0 case classification drift",
    )
    semantics = matrix.get("evidence_semantics")
    require(isinstance(semantics, dict), "P0 evidence semantics missing")
    require(
        semantics.get("source_presence_is_runtime_execution") is False,
        "source presence cannot become runtime evidence",
    )
    exact_head_requirements = matrix.get("exact_head_requirements")
    require(isinstance(exact_head_requirements, Mapping), "P0 exact-head requirements are malformed")
    require(
        exact_head_requirements.get("classified_evidence_v2_required") is True,
        "classified P0 evidence must be required",
    )

    classifier = read_text(root, "scripts/classify_p0_transport_evidence_v1.py")
    require_tokens(
        classifier,
        (
            '"RUNTIME_SOCKET_OBSERVED"',
            '"EXACT_HEAD_COMPILED_SOURCE_BOUND"',
            '"BEST_EFFORT_CONTROLLED_DROP_SOURCE_BOUND"',
            '"executed_pass": len(RUNTIME_OBSERVED)',
            '"source_presence_is_runtime_execution": False',
            '"heptabao.p0-transport-exact-result.v2"',
        ),
        "P0 evidence classifier",
    )
    evidence_validator = read_text(
        root, "scripts/validate_p0_transport_evidence_v2.py"
    )
    require_tokens(
        evidence_validator,
        (
            'counts["executed_pass"] == 11',
            'case.get("evidence_class") == evidence_class',
            'source.get("commit") == expected_commit',
            'report.get("qualification") is False',
            'report.get("authority_effect") == "NONE"',
        ),
        "P0 evidence validator",
    )

    durable = read_text(
        root, "probes/h02/openraft-tokio/src/bin/durable_store_lab.rs"
    )
    require_tokens(
        durable,
        (
            "async fn log_semantic_snapshot(",
            "store.get_log_state().await?",
            "store.read_vote().await?",
            "store.read_committed().await?",
            "store.try_get_log_entries(..).await?",
            "legacy_log_bytes_match",
            "let legacy_log_vote_matches = semantic_field_matches(",
            "legacy_log_committed_matches",
            "legacy_log_entries_match",
            "legacy_log_membership_matches",
            "legacy_log_reopen_matches",
            "legacy_state_last_applied_matches",
            "legacy_state_membership_matches",
            "legacy_state_reopen_matches",
            '"explicit_legacy_log_semantics_verified": true',
            '"explicit_legacy_state_membership_verified": true',
        ),
        "H02 legacy-adoption evidence",
    )

    workflow = read_text(
        root, ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
    )
    validate_workflow_semantics(workflow)
    validate_lane_arbitration_contract(root, workflow)
    validate_job_identity_contract(root, workflow)
    require_tokens(
        workflow,
        (
            "source_kind: ${{ fromJSON",
            "github.event_name == 'pull_request'",
            "matrix.source_kind == 'merge' && github.sha",
            "test \"$SOURCE_SHA\" != \"$HEAD_SHA\"",
            "git rev-list --parents -n 1 HEAD",
            "test \"$parent_one\" = \"$BASE_SHA\"",
            "test \"$parent_two\" = \"$HEAD_SHA\"",
            "chore(provenance): owner-ratify V1.3.1 canonical source tree",
            "*github-actions*",
            "cargo +1.98.0 fmt --all -- --check",
            "cargo +1.98.0 test --locked --workspace --all-targets",
            "cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings",
            "scripts/classify_p0_transport_evidence_v1.py",
            "scripts/validate_p0_transport_evidence_v2.py",
            "scripts/h02_exact_head_matrix_v1.py",
            'summary["matrix"]["executed_entry_count"] == 24',
            'p0["counts"]["executed_pass"] == 11',
            '"qualification": False',
            '"authority_effect": "NONE"',
            "runs-on: ubuntu-24.04",
            "if: ${{ always() }}",
            "download-artifact",
            "arbitrate_v1_3_1_lanes_v1.py",
            "lane-arbitration.json",
        ),
        "head and synthetic-merge closure workflow",
    )
    for forbidden in (
        "contents: write",
        "persist-credentials: true",
        "git push",
        "git commit",
        "ubuntu-slim",
    ):
        require(forbidden not in workflow, f"forbidden workflow marker: {forbidden}")

    renderer = read_text(root, "scripts/render_canonical_project_state_v1.py")
    require_tokens(
        renderer,
        (
            "--state-input",
            "--manifest",
            "resolution_inputs",
            "state_input_sha256",
            "manifest_sha256",
            "current_state_input",
            "manifest does not index selected state input",
        ),
        "active canonical-state resolver",
    )

    protocol = read_text(
        root, "docs/execution/HEPTABAO_V1_3_1_FINAL_CLOSURE_PROTOCOL.md"
    )
    require_tokens(
        protocol,
        (
            "11 entries are `RUNTIME_SOCKET_OBSERVED`",
            "two entries are `EXACT_HEAD_COMPILED_SOURCE_BOUND`",
            "one entry is `BEST_EFFORT_CONTROLLED_DROP_SOURCE_BOUND`",
            "GitHub's synthetic merge commit",
            "persisted vote",
            "retained membership entries",
            "kind: HISTORICAL",
            "active V1.3.1 evidence lane",
            "External boundary",
        ),
        "final closure protocol",
    )

    manifest = read_yaml(
        root, "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml"
    )
    require(manifest.get("schema") == ACTIVE_MANIFEST_SCHEMA, "active manifest schema drift")
    require(manifest.get("plan_id") == PLAN_ID, "active manifest plan ID drift")
    require(manifest.get("revision") == "1.3.1", "active manifest revision drift")
    require(manifest.get("status") == "NORMATIVE_REPOSITORY_GAP_CLOSURE_EXTENSION", "active manifest status drift")
    require(manifest.get("inherits") == ACTIVE_MANIFEST_PARENT, "active manifest parent drift")
    validate_active_manifest_schema(root, manifest)
    validate_current_bindings(root, status, manifest)
    validate_ratification_authenticity(status, protocol, workflow)
    validate_workflow_coverage(root, status, manifest, workflow)
    documents = manifest.get("documents")
    require(isinstance(documents, list), "V1.3.1 manifest documents missing")
    paths = {
        entry.get("path")
        for entry in documents
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    for path in (
        CURRENT_MANIFEST,
        "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml",
        CURRENT_STATE,
        CURRENT_PLAN,
        "docs/execution/HEPTABAO_V1_3_1_FINAL_CLOSURE_PROTOCOL.md",
        "planning/HEPTABAO_P0_TRANSPORT_TEST_MATRIX_V2.yaml",
        "scripts/p0_transport_exact_v1.py",
        "scripts/classify_p0_transport_evidence_v1.py",
        "scripts/validate_p0_transport_evidence_v2.py",
        "scripts/h02_exact_head_matrix_v1.py",
        "schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json",
        "scripts/validate_v1_3_1_final_closure_v1.py",
        "tests/plan/test_p0_transport_evidence_classification_v2.py",
        "tests/plan/test_v1_3_1_final_closure.py",
        ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml",
        ".github/workflows/plan-v1.3.1-final-exact.yml",
        "schemas/heptabao_v1_3_1_technical_completion_receipt_v1.schema.json",
        "scripts/validate_v1_3_1_technical_completion_receipt_v1.py",
        "tests/plan/test_v1_3_1_technical_completion_receipt.py",
        "schemas/heptabao_v1_3_1_lane_arbitration_v1.schema.json",
        "scripts/arbitrate_v1_3_1_lanes_v1.py",
        "tests/plan/test_v1_3_1_lane_arbitration.py",
        "scripts/render_canonical_project_state_v1.py",
    ):
        require(path in paths, f"final closure manifest missing: {path}")
    require(manifest.get("qualification") is False, "manifest qualification drift")
    require(
        manifest.get("compatibility_claim") is False,
        "manifest compatibility drift",
    )
    require(manifest.get("authority_effect") == "NONE", "manifest authority drift")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    try:
        validate(args.root)
    except (OSError, TypeError, AttributeError, KeyError, yaml.YAMLError, FinalClosureValidationError) as error:
        print(f"HeptaBao V1.3.1 final closure validation FAILED: {error}")
        return 1
    print(
        "HeptaBao V1.3.1 final closure validation passed: "
        "P0 evidence classified; H02 legacy semantics bound; head+merge gates required; "
        "qualification=false authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
