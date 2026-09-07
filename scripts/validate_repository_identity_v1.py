#!/usr/bin/env python3
"""Fail-closed validation of HeptaBao's current repository identity surfaces."""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CURRENT_REPOSITORY_ID = 1_349_115_072
CURRENT_OWNER = "TrillionniumFoundation"
CURRENT_REPOSITORY = f"{CURRENT_OWNER}/HeptaBao"
HISTORICAL_REPOSITORY = "ProfHepta/HeptaBao"
DESIGNATED_RATIFIER_LOGIN = "ProfHepta"
DESIGNATED_RATIFIER_ACCOUNT_ID = 102_159_240
DEPRECATED_OWNER = "ProfAlex" + "QI"

WORKFLOW_PATH = ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
CANONICAL_JOB_ID = "full-technical-matrix"
CANONICAL_GATE_A_STEP = "Validate Gate A inherited contracts and Python regression"
IDENTITY_VALIDATOR_PATH = "scripts/validate_repository_identity_v1.py"
EXPECTED_WORKFLOW_ENVIRONMENT = {
    "EXPECTED_REPOSITORY_ID": str(CURRENT_REPOSITORY_ID),
    "EXPECTED_REPOSITORY": CURRENT_REPOSITORY,
    "EXPECTED_HEAD_OWNER": "${{ github.event.pull_request.head.repo.owner.login || github.repository_owner }}",
    "EXPECTED_RATIFIER_LOGIN": DESIGNATED_RATIFIER_LOGIN,
    "EXPECTED_RATIFIER_ID": str(DESIGNATED_RATIFIER_ACCOUNT_ID),
}
CURRENT_SCHEMA_BINDINGS: dict[str, tuple[int, int]] = {
    "schemas/heptabao_v1_3_1_technical_completion_receipt_v1.schema.json": (2, 1),
    "schemas/heptabao_v1_3_1_lane_arbitration_v1.schema.json": (1, 0),
    "schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json": (1, 0),
}
CURRENT_EXECUTION_SURFACES = (
    WORKFLOW_PATH,
    "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml",
    "scripts/arbitrate_v1_3_1_lanes_v1.py",
    "scripts/classify_p0_transport_evidence_v1.py",
    "scripts/collect_github_job_identity_v1.py",
    "scripts/h02_exact_head_matrix_v1.py",
    "scripts/p0_transport_exact_core_v1.py",
    "scripts/validate_p0_transport_evidence_v2.py",
    "scripts/validate_v1_3_1_technical_completion_receipt_v1_core.py",
)
REQUIRED_PATHS = tuple(sorted(set(CURRENT_SCHEMA_BINDINGS) | set(CURRENT_EXECUTION_SURFACES) | {
    ".github/CODEOWNERS",
    "docs/execution/HEPTABAO_V1_3_1_FINAL_CLOSURE_PROTOCOL.md",
    "docs/plan/HEPTABAO_PLAN_V1_3_1_REPOSITORY_GAP_CLOSURE.md",
}))
IGNORED_COMPONENTS = frozenset({
    ".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__", "target",
})
IGNORED_SUFFIXES = frozenset({".pyc", ".pyo"})
HEREDOC_PATTERN = re.compile(
    r"<<(?P<strip>-?)[ \t]*(?P<quote>['\"]?)(?P<delimiter>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P=quote)"
)


class IdentityFailure(RuntimeError):
    """A current repository identity invariant did not hold."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise IdentityFailure(message)


def read_text(root: Path, relative: str) -> str:
    try:
        return (root / relative).read_text(encoding="utf-8")
    except OSError as error:
        raise IdentityFailure(f"cannot read {relative}: {error}") from error


def _strict_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key: {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def read_json(root: Path, relative: str) -> Any:
    try:
        return json.loads(
            read_text(root, relative),
            object_pairs_hook=_strict_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError, IdentityFailure) as error:
        raise IdentityFailure(f"{relative}: invalid strict JSON: {error}") from error


class UniqueStringLoader(yaml.BaseLoader):
    """String-preserving YAML loader with duplicate-key rejection."""


def _construct_unique_mapping(
    loader: UniqueStringLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        require(isinstance(key, str), "workflow mapping keys must be strings")
        require(key not in result, f"duplicate workflow YAML key / duplicate key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueStringLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_yaml(text: str, label: str) -> dict[str, Any]:
    try:
        value = yaml.load(text, Loader=UniqueStringLoader)
    except (yaml.YAMLError, IdentityFailure) as error:
        raise IdentityFailure(f"{label} is invalid or ambiguous YAML: {error}") from error
    require(isinstance(value, dict), f"{label} must be a YAML mapping")
    return value


def mapping(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be a mapping")
    return value


def sequence(value: Any, label: str) -> list[Any]:
    require(isinstance(value, list), f"{label} must be a sequence")
    return value


def executable_shell_lines(script: str) -> list[str]:
    """Discard comments and here-document bodies before structural matching."""
    result: list[str] = []
    heredocs: list[tuple[str, bool]] = []
    for raw in script.splitlines():
        if heredocs:
            delimiter, strip_tabs = heredocs[0]
            candidate = raw.lstrip("\t") if strip_tabs else raw
            if candidate.strip() == delimiter:
                heredocs.pop(0)
            continue
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        result.append(raw)
        heredocs.extend(
            (match.group("delimiter"), match.group("strip") == "-")
            for match in HEREDOC_PATTERN.finditer(raw)
        )
    require(not heredocs, "canonical Gate-A shell contains an unterminated here-document")
    return result


def shell_tokens(line: str, label: str) -> list[str]:
    try:
        return shlex.split(line, comments=True, posix=True)
    except ValueError as error:
        raise IdentityFailure(f"{label}: invalid shell tokenization: {error}") from error


def validate_identity_validator_invocation(script: str) -> None:
    lines = executable_shell_lines(script)
    starts = [i for i, line in enumerate(lines) if re.fullmatch(r"[ \t]*validators=\([ \t]*", line)]
    require(len(starts) == 1, "canonical Gate-A must define validators array exactly once")
    start = starts[0]
    closing = next((i for i in range(start + 1, len(lines)) if re.fullmatch(r"[ \t]*\)[ \t]*", lines[i])), None)
    require(closing is not None, "canonical Gate-A validators array is unterminated")
    validators: list[str] = []
    for line in lines[start + 1:closing]:
        tokens = shell_tokens(line, "canonical Gate-A validators array")
        if not tokens:
            continue
        require(
            len(tokens) == 1 and re.fullmatch(r"scripts/[A-Za-z0-9_.-]+\.py", tokens[0]) is not None,
            f"canonical Gate-A validator entry is not one literal script path: {line!r}",
        )
        validators.append(tokens[0])
    require(
        validators.count(IDENTITY_VALIDATOR_PATH) == 1,
        "canonical workflow must invoke the transfer-aware identity validator exactly once",
    )
    require(
        len(validators) == 24 and len(set(validators)) == 24,
        "canonical Gate-A validators array must contain exactly 24 unique literal scripts",
    )
    loop_starts = [
        i for i in range(closing + 1, len(lines))
        if re.fullmatch(r'[ \t]*for[ \t]+script[ \t]+in[ \t]+"\$\{validators\[@\]\}"[ \t]*;[ \t]*do[ \t]*', lines[i])
    ]
    require(len(loop_starts) == 1, "canonical Gate-A validator execution loop is missing or ambiguous")
    loop_start = loop_starts[0]
    pre_loop = lines[closing + 1:loop_start]
    require(
        len(pre_loop) == 2
        and re.fullmatch(r'[ \t]*test[ \t]+"\$\{#validators\[@\]\}"[ \t]+-eq[ \t]+24[ \t]*', pre_loop[0])
        and re.fullmatch(r'[ \t]*declare[ \t]+-A[ \t]+seen_validators=\(\)[ \t]*', pre_loop[1]),
        "canonical Gate-A validator array must be frozen before its execution loop",
    )
    loop_end = next((i for i in range(loop_start + 1, len(lines)) if re.fullmatch(r"[ \t]*done[ \t]*", lines[i])), None)
    require(loop_end is not None, "canonical Gate-A validator execution loop is unterminated")
    expected = (
        r'[ \t]*test[ \t]+-f[ \t]+"\$script"[ \t]*',
        r'[ \t]*test[ \t]+-z[ \t]+"\$\{seen_validators\[\$script\]\+present\}"[ \t]*',
        r'[ \t]*seen_validators\[\$script\]=1[ \t]*',
        r'[ \t]*python3[ \t]+"\$script"[ \t]*\|[ \t]*tee[ \t]+-a[ \t]+"\$evidence/validators\.log"[ \t]*',
    )
    body = lines[loop_start + 1:loop_end]
    require(
        len(body) == len(expected)
        and all(re.fullmatch(pattern, line) for pattern, line in zip(expected, body, strict=True)),
        "canonical Gate-A loop must execute each validator in the fail-closed sequence",
    )


def parse_workflow_identity_environment(text: str) -> dict[str, Any]:
    workflow = load_yaml(text, "canonical workflow")
    jobs = mapping(workflow.get("jobs"), "canonical workflow jobs")
    job = mapping(jobs.get(CANONICAL_JOB_ID), f"canonical job {CANONICAL_JOB_ID}")
    require("if" not in job, "canonical technical matrix job must not be conditionally disabled")
    require(job.get("continue-on-error") in (None, "false"), "canonical technical matrix job must fail closed")
    env = mapping(job.get("env"), "canonical technical matrix env")
    identity = {key: env.get(key) for key in EXPECTED_WORKFLOW_ENVIRONMENT}
    steps = sequence(job.get("steps"), "canonical technical matrix steps")
    matches = [step for step in steps if isinstance(step, dict) and step.get("name") == CANONICAL_GATE_A_STEP]
    require(len(matches) == 1, f"canonical workflow must contain exactly one {CANONICAL_GATE_A_STEP!r} step")
    step = mapping(matches[0], "canonical Gate-A step")
    require("if" not in step, "canonical Gate-A identity validation step must not be disabled")
    require(step.get("continue-on-error") in (None, "false"), "canonical Gate-A identity validation step must fail closed")
    require(step.get("shell") == "bash", "canonical Gate-A identity validation must use bash")
    run = step.get("run")
    require(isinstance(run, str), "canonical Gate-A identity validation step must have an executable run block")
    validate_identity_validator_invocation(run)
    return identity


def fallback_source_paths(root: Path) -> list[Path]:
    result: list[Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as scan:
                entries = sorted(scan, key=lambda item: item.name)
        except OSError as error:
            raise IdentityFailure(f"cannot enumerate source-archive directory {directory.relative_to(root)}: {error}") from error
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root)
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as error:
                raise IdentityFailure(f"cannot inspect source-archive entry {relative.as_posix()}: {error}") from error
            if stat.S_ISLNK(mode):
                raise IdentityFailure(f"source-archive identity scan refuses symlink: {relative.as_posix()}")
            ignored = any(part in IGNORED_COMPONENTS for part in relative.parts)
            if stat.S_ISDIR(mode):
                if not ignored:
                    pending.append(path)
            elif not stat.S_ISREG(mode):
                raise IdentityFailure(f"source-archive identity scan refuses non-regular entry: {relative.as_posix()}")
            elif not ignored and path.suffix not in IGNORED_SUFFIXES:
                result.append(path)
    return sorted(result, key=lambda path: path.relative_to(root).as_posix())


def tracked_paths(root: Path) -> list[Path]:
    try:
        payload = subprocess.check_output(["git", "ls-files", "-z"], cwd=root, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return fallback_source_paths(root)
    return [root / raw.decode("utf-8") for raw in payload.split(b"\0") if raw]


def collect_consts(value: Any) -> list[Any]:
    if isinstance(value, dict):
        return ([value["const"]] if "const" in value else []) + [item for child in value.values() for item in collect_consts(child)]
    if isinstance(value, list):
        return [item for child in value for item in collect_consts(child)]
    return []


def validate_no_deprecated_owner(root: Path) -> int:
    deprecated = DEPRECATED_OWNER.encode()
    paths = tracked_paths(root)
    offenders: list[str] = []
    for path in paths:
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise IdentityFailure(f"cannot read tracked path {path.relative_to(root)}: {error}") from error
        if deprecated in payload:
            offenders.append(path.relative_to(root).as_posix())
    require(not offenders, "deprecated owner identity remains in: " + ", ".join(sorted(offenders)))
    return len(paths)


def validate_repository_identity(root: Path = ROOT) -> int:
    root = Path(root)
    require(not root.is_symlink(), f"repository root must not be a symlink: {root}")
    require(root.is_dir(), f"repository root is missing: {root}")
    for relative in REQUIRED_PATHS:
        require((root / relative).is_file(), f"required identity surface is missing: {relative}")

    tracked_count = validate_no_deprecated_owner(root)
    for relative, (minimum_name, minimum_id) in CURRENT_SCHEMA_BINDINGS.items():
        consts = collect_consts(read_json(root, relative))
        require(HISTORICAL_REPOSITORY not in consts, f"{relative}: historical repository name is accepted by a current schema")
        require(consts.count(CURRENT_REPOSITORY) >= minimum_name, f"{relative}: current repository full-name binding is missing")
        require(consts.count(CURRENT_REPOSITORY_ID) >= minimum_id, f"{relative}: stable repository-ID binding is missing")

    for relative in CURRENT_EXECUTION_SURFACES:
        text = read_text(root, relative)
        require(HISTORICAL_REPOSITORY not in text, f"{relative}: historical repository name leaked into current execution")
        require(CURRENT_REPOSITORY in text, f"{relative}: current repository full name is not bound")
    identity = parse_workflow_identity_environment(read_text(root, WORKFLOW_PATH))
    require(identity == EXPECTED_WORKFLOW_ENVIRONMENT, f"canonical workflow identity environment drift: {identity!r}")

    closure = load_yaml(read_text(root, "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"), "final closure input")
    integration = mapping(closure.get("canonical_integration"), "canonical_integration")
    require(integration.get("repository_id") == str(CURRENT_REPOSITORY_ID), "final closure canonical_integration.repository_id drift")
    require(integration.get("repository") == CURRENT_REPOSITORY, "final closure canonical_integration.repository drift")
    require(integration.get("repository_owner") == CURRENT_OWNER, "final closure canonical_integration.repository_owner drift")
    require(integration.get("source_identity") == "RESOLVE_FROM_EVENT_AND_GIT_NOT_FROM_STATIC_DOCUMENT", "final closure source identity resolution drift")
    require(integration.get("synthetic_merge_identity") == "RESOLVE_FROM_PULL_REQUEST_EVENT_AND_VERIFY_TWO_PARENTS", "final closure synthetic merge identity resolution drift")
    ratification = mapping(closure.get("ratification_authenticity"), "ratification_authenticity")
    require(ratification.get("designated_ratifier_login") == DESIGNATED_RATIFIER_LOGIN, "final closure designated ratifier login drift")
    require(ratification.get("designated_ratifier_account_id") == str(DESIGNATED_RATIFIER_ACCOUNT_ID), "final closure designated ratifier account drift")
    require(ratification.get("repository_owner_may_differ_from_ratifier") == "true", "final closure repository_owner_may_differ_from_ratifier must remain true")

    for relative in (
        "docs/plan/HEPTABAO_PLAN_V1_3_1_REPOSITORY_GAP_CLOSURE.md",
        "docs/execution/HEPTABAO_V1_3_1_FINAL_CLOSURE_PROTOCOL.md",
    ):
        text = read_text(root, relative)
        require(CURRENT_REPOSITORY in text, f"{relative}: current repository not documented")
        require(HISTORICAL_REPOSITORY in text, f"{relative}: historical lineage not documented")
        require(DESIGNATED_RATIFIER_LOGIN in text, f"{relative}: designated ratifier separation not documented")
    codeowners = read_text(root, ".github/CODEOWNERS")
    require("Bootstrap ownership only" in codeowners, "CODEOWNERS must explicitly remain bootstrap-only until independent teams exist")
    require("does not satisfy independent-review" in codeowners, "CODEOWNERS must not claim to satisfy independent review")
    require(f"* @{DESIGNATED_RATIFIER_LOGIN}" in codeowners, "bootstrap CODEOWNERS entry for the designated repository steward is missing")
    return tracked_count


def main(argv: Iterable[str] | None = None) -> int:
    arguments = list(argv if argv is not None else sys.argv[1:])
    if len(arguments) > 1:
        print("usage: validate_repository_identity_v1.py [REPOSITORY_ROOT]", file=sys.stderr)
        return 2
    root = Path(arguments[0]).resolve() if arguments else ROOT
    try:
        count = validate_repository_identity(root)
    except (IdentityFailure, OSError) as error:
        print(f"repository identity validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "repository identity validation passed: "
        f"repository_id={CURRENT_REPOSITORY_ID} current={CURRENT_REPOSITORY} "
        f"historical={HISTORICAL_REPOSITORY} "
        f"ratifier={DESIGNATED_RATIFIER_LOGIN}/{DESIGNATED_RATIFIER_ACCOUNT_ID} "
        f"tracked_files={count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
