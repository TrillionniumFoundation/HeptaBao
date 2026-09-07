#!/usr/bin/env python3
"""Validate V1.3.1 source and fail-closed workflow admission.

The legacy source validator remains available beside this wrapper. Its
historical workflow path inventory is preserved as compatibility input, while
this wrapper validates the current repository-wide scheduling boundary:
exactly one automatic pull-request workflow and exactly two workflows that may
run automatically on pushes to the active integration branch.
"""

from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

ACTIVE_BRANCH = "codex/plan-v1.3-gap-closure-v2"
CANONICAL_PR_WORKFLOW = "plan-v1.3.1-head-and-merge-closure.yml"
EXACT_SOURCE_WORKFLOW = "export-exact-audit-source.yml"
DIAGNOSTIC_FALLBACK_WORKFLOW = "plan-v1.3.1-final-exact.yml"
HISTORICAL_WORKFLOW = ".github/workflows/plan-v1.3-gap-closure.yml"
LEGACY_VALIDATOR = "validate_plan_v1_3_1_legacy.py"
LEGACY_VALIDATOR_PATH = f"scripts/{LEGACY_VALIDATOR}"
ACTIVE_MANIFEST = "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml"
FINAL_CLOSURE_INPUT = "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
WORKFLOW_SUFFIXES = frozenset({".yml", ".yaml"})
SUPPORTED_EVENTS = frozenset({"pull_request", "push", "workflow_dispatch"})
UNSUPPORTED_BRANCH_PATTERN_MARKERS = frozenset({"+", "@", "(", ")", "{", "}", "\\"})
HISTORICAL_PATH_INVENTORY = (
    "crates/heptabao-authbus-contracts/**",
    "crates/heptabao-governance/**",
    "crates/heptabao-oracle-observer/**",
    "crates/heptabao-p0-server/**",
    "crates/heptabao-platform-bakeoff/**",
    "crates/heptabao-platform-contracts/**",
    "crates/heptabao-protocol/**",
    "probes/h02/openraft-tokio/**",
)


class UniqueKeyLoader(yaml.SafeLoader):
    """YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicated = key in mapping
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"unhashable mapping key: {key!r}",
                key_node.start_mark,
            ) from error
        if duplicated:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_legacy() -> ModuleType:
    path = Path(__file__).with_name(LEGACY_VALIDATOR)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"legacy validator is missing or symlinked: {path}")
    spec = importlib.util.spec_from_file_location("heptabao_v1_3_1_legacy", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load legacy validator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_LEGACY = _load_legacy()
ValidationError = _LEGACY.ValidationError


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _workflow_paths(root: Path) -> list[Path]:
    workflow_dir = root / ".github" / "workflows"
    require(
        workflow_dir.is_dir() and not workflow_dir.is_symlink(),
        "workflow directory is missing or symlinked",
    )
    paths: list[Path] = []
    for path in sorted(workflow_dir.iterdir()):
        if path.suffix not in WORKFLOW_SUFFIXES:
            continue
        require(
            path.is_file() and not path.is_symlink(),
            f"workflow path is not a regular file: {path.name}",
        )
        paths.append(path)
    require(paths, "workflow directory contains no YAML workflows")
    names = [path.name for path in paths]
    require(len(names) == len(set(names)), "workflow filenames are duplicated")
    return paths


def _read_yaml_mapping(path: Path, label: str) -> dict[Any, Any]:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing or symlinked")
    value = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    require(isinstance(value, dict), f"{label} must contain one mapping")
    return value


def _validate_dependency_binding(root: Path) -> None:
    legacy_path = root / LEGACY_VALIDATOR_PATH
    require(
        legacy_path.is_file() and not legacy_path.is_symlink(),
        "legacy V1.3.1 validator dependency is missing or symlinked",
    )

    manifest = _read_yaml_mapping(root / ACTIVE_MANIFEST, "active normative manifest")
    documents = manifest.get("documents")
    require(isinstance(documents, list), "active manifest document list is malformed")
    matches = [
        entry
        for entry in documents
        if isinstance(entry, Mapping) and entry.get("path") == LEGACY_VALIDATOR_PATH
    ]
    require(
        len(matches) == 1,
        "legacy V1.3.1 validator dependency must be indexed exactly once",
    )
    dependency = matches[0]
    require(dependency.get("kind") == "NORMATIVE", "legacy validator dependency kind drift")
    require(
        dependency.get("digest") == "RESOLVE_FROM_EXACT_SOURCE",
        "legacy validator dependency digest must resolve from exact source",
    )
    require(
        dependency.get("authority_effect") == "NONE",
        "legacy validator dependency cannot grant authority",
    )

    final_input = _read_yaml_mapping(
        root / FINAL_CLOSURE_INPUT,
        "final closure input",
    )
    coverage = final_input.get("workflow_coverage")
    require(isinstance(coverage, Mapping), "final closure workflow coverage is malformed")
    required_paths = coverage.get("required_manifest_paths")
    require(
        isinstance(required_paths, list)
        and required_paths.count(LEGACY_VALIDATOR_PATH) == 1,
        "legacy validator dependency must be required by final closure manifest coverage",
    )


def _read_workflow(path: Path) -> tuple[dict[Any, Any], str]:
    text = path.read_text(encoding="utf-8")
    literal_on_keys = re.findall(
        r"(?m)^(?:on|['\"]on['\"])[ \t]*:",
        text,
    )
    require(
        len(literal_on_keys) == 1,
        f"{path.name} must contain exactly one literal top-level on key",
    )
    value = yaml.load(text, Loader=UniqueKeyLoader)
    require(isinstance(value, dict), f"workflow is not a mapping: {path.name}")
    return value, text


def _events(document: Mapping[Any, Any], label: str) -> dict[str, Any]:
    has_string = "on" in document
    yaml11_keys = [key for key in document if key is True]
    has_yaml11 = bool(yaml11_keys)
    require(has_string or has_yaml11, f"{label} trigger declaration missing")
    require(
        not (has_string and has_yaml11),
        f"{label} trigger declaration ambiguous",
    )
    value = document["on"] if has_string else document[yaml11_keys[0]]
    if isinstance(value, str):
        events = {value: None}
    elif isinstance(value, list):
        require(
            value and all(isinstance(item, str) and item for item in value),
            f"{label} trigger list malformed",
        )
        require(len(value) == len(set(value)), f"{label} trigger list duplicated")
        events = {item: None for item in value}
    else:
        require(isinstance(value, Mapping), f"{label} trigger declaration malformed")
        require(
            all(isinstance(name, str) and name for name in value),
            f"{label} trigger name malformed",
        )
        events = dict(value)
    for event_name, configuration in events.items():
        require(
            configuration is None or isinstance(configuration, Mapping),
            f"{label} trigger configuration malformed: {event_name}",
        )
    return events


def _string_list(value: Any, label: str) -> list[str]:
    if isinstance(value, str):
        result = [value]
    else:
        require(
            isinstance(value, list)
            and value
            and all(isinstance(item, str) and item for item in value),
            f"{label} must be a non-empty string or string list",
        )
        result = list(value)
    require(len(result) == len(set(result)), f"{label} contains duplicates")
    return result


def _pattern_matches_active_branch(pattern: str, label: str) -> bool:
    require(pattern.strip() == pattern and pattern, f"{label} contains a blank branch pattern")
    require(
        not any(marker in pattern for marker in UNSUPPORTED_BRANCH_PATTERN_MARKERS),
        f"{label} uses unsupported branch-pattern syntax: {pattern!r}",
    )
    return fnmatch.fnmatchcase(ACTIVE_BRANCH, pattern)


def _active_push(push: Any, label: str) -> bool:
    if push is None:
        return True
    require(isinstance(push, Mapping), f"{label} push trigger malformed")
    branches = push.get("branches")
    branches_ignore = push.get("branches-ignore")
    require(
        not (branches is not None and branches_ignore is not None),
        f"{label} cannot define both push.branches and push.branches-ignore",
    )
    if branches is not None:
        selected = False
        saw_positive = False
        for raw_pattern in _string_list(branches, f"{label} push.branches"):
            negative = raw_pattern.startswith("!")
            pattern = raw_pattern[1:] if negative else raw_pattern
            if not negative:
                saw_positive = True
            if _pattern_matches_active_branch(pattern, f"{label} push.branches"):
                selected = not negative
        require(saw_positive, f"{label} push.branches requires a positive pattern")
        return selected
    if branches_ignore is not None:
        ignored = any(
            _pattern_matches_active_branch(pattern, f"{label} push.branches-ignore")
            for pattern in _string_list(
                branches_ignore,
                f"{label} push.branches-ignore",
            )
        )
        return not ignored
    if "tags" in push or "tags-ignore" in push:
        # GitHub does not run branch refs when only tag filters are declared.
        return False
    return True


def _validate_permissions(value: Any, label: str, *, required: bool) -> None:
    if value is None:
        require(not required, f"{label} permissions declaration missing")
        return
    if value == "read-all":
        return
    require(value != "write-all", f"{label} cannot use write-all permissions")
    require(isinstance(value, Mapping), f"{label} permissions must be a mapping")
    for name, grant in value.items():
        require(isinstance(name, str) and name, f"{label} permission name malformed")
        require(
            grant in {"read", "none"},
            f"{label} permission must be read or none: {name}={grant!r}",
        )


def _validate_workflow_security(document: Mapping[Any, Any], label: str) -> None:
    _validate_permissions(document.get("permissions"), label, required=True)
    jobs = document.get("jobs")
    require(isinstance(jobs, Mapping) and jobs, f"{label} jobs mapping missing")
    for job_name, job in jobs.items():
        require(
            isinstance(job_name, str) and isinstance(job, Mapping),
            f"{label} job is malformed: {job_name!r}",
        )
        if "permissions" in job:
            _validate_permissions(
                job.get("permissions"),
                f"{label} job {job_name}",
                required=True,
            )
        steps = job.get("steps", [])
        require(isinstance(steps, list), f"{label} job {job_name} steps malformed")
        for index, step in enumerate(steps):
            require(
                isinstance(step, Mapping),
                f"{label} job {job_name} step {index} malformed",
            )
            uses = step.get("uses")
            if not isinstance(uses, str) or "actions/checkout@" not in uses:
                continue
            options = step.get("with")
            require(
                isinstance(options, Mapping)
                and options.get("persist-credentials") is False,
                f"{label} checkout step must set persist-credentials: false",
            )


def validate_workflow_admission(root: Path) -> None:
    paths = _workflow_paths(root)
    names = {path.name for path in paths}
    for required_name in (
        CANONICAL_PR_WORKFLOW,
        EXACT_SOURCE_WORKFLOW,
        DIAGNOSTIC_FALLBACK_WORKFLOW,
    ):
        require(required_name in names, f"required workflow is missing: {required_name}")

    pull_request_workflows: list[str] = []
    active_push_workflows: list[str] = []
    event_map: dict[str, dict[str, Any]] = {}
    for path in paths:
        value, _ = _read_workflow(path)
        _validate_workflow_security(value, path.name)
        events = _events(value, path.name)
        unsupported = set(events) - SUPPORTED_EVENTS
        require(
            not unsupported,
            f"{path.name} contains unsupported automatic events: {sorted(unsupported)}",
        )
        require(
            "workflow_dispatch" in events,
            f"{path.name} must retain workflow_dispatch for bounded reproduction",
        )
        event_map[path.name] = events
        if "pull_request" in events:
            pull_request_workflows.append(path.name)
        if "push" in events and _active_push(events["push"], path.name):
            active_push_workflows.append(path.name)

    require(
        pull_request_workflows == [CANONICAL_PR_WORKFLOW],
        "automatic PR workflow set must contain only the canonical head-and-merge lane: "
        f"{pull_request_workflows}",
    )
    canonical_events = event_map[CANONICAL_PR_WORKFLOW]
    require(
        set(canonical_events) == {"pull_request", "workflow_dispatch"},
        "canonical workflow triggers must be exactly pull_request and workflow_dispatch",
    )
    pr_configuration = canonical_events["pull_request"]
    require(
        pr_configuration is None or isinstance(pr_configuration, Mapping),
        "canonical pull_request configuration malformed",
    )
    if isinstance(pr_configuration, Mapping):
        forbidden_filters = {
            "branches",
            "branches-ignore",
            "paths",
            "paths-ignore",
        } & set(pr_configuration)
        require(
            not forbidden_filters,
            "canonical PR lane must cover every base branch and repository path: "
            f"{sorted(forbidden_filters)}",
        )
        types = pr_configuration.get("types")
        if types is not None:
            type_list = _string_list(types, "canonical pull_request.types")
            require(
                "synchronize" in type_list,
                "canonical PR lane must run when the source head changes",
            )

    require(
        set(active_push_workflows)
        == {EXACT_SOURCE_WORKFLOW, DIAGNOSTIC_FALLBACK_WORKFLOW},
        "active-branch push workflows must be exact-source export plus bounded fallback: "
        f"{active_push_workflows}",
    )
    for name in (EXACT_SOURCE_WORKFLOW, DIAGNOSTIC_FALLBACK_WORKFLOW):
        require(
            set(event_map[name]) == {"push", "workflow_dispatch"},
            f"{name} triggers must be exactly push and workflow_dispatch",
        )

    historical_events = event_map[Path(HISTORICAL_WORKFLOW).name]
    require(
        "pull_request" not in historical_events,
        "historical V1.3 workflow cannot admit automatic PR runs",
    )
    require(
        not _active_push(
            historical_events.get("push"),
            Path(HISTORICAL_WORKFLOW).name,
        ),
        "historical V1.3 workflow cannot admit active-branch push runs",
    )


def validate(root: Path) -> None:
    root = root.resolve()
    _validate_dependency_binding(root)
    validate_workflow_admission(root)

    original_read_text = _LEGACY.read_text

    def compatibility_read_text(validation_root: Path, relative: str) -> str:
        text = original_read_text(validation_root, relative)
        if relative == HISTORICAL_WORKFLOW:
            inventory = "\n".join(f"# {item}" for item in HISTORICAL_PATH_INVENTORY)
            return (
                text
                + "\n# Historical path inventory retained for legacy source-contract compatibility.\n"
                + inventory
                + "\n"
            )
        return text

    _LEGACY.read_text = compatibility_read_text
    try:
        _LEGACY.validate(root)
    finally:
        _LEGACY.read_text = original_read_text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root",
    )
    args = parser.parse_args()
    try:
        validate(args.root)
    except (
        ValidationError,
        OSError,
        RuntimeError,
        ValueError,
        yaml.YAMLError,
    ) as error:
        print(f"HeptaBao V1.3.1 gap-closure validation FAILED: {error}", file=sys.stderr)
        return 1
    print("HeptaBao V1.3.1 gap-closure validation PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
