#!/usr/bin/env python3
"""Fail closed on credential/publication paths in this unqualified source tree.

This is a structural regression gate, not an independent approval or a sandbox.
All installed workflows are inspected, including manual and currently skipped
jobs. A future publisher needs a separately reviewed trust boundary; this gate
has no publishing exception and never downloads or executes artifact payloads.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

MAX_WORKFLOW_BYTES = 1024 * 1024
MAX_WORKFLOWS = 256
RETIRED_RELAYS = frozenset({
    "exec-v1.9.0-pr-relay.yml",
    "exec-v1.9.0-pr-relay-arm64.yml",
    "exec-v1.9.0-pr-relay-ubuntu22.yml",
})


class PolicyError(ValueError):
    """The input cannot establish this tree's read-only trust boundary."""


class WorkflowLoader(yaml.SafeLoader):
    pass


# YAML 1.1 treats the GitHub Actions key `on` as a boolean. Keep true/false
# booleans but do not mutate PyYAML's global loader configuration.
WorkflowLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in values
          if tag != "tag:yaml.org,2002:bool"]
    for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"),
    list("tTfF"),
)


def unique_mapping(loader: WorkflowLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    result = {}
    for key_node, value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise PolicyError("YAML merge keys are forbidden")
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise PolicyError(f"duplicate or non-string mapping key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


WorkflowLoader.add_constructor("tag:yaml.org,2002:map", unique_mapping)


def parse_workflow(text: str) -> dict[str, Any]:
    if len(text.encode("utf-8")) > MAX_WORKFLOW_BYTES:
        raise PolicyError("workflow size limit exceeded")
    try:
        for index, event in enumerate(yaml.parse(text)):
            if index > 100_000 or isinstance(event, yaml.events.AliasEvent):
                raise PolicyError("YAML aliases or excessive structure are forbidden")
        value = yaml.load(text, Loader=WorkflowLoader)
    except (yaml.YAMLError, RecursionError) as error:
        raise PolicyError(f"invalid workflow YAML: {error}") from error
    if not isinstance(value, dict) or not value:
        raise PolicyError("workflow must be a nonempty mapping")
    return value


def read_only(value: Any, location: str) -> None:
    if value == "read-all":
        return
    if not isinstance(value, dict):
        raise PolicyError(f"{location}: explicit read-only permissions required")
    for scope, access in value.items():
        if access not in ("read", "none") or scope == "id-token":
            raise PolicyError(f"{location}: prohibited permission {scope}={access!r}")


def walk(value: Any, location: str = "workflow"):
    yield location, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{location}[{index}]")


def validate_text(text: str, filename: str = "workflow.yml") -> None:
    if filename in RETIRED_RELAYS:
        raise PolicyError("retired relay must not be installed, even with if: false")
    workflow = parse_workflow(text)
    read_only(workflow.get("permissions"), "workflow.permissions")
    events = workflow.get("on")
    if isinstance(events, str):
        names = [events]
    elif isinstance(events, dict):
        names = list(events)
    elif isinstance(events, list) and all(isinstance(x, str) for x in events):
        names = events
    else:
        raise PolicyError("explicit event set required")
    if not names or set(names) & {"pull_request_target", "workflow_run"}:
        raise PolicyError("privileged or empty event set forbidden in qualification tree")
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise PolicyError("nonempty jobs required")
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            raise PolicyError(f"invalid job: {job_name}")
        # Reusable workflows can hide a publishing/credential path. No such
        # delegation is admitted until its complete transitive graph is reviewed.
        if "uses" in job or "secrets" in job:
            raise PolicyError(f"{job_name}: reusable workflow or secrets delegation forbidden")
        if not isinstance(job.get("steps"), list) or not job["steps"]:
            raise PolicyError(f"{job_name}: explicit nonempty steps required")
    for location, value in walk(workflow):
        if isinstance(value, dict):
            if "permissions" in value:
                read_only(value["permissions"], f"{location}.permissions")
            uses = value.get("uses")
            if isinstance(uses, str) and uses.lower().startswith("actions/checkout@"):
                options = value.get("with", {})
                if not isinstance(options, dict) or options.get("persist-credentials") is not False:
                    raise PolicyError(f"{location}: checkout must set persist-credentials: false")
                if "token" in options or "ssh-key" in options:
                    raise PolicyError(f"{location}: alternate checkout credentials forbidden")
        elif isinstance(value, str):
            if re.search(r"\$\{\{[^}]*\bsecrets\b", value, re.I):
                raise PolicyError(f"{location}: secret injection forbidden")
            if ".exec/run_v1_9.sh" in value or "exec/v1.9.0-full-repository-convergence-v1" in value:
                raise PolicyError(f"{location}: retired controller execution forbidden")


def validate_directory(directory: Path) -> dict[str, Any]:
    if directory.is_symlink() or not directory.is_dir():
        raise PolicyError("workflow directory missing or symlinked")
    paths = sorted(p for p in directory.iterdir() if p.suffix.lower() in {".yml", ".yaml"})
    if not paths or len(paths) > MAX_WORKFLOWS:
        raise PolicyError("empty or excessive workflow set")
    checked = []
    failures = []
    for path in paths:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_WORKFLOW_BYTES:
                raise PolicyError("nonregular or oversized workflow")
            validate_text(path.read_text(encoding="utf-8"), path.name)
            checked.append(path.name)
        except (PolicyError, OSError, UnicodeError, RecursionError) as error:
            failures.append({"path": path.name, "error": str(error)})
    return {"schema": "heptabao.workflow-trust-check.v1", "checked": checked,
            "failures": failures, "result": "FAIL" if failures else "PASS",
            "authority_effect": "NONE", "production_authority": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path,
                        default=Path(__file__).resolve().parents[1] / ".github/workflows")
    args = parser.parse_args()
    try:
        result = validate_directory(args.directory)
    except (PolicyError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return int(bool(result["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
