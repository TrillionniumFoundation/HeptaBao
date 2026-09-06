#!/usr/bin/env python3
"""Fail closed on credential/publication paths in this unqualified source tree.

This is a candidate-controlled structural regression gate, not an independent
admission policy, credential-free environment, immutable runner-image proof or
transitive script sandbox.
All installed workflows are inspected, including manual and currently skipped
jobs. A future publisher needs a separately reviewed trust boundary; this gate
has no publishing exception and never downloads or executes artifact payloads.
"""
from __future__ import annotations

import argparse
import hashlib
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


# This finite set constrains the YAML runner/action surface. Runner labels are
# service selectors, NOT immutable machine images or proof of live runner-group
# administration. The historical ubuntu-latest selector is retained explicitly.
HOSTED_RUNNER_LABELS = frozenset({
    "ubuntu-24.04", "ubuntu-24.04-arm", "ubuntu-latest", "ubuntu-slim", "macos-15",
})
PINNED_ACTIONS = frozenset({
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
})
SHA_EXPRESSIONS = frozenset("".join(value.split()) for value in (
    "${{ github.sha }}",
    "${{ github.event.pull_request.head.sha }}",
    "${{ github.event.pull_request.base.sha }}",
    "${{ github.event.pull_request.head.sha || github.sha }}",
    "${{ matrix.source_kind == 'prospective-merge' && github.sha || github.event.pull_request.head.sha }}",
    "${{ matrix.source_kind == 'merge' && github.sha || (github.event.pull_request.head.sha || github.sha) }}",
))
HISTORICAL_READ_TOKEN_FILE = "plan-v1.3.1-head-and-merge-closure.yml"
HISTORICAL_READ_TOKEN_DIGEST = "738b38909dc8bc44a8e848252bf7dc30c3a540a7641da8f6002c9a263b39017d"
HISTORICAL_READ_TOKEN_LOCATIONS = frozenset({
    "workflow.jobs.full-technical-matrix.steps[1].env.GH_TOKEN",
    "workflow.jobs.full-technical-matrix.steps[11].env.GH_TOKEN",
    "workflow.jobs.arbitrate-head-and-merge-evidence.steps[4].env.GH_TOKEN",
})
CREDENTIAL_KEYS = frozenset({
    "token", "github-token", "gh-token", "password", "username", "registry",
    "credentials", "private-key", "api-key", "access-key", "access-token", "authorization",
})
EXPRESSION_RE = re.compile(r"\$\{\{(.*?)}}", re.S)


def is_sha_source(value: Any) -> bool:
    return isinstance(value, str) and (
        re.fullmatch(r"[0-9a-f]{40}", value) is not None
        or "".join(value.split()) in SHA_EXPRESSIONS
    )


def check_relative_path(value: Any, location: str) -> None:
    if (not isinstance(value, str) or not value
            or re.fullmatch(r"[A-Za-z0-9_./-]+", value) is None
            or value.startswith(("/", "-")) or ".." in value.split("/")):
        raise PolicyError(f"{location}: static workspace-relative path required")


def check_inline_expressions(script: str, job: dict[str, Any], location: str) -> None:
    # Expressions inserted into shell programs are restricted to SHA selectors
    # or finite source-defined matrix strings without shell metacharacters.
    # This is not a shell parser or a transitive script sandbox.
    for match in EXPRESSION_RE.finditer(script):
        expression = match.group(0)
        if is_sha_source(expression):
            continue
        matrix_match = re.fullmatch(r"\s*matrix\.([A-Za-z_][A-Za-z0-9_]*)\s*", match.group(1))
        if matrix_match is None:
            raise PolicyError(f"{location}: unbounded expression in shell program")
        key = matrix_match.group(1)
        strategy = job.get("strategy", {})
        matrix = strategy.get("matrix", {}) if isinstance(strategy, dict) else {}
        if not isinstance(matrix, dict):
            raise PolicyError(f"{location}: dynamic matrix cannot select executable inputs")
        values = list(matrix.get(key, [])) if isinstance(matrix.get(key), list) else []
        include = matrix.get("include", [])
        if not isinstance(include, list) or any(not isinstance(row, dict) for row in include):
            raise PolicyError(f"{location}: invalid matrix include")
        values.extend(row[key] for row in include if key in row)
        if not values or any(not isinstance(v, str) or not v
                or re.fullmatch(r"[A-Za-z0-9_./-]+", v) is None
                or v.startswith(("/", "-")) or ".." in v.split("/") for v in values):
            raise PolicyError(f"{location}: matrix executable inputs must be finite safe strings")
    continued = False
    for line in script.splitlines():
        if not continued and re.search(r"^\s*(?:exec\s+)?[\"']?\$(?:\{|\(|[A-Za-z_])", line):
            raise PolicyError(f"{location}: dynamic command selector is forbidden")
        continued = line.rstrip().endswith("\\")


def check_execution_surface(workflow: dict[str, Any], filename: str, source: str) -> None:
    frozen_observer = (filename == HISTORICAL_READ_TOKEN_FILE
                       and hashlib.sha256(source.encode("utf-8")).hexdigest()
                       == HISTORICAL_READ_TOKEN_DIGEST)

    def observer_exception(location: str, value: Any) -> bool:
        return (frozen_observer and location in HISTORICAL_READ_TOKEN_LOCATIONS
                and value == "${{ github.token }}")

    root_env = workflow.get("env", {})
    if not isinstance(root_env, dict):
        raise PolicyError("workflow.env: explicit mapping required")
    for name, job in workflow["jobs"].items():
        location = f"workflow.jobs.{name}"
        runner = job.get("runs-on")
        if not isinstance(runner, str) or runner not in HOSTED_RUNNER_LABELS:
            raise PolicyError(f"{location}: runner must be an explicitly listed hosted selector")
        for field in ("environment", "container", "services"):
            if field in job:
                raise PolicyError(f"{location}.{field}: deployment/container delegation forbidden")
        job_env = job.get("env", {})
        if not isinstance(job_env, dict):
            raise PolicyError(f"{location}.env: explicit mapping required")
        for index, step in enumerate(job["steps"]):
            step_location = f"{location}.steps[{index}]"
            if not isinstance(step, dict):
                raise PolicyError(f"{step_location}: step must be a mapping")
            if ("run" in step) == ("uses" in step):
                raise PolicyError(f"{step_location}: exactly one run or uses is required")
            if "uses" in step:
                uses = step["uses"]
                if not isinstance(uses, str) or uses not in PINNED_ACTIONS:
                    raise PolicyError(f"{step_location}: action not in immutable first-party allowlist")
                options = step.get("with", {})
                if not isinstance(options, dict):
                    raise PolicyError(f"{step_location}.with: mapping required")
                if uses.startswith("actions/checkout@"):
                    if "repository" in options:
                        raise PolicyError(f"{step_location}: alternate checkout repository forbidden")
                    if "path" in options:
                        check_relative_path(options["path"], f"{step_location}.with.path")
                    ref = options.get("ref")
                    if ref is not None:
                        if "".join(str(ref).split()) == "${{env.SOURCE_SHA}}":
                            step_env = step.get("env", {})
                            if not isinstance(step_env, dict):
                                raise PolicyError(f"{step_location}.env: mapping required")
                            effective = {**root_env, **job_env, **step_env}
                            ref = effective.get("SOURCE_SHA")
                        if not is_sha_source(ref):
                            raise PolicyError(f"{step_location}: checkout ref is not an exact-SHA selector")
            else:
                if not isinstance(step["run"], str) or not step["run"].strip():
                    raise PolicyError(f"{step_location}.run: nonempty static program required")
                check_inline_expressions(step["run"], job, step_location)

    for location, value in walk(workflow):
        if location.endswith(".env") and not isinstance(value, dict):
            raise PolicyError(f"{location}: dynamic environment mapping forbidden")
        if location.endswith(".defaults"):
            if (not isinstance(value, dict) or set(value) != {"run"}
                    or not isinstance(value["run"], dict)
                    or not set(value["run"]) <= {"shell", "working-directory"}):
                raise PolicyError(f"{location}: explicit closed run defaults required")
        if isinstance(value, dict):
            for key, child in value.items():
                canonical = key.lower().replace("_", "-")
                target = f"{location}.{key}"
                if canonical in CREDENTIAL_KEYS or canonical.startswith("ssh-"):
                    if not observer_exception(target, child):
                        raise PolicyError(f"{target}: credential-bearing key outside frozen observer")
        if location.endswith(".shell") and value != "bash":
            raise PolicyError(f"{location}: only the static bash shell is admitted")
        if location.endswith(".working-directory"):
            check_relative_path(value, location)
        if isinstance(value, str):
            for match in EXPRESSION_RE.finditer(value):
                expression = "".join(match.group(1).lower().split())
                credential_context = ("github" in expression and (
                    "token" in expression or expression == "github" or "tojson(github" in expression))
                if credential_context and not observer_exception(location, value):
                    raise PolicyError(f"{location}: GitHub token/context injection forbidden")


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
    check_execution_surface(workflow, filename, text)
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
            "authority_effect": "NONE", "production_authority": False,
            "independent_admission": False,
            "runner_image_immutability": "NOT_ESTABLISHED_BY_LABEL_ALLOWLIST",
            "credential_model": "read-only token use by pinned actions and one exact historical observer; not credential-free",
            "transitive_script_sandbox": False,
            "requires_live_runner_environment_and_independent_policy_controls": True}


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
