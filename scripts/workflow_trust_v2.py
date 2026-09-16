"""V2 executable-input and artifact-action closure for workflow trust checks.

This module extends the frozen V1 structural checker.  It remains a
candidate-controlled static policy, not an independent admission authority or a
runtime sandbox.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

import validate_workflow_trust_v1 as base

MAX_TEMPLATE_BYTES = 4096
CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_ACTION = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
UPLOAD_ARTIFACT_ACTION = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD_ARTIFACT_ACTION = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
EXPRESSION_RE = re.compile(r"\$\{\{(.*?)}}", re.S)
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SAFE_FRAGMENT_RE = re.compile(r"[A-Za-z0-9_./:+-]*")
SAFE_MATRIX_VALUE_RE = re.compile(r"[A-Za-z0-9_./:+-]{1,256}")
MATRIX_RE = re.compile(r"matrix\.([A-Za-z_][A-Za-z0-9_]*)")
STEP_OUTPUT_RE = re.compile(r"steps\.[A-Za-z_][A-Za-z0-9_-]*\.outputs\.[A-Za-z_][A-Za-z0-9_-]*")
NEEDS_RESULT_RE = re.compile(r"needs\.[A-Za-z_][A-Za-z0-9_-]*\.result")
ENV_REF_RE = re.compile(r"env\.([A-Za-z_][A-Za-z0-9_]*)")

SAFE_GITHUB_EXPRESSIONS = frozenset({
    "github.sha",
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.sha || github.sha",
    "github.event.pull_request.base.sha",
    "github.event.pull_request.base.sha || ''",
    "github.event.pull_request.head.repo.owner.login || github.repository_owner",
    "github.event.pull_request.number || ''",
    "github.event.pull_request.number || 'workflow_dispatch'",
    "github.run_id",
    "github.run_attempt",
    "matrix.source_kind == 'merge' && github.sha || (github.event.pull_request.head.sha || github.sha)",
    "matrix.source_kind == 'prospective-merge' && github.sha || github.event.pull_request.head.sha",
})
DYNAMIC_MATRIX_ENUMS = {
    "${{ fromJSON(github.event_name == 'pull_request' && '[\"head\",\"merge\"]' || '[\"head\"]') }}":
        ("head", "merge"),
}


def _load_registry() -> tuple[dict[tuple[str, str], str], dict[tuple[str, str], dict[str, Any]]]:
    path = Path(__file__).with_name("workflow_trust_action_registry_v2.json")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "heptabao.workflow-trust-action-registry.v2":
        raise base.PolicyError("workflow action registry schema mismatch")
    uploads: dict[tuple[str, str], str] = {}
    downloads: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in value.get("uploads", []):
        key = (entry["file"], entry["location"])
        if key in uploads or not isinstance(entry.get("path"), str):
            raise base.PolicyError("duplicate or invalid upload registry entry")
        uploads[key] = entry["path"]
    for entry in value.get("downloads", []):
        key = (entry["file"], entry["location"])
        if key in downloads:
            raise base.PolicyError("duplicate download registry entry")
        downloads[key] = {name: entry[name] for name in ("pattern", "path", "merge-multiple")}
    if len(uploads) != 30 or len(downloads) != 1:
        raise base.PolicyError("workflow action registry cardinality mismatch")
    return uploads, downloads


APPROVED_UPLOAD_PATHS, APPROVED_DOWNLOAD_OPTIONS = _load_registry()
ObserverException = Callable[[str, Any], bool]


def compact(value: str) -> str:
    return " ".join(value.strip().split())


def _matrix_values(job: dict[str, Any], key: str, location: str) -> list[str]:
    strategy = job.get("strategy", {})
    matrix = strategy.get("matrix", {}) if isinstance(strategy, dict) else {}
    if not isinstance(matrix, dict):
        raise base.PolicyError(f"{location}: dynamic matrix cannot select executable inputs")
    raw = matrix.get(key)
    if isinstance(raw, list):
        values: list[Any] = list(raw)
    elif isinstance(raw, str) and raw in DYNAMIC_MATRIX_ENUMS:
        values = list(DYNAMIC_MATRIX_ENUMS[raw])
    else:
        values = []
    include = matrix.get("include", [])
    if not isinstance(include, list) or any(not isinstance(row, dict) for row in include):
        raise base.PolicyError(f"{location}: invalid matrix include")
    values.extend(row[key] for row in include if key in row)
    if not values or any(
        not isinstance(item, str)
        or SAFE_MATRIX_VALUE_RE.fullmatch(item) is None
        or item.startswith(("/", "-"))
        or ".." in item.split("/")
        for item in values
    ):
        raise base.PolicyError(f"{location}: matrix executable inputs must be finite safe strings")
    return list(dict.fromkeys(values))


def _check_expression(
    expression: str,
    job: dict[str, Any],
    location: str,
    observer_exception: ObserverException,
    effective_env: dict[str, str] | None = None,
) -> None:
    value = compact(expression)
    wrapped = "${{ " + value + " }}"
    if value == "github.token":
        if observer_exception(location, wrapped):
            return
        raise base.PolicyError(f"{location}: GitHub token/context injection forbidden")
    if value in SAFE_GITHUB_EXPRESSIONS or value == "runner.temp":
        return
    match = MATRIX_RE.fullmatch(value)
    if match:
        _matrix_values(job, match.group(1), location)
        return
    if STEP_OUTPUT_RE.fullmatch(value) or NEEDS_RESULT_RE.fullmatch(value):
        return
    match = ENV_REF_RE.fullmatch(value)
    if match and effective_env is not None:
        name = match.group(1)
        if name == "SOURCE_SHA" and base.is_sha_source(effective_env.get(name)):
            return
    raise base.PolicyError(f"{location}: expression source is not in the executable-data allowlist")


def _check_template(
    value: str,
    job: dict[str, Any],
    location: str,
    observer_exception: ObserverException,
    effective_env: dict[str, str] | None = None,
) -> None:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        raise base.PolicyError(f"{location}: bounded static string required")
    for match in EXPRESSION_RE.finditer(value):
        _check_expression(match.group(1), job, location, observer_exception, effective_env)
    static = EXPRESSION_RE.sub("", value)
    if "\n" in static or "\x00" in static or SAFE_FRAGMENT_RE.fullmatch(static) is None:
        raise base.PolicyError(f"{location}: unsafe static template characters")


def _check_env(
    mapping: dict[str, Any],
    job: dict[str, Any],
    location: str,
    observer_exception: ObserverException,
    effective_env: dict[str, str],
) -> None:
    for name, value in mapping.items():
        target = f"{location}.{name}"
        if ENV_NAME_RE.fullmatch(name) is None or not isinstance(value, str):
            raise base.PolicyError(f"{target}: static string environment entry required")
        canonical = name.lower().replace("_", "-")
        if canonical in base.CREDENTIAL_KEYS or canonical.startswith("ssh-"):
            if not observer_exception(target, value):
                raise base.PolicyError(f"{target}: credential-bearing key outside frozen observer")
        if EXPRESSION_RE.search(value):
            _check_template(value, job, target, observer_exception, effective_env)


def _check_env_sinks(script: str, effective_env: dict[str, str], location: str) -> None:
    for name in effective_env:
        variable = rf"\$(?:{re.escape(name)}\b|\{{{re.escape(name)}\}})"
        if re.search(rf"\b(?:bash|sh|dash|zsh)\s+-c\s+[\"']?{variable}", script):
            raise base.PolicyError(f"{location}: environment-fed shell program is forbidden")
        if re.search(rf"\beval\b[^\n]*{variable}", script):
            raise base.PolicyError(f"{location}: environment-fed eval is forbidden")
        if re.search(rf"(?:^|;\s*|&&\s*|\|\|\s*)[\"']?{variable}", script, re.M):
            raise base.PolicyError(f"{location}: environment value cannot select a command")
        if re.search(rf"(?:^|\n)\s*(?:source|\.)\s+[\"']?{variable}(?:[/\"']|\s|$)", script):
            raise base.PolicyError(f"{location}: environment-fed source path is forbidden")


def check_upload_path(
    value: str,
    job: dict[str, Any],
    location: str,
    observer_exception: ObserverException,
    effective_env: dict[str, str],
) -> None:
    if not isinstance(value, str):
        raise base.PolicyError(f"{location}: artifact path must be a static string")
    paths = [line.strip() for line in value.splitlines() if line.strip()]
    if not paths:
        raise base.PolicyError(f"{location}: artifact path set is empty")
    for item in paths:
        if any(token in item for token in ("*", "?", "[", "]", "\\", "~", "\x00")):
            raise base.PolicyError(f"{location}: artifact glob or ambiguous path is forbidden")
        for match in EXPRESSION_RE.finditer(item):
            _check_expression(match.group(1), job, location, observer_exception, effective_env)
        expressions = [compact(match.group(1)) for match in EXPRESSION_RE.finditer(item)]
        if expressions:
            if expressions[0] != "runner.temp" or not item.startswith("${{ runner.temp }}/"):
                raise base.PolicyError(f"{location}: dynamic artifact root must be runner.temp")
            suffix = item[len("${{ runner.temp }}/"):]
            static = EXPRESSION_RE.sub("", suffix)
            if not suffix or static.startswith(("/", "-")) or ".." in static.split("/") or "$" in static:
                raise base.PolicyError(f"{location}: broad or escaping runner temporary export is forbidden")
        elif item.startswith(("/", "-", ".")) or ".." in item.split("/") or "$" in item:
            raise base.PolicyError(f"{location}: artifact path may not escape its declared root")


def _checkout(options: dict[str, Any], location: str, env: dict[str, str]) -> None:
    if set(options) - {"ref", "fetch-depth", "persist-credentials"}:
        raise base.PolicyError(f"{location}: checkout input outside closed schema")
    if options.get("persist-credentials") is not False:
        raise base.PolicyError(f"{location}: checkout must set persist-credentials: false")
    if "fetch-depth" in options and options["fetch-depth"] not in (0, 1):
        raise base.PolicyError(f"{location}: checkout fetch-depth must be 0 or 1")
    ref = options.get("ref")
    if ref is not None:
        if "".join(str(ref).split()) == "${{env.SOURCE_SHA}}":
            ref = env.get("SOURCE_SHA")
        if not base.is_sha_source(ref):
            raise base.PolicyError(f"{location}: checkout ref is not an exact-SHA selector")


def _setup_python(options: dict[str, Any], location: str) -> None:
    if set(options) - {"python-version", "cache", "cache-dependency-path"}:
        raise base.PolicyError(f"{location}: setup-python input outside closed schema")
    if options.get("python-version") not in {"3.12", "3.13"}:
        raise base.PolicyError(f"{location}: setup-python version must be a reviewed static version")
    if "cache" in options:
        if options.get("cache") != "pip" or options.get("cache-dependency-path") != "requirements-plan.txt":
            raise base.PolicyError(f"{location}: setup-python cache inputs outside closed schema")
    elif "cache-dependency-path" in options:
        raise base.PolicyError(f"{location}: cache dependency path without reviewed cache mode")


def _upload(
    options: dict[str, Any], filename: str, location: str, job: dict[str, Any],
    observer_exception: ObserverException, env: dict[str, str],
) -> None:
    if set(options) != {"name", "path", "if-no-files-found", "retention-days"}:
        raise base.PolicyError(f"{location}: upload-artifact input set outside closed schema")
    if APPROVED_UPLOAD_PATHS.get((filename, location)) != options.get("path"):
        raise base.PolicyError(f"{location}: upload path is not the reviewed per-invocation path")
    if options.get("if-no-files-found") not in {"error", "warn"}:
        raise base.PolicyError(f"{location}: upload missing-file policy outside closed schema")
    retention = options.get("retention-days")
    if isinstance(retention, bool) or not isinstance(retention, int) or not 1 <= retention <= 30:
        raise base.PolicyError(f"{location}: upload retention must be an integer from 1 through 30")
    name = options.get("name")
    if not isinstance(name, str) or not name or len(name) > 256:
        raise base.PolicyError(f"{location}: bounded artifact name required")
    _check_template(name, job, f"{location}.with.name", observer_exception, env)
    check_upload_path(options["path"], job, f"{location}.with.path", observer_exception, env)


def _download(
    options: dict[str, Any], filename: str, location: str, job: dict[str, Any],
    observer_exception: ObserverException, env: dict[str, str],
) -> None:
    if set(options) != {"pattern", "path", "merge-multiple"}:
        raise base.PolicyError(f"{location}: download-artifact input set outside closed schema")
    expected = APPROVED_DOWNLOAD_OPTIONS.get((filename, location))
    actual = {name: options.get(name) for name in ("pattern", "path", "merge-multiple")}
    if expected != actual:
        raise base.PolicyError(f"{location}: download-artifact inputs are not the reviewed invocation")
    if options.get("merge-multiple") is not False:
        raise base.PolicyError(f"{location}: artifact merging is forbidden")
    _check_template(options["pattern"], job, f"{location}.with.pattern", observer_exception, env)
    check_upload_path(options["path"], job, f"{location}.with.path", observer_exception, env)


def _action(
    step: dict[str, Any], filename: str, location: str, job: dict[str, Any],
    observer_exception: ObserverException, env: dict[str, str],
) -> None:
    action = step.get("uses")
    options = step.get("with", {})
    if not isinstance(action, str) or not isinstance(options, dict):
        raise base.PolicyError(f"{location}: invalid action step")
    if action == CHECKOUT_ACTION:
        _checkout(options, location, env)
    elif action == SETUP_PYTHON_ACTION:
        _setup_python(options, location)
    elif action == UPLOAD_ARTIFACT_ACTION:
        _upload(options, filename, location, job, observer_exception, env)
    elif action == DOWNLOAD_ARTIFACT_ACTION:
        _download(options, filename, location, job, observer_exception, env)
    elif action not in base.PINNED_ACTIONS:
        raise base.PolicyError(f"{location}: action is not pinned in the executable allowlist")


def validate_extra(text: str, filename: str = "workflow.yml") -> None:
    workflow = base.load_workflow(text, filename)
    if not isinstance(workflow, dict):
        raise base.PolicyError("workflow root must be a mapping")
    root_env = workflow.get("env", {})
    if not isinstance(root_env, dict):
        raise base.PolicyError("workflow env must be a mapping")
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        raise base.PolicyError("workflow jobs must be a mapping")
    observer_exception = base.make_observer_exception(filename)
    for job_name, job in jobs.items():
        location = f"workflow.jobs.{job_name}"
        if not isinstance(job, dict):
            raise base.PolicyError(f"{location}: job must be a mapping")
        effective_env: dict[str, str] = {}
        _check_env(root_env, job, "workflow.env", observer_exception, effective_env)
        effective_env.update(root_env)
        job_env = job.get("env", {})
        if not isinstance(job_env, dict):
            raise base.PolicyError(f"{location}.env: mapping required")
        _check_env(job_env, job, f"{location}.env", observer_exception, effective_env)
        effective_env.update(job_env)
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            raise base.PolicyError(f"{location}.steps: list required")
        for index, step in enumerate(steps):
            step_location = f"{location}.steps[{index}]"
            if not isinstance(step, dict):
                raise base.PolicyError(f"{step_location}: mapping required")
            step_env = step.get("env", {})
            if not isinstance(step_env, dict):
                raise base.PolicyError(f"{step_location}.env: mapping required")
            scoped_env = dict(effective_env)
            _check_env(step_env, job, f"{step_location}.env", observer_exception, scoped_env)
            scoped_env.update(step_env)
            if "uses" in step:
                _action(step, filename, step_location, job, observer_exception, scoped_env)
            run = step.get("run")
            if run is not None:
                if not isinstance(run, str):
                    raise base.PolicyError(f"{step_location}.run: script must be a string")
                for match in EXPRESSION_RE.finditer(run):
                    _check_expression(match.group(1), job, f"{step_location}.run", observer_exception, scoped_env)
                _check_env_sinks(run, scoped_env, f"{step_location}.run")


def registry_digest() -> str:
    path = Path(__file__).with_name("workflow_trust_action_registry_v2.json")
    return hashlib.sha256(path.read_bytes()).hexdigest()
