#!/usr/bin/env python3
"""Resolve HeptaBao's static canonical-state input against an exact source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

SHA40 = re.compile(r"^[0-9a-f]{40}$")
REF_SAFE = re.compile(r"^[A-Za-z0-9._/@+:-]+$")
DEFAULT_STATE_INPUT = "planning/HEPTABAO_CANONICAL_PROJECT_STATE_V1.yaml"
DEFAULT_MANIFEST = "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml"
HISTORICAL_REPOSITORY = "ProfHepta/HeptaBao"
CURRENT_REPOSITORY = "TrillionniumFoundation/HeptaBao"
ACTIVE_STATE_INPUT = "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""


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


class Failure(RuntimeError):
    pass


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise Failure(f"git {' '.join(args)} failed") from error


def repository_file(
    root: Path, requested: str | None, default: str, label: str
) -> tuple[Path, str]:
    """Resolve a repository-relative input and reject escaping/special paths."""

    relative = requested or default
    if not isinstance(relative, str) or not relative.strip():
        raise Failure(f"{label} must be a non-empty repository-relative path")
    candidate = Path(relative)
    if candidate.is_absolute():
        raise Failure(f"{label} must be repository-relative")
    # Do not follow a symlink supplied by an input document.  Resolving a
    # symlink first would let a manifest escape the checked-out source tree or
    # silently hash a mutable file outside the declared path.
    lexical = root / candidate
    if lexical.is_symlink():
        raise Failure(f"{label} must not be a symlink: {relative}")
    path = (root / candidate).resolve()
    try:
        normalized = path.relative_to(root).as_posix()
    except ValueError as error:
        raise Failure(f"{label} escapes the repository root") from error
    if not path.is_file():
        raise Failure(f"{label} does not name a regular file: {normalized}")
    return path, normalized


def read_mapping(path: Path, label: str) -> dict[str, Any]:
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise Failure(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise Failure(f"{label} must contain one mapping")
    return value


def require_pointer(
    mapping: dict[str, Any], key: str, expected: str, label: str, *, required: bool
) -> None:
    value = mapping.get(key)
    if value is None:
        if required:
            raise Failure(f"{label} is missing required pointer {key}")
        return
    if not isinstance(value, str) or value != expected:
        raise Failure(f"{label} {key} must point to {expected}")


def validate_inputs(
    root: Path,
    state: dict[str, Any],
    state_rel: str,
    manifest: dict[str, Any],
    manifest_rel: str,
) -> list[dict[str, str]]:
    """Validate state/manifest cross-pointers before hashing any documents.

    The historical defaults retain their V1.2 self-resolved binding contract.
    An explicitly selected revision (such as V1.3.1) must carry a complete,
    mutually consistent current-plan/current-state/current-state-input bundle.
    """

    binding = state.get("binding")
    if binding is not None:
        if not isinstance(binding, dict) or binding.get("mode") != "SELF_RESOLVED_AT_VERIFICATION":
            raise Failure("canonical state input is not self-resolved")
    elif state_rel == DEFAULT_STATE_INPUT and manifest_rel == DEFAULT_MANIFEST:
        raise Failure("canonical state input is missing its self-resolved binding")

    # Both legacy and active state inputs may name the manifest explicitly.
    require_pointer(state, "normative_manifest", manifest_rel, "state input", required=False)
    require_pointer(manifest, "normative_manifest", manifest_rel, "manifest", required=False)

    explicit_revision = state_rel != DEFAULT_STATE_INPUT or manifest_rel != DEFAULT_MANIFEST
    pointer_keys = ("current_plan", "current_state", "current_state_input")
    for mapping, label in ((state, "state input"), (manifest, "manifest")):
        for key in pointer_keys:
            value = mapping.get(key)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise Failure(f"{label} {key} must be a non-empty repository-relative path")
    if explicit_revision:
        require_pointer(state, "normative_manifest", manifest_rel, "state input", required=True)
        for key in pointer_keys:
            state_value = state.get(key)
            manifest_value = manifest.get(key)
            if not isinstance(state_value, str) or not isinstance(manifest_value, str):
                raise Failure(f"active state/manifest must both provide {key}")
            if state_value != manifest_value:
                raise Failure(f"state and manifest {key} pointers disagree")
        require_pointer(state, "current_state_input", state_rel, "state input", required=True)
        require_pointer(manifest, "current_state_input", state_rel, "manifest", required=True)
    else:
        # Keep the historical invocation fail-closed while allowing its state
        # object to omit the newer current_state pointer.
        require_pointer(manifest, "current_state_input", state_rel, "manifest", required=True)

    documents_value = manifest.get("documents")
    if not isinstance(documents_value, list) or not documents_value:
        raise Failure("manifest documents must be a non-empty list")
    documents: list[dict[str, str]] = []
    paths: set[str] = set()
    identifiers: set[str] = set()
    for index, entry in enumerate(documents_value):
        if not isinstance(entry, dict):
            raise Failure(f"manifest document {index} must be a mapping")
        identifier = entry.get("id")
        kind = entry.get("kind")
        requested_path = entry.get("path")
        if not isinstance(identifier, str) or not identifier.strip():
            raise Failure(f"manifest document {index} has no usable id")
        if not isinstance(kind, str) or not kind.strip():
            raise Failure(f"manifest document {index} has no usable kind")
        if entry.get("authority_effect") != "NONE":
            raise Failure(f"manifest document {index} grants authority")
        document_path, document_rel = repository_file(
            root, requested_path, "", f"manifest document {index}"
        )
        del document_path  # the path is re-used below when hashing
        if document_rel in paths:
            raise Failure(f"manifest contains duplicate document path: {document_rel}")
        if identifier in identifiers:
            raise Failure(f"manifest contains duplicate document id: {identifier}")
        paths.add(document_rel)
        identifiers.add(identifier)
        documents.append({"id": identifier, "path": document_rel, "kind": kind})

    # Every pointer named by either object must resolve to a real file, and
    # current pointers must be represented in the selected manifest.
    for mapping, label in ((state, "state input"), (manifest, "manifest")):
        for key in ("current_plan", "current_state", "current_state_input"):
            value = mapping.get(key)
            if value is None:
                continue
            pointer_path, pointer_rel = repository_file(root, value, "", f"{label} {key}")
            del pointer_path
            if pointer_rel not in paths:
                raise Failure(f"manifest does not index {label} {key}: {pointer_rel}")
    if state_rel not in paths:
        raise Failure(f"manifest does not index selected state input: {state_rel}")

    claims = state.get("claims")
    if "claims" in state and not isinstance(claims, dict):
        raise Failure("state input claims must be a mapping")
    if isinstance(claims, dict):
        if claims.get("qualification") is not False or claims.get("compatibility_claim") is not False:
            raise Failure("state input claims qualification or compatibility")
        if claims.get("selected_candidates") != []:
            raise Failure("state input selects a candidate")
        if claims.get("selection_effect") != "NONE" or claims.get("authority_effect") != "NONE":
            raise Failure("state input claims selection or authority")
    else:
        if state.get("qualification") is not False or state.get("compatibility_claim") is not False:
            raise Failure("state input claims qualification or compatibility")
        if "selected_candidates" in state and state.get("selected_candidates") != []:
            raise Failure("state input selects a candidate")
        if "selection_effect" in state and state.get("selection_effect") != "NONE":
            raise Failure("state input claims selection")
        if state.get("authority_effect") != "NONE":
            raise Failure("state input claims authority")
    if "qualification" in manifest and manifest.get("qualification") is not False:
        raise Failure("manifest claims qualification")
    if "compatibility_claim" in manifest and manifest.get("compatibility_claim") is not False:
        raise Failure("manifest claims compatibility")
    if "authority_effect" in manifest and manifest.get("authority_effect") != "NONE":
        raise Failure("manifest claims authority")
    return documents


def resolve(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).resolve()
    source_path, state_rel = repository_file(
        root, getattr(args, "state_input", None), DEFAULT_STATE_INPUT, "state input"
    )
    expected_repository = (
        CURRENT_REPOSITORY if state_rel == ACTIVE_STATE_INPUT else HISTORICAL_REPOSITORY
    )
    repository = getattr(args, "repository", expected_repository)
    if repository != expected_repository:
        raise Failure("repository identity drift")
    manifest_path, manifest_rel = repository_file(
        root, getattr(args, "manifest", None), DEFAULT_MANIFEST, "manifest"
    )
    state = read_mapping(source_path, "state input")
    manifest = read_mapping(manifest_path, "manifest")
    documents = validate_inputs(root, state, state_rel, manifest, manifest_rel)

    actual_commit = git(root, "rev-parse", "HEAD")
    actual_tree = git(root, "rev-parse", "HEAD^{tree}")
    commit = args.commit or actual_commit
    tree = args.tree or actual_tree
    if args.commit is not None and commit != actual_commit:
        raise Failure("declared commit does not match checked-out HEAD")
    if args.tree is not None and tree != actual_tree:
        raise Failure("declared tree does not match checked-out HEAD tree")
    ref = args.ref or git(root, "symbolic-ref", "--short", "-q", "HEAD") or "DETACHED"
    # A ref is descriptive provenance, not a checkout instruction here, but it
    # still must be an unambiguous Git ref token.  Reject control characters,
    # traversal and revision-expression syntax so a caller cannot smuggle a
    # second object selector into the derived record.
    if (
        not isinstance(ref, str)
        or not ref.strip()
        or REF_SAFE.fullmatch(ref) is None
        or ".." in ref
        or ref.startswith("-")
        or ref.endswith((".", ".lock", "/"))
        or any(token in ref for token in ("~", "^", ":", "\\"))
    ):
        raise Failure("ref is not a safe literal Git ref")
    if not SHA40.fullmatch(commit) or not SHA40.fullmatch(tree):
        raise Failure("commit and tree must be full lowercase SHA-1 object IDs")
    status = git(root, "status", "--porcelain=v1", "--untracked-files=all")
    clean_tree = status == ""
    if args.require_clean and not clean_tree:
        raise Failure("source tree is not clean")

    resolved_documents = []
    for entry in documents:
        path = root / entry["path"]
        resolved_documents.append({**entry, "sha256": file_sha256(path)})

    lock_path = root / "probes/h02/openraft-tokio/Cargo.lock"
    resolved: dict[str, Any] = {
        **state,
        "binding": {
            "mode": "EXACT_SOURCE_RESOLVED",
            "repository": repository,
            "ref": ref,
            "commit": commit,
            "tree": tree,
            "clean_tree": clean_tree,
        },
        "resolved_documents": resolved_documents,
        "resolution_inputs": {
            "state_input": state_rel,
            "manifest": manifest_rel,
        },
        "resolved_artifacts": {
            "openraft_lock_path": str(lock_path.relative_to(root)),
            "openraft_lock_sha256": file_sha256(lock_path),
            "plan_validator_sha256": file_sha256(root / "scripts/validate_plan_v1_2.py"),
            "state_input_path": state_rel,
            "state_input_sha256": file_sha256(source_path),
            "manifest_path": manifest_rel,
            "manifest_sha256": file_sha256(manifest_path),
        },
        "execution_identity": {
            "environment_id": args.environment_id,
            "runner_id": args.runner_id,
            "runner_name": args.runner_name,
            "job_id": args.job_id,
            "run_id": args.run_id,
        },
        "qualification": False,
        "compatibility_claim": False,
        "selected_candidates": [],
        "selection_effect": "NONE",
        "authority_effect": "NONE",
    }
    return resolved


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--root", default=".")
    value.add_argument("--repository", default=HISTORICAL_REPOSITORY)
    value.add_argument("--state-input", default=DEFAULT_STATE_INPUT)
    value.add_argument("--manifest", default=DEFAULT_MANIFEST)
    value.add_argument("--ref")
    value.add_argument("--commit")
    value.add_argument("--tree")
    value.add_argument("--environment-id", default="unavailable")
    value.add_argument("--runner-id")
    value.add_argument("--runner-name")
    value.add_argument("--job-id")
    value.add_argument("--run-id")
    value.add_argument("--require-clean", action="store_true")
    value.add_argument("--output", required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        result = resolve(args)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except (Failure, OSError, ValueError, KeyError, yaml.YAMLError) as error:
        print(f"canonical project-state resolution FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "canonical project state resolved: "
        f"commit={result['binding']['commit']} tree={result['binding']['tree']} "
        "qualification=false authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
