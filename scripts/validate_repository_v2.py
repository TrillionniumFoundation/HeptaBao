#!/usr/bin/env python3
"""Validate the current V2 repository truth without rewriting source files."""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
STATE_PATH = ROOT / "planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml"
MATRIX_PATH = ROOT / "planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml"
BLOCKERS_PATH = ROOT / "planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml"
V3_HEADINGS = (
    "Purpose and non-goals",
    "Public API and ownership",
    "State and data model",
    "Invariants and authorization",
    "Failure, retry and reconciliation",
    "Concurrency and ordering",
    "Security and privacy",
    "Persistence and compatibility",
    "Observability",
    "Operations",
    "Tests and executable evidence",
    "Evolution and open boundaries",
)


def read_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain a mapping")
    return value


def workspace_members() -> list[str]:
    value = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    members = value.get("workspace", {}).get("members", [])
    if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
        raise ValueError("Cargo.toml workspace.members must be a string list")
    return members


def package_name(manifest: Path) -> str:
    value = tomllib.loads(manifest.read_text(encoding="utf-8"))
    name = value.get("package", {}).get("name")
    if not isinstance(name, str) or not name:
        raise ValueError(f"{manifest.relative_to(ROOT)} has no package.name")
    return name


def lockfile_names() -> set[str]:
    value = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    packages = value.get("package", [])
    if not isinstance(packages, list):
        raise ValueError("Cargo.lock package table is invalid")
    return {
        item["name"]
        for item in packages
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }


def discovered_tests(source_root: Path) -> int:
    total = 0
    for path in source_root.rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        total += len(re.findall(r"(?m)^\s*#\[(?:test|tokio::test)\]\s*$", text))
    return total


def validate_v3_guide(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    for title in V3_HEADINGS:
        heading = f"## {title}\n"
        if text.count(heading) != 1:
            errors.append(f"{path.relative_to(ROOT)} must contain exactly one {heading.strip()!r}")
            continue
        section = text.split(heading, 1)[1].split("\n## ", 1)[0].strip()
        if len(section) < 40:
            errors.append(f"{path.relative_to(ROOT)} section {title!r} is not substantive")
    handbook = "docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md"
    if handbook not in text:
        errors.append(f"{path.relative_to(ROOT)} must reference {handbook}")
    return errors


def validate() -> list[str]:
    errors: list[str] = []
    required = (STATE_PATH, MATRIX_PATH, BLOCKERS_PATH)
    for path in required:
        if not path.is_file():
            errors.append(f"missing current file: {path.relative_to(ROOT)}")
    if errors:
        return errors

    state = read_yaml(STATE_PATH)
    matrix = read_yaml(MATRIX_PATH)
    blockers = read_yaml(BLOCKERS_PATH)
    if state.get("plan_id") != matrix.get("plan_id") or state.get("plan_id") != blockers.get("plan_id"):
        errors.append("current state, capability matrix and blocker register must share one plan_id")

    members = workspace_members()
    if len(members) != len(set(members)):
        errors.append("Cargo workspace contains duplicate members")
    names: list[str] = []
    lock_names = lockfile_names()
    for member in members:
        root = ROOT / member
        manifest = root / "Cargo.toml"
        if not manifest.is_file():
            errors.append(f"missing manifest: {manifest.relative_to(ROOT)}")
            continue
        name = package_name(manifest)
        names.append(name)
        if root.name != name:
            errors.append(f"workspace directory {root.name!r} does not match package {name!r}")
        source = root / "src/lib.rs"
        if not source.is_file():
            source = root / "src/main.rs"
        if not source.is_file():
            errors.append(f"{name} has no src/lib.rs or src/main.rs")
        guide = ROOT / "docs/modules" / f"{name}.md"
        if not guide.is_file():
            errors.append(f"{name} has no module guide")
        if name not in lock_names:
            errors.append(f"{name} is absent from Cargo.lock")

    if len(names) != len(set(names)):
        errors.append("workspace contains duplicate package names")

    modules = matrix.get("modules", [])
    if not isinstance(modules, list):
        errors.append("capability matrix modules must be a list")
        modules = []
    by_name = {
        item.get("crate"): item
        for item in modules
        if isinstance(item, dict) and isinstance(item.get("crate"), str)
    }
    if set(names) != set(by_name):
        missing = sorted(set(names) - set(by_name))
        stale = sorted(set(by_name) - set(names))
        if missing:
            errors.append("capability matrix missing workspace packages: " + ", ".join(missing))
        if stale:
            errors.append("capability matrix contains non-workspace packages: " + ", ".join(stale))
    for name, item in by_name.items():
        source = ROOT / str(item.get("source", ""))
        guide = ROOT / str(item.get("guide", ""))
        if not source.is_file():
            errors.append(f"matrix source missing for {name}: {source.relative_to(ROOT)}")
        if not guide.is_file():
            errors.append(f"matrix guide missing for {name}: {guide.relative_to(ROOT)}")
        elif item.get("documentation_standard") == "V3":
            errors.extend(validate_v3_guide(guide))
        source_root = ROOT / "crates" / name
        if source_root.is_dir() and discovered_tests(source_root) == 0:
            errors.append(f"{name} has no discovered Rust tests")

    entries = blockers.get("repository_blockers", [])
    if not isinstance(entries, list):
        errors.append("repository_blockers must be a list")
        entries = []
    ids = [item.get("id") for item in entries if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        errors.append("repository blocker IDs must be unique")
    for item in entries:
        if not isinstance(item, dict):
            errors.append("repository blocker entry must be a mapping")
            continue
        if item.get("state") == "CLOSED_REPOSITORY_SCOPE":
            evidence = item.get("evidence", [])
            if not isinstance(evidence, list) or not evidence:
                errors.append(f"closed blocker {item.get('id')} has no evidence")
                continue
            for value in evidence:
                path = ROOT / str(value)
                if not path.exists():
                    errors.append(f"closed blocker {item.get('id')} evidence is missing: {value}")

    external = blockers.get("external_blockers", [])
    if not isinstance(external, list):
        errors.append("external_blockers must be a list")
        external = []
    for item in external:
        if isinstance(item, dict) and item.get("state") == "CLOSED_REPOSITORY_SCOPE":
            errors.append(f"external blocker {item.get('id')} cannot be repository-closed")

    current = state.get("current_documents", {})
    if not isinstance(current, dict):
        errors.append("canonical state current_documents must be a mapping")
    else:
        for label, value in current.items():
            path = ROOT / str(value)
            if not path.is_file():
                errors.append(f"current document {label} is missing: {value}")
    return errors


def main() -> int:
    try:
        errors = validate()
        members = workspace_members()
    except (OSError, ValueError, tomllib.TOMLDecodeError, yaml.YAMLError) as error:
        print(f"repository-v2: ERROR: {error}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"repository-v2: ERROR: {error}", file=sys.stderr)
        return 1
    print(f"repository-v2: PASS ({len(members)} workspace packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
