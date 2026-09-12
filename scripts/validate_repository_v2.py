#!/usr/bin/env python3
"""Validate the current V2 repository truth without rewriting source files."""
from __future__ import annotations

import glob
import importlib.util
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
README_PATH = ROOT / "README.md"
CURRENT_DOCUMENTATION_PATH = ROOT / "docs/CURRENT_DOCUMENTATION.md"
MODULE_INDEX_PATH = ROOT / "docs/modules/README.md"
SECURITY_PATH = ROOT / "SECURITY.md"
LICENSE_PLANNING_PATH = ROOT / "LICENSE-PLANNING.md"

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

G4_PACKAGES = {
    "heptabao-agent",
    "heptabao-cli-contracts",
    "heptabao-client-contracts",
    "heptabao-compatibility",
    "heptabao-ha-contracts",
    "heptabao-kms-contracts",
    "heptabao-migration",
    "heptabao-proxy",
}

FALSE_CLAIMS = {
    "qualification": False,
    "compatibility_claim": False,
    "production_authority": False,
    "migration_authority": False,
    "release_authority": False,
    "authority_effect": "NONE",
}

CURRENT_DOCUMENTS = (README_PATH, CURRENT_DOCUMENTATION_PATH, MODULE_INDEX_PATH)


def validate_compatibility_corpus() -> list[str]:
    path = ROOT / "scripts/validate_compatibility_corpus.py"
    spec = importlib.util.spec_from_file_location("heptabao_compatibility_corpus", path)
    if spec is None or spec.loader is None:
        return ["unable to load compatibility corpus validator"]
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return list(module.validate(ROOT))


def display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


def read_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{display_path(path)} must contain a mapping")
    return value


def workspace_member_patterns() -> list[str]:
    value = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    members = value.get("workspace", {}).get("members", [])
    if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
        raise ValueError("Cargo.toml workspace.members must be a string list")
    return members


def workspace_members() -> list[str]:
    expanded: list[str] = []
    for pattern in workspace_member_patterns():
        if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            raise ValueError(f"workspace member pattern is outside the repository: {pattern}")
        if glob.has_magic(pattern):
            matches = sorted(
                path
                for path in ROOT.glob(pattern)
                if path.is_dir() and (path / "Cargo.toml").is_file()
            )
            if not matches:
                raise ValueError(f"workspace member glob matched no crates: {pattern}")
            expanded.extend(path.relative_to(ROOT).as_posix() for path in matches)
        else:
            path = ROOT / pattern
            if not path.is_dir() or not (path / "Cargo.toml").is_file():
                raise ValueError(f"workspace member is not a crate directory: {pattern}")
            expanded.append(Path(pattern).as_posix())
    if len(expanded) != len(set(expanded)):
        raise ValueError("Cargo workspace patterns expand to duplicate members")
    return sorted(expanded)


def package_name(manifest: Path) -> str:
    value = tomllib.loads(manifest.read_text(encoding="utf-8"))
    name = value.get("package", {}).get("name")
    if not isinstance(name, str) or not name:
        raise ValueError(f"{display_path(manifest)} has no package.name")
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
    label = display_path(path)
    text = path.read_text(encoding="utf-8")
    for title in V3_HEADINGS:
        heading = f"## {title}\n"
        if text.count(heading) != 1:
            errors.append(f"{label} must contain exactly one {heading.strip()!r}")
            continue
        section = text.split(heading, 1)[1].split("\n## ", 1)[0].strip()
        if len(section) < 40:
            errors.append(f"{label} section {title!r} is not substantive")
    handbook = "docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md"
    if handbook not in text:
        errors.append(f"{label} must reference {handbook}")
    return errors


def validate_claims(label: str, claims: Any) -> list[str]:
    if not isinstance(claims, dict):
        return [f"{label} claims must be a mapping"]
    errors: list[str] = []
    for key, expected in FALSE_CLAIMS.items():
        if claims.get(key) != expected:
            errors.append(f"{label} must keep {key}={expected!r}")
    return errors


def validate_current_documentation(plan_id: str, package_names: set[str]) -> list[str]:
    errors: list[str] = []
    count = len(package_names)
    for path in CURRENT_DOCUMENTS:
        if not path.is_file():
            errors.append(f"missing current documentation entry: {display_path(path)}")
            continue
        text = path.read_text(encoding="utf-8")
        if plan_id not in text:
            errors.append(f"{display_path(path)} does not identify current plan {plan_id}")
        if "V1.4.7 / CURRENT" in text or "H00 / planning and governance implementation" in text:
            errors.append(f"{display_path(path)} contains a stale current-status claim")

    if README_PATH.is_file():
        readme = README_PATH.read_text(encoding="utf-8")
        if f"**{count} packages**" not in readme:
            errors.append(f"README.md must state the exact current package count ({count})")
        for command in (
            "python scripts/validate_repository_v2.py",
            "cargo +1.98.0 fmt --all -- --check",
            "cargo +1.98.0 test --locked --workspace --all-targets",
            "cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings",
            "cargo +1.98.0 doc --locked --workspace --no-deps",
        ):
            if command not in readme:
                errors.append(f"README.md is missing current validation command: {command}")

    if CURRENT_DOCUMENTATION_PATH.is_file():
        portal = CURRENT_DOCUMENTATION_PATH.read_text(encoding="utf-8")
        if f"all {count} workspace packages" not in portal:
            errors.append(
                "docs/CURRENT_DOCUMENTATION.md must state the exact current workspace count"
            )
        for current in (
            "planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml",
            "planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml",
            "planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml",
            "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V2_1.md",
            "docs/modules/README.md",
        ):
            if current not in portal:
                errors.append(f"current documentation portal is missing {current}")

    if MODULE_INDEX_PATH.is_file():
        index = MODULE_INDEX_PATH.read_text(encoding="utf-8")
        if f"{count} WORKSPACE PACKAGES" not in index:
            errors.append(f"module index package-count banner must match current scope ({count})")
        indexed = set(
            re.findall(r"(?m)^\| `(heptabao-[^`]+)` \|", index)
        )
        if indexed != package_names:
            missing = sorted(package_names - indexed)
            stale = sorted(indexed - package_names)
            if missing:
                errors.append("module index missing packages: " + ", ".join(missing))
            if stale:
                errors.append("module index contains stale packages: " + ", ".join(stale))
        for name in package_names:
            row = f"| `{name}` |"
            if index.count(row) != 1:
                errors.append(f"module index must contain exactly one row for {name}")
    return errors


def validate_g4_contracts(
    package_names: set[str], matrix_by_name: dict[str, dict[str, Any]], planned: list[str]
) -> list[str]:
    errors: list[str] = []
    missing = sorted(G4_PACKAGES - package_names)
    if missing:
        errors.append("G4 contract packages are missing: " + ", ".join(missing))
    planned_g4 = sorted(set(planned) & G4_PACKAGES)
    if planned_g4:
        errors.append("implemented G4 packages cannot remain planned: " + ", ".join(planned_g4))
    for name in sorted(G4_PACKAGES & package_names):
        item = matrix_by_name.get(name, {})
        if item.get("documentation_standard") != "V3":
            errors.append(f"{name} must use module documentation standard V3")
        if item.get("state") != "IMPLEMENTED_REVIEW_REQUIRED":
            errors.append(f"{name} must be IMPLEMENTED_REVIEW_REQUIRED")

    semantic_markers = {
        "heptabao-agent": ("mark_outcome_unknown_after_entry", "FailedClosed"),
        "heptabao-cli-contracts": ("SecretInArguments", "--secret-stdin"),
        "heptabao-proxy": ("connection_nominations", "authorization_value"),
        "heptabao-kms-contracts": ("OutcomeUnknownAfterEntry", "ReconcileOnly"),
    }
    for name, markers in semantic_markers.items():
        path = ROOT / "crates" / name / "src/lib.rs"
        if not path.is_file():
            continue
        source = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in source:
                errors.append(f"{name} is missing required semantic marker {marker!r}")
    return errors


def validate() -> list[str]:
    errors: list[str] = []
    required = (
        STATE_PATH,
        MATRIX_PATH,
        BLOCKERS_PATH,
        README_PATH,
        CURRENT_DOCUMENTATION_PATH,
        MODULE_INDEX_PATH,
        SECURITY_PATH,
        LICENSE_PLANNING_PATH,
    )
    for path in required:
        if not path.is_file():
            errors.append(f"missing current file: {display_path(path)}")
    if errors:
        return errors

    state = read_yaml(STATE_PATH)
    matrix = read_yaml(MATRIX_PATH)
    blockers = read_yaml(BLOCKERS_PATH)
    plan_id = state.get("plan_id")
    if not isinstance(plan_id, str) or not plan_id:
        errors.append("canonical state must declare a nonempty plan_id")
        plan_id = ""
    if plan_id != matrix.get("plan_id") or plan_id != blockers.get("plan_id"):
        errors.append("current state, capability matrix and blocker register must share one plan_id")

    errors.extend(validate_claims("canonical state", state.get("claims")))
    errors.extend(validate_claims("blocker register", blockers.get("claims")))
    errors.extend(validate_claims("capability matrix", matrix.get("claims")))

    members = workspace_members()
    names: list[str] = []
    lock_names = lockfile_names()
    for member in members:
        root = ROOT / member
        manifest = root / "Cargo.toml"
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
    package_names = set(names)
    guide_names = {path.stem for path in (ROOT / "docs/modules").glob("heptabao-*.md")}
    if guide_names != package_names:
        missing = sorted(package_names - guide_names)
        stale = sorted(guide_names - package_names)
        if missing:
            errors.append("module guide set missing packages: " + ", ".join(missing))
        if stale:
            errors.append("module guide set contains non-workspace packages: " + ", ".join(stale))

    modules = matrix.get("modules", [])
    if not isinstance(modules, list):
        errors.append("capability matrix modules must be a list")
        modules = []
    by_name = {
        item.get("crate"): item
        for item in modules
        if isinstance(item, dict) and isinstance(item.get("crate"), str)
    }
    if len(by_name) != len(modules):
        errors.append("capability matrix has duplicate or invalid module entries")
    if package_names != set(by_name):
        missing = sorted(package_names - set(by_name))
        stale = sorted(set(by_name) - package_names)
        if missing:
            errors.append("capability matrix missing workspace packages: " + ", ".join(missing))
        if stale:
            errors.append("capability matrix contains non-workspace packages: " + ", ".join(stale))
    for name, item in by_name.items():
        source = ROOT / str(item.get("source", ""))
        guide = ROOT / str(item.get("guide", ""))
        expected_source = ROOT / "crates" / name / "src/lib.rs"
        expected_guide = ROOT / "docs/modules" / f"{name}.md"
        if source != expected_source:
            errors.append(f"matrix source for {name} is not canonical: {display_path(source)}")
        if guide != expected_guide:
            errors.append(f"matrix guide for {name} is not canonical: {display_path(guide)}")
        if not source.is_file():
            errors.append(f"matrix source missing for {name}: {display_path(source)}")
        if not guide.is_file():
            errors.append(f"matrix guide missing for {name}: {display_path(guide)}")
        elif item.get("documentation_standard") == "V3":
            errors.extend(validate_v3_guide(guide))
        source_root = ROOT / "crates" / name
        if source_root.is_dir() and discovered_tests(source_root) == 0:
            errors.append(f"{name} has no discovered Rust tests")

    planned_value = matrix.get("planned_modules", [])
    if not isinstance(planned_value, list) or not all(
        isinstance(item, str) for item in planned_value
    ):
        errors.append("capability matrix planned_modules must be a string list")
        planned: list[str] = []
    else:
        planned = planned_value
        if set(planned) & package_names:
            errors.append("capability matrix cannot list implemented packages as planned")
    errors.extend(validate_g4_contracts(package_names, by_name, planned))
    errors.extend(validate_current_documentation(plan_id, package_names))

    errors.extend(validate_compatibility_corpus())

    entries = blockers.get("repository_blockers", [])
    if not isinstance(entries, list):
        errors.append("repository_blockers must be a list")
        entries = []
    ids = [item.get("id") for item in entries if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        errors.append("repository blocker IDs must be unique")
    by_blocker = {
        item.get("id"): item
        for item in entries
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    for item in entries:
        if not isinstance(item, dict):
            errors.append("repository blocker entry must be a mapping")
            continue
        state_value = item.get("state")
        if state_value not in {
            "IMPLEMENTATION_IN_PROGRESS",
            "IMPLEMENTED_REVIEW_REQUIRED",
            "CLOSED_REPOSITORY_SCOPE",
        }:
            errors.append(f"repository blocker {item.get('id')} has invalid state {state_value!r}")
        if state_value in {"IMPLEMENTED_REVIEW_REQUIRED", "CLOSED_REPOSITORY_SCOPE"}:
            evidence = item.get("evidence", [])
            if not isinstance(evidence, list) or not evidence:
                errors.append(f"implemented blocker {item.get('id')} has no evidence")
                continue
            for value in evidence:
                path = ROOT / str(value)
                if not path.exists():
                    errors.append(
                        f"implemented blocker {item.get('id')} evidence is missing: {value}"
                    )
    rep006 = by_blocker.get("HB-V2-REP-006", {})
    if rep006.get("state") != "IMPLEMENTED_REVIEW_REQUIRED":
        errors.append("HB-V2-REP-006 must be IMPLEMENTED_REVIEW_REQUIRED after G4 source closure")
    rep006_evidence = set(rep006.get("evidence", [])) if isinstance(rep006, dict) else set()
    for name in ("heptabao-agent", "heptabao-cli-contracts", "heptabao-proxy", "heptabao-kms-contracts"):
        source = f"crates/{name}/src/lib.rs"
        guide = f"docs/modules/{name}.md"
        if source not in rep006_evidence or guide not in rep006_evidence:
            errors.append(f"HB-V2-REP-006 evidence must bind source and guide for {name}")

    external = blockers.get("external_blockers", [])
    if not isinstance(external, list):
        errors.append("external_blockers must be a list")
        external = []
    for item in external:
        if not isinstance(item, dict):
            errors.append("external blocker entry must be a mapping")
        elif item.get("state") != "EXTERNAL_COMPLETION_REQUIRED":
            errors.append(
                f"external blocker {item.get('id')} must remain EXTERNAL_COMPLETION_REQUIRED"
            )

    current = state.get("current_documents", {})
    if not isinstance(current, dict):
        errors.append("canonical state current_documents must be a mapping")
    else:
        for label, value in current.items():
            path = ROOT / str(value)
            if not path.is_file():
                errors.append(f"current document {label} is missing: {value}")
    workstreams = state.get("workstreams", {})
    if not isinstance(workstreams, dict):
        errors.append("canonical state workstreams must be a mapping")
    else:
        required_workstreams = {
            "G0_repository_truth",
            "G1_durable_vertical_slice",
            "G2_authenticated_service_adapter",
            "G3_provider_and_destructive_qualification",
            "G4_ha_migration_compatibility_release",
            "G5_external_authority",
        }
        missing_workstreams = sorted(required_workstreams - set(workstreams))
        if missing_workstreams:
            errors.append("canonical state is missing V2.1 workstreams: " + ", ".join(missing_workstreams))

    security = SECURITY_PATH.read_text(encoding="utf-8")
    if "V2.1 durable vertical-slice candidate under review" not in security:
        errors.append("SECURITY.md does not describe the current V2.1 repository status")
    licensing = LICENSE_PLANNING_PATH.read_text(encoding="utf-8")
    if "HB-BLK-EXT-001" not in licensing or "NO FINAL OUTBOUND LICENSE SELECTED" not in licensing:
        errors.append("LICENSE-PLANNING.md must keep the unresolved external legal blocker explicit")
    inventory_path = ROOT / "scripts/current_source_inventory.py"
    inventory_spec = importlib.util.spec_from_file_location("heptabao_current_inventory", inventory_path)
    if inventory_spec is None or inventory_spec.loader is None:
        errors.append("current source inventory validator cannot be loaded")
    else:
        inventory_module = importlib.util.module_from_spec(inventory_spec)
        inventory_spec.loader.exec_module(inventory_module)
        errors.extend(inventory_module.validate(ROOT))
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
