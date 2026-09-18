#!/usr/bin/env python3
"""Small semantic drift guards; not an automatic documentation completeness proof."""
from __future__ import annotations

import importlib.util
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HISTORY = re.compile(r"<!-- BEGIN GENERATED V1\.4\.7 [^\n]*-->.*?<!-- END GENERATED V1\.4\.7 [^\n]*-->", re.S)
API = re.compile(r"<!-- CURRENT API: ([^\s#]+)#([A-Za-z_]\w*) -->\s*```text\n(.*?)\n```", re.S)
ROW = re.compile(r"^\| `(heptabao-[^`]+)` \| (yes|no) \| ([^|]+) \| `([^`]+)::([A-Za-z_]\w*)` \|$", re.M)


def human_text(text: str) -> str:
    return HISTORY.sub("", text)


def normalize_declaration(text: str) -> str:
    return re.sub(r"\s+", "", text)


def function_declaration(source: str, name: str) -> str | None:
    match = re.search(r"(?m)^\s*pub(?:\([^)]*\))?\s+(?:(?:const|async|unsafe)\s+)*fn\s+" + re.escape(name) + r"\s*\(", source)
    if match is None:
        return None
    end = source.find("{", match.start())
    return source[match.start():end].strip() if end >= 0 else None


def validate_api_contracts(root: Path, text: str, label: str) -> list[str]:
    errors = []
    for relative, name, declared in API.findall(human_text(text)):
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or not (root / path).is_file():
            errors.append(f"{label}: invalid current API source {relative}")
            continue
        actual = function_declaration((root / path).read_text(), name)
        if actual is None or normalize_declaration(actual) != normalize_declaration(declared):
            errors.append(f"{label}: current API signature drift at {relative}#{name}")
    return errors


def runtime_closure(root: Path, packages: dict[str, dict]) -> set[str]:
    closure = {"heptabao-server"}
    pending = list(closure)
    while pending:
        name = pending.pop()
        manifest = tomllib.loads((root / packages[name]["root"] / "Cargo.toml").read_text())
        # Normal and target-specific runtime path dependencies, excluding tests/build tools.
        tables = [manifest.get("dependencies", {})]
        tables += [value.get("dependencies", {}) for value in manifest.get("target", {}).values()]
        for table in tables:
            for alias, value in table.items():
                if not isinstance(value, dict) or "path" not in value:
                    continue
                dependency = value.get("package", alias)
                if dependency not in packages:
                    raise ValueError(f"unmapped runtime path dependency: {dependency}")
                if dependency not in closure:
                    closure.add(dependency)
                    pending.append(dependency)
    return closure


def current_packages(root: Path, inventory_module, details: dict[str, dict]) -> dict[str, dict]:
    """Reconstruct package navigation from manifests, independent of compact snapshot shape."""
    packages: dict[str, dict] = {}
    for member in inventory_module.members(root):
        manifest = tomllib.loads((root / member / "Cargo.toml").read_text())
        name = manifest["package"]["name"]
        if name in packages:
            raise ValueError(f"duplicate current package: {name}")
        packages[name] = {
            "package": name,
            "root": member,
            "guide": f"docs/modules/{name}.md",
        }
    if set(packages) != set(details):
        raise ValueError("compact inventory details differ from current workspace package set")
    return packages


def validate(root: Path = ROOT) -> list[str]:
    coverage_spec = importlib.util.spec_from_file_location("documentation_coverage", Path(__file__).with_name("current_compatibility_coverage.py"))
    if coverage_spec is None or coverage_spec.loader is None:
        return ["cannot load compatibility documentation coverage guard"]
    coverage_module = importlib.util.module_from_spec(coverage_spec)
    coverage_spec.loader.exec_module(coverage_module)
    errors: list[str] = coverage_module.validate(root)
    truth_spec = importlib.util.spec_from_file_location("runtime_doc_truth", Path(__file__).with_name("validate_runtime_doc_truth.py"))
    if truth_spec is None or truth_spec.loader is None:
        return errors + ["cannot load current runtime documentation guard"]
    truth_module = importlib.util.module_from_spec(truth_spec)
    truth_spec.loader.exec_module(truth_module)
    errors.extend(truth_module.validate(root))
    spec = importlib.util.spec_from_file_location("semantic_inventory", root / "scripts/current_source_inventory.py")
    if spec is None or spec.loader is None:
        return ["cannot load current inventory for documentation semantics"]
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        _snapshot, details = module.inventory(root)
        packages = current_packages(root, module, details)
        closure = runtime_closure(root, packages)
        for name, row in packages.items():
            text = (root / row["guide"]).read_text()
            human = human_text(text)
            if "GENERATED V1.4.7" in text and "docs/modules/CURRENT_SOURCE_BINDING.md" not in human:
                errors.append(f"{name}: historical blocks need an explicit current-source notice")
            heading = "## Public API and ownership\n"
            if heading in human:
                section = human.split(heading, 1)[1].split("\n## ", 1)[0]
                # Remove the shared provenance notice: it cannot substitute for API semantics.
                substantive = re.sub(r"Current source binding:.*?current API authority\.", "", section, flags=re.S)
                names = {value[3] for value in details[name]["public_lexical_declarations"]}
                if len(substantive.strip()) < 160 or not any(re.search(r"\b" + re.escape(symbol) + r"\b", substantive) for symbol in names):
                    errors.append(f"{name}: current API ownership semantics are missing outside historical tables")
            tests = details[name]["discovered_test_functions"]
            if not any(re.search(r"(?<![A-Za-z0-9_])" + re.escape(test[2]) + r"(?![A-Za-z0-9_])", human) for test in tests):
                errors.append(f"{name}: guide needs a current named source test outside historical tables")
            errors.extend(validate_api_contracts(root, text, row["guide"]))

        mapping = (root / "docs/modules/CURRENT_RUNTIME_MAP.md").read_text()
        rows = ROW.findall(mapping)
        mapped = [row[0] for row in rows]
        if set(mapped) != set(packages) or len(mapped) != len(set(mapped)):
            errors.append("runtime map must contain exactly one row per current workspace package")
        for name, runtime, responsibility, source, test in rows:
            if name not in packages:
                continue
            if (runtime == "yes") != (name in closure):
                errors.append(f"runtime map dependency drift for {name}")
            anchors = {(value[0], value[2]) for value in details[name]["discovered_test_functions"]}
            if (source, test) not in anchors:
                errors.append(f"runtime map test anchor drift for {name}: {source}::{test}")
            if len(responsibility.strip()) < 20:
                errors.append(f"runtime map lacks role/route boundary for {name}")
        if f"**{len(packages)} workspace packages**" not in mapping or f"**{len(closure)}**" not in mapping:
            errors.append("runtime map package/runtime count narrative drift")

        auth_path = "docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md"
        auth = (root / auth_path).read_text()
        required = ("crates/heptabao-server/src/auth.rs", "authorize_request")
        if required not in {(path, name) for path, name, _ in API.findall(auth)}:
            errors.append("auth guide must bind the current authorize_request signature, including live now")
        errors.extend(validate_api_contracts(root, auth, auth_path))
        for historical in ("HEPTABAO_SYSTEM_CONTEXT_AND_CRATE_GRAPH_V1.md", "HEPTABAO_AUTHORITATIVE_DATA_OWNERSHIP_AND_TRANSACTION_MAP_V1.md"):
            text = (root / "docs/architecture" / historical).read_text()
            if "Historical target architecture" not in text or "HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md" not in text:
                errors.append(f"{historical}: target architecture needs current runtime navigation")

        capacity_path = root / "docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md"
        capacity = capacity_path.read_text()
        stale_ha_claims = (
            "HA mode deliberately rejects replay retirement",
            "When HA is enabled the route returns 409",
        )
        for claim in stale_ha_claims:
            if claim in capacity:
                errors.append(f"capacity guide retains stale HA replay claim: {claim}")
        for marker in (
            "Raft-coordinated transition",
            "missing multiple epochs",
            "forced snapshot installation across epochs",
        ):
            if marker not in capacity:
                errors.append(f"capacity guide lacks current HA replay lifecycle marker: {marker}")
    except (OSError, ValueError, KeyError, TypeError) as error:
        errors.append(f"current documentation semantics: {error}")
    return errors


def main() -> int:
    errors = validate()
    for error in errors:
        print(f"documentation-semantics: {error}", file=sys.stderr)
    if not errors:
        print("documentation-semantics: PASS (API/history/runtime/test drift guards only)")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
