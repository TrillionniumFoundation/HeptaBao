#!/usr/bin/env python3
"""Content-bound current module inventory; frozen V1.4.7 evidence is not rewritten.

This is a lexical inventory, NOT a Rust visibility proof or a test-pass receipt.
The compact committed snapshot binds the full reproducible details by SHA-256.
An external CI receipt binds that snapshot to the actual commit and Git tree,
which avoids embedding a self-referential commit ID inside the commit itself.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = "planning/HEPTABAO_CURRENT_SOURCE_INVENTORY_V2.json"
HISTORICAL = "planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml"
# Exact preserved bytes at the reviewed input to this remediation, not regenerated.
HISTORICAL_SHA256 = "4b88d830ad088b9b611f051164b1c202d3cfcee986d100ae67706c701f5c8cf7"
SCHEMA = "heptabao.current-source-inventory.v2"
PUBLIC = re.compile(r"^\s*pub(?:\([^)]*\))?\s+(?:(?:async|unsafe|const)\s+)*(fn|struct|enum|trait|type|mod|use|static|const)\s+([A-Za-z_][A-Za-z0-9_]*)")
TEST = re.compile(r"^\s*#\[(?:test|(?:tokio|async_std)::test)(?:\([^]]*\))?\]\s*$")
FN = re.compile(r"\b(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read(root: Path, relative: str) -> bytes:
    path = root / relative
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("inventory path escapes repository")
    for parent in (path, *path.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError(f"symlinked inventory input: {relative}")
    if not path.is_file():
        raise ValueError(f"missing inventory input: {relative}")
    return path.read_bytes()


def members(root: Path) -> list[str]:
    workspace = tomllib.loads(read(root, "Cargo.toml").decode())["workspace"]
    if workspace.get("exclude"):
        raise ValueError("workspace.exclude requires an explicit inventory policy update")
    result: list[str] = []
    for pattern in workspace["members"]:
        if not isinstance(pattern, str) or Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            raise ValueError("invalid workspace member pattern")
        matches = sorted(p for p in root.glob(pattern) if p.is_dir() and (p / "Cargo.toml").is_file())
        if not matches:
            raise ValueError(f"empty workspace member: {pattern}")
        result.extend(p.relative_to(root).as_posix() for p in matches)
    if len(result) != len(set(result)):
        raise ValueError("duplicate workspace member")
    return sorted(result)


def lexical(text: str, path: str) -> dict[str, Any]:
    declarations, tests = [], []
    pending: int | None = None
    for number, line in enumerate(text.splitlines(), 1):
        match = PUBLIC.match(line)
        if match:
            declarations.append([path, number, match.group(1), match.group(2), line.strip()])
        if TEST.match(line):
            pending = number
        elif pending is not None:
            function = FN.search(line)
            if function:
                tests.append([path, pending, function.group(1)])
                pending = None
            elif line.strip() and not line.lstrip().startswith(("#", "//")):
                pending = None
    return {"public_lexical_declarations": declarations, "discovered_test_functions": tests}


def dependency_paths(manifest: dict[str, Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    def visit(value: dict[str, Any], prefix: str = "") -> None:
        for key, table in sorted(value.items()):
            if not isinstance(table, dict):
                continue
            scope = f"{prefix}.{key}" if prefix else key
            if key in {"dependencies", "dev-dependencies", "build-dependencies"}:
                for name, detail in sorted(table.items()):
                    if isinstance(detail, dict) and "path" in detail:
                        result.append({"scope": scope, "name": name, "path": detail["path"]})
            elif key == "target" or prefix.startswith("target"):
                visit(table, scope)
    visit(manifest)
    return result


def inventory(root: Path = ROOT) -> tuple[dict[str, Any], dict[str, Any]]:
    root = root.resolve()
    if digest(read(root, HISTORICAL)) != HISTORICAL_SHA256:
        raise ValueError("frozen V1.4.7 source evidence changed; do not regenerate it as current")
    rows, all_details = [], {}
    for member in members(root):
        manifest_bytes = read(root, f"{member}/Cargo.toml")
        manifest = tomllib.loads(manifest_bytes.decode())
        name = manifest["package"]["name"]
        if name in all_details or not re.fullmatch(r"heptabao-[a-z0-9-]+", name):
            raise ValueError("duplicate or invalid package name")
        guide = f"docs/modules/{name}.md"
        files, public, tests = [], [], []
        for path in sorted((root / member).rglob("*.rs")):
            relative = path.relative_to(root).as_posix()
            data = read(root, relative)
            files.append({"path": relative, "bytes": len(data), "sha256": digest(data)})
            detail = lexical(data.decode(), relative)
            public.extend(detail["public_lexical_declarations"])
            tests.extend(detail["discovered_test_functions"])
        if not files:
            raise ValueError(f"no Rust source for {name}")
        detail = {"files": files, "public_lexical_declarations": public,
                  "discovered_test_functions": tests,
                  "path_dependencies": dependency_paths(manifest)}
        all_details[name] = detail
        rows.append({"package": name, "root": member, "guide": guide,
                     "manifest_sha256": digest(manifest_bytes),
                     "guide_sha256": digest(read(root, guide)),
                     "details_sha256": digest(canonical(detail)),
                     "rust_files": len(files), "public_lexical_declarations": len(public),
                     "discovered_test_functions": len(tests),
                     "path_dependencies": detail["path_dependencies"]})
    rows.sort(key=lambda row: row["package"])
    guides = {p.stem for p in (root / "docs/modules").glob("heptabao-*.md")}
    if guides != set(all_details):
        raise ValueError("module guide set differs from the expanded workspace")
    snapshot = {"schema": SCHEMA, "scope": "source-and-document-binding-only",
                "workspace_sha256": digest(read(root, "Cargo.toml")),
                "lockfile_sha256": digest(read(root, "Cargo.lock")),
                "historical_v1_4_7_sha256": HISTORICAL_SHA256,
                "package_count": len(rows), "modules": rows,
                "qualification": False, "compatibility_claim": False,
                "production_authority": False, "release_authority": False}
    return snapshot, all_details


def validate(root: Path = ROOT) -> list[str]:
    try:
        expected, _ = inventory(root)
        if read(root, SNAPSHOT) != canonical(expected):
            return ["current source inventory drift: regenerate and review the V2 snapshot, not V1.4.7"]
        return []
    except (OSError, ValueError, KeyError, TypeError) as error:
        return [f"current source inventory: {error}"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--details", action="store_true")
    args = parser.parse_args()
    if args.check:
        errors = validate()
        for error in errors:
            print(error, file=sys.stderr)
        if not errors:
            print("current-source-inventory: PASS (source binding only)")
        return int(bool(errors))
    try:
        snapshot, details = inventory()
        if args.write:
            (ROOT / SNAPSHOT).write_bytes(canonical(snapshot))
        else:
            sys.stdout.buffer.write(canonical({"snapshot": snapshot, "details": details}))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"current source inventory: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
