#!/usr/bin/env python3
"""Reproducible current module inventory; frozen V1.4.7 evidence is not rewritten.

This is a lexical diagnostic inventory, NOT a Rust visibility proof, a test-pass
receipt, or an additional source authority. Exact Git commit/tree identity already
binds repository bytes in CI. The compact committed snapshot is retained only as a
review aid and may lag source changes without blocking development; --details or
--write always recompute the current digest from the checked-out tree.
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
SCHEMA = "heptabao.current-source-inventory.v3"
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
    # Vendored dependencies can own their upstream build/test policy without
    # becoming first-party modules. Never let an exclusion hide a declared
    # product member or an unchecked path outside the vendor directory.
    excluded = workspace.get("exclude", [])
    if not isinstance(excluded, list):
        raise ValueError("invalid workspace exclusions")
    for entry in excluded:
        if (not isinstance(entry, str) or not re.fullmatch(r"vendor/[A-Za-z0-9_.-]+", entry)
                or Path(entry).name in {".", ".."}):
            raise ValueError("workspace exclusions must name explicit vendored dependencies")
        read(root, f"{entry}/Cargo.toml")
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
    if set(result).intersection(excluded):
        raise ValueError("workspace exclusion hides a declared member")
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
    binding = {"workspace_sha256": digest(read(root, "Cargo.toml")),
               "lockfile_sha256": digest(read(root, "Cargo.lock")),
               "historical_v1_4_7_sha256": HISTORICAL_SHA256,
               "modules": rows}
    snapshot = {"schema": SCHEMA, "scope": "source-and-document-binding-only",
                "package_count": len(rows),
                "inventory_sha256": digest(canonical(binding)),
                "qualification": False, "compatibility_claim": False,
                "production_authority": False, "release_authority": False}
    return snapshot, all_details


def validate(root: Path = ROOT) -> list[str]:
    """Validate inventory inputs and the diagnostic snapshot envelope.

    Source/guide/manifest/lock content drift is intentionally *not* compared with
    the committed snapshot. The exact checkout's Git tree is the source binding;
    requiring a second hand-refreshed digest commit after every source edit adds
    no independent evidence and used to create false-negative CI churn.
    """
    try:
        current, _ = inventory(root)
        raw = read(root, SNAPSHOT)
        snapshot = json.loads(raw)
        if not isinstance(snapshot, dict):
            return ["current source inventory snapshot must contain an object"]
        required = {
            "schema": SCHEMA,
            "scope": "source-and-document-binding-only",
            "package_count": current["package_count"],
            "qualification": False,
            "compatibility_claim": False,
            "production_authority": False,
            "release_authority": False,
        }
        for key, expected in required.items():
            if snapshot.get(key) != expected:
                return [f"current source inventory snapshot has invalid {key}"]
        value = snapshot.get("inventory_sha256")
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) or value == "0" * 64:
            return ["current source inventory snapshot has invalid diagnostic digest"]
        return []
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
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
            snapshot, _ = inventory()
            print(
                "current-source-inventory: PASS "
                f"(Git tree authoritative; current diagnostic={snapshot['inventory_sha256']})"
            )
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
