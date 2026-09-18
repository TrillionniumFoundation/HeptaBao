#!/usr/bin/env python3
"""Fail-closed validation for per-module design/semantics/evidence dossiers.

The module registry is navigation metadata, not a second source-of-truth ledger.
Current acceptance binds the immutable Git commit and each crate's src tree.
The validator therefore derives workspace cardinality from Cargo.toml and does not
require hand-maintained package counts, manifest hashes, or source digests to
match a copied snapshot.

Named executable anchors are still resolved against the actual Rust source and
the dossier must name the file that really contains the test. Security-sensitive
authority claims remain fail-closed.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "Design and state ownership",
    "Module boundaries and trust assumptions",
    "Failure semantics and ordering",
    "Acceptance evidence",
    "Known gaps and evolution",
]
ANCHOR_LINE = re.compile(
    r"\*\*Named executable anchor:\*\* \x60(?P<anchor>[^\x60]+)\x60 in \x60(?P<path>[^\x60]+)\x60\."
)


def run_git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def exact_head() -> str:
    return run_git("rev-parse", "HEAD")


def git_tree_oid(path: Path) -> str:
    relative = path.relative_to(ROOT).as_posix()
    oid = run_git("rev-parse", f"HEAD:{relative}")
    if not re.fullmatch(r"[0-9a-f]{40,64}", oid):
        raise RuntimeError(f"invalid Git tree oid for {relative}: {oid}")
    return oid


def crates() -> dict[str, Path]:
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    out: dict[str, Path] = {}
    for member in manifest["workspace"]["members"]:
        candidates = sorted(ROOT.glob(member)) if "*" in member else [ROOT / member]
        for directory in candidates:
            if not directory.is_dir():
                continue
            package_manifest = directory / "Cargo.toml"
            if package_manifest.is_file():
                package = tomllib.loads(package_manifest.read_text())["package"]["name"]
                if package in out:
                    raise ValueError(f"duplicate workspace package {package}")
                out[package] = directory
    return out


def anchor_files(anchor: str, sources: list[Path]) -> list[Path]:
    definition = re.compile(rf"\bfn\s+{re.escape(anchor)}\s*\(")
    return [path for path in sources if definition.search(path.read_text())]


def main() -> int:
    errors: list[str] = []
    try:
        head = exact_head()
        workspace = crates()
    except (RuntimeError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"module closure validation cannot bind the current workspace: {error}", file=sys.stderr)
        return 1

    registry_path = ROOT / "planning/HEPTABAO_MODULE_CLOSURE_REGISTRY_V1.yaml"
    registry = yaml.safe_load(registry_path.read_text())
    entries = {item["crate"]: item for item in registry.get("modules", [])}

    if set(workspace) != set(entries):
        errors.append(
            "registry/workspace mismatch "
            f"missing={sorted(set(workspace) - set(entries))} "
            f"extra={sorted(set(entries) - set(workspace))}"
        )

    bindings: list[tuple[str, str]] = []
    for name, directory in sorted(workspace.items()):
        entry = entries.get(name)
        dossier = ROOT / entry["dossier"] if entry else ROOT / "missing"
        guide = ROOT / entry["guide"] if entry else ROOT / "missing"
        source_root = directory / "src"
        sources = sorted(source_root.glob("**/*.rs"))

        if not dossier.is_file():
            errors.append(f"{name}: missing dossier")
            continue
        text = dossier.read_text()
        if not text.startswith(f"# {name} module closure dossier"):
            errors.append(f"{name}: title mismatch")
        for heading in REQUIRED:
            if f"## {heading}" not in text:
                errors.append(f"{name}: missing section {heading}")
        if not guide.is_file():
            errors.append(f"{name}: missing guide")
        elif f"../module-closure/{name}.md" not in guide.read_text():
            errors.append(f"{name}: guide does not link dossier")

        if not sources:
            errors.append(f"{name}: no Rust source files under {source_root.relative_to(ROOT)}")
            continue

        try:
            tree_oid = git_tree_oid(source_root)
        except RuntimeError as error:
            errors.append(f"{name}: cannot bind Git source tree: {error}")
            continue
        bindings.append((name, tree_oid))

        anchor = entry.get("test_anchor") if entry else None
        if anchor:
            matches = anchor_files(anchor, sources)
            if len(matches) != 1:
                rendered = [path.relative_to(ROOT).as_posix() for path in matches]
                errors.append(f"{name}: test anchor {anchor!r} resolves to {rendered}")
            dossier_match = ANCHOR_LINE.search(text)
            if dossier_match is None:
                errors.append(f"{name}: dossier lacks a parseable named executable anchor line")
            else:
                if dossier_match.group("anchor") != anchor:
                    errors.append(
                        f"{name}: dossier anchor {dossier_match.group('anchor')!r} != registry {anchor!r}"
                    )
                if len(matches) == 1:
                    actual_path = matches[0].relative_to(ROOT).as_posix()
                    if dossier_match.group("path") != actual_path:
                        errors.append(
                            f"{name}: dossier anchor file {dossier_match.group('path')} != actual {actual_path}"
                        )
        elif "No in-crate test function was discovered" not in text:
            errors.append(f"{name}: missing explicit no-test evidence")

        if any(
            token in text
            for token in (
                "production_authority: true",
                "qualification: true",
                "authority_effect: GRANT",
                "TODO",
                "TBD",
                "PLACEHOLDER",
            )
        ):
            errors.append(f"{name}: forbidden claim/placeholder")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(f"module closure validation: PASS ({len(workspace)} workspace modules)")
    print(f"exact head: {head}")
    print("binding: exact-head Git src-tree oid; registry hashes/counts are non-authoritative metadata")
    for name, tree_oid in bindings:
        print(f"{name}\tgit-tree={tree_oid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
