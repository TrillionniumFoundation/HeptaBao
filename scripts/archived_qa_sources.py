#!/usr/bin/env python3
"""Verify or recover retired QA source snapshots from their immutable Git commit.

No archived program is executed. Recovery writes only into a new directory
outside this checkout. For a complete historical replay, use a detached
worktree at the manifest's source_commit instead of mixing old and new code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/audits/2026-11-15-repository-cleanup/retired-sources.json"
SCHEMA = "heptabao.retired-qa-sources.v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def inventory(manifest_path: Path = MANIFEST) -> tuple[dict, list[dict]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(isinstance(manifest, dict), "invalid retirement manifest")
    require(manifest.get("schema") == SCHEMA, "unsupported retirement manifest")
    commit = manifest.get("source_commit", "")
    require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
            "invalid source commit")
    try:
        require(git("rev-parse", f"{commit}^{{tree}}").decode("ascii").strip()
                == manifest.get("source_tree"), "source tree mismatch")
        tree = git("ls-tree", "-rz", "--full-tree", commit)
    except subprocess.CalledProcessError as error:
        raise ValueError(
            f"archive commit unavailable; fetch it with: git fetch origin {commit}"
        ) from error
    originals = {}
    for record in tree.split(b"\0"):
        if record:
            metadata, path = record.split(b"\t", 1)
            mode, kind, blob = metadata.decode("ascii").split()
            originals[path.decode("utf-8")] = (mode, kind, blob)

    entries = manifest.get("entries")
    require(isinstance(entries, list) and bool(entries), "empty retirement manifest")
    seen = set()
    for entry in entries:
        require(isinstance(entry, dict), "invalid archive entry")
        name = entry.get("path", "")
        require(isinstance(name, str) and bool(name), "invalid archive path")
        path = PurePosixPath(name)
        require(
            not path.is_absolute()
            and path.as_posix() == name and ".." not in path.parts
            and "\\" not in name and ".git" not in path.parts,
            "unsafe archive path",
        )
        require(name not in seen, "duplicate archive path")
        seen.add(name)
        require(entry.get("mode") in {"100644", "100755"}, "unsupported archive mode")
        require(isinstance(entry.get("git_blob"), str)
                and re.fullmatch(r"[0-9a-f]{40}", entry["git_blob"]) is not None,
                "invalid Git blob")
        require(isinstance(entry.get("sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None,
                "invalid SHA256")
        require(type(entry.get("bytes")) is int and entry["bytes"] >= 0,
                "invalid archive size")
        require(originals.get(name) == (entry["mode"], "blob", entry["git_blob"]),
                f"source commit does not bind archived path: {name}")
    require(manifest.get("file_count") == len(entries), "archive count mismatch")
    require(manifest.get("total_bytes") == sum(entry["bytes"] for entry in entries),
            "archive byte count mismatch")
    return manifest, entries


def verify_entries(entries: list[dict], destination: Path | None) -> int:
    total = 0
    with subprocess.Popen(
        ["git", "-C", str(ROOT), "cat-file", "--batch"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    ) as process:
        assert process.stdin is not None and process.stdout is not None
        try:
            for entry in entries:
                process.stdin.write((entry["git_blob"] + "\n").encode("ascii"))
                process.stdin.flush()
                header = process.stdout.readline().decode("ascii").strip().split()
                require(header == [entry["git_blob"], "blob", str(entry["bytes"])],
                        f"Git object header mismatch: {entry['path']}")
                content = process.stdout.read(entry["bytes"])
                require(len(content) == entry["bytes"] and process.stdout.read(1) == b"\n",
                        f"truncated Git object: {entry['path']}")
                require(hashlib.sha256(content).hexdigest() == entry["sha256"],
                        f"SHA256 mismatch: {entry['path']}")
                if destination is not None:
                    target = destination / entry["path"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as output:
                        output.write(content)
                    target.chmod(int(entry["mode"], 8) & 0o777)
                total += len(content)
        finally:
            process.stdin.close()
        require(process.wait() == 0, "Git object reader failed")
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--verify", action="store_true", help="verify source bindings and all bytes (default)")
    action.add_argument("--restore-to", type=Path, help="recover into a NEW directory outside the checkout")
    parser.add_argument("--prefix", default="", help="select archived paths with this repository-relative prefix")
    parser.add_argument("--manifest", type=Path, default=MANIFEST,
                        help="retirement manifest to use (default: initial source cleanup)")
    args = parser.parse_args()
    try:
        manifest, entries = inventory(args.manifest)
        selected = [entry for entry in entries if entry["path"].startswith(args.prefix)]
        require(bool(selected), "prefix selects no archived source files")
        # Verify the entire selection before creating any output directory.
        total = verify_entries(selected, None)
        destination = None
        if args.restore_to is not None:
            destination = args.restore_to.absolute()
            require(not destination.exists() and not destination.is_symlink(),
                    "restore destination must not already exist")
            resolved = destination.resolve()
            require(resolved != ROOT and ROOT not in resolved.parents,
                    "restore destination must be outside the checkout")
            destination.mkdir(mode=0o700)
            verify_entries(selected, destination)
        print(json.dumps({
            "source_commit": manifest["source_commit"],
            "verified_files": len(selected), "verified_bytes": total,
            "restored_to": str(destination) if destination is not None else None,
            "archived_code_executed": False,
        }, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"archive verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
