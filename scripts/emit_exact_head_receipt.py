#!/usr/bin/env python3
"""Emit a machine-readable, exact-head qualification receipt.

The receipt deliberately records observations, not authority.  It is intended to
be uploaded by CI only after the commands represented by the caller have run.
A receipt never converts a bounded module/unit result into OpenBao replacement,
production, migration, or release authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def git(*args: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise RuntimeError(process.stderr.strip() or "git command failed")
    return process.stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--result", choices=("pass", "fail"), required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--command", action="append", default=[])
    parser.add_argument("--artifact", action="append", default=[])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    head = git("rev-parse", "HEAD")
    root_tree = git("rev-parse", "HEAD^{tree}")
    dirty = git("status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        print("refusing to emit an exact-head receipt from a dirty checkout", file=sys.stderr)
        return 1

    artifacts = []
    for raw in args.artifact:
        path = (ROOT / raw).resolve()
        try:
            relative = path.relative_to(ROOT).as_posix()
        except ValueError:
            print(f"artifact escapes repository: {raw}", file=sys.stderr)
            return 1
        if not path.is_file():
            print(f"artifact does not exist: {relative}", file=sys.stderr)
            return 1
        artifacts.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
        )

    receipt = {
        "schema": "heptabao.exact-head-receipt.v1",
        "repository": "TrillionniumFoundation/HeptaBao",
        "commit": head,
        "root_tree": root_tree,
        "profile": args.profile,
        "result": args.result,
        "commands": args.command,
        "artifacts": artifacts,
        "runner": {
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "github_job": os.environ.get("GITHUB_JOB"),
            "runner_os": os.environ.get("RUNNER_OS"),
            "runner_arch": os.environ.get("RUNNER_ARCH"),
        },
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "authority": {
            "compatibility": False,
            "production": False,
            "migration": False,
            "release": False,
        },
    }
    rendered = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
