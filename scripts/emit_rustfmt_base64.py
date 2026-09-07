#!/usr/bin/env python3
"""Emit rustfmt-mutated Rust files as base64 for one diagnostic CI run."""
from __future__ import annotations

import base64
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=AM"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    emitted = 0
    for relative in sorted(filter(None, result.stdout.splitlines())):
        path = ROOT / relative
        if path.suffix != ".rs" or not path.is_file():
            continue
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        print(f"RUSTFMT_FILE_BEGIN {relative}")
        print(encoded)
        print(f"RUSTFMT_FILE_END {relative}")
        emitted += 1
    print(f"RUSTFMT_FILE_COUNT {emitted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
