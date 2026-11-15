#!/usr/bin/env python3
"""Reject installed acceptance workflows that mutate repository source or refs."""
from __future__ import annotations

import re
from pathlib import Path

MUTATION_RE = re.compile(
    r"\bgit\s+(?:push|commit|add|tag)\b"
    r"|\bgh\s+(?:pr\s+create|release\s+create|api\b)"
    r"|api\.github\.com/repos/[^\s'\"]+/git/refs",
    re.I,
)


def validate_directory(directory: Path) -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() not in {".yml", ".yaml"} or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        match = MUTATION_RE.search(text)
        if match:
            failures.append({"path": path.name, "error": "acceptance workflow source/ref mutation is forbidden"})
    return failures


def main() -> int:
    root = Path(__file__).resolve().parents[1] / ".github/workflows"
    failures = validate_directory(root)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure['path']}: {failure['error']}")
        return 1
    print("acceptance-immutability: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
