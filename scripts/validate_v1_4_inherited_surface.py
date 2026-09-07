#!/usr/bin/env python3
"""Verify that V1.4 extends, rather than rewrites, the frozen V1.3.1 source."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE_COMMIT = "a5b9739e46f4bed54dbb3edd0e32400481b3b12f"
BASELINE_TREE = "1727b9498258883b2504c53ac501c415a07218e2"

EXPECTED_DELTA = {
    ".github/workflows/plan-v1.4-durable-single-node.yml": "A",
    "Cargo.lock": "M",
    "Cargo.toml": "M",
    "crates/heptabao-barrier-api/Cargo.toml": "A",
    "crates/heptabao-barrier-api/src/lib.rs": "A",
    "crates/heptabao-durable-core/Cargo.toml": "A",
    "crates/heptabao-durable-core/src/lib.rs": "A",
    "crates/heptabao-single-node-store/Cargo.toml": "A",
    "crates/heptabao-single-node-store/src/lib.rs": "A",
    "crates/heptabao-storage-api/Cargo.toml": "A",
    "crates/heptabao-storage-api/src/lib.rs": "A",
    "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_4.md": "A",
    "docs/storage/HEPTABAO_SINGLE_NODE_DURABLE_STORE_V1.md": "A",
    "planning/HEPTABAO_BLOCKER_REGISTER_V1_4.yaml": "A",
    "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4.yaml": "A",
    "planning/HEPTABAO_V1_4_DURABLE_FOUNDATION_STATUS.yaml": "A",
    "schemas/heptabao_normative_document_manifest_v1_4.schema.json": "A",
    "scripts/validate_plan_v1_4.py": "A",
    "scripts/validate_v1_4_inherited_surface.py": "A",
    "tests/plan/test_plan_v1_4.py": "A",
}


class InheritedSurfaceFailure(RuntimeError):
    """Raised when V1.4 changes a file outside its closed extension surface."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InheritedSurfaceFailure(message)


def parse_name_status(text: str) -> dict[str, str]:
    observed: dict[str, str] = {}
    for line in text.splitlines():
        require(line != "", "git diff emitted an empty name-status entry")
        fields = line.split("\t")
        require(len(fields) == 2, f"unsupported rename/copy or malformed diff entry: {line!r}")
        status, path = fields
        require(status in {"A", "M"}, f"forbidden V1.4 delta status {status!r} for {path!r}")
        require(path not in observed, f"duplicate V1.4 delta path: {path}")
        require(
            path and not path.startswith("/") and "\\" not in path and ".." not in Path(path).parts,
            f"invalid V1.4 delta path: {path!r}",
        )
        observed[path] = status
    return observed


def validate_delta(observed: dict[str, str]) -> None:
    unexpected = sorted(set(observed) - set(EXPECTED_DELTA))
    missing = sorted(set(EXPECTED_DELTA) - set(observed))
    wrong_status = sorted(
        path
        for path in set(observed) & set(EXPECTED_DELTA)
        if observed[path] != EXPECTED_DELTA[path]
    )
    require(not unexpected, f"V1.4 modified inherited or unmanifested paths: {unexpected}")
    require(not missing, f"V1.4 expected extension paths are missing from the exact delta: {missing}")
    require(not wrong_status, f"V1.4 delta status drifted for paths: {wrong_status}")


def git(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise InheritedSurfaceFailure(
            f"git {' '.join(arguments)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def validate_repository() -> None:
    require(
        git("rev-parse", f"{BASELINE_COMMIT}^{{commit}}") == BASELINE_COMMIT,
        "frozen V1.3.1 baseline commit identity drifted",
    )
    require(
        git("rev-parse", f"{BASELINE_COMMIT}^{{tree}}") == BASELINE_TREE,
        "frozen V1.3.1 baseline tree identity drifted",
    )
    head = git("rev-parse", "HEAD")
    require(head != BASELINE_COMMIT, "V1.4 head did not advance beyond the frozen baseline")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", BASELINE_COMMIT, "HEAD"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    require(
        ancestor.returncode == 0,
        "V1.4 head is not a direct descendant of the frozen V1.3.1 baseline",
    )
    name_status = git(
        "diff",
        "--name-status",
        "--no-renames",
        f"{BASELINE_COMMIT}...HEAD",
    )
    validate_delta(parse_name_status(name_status))


def main() -> int:
    try:
        validate_repository()
    except (OSError, InheritedSurfaceFailure) as error:
        print(f"V1.4 inherited-surface validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "V1.4 inherited surface validation: PASS "
        f"(baseline={BASELINE_COMMIT}, changed_paths={len(EXPECTED_DELTA)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
