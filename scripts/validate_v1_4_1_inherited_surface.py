#!/usr/bin/env python3
"""Verify that V1.4.1 is a closed additive extension of the frozen V1.4 tree."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE_COMMIT = "33e1c14c3e417ea1c9ea181e2181751736c7bce5"
BASELINE_TREE = "7c49319a20ffbbe7a9b8b078e052da63dd6b636b"

EXPECTED_DELTA = {
    ".github/workflows/plan-v1.4.1-durable-operation-ledger.yml": "A",
    "Cargo.lock": "M",
    "Cargo.toml": "M",
    "crates/heptabao-journal-api/Cargo.toml": "A",
    "crates/heptabao-journal-api/src/lib.rs": "A",
    "crates/heptabao-journaled-core/Cargo.toml": "A",
    "crates/heptabao-journaled-core/src/lib.rs": "A",
    "crates/heptabao-operation-ledger/Cargo.toml": "A",
    "crates/heptabao-operation-ledger/src/lib.rs": "A",
    "crates/heptabao-single-node-journal/Cargo.toml": "A",
    "crates/heptabao-single-node-journal/src/lib.rs": "A",
    "docs/audit/HEPTABAO_DURABLE_OPERATION_LEDGER_V1.md": "A",
    "docs/plan/HEPTABAO_PLAN_V1_4_1_DURABLE_JOURNAL_AND_OPERATION_LEDGER.md": "A",
    "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_1.yaml": "A",
    "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_1.yaml": "A",
    "planning/HEPTABAO_V1_4_1_DURABLE_OPERATION_LEDGER_STATUS.yaml": "A",
    "schemas/heptabao_normative_document_manifest_v1_4_1.schema.json": "A",
    "scripts/validate_plan_v1_4_1.py": "A",
    "scripts/validate_v1_4_1_inherited_surface.py": "A",
    "tests/plan/test_plan_v1_4_1.py": "A",
}


class InheritedSurfaceFailure(RuntimeError):
    """Raised when V1.4.1 changes a file outside its closed extension surface."""


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
        require(status in {"A", "M"}, f"forbidden V1.4.1 delta status {status!r} for {path!r}")
        require(path not in observed, f"duplicate V1.4.1 delta path: {path}")
        require(
            path and not path.startswith("/") and "\\" not in path and ".." not in Path(path).parts,
            f"invalid V1.4.1 delta path: {path!r}",
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
    require(not unexpected, f"V1.4.1 modified inherited or unmanifested paths: {unexpected}")
    require(not missing, f"V1.4.1 expected extension paths are missing: {missing}")
    require(not wrong_status, f"V1.4.1 delta status drifted for paths: {wrong_status}")


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
        "frozen V1.4 baseline commit identity drifted",
    )
    require(
        git("rev-parse", f"{BASELINE_COMMIT}^{{tree}}") == BASELINE_TREE,
        "frozen V1.4 baseline tree identity drifted",
    )
    head = git("rev-parse", "HEAD")
    require(head != BASELINE_COMMIT, "V1.4.1 head did not advance beyond the frozen baseline")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", BASELINE_COMMIT, "HEAD"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    require(ancestor.returncode == 0, "V1.4.1 head is not a descendant of frozen V1.4")
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
        print(f"V1.4.1 inherited-surface validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "V1.4.1 inherited surface validation: PASS "
        f"(baseline={BASELINE_COMMIT}, changed_paths={len(EXPECTED_DELTA)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
