#!/usr/bin/env python3
"""Prove V1.4.3 is an exact closed extension of the frozen V1.4.2 tree."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from validate_plan_v1_4_3 import ValidationFailure, validate

ROOT = Path(__file__).resolve().parents[1]
BASELINE_COMMIT = "34e8dc0caceb84288d4ef61f79cd7ca062718b63"
BASELINE_TREE = "a1a0e7ab4e5ae8d4a2a5a7cde425eaf94a54b1d7"
EXPECTED_REPOSITORY_ID = "1349115072"
EXPECTED_REPOSITORY = "TrillionniumFoundation/HeptaBao"

EXPECTED_DELTA = {
    "Cargo.toml": "M",
    "Cargo.lock": "M",
    "crates/heptabao-filesystem-guard/Cargo.toml": "A",
    "crates/heptabao-filesystem-guard/src/lib.rs": "A",
    "crates/heptabao-single-node-store/Cargo.toml": "M",
    "crates/heptabao-single-node-store/src/lib.rs": "M",
    "crates/heptabao-single-node-journal/Cargo.toml": "M",
    "crates/heptabao-single-node-journal/src/lib.rs": "M",
    "docs/plan/HEPTABAO_PLAN_V1_4_3_DESCRIPTOR_ANCHOR_AND_WRITER_FENCING.md": "A",
    "docs/storage/HEPTABAO_DESCRIPTOR_ANCHOR_AND_WRITER_FENCE_V1.md": "A",
    "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_3.yaml": "A",
    "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_3.yaml": "A",
    "planning/HEPTABAO_V1_4_3_DESCRIPTOR_FENCING_STATUS.yaml": "A",
    "schemas/heptabao_normative_document_manifest_v1_4_3.schema.json": "A",
    "scripts/validate_plan_v1_4_3.py": "A",
    "scripts/validate_v1_4_3_inherited_surface.py": "A",
    "tests/plan/test_plan_v1_4_3.py": "A",
    ".github/workflows/plan-v1.4.3-descriptor-fencing.yml": "A",
}


def run_git(*arguments: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and result.returncode != 0:
        raise ValidationFailure(
            f"git {' '.join(arguments)} failed: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def normalized_remote(remote: str) -> str:
    value = remote.strip()
    prefixes = (
        "https://github.com/",
        "http://github.com/",
        "ssh://git@github.com/",
        "git@github.com:",
    )
    for prefix in prefixes:
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break
    if value.endswith(".git"):
        value = value[:-4]
    return value.strip("/")


def parse_delta(output: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    if not output:
        return parsed
    for raw_line in output.splitlines():
        fields = raw_line.split("\t")
        status = fields[0]
        code = status[0]
        if code in {"R", "C"}:
            raise ValidationFailure(f"renames or copies are forbidden in V1.4.3: {raw_line}")
        if len(fields) != 2 or code not in {"A", "M", "D", "T"}:
            raise ValidationFailure(f"unexpected git delta line: {raw_line}")
        path = fields[1]
        if path in parsed:
            raise ValidationFailure(f"duplicate changed path: {path}")
        parsed[path] = code
    return parsed


def validate_repository_identity() -> None:
    repository = normalized_remote(run_git("config", "--get", "remote.origin.url"))
    if repository != EXPECTED_REPOSITORY:
        raise ValidationFailure(f"repository identity drifted: {repository!r}")
    status = ROOT / "planning/HEPTABAO_V1_4_3_DESCRIPTOR_FENCING_STATUS.yaml"
    if EXPECTED_REPOSITORY_ID not in status.read_text(encoding="utf-8"):
        raise ValidationFailure("stable repository ID is absent from V1.4.3 status")


def validate_git_surface() -> None:
    if run_git("status", "--porcelain=v1", "--untracked-files=all"):
        raise ValidationFailure("V1.4.3 exact-source tree is dirty")
    baseline_type = run_git("cat-file", "-t", BASELINE_COMMIT)
    if baseline_type != "commit":
        raise ValidationFailure("frozen V1.4.2 baseline commit is unavailable")
    actual_tree = run_git("rev-parse", f"{BASELINE_COMMIT}^{{tree}}")
    if actual_tree != BASELINE_TREE:
        raise ValidationFailure(f"frozen V1.4.2 baseline tree drifted: {actual_tree}")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", BASELINE_COMMIT, "HEAD"],
        cwd=ROOT,
        check=False,
    )
    if ancestor.returncode != 0:
        raise ValidationFailure("V1.4.3 head does not descend from the frozen V1.4.2 head")
    delta = parse_delta(
        run_git(
            "diff",
            "--name-status",
            "--find-renames=1%",
            f"{BASELINE_COMMIT}..HEAD",
        )
    )
    if delta != EXPECTED_DELTA:
        missing = sorted(set(EXPECTED_DELTA) - set(delta))
        extra = sorted(set(delta) - set(EXPECTED_DELTA))
        wrong = sorted(
            path
            for path in set(delta) & set(EXPECTED_DELTA)
            if delta[path] != EXPECTED_DELTA[path]
        )
        raise ValidationFailure(
            f"V1.4.3 exact delta drifted: missing={missing}, extra={extra}, wrong_status={wrong}"
        )
    summary = run_git("diff", "--summary", f"{BASELINE_COMMIT}..HEAD")
    if " mode change " in f" {summary} ":
        raise ValidationFailure("V1.4.3 changes an inherited file mode")
    for path, status in EXPECTED_DELTA.items():
        mode_line = run_git("ls-tree", "HEAD", "--", path)
        if not mode_line:
            raise ValidationFailure(f"changed path is missing from HEAD: {path}")
        mode = mode_line.split(maxsplit=1)[0]
        if mode not in {"100644", "100755"}:
            raise ValidationFailure(f"changed path is not a regular file: {path} ({mode})")
        if status == "A" and not (ROOT / path).is_file():
            raise ValidationFailure(f"added V1.4.3 path is not a regular checkout file: {path}")


def main() -> int:
    try:
        validate_repository_identity()
        validate_git_surface()
        validate(ROOT)
    except (OSError, ValidationFailure) as error:
        print(f"V1.4.3 inherited surface validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "V1.4.3 inherited surface validation: PASS "
        f"(baseline={BASELINE_COMMIT}, changed_paths={len(EXPECTED_DELTA)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
