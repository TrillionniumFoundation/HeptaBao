"""Source/binary-bound, non-authoritative observations for online-auth fixtures."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
from bao_http import private_write


def admit_output(path: Path) -> tuple[int, int]:
    """Reject existing/linked outputs before allocating a synthetic service."""
    path = path.absolute()
    for parent in (path.parent, *path.parent.parents):
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError("report_directory_not_regular")
    info = path.parent.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("report_directory_not_private")
    if os.path.lexists(path):
        raise ValueError("report_already_exists")
    return info.st_dev, info.st_ino


def source_identity(root: Path, binary: Path) -> dict:
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL)
    # Commit identity alone does not bind a dirty source tree. Include bytes of
    # tracked and untracked non-ignored source, but never follow source symlinks.
    digest = hashlib.sha256()
    paths = sorted(set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")) - {b""})
    for raw in paths:
        path = root / os.fsdecode(raw)
        digest.update(len(raw).to_bytes(8, "big") + raw)
        if not os.path.lexists(path):
            digest.update(b"missing")
            continue
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            data = os.fsencode(os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            data = path.read_bytes()
        else:
            raise ValueError("source_contains_nonregular_object")
        digest.update(info.st_mode.to_bytes(8, "big") + hashlib.sha256(data).digest())
    with binary.open("rb") as stream:
        binary_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "source_commit": git("rev-parse", "HEAD").decode().strip(),
        "source_tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
        "source_dirty": bool(git("status", "--porcelain", "--untracked-files=all")),
        "source_content_sha256": digest.hexdigest(),
        "binary_sha256": binary_hash,
    }


def complete_checks(checks: list[dict], expected_count: int) -> bool:
    if not checks or len(checks) != expected_count:
        return False
    names = []
    for row in checks:
        if not isinstance(row, dict) or set(row) != {"case", "passed"}:
            return False
        if row["passed"] is not True or not isinstance(row["case"], str) or not re.fullmatch(r"[a-z0-9_]{1,120}", row["case"]):
            return False
        names.append(row["case"])
    return len(set(names)) == len(names)


def publish(output: Path, admitted_parent: tuple[int, int], report: dict,
            before: dict, after: dict, expected_count: int) -> None:
    if before != after:
        report["failure"] = "source_or_binary_changed_during_execution"
    if not complete_checks(report["checks"], expected_count):
        report["failure"] = report.get("failure") or "incomplete_or_invalid_observations"
    report["status"] = "passed" if report.get("failure") is None else "failed"
    report.update(before)
    report["source_and_binary_unchanged"] = before == after
    report["independent_qualification"] = False
    report["compatibility_claim"] = False
    report["production_authority"] = False
    # Recheck caller directory identity. This is output admission and metadata
    # protection, not an external signer or a same-UID adversary sandbox.
    if admit_output(output) != admitted_parent:
        raise ValueError("report_parent_changed_during_execution")
    private_write(output, report, replace=False)
