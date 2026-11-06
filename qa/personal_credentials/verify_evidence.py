#!/usr/bin/env python3
"""Verify the finite evidence archive without interpreting receipt outcomes.

Normal execution is read-only. Receipts and Git bundles are opaque bytes; a
matching digest proves neither authenticity, test success nor qualification.
--self-test creates and removes only its own temporary synthetic archives.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

INDEX_SCHEMA = "heptabao.personal-credentials.evidence-index.v1"
RESULT_SCHEMA = "heptabao.personal-credentials.archive-integrity.v1"
SCOPE = "archive_integrity_only"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_ENTRIES = 256
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
COMMIT = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
COMMON = {"file", "bytes", "sha256"}
ENTRY_SHAPES = (
    COMMON | {"transformation"},
    COMMON | {"transformation", "github_run_id", "github_job_id"},
    COMMON | {"base_required", "source_commit"},
)


class InvalidArchive(Exception):
    """Only fixed error codes are emitted; never input text or file contents."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise InvalidArchive(code)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "manifest_duplicate_json_key")
        result[key] = value
    return result


def reject_constant(_value: str) -> None:
    raise InvalidArchive("manifest_nonfinite_number")


def manifest(raw: bytes) -> list[dict]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=reject_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise InvalidArchive("manifest_invalid_json") from error
    require(type(value) is dict and set(value) == {
        "schema", "synthetic_only", "production_qualified", "entries"
    }, "manifest_fields")
    require(value["schema"] == INDEX_SCHEMA, "manifest_schema")
    require(value["synthetic_only"] is True and value["production_qualified"] is False,
            "manifest_scope_flags")
    entries = value["entries"]
    require(type(entries) is list and 0 < len(entries) <= MAX_ENTRIES,
            "manifest_entry_limit")
    seen = set()
    total = 0
    for entry in entries:
        require(type(entry) is dict and set(entry) in ENTRY_SHAPES, "entry_fields")
        name = entry["file"]
        require(type(name) is str and NAME.fullmatch(name) is not None
                and name.casefold() != "manifest.json", "entry_unsafe_filename")
        require(name.casefold() not in seen, "entry_duplicate_filename")
        seen.add(name.casefold())
        require(type(entry["bytes"]) is int and 0 <= entry["bytes"] <= MAX_FILE_BYTES,
                "entry_size_limit")
        total += entry["bytes"]
        require(total <= MAX_TOTAL_BYTES, "archive_size_limit")
        require(type(entry["sha256"]) is str and SHA256.fullmatch(entry["sha256"]) is not None,
                "entry_sha256")
        if "transformation" in entry:
            description = entry["transformation"]
            require(type(description) is str and 0 < len(description) <= 512
                    and description.isprintable(), "entry_metadata")
            try:
                description.encode("utf-8")
            except UnicodeError as error:
                raise InvalidArchive("entry_metadata") from error
        if "github_run_id" in entry:
            require(all(type(entry[key]) is int and 0 < entry[key] < 2**63
                        for key in ("github_run_id", "github_job_id")), "entry_metadata")
        if "source_commit" in entry:
            require(all(type(entry[key]) is str and COMMIT.fullmatch(entry[key]) is not None
                        for key in ("base_required", "source_commit")), "entry_metadata")
    return entries


def identity(value: os.stat_result) -> tuple:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_file(directory: int, name: str, limit: int, *, expected_size: int | None = None,
              capture: bool = False) -> tuple[str, int, tuple, bytes]:
    # NONBLOCK prevents a replacement FIFO from blocking before fstat can reject it.
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except OSError as error:
        raise InvalidArchive("file_open_refused") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), "archive_nonregular_file")
        require(0 <= before.st_size <= limit, "file_size_limit")
        if expected_size is not None:
            require(before.st_size == expected_size, "file_length_mismatch")
        digest = hashlib.sha256()
        parts = []
        count = 0
        while True:
            chunk = os.read(descriptor, min(65536, before.st_size - count + 1))
            if not chunk:
                break
            count += len(chunk)
            require(count <= before.st_size, "file_changed_during_read")
            digest.update(chunk)
            if capture:
                parts.append(chunk)
        require(count == before.st_size and identity(os.fstat(descriptor)) == identity(before),
                "file_changed_during_read")
        return digest.hexdigest(), count, identity(before), b"".join(parts)
    finally:
        os.close(descriptor)


def names(directory: int) -> set[str]:
    result = set()
    with os.scandir(directory) as scan:
        for entry in scan:
            require(len(result) < MAX_ENTRIES + 1, "archive_entry_limit")
            require(stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode),
                    "archive_nonregular_file")
            result.add(entry.name)
    return result


def verify(root: Path) -> dict:
    require(all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")),
            "unsupported_platform")
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise InvalidArchive("archive_root_refused") from error
    try:
        root_before = identity(os.fstat(directory))
        digest, _, manifest_identity, raw = read_file(directory, "manifest.json", MAX_MANIFEST_BYTES, capture=True)
        entries = manifest(raw)
        expected = {"manifest.json"} | {entry["file"] for entry in entries}
        observed = names(directory)
        require(not observed - expected, "archive_unindexed_file")
        require(not expected - observed, "archive_missing_file")
        bindings = {"manifest.json": manifest_identity}
        verified_bytes = 0
        for entry in entries:
            actual, length, file_identity, _ = read_file(directory, entry["file"], MAX_FILE_BYTES,
                                                        expected_size=entry["bytes"])
            require(actual == entry["sha256"], "file_sha256_mismatch")
            bindings[entry["file"]] = file_identity
            verified_bytes += length
        # Bind the end of the observation as well as each opened descriptor.
        require(names(directory) == expected and identity(os.fstat(directory)) == root_before,
                "archive_changed_during_read")
        require(identity(os.stat(root, follow_symlinks=False)) == root_before,
                "archive_changed_during_read")
        for name, bound in bindings.items():
            require(identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == bound,
                    "archive_changed_during_read")
        return {"archive_integrity": "passed", "indexed_files": len(entries),
                "verified_bytes": verified_bytes, "manifest_sha256": digest}
    finally:
        os.close(directory)


def self_test() -> dict:
    rows = []

    def seed(root: Path) -> None:
        root.mkdir(mode=0o700)
        raw = b'{"status":"failed","synthetic_only":true}\n'
        (root / "receipt.public.json").write_bytes(raw)
        value = {"schema": INDEX_SCHEMA, "synthetic_only": True, "production_qualified": False,
                 "entries": [{"file": "receipt.public.json", "bytes": len(raw),
                              "sha256": hashlib.sha256(raw).hexdigest(),
                              "transformation": "synthetic self-test bytes"}]}
        (root / "manifest.json").write_text(json.dumps(value), encoding="utf-8")

    def edit(root: Path, change) -> None:
        path = root / "manifest.json"
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def duplicate(root: Path, field: str) -> None:
        path = root / "manifest.json"
        path.write_text(path.read_text().replace('"' + field + '":', '"' + field + '":null,"' + field + '":', 1))

    def link_file(root: Path, name: str) -> None:
        path = root / name
        target = root.parent / (root.name + "-target")
        path.rename(target)
        path.symlink_to(target)

    def link_root(root: Path) -> None:
        target = root.parent / (root.name + "-target")
        root.rename(target)
        root.symlink_to(target, target_is_directory=True)

    cases = [
        ("failed_receipt_is_opaque_and_archive_passes", None, None),
        ("same_length_tamper", lambda p: (p / "receipt.public.json").write_bytes(
            b"[" + (p / "receipt.public.json").read_bytes()[1:]), "file_sha256_mismatch"),
        ("truncated_file", lambda p: (p / "receipt.public.json").write_bytes(b"short"), "file_length_mismatch"),
        ("duplicate_top_json_key", lambda p: duplicate(p, "schema"), "manifest_duplicate_json_key"),
        ("duplicate_entry_json_key", lambda p: duplicate(p, "bytes"), "manifest_duplicate_json_key"),
        ("traversal_filename", lambda p: edit(p, lambda v: v["entries"][0].update(file="../outside.json")), "entry_unsafe_filename"),
        ("absolute_filename", lambda p: edit(p, lambda v: v["entries"][0].update(file="/outside.json")), "entry_unsafe_filename"),
        ("symlink_indexed_file", lambda p: link_file(p, "receipt.public.json"), "archive_nonregular_file"),
        ("symlink_manifest", lambda p: link_file(p, "manifest.json"), "file_open_refused"),
        ("symlink_root", link_root, "archive_root_refused"),
        ("unindexed_file", lambda p: (p / "extra.json").write_bytes(b"extra"), "archive_unindexed_file"),
        ("missing_file", lambda p: (p / "receipt.public.json").unlink(), "archive_missing_file"),
        ("duplicate_filename", lambda p: edit(p, lambda v: v["entries"].append(dict(v["entries"][0]))), "entry_duplicate_filename"),
        ("wrong_schema", lambda p: edit(p, lambda v: v.update(schema="unsupported")), "manifest_schema"),
        ("oversize_manifest", lambda p: (p / "manifest.json").write_bytes(b" " * (MAX_MANIFEST_BYTES + 1)), "file_size_limit"),
        ("oversize_entry", lambda p: edit(p, lambda v: v["entries"][0].update(bytes=MAX_FILE_BYTES + 1)), "entry_size_limit"),
        ("excess_entries", lambda p: edit(p, lambda v: v.update(entries=v["entries"] * (MAX_ENTRIES + 1))), "manifest_entry_limit"),
        ("boolean_length", lambda p: edit(p, lambda v: v["entries"][0].update(bytes=True)), "entry_size_limit"),
        ("nested_directory", lambda p: (p / "nested").mkdir(), "archive_nonregular_file"),
        ("fifo_is_refused_without_blocking", lambda p: os.mkfifo(p / "fifo"), "archive_nonregular_file"),
        ("nonfinite_json", lambda p: (p / "manifest.json").write_bytes(b'{"schema":NaN}'), "manifest_nonfinite_number"),
        ("invalid_utf8", lambda p: (p / "manifest.json").write_bytes(b"\xff"), "manifest_invalid_json"),
    ]
    with tempfile.TemporaryDirectory(prefix="heptabao-evidence-selftest-") as temporary:
        base = Path(temporary)
        for number, (name, change, expected) in enumerate(cases):
            root = base / str(number)
            seed(root)
            if change is not None:
                change(root)
            before = None if expected else {p.name: p.read_bytes() for p in root.iterdir()}
            observed = None
            try:
                verify(root)
            except InvalidArchive as error:
                observed = str(error)
            except Exception:
                observed = "unexpected_exception"
            unchanged = before is None or before == {p.name: p.read_bytes() for p in root.iterdir()}
            rows.append({"case": name, "passed": observed == expected and unchanged})
        # Two independent CLI processes verify the advertised exit-status boundary.
        for name, corrupt, expected_exit in (("cli_success_scope", False, 0), ("cli_failure_nonzero", True, 1)):
            root = base / name
            seed(root)
            if corrupt:
                (root / "receipt.public.json").write_bytes(b"tampered")
            child = subprocess.run([sys.executable, str(Path(__file__).absolute()), "--root", str(root)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            try:
                value = json.loads(child.stdout)
                passed = (child.returncode == expected_exit and not child.stderr and value["scope"] == SCOPE
                          and value["receipt_results_evaluated"] is False and value["qualification_granted"] is False)
            except (ValueError, KeyError):
                passed = False
            rows.append({"case": name, "passed": passed})
    return {"self_test": True, "passed": all(row["passed"] for row in rows),
            "checks_passed": sum(row["passed"] for row in rows), "expected_count": len(rows), "cases": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--root", type=Path, help="archive directory (default: evidence/20261106 beside this script)")
    group.add_argument("--self-test", action="store_true", help="test private synthetic archives, including negative cases")
    args = parser.parse_args()
    result = {"schema": RESULT_SCHEMA, "scope": SCOPE, "receipt_results_evaluated": False,
              "qualification_granted": False}
    try:
        if args.self_test:
            result.update(self_test())
            success = result["passed"]
        else:
            root = args.root if args.root is not None else Path(__file__).absolute().parent / "evidence" / "20261106"
            result.update(verify(root))
            success = True
    except InvalidArchive as error:
        result.update(archive_integrity="failed", error=str(error))
        success = False
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        result.update(archive_integrity="failed", error="archive_io_or_runtime_error")
        success = False
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
