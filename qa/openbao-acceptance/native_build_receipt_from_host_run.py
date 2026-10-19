#!/usr/bin/env python3
"""Project existing physical build evidence for the unchanged LAN98 admission.

Reads the pinned completed host-run summary, manifest, compiler/build/format
logs and actual owned binary. Creates one NEW private receipt. Never compiles,
executes a binary, opens a network connection, changes a source tree or upgrades
failed scoped tests into passing tests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


# Build artifacts only. Metadata, HTTP, fixture and product archive limits are unchanged.
BINARY_ARTIFACT_LIMIT = 2 * 1024 ** 3
STREAM_CHUNK_BYTES = 1024 ** 2


class Refusal(ValueError):
    pass


def need(condition, label):
    if not condition:
        raise Refusal(label)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def owned_bytes(path, limit):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_owned_file_required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and not before.st_mode & 0o022
             and 0 < before.st_size <= limit, "bounded_owned_regular_file_required")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(descriptor)
        named = path.lstat()
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns)
        need(identity(before) == identity(after) == identity(named)
             and len(raw) == before.st_size, "source_file_changed_during_read")
        return raw
    finally:
        os.close(descriptor)


def owned_binary_digest(path):
    """Observe an unchanged owned binary without materializing it in memory."""
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_owned_file_required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and not before.st_mode & 0o022
             and 0 < before.st_size <= BINARY_ARTIFACT_LIMIT,
             "bounded_owned_binary_required")
        state, size = hashlib.sha256(), 0
        while True:
            chunk = os.read(descriptor, STREAM_CHUNK_BYTES)
            if not chunk:
                break
            size += len(chunk)
            need(size <= BINARY_ARTIFACT_LIMIT, "binary_grew_beyond_artifact_bound")
            state.update(chunk)
        after = os.fstat(descriptor)
        named = path.lstat()
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns)
        need(identity(before) == identity(after) == identity(named)
             and size == before.st_size, "source_binary_changed_during_read")
        return state.hexdigest(), size
    finally:
        os.close(descriptor)


def record(summary, label):
    commands = summary.get("commands")
    need(isinstance(commands, list) and all(isinstance(row, dict) for row in commands),
         "actual_command_inventory_required")
    rows = [row for row in commands if row.get("label") == label]
    need(len(rows) == 1, "exact_command_record_required")
    row = rows[0]
    need(type(row.get("exit_code")) is int and row["exit_code"] == 0
         and row.get("status") == "passed" and not row.get("timed_out"),
         "required_build_command_did_not_pass")
    return row


def checked_log(directory, row):
    name = row.get("log")
    need(isinstance(name, str) and Path(name).name == name, "owned_log_name_required")
    raw = owned_bytes(directory / name, 32 * 1024 * 1024)
    need(digest(raw) == row.get("log_sha256"), "actual_log_digest_mismatch")
    first, separator, rest = raw.partition(b"\n")
    need(separator and json.loads(first).get("argv") == row.get("argv"),
         "actual_log_command_mismatch")
    return rest.decode("utf-8", errors="strict")


def project(summary_path, summary_sha256, manifest_path, commit, tree, runner_sha256):
    for value, length in ((summary_sha256, 64), (commit, 40), (tree, 40), (runner_sha256, 64)):
        need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value),
             "explicit_exact_source_pins_required")
    raw = owned_bytes(summary_path, 8 * 1024 * 1024)
    need(digest(raw) == summary_sha256, "actual_summary_digest_mismatch")
    summary = json.loads(raw)
    need(isinstance(summary, dict) and summary.get("runner_completed") is True
         and summary.get("source_unchanged") is True
         and summary.get("source_commit") == commit and summary.get("source_tree") == tree
         and summary.get("runner_sha256") == runner_sha256
         and summary.get("status") in ("passed_scoped_host_recovery", "failed_or_blocked")
         and isinstance(summary.get("finished_utc"), str) and summary["finished_utc"],
         "completed_exact_frozen_host_run_required")
    manifest_raw = owned_bytes(manifest_path, 16 * 1024 * 1024)
    need(digest(manifest_raw) == summary.get("manifest_sha256"), "actual_manifest_digest_mismatch")
    manifest = json.loads(manifest_raw)
    need(isinstance(manifest, dict) and manifest.get("commit") == commit
         and manifest.get("tree") == tree and isinstance(manifest.get("files"), list)
         and len(manifest["files"]) > 0, "exact_manifest_required")
    for field in ("source_before", "source_after"):
        observed = summary.get(field)
        need(isinstance(observed, dict) and observed.get("commit") == commit
             and observed.get("tree") == tree and type(observed.get("verified_files")) is int
             and observed["verified_files"] == len(manifest["files"]),
             "both_actual_full_source_tree_verifications_required")
    directory = Path(summary_path).parent
    build, compiler, binary_format = (record(summary, label) for label in
                                      ("build-server", "rustc-version", "built-binary-format"))
    need(build.get("argv", [])[1:] == ["build", "--locked", "--offline", "-p", "heptabao-server",
         "--bin", "heptabao-server", "--features",
         "experimental-native-v6-ha,private-ha-forward-diagnostic"],
         "actual_native_build_argv_required")
    need(compiler.get("argv", [])[1:] == ["--version", "--verbose"],
         "actual_native_compiler_identity_required")
    binary = directory / "heptabao-server"
    need(build.get("binary") == str(binary)
         and binary_format.get("argv") == ["/usr/bin/file", str(binary)],
         "actual_owned_binary_path_required")
    checked_log(directory, build)
    compiler_text = checked_log(directory, compiler)
    format_text = checked_log(directory, binary_format)
    hosts = re.findall(r"^host: ([A-Za-z0-9_.-]{1,80})$", compiler_text, re.MULTILINE)
    need(len(hosts) == 1, "one_actual_compiler_host_required")
    abi = hosts[0]
    admitted = {
        "aarch64-apple-darwin": ("arm64", ("Mach-O", "arm64")),
        "x86_64-apple-darwin": ("x86_64", ("Mach-O", "x86_64")),
        "x86_64-unknown-linux-gnu": ("x86_64", ("ELF 64-bit", "x86-64")),
        "x86_64-unknown-linux-musl": ("x86_64", ("ELF 64-bit", "x86-64")),
        "aarch64-unknown-linux-gnu": ("aarch64", ("ELF 64-bit", "ARM aarch64")),
        "aarch64-unknown-linux-musl": ("aarch64", ("ELF 64-bit", "ARM aarch64")),
    }
    need(abi in admitted and summary.get("machine") == admitted[abi][0]
         and all(token in format_text for token in admitted[abi][1]),
         "actual_native_abi_and_binary_format_mismatch")
    actual_digest, binary_bytes = owned_binary_digest(binary)
    need(actual_digest == build.get("binary_sha256")
         and type(build.get("binary_bytes")) is int and binary_bytes == build["binary_bytes"],
         "actual_built_binary_digest_or_size_mismatch")
    return {
        "schema": "heptabao.native-build.v1", "source_commit": commit, "source_tree": tree,
        "binary_sha256": actual_digest, "build_exit_code": build["exit_code"],
        "source_freeze_verified": summary["source_unchanged"], "native_abi": abi,
        "provenance": {
            "schema": "heptabao.physical-host-build-receipt-projection.v1",
            "actual_host_summary_sha256": summary_sha256,
            "actual_manifest_sha256": digest(manifest_raw), "actual_runner_sha256": runner_sha256,
            "actual_build_log_sha256": build["log_sha256"],
            "actual_compiler_log_sha256": compiler["log_sha256"],
            "actual_binary_format_log_sha256": binary_format["log_sha256"],
            "actual_binary_bytes": binary_bytes, "actual_build_argv": build["argv"],
            "source_files_verified_before_and_after": len(manifest["files"]),
            "source_freeze_basis": "pinned_completed_host_run_full_tree_verifications",
            "original_scoped_host_status": summary["status"],
            "original_scoped_host_passed": summary["status"] == "passed_scoped_host_recovery",
            "lan98_executed_by_projection": False, "production_cutover": False,
        },
    }


def write_new(path, value):
    path = Path(path)
    parent = path.parent
    info = parent.stat()
    need(path.is_absolute() and parent.resolve(strict=True) == parent
         and stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
         "new_receipt_parent_must_be_owned_and_canonical")
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(parent, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return digest(raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("summary", "manifest", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("summary-sha256", "source-commit", "source-tree", "runner-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        value = project(args.summary, args.summary_sha256, args.manifest,
                        args.source_commit, args.source_tree, args.runner_sha256)
        output_sha256 = write_new(args.output, value)
    except (OSError, ValueError, KeyError, TypeError) as error:
        label = str(error) if isinstance(error, Refusal) else "projection_input_or_output_rejected"
        print(json.dumps({"status": "refused", "reason": label, "remote_operations": 0}))
        return 1
    print(json.dumps({"status": "receipt_projected", "receipt_sha256": output_sha256,
                      "native_abi": value["native_abi"], "remote_operations": 0,
                      "original_scoped_host_status": value["provenance"]["original_scoped_host_status"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
