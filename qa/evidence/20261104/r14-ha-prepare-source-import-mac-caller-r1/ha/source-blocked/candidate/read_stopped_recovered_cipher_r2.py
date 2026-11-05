#!/usr/bin/env python3
"""Read exactly this fresh fixture's earlier recovered references after all owned stops.
REFERENCE_JSON is supplied as a Python string literal by the pinned caller over
its existing SSH stdin. No directory enumeration, repair, file writes or children.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261103-ha-closure-r1/r10-pocket3-mac1-postrecovery-cold-node1-r2"
UID = 501
COMMIT = "49503322c7f446e5eb41e7744f1fdbd7f1192ecc"
TREE = "1d4211f91e1b34a2ed087a3bbef2e2884bac88e9"
MAX_REFERENCE = MAX_OUTPUT = 1024 * 1024
MAX_LEAVES = 4096
MAX_LEAF = 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_SECONDS = 15.0
IDENTITY_KEYS = {"device", "inode", "uid", "mode", "nlink", "bytes", "mtime_ns", "ctime_ns"}
LEAF = re.compile(r"v6-[0-9a-f]{64}\.blob\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def within(until):
    need(time.monotonic() < until, "original_reference_read_deadline_expired")


def no_duplicate(pairs):
    result = {}
    for name, value in pairs:
        need(name not in result, "duplicate_reference_key")
        result[name] = value
    return result


def reject_constant(_):
    raise Refused("nonfinite_reference")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def identity(info):
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
            "mode": stat.S_IMODE(info.st_mode), "nlink": info.st_nlink,
            "bytes": info.st_size, "mtime_ns": info.st_mtime_ns,
            "ctime_ns": info.st_ctime_ns}


def parse_reference(raw, run_id, expected_sha256):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_REFERENCE, "reference_input_bound")
    need(HEX.fullmatch(expected_sha256) is not None
         and hashlib.sha256(raw).hexdigest() == expected_sha256, "captured_reference_digest_changed")
    value = json.loads(raw, object_pairs_hook=no_duplicate, parse_constant=reject_constant)
    need(type(value) is dict and set(value) == {
        "schema", "fixture_run_id", "source_commit", "source_tree", "node_id", "root",
        "captured_from_same_recovered_scan", "inventory_sha256", "restored_count",
        "restored_bytes", "directories", "leaves"}, "captured_reference_shape")
    need(value["schema"] == "heptabao.postrecovery-captured-cipher-reference.v1"
         and value["fixture_run_id"] == run_id and value["source_commit"] == COMMIT
         and value["source_tree"] == TREE and value["node_id"] == 1 and value["root"] == ROOT
         and value["captured_from_same_recovered_scan"] is True
         and HEX.fullmatch(value["inventory_sha256"]) is not None, "captured_reference_binding")
    leaves = value["leaves"]
    need(type(leaves) is dict and 0 < len(leaves) <= MAX_LEAVES
         and type(value["restored_count"]) is int and value["restored_count"] == len(leaves),
         "captured_reference_count")
    total = 0
    for name, row in leaves.items():
        need(LEAF.fullmatch(name) is not None and type(row) is dict
             and set(row) == {"sha256", "bytes", "identity"}, "captured_leaf_shape")
        fact = row["identity"]
        need(type(row["bytes"]) is int and 0 < row["bytes"] <= MAX_LEAF
             and type(row["sha256"]) is str and HEX.fullmatch(row["sha256"]) is not None
             and type(fact) is dict and set(fact) == IDENTITY_KEYS
             and all(type(v) is int and v >= 0 for v in fact.values())
             and fact["uid"] == UID and fact["nlink"] == 1
             and fact["mode"] & 0o077 == 0 and fact["bytes"] == row["bytes"],
             "captured_leaf_identity_invalid")
        total += row["bytes"]
        need(total <= MAX_TOTAL, "captured_reference_total_bound")
    need(type(value["restored_bytes"]) is int and total == value["restored_bytes"],
         "captured_reference_bytes")
    directories = value["directories"]
    need(type(directories) is list and len(directories) == 3
         and [x.get("name") for x in directories] == [ROOT, "raft", "native-v6-ciphertext"],
         "captured_directory_reference_shape")
    for row in directories:
        need(type(row) is dict and set(row) == {"name", "identity"}
             and type(row["identity"]) is dict and set(row["identity"]) == IDENTITY_KEYS
             and all(type(v) is int and v >= 0 for v in row["identity"].values())
             and row["identity"]["uid"] == UID and row["identity"]["mode"] & 0o077 == 0,
             "captured_directory_reference_identity")
    return value


def execute(value, run_id, until):
    within(until)
    need(os.geteuid() == UID, "fixed_uid_mismatch")
    root = Path(ROOT)
    need(root.resolve(strict=True) == root, "fixed_root_is_not_canonical")
    descriptors, directory_facts = [], []
    files = []
    total = 0
    def directory(parent, name, expected):
        within(until)
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent)
        descriptors.append(fd)
        opened = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fact = identity(opened)
        need(stat.S_ISDIR(opened.st_mode) and opened.st_uid == UID
             and opened.st_mode & 0o077 == 0
             and identity(before) == fact == identity(named), "owned_directory_identity_changed")
        # Stopping owners may change directory mtime/size. Across the two
        # phases bind its actual object and protection, not a stale timestamp.
        for key in ("device", "inode", "uid", "mode"):
            need(fact[key] == expected[key], "captured_directory_object_changed")
        directory_facts.append((fd, parent, name, fact))
        return fd
    def read_small(parent, name, limit):
        within(until)
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            opened = os.fstat(fd)
            need(stat.S_ISREG(opened.st_mode) and opened.st_uid == UID
                 and opened.st_nlink == 1 and opened.st_mode & 0o077 == 0
                 and 0 < opened.st_size <= limit and identity(before) == identity(opened),
                 "owned_marker_identity")
            parts, size = [], 0
            while True:
                within(until)
                part = os.read(fd, min(65536, limit + 1 - size))
                if not part:
                    break
                size += len(part)
                need(size <= limit, "marker_read_bound")
                parts.append(part)
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            need(identity(before) == identity(after) == identity(named) and size == before.st_size,
                 "marker_identity_changed")
            return b"".join(parts)
        finally:
            os.close(fd)
    try:
        refs = value["directories"]
        root_fd = directory(None, ROOT, refs[0]["identity"])
        for name in ("process.pid", "process.identity.json"):
            within(until)
            try:
                os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused("owned_stop_marker_still_present")
        marker_raw = read_small(root_fd, "native-ha-fixture.json", 65536)
        marker = json.loads(marker_raw, object_pairs_hook=no_duplicate, parse_constant=reject_constant)
        root_fact = identity(os.fstat(root_fd))
        need(type(marker) is dict and marker.get("run_id") == run_id and marker.get("root") == ROOT
             and marker.get("production_authority") is False
             and marker.get("root_device") == root_fact["device"]
             and marker.get("root_inode") == root_fact["inode"], "private_fixture_marker_mismatch")
        raft_fd = directory(root_fd, "raft", refs[1]["identity"])
        store_fd = directory(raft_fd, "native-v6-ciphertext", refs[2]["identity"])
        for name, expected in sorted(value["leaves"].items()):
            within(until)
            before = os.stat(name, dir_fd=store_fd, follow_symlinks=False)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=store_fd)
            try:
                opened = os.fstat(fd)
                first = identity(opened)
                need(stat.S_ISREG(opened.st_mode) and opened.st_uid == UID and opened.st_nlink == 1
                     and opened.st_mode & 0o077 == 0 and 0 < opened.st_size <= MAX_LEAF
                     and identity(before) == first == expected["identity"], "captured_leaf_object_changed")
                h, size = hashlib.sha256(), 0
                while True:
                    within(until)
                    part = os.read(fd, 65536)
                    if not part:
                        break
                    size += len(part)
                    total += len(part)
                    need(size <= MAX_LEAF and total <= MAX_TOTAL, "cipher_read_bound")
                    h.update(part)
                after = identity(os.fstat(fd))
                named = identity(os.stat(name, dir_fd=store_fd, follow_symlinks=False))
                need(first == after == named and size == expected["bytes"]
                     and h.hexdigest() == expected["sha256"], "captured_leaf_content_or_identity_changed")
                files.append({"name": name, "bytes": size, "sha256": h.hexdigest(),
                              "before": first, "after": after, "named_after": named})
            finally:
                os.close(fd)
        need(len(files) == value["restored_count"] and total == value["restored_bytes"],
             "captured_reference_set_incomplete")
        directories = []
        for fd, parent, name, before in directory_facts:
            within(until)
            named_info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            named = identity(named_info)
            after = identity(os.fstat(fd))
            need(stat.S_ISDIR(named_info.st_mode) and before == after == named,
                 "directory_final_named_binding_changed")
            directories.append({"name": name, "before": before, "after": after, "named_after": named})
        within(until)
        return {"node_id": 1, "fixed_root": ROOT, "actual_reference_count": len(files),
                "actual_reference_bytes": total, "all_captured_leaves_match": True,
                "unreferenced_leaves_enumerated_or_read": False, "files": files,
                "directories": directories, "marker_sha256": hashlib.sha256(marker_raw).hexdigest()}
    finally:
        errors = []
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except OSError:
                errors.append(fd)
        need(not errors, "held_directory_close_failed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--reference-sha256", required=True)
    parser.add_argument("--max-seconds", type=float, required=True)
    args = parser.parse_args()
    need(len(args.run_id) == 32 and all(c in "0123456789abcdef" for c in args.run_id)
         and 0 < args.max_seconds <= MAX_SECONDS, "fixed_reference_arguments")
    started = time.monotonic()
    until = started + args.max_seconds
    result = {"schema": "heptabao.postrecovery-stopped-cipher-reference.v1",
              "status": "failed", "fixture_run_id": args.run_id,
              "reference_sha256": args.reference_sha256, "new_read_seconds": args.max_seconds,
              "file_writes": 0, "child_processes": 0, "product_requests": 0,
              "production_authority": False}
    rc = 1
    try:
        need(type(REFERENCE_JSON) is str, "caller_reference_literal_missing")
        raw = REFERENCE_JSON.encode("utf-8")
        value = parse_reference(raw, args.run_id, args.reference_sha256)
        within(until)
        result["observation"] = execute(value, args.run_id, until)
        within(until)
        result["status"] = "completed"
        rc = 0
    except Refused as error:
        result["failure_code"] = str(error)
    except BaseException as error:
        result["failure_type"] = type(error).__name__
    result["elapsed_seconds"] = time.monotonic() - started
    result["publication_within_original_read_deadline"] = time.monotonic() < until
    if not result["publication_within_original_read_deadline"]:
        result["status"], rc = "failed", 1
    output = canonical(result)
    if len(output) > MAX_OUTPUT:
        output = canonical({"schema": result["schema"], "status": "failed",
                            "failure_code": "public_reference_output_bound"})
        rc = 1
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    return rc if time.monotonic() < until else 1


if __name__ == "__main__":
    raise SystemExit(main())
