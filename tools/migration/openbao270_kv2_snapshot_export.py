#!/usr/bin/env python3
"""Project an externally pinned complete OpenBao2.7.0 snapshot raw spool.

This offline maintenance operation makes no HTTP request. It does not replace
the live export's original five/360-second qualification. The already-qualified
backup owner supplies the witness SHA separately. Both outputs are create-only
private files; a failure preserves any partial output and never retries import.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import struct
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("snapshot_raw_decoder", HERE / "kv2_lossless_raw.py")
decoder = importlib.util.module_from_spec(spec); sys.modules[spec.name] = decoder; spec.loader.exec_module(decoder)
need, DecodeError = decoder.need, decoder.DecodeError
MAINTENANCE_SECONDS = 300


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def check(end):
    need(time.monotonic() < end, "snapshot offline maintenance deadline")


def open_private(path, maximum, *, expected_sha=None, exact_bytes=None, end, owner_uid=None):
    path = Path(path); check(end)
    owner_uid = os.getuid() if owner_uid is None else owner_uid
    need(path.is_absolute() and path.resolve(strict=True) == path, "snapshot input path alias")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == owner_uid and s.st_nlink == 1
             and stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size <= maximum
             and (exact_bytes is None or s.st_size == exact_bytes), "snapshot input custody")
        digest = hashlib.sha256(); count = 0
        while True:
            check(end); raw = os.read(fd, 1048576)
            if not raw: break
            count += len(raw); digest.update(raw)
        need(count == s.st_size and (expected_sha is None or digest.hexdigest() == expected_sha)
             and identity(s) == identity(os.fstat(fd)) == identity(path.lstat()), "snapshot input changed")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, s, digest.hexdigest()
    except BaseException:
        os.close(fd); raise


def recheck(fd, path, before, expected_sha, end):
    digest = hashlib.sha256(); offset = 0
    while offset < before.st_size:
        check(end); raw = os.pread(fd, min(1048576, before.st_size - offset), offset)
        need(raw, "snapshot input short after read"); digest.update(raw); offset += len(raw)
    need(digest.hexdigest() == expected_sha
         and identity(before) == identity(os.fstat(fd)) == identity(Path(path).lstat()),
         "snapshot input changed after projection")


def read_spool(fd, document, end):
    spool = document["spool"]; mount = document["mount"]
    selected_root = "logical/" + mount["uuid"] + "/" + mount["backend_uuid"] + "/"
    selected = []; seen = set(); roots_seen = set(); total = paths = count = offset = 0
    while offset < spool["bytes"]:
        check(end); header = os.pread(fd, 16, offset)
        need(len(header) == 16, "snapshot truncated frame header")
        name_bytes, raw_bytes = struct.unpack(">QQ", header)
        need(0 < name_bytes <= 65536 and raw_bytes <= decoder.NATIVE_LARGE_BOUNDS.record_bytes
             and offset + 16 + name_bytes + raw_bytes <= spool["bytes"], "snapshot frame bounds")
        name = os.pread(fd, name_bytes, offset + 16)
        raw = os.pread(fd, raw_bytes, offset + 16 + name_bytes)
        need(len(name) == name_bytes and len(raw) == raw_bytes, "snapshot truncated frame")
        path = decoder.utf8(name)
        need(path not in seen and sum(path.startswith(root) for root in spool["roots"]) == 1,
             "snapshot duplicate or out-of-scope frame")
        roots_seen.update(root for root in spool["roots"] if path.startswith(root))
        seen.add(path); count += 1; total += raw_bytes; paths += name_bytes
        need(count <= spool["records"] and total <= spool["raw_bytes"] and paths <= spool["path_bytes"],
             "snapshot spool aggregate exceeded")
        if path.startswith(selected_root): selected.append((path, raw))
        offset += 16 + name_bytes + raw_bytes
    need(offset == spool["bytes"] and count == spool["records"]
         and total == spool["raw_bytes"] and paths == spool["path_bytes"]
         and roots_seen == set(spool["roots"]), "snapshot spool incomplete")
    return selected


def create_private(path, raw, end):
    path = Path(path); check(end)
    need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent, "snapshot output parent alias")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); fd = None
    try:
        before = os.fstat(parent)
        need(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid()
             and stat.S_IMODE(before.st_mode) == 0o700, "snapshot output parent custody")
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            for offset in range(0, len(raw), 1048576):
                check(end); stream.write(raw[offset:offset + 1048576])
            stream.flush(); os.fsync(fd)
        os.fsync(parent); check(end)
        after = os.fstat(fd)
        need(stat.S_ISREG(after.st_mode) and after.st_uid == os.getuid() and after.st_nlink == 1
             and stat.S_IMODE(after.st_mode) == 0o600 and after.st_size == len(raw)
             and identity(after) == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
             == identity(path.lstat()), "snapshot output identity or custody changed")
        p = path.parent.lstat(); current = os.fstat(parent)
        need((p.st_dev, p.st_ino, p.st_uid, p.st_gid, p.st_mode)
             == (current.st_dev, current.st_ino, current.st_uid, current.st_gid, current.st_mode)
             == (before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode),
             "snapshot output parent changed")
        return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                "identity": list(identity(after))}
    finally:
        try:
            if fd is not None: os.close(fd)
        finally:
            os.close(parent)


def verify_created(record, end):
    fd, before, digest = open_private(record["path"], record["bytes"],
        expected_sha=record["sha256"], exact_bytes=record["bytes"], end=end)
    try:
        need(list(identity(before)) == record["identity"], "snapshot output replaced")
        recheck(fd, record["path"], before, digest, end)
    finally:
        os.close(fd)


def export_snapshot(witness, witness_sha256, raw_spool, output, provenance, *, end=None):
    end = time.monotonic() + MAINTENANCE_SECONDS if end is None else end
    witness_fd = spool_fd = None
    need(Path(output) != Path(provenance), "snapshot outputs must differ")
    try:
        witness_fd, witness_stat, actual_sha = open_private(witness, 131072, expected_sha=witness_sha256, end=end)
        wire = os.pread(witness_fd, witness_stat.st_size, 0)
        source = decoder.admit_snapshot_source(wire, actual_sha)
        document = decoder._snapshot_document(source.raw, source.sha256)
        spool = document["spool"]
        spool_fd, spool_stat, spool_sha = open_private(raw_spool,
            2 * decoder.MAX_TOTAL + 16 * decoder.NATIVE_RAW_RECORDS,
            expected_sha=spool["sha256"], exact_bytes=spool["bytes"], end=end)
        records = read_spool(spool_fd, document, end)
        value = decoder.decode_records(records, bounds=decoder.NATIVE_LARGE_BOUNDS, source=source)
        # Concurrent raw capture order is not meaningful. Stable logical-path
        # order permits an independent complete history projection to compare
        # exact output bytes, including the final newline.
        value["entries"] = dict(sorted(value["entries"].items()))
        raw = (decoder.dumps_lossless(value) + "\n").encode("utf-8")
        need(len(raw) <= decoder.MAX_TOTAL, "snapshot native-large bundle byte bound")
        proof = decoder.snapshot_provenance(source, raw)
        recheck(witness_fd, witness, witness_stat, witness_sha256, end)
        recheck(spool_fd, raw_spool, spool_stat, spool_sha, end)
        bundle = create_private(output, raw, end)
        sidecar = create_private(provenance, (json.dumps(proof, sort_keys=True, indent=2) + "\n").encode(), end)
        recheck(witness_fd, witness, witness_stat, witness_sha256, end)
        recheck(spool_fd, raw_spool, spool_stat, spool_sha, end)
        verify_created(bundle, end); verify_created(sidecar, end)
        check(end)
        return {"schema": "heptabao.openbao270-snapshot-export-receipt.v1", "status": "complete_offline_source_projection",
            "source_witness_sha256": witness_sha256, "bundle": bundle, "provenance": sidecar,
            "logical_paths": len(value["entries"]), "raw_records": len(records),
            "source_inputs_unchanged": True, "source_http_requests": 0, "source_modified": False,
            "source_config_record_synthesized": False, "target_import_qualified": False,
            "live_source_current_frontier_qualified": False, "formal_live_export_5_360_qualified": False}
    finally:
        try:
            if spool_fd is not None: os.close(spool_fd)
        finally:
            if witness_fd is not None: os.close(witness_fd)


def main(argv=None):
    started = time.monotonic(); os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--witness", required=True)
    parser.add_argument("--witness-sha256", required=True)
    parser.add_argument("--raw-spool", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--provenance", required=True)
    args = parser.parse_args(argv)
    def interrupted(number, frame):
        raise DecodeError("snapshot offline operation interrupted")
    original_handlers = {number: signal.signal(number, interrupted)
                         for number in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
    signal.setitimer(signal.ITIMER_REAL, max(0.001, started + MAINTENANCE_SECONDS - time.monotonic()))
    try:
        report = export_snapshot(args.witness, args.witness_sha256, args.raw_spool, args.output, args.provenance,
                                 end=started + MAINTENANCE_SECONDS)
        report["elapsed_seconds"] = time.monotonic() - started
        print(json.dumps(report, sort_keys=True), flush=True)
        return 0
    except BaseException as error:
        # A malformed private record may occur in an exception message. Only a
        # fixed public refusal and the class are emitted; all outputs remain.
        print(json.dumps({"schema": "heptabao.openbao270-snapshot-export-receipt.v1", "status": "refused",
            "error_type": type(error).__name__, "error_code": "offline_snapshot_projection_refused",
            "source_http_requests": 0, "target_import_qualified": False, "partial_outputs_retained": True}), flush=True)
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for number, handler in original_handlers.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    raise SystemExit(main())
