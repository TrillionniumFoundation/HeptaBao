#!/usr/bin/env python3
"""One bounded numeric read of a fixed fresh direction-R3 node after its owned stop.
Does not invoke Rust open_existing, repair/truncate a journal, or open ciphertext.
The controller supplies the actual fresh run ID and records the original stop.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import time
import zlib

BASELINE_FAILURE_SHA = "bd7cc8949faca6bebcad6c847f2f1506526a6329ed6392f865892f253cf0c912"
ROOTS = {
    1: ("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261103-ha-closure-r1/r10-pocket3-mac1-direct98-node1-r3", 501),
    2: ("/home/qian-qi/heptabao-ha-closure-20261103-r1/r10-pocket3-mac1-direct98-node2-r3", 1000),
}
# Exact stopped-fixture metadata observations, per node; no permission changes.
LOG_MODES = {1: (0o755, 0o644), 2: (0o775, 0o664)}
MAX_FILE = 8 * 1024 * 1024
MAX_LOGS = 4096
MAX_EVENTS = 16384
MAX_VOTES = 256
SECONDS = 15.0
U64 = (1 << 64) - 1


class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def within(until):
    require(time.monotonic() < until, "original_read_deadline_expired")


def no_duplicate(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def no_constant(_):
    raise Refused("nonfinite_json")


def parse(raw):
    return json.loads(raw, object_pairs_hook=no_duplicate, parse_constant=no_constant)


def uint(value):
    require(type(value) is int and 0 <= value <= U64, "invalid_unsigned_metadata")
    return value


def lid(value, nullable=True):
    if value is None and nullable:
        return None
    require(type(value) is dict and set(value) == {"leader_id", "index"}, "invalid_log_id")
    leader = value["leader_id"]
    require(type(leader) is dict and set(leader) == {"term", "node_id"}, "invalid_leader_id")
    term, node, index = uint(leader["term"]), uint(leader["node_id"]), uint(value["index"])
    require(node in (0, 1, 2, 3), "foreign_log_node")
    return {"leader_id": {"term": term, "node_id": node}, "index": index}


def lid_order(value):
    return None if value is None else (value["leader_id"]["term"], value["leader_id"]["node_id"], value["index"])


def vote(value):
    if value is None:
        return None
    require(type(value) is dict and set(value) == {"leader_id", "committed"}, "invalid_vote")
    require(type(value["committed"]) is bool, "invalid_vote_flag")
    fake = lid({"leader_id": value["leader_id"], "index": 0}, False)
    return {"leader_id": fake["leader_id"], "committed": value["committed"]}


def envelope(raw, magic, offset=0, allow_suffix=False):
    require(len(raw) - offset >= 20 and raw[offset:offset + 8] == magic, "bad_envelope_header")
    length = struct.unpack_from("<Q", raw, offset + 8)[0]
    require(length <= MAX_FILE, "metadata_frame_above_new_read_bound")
    end = offset + 16 + length
    require(end + 4 <= len(raw), "incomplete_metadata_frame")
    require(allow_suffix or end + 4 == len(raw), "unexpected_envelope_suffix")
    payload = raw[offset + 16:end]
    require((zlib.crc32(payload) & 0xffffffff) == struct.unpack_from("<I", raw, end)[0],
            "metadata_crc_mismatch")
    return payload, end + 4


def entry(index, serialized):
    require(type(serialized) is str, "invalid_log_entry_encoding")
    value = parse(serialized)
    require(type(value) is dict and set(value) == {"log_id", "payload"}, "invalid_log_entry_shape")
    log_id = lid(value["log_id"], False)
    require(log_id["index"] == index, "entry_index_mismatch")
    # No payload is returned or treated as authority. Exact original strings are
    # retained only to reproduce the product's conflicting-overwrite rejection.
    return (serialized, log_id)


def project(checkpoint, journal, until):
    payload, _ = envelope(checkpoint, b"HBRLOG01")
    state = parse(payload)
    require(type(state) is dict and set(state) == {
        "journal_format", "journal_epoch", "last_purged_log_id", "committed", "vote", "log"
    }, "unsupported_checkpoint_shape")
    require(state["journal_format"] == 1 and type(state["journal_format"]) is int,
            "unsupported_checkpoint_format")
    epoch = uint(state["journal_epoch"])
    require(epoch > 0 and type(state["log"]) is dict and len(state["log"]) <= MAX_LOGS,
            "invalid_checkpoint_bound")
    logs = {}
    for key, serialized in state["log"].items():
        within(until)
        require(type(key) is str and key.isascii() and key.isdecimal()
                and (key == "0" or not key.startswith("0")), "invalid_log_index_key")
        index = uint(int(key))
        logs[index] = entry(index, serialized)
    purged, committed, current_vote = lid(state["last_purged_log_id"]), lid(state["committed"]), vote(state["vote"])
    checkpoint_vote = current_vote
    require(len(journal) >= 16 and journal[:8] == b"HBRLJ001", "bad_journal_header")
    journal_epoch = struct.unpack_from("<Q", journal, 8)[0]
    require(0 < journal_epoch <= epoch, "invalid_journal_epoch")
    events = 0
    counts = {"Vote": 0, "Committed": 0, "Append": 0, "Truncate": 0, "Purge": 0}
    votes = []
    ignored_stale_journal = journal_epoch < epoch
    if not ignored_stale_journal:
        offset = 16
        while offset < len(journal):
            within(until)
            require(events < MAX_EVENTS, "event_count_above_new_read_bound")
            raw, next_offset = envelope(journal, b"HBRLE001", offset, True)
            event = parse(raw)
            require(type(event) is dict and len(event) == 1, "invalid_journal_event")
            kind, value = next(iter(event.items()))
            require(kind in counts, "unknown_journal_event")
            events += 1
            counts[kind] += 1
            if kind == "Vote":
                current_vote = vote(value)
                require(current_vote is not None and len(votes) < MAX_VOTES, "vote_count_or_shape")
                votes.append({"event_ordinal": events, "file_offset": offset,
                              "vote": current_vote, "event_payload_sha256": hashlib.sha256(raw).hexdigest()})
            elif kind == "Committed":
                committed = lid(value)
            elif kind == "Append":
                require(type(value) is list and len(value) <= MAX_LOGS, "append_count_or_shape")
                for pair in value:
                    within(until)
                    require(type(pair) is list and len(pair) == 2, "invalid_append_pair")
                    index = uint(pair[0])
                    candidate = entry(index, pair[1])
                    if index in logs:
                        require(logs[index][0] == candidate[0], "conflicting_log_overwrite")
                    else:
                        logs[index] = candidate
                    require(len(logs) <= MAX_LOGS, "log_count_above_new_read_bound")
            elif kind == "Truncate":
                require(type(value) is dict and set(value) == {"start"}, "invalid_truncate")
                start = uint(value["start"])
                logs = {key: item for key, item in logs.items() if key < start}
            else:
                require(type(value) is dict and set(value) == {"log_id"}, "invalid_purge")
                next_purged = lid(value["log_id"], False)
                require(purged is None or lid_order(purged) <= lid_order(next_purged), "purge_regressed")
                logs = {key: item for key, item in logs.items() if key > next_purged["index"]}
                purged = next_purged
            offset = next_offset
        require(offset == len(journal), "journal_not_fully_consumed")
    previous = None if purged is None else purged["index"]
    for index in sorted(logs):
        within(until)
        require(previous is None or (previous < U64 and index == previous + 1), "log_hole")
        previous = index
    last = logs[max(logs)][1] if logs else purged
    within(until)
    return {
        "journal_format": 1, "checkpoint_epoch": epoch, "journal_epoch": journal_epoch,
        "stale_journal_ignored_by_product_rule": ignored_stale_journal,
        "complete_current_epoch_journal": not ignored_stale_journal,
        "checkpoint_vote": checkpoint_vote, "final_vote": current_vote,
        "committed_log_id": committed, "last_log_id": last, "last_purged_log_id": purged,
        "retained_entry_count": len(logs), "event_count": events, "event_counts": counts,
        "vote_events": votes, "retained_log_contiguous": True,
        "committed_not_beyond_last_log": committed is None or
            (last is not None and lid_order(committed) <= lid_order(last)),
        "entry_payload_semantics_validated": False,
        "applied_frontier_read_from_state_machine": False,
        "projection_is_read_authority": False,
    }


def identity(info):
    return {
        "device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
        "mode": stat.S_IMODE(info.st_mode), "nlink": info.st_nlink,
        "bytes": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
    }


def read_fd(fd, expected, until):
    within(until)
    chunks = []
    left = expected
    while left:
        within(until)
        raw = os.read(fd, min(left, 65536))
        require(bool(raw), "file_short_read")
        chunks.append(raw)
        left -= len(raw)
    require(os.read(fd, 1) == b"", "file_grew_during_read")
    within(until)
    return b"".join(chunks)


def execute(node, until, run_id):
    raw_root, expected_uid = ROOTS[node]
    log_directory_mode, log_file_mode = LOG_MODES[node]
    root = Path(raw_root)
    require(os.getuid() == expected_uid and root.resolve(strict=True) == root, "fixed_root_or_uid")
    descriptors = []
    opened = []
    directory_facts = []
    def directory(name, parent=None, expected_mode=0o700):
        within(until)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        descriptors.append(fd)
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == expected_uid
                and stat.S_IMODE(info.st_mode) == expected_mode, "owned_directory_mode")
        directory_facts.append((fd, parent, name, identity(info)))
        return fd
    def file(name, parent, maximum, expected_mode=0o600):
        within(until)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        descriptors.append(fd)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == expected_uid
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == expected_mode
                and info.st_size <= maximum, "owned_bounded_regular_file_mode")
        opened.append((fd, parent, name, identity(info)))
        return fd, info.st_size
    try:
        rootfd = directory(raw_root)
        root_stat = os.fstat(rootfd)
        markerfd, marker_size = file("native-ha-fixture.json", rootfd, 4096)
        marker_raw = read_fd(markerfd, marker_size, until)
        marker = parse(marker_raw)
        require(type(marker) is dict and marker.get("schema") == "heptabao.native-v6-fixture-owner.v1"
                and marker.get("run_id") == run_id and marker.get("root") == raw_root
                and marker.get("node_id") == node and marker.get("production_authority") is False
                and marker.get("root_device") == root_stat.st_dev
                and marker.get("root_inode") == root_stat.st_ino, "fixture_owner_marker_mismatch")
        raftfd = directory("raft", rootfd)
        # Product-created descendants remain inside the already verified private
        # root/raft ancestors. Bind the exact observed modes; never chmod them.
        logfd = directory("log", raftfd, log_directory_mode)
        checkpointfd, checkpoint_size = file("raft-log.bin", logfd, MAX_FILE, log_file_mode)
        journalfd, journal_size = file("raft-log.journal", logfd, MAX_FILE, log_file_mode)
        checkpoint = read_fd(checkpointfd, checkpoint_size, until)
        journal = read_fd(journalfd, journal_size, until)
        projection = project(checkpoint, journal, until)
        facts = []
        content = [marker_raw, checkpoint, journal]
        for (fd, parent, name, before), raw in zip(opened, content):
            after = identity(os.fstat(fd))
            named = identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
            require(before == after == named, "file_identity_changed")
            facts.append({"relative_file": name, "before": before, "after": after,
                          "sha256": hashlib.sha256(raw).hexdigest()})
        directories = []
        for fd, parent, name, before in directory_facts:
            after = identity(os.fstat(fd))
            named_info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            named = identity(named_info)
            require(stat.S_ISDIR(named_info.st_mode) and before == after == named,
                    "directory_identity_changed")
            directories.append({"directory": name, "before": before, "after": after,
                                "named_after": named})
        require(root.stat().st_dev == root_stat.st_dev and root.stat().st_ino == root_stat.st_ino
                and root.resolve(strict=True) == root, "root_identity_changed")
        within(until)
        return {"node_id": node, "fixed_root": raw_root, "directories": directories,
                "files": facts, "numeric_projection": projection}
    finally:
        close_failed = False
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except OSError:
                close_failed = True
        if close_failed:
            raise Refused("descriptor_close_failed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", type=int, choices=sorted(ROOTS), required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--max-seconds", type=float, required=True)
    args = parser.parse_args()
    if (len(args.run_id) != 32 or any(c not in "0123456789abcdef" for c in args.run_id)
            or not 0 < args.max_seconds <= SECONDS):
        parser.error("invalid_fixed_fixture_read_binding")
    started = time.monotonic()
    until = started + args.max_seconds
    result = {
        "schema": "heptabao.direction-r3-stopped-node-numeric-observer.v1",
        "fixture_run_id": args.run_id, "baseline_direction_failure_sha256": BASELINE_FAILURE_SHA,
        "scope": "readonly after this fixed node owned stop; current persisted state, not historical live metrics",
        "new_observer_deadline_seconds": args.max_seconds, "new_max_bytes_per_log_file": MAX_FILE,
        "child_processes": 0, "file_writes": 0, "product_requests": 0,
        "ciphertext_or_state_machine_files_opened": False,
        "production_authority": False, "status": "failed",
    }
    rc = 1
    try:
        result["observation"] = execute(args.node, until, args.run_id)
        within(until)
        result["status"] = "completed"
        rc = 0
    except Refused as error:
        result["failure_code"] = str(error)
    except BaseException as error:
        result["failure_type"] = type(error).__name__
    result["elapsed_seconds"] = time.monotonic() - started
    result["publication_within_original_observer_deadline"] = time.monotonic() < until
    if not result["publication_within_original_observer_deadline"]:
        result["status"] = "failed"
        result["failure_code"] = "original_read_deadline_expired"
        rc = 1
    output = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    if len(output.encode()) > 65536:
        output = json.dumps({"schema": result["schema"], "status": "failed",
                             "failure_code": "public_output_bound", "file_writes": 0,
                             "product_requests": 0}) + "\n"
        rc = 1
    sys.stdout.write(output)
    sys.stdout.flush()
    # Authority exit 0 also proves publication finished within the same bound.
    return rc if time.monotonic() < until else 1


if __name__ == "__main__":
    raise SystemExit(main())
