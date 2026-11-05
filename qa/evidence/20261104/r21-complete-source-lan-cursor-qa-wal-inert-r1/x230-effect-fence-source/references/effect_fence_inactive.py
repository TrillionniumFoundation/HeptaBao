#!/usr/bin/env python3
"""Inactive, source-only proposal: reserve one exact old relay name; never replay."""
import errno
import hashlib
import json
import os
import signal
import stat
import sys
import time

BASE = "/home/qian-qi/heptabao-ha-closure-20261103-r1"
CONTROLS = BASE + "/normal-cold-h2-x230-transfer-controls-r1"
ROOT_NAME = "normal-cold-h2-x230-transfer-r1"
TOMBSTONE_NAME = "relay-effect-fence.public.json"
ORIGINAL_JOB = "1a1aa57458d-fc05-4156"
ORIGINAL_KEY = "heptabao-df026-x230-source-artifacts-relay-r1-732fa7e7"
ORIGINAL_REQUEST_SHA256 = "2243e731b0878b8a0ba724674371a541fc89142ee59af80da5535f18262dc280"
ORIGINAL_REQUEST_DIGEST = "aaec19b4b6de67f3cf58d898ee388396d73f4b3409fbba972df5f2de3f5f2b47"
BINDING_READY = False
METADATA_EVIDENCE_SHA256 = "da22041ad211aadaedf50655aff25284c3f361020a15416ee4e065c7a9d4a088"
EXPECTED_DIRECTORIES = {
    "/": [2050, 2, 0, 0, 16877, 26, 4096, 1792626742716890237, 1792626742716890237],
    "/home": [2050, 49807361, 0, 0, 16877, 4, 4096, 1783933443288708081, 1783933443288708081],
    "/home/qian-qi": [2050, 49938433, 1000, 1000, 16872, 605, 147456, 1793857598066648108, 1793857598066648108],
    "/home/qian-qi/heptabao-ha-closure-20261103-r1": [2050, 52559902, 1000, 1000, 16832, 194, 20480, 1793858713862347110, 1793858713862347110],
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-cold-h2-x230-transfer-controls-r1": [2050, 7241098, 1000, 1000, 16832, 2, 4096, 1793858714901317289, 1793858714901317289],
}
EXPECTED_CONTROLS = {
    "sender.py": {"bytes": 8862, "sha256": "c649d82d09c52519a4b6f240ecd02d987941ad8bb8ab3f74f490afa9301fd742", "blob": "5fe51ddedcfe02f5e1b69714e6de8fe61dff9ab4",
        "identity": [2050, 7241099, 1000, 1000, 33152, 1, 8862, 1793858713962971085, 1793858714190585728]},
    "receiver.py": {"bytes": 29900, "sha256": "fefacf7be6b9785e4be7de94584ec60245ddec87573f6404739730b97546275d", "blob": "4a302b89c1de1473844b4e364cb44e51d1310a1a",
        "identity": [2050, 7241100, 1000, 1000, 33152, 1, 29900, 1793858714295334682, 1793858714469539590]},
    "relay.py": {"bytes": 21085, "sha256": "732fa7e74d859c48cd3844967409254e6f7cd44d4ceb148a20d2ea89ed07388f", "blob": "b076da8a629694e0dc988c57c13e03fa1b2ec548",
        "identity": [2050, 7241101, 1000, 1000, 33152, 1, 21085, 1793858714562990517, 1793858714706622260]},
}
SOFT_SECONDS = 15
READ_CAP = 131072
TOMBSTONE_CAP = 8192
OUTPUT_CAP = 32768
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

class Refused(Exception):
    pass

def identity(s):
    return [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]

def require_invocation():
    if not (len(sys.argv) == 2 and sys.argv[0] == "-c"
            and len(sys.orig_argv) == 7
            and sys.orig_argv[0] == "/usr/bin/python3"
            and sys.orig_argv[1:5] == ["-I", "-S", "-B", "-c"]
            and sys.orig_argv[6] == sys.argv[1]
            and len(sys.argv[1]) == 64
            and all(c in "0123456789abcdef" for c in sys.argv[1])
            and hashlib.sha256(sys.orig_argv[5].encode("utf-8")).hexdigest()
                == sys.argv[1]):
        raise Refused("exact_code_and_argv_required")
    return sys.argv[1]


class Fence:
    def __init__(self):
        self.start_ns = time.monotonic_ns()
        self.until_ns = self.start_ns + SOFT_SECONDS * 1000000000
        self.phase = "entry"
        self.pending_signal = None
        self.ledger = []
        self.nodes = []
        self.metadata_calls = 0
        self.bytes_read = 0
        self.mkdir_attempted = False
        self.mkdir_returned_success = False
        self.parent_entry_fsynced = False
        self.tombstone_create_attempted = False
        self.tombstone_fsynced = False
        self.directory_fsynced = False
        self.absence_observation = None

    def handle_signal(self, sig, _frame):
        self.pending_signal = sig

    def check(self):
        if self.pending_signal is not None:
            raise Refused("signal_received")
        if time.monotonic_ns() >= self.until_ns:
            raise Refused("original_fifteen_second_deadline")

    def observe(self, fn):
        self.check()
        self.metadata_calls += 1
        if self.metadata_calls > 128:
            raise Refused("fixed_metadata_bound")
        value = fn()
        self.check()
        return value

    def open_fd(self, label, fn):
        self.check()
        row = {"label": label, "fd": None, "open_attempted": False,
               "opened": False, "close_attempted": False, "closed": False,
               "close_error_type": None, "close_errno": None}
        self.ledger.append(row)
        if len(self.ledger) > 10:
            raise Refused("fixed_descriptor_bound")
        row["open_attempted"] = True
        row["fd"] = fn()
        row["opened"] = True
        self.check()
        return row["fd"]

    def bind(self, path, name, parent_fd, directory, expected):
        self.phase = "bind_fixed_directory" if directory else "bind_public_source"
        before = self.observe(lambda: os.stat(name, dir_fd=parent_fd,
                                              follow_symlinks=False))
        if identity(before) != expected:
            raise Refused("fixed_identity_mismatch")
        if directory:
            if not stat.S_ISDIR(before.st_mode):
                raise Refused("fixed_directory_type")
        elif not (stat.S_ISREG(before.st_mode) and before.st_uid == 1000
                  and before.st_gid == 1000 and before.st_nlink == 1
                  and stat.S_IMODE(before.st_mode) == 0o600):
            raise Refused("fixed_source_type_owner_mode")
        fd = self.open_fd(path, lambda: os.open(
            name, DIR_FLAGS if directory else FILE_FLAGS, dir_fd=parent_fd))
        held = self.observe(lambda: os.fstat(fd))
        named = self.observe(lambda: os.stat(name, dir_fd=parent_fd,
                                             follow_symlinks=False))
        if identity(held) != expected or identity(named) != expected:
            raise Refused("opened_named_held_identity_mismatch")
        node = {"path": path, "name": name, "parent_fd": parent_fd, "fd": fd,
                "identity_before": expected, "expected_current": expected,
                "directory": directory, "identity_after": None}
        self.nodes.append(node)
        return node

    def current_identity(self, node):
        held = self.observe(lambda: os.fstat(node["fd"]))
        named = self.observe(lambda: os.stat(node["name"],
            dir_fd=node["parent_fd"], follow_symlinks=False))
        if identity(held) != identity(named):
            raise Refused("current_named_held_identity_mismatch")
        return identity(held)

    def verify_nodes(self):
        self.phase = "verify_fixed_named_held"
        for node in self.nodes:
            actual = self.current_identity(node)
            if actual != node["expected_current"]:
                raise Refused("fixed_identity_changed")
            node["identity_after"] = actual

    def read_source(self, node, expected):
        self.phase = "read_exact_public_source"
        if self.current_identity(node) != expected["identity"]:
            raise Refused("source_identity_before_read")
        self.check()
        os.lseek(node["fd"], 0, os.SEEK_SET)
        self.check()
        chunks = []
        count = 0
        while True:
            self.check()
            part = os.read(node["fd"], min(65536, expected["bytes"] + 1 - count))
            self.bytes_read += len(part)
            self.check()
            if self.bytes_read > READ_CAP:
                raise Refused("fixed_total_public_read_cap")
            if not part:
                break
            chunks.append(part)
            count += len(part)
            if count > expected["bytes"]:
                raise Refused("fixed_source_size")
        raw = b"".join(chunks)
        if count != expected["bytes"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
            raise Refused("fixed_source_whole_hash")
        if hashlib.sha1(("blob " + str(count) + "\0").encode() + raw).hexdigest() != expected["blob"]:
            raise Refused("fixed_source_git_blob")
        if self.current_identity(node) != expected["identity"]:
            raise Refused("source_identity_after_read")
        return {"path": node["path"], "bytes": count,
                "sha256": expected["sha256"], "blob": expected["blob"],
                "identity": expected["identity"]}

    def reserve(self, parent):
        self.phase = "held_parent_absence"
        self.check()
        try:
            self.observe(lambda: os.stat(ROOT_NAME, dir_fd=parent["fd"],
                                        follow_symlinks=False))
        except FileNotFoundError as error:
            if error.errno != errno.ENOENT:
                raise
            self.absence_observation = "absent"
        else:
            self.absence_observation = "present"
            raise Refused("existing_root_no_modification")
        self.phase = "atomic_mkdir_once"
        self.check()
        self.mkdir_attempted = True
        os.mkdir(ROOT_NAME, 0o700, dir_fd=parent["fd"])
        self.mkdir_returned_success = True
        self.check()
        os.fsync(parent["fd"])
        self.parent_entry_fsynced = True
        self.check()
        current_parent = self.current_identity(parent)
        if current_parent[:5] != parent["identity_before"][:5]:
            raise Refused("parent_identity_changed_beyond_owned_entry")
        parent["expected_current"] = current_parent
        self.phase = "hold_new_reservation"
        before = self.observe(lambda: os.stat(ROOT_NAME, dir_fd=parent["fd"],
                                              follow_symlinks=False))
        if not (stat.S_ISDIR(before.st_mode) and before.st_uid == 1000
                and before.st_gid == 1000 and stat.S_IMODE(before.st_mode) == 0o700):
            raise Refused("new_reservation_owner_mode")
        root_fd = self.open_fd(BASE + "/" + ROOT_NAME, lambda: os.open(
            ROOT_NAME, DIR_FLAGS, dir_fd=parent["fd"]))
        held = self.observe(lambda: os.fstat(root_fd))
        named = self.observe(lambda: os.stat(ROOT_NAME, dir_fd=parent["fd"],
                                             follow_symlinks=False))
        root_id = identity(before)
        if root_id != identity(held) or root_id != identity(named):
            raise Refused("new_reservation_named_held")
        node = {"path": BASE + "/" + ROOT_NAME, "name": ROOT_NAME,
                "parent_fd": parent["fd"], "fd": root_fd,
                "identity_before": root_id, "expected_current": root_id,
                "directory": True, "identity_after": None}
        self.nodes.append(node)
        return node

    def publish(self, root, raw):
        if not self.mkdir_returned_success or not self.parent_entry_fsynced:
            raise Refused("reservation_must_precede_tombstone")
        if len(raw) > TOMBSTONE_CAP:
            raise Refused("fixed_tombstone_cap")
        self.phase = "tombstone_create_once"
        self.check()
        self.tombstone_create_attempted = True
        fd = self.open_fd(root["path"] + "/" + TOMBSTONE_NAME, lambda: os.open(
            TOMBSTONE_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=root["fd"]))
        offset = 0
        while offset < len(raw):
            self.check()
            written = os.write(fd, raw[offset:])
            self.check()
            if written <= 0:
                raise Refused("tombstone_write_progress")
            offset += written
        os.fsync(fd)
        self.tombstone_fsynced = True
        self.check()
        before = self.observe(lambda: os.fstat(fd))
        if not (stat.S_ISREG(before.st_mode) and before.st_uid == 1000
                and before.st_gid == 1000 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_size == len(raw)):
            raise Refused("tombstone_file_identity")
        self.check()
        os.lseek(fd, 0, os.SEEK_SET)
        readback = bytearray()
        while True:
            self.check()
            part = os.read(fd, min(8192, len(raw) + 1 - len(readback)))
            self.bytes_read += len(part)
            self.check()
            if self.bytes_read > READ_CAP:
                raise Refused("fixed_total_public_read_cap")
            if not part:
                break
            readback.extend(part)
            if len(readback) > len(raw):
                raise Refused("tombstone_readback_size")
        if bytes(readback) != raw:
            raise Refused("tombstone_same_fd_readback")
        after = self.observe(lambda: os.fstat(fd))
        named = self.observe(lambda: os.stat(TOMBSTONE_NAME, dir_fd=root["fd"],
                                             follow_symlinks=False))
        if identity(before) != identity(after) or identity(before) != identity(named):
            raise Refused("tombstone_named_held_changed")
        self.nodes.append({
            "path": root["path"] + "/" + TOMBSTONE_NAME, "name": TOMBSTONE_NAME,
            "parent_fd": root["fd"], "fd": fd, "identity_before": identity(before),
            "expected_current": identity(before), "directory": False, "identity_after": None,
        })
        self.check()
        os.fsync(root["fd"])
        self.directory_fsynced = True
        self.check()
        current = self.current_identity(root)
        if current[:6] != root["identity_before"][:6]:
            raise Refused("reservation_changed_beyond_owned_file")
        root["expected_current"] = current
        return {"path": root["path"] + "/" + TOMBSTONE_NAME, "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "identity": identity(before), "same_fd_readback": True,
                "fsynced": True, "create_only": True}

    def close_all(self):
        self.phase = "descriptor_closure"
        for row in reversed(self.ledger):
            if row["fd"] is None or row["close_attempted"]:
                continue
            row["close_attempted"] = True
            try:
                os.close(row["fd"])
            except BaseException as error:
                row["close_error_type"] = type(error).__name__
                row["close_errno"] = getattr(error, "errno", None)
            else:
                row["closed"] = True
        return all(not row["opened"] or row["closed"] for row in self.ledger)

def validate_binding():
    if BINDING_READY is not True:
        raise Refused("actual_metadata_binding_unresolved")
    if not (isinstance(METADATA_EVIDENCE_SHA256, str)
            and len(METADATA_EVIDENCE_SHA256) == 64
            and all(c in "0123456789abcdef" for c in METADATA_EVIDENCE_SHA256)):
        raise Refused("metadata_evidence_pin")
    if set(EXPECTED_DIRECTORIES) != {"/", "/home", "/home/qian-qi", BASE, CONTROLS}:
        raise Refused("fixed_directory_set")
    for path, row in EXPECTED_DIRECTORIES.items():
        if not (isinstance(row, list) and len(row) == 9
                and all(type(x) is int for x in row) and stat.S_ISDIR(row[4])):
            raise Refused("fixed_directory_identity_shape")
        if row[4] & 0o022:
            raise Refused("writable_ancestor_or_controls")
        if path in (BASE, CONTROLS) and row[2] != 1000:
            raise Refused("fixed_owned_directory_uid")

def main():
    state = Fence()
    report = {"schema": "heptabao.x230-original-relay-effect-fence.v1",
              "status": "failed", "original_job": ORIGINAL_JOB,
              "original_key": ORIGINAL_KEY, "original_execution_state": "unknown",
              "source_sha256": None, "metadata_evidence_sha256": METADATA_EVIDENCE_SHA256,
              "soft_seconds": SOFT_SECONDS, "sources_before": [], "sources_after": [],
              "tombstone": None, "error": None, "transport_started": False,
              "children_started": 0, "network_started": False, "signals_sent": False,
              "old_root_or_existing_file_deleted_or_modified": False,
              "original_job_terminal_or_cleanup_proven": False}
    body_ok = False
    closed = False
    try:
        report["source_sha256"] = require_invocation()
        validate_binding()
        if os.getuid() != 1000 or os.getgid() != 1000:
            raise Refused("operator_uid_gid")
        os.umask(0o077)
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, state.handle_signal)
        slash = state.bind("/", "/", None, True, EXPECTED_DIRECTORIES["/"])
        home = state.bind("/home", "home", slash["fd"], True, EXPECTED_DIRECTORIES["/home"])
        user = state.bind("/home/qian-qi", "qian-qi", home["fd"], True,
                          EXPECTED_DIRECTORIES["/home/qian-qi"])
        parent = state.bind(BASE, "heptabao-ha-closure-20261103-r1", user["fd"], True,
                            EXPECTED_DIRECTORIES[BASE])
        control = state.bind(CONTROLS, "normal-cold-h2-x230-transfer-controls-r1",
                             parent["fd"], True, EXPECTED_DIRECTORIES[CONTROLS])
        sources = []
        for name, expected in EXPECTED_CONTROLS.items():
            node = state.bind(CONTROLS + "/" + name, name, control["fd"], False,
                              expected["identity"])
            sources.append((node, expected))
            report["sources_before"].append(state.read_source(node, expected))
        state.verify_nodes()
        root = state.reserve(parent)
        state.verify_nodes()
        tombstone = {
            "schema": "heptabao.x230-relay-future-effect-reservation.v1",
            "original_job": ORIGINAL_JOB, "original_key": ORIGINAL_KEY,
            "original_request_sha256": ORIGINAL_REQUEST_SHA256,
            "original_controller_request_digest": ORIGINAL_REQUEST_DIGEST,
            "original_execution_state": "unknown",
            "relay_source_sha256": EXPECTED_CONTROLS["relay.py"]["sha256"],
            "relay_source_blob": EXPECTED_CONTROLS["relay.py"]["blob"],
            "reservation_source_sha256": report["source_sha256"],
            "metadata_evidence_sha256": METADATA_EVIDENCE_SHA256,
            "fixed_root": root["path"], "root_identity_at_creation": root["identity_before"],
            "parent_identity_before": parent["identity_before"],
            "parent_identity_after_owned_mkdir": parent["expected_current"],
            "public_sources_verified_before_creation": report["sources_before"],
            "mkdir_returned_success": True,
            "scope": "prevent this exact relay from newly crossing mandatory ROOT.mkdir",
            "remaining_possible_effects": ["old Python process", "read-only finally ps", "worker logs"],
            "acceptance_requires": "new authoritative exit0/full durable result, final named/held source proof and all registered FD closure",
            "must_preserve_original_unknown": True,
        }
        raw = (json.dumps(tombstone, sort_keys=True) + "\n").encode("utf-8")
        report["tombstone"] = state.publish(root, raw)
        for node, expected in sources:
            report["sources_after"].append(state.read_source(node, expected))
        state.verify_nodes()
        if report["sources_before"] != report["sources_after"]:
            raise Refused("public_source_before_after_changed")
        state.check()
        body_ok = True
    except BaseException as error:
        report["error"] = {"phase": state.phase, "type": type(error).__name__,
                          "errno": getattr(error, "errno", None),
                          "reason": str(error) if isinstance(error, Refused) else None}
    finally:
        closed = state.close_all()
        elapsed = time.monotonic_ns() - state.start_ns
        report.update({
            "descriptors": state.ledger, "all_registered_descriptors_closed": closed,
            "unknown_descriptor_closure": not closed, "metadata_calls": state.metadata_calls,
            "bytes_read": state.bytes_read, "mkdir_attempted": state.mkdir_attempted,
            "mkdir_returned_success": state.mkdir_returned_success,
            "parent_entry_fsynced": state.parent_entry_fsynced,
            "tombstone_create_attempted": state.tombstone_create_attempted,
            "tombstone_fsynced": state.tombstone_fsynced,
            "directory_fsynced": state.directory_fsynced,
            "absence_observation": state.absence_observation,
            "pending_signal": state.pending_signal,
            "body_and_cleanup_elapsed_ns": elapsed,
            "body_and_cleanup_within_original_deadline": elapsed < SOFT_SECONDS * 1000000000,
            "nodes": [{k: v for k, v in node.items() if k not in ("fd", "parent_fd")}
                      for node in state.nodes],
        })
        ready = (body_ok and closed and state.pending_signal is None
                 and elapsed < SOFT_SECONDS * 1000000000)
        report["status"] = "effect_fence_published" if ready else "failed"
    encoded = (json.dumps(report, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > OUTPUT_CAP:
        return 1
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0 if (ready and state.pending_signal is None
                 and time.monotonic_ns() < state.until_ns) else 1

if __name__ == "__main__":
    sys.exit(main())
