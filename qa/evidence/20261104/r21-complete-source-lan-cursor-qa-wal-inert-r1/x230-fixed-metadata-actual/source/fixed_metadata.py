#!/usr/bin/env python3
"""Fixed public metadata only for the unknown X230 relay; no reservation is made."""
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
OLD_ROOT_NAME = "normal-cold-h2-x230-transfer-r1"
OLD_JOB = "1a1aa57458d-fc05-4156"
OLD_KEY = "heptabao-df026-x230-source-artifacts-relay-r1-732fa7e7"
OLD_REQUEST_SHA256 = "2243e731b0878b8a0ba724674371a541fc89142ee59af80da5535f18262dc280"
OLD_REQUEST_DIGEST = "aaec19b4b6de67f3cf58d898ee388396d73f4b3409fbba972df5f2de3f5f2b47"
SOFT_SECONDS = 5
OUTPUT_CAP = 32768
EXPECTED_FILES = {
    "sender.py": [2050, 7241099, 1000, 1000, 33152, 1, 8862,
                  1793858713962971085, 1793858714190585728],
    "receiver.py": [2050, 7241100, 1000, 1000, 33152, 1, 29900,
                    1793858714295334682, 1793858714469539590],
    "relay.py": [2050, 7241101, 1000, 1000, 33152, 1, 21085,
                 1793858714562990517, 1793858714706622260],
}
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

class Metadata:
    def __init__(self):
        self.started_ns = time.monotonic_ns()
        self.until_ns = self.started_ns + SOFT_SECONDS * 1000000000
        self.pending_signal = None
        self.phase = "entry"
        self.metadata_calls = 0
        self.ledger = []
        self.nodes = []
        self.absence = []

    def check(self):
        if self.pending_signal is not None:
            raise Refused("signal_received")
        if time.monotonic_ns() >= self.until_ns:
            raise Refused("original_five_second_deadline")

    def handle_signal(self, sig, _frame):
        self.pending_signal = sig

    def observe(self, fn):
        self.check()
        self.metadata_calls += 1
        if self.metadata_calls > 42:
            raise Refused("fixed_metadata_bound")
        value = fn()
        self.check()
        return value

    def open_fd(self, label, fn):
        self.check()
        row = {"label": label, "open_attempted": False, "opened": False,
               "fd": None, "close_attempted": False, "closed": False,
               "close_error_type": None, "close_errno": None}
        self.ledger.append(row)
        if len(self.ledger) > 8:
            raise Refused("fixed_descriptor_bound")
        row["open_attempted"] = True
        row["fd"] = fn()
        row["opened"] = True
        self.check()
        return row["fd"]

    def bind(self, path, name, parent_fd, directory, expected=None):
        self.phase = "bind_" + ("directory" if directory else "public_source")
        named = lambda: os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        before = self.observe(named)
        if directory:
            if not stat.S_ISDIR(before.st_mode):
                raise Refused("fixed_directory_type")
        elif not (stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                  and before.st_uid == 1000 and before.st_gid == 1000
                  and stat.S_IMODE(before.st_mode) == 0o600):
            raise Refused("fixed_public_source_type_owner_mode")
        flags = DIR_FLAGS if directory else FILE_FLAGS
        fd = self.open_fd(path, lambda: os.open(name, flags, dir_fd=parent_fd))
        opened = self.observe(lambda: os.fstat(fd))
        after = self.observe(named)
        actual = identity(before)
        if actual != identity(opened) or actual != identity(after):
            raise Refused("named_held_identity_changed")
        if path in (BASE, CONTROLS) and before.st_uid != 1000:
            raise Refused("fixed_owned_directory_uid")
        if expected is not None and actual != expected:
            raise Refused("published_source_metadata_changed")
        node = {"path": path, "name": name, "parent_fd": parent_fd, "fd": fd,
                "directory": directory, "identity_before": actual,
                "identity_after": None}
        self.nodes.append(node)
        return fd

    def absent_once(self, parent_fd, ordinal):
        self.phase = "original_root_absence_" + str(ordinal)
        row = {"ordinal": ordinal, "path": BASE + "/" + OLD_ROOT_NAME,
               "observation": "not_observed", "identity": None}
        self.absence.append(row)
        self.check()
        self.metadata_calls += 1
        if self.metadata_calls > 42:
            raise Refused("fixed_metadata_bound")
        try:
            current = os.stat(OLD_ROOT_NAME, dir_fd=parent_fd,
                              follow_symlinks=False)
        except FileNotFoundError as error:
            if error.errno != errno.ENOENT:
                raise
            row["observation"] = "absent"
        else:
            row["observation"] = "present"
            row["identity"] = identity(current)
            raise Refused("original_root_present")
        self.check()

    def verify_nodes(self):
        self.phase = "final_named_held_metadata"
        for node in self.nodes:
            held = self.observe(lambda n=node: os.fstat(n["fd"]))
            named = self.observe(lambda n=node: os.stat(
                n["name"], dir_fd=n["parent_fd"], follow_symlinks=False))
            after = identity(held)
            node["identity_after"] = after
            if after != node["identity_before"] or after != identity(named):
                raise Refused("final_named_held_identity_changed")

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

def main():
    state = Metadata()
    report = {
        "schema": "heptabao.x230-relay-fence-input-metadata.v1",
        "status": "failed", "source_sha256": None, "original_job": OLD_JOB,
        "original_key": OLD_KEY, "original_request_sha256": OLD_REQUEST_SHA256,
        "original_request_digest": OLD_REQUEST_DIGEST,
        "original_execution_state": "unknown",
        "soft_seconds": SOFT_SECONDS, "metadata_only": True,
        "file_body_bytes_read": 0, "directory_listing_performed": False,
        "filesystem_writes": 0, "children_started": 0,
        "network_started": False, "signals_sent": False,
        "fence_created": False, "absence_is_atomic_reservation": False,
        "error": None,
    }
    body_ok = False
    closed = False
    try:
        report["source_sha256"] = require_invocation()
        if os.getuid() != 1000 or os.getgid() != 1000:
            raise Refused("operator_uid_gid")
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, state.handle_signal)
        root = state.bind("/", "/", None, True)
        home = state.bind("/home", "home", root, True)
        user = state.bind("/home/qian-qi", "qian-qi", home, True)
        parent = state.bind(BASE, "heptabao-ha-closure-20261103-r1", user, True)
        controls = state.bind(CONTROLS, "normal-cold-h2-x230-transfer-controls-r1",
                              parent, True)
        state.absent_once(parent, 1)
        for name, expected in EXPECTED_FILES.items():
            state.bind(CONTROLS + "/" + name, name, controls, False, expected)
        state.verify_nodes()
        state.absent_once(parent, 2)
        state.check()
        body_ok = True
    except BaseException as error:
        report["error"] = {"phase": state.phase, "type": type(error).__name__,
                           "errno": getattr(error, "errno", None),
                           "reason": str(error) if isinstance(error, Refused) else None}
    finally:
        closed = state.close_all()
        report["descriptors"] = state.ledger
        report["all_registered_descriptors_closed"] = closed
        report["metadata_calls"] = state.metadata_calls
        report["maximum_registered_descriptors"] = len(state.ledger)
        report["nodes"] = [
            {key: value for key, value in n.items()
             if key not in ("fd", "parent_fd")}
            for n in state.nodes
        ]
        report["original_root_observations"] = state.absence
        report["pending_signal"] = state.pending_signal
        elapsed = time.monotonic_ns() - state.started_ns
        report["body_and_cleanup_elapsed_ns"] = elapsed
        report["body_and_cleanup_within_original_deadline"] = (
            elapsed < SOFT_SECONDS * 1000000000)
        report["unknown_descriptor_closure"] = not closed
        ready = (body_ok and closed and state.pending_signal is None
                 and elapsed < SOFT_SECONDS * 1000000000)
        report["status"] = "metadata_observed" if ready else "failed"
    raw = (json.dumps(report, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > OUTPUT_CAP:
        return 1
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    return 0 if (ready and state.pending_signal is None
                 and time.monotonic_ns() < state.until_ns) else 1

if __name__ == "__main__":
    sys.exit(main())
