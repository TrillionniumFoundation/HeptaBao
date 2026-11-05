"""SOURCE ONLY: fixed failed QA artifact alias observation, no execution/write.

This reads the one Cargo-declared R2 executable and only matching QA binary
names under its fixed release/deps directory. Both actual hardlink pathnames
must account for the observed link count. No Cargo command, product request,
binary execution, chmod, link, rename, unlink, or retained-copy write occurs.
The 15-second bound is a soft whole-read deadline; outer supervision is a
separately reviewed 45-second proposal. Expired/unclean observations fail.
"""
import hashlib
import json
import os
import re
import signal
import stat
import sys
import time

TARGET = "/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/target-normal-r3"
PRIMARY = TARGET + "/release/heptabao-native-h2-qa"
TARGET_IDENTITY = (66306, 31606588, 1000, 1000, 0o700)
EXPECTED_VERSION = "66306:31633993:4616576:1793869496670294192:1793869496695294129"
EXPECTED_SHA256 = "1f1c6eccf1ac9652a69572cb270b1d3d99a3402eaabf6d7feed6e4b2c4d55b13"
EXPECTED_BYTES = 4616576
EXPECTED_NLINK = 2
EXPECTED_MODE = 0o700
MAX_NAMES = 16384
MAX_NAME_BYTES = 1048576
MAX_QA_NAMES = 32
ALIAS_NAME = re.compile(r"heptabao[-_]native[-_]h2[-_]qa-[0-9a-f]{16}\Z")
BUDGET_NS = 15_000_000_000
MAX_BODY_BYTES = EXPECTED_BYTES * EXPECTED_NLINK
MAX_EOF_PROBE_BYTES = EXPECTED_NLINK
MAX_RETURNED_BYTES = MAX_BODY_BYTES + MAX_EOF_PROBE_BYTES


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def full_id(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
            value.st_mode, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def dir_id(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
            stat.S_IMODE(value.st_mode))


def version(value):
    return ":".join(str(x) for x in (
        value.st_dev, value.st_ino, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Cancelled(BaseException):
    pass

class Signals:
    def __init__(self):
        self.protected = 0
        self.pending = None

    def handler(self, signum, _frame):
        if self.pending is None:
            self.pending = signum
        if not self.protected:
            raise Cancelled()

    def install(self):
        signal.signal(signal.SIGTERM, self.handler)
        signal.signal(signal.SIGINT, self.handler)

    def check(self):
        if self.pending is not None:
            raise Cancelled()

def protected_call(method):
    def call(self, *args, **kwargs):
        self.signals.protected += 1
        try:
            return method(self, *args, **kwargs)
        finally:
            self.signals.protected -= 1
    return call

def public_errno(error):
    value = getattr(error, "errno", None)
    return value if type(value) is int and 0 < value < 4096 else None


class Observation:
    def __init__(self, signals=None):
        self.signals = Signals() if signals is None else signals
        self.started = time.monotonic_ns()
        self.until = self.started + BUDGET_NS
        self.fds = {}
        self.fd_rows = []
        self.open_registration_unknown = False
        self.opened = 0
        self.closed = 0
        self.close_failures = 0
        self.dirs = []
        self.scandir_closed = False
        self.scandir_object = None
        self.scandir_open_unknown = False
        self.scandir_created = False
        self.scandir_close_attempted = False
        self.scandir_close_error = None
        self.bytes_read = 0
        self.body_bytes_read = 0
        self.eof_bytes_read = 0
        self.eof_probe_calls = 0

    def remaining(self):
        self.signals.check()
        need(time.monotonic_ns() < self.until, "original_read_deadline")

    @protected_call
    def open_fd(self, path, flags, role, parent=None):
        self.remaining()
        # A non-OSError before registration completes is explicitly unknown.
        # This flag is never used to infer that an unregistered FD was closed.
        self.open_registration_unknown = True
        try:
            fd = os.open(path, flags, dir_fd=parent)
        except OSError:
            self.open_registration_unknown = False
            raise
        row = {"ordinal": len(self.fd_rows) + 1, "role": role,
               "close_attempted": False, "closed": False,
               "close_errno": None, "close_error": None}
        self.fds[fd] = row
        self.fd_rows.append(row)
        self.opened += 1
        self.open_registration_unknown = False
        return fd

    @protected_call
    def close_once(self, fd):
        if fd not in self.fds:
            return
        row = self.fds.pop(fd)
        row["close_attempted"] = True
        try:
            os.close(fd)
        except BaseException as error:
            row["close_error"] = "close_not_confirmed"
            row["close_errno"] = public_errno(error)
            self.close_failures += 1
            raise
        else:
            row["closed"] = True
            self.closed += 1

    @protected_call
    def close_scandir_once(self):
        if not self.scandir_created or self.scandir_close_attempted:
            return
        self.scandir_close_attempted = True
        try:
            self.scandir_object.close()
        except BaseException as error:
            self.scandir_close_error = {
                "code": "scandir_close_not_confirmed",
                "errno": public_errno(error)}
            raise
        else:
            self.scandir_closed = True

    @protected_call
    def close_all_once(self):
        try:
            self.close_scandir_once()
        except BaseException:
            pass
        for fd in list(self.fds)[::-1]:
            try:
                self.close_once(fd)
            except BaseException:
                # No second close of an uncertain descriptor number.
                pass

    def closures_proven(self):
        return (
            not self.open_registration_unknown and not self.scandir_open_unknown
            and not self.close_failures and not self.fds
            and self.opened == self.closed == len(self.fd_rows)
            and all(row["close_attempted"] and row["closed"]
                    and row["close_error"] is None for row in self.fd_rows)
            and (not self.scandir_created or
                 (self.scandir_close_attempted and self.scandir_closed
                  and self.scandir_close_error is None)))

    def check_dir(self, value):
        need(stat.S_ISDIR(value.st_mode)
             and value.st_uid in (0, os.geteuid())
             and not stat.S_IMODE(value.st_mode) & 0o002,
             "unsafe_directory")

    def open_dirs(self):
        need(os.geteuid() == 1000, "operator_uid")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        self.remaining()
        root = self.open_fd("/", flags, "ancestor")
        captured = os.fstat(root)
        self.check_dir(captured)
        self.dirs.append((None, "/", root, dir_id(captured)))
        parent = root
        target_fd = None
        parts = (TARGET + "/release/deps").lstrip("/").split("/")
        for index, name in enumerate(parts):
            self.remaining()
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            self.check_dir(before)
            fd = self.open_fd(name, flags, "ancestor", parent)
            held = os.fstat(fd)
            self.check_dir(held)
            need(dir_id(held) == dir_id(before)
                 and dir_id(os.stat(name, dir_fd=parent,
                                    follow_symlinks=False)) == dir_id(before),
                 "directory_open_identity")
            self.dirs.append((parent, name, fd, dir_id(before)))
            if index == len(parts) - 3:
                target_fd = fd
                need(dir_id(held) == TARGET_IDENTITY, "exact_target_identity")
            parent = fd
        need(target_fd is not None, "target_fd_missing")
        return self.dirs[-2][2], self.dirs[-1][2]

    def verify_dirs(self):
        for parent, name, fd, captured in self.dirs:
            self.remaining()
            held = os.fstat(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            self.check_dir(held)
            self.check_dir(named)
            need(dir_id(held) == captured and dir_id(named) == captured,
                 "directory_named_identity")

    def checked_file(self, parent, name, expected_identity=None):
        self.remaining()
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 1000
             and before.st_gid == 1000 and before.st_nlink == EXPECTED_NLINK
             and stat.S_IMODE(before.st_mode) == EXPECTED_MODE
             and before.st_size == EXPECTED_BYTES
             and version(before) == EXPECTED_VERSION,
             "exact_artifact_metadata")
        captured = full_id(before)
        if expected_identity is not None:
            need(captured == expected_identity, "alias_full_identity")
        fd = self.open_fd(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            "artifact", parent)
        need(full_id(os.fstat(fd)) == captured, "artifact_open_identity")
        return fd, captured

    @protected_call
    def hash_file(self, fd, parent, name, captured):
        self.remaining()
        need(self.body_bytes_read + EXPECTED_BYTES <= MAX_BODY_BYTES
             and self.bytes_read + EXPECTED_BYTES + 1 <= MAX_RETURNED_BYTES
             and self.eof_probe_calls < MAX_EOF_PROBE_BYTES,
             "whole_read_bytes_admission")
        digest = hashlib.sha256()
        left = EXPECTED_BYTES
        while left:
            self.remaining()
            count = min(65536, left, MAX_BODY_BYTES - self.body_bytes_read,
                        MAX_RETURNED_BYTES - self.bytes_read)
            need(count > 0, "whole_read_bytes_remaining")
            block = os.read(fd, count)
            self.body_bytes_read += len(block)
            self.bytes_read += len(block)
            need(self.body_bytes_read <= MAX_BODY_BYTES
                 and self.bytes_read <= MAX_RETURNED_BYTES,
                 "whole_read_bytes_bound")
            need(0 < len(block) <= count, "artifact_short_or_oversized_read")
            left -= len(block)
            digest.update(block)
        self.remaining()
        need(self.eof_probe_calls < MAX_EOF_PROBE_BYTES
             and self.eof_bytes_read + 1 <= MAX_EOF_PROBE_BYTES
             and self.bytes_read + 1 <= MAX_RETURNED_BYTES,
             "eof_probe_bytes_admission")
        self.eof_probe_calls += 1
        tail = os.read(fd, 1)
        self.eof_bytes_read += len(tail)
        self.bytes_read += len(tail)
        need(self.eof_bytes_read <= MAX_EOF_PROBE_BYTES
             and self.bytes_read <= MAX_RETURNED_BYTES,
             "whole_read_bytes_bound")
        need(tail == b"", "artifact_trailing_bytes")
        self.remaining()
        need(full_id(os.fstat(fd)) == captured
             and full_id(os.stat(name, dir_fd=parent,
                                 follow_symlinks=False)) == captured,
             "artifact_hash_final_identity")
        actual = digest.hexdigest()
        need(actual == EXPECTED_SHA256, "artifact_whole_sha256")
        return actual

    @protected_call
    def find_alias(self, deps, captured):
        self.remaining()
        names_seen = 0
        name_bytes = 0
        candidates = []
        self.scandir_open_unknown = True
        self.scandir_object = os.scandir(deps)
        self.scandir_created = True
        self.scandir_open_unknown = False
        try:
            for entry in self.scandir_object:
                self.remaining()
                names_seen += 1
                name_bytes += len(os.fsencode(entry.name))
                need(names_seen <= MAX_NAMES and name_bytes <= MAX_NAME_BYTES,
                     "directory_names_bound")
                if ALIAS_NAME.fullmatch(entry.name):
                    candidates.append(entry.name)
                    need(len(candidates) <= MAX_QA_NAMES, "qa_names_bound")
        finally:
            self.close_scandir_once()
        self.remaining()
        matches = []
        for name in sorted(candidates):
            self.remaining()
            value = os.stat(name, dir_fd=deps, follow_symlinks=False)
            if (value.st_dev, value.st_ino) == captured[:2]:
                need(full_id(value) == captured, "alias_census_identity")
                matches.append(name)
        need(len(matches) + 1 == EXPECTED_NLINK,
             "link_count_not_fully_accounted_for")
        return matches[0], names_seen, name_bytes, len(candidates)


def main():
    signals = Signals()
    observation = Observation(signals)
    result = {
        "schema": "heptabao.qa-r2.fixed-cargo-alias-observation.v2",
        "status": "failed", "aliases": [], "binary_executions": 0,
        "child_starts": 0, "file_writes": 0, "network_requests": 0,
        "original_qa_r2_result_remains_failed": True,
    }
    error = None
    # Protect the complete resource lifetime before installing the handlers.
    # remaining() responds to pending cancellation; a later signal cannot
    # escape entry to the one cleanup attempt.
    signals.protected += 1
    try:
        signals.install()
        need(len(sys.argv) == 2 and re.fullmatch(r"[0-9a-f]{64}", sys.argv[1]),
             "argv_contract")
        original = sys.orig_argv
        need(original.count("-c") == 1, "source_argument")
        index = original.index("-c")
        need(index + 1 < len(original)
             and sha(original[index + 1].encode()) == sys.argv[1],
             "source_sha256")
        result["source_sha256"] = sys.argv[1]
        release, deps = observation.open_dirs()
        primary_name = "heptabao-native-h2-qa"
        primary_fd, captured = observation.checked_file(release, primary_name)
        alias, seen, name_bytes, candidates = observation.find_alias(deps, captured)
        alias_fd, alias_identity = observation.checked_file(deps, alias, captured)
        primary_sha = observation.hash_file(
            primary_fd, release, primary_name, captured)
        alias_sha = observation.hash_file(alias_fd, deps, alias, alias_identity)
        observation.verify_dirs()
        for fd, parent, name in (
                (primary_fd, release, primary_name), (alias_fd, deps, alias)):
            need(full_id(os.fstat(fd)) == captured
                 and full_id(os.stat(name, dir_fd=parent,
                                     follow_symlinks=False)) == captured,
                 "final_alias_set_identity")
        observation.remaining()
        result.update({
            "status": "observed_fixed_two_aliases",
            "expected_link_count": EXPECTED_NLINK,
            "full_identity": [str(x) for x in captured],
            "primary_version": EXPECTED_VERSION,
            "aliases": [
                {"path": PRIMARY, "bytes": EXPECTED_BYTES, "sha256": primary_sha},
                {"path": TARGET + "/release/deps/" + alias,
                 "bytes": EXPECTED_BYTES, "sha256": alias_sha},
            ],
            "directory_entries_seen": seen, "directory_name_bytes": name_bytes,
            "qa_prefix_candidates": candidates,
            "same_full_identity": True,
            "link_count_fully_accounted_for": True,
        })
    except Cancelled:
        error = {"code": "cancelled"}
    except Refused as failure:
        error = {"code": str(failure)}
    except OSError as failure:
        error = {"code": "os_error", "errno": public_errno(failure)}
    except BaseException:
        error = {"code": "unexpected_observation_error"}
    finally:
        try:
            observation.close_all_once()
        finally:
            signals.protected -= 1
    completed = time.monotonic_ns()
    closures = observation.closures_proven()
    result.update({
        "elapsed_after_closure_ns": completed - observation.started,
        "within_original_read_deadline_after_closure": completed < observation.until,
        "fds_opened": observation.opened, "fds_closed_once": observation.closed,
        "fd_close_failures": observation.close_failures,
        "fds_remaining": len(observation.fds),
        "fd_closure_rows": observation.fd_rows,
        "open_registration_unknown": observation.open_registration_unknown,
        "iterator_created": observation.scandir_created,
        "iterator_close_attempted": observation.scandir_close_attempted,
        "iterator_closed_once": observation.scandir_closed,
        "iterator_close_error": observation.scandir_close_error,
        "iterator_open_unknown": observation.scandir_open_unknown,
        "all_registered_resources_closed": closures,
        "resource_outcome_unknown": not closures,
        "cancel_signal": signals.pending,
        "body_bytes_read": observation.body_bytes_read,
        "body_bytes_limit": MAX_BODY_BYTES,
        "eof_probe_calls": observation.eof_probe_calls,
        "eof_probe_bytes_read": observation.eof_bytes_read,
        "eof_probe_bytes_limit": MAX_EOF_PROBE_BYTES,
        "bytes_read": observation.bytes_read,
        "total_returned_bytes_limit": MAX_RETURNED_BYTES, "error": error,
    })
    if (error is not None or not closures or signals.pending is not None
            or completed >= observation.until):
        result["status"] = "failed"
    signals.protected += 1
    try:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
        if time.monotonic_ns() >= observation.until or signals.pending is not None:
            return 1
        return 0 if result["status"] == "observed_fixed_two_aliases" else 1
    finally:
        signals.protected -= 1


if __name__ == "__main__":
    raise SystemExit(main())

