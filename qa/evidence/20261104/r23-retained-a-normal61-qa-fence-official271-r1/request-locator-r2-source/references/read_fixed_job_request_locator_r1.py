"""SOURCE ONLY: bounded fixed-request observation; never grants replay.

The public runtime source is a schema reference, not proof of deployed code.
A host-specific known request is checked before enumerating candidate names.
Only request.json is read. No stdin.bin, child, network, signal, or file write.
A match proves a stored request binding, not launch, execution, or termination.
A non-match never proves absence or permits replay. Directory membership is
not claimed to be a stable snapshot. New/unreadable entries fail this read.
"""
import hashlib
import json
import os
import re
import stat
import sys
import time

CONFIGS = json.loads(r'''{
  "desktop-fence": {
    "host": "desktop",
    "floor_unix_ms": 1793864424254,
    "anchor_job_id": "1a1aaa6db3e-fc05-45a6",
    "anchor_digest": "39297690cdf83252668d9aa1a0656dc677544816c8b6653513c15a4876a04486",
    "anchor_fields": {
      "executable": "/usr/bin/python3",
      "cwd": "/home/qian-qi/heptabao-ha-closure-20261103-r1",
      "args_count": 6,
      "args_json_sha256": "f30d8359ac3a48c8fdf7ff80cc66ba1bd687816abde3b07944af218b55a3a56d",
      "env": {},
      "timeout_seconds": 60,
      "nice": 0,
      "cpu_quota_percent": null,
      "memory_max_bytes": null,
      "has_stdin": false
    },
    "target_digest": "2cd54d3522e4fccfef1e26edd4e86f7908e08e9183e1bb2bfdd8caad83ee4bf5",
    "target_fields": {
      "executable": "/usr/bin/python3",
      "cwd": "/home/qian-qi/heptabao-ha-closure-20261103-r1",
      "args_count": 6,
      "args_json_sha256": "26f457b4bd7ed964c9a614cb21c575975d813637db0e9f442418d0efb9627e79",
      "env": {},
      "timeout_seconds": 60,
      "nice": 0,
      "cpu_quota_percent": null,
      "memory_max_bytes": null,
      "has_stdin": false
    }
  },
  "rog-source": {
    "host": "rog",
    "floor_unix_ms": 1793864424254,
    "anchor_job_id": "1a1aad691c1-fc05-47e5",
    "anchor_digest": "51752897890cc752bfa1819ce557ccb6eb293586681cc46b81200a368439f3ed",
    "anchor_fields": {
      "executable": "/usr/bin/python3",
      "cwd": "/home/qian-qi",
      "args_count": 5,
      "args_json_sha256": "a6517813a4abb8c0a0e49e67556e2586adb3a1cf82783476caefe9347bd1bae6",
      "env": {},
      "timeout_seconds": 60,
      "nice": 0,
      "cpu_quota_percent": null,
      "memory_max_bytes": null,
      "has_stdin": true
    },
    "target_digest": "bae96736cb7abc92a03e93f7e55f5c108a152dcf5f5aeb237643b935218df42b",
    "target_fields": {
      "executable": "/usr/bin/python3",
      "cwd": "/home/qian-qi",
      "args_count": 9,
      "args_json_sha256": "d5e91a7f658c471a263d009e12020ca9192fd68032bd92be5ba259f8216d8e18",
      "env": {},
      "timeout_seconds": 360,
      "nice": 0,
      "cpu_quota_percent": null,
      "memory_max_bytes": null,
      "has_stdin": true
    }
  }
}''')
JOBS_PARTS = ("home", "qian-qi", ".local", "state",
              "hepta-runtime-mac-worker", "jobs")
JOBS_PATH = "/" + "/".join(JOBS_PARTS)
BUDGET_NS = 15_000_000_000
MAX_NAMES = 16_384
MAX_NAME_BYTES = 1_048_576
MAX_CANDIDATES = 128
MAX_REQUEST_BYTES = 262_144
MAX_TOTAL_REQUEST_BYTES = 8_388_608
MAX_MATCHES = 8
MAX_JSON_NODES = 65_536
MAX_JSON_DEPTH = 64
JOB_NAME = re.compile(r"([0-9a-f]{1,32})-([0-9a-f]{1,8})-([0-9a-f]{1,16})\Z")


class Refused(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(value, code):
    if not value:
        raise Refused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def full_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_identity(info):
    # Directory mtime/ctime/nlink are not inventory-snapshot witnesses.
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def canonical_job_time(name):
    if type(name) is not str or len(name) > 58:
        return None
    match = JOB_NAME.fullmatch(name)
    if match is None:
        return None
    pieces = match.groups()
    if any(format(int(part, 16), "x") != part for part in pieces):
        return None
    return int(pieces[0], 16)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def constant(_value):
        raise Refused("non_finite_json")

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                       parse_constant=constant)
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        need(nodes <= MAX_JSON_NODES and depth <= MAX_JSON_DEPTH,
             "json_structure_bound")
        if type(item) is dict:
            need(all(type(key) is str for key in item), "json_key_type")
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
        else:
            need(type(item) in (str, int, bool, type(None)),
                 "json_value_type")
    need(type(value) is dict, "request_not_object")
    return value


def equal_typed(actual, expected):
    return type(actual) is type(expected) and actual == expected


def verify_request(value, job_id, digest, fields):
    need(type(value) is dict, "request_not_object")
    need(value.get("job_id") == job_id, "request_job_id")
    expected_dir = JOBS_PATH + "/" + job_id
    need(value.get("job_dir") == expected_dir, "request_job_directory")
    need(value.get("unit") == "hepta-runtime-job-" + job_id, "request_unit")
    need(value.get("request_digest") == digest, "request_digest")
    need(value.get("request_fingerprint") == digest, "request_fingerprint")
    for key in ("executable", "cwd", "env", "timeout_seconds", "nice",
                "cpu_quota_percent", "memory_max_bytes"):
        need(key in value and equal_typed(value[key], fields[key]),
             "request_typed_field")
    args = value.get("args")
    need(type(args) is list and len(args) == fields["args_count"]
         and all(type(arg) is str and "\x00" not in arg for arg in args),
         "request_args_shape")
    need(sha(encode(args)) == fields["args_json_sha256"], "request_args_hash")
    # The deployed known anchor must have this schema before candidate reads.
    # host/idempotency_key are absent in the reference launch request.
    need("host" not in value and "idempotency_key" not in value
         and "stdin" not in value, "request_schema_fields")
    if fields["has_stdin"]:
        need(value.get("stdin_path") == expected_dir + "/stdin.bin",
             "request_stdin_path")
    else:
        need("stdin_path" not in value, "unexpected_stdin_path")
    # Never open stdin_path. Its original complete value was included in the
    # independently reproduced request digest; this observer does not re-hash it.
    return True


class Reader:
    def __init__(self, start):
        self.start = start
        self.until = start + BUDGET_NS
        self.fds = {}
        self.close_failures = 0
        self.opened = 0
        self.closed = 0
        self.total_request_bytes = 0
        self.request_files_read = 0
        self.scandir_closed = False
        self.ancestor_pins = []

    def remaining(self):
        need(time.monotonic_ns() < self.until, "original_read_deadline")

    def register(self, fd, role):
        # os.open is immediately followed by registration; no child operations.
        self.fds[fd] = role
        self.opened += 1
        return fd

    def close_once(self, fd):
        if fd not in self.fds:
            return
        del self.fds[fd]
        try:
            os.close(fd)
        except BaseException:
            self.close_failures += 1
            raise
        else:
            self.closed += 1

    def close_all_once(self):
        for fd in list(self.fds)[::-1]:
            try:
                self.close_once(fd)
            except BaseException:
                # No second close of an uncertain descriptor number.
                pass

    def dir_check(self, info, private):
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid())
             and not stat.S_IMODE(info.st_mode) & 0o022
             and info.st_nlink > 0, "unsafe_directory")
        if private:
            need(info.st_uid == os.geteuid()
                 and stat.S_IMODE(info.st_mode) == 0o700,
                 "unsafe_private_directory")

    def compare_named_dir(self, parent, name, fd, captured, private):
        self.remaining()
        held = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        self.dir_check(held, private)
        self.dir_check(named, private)
        need(directory_identity(held) == captured
             and directory_identity(named) == captured, "directory_identity")

    def open_fixed_ancestors(self):
        self.remaining()
        need(os.geteuid() == 1000, "unexpected_operator_uid")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        root_fd = self.register(os.open("/", flags), "ancestor")
        root_stat = os.fstat(root_fd)
        self.dir_check(root_stat, False)
        root_identity = directory_identity(root_stat)
        self.ancestor_pins.append((None, "/", root_fd, root_identity, False))
        parent = root_fd
        for index, part in enumerate(JOBS_PARTS):
            self.remaining()
            private = index >= len(JOBS_PARTS) - 2
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            self.dir_check(before, private)
            fd = self.register(os.open(part, flags, dir_fd=parent), "ancestor")
            captured = directory_identity(before)
            self.compare_named_dir(parent, part, fd, captured, private)
            self.ancestor_pins.append((parent, part, fd, captured, private))
            parent = fd
        return parent

    def verify_ancestors(self):
        for parent, name, fd, captured, private in self.ancestor_pins:
            if parent is None:
                self.remaining()
                held = os.fstat(fd)
                named = os.stat("/", follow_symlinks=False)
                self.dir_check(held, False)
                self.dir_check(named, False)
                need(directory_identity(held) == captured
                     and directory_identity(named) == captured,
                     "root_directory_identity")
            else:
                self.compare_named_dir(parent, name, fd, captured, private)

    def read_request(self, jobs_fd, job_id, role):
        self.remaining()
        need(canonical_job_time(job_id) is not None, "noncanonical_job_id")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        before_dir = os.stat(job_id, dir_fd=jobs_fd, follow_symlinks=False)
        self.dir_check(before_dir, True)
        job_fd = self.register(os.open(job_id, flags, dir_fd=jobs_fd), role)
        file_fd = None
        try:
            captured_dir = directory_identity(before_dir)
            self.compare_named_dir(jobs_fd, job_id, job_fd, captured_dir, True)
            before = os.stat("request.json", dir_fd=job_fd,
                             follow_symlinks=False)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                 and before.st_nlink == 1
                 and stat.S_IMODE(before.st_mode) == 0o600
                 and 0 < before.st_size <= MAX_REQUEST_BYTES,
                 "unsafe_request_file")
            file_fd = self.register(
                os.open("request.json", os.O_RDONLY | os.O_NOFOLLOW
                        | os.O_CLOEXEC, dir_fd=job_fd), role)
            captured = full_identity(before)
            need(full_identity(os.fstat(file_fd)) == captured,
                 "request_open_identity")
            chunks = []
            left = before.st_size
            while left:
                self.remaining()
                block = os.read(file_fd, min(left, 65536))
                need(bool(block), "request_short_read")
                left -= len(block)
                self.total_request_bytes += len(block)
                need(self.total_request_bytes <= MAX_TOTAL_REQUEST_BYTES,
                     "total_request_bytes_bound")
                chunks.append(block)
            need(os.read(file_fd, 1) == b"", "request_trailing_bytes")
            self.remaining()
            need(full_identity(os.fstat(file_fd)) == captured
                 and full_identity(os.stat("request.json", dir_fd=job_fd,
                                           follow_symlinks=False)) == captured,
                 "request_final_identity")
            raw = b"".join(chunks)
            digest = sha(raw)
            value = strict_json(raw)
            self.remaining()
            self.compare_named_dir(jobs_fd, job_id, job_fd, captured_dir, True)
            self.verify_ancestors()
            self.request_files_read += 1
            return value, len(raw), digest
        finally:
            if file_fd is not None:
                self.close_once(file_fd)
            self.close_once(job_fd)

    def candidates(self, jobs_fd, floor):
        self.remaining()
        found = []
        count = 0
        name_bytes = 0
        with os.scandir(jobs_fd) as entries:
            for entry in entries:
                self.remaining()
                count += 1
                name_bytes += len(os.fsencode(entry.name))
                need(count <= MAX_NAMES and name_bytes <= MAX_NAME_BYTES,
                     "directory_names_bound")
                stamp = canonical_job_time(entry.name)
                if stamp is not None and stamp >= floor:
                    found.append((stamp, entry.name))
                    need(len(found) <= MAX_CANDIDATES,
                         "recent_candidates_bound")
        self.scandir_closed = True
        self.remaining()
        self.verify_ancestors()
        return [name for _stamp, name in sorted(found)], count, name_bytes


def main():
    start = time.monotonic_ns()
    reader = Reader(start)
    report = {
        "schema": "heptabao.fixed-worker-request-locator.v1",
        "status": "failed",
        "absence_proven": False,
        "replay_authorized": False,
        "job_execution_or_termination_proven": False,
        "complete_inventory_or_stable_membership_proven": False,
        "deployed_runtime_source_identity_proven": False,
        "stdin_content_rechecked": False,
        "matches": [],
    }
    failure = None
    try:
        need(len(sys.argv) == 5 and sys.argv[1] == "--scope"
             and sys.argv[3] == "--self-sha256", "argv_contract")
        scope = sys.argv[2]
        need(scope in CONFIGS, "scope_not_fixed")
        original = sys.orig_argv
        need(original.count("-c") == 1, "exact_source_argument")
        position = original.index("-c")
        need(position + 1 < len(original), "source_argument_missing")
        source = original[position + 1].encode("utf-8")
        need(re.fullmatch(r"[0-9a-f]{64}", sys.argv[4]) is not None
             and sha(source) == sys.argv[4], "source_hash")
        config = CONFIGS[scope]
        report["scope"] = scope
        report["configured_host"] = config["host"]
        report["source_sha256"] = sys.argv[4]
        report["floor_unix_ms"] = config["floor_unix_ms"]
        jobs_fd = reader.open_fixed_ancestors()
        anchor, size, digest = reader.read_request(
            jobs_fd, config["anchor_job_id"], "known_anchor")
        verify_request(anchor, config["anchor_job_id"], config["anchor_digest"],
                       config["anchor_fields"])
        report["known_anchor"] = {
            "job_id": config["anchor_job_id"],
            "request_digest": config["anchor_digest"],
            "request_file_bytes": size, "request_file_sha256": digest,
            "typed_fields_match": True,
        }
        del anchor
        names, count, name_bytes = reader.candidates(
            jobs_fd, config["floor_unix_ms"])
        report["directory_entries_observed"] = count
        report["directory_name_bytes_observed"] = name_bytes
        report["candidate_count"] = len(names)
        for name in names:
            reader.remaining()
            if name == config["anchor_job_id"]:
                continue
            value, size, digest = reader.read_request(jobs_fd, name, "candidate")
            if value.get("request_digest") == config["target_digest"]:
                verify_request(value, name, config["target_digest"],
                               config["target_fields"])
                report["matches"].append({
                    "job_id": name,
                    "request_digest": config["target_digest"],
                    "request_file_bytes": size,
                    "request_file_sha256": digest,
                })
                need(len(report["matches"]) <= MAX_MATCHES, "matches_bound")
            del value
        reader.verify_ancestors()
        reader.remaining()
        report["status"] = "bounded_read_completed"
    except Refused as error:
        failure = {"code": error.code}
    except OSError as error:
        failure = {"code": "os_error", "errno": error.errno}
    except (ValueError, UnicodeError, RecursionError):
        failure = {"code": "request_parse_error"}
    except BaseException:
        failure = {"code": "unexpected_reader_error"}
    finally:
        reader.close_all_once()
    completed = time.monotonic_ns()
    report["elapsed_after_closure_ns"] = completed - start
    report["within_original_deadline_after_closure"] = completed < reader.until
    report["fds_opened"] = reader.opened
    report["fds_closed_once"] = reader.closed
    report["fd_close_failures"] = reader.close_failures
    report["fds_remaining"] = len(reader.fds)
    report["scandir_closed"] = reader.scandir_closed
    report["request_files_read"] = reader.request_files_read
    report["request_bytes_read"] = reader.total_request_bytes
    if (failure is not None or reader.close_failures or reader.fds
            or completed >= reader.until):
        report["status"] = "failed"
    report["failure"] = failure
    # Publication is stdout only; a successful authority exit also requires the
    # post-flush check below. There is no reset of the original 15-second clock.
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)
    if time.monotonic_ns() >= reader.until:
        return 1
    return 0 if report["status"] == "bounded_read_completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

