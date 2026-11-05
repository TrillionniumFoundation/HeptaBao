"""One fixed stopped synthetic node log: public marker projection only."""
import hashlib
import json
import os
import re
import signal
import stat
import sys
import time

ROOT = "/home/qian-qi/heptabao-ha-closure-20261103-r1/r10-pocket3-mac1-postrecovery-cold-node2-r2"
LEAF = "process.log"
RUN_ID = "1d2269955b8e0cac332c40625057bb0f"
MAX_INPUT = 2 * 1024 * 1024
MAX_MARKERS = 128
MAX_OUTPUT = 65536
TOTAL_SECONDS = 15.0
PHASES = frozenset(["committed_changed_root_recover","committed_enrollment","committed_final_witness","committed_read_entry","committed_read_index","committed_same_root_reopen","install_detached_metadata","install_local_objects","install_local_root_cas","install_local_root_readback","install_locator_batches","install_post_cas_graph","install_pre_cas_graph","install_prepare_root_cas","install_published_local_plan","install_received_graph","install_root_binding","sync_after_migration","sync_changed_root_install","sync_current_local_finish","sync_current_local_graph","sync_current_local_graph_after_repair","sync_current_local_repair","sync_environment","sync_final_environment","sync_local_guard","sync_local_selection","sync_migration_source","sync_predecessor_read_boundary","sync_process_witness","sync_publish_local_state","sync_v5_source"])
CODES = frozenset(["changed_root_recover_refused","final_witness_refused","read_index_refused","same_root_reopen_refused","scope_not_completed"])
U128_MAX = (1 << 128) - 1
SYNC = re.compile(rb"HBHA-NATIVE-SYNC-FAIL step=([a-z0-9_]{1,64}) code=([a-z0-9_]{1,64}) reason_sha=(-|[0-9a-f]{64}) elapsed_us=([0-9]{1,39}) step_elapsed_us=([0-9]{1,39}) original_deadline_expired=(true|false) original_remaining_ns=([0-9]{1,39}) panicking=(true|false)\n")
UNSEAL = re.compile(rb"HBHA-DIAG-UNSEAL route_status=([0-9]{1,5}) state_loaded=(true|false) recovery_required=(true|false) barrier_loaded=(true|false) record_root=(true|false) activation=(true|false) original_deadline_present=(true|false)\n")
INTERRUPTED = False


class Refused(Exception):
    pass


def on_signal(_number, _frame):
    # No Python exception may interrupt open -> ledger or a one-shot close.
    # Every work boundary checks this flag; cleanup always visits the full ledger.
    global INTERRUPTED
    INTERRUPTED = True


def remaining(until):
    if INTERRUPTED:
        raise Refused("interrupted")
    if time.monotonic() >= until:
        raise Refused("original_observer_deadline_elapsed")


def facts(value):
    return {
        "device": value.st_dev, "inode": value.st_ino,
        "uid": value.st_uid, "gid": value.st_gid,
        "mode": stat.S_IMODE(value.st_mode), "type": stat.S_IFMT(value.st_mode),
        "nlink": value.st_nlink, "bytes": value.st_size,
        "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns,
    }


def same_directory(left, right):
    return all(left[key] == right[key] for key in
               ("device", "inode", "uid", "gid", "mode", "type"))


def same_file(left, right):
    return left == right


def parse_marker(line, line_number):
    token = line.split(b" ", 1)[0].rstrip(b"\n")
    if token not in (b"HBHA-NATIVE-SYNC-FAIL", b"HBHA-DIAG-UNSEAL"):
        return None
    if len(line) > 512:
        raise Refused("marker_too_long")
    if token == b"HBHA-NATIVE-SYNC-FAIL":
        match = SYNC.fullmatch(line)
        if match is None:
            raise Refused("invalid_sync_marker_shape")
        step, code, reason, elapsed, step_elapsed, expired, left, panicking = match.groups()
        step, code = step.decode("ascii"), code.decode("ascii")
        if step not in PHASES or code not in CODES:
            raise Refused("unknown_static_marker_label")
        numbers = [int(elapsed), int(step_elapsed), int(left)]
        if any(number > U128_MAX for number in numbers) or any(
            str(number).encode("ascii") != raw
            for number, raw in zip(numbers, (elapsed, step_elapsed, left), strict=True)
        ):
            raise Refused("marker_integer_out_of_range")
        result = {
            "marker": "HBHA-NATIVE-SYNC-FAIL", "step": step, "code": code,
            "reason_sha": reason.decode("ascii"),
            "elapsed_us": str(numbers[0]), "step_elapsed_us": str(numbers[1]),
            "original_deadline_expired": expired == b"true",
            "original_remaining_ns": str(numbers[2]), "panicking": panicking == b"true",
        }
    else:
        match = UNSEAL.fullmatch(line)
        if match is None:
            raise Refused("invalid_unseal_marker_shape")
        values = match.groups()
        status = int(values[0])
        if not 100 <= status <= 599 or str(status).encode("ascii") != values[0]:
            raise Refused("marker_status_out_of_range")
        result = {"marker": "HBHA-DIAG-UNSEAL", "route_status": status}
        for key, value in zip(
            ("state_loaded", "recovery_required", "barrier_loaded", "record_root",
             "activation", "original_deadline_present"), values[1:], strict=True
        ):
            result[key] = value == b"true"
    result["line_number"] = line_number
    result["line_bytes"] = len(line)
    result["line_sha256"] = hashlib.sha256(line).hexdigest()
    return result


def main():
    began = time.monotonic()
    until = began + TOTAL_SECONDS
    old_handlers = {}
    descriptors = []
    directories = []
    result = {
        "schema": "heptabao.b2-stopped-node2-public-log-projection.v1",
        "fixture_run_id": RUN_ID, "node_id": 2,
        "root": ROOT, "leaf": LEAF, "status": "refused", "complete": False,
        "read_only": True, "product_requests": 0, "children_started": 0,
        "files_written": 0, "new_shared_seconds": TOTAL_SECONDS,
        "max_input_bytes": MAX_INPUT, "max_output_bytes": MAX_OUTPUT,
        "max_marker_count": MAX_MARKERS, "raw_log_values_emitted": False,
        "unknown_lines_emitted": False, "cross_request_correlation_proven": False,
        "no_matching_marker_does_not_prove_no_internal_failure": True,
        "unsigned_128_time_fields_encoded_as_decimal_strings": True,
        "markers": [], "directories": [], "scanned_bytes": 0, "scanned_lines": 0,
        "unselected_lines": 0, "descriptors": [], "all_owned_descriptors_closed": False,
        "publication_within_original_deadline": False,
    }
    try:
        if len(sys.argv) != 2 or re.fullmatch(r"[0-9a-f]{64}", sys.argv[1]) is None:
            raise Refused("exact_source_pin_argument_required")
        result["source_sha256_argument"] = sys.argv[1]
        if os.getuid() != 1000 or sys.platform != "linux":
            raise Refused("expected_host_platform_owner")
        for number in (signal.SIGINT, signal.SIGTERM):
            old_handlers[number] = signal.signal(number, on_signal)
        remaining(until)
        root_before = facts(os.lstat("/"))
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append({"fd": fd, "kind": "directory", "close_attempted": False,
                            "closed": False, "close_error": False})
        root_open = facts(os.fstat(fd))
        if not stat.S_ISDIR(root_open["type"]) or not same_directory(root_before, root_open):
            raise Refused("root_directory_identity")
        directories.append({"fd": fd, "parent_fd": None, "name": "/", "path": "/",
                            "before": root_before, "opened": root_open})
        path = ""
        for name in ROOT.split("/")[1:]:
            remaining(until)
            before = facts(os.stat(name, dir_fd=fd, follow_symlinks=False))
            if not stat.S_ISDIR(before["type"]):
                raise Refused("directory_not_regular_nofollow")
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append({"fd": child, "kind": "directory", "close_attempted": False,
                                "closed": False, "close_error": False})
            opened = facts(os.fstat(child))
            named = facts(os.stat(name, dir_fd=fd, follow_symlinks=False))
            if not same_directory(before, opened) or not same_directory(opened, named):
                raise Refused("directory_open_identity_changed")
            path += "/" + name
            directories.append({"fd": child, "parent_fd": fd, "name": name, "path": path,
                                "before": before, "opened": opened})
            fd = child
        if directories[-1]["opened"]["uid"] != 1000 or directories[-1]["opened"]["mode"] != 0o700:
            raise Refused("fixture_root_owner_mode")
        remaining(until)
        before = facts(os.stat(LEAF, dir_fd=fd, follow_symlinks=False))
        if not (stat.S_ISREG(before["type"]) and before["uid"] == 1000
                and before["mode"] == 0o600 and before["nlink"] == 1
                and 0 <= before["bytes"] <= MAX_INPUT):
            raise Refused("log_file_owner_mode_size")
        log_fd = os.open(LEAF, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        descriptors.append({"fd": log_fd, "kind": "log", "close_attempted": False,
                            "closed": False, "close_error": False})
        opened = facts(os.fstat(log_fd))
        named = facts(os.stat(LEAF, dir_fd=fd, follow_symlinks=False))
        if not same_file(before, opened) or not same_file(opened, named):
            raise Refused("log_open_identity_changed")
        result["input_before"] = before
        digest = hashlib.sha256()
        data = bytearray()
        while len(data) < before["bytes"]:
            remaining(until)
            chunk = os.read(log_fd, min(65536, before["bytes"] - len(data)))
            if not chunk:
                raise Refused("log_early_eof")
            digest.update(chunk)
            data.extend(chunk)
        remaining(until)
        if os.read(log_fd, 1):
            raise Refused("log_grew")
        result["scanned_bytes"] = len(data)
        result["input_sha256"] = digest.hexdigest()
        for line_number, line in enumerate(data.splitlines(keepends=True), 1):
            remaining(until)
            result["scanned_lines"] = line_number
            marker = parse_marker(bytes(line), line_number)
            if marker is None:
                result["unselected_lines"] += 1
            else:
                if len(result["markers"]) >= MAX_MARKERS:
                    raise Refused("marker_count_exceeded")
                result["markers"].append(marker)
        remaining(until)
        after = facts(os.fstat(log_fd))
        named_after = facts(os.stat(LEAF, dir_fd=fd, follow_symlinks=False))
        result["input_after"] = after
        result["input_named_after"] = named_after
        if not same_file(before, after) or not same_file(after, named_after):
            raise Refused("log_final_identity_changed")
        for row in directories:
            remaining(until)
            held = facts(os.fstat(row["fd"]))
            named = facts(os.lstat("/")) if row["parent_fd"] is None else facts(
                os.stat(row["name"], dir_fd=row["parent_fd"], follow_symlinks=False))
            public = {key: row[key] for key in ("name", "path", "before", "opened")}
            public.update(after=held, named_after=named)
            result["directories"].append(public)
            if not same_directory(row["opened"], held) or not same_directory(held, named):
                raise Refused("directory_final_named_identity_changed")
        remaining(until)
        result["status"] = "observed"
        result["complete"] = True
    except Refused as error:
        result["failure_code"] = error.args[0]
    except Exception as error:
        result["failure_code"] = "observer_exception"
        result["failure_type"] = type(error).__name__
    finally:
        for row in reversed(descriptors):
            row["close_attempted"] = True
            try:
                os.close(row["fd"])
                row["closed"] = True
            except OSError:
                row["close_error"] = True
            result["descriptors"].append({key: row[key] for key in
                                          ("kind", "close_attempted", "closed", "close_error")})
        result["all_owned_descriptors_closed"] = all(
            row["close_attempted"] and row["closed"] and not row["close_error"]
            for row in descriptors)
        if not result["all_owned_descriptors_closed"]:
            result["complete"] = False
            result["status"] = "refused"
            result["failure_code"] = "descriptor_close_failed"
        if INTERRUPTED:
            result["complete"] = False
            result["status"] = "refused"
            result["failure_code"] = "interrupted"
        for number, handler in old_handlers.items():
            signal.signal(number, handler)
    try:
        remaining(until)
        result["publication_within_original_deadline"] = True
    except Refused:
        result["complete"] = False
        result["status"] = "refused"
        result["failure_code"] = "publication_deadline_or_signal"
    result["elapsed_seconds_before_publication"] = time.monotonic() - began
    encoded = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(encoded) > MAX_OUTPUT:
        raise SystemExit(2)
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    remaining(until)
    raise SystemExit(0 if result["complete"] else 1)


if __name__ == "__main__":
    main()
