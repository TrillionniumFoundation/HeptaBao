#!/usr/bin/env python3
"""NEW owned, offline QA client build. No product server or network request.

A reviewed binding is mandatory. All dependency packages in the generated
QA lock must be exact version/source/checksum members of canonical df026.
The already-frozen product worktree is read-only throughout.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import subprocess
import time
import tomllib

sys.dont_write_bytecode = True
COMMIT = "df026fe323dd7cf0f0ec57d7d2d9c5a79897053c"
TREE = "424463ccd2310ddc1e7b2bbcd7b7af29ae58c825"
SOURCE = Path("/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/source")
CONTROL = Path("/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r2")
ROOT = Path("/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r2")
TOOL_ROOT = Path("/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin")
CARGO_HOME = Path("/home/qian-qi/heptabao-native-20261029-c1bd-r1/cargo-home")
NORMAL_RUNNER_SHA = "1a3fdc3a7cf6504447feb7d7dadf2f365b292512f6d0cf8cdfb4a2ea63d33d40"
CANONICAL_LOCK_SHA = "d2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5"
MAX_LOG = 8 * 1024 * 1024
PROFILE = {"opt_level": "3", "debuginfo": 0, "debug_assertions": True,
           "overflow_checks": True, "test": False}
OPEN_FDS = set()
FD_CLOSE_FAILED = False

class BindingError(RuntimeError):
    pass

def open_fd(path, flags, mode=0o600):
    fd = os.open(path, flags, mode)
    OPEN_FDS.add(fd)
    return fd

def close_fd(fd):
    global FD_CLOSE_FAILED
    try:
        os.close(fd)
    except BaseException:
        FD_CLOSE_FAILED = True
        raise
    OPEN_FDS.remove(fd)

CAPS = {
    "total_seconds": 600,
    "git_seconds": 15,
    "tool_seconds": 15,
    "lock_seconds": 20,
    "build_seconds": 180,
    "components_build_seconds": 180,
    "list_seconds": 15,
    "components_seconds": 30,
    "cleanup_term_seconds": 5,
    "cleanup_kill_seconds": 5
}
INPUT_PINS = {
    "rust_source": [
        "native_h2_client.rs",
        19382,
        "41347a71055e5c7086a256549f25f20d52ba8361e16926b4470f3448425f90dd"
    ],
    "test_source": [
        "native_h2_client_tests.rs",
        8942,
        "7f23470287fe953f0271e974d6eda759b7daf9f15bc363d522a02d3633e012c2"
    ],
    "cargo_manifest": [
        "Cargo.toml",
        957,
        "960de7b19776cda4bd8a00561a417f72b08ca320efb93ec05028a3be0e7315e5"
    ],
    "canonical_lock": [
        "canonical.Cargo.lock",
        101193,
        "d2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5"
    ],
    "owner_reference": [
        "owned_reference_phaseb_r3.py",
        61210,
        "10816d06fd5ad59175872ccb7db1337d7677e92405a26a7ab1cae2796ee0a86c"
    ],
    "cli_reference": [
        "official_cli_reference_r4.py",
        46586,
        "18318841d3538e60fddf951708055a206402f5bf1ecdacc2bfceabec4f998dd9"
    ]
}
COMPONENT_TESTS = [
    "component_tests::native_h2_client_accepts_complete_data_eos",
    "component_tests::native_h2_client_accepts_complete_empty_trailers_eos",
    "component_tests::native_h2_client_rejects_rst_no_error_after_exact_body_before_eos",
    "component_tests::native_h2_client_rejects_eof_after_exact_body_before_eos",
    "component_tests::native_h2_client_rejects_short_eos_and_duplicate_content_length",
    "component_tests::native_h2_client_refuses_expired_or_extended_original_deadline"
]
PRODUCT_COLD_H2_TESTS = [
    "service::native_v6_ha_install::read::cold_timing_tests::cold_native_ha_timing_preserves_once_and_owned_result_identity",
    "service::native_v6_ha_install::read::cold_timing_tests::cold_native_ha_timing_preserves_nested_source_and_inner_results",
    "service::native_v6_ha_install::tests::native_ha_install_batches_actual_readindex_cold_missing_and_corrupt_file",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_is_unentered_and_retains_outer_context",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_expired_deadline_never_calls_work",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_preserves_inner_result",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_joins_panicked_work_and_drops_capture",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_does_not_authorize_nested_runtime_context",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_cancelled_waiter_retains_blocking_capacity"
]

def need(ok: bool, code: str) -> None:
    if not ok:
        raise BindingError(code)

def remaining(until: int) -> float:
    value = (until - time.monotonic_ns()) / 1e9
    need(value > 0, "original_action_deadline")
    return value

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def identity(st: os.stat_result) -> dict:
    return {"device": st.st_dev, "inode": st.st_ino, "uid": st.st_uid, "gid": st.st_gid,
            "links": st.st_nlink, "mode": stat.S_IMODE(st.st_mode),
            "bytes": st.st_size, "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns}

def exact_path(value: str) -> Path:
    need(type(value) is str and value.startswith("/") and "\0" not in value, "absolute_path_required")
    path = Path(value)
    need(str(path) == value and ".." not in path.parts, "canonical_path_spelling")
    return path

def no_symlink_ancestors(path: Path) -> None:
    for parent in reversed(path.parents):
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "symlink_or_nondirectory_ancestor")
    need(path.parent.resolve(strict=True) == path.parent, "resolved_parent_changed")

def duplicate_free(pairs: list[tuple[str, object]]) -> dict:
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate_json_key")
        out[key] = value
    return out

def parse(raw: bytes) -> object:
    return json.loads(raw.decode(), object_pairs_hook=duplicate_free)

def read_file(path: Path, maximum: int, until: int, *, retain: bool = True) -> tuple[bytes | None, dict]:
    remaining(until)
    no_symlink_ancestors(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "regular_single_link_file_required")
    need(0 <= before.st_size <= maximum, "file_size_bound")
    fd = open_fd(path, os.O_RDONLY | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    data = bytearray() if retain else None
    try:
        need(identity(os.fstat(fd)) == identity(before), "file_identity_before_read")
        count = 0
        while True:
            remaining(until)
            block = os.read(fd, min(1024 * 1024, maximum + 1 - count))
            if not block:
                break
            count += len(block)
            need(count <= maximum, "file_size_bound")
            digest.update(block)
            if data is not None:
                data.extend(block)
        need(identity(os.fstat(fd)) == identity(before)
             and identity(path.lstat()) == identity(before), "file_identity_after_read")
        remaining(until)
        return (bytes(data) if data is not None else None), {
            **identity(before), "path": str(path), "sha256": digest.hexdigest()}
    finally:
        close_fd(fd)

def pin_file(pin: dict, until: int, *, retain: bool = False) -> tuple[bytes | None, dict]:
    need(type(pin) is dict and set(pin) == {"path", "sha256", "bytes", "uid", "mode"}, "exact_file_pin_fields")
    need(type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is not None
         and pin["sha256"] != "0" * 64, "real_file_sha_required")
    need(type(pin["bytes"]) is int and 0 < pin["bytes"] <= 512 * 1024 * 1024, "real_file_size_required")
    need(type(pin["uid"]) is int and pin["uid"] in (0, os.getuid()), "allowed_file_owner")
    need(type(pin["mode"]) is int and 0 <= pin["mode"] <= 0o777
         and not pin["mode"] & 0o022, "pinned_nonwritable_by_others_mode")
    raw, observation = read_file(exact_path(pin["path"]), pin["bytes"], until, retain=retain)
    need(all(observation[key] == pin[key] for key in ("sha256", "bytes", "uid", "mode")), "file_pin_mismatch")
    return raw, observation

def load_verified_module(name: str, path: Path, expected_sha: str, expected_bytes: int, until: int):
    raw, observation = read_file(path, expected_bytes, until)
    need(observation["sha256"] == expected_sha and len(raw) == expected_bytes, "module_pin_mismatch")
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None, "module_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    # Execute the exact already-hashed source bytes, rather than reopen the path.
    exec(compile(raw, str(path), "exec"), module.__dict__)
    remaining(until)
    return module

def lock_subset(actual_raw: bytes, canonical_raw: bytes) -> dict:
    actual = tomllib.loads(actual_raw.decode("utf-8"))
    canonical = tomllib.loads(canonical_raw.decode("utf-8"))
    need(type(actual) is dict and set(actual) == {"version", "package"}
         and type(actual["version"]) is int
         and actual["version"] == canonical.get("version"), "qa_lock_top_level")
    package_list = canonical.get("package")
    need(type(package_list) is list and type(actual["package"]) is list
         and 1 < len(actual["package"]) <= len(package_list), "qa_lock_package_bound")
    allowed = {}
    for item in package_list:
        key = (item["name"], item["version"], item.get("source"))
        need(key not in allowed, "canonical_lock_duplicate_package")
        allowed[key] = item.get("checksum")
    seen, members, own = set(), [], 0
    for item in actual["package"]:
        need(type(item) is dict and set(item) <=
             {"name", "version", "source", "checksum", "dependencies"}, "qa_lock_package_fields")
        need(type(item.get("name")) is str and type(item.get("version")) is str
             and type(item.get("dependencies", [])) is list
             and all(type(value) is str for value in item.get("dependencies", [])),
             "qa_lock_package_types")
        key = (item["name"], item["version"], item.get("source"))
        need(key not in seen, "qa_lock_duplicate_package")
        seen.add(key)
        if item["name"] == "heptabao-native-h2-qa":
            need(item["version"] == "0.1.0" and "source" not in item
                 and "checksum" not in item, "only_owned_qa_root_package")
            own += 1
            continue
        need(item.get("source") == "registry+https://github.com/rust-lang/crates.io-index"
             and type(item.get("checksum")) is str
             and re.fullmatch(r"[0-9a-f]{64}", item["checksum"]) is not None
             and key in allowed and item["checksum"] == allowed[key],
             "qa_dependency_not_exact_canonical_lock_member")
        members.append({"name": item["name"], "version": item["version"],
                        "source": item["source"], "checksum": item["checksum"]})
    need(own == 1, "one_owned_qa_root_package")
    members.sort(key=lambda item: (item["name"], item["version"], item["source"]))
    return {"schema": "heptabao.native-h2-qa.lock-subset.v1",
            "canonical_sha256": sha(canonical_raw), "qa_lock_sha256": sha(actual_raw),
            "registry_package_count": len(members), "owned_qa_package_count": own,
            "packages": members, "exact_version_source_checksum_subset": True}


def write_new(path: Path, raw: bytes) -> None:
    fd = open_fd(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW)
    try:
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:])
            need(count > 0, "owned_write_incomplete")
            at += count
        os.fsync(fd)
    finally:
        close_fd(fd)
    parent = open_fd(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        close_fd(parent)


def write_json(path: Path, value) -> bytes:
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    write_new(path, raw)
    return raw


def fixed_error(error: BaseException) -> str:
    code = str(error)
    return code if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,159}", code or "") else type(error).__name__


def target_identity(path: Path) -> dict:
    no_symlink_ancestors(path)
    value = path.lstat()
    need(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode)
         and value.st_uid == os.getuid() and not stat.S_IMODE(value.st_mode) & 0o002,
         "existing_owned_target_directory")
    return {key: identity(value)[key] for key in ("device", "inode", "uid", "gid", "mode")}


def qa_command_owner_class(owner_reference, cli):
    """Own only this builder's direct, single-threaded Popen commands.

    The retained CLI helper still requires visible executable/argv. These short
    QA commands instead bind the exact Popen invocation to an unreaped kernel
    child, then require an actual WNOWAIT exit event before Popen.wait consumes
    it. Empty /proc cmdline is neither read nor accepted as evidence.
    """
    class QaCommands(owner_reference.owner_class(cli)):
        def __init__(self, root):
            super().__init__(root)
            self.command_custody = {}

        def child_stat(self, process, until):
            remaining(until)
            fd = open_fd(Path("/proc") / str(process.pid) / "stat",
                         os.O_RDONLY | os.O_NOFOLLOW)
            try:
                raw = os.read(fd, 8193)
                need(len(raw) <= 8192 and os.read(fd, 1) == b"", "owned_stat_complete_bounded")
            finally:
                close_fd(fd)
            remaining(until)
            end = raw.rfind(b") ")
            need(raw.startswith((str(process.pid) + " (").encode()) and end > 0,
                 "owned_stat_pid")
            fields = raw[end + 2:].split()
            need(len(fields) >= 20 and fields[0] in
                 (b"R", b"S", b"D", b"T", b"t", b"Z", b"X", b"x", b"I", b"P", b"W"),
                 "owned_stat_shape")
            captured = {"pid": process.pid, "state": fields[0].decode("ascii"),
                        "ppid": int(fields[1]), "pgid": int(fields[2]),
                        "start_ticks": int(fields[19])}
            need(captured["ppid"] == os.getpid() and captured["pgid"] == process.pid
                 and 0 < captured["start_ticks"] < 2**64, "owned_unreaped_start_identity")
            return captured

        def peek_child_exit(self, process, until):
            remaining(until)
            need(process.returncode is None and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
                 "owned_child_not_previously_reaped")
            # P_PID selects this actual direct child; ECHILD is a failure.
            # WNOWAIT never consumes the exit event or releases the PID.
            event = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            remaining(until)
            if event is None:
                return None
            need(event.si_pid == process.pid and event.si_uid == os.getuid()
                 and event.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED),
                 "owned_waitid_terminal_identity")
            if event.si_code == os.CLD_EXITED:
                need(0 <= event.si_status <= 255, "owned_waitid_exit_status")
                code = event.si_status
            else:
                need(0 < event.si_status < signal.NSIG, "owned_waitid_signal_status")
                code = -event.si_status
            return {"pid": event.si_pid, "uid": event.si_uid,
                    "si_code": event.si_code, "si_status": event.si_status,
                    "expected_returncode": code, "not_reaped": True}

        def start_child(self, argv, *, until, **options):
            need(not self.creating_child and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
                 "qa_direct_child_creation_contract")
            need(type(argv) is list and bool(argv)
                 and all(type(arg) is str and "\0" not in arg for arg in argv)
                 and argv[0] in ("/usr/bin/git", str(TOOL_ROOT / "rustc"),
                                 str(TOOL_ROOT / "cargo"),
                                 str(ROOT / "artifacts" / "heptabao-native-h2-qa-tests")),
                 "qa_fixed_command_executable")
            need(set(options) == {"cwd", "stdin", "stdout", "stderr", "env", "start_new_session"}
                 and options["start_new_session"] is True
                 and options["stdin"] == subprocess.DEVNULL
                 and options["stdout"] in OPEN_FDS and options["stderr"] in OPEN_FDS
                 and options["cwd"] in (ROOT, ROOT / "project"), "qa_direct_command_options")
            exact_argv = tuple(argv)
            self.creating_child = True
            try:
                remaining(until)
                process = subprocess.Popen(exact_argv, shell=False, close_fds=True, **options)
                index = len(self.children)
                self.children.append((process, None))
            finally:
                self.creating_child = False
                pending, self.pending_signal = self.pending_signal, None
                if pending is not None:
                    raise cli.Refused("owner_signal_" + str(pending))
            proof = {"pid": process.pid, "mechanism": "direct_popen_unreaped_waitid_v1",
                     "requested_argv_sha256": sha(b"\0".join(os.fsencode(x) for x in exact_argv) + b"\0"),
                     "popen_returned": True, "provisionally_registered_before_observation": True,
                     "custody_verified": False, "live_proc_argv_observed": False,
                     "waitid_calls": 0, "terminal_event": None, "terminal_consumed": False}
            self.child_provenance.append(proof)
            self.command_custody[id(process)] = proof
            need(process.args == exact_argv and process.returncode is None, "qa_exact_popen_object")
            before = self.child_stat(process, until)
            event = self.peek_child_exit(process, until)
            proof["waitid_calls"] += 1
            after = self.child_stat(process, until)
            need(all(before[key] == after[key] for key in ("pid", "ppid", "pgid", "start_ticks")),
                 "owned_unreaped_identity_changed")
            need(self.children[index] == (process, None), "qa_original_provisional_registration")
            self.children[index] = (process, after)
            proof.update({"identity_before": before, "identity_after": after,
                          "terminal_event": event, "custody_verified": True})
            return process

        def wait_child(self, process, until):
            proof = self.command_custody[id(process)]
            captured = next(saved for child, saved in self.children if child is process)
            need(proof["custody_verified"] and captured is not None,
                 "qa_custody_required_before_wait")
            wait_budget = remaining(until)
            delay = 0.0005
            while True:
                if time.monotonic_ns() >= until:
                    raise subprocess.TimeoutExpired(process.args, wait_budget)
                event = self.peek_child_exit(process, until)
                proof["waitid_calls"] += 1
                previous = proof["terminal_event"]
                need(previous is None or event == previous, "owned_terminal_event_changed")
                if event is not None:
                    current = self.child_stat(process, until)
                    need(all(current[key] == captured[key]
                             for key in ("pid", "ppid", "pgid", "start_ticks")),
                         "owned_terminal_start_identity_changed")
                    proof["terminal_event"] = event
                    code = process.wait(timeout=remaining(until))
                    need(code == event["expected_returncode"] and process.returncode == code,
                         "owned_waitid_and_popen_status_disagree")
                    proof["terminal_consumed"] = True
                    proof["wait_returncode"] = code
                    return code
                time.sleep(min(delay, remaining(until)))
                delay = min(delay * 2, 0.05)
    return QaCommands


def main() -> int:
    started = time.monotonic_ns()
    until = started + CAPS["total_seconds"] * 1_000_000_000
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--binding-sha256", required=True)
    parser.add_argument("--self-sha256", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    need(sys.flags.isolated == sys.flags.no_site == sys.flags.dont_write_bytecode == 1,
         "python_I_S_B_required")
    need(args.binding == CONTROL / "build-binding.private.json"
         and Path(__file__).absolute() == CONTROL / "build_native_h2_client_r1.py",
         "fixed_build_control_paths")
    binding_raw, binding_file = read_file(args.binding, 2 * 1024 * 1024, until)
    need(binding_file["sha256"] == args.binding_sha256
         and binding_file["uid"] == os.getuid() and binding_file["mode"] == 0o600,
         "exact_private_build_binding")
    control_file_raw, self_file = read_file(Path(__file__).absolute(), 256 * 1024, until)
    need(self_file["sha256"] == args.self_sha256 and self_file["uid"] == os.getuid()
         and self_file["mode"] == 0o600, "exact_builder_source")
    spec = parse(binding_raw)
    need(type(spec) is dict and set(spec) == {
        "schema", "ready", "candidate_commit", "candidate_tree", "source", "root",
        "control", "target", "target_identity", "cargo_home", "host", "tools",
        "inputs", "normal_product_result", "caps"
    }, "exact_build_binding_fields")
    need(spec["schema"] == "heptabao.native-h2-qa.build-binding.v1"
         and spec["ready"] is True
         and spec["candidate_commit"] == COMMIT and spec["candidate_tree"] == TREE
         and spec["source"] == str(SOURCE) and spec["root"] == str(ROOT)
         and spec["control"] == str(CONTROL) and spec["cargo_home"] == str(CARGO_HOME)
         and spec["caps"] == CAPS, "resolved_exact_build_binding")
    host = spec["host"]
    need(type(host) is dict and set(host) == {"uid", "machine_id_sha256"}
         and host["uid"] == os.getuid() == 1000 and os.uname().sysname == "Linux"
         and os.uname().machine == "x86_64", "actual_rog_native_abi")
    machine, _ = read_file(Path("/etc/machine-id"), 256, until)
    need(sha(machine) == host["machine_id_sha256"], "exact_rog_machine")
    no_symlink_ancestors(CONTROL)
    control_identity = CONTROL.lstat()
    need(stat.S_ISDIR(control_identity.st_mode) and control_identity.st_uid == os.getuid()
         and stat.S_IMODE(control_identity.st_mode) == 0o700, "owned_controls_custody")
    target = exact_path(spec["target"])
    need(target.is_relative_to(Path("/home/qian-qi")) and target != Path("/home/qian-qi")
         and not target.is_relative_to(SOURCE) and not SOURCE.is_relative_to(target)
         and not target.is_relative_to(ROOT) and target != CONTROL
         and target_identity(target) == spec["target_identity"], "exact_existing_bound_target")
    # No fallback target creation or repair is permitted. A future exact target
    # binding must be independently authorized after the normal job is stopped.
    need(CARGO_HOME.is_dir() and not CARGO_HOME.is_symlink(), "existing_cargo_home")
    no_symlink_ancestors(CARGO_HOME)
    tools = spec["tools"]
    need(type(tools) is dict and set(tools) == {"python", "git", "cargo", "rustc"},
         "exact_tool_set")
    tool_paths = {"python": str(Path(sys.executable).resolve(strict=True)), "git": "/usr/bin/git",
                  "cargo": str(TOOL_ROOT / "cargo"), "rustc": str(TOOL_ROOT / "rustc")}
    observed_inputs = {"tools": {}, "sources": {}}
    for name, pin in tools.items():
        need(pin["path"] == tool_paths[name], "exact_native_tool_path")
        _, observed_inputs["tools"][name] = pin_file(pin, until)
    inputs = spec["inputs"]
    need(type(inputs) is dict and set(inputs) == set(INPUT_PINS), "exact_reviewed_input_set")
    recovered = {}
    for role, (filename, size, digest) in INPUT_PINS.items():
        pin = inputs[role]
        need(pin["path"] == str(CONTROL / "inputs" / filename)
             and pin["bytes"] == size and pin["sha256"] == digest
             and pin["uid"] == os.getuid() and pin["mode"] == 0o600,
             "reviewed_input_layout_and_whole_pin")
        recovered[role], observed_inputs["sources"][role] = pin_file(pin, until, retain=True)
    normal_raw, normal_observed = pin_file(spec["normal_product_result"], until, retain=True)
    normal = parse(normal_raw)
    need(normal.get("schema") == "heptabao.linux-normal-cold-h2-exact-tests.v1"
         and normal.get("source_commit") == COMMIT and normal.get("source_tree") == TREE
         and normal.get("controller_sha256") == NORMAL_RUNNER_SHA
         and normal.get("status") == "passed" and normal.get("test_count") == 44
         and normal.get("selected_test_total") == 60
         and normal.get("normal_default_features") is True and normal.get("fixture_features") == []
         and normal.get("original_44_status") == normal.get("original_44_and_ingress_7_status") == "passed"
         and normal.get("ingress_observer_regression", {}).get("status") == "passed"
         and normal.get("cold_h2_regression", {}).get("status") == "passed"
         and normal.get("cold_h2_regression", {}).get("actual_test_names") == PRODUCT_COLD_H2_TESTS
         and normal.get("source_unchanged") is True
         and normal.get("binary_unchanged") is True and normal.get("release_artifacts_unchanged") is True
         and all(item.get("direct_child_reaped") is True and item.get("remaining") == []
                 and not item.get("cleanup_error_type") for item in normal.get("cleanup", []))
         and bool(normal.get("cleanup")), "actual_completed_normal_44_7_9_required")
    canonical_lock, canonical_lock_observed = read_file(SOURCE / "Cargo.lock", 2 * 1024 * 1024, until)
    need(sha(canonical_lock) == CANONICAL_LOCK_SHA
         and canonical_lock == recovered["canonical_lock"], "actual_canonical_lock_source")
    need(not ROOT.exists() and not ROOT.is_symlink(), "fresh_qa_build_root_required")
    no_symlink_ancestors(ROOT)
    # This is the sole mutable project. SOURCE is never a Cargo working directory.
    ROOT.mkdir(mode=0o700)
    created = True
    (ROOT / "private").mkdir(mode=0o700)
    (ROOT / "project").mkdir(mode=0o700)
    (ROOT / "artifacts").mkdir(mode=0o700)
    project = ROOT / "project"
    result = {"schema": "heptabao.native-h2-qa.build.v2", "status": "failed",
              "candidate_commit": COMMIT, "candidate_tree": TREE,
              "controller_sha256": self_file["sha256"], "binding_sha256": args.binding_sha256,
              "normal_product_result_sha256": normal_observed["sha256"],
              "normal_product_runner_sha256": NORMAL_RUNNER_SHA,
              "caps": CAPS, "started_monotonic_ns": started, "deadline_monotonic_ns": until,
              "commands": [], "command_intents": [], "owned_cleanup": [], "all_owned_stopped": False,
              "all_input_fds_closed": False, "completed_within_original_build_deadline": False,
              "offline_only": True, "product_modified": False, "product_or_http_requests": 0,
              "new_qa_components_not_added_to_product_44_7_9": True,
              "component_names": COMPONENT_TESTS,
              "reviewed_sources": {role: {"bytes": INPUT_PINS[role][1], "sha256": INPUT_PINS[role][2]}
                                   for role in ("rust_source", "test_source", "cargo_manifest")}}
    owner = None
    stage = "owned_definition_import"
    try:
        modules = {}
        for role in ("owner_reference", "cli_reference"):
            module_spec = importlib.util.spec_from_loader("h2qa_" + role, loader=None)
            need(module_spec is not None, "owned_module_spec")
            module = importlib.util.module_from_spec(module_spec)
            sys.modules[module_spec.name] = module
            exec(compile(recovered[role], str(CONTROL / "inputs" / INPUT_PINS[role][0]), "exec"),
                 module.__dict__)
            modules[role] = module
        cli = modules["cli_reference"]
        cli.ROOT = ROOT
        owner = qa_command_owner_class(modules["owner_reference"], cli)(ROOT)
        signal.signal(signal.SIGTERM, owner.interrupted)
        signal.signal(signal.SIGINT, owner.interrupted)
        environment = {
            "PATH": str(TOOL_ROOT) + ":/usr/bin:/bin", "HOME": str(ROOT), "LANG": "C", "LC_ALL": "C",
            "CARGO_HOME": str(CARGO_HOME), "CARGO_TARGET_DIR": str(target), "CARGO_BUILD_JOBS": "1",
            "CARGO_PROFILE_RELEASE_OPT_LEVEL": "3", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "16",
            "CARGO_PROFILE_RELEASE_LTO": "false", "CARGO_PROFILE_RELEASE_DEBUG": "0",
            "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS": "true",
            "CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS": "true", "CARGO_PROFILE_RELEASE_PANIC": "unwind",
            "RUSTFLAGS": "", "CARGO_TERM_COLOR": "never", "RUSTC": str(TOOL_ROOT / "rustc"),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

        def command(label, argv, cap, *, cwd=project):
            start = time.monotonic_ns()
            child_until = min(until, start + cap * 1_000_000_000)
            remaining(child_until)
            intent = {"label": label, "argv": argv, "cwd": str(cwd),
                      "started_monotonic_ns": start, "deadline_monotonic_ns": child_until,
                      "outer_cap_seconds": cap}
            write_json(ROOT / (label + ".intent.public.json"), intent)
            result["command_intents"].append(intent)
            remaining(child_until)
            out = open_fd(ROOT / (label + ".stdout"),
                          os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW)
            err = None
            process = None
            timed_out = False
            try:
                err = open_fd(ROOT / (label + ".stderr"),
                              os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW)
                process = owner.start_child(
                    argv, until=child_until, cwd=cwd, stdin=subprocess.DEVNULL,
                    stdout=out, stderr=err, env=environment, start_new_session=True)
                try:
                    owner.wait_child(process, child_until)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    captured = next(saved for child, saved in owner.children if child is process)
                    owner.stop_once(process, captured, propagate=True)
                os.fsync(out)
                os.fsync(err)
            finally:
                if err is not None:
                    close_fd(err)
                close_fd(out)
            completed = time.monotonic_ns()
            stdout, outmeta = read_file(ROOT / (label + ".stdout"), MAX_LOG, until)
            _, errmeta = read_file(ROOT / (label + ".stderr"), MAX_LOG, until, retain=False)
            record = {
                "label": label, "argv": argv, "cwd": str(cwd), "exit_code": process.returncode,
                "timed_out": timed_out, "started_monotonic_ns": start,
                "completed_monotonic_ns": completed, "deadline_monotonic_ns": child_until,
                "completed_within_deadline": completed < child_until,
                "elapsed_seconds": (completed - start) / 1e9,
                "outer_cap_seconds": cap, "owned_pgid": process.pid,
                "direct_child_reaped": process.returncode is not None,
                "remaining": cli.group_members(process.pid),
                "stdout_sha256": outmeta["sha256"], "stderr_sha256": errmeta["sha256"],
            }
            result["commands"].append(record)
            write_json(ROOT / (label + ".public.json"), record)
            need(record["exit_code"] == 0 and not timed_out
                 and record["completed_within_deadline"]
                 and record["direct_child_reaped"] and not record["remaining"],
                 "owned_command_failed_or_unknown")
            return stdout, record

        def source_guard(label):
            values = {}
            for key, suffix in (("commit", ["rev-parse", "HEAD"]),
                                ("tree", ["rev-parse", "HEAD^{tree}"]),
                                ("status", ["status", "--porcelain", "--untracked-files=all"])):
                raw, _ = command(label + "-" + key,
                    ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                     "-C", str(SOURCE), *suffix], CAPS["git_seconds"], cwd=ROOT)
                values[key] = raw.decode("utf-8").strip()
            need(values == {"commit": COMMIT, "tree": TREE, "status": ""}, "canonical_source_clean")
            return values

        stage = "canonical_before"
        result["source_before"] = source_guard("source-before")
        raw, _ = command("rustc-version", [str(TOOL_ROOT / "rustc"), "-vV"], CAPS["tool_seconds"])
        rustc_version = raw.decode("utf-8")
        need("release: 1.98.0\n" in rustc_version and "host: x86_64-unknown-linux-gnu\n" in rustc_version,
             "exact_rust_toolchain")
        result["rustc_vv"] = rustc_version
        for role in ("rust_source", "test_source", "cargo_manifest"):
            write_new(project / INPUT_PINS[role][0], recovered[role])
        write_new(project / "Cargo.lock", canonical_lock)
        stage = "offline_lock_generation"
        command("lock", [str(TOOL_ROOT / "cargo"), "generate-lockfile", "--offline"], CAPS["lock_seconds"])
        qa_lock, _ = read_file(project / "Cargo.lock", 2 * 1024 * 1024, until)
        subset = lock_subset(qa_lock, canonical_lock)
        result["lock_subset"] = subset
        write_new(ROOT / "artifacts" / "Cargo.lock", qa_lock)
        write_new(ROOT / "artifacts" / "canonical.Cargo.lock", canonical_lock)

        def compile_and_retain(label, cargo_action, cap, test, destination):
            raw, record = command(label, cargo_action, cap)
            events = [parse(line) for line in raw.splitlines() if line.strip()]
            need(all(type(item) is dict for item in events), "cargo_json_events")
            need(sum(item.get("reason") == "build-finished" and item.get("success") is True
                     for item in events) == 1, "cargo_actual_build_finished")
            artifacts = [item for item in events
                         if item.get("reason") == "compiler-artifact"
                         and item.get("target", {}).get("name") == "heptabao-native-h2-qa"
                         and item.get("executable")]
            need(len(artifacts) == 1, "single_actual_qa_compiler_artifact")
            event = artifacts[0]
            expected_profile = {**PROFILE, "test": test}
            need(event.get("features") == [] and event.get("profile") == expected_profile,
                 "qa_actual_features_and_profile")
            built = exact_path(event["executable"])
            need(built.is_relative_to(target) and not built.is_relative_to(SOURCE),
                 "qa_artifact_bound_target")
            contents, source_meta = read_file(built, 128 * 1024 * 1024, until)
            need(source_meta["uid"] == os.getuid() and bool(source_meta["mode"] & 0o100),
                 "actual_qa_artifact_custody")
            write_new(destination, contents)
            os.chmod(destination, 0o500, follow_symlinks=False)
            _, retained = read_file(destination, 128 * 1024 * 1024, until, retain=False)
            need(retained["sha256"] == source_meta["sha256"] and retained["bytes"] == source_meta["bytes"],
                 "retained_qa_exact_artifact")
            return {**retained, "features": event["features"], "profile": event["profile"],
                    "compiler_executable": str(built), "cargo_stdout_sha256": record["stdout_sha256"]}

        stage = "offline_locked_binary"
        cargo = str(TOOL_ROOT / "cargo")
        executable = ROOT / "artifacts" / "heptabao-native-h2-qa"
        result["executable"] = compile_and_retain("build",
            [cargo, "build", "--release", "--locked", "--offline",
             "--bin", "heptabao-native-h2-qa", "--message-format=json-render-diagnostics"],
            CAPS["build_seconds"], False, executable)
        stage = "offline_locked_component_compile"
        test_binary = ROOT / "artifacts" / "heptabao-native-h2-qa-tests"
        result["component_binary"] = compile_and_retain("components-build",
            [cargo, "test", "--release", "--locked", "--offline", "--bin", "heptabao-native-h2-qa",
             "--no-run", "--message-format=json-render-diagnostics"],
            CAPS["components_build_seconds"], True, test_binary)
        stage = "six_component_listing"
        raw, _ = command("components-list", [str(test_binary), "component_tests::", "--list"],
                         CAPS["list_seconds"])
        listed = [line[:-6] for line in raw.decode("utf-8").splitlines() if line.endswith(": test")]
        need(len(listed) == 6 and set(listed) == set(COMPONENT_TESTS), "exact_six_component_listing")
        stage = "six_component_execution"
        raw, component_record = command("components",
            [str(test_binary), "component_tests::", "--nocapture", "--test-threads=1"],
            CAPS["components_seconds"])
        text = raw.decode("utf-8")
        executed = [line[5:-7] for line in text.splitlines()
                    if line.startswith("test ") and line.endswith(" ... ok")]
        need(len(executed) == 6 and set(executed) == set(COMPONENT_TESTS)
             and text.count("test result: ok. 6 passed; 0 failed; 0 ignored;") == 1,
             "six_components_actually_executed")
        component_raw, _ = read_file(ROOT / "components.public.json", 64 * 1024, until)
        result["component_record_sha256"] = sha(component_raw)
        stage = "canonical_after"
        result["source_after"] = source_guard("source-after")
        need(target_identity(target) == spec["target_identity"], "same_target_directory")
        for role in ("rust_source", "test_source", "cargo_manifest"):
            project_raw, _ = read_file(project / INPUT_PINS[role][0], 256 * 1024, until)
            need(project_raw == recovered[role], "owned_qa_source_unchanged")
        actual_lock_after, _ = read_file(project / "Cargo.lock", 2 * 1024 * 1024, until)
        need(actual_lock_after == qa_lock, "qa_lock_unchanged_after_locked_builds")
        source_lock_after, current_lock = read_file(SOURCE / "Cargo.lock", 2 * 1024 * 1024, until)
        need(current_lock == canonical_lock_observed and source_lock_after == canonical_lock,
             "canonical_lock_never_modified")
        for name, pin in tools.items():
            _, actual = pin_file(pin, until)
            need(actual == observed_inputs["tools"][name], "pinned_tool_changed")
        for role, pin in inputs.items():
            _, actual = pin_file(pin, until)
            need(actual == observed_inputs["sources"][role], "pinned_qa_input_changed")
        _, final_normal = pin_file(spec["normal_product_result"], until)
        need(final_normal == normal_observed, "normal_qualification_receipt_changed")
        _, current_binding = read_file(args.binding, 2 * 1024 * 1024, until)
        _, current_builder = read_file(Path(__file__).absolute(), 256 * 1024, until)
        need(current_binding == binding_file and current_builder == self_file, "control_input_changed")
        result["verified_inputs"] = observed_inputs
        result["status"] = "passed"
        stage = "complete"
    except BaseException as error:
        result["failure_code"] = fixed_error(error)
        result["failure_stage"] = stage
        result["status"] = "failed"
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if owner is not None:
            result["owned_cleanup"] = owner.cleanup()
            result["child_provenance"] = owner.child_provenance
            result["child_exec_visibility"] = owner.child_exec_visibility
        result["all_owned_stopped"] = all(item.get("owned_stopped") is True
                                         and item.get("direct_child_reaped") is True
                                         for item in result["owned_cleanup"])
        # A close failure remains represented by an open descriptor. Do not
        # synthesize successful closure or repeat any child command.
        result["all_input_fds_closed"] = not OPEN_FDS and not FD_CLOSE_FAILED
        result["incomplete_command_labels"] = sorted(
            {item["label"] for item in result["command_intents"]}
            - {item["label"] for item in result["commands"]})
        result["command_outcome_unknown"] = bool(result["incomplete_command_labels"]) or not result["all_owned_stopped"]
        finished = time.monotonic_ns()
        result["completed_monotonic_ns"] = finished
        result["completed_within_original_build_deadline"] = finished < until
        if not (result["all_owned_stopped"] and result["all_input_fds_closed"]
                and not result["command_outcome_unknown"]
                and result["completed_within_original_build_deadline"]):
            result["status"] = "failed"
        encoded = write_json(ROOT / "result.public.json", result)
        print(json.dumps({"status": result["status"], "result": str(ROOT / "result.public.json"),
                          "result_sha256": sha(encoded), "all_owned_stopped": result["all_owned_stopped"],
                          "all_input_fds_closed": not OPEN_FDS and not FD_CLOSE_FAILED,
                          "product_or_http_requests": 0,
                          "completed_within_original_build_deadline": time.monotonic_ns() < until},
                         sort_keys=True), flush=True)
    return 0 if (result["status"] == "passed" and not OPEN_FDS and not FD_CLOSE_FAILED
                 and time.monotonic_ns() < until) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"status": "failed_before_or_after_owned_build",
                          "failure_code": fixed_error(error),
                          "runtime_qualification": False,
                          "all_input_fds_closed": not OPEN_FDS and not FD_CLOSE_FAILED}, sort_keys=True), flush=True)
        raise SystemExit(2) from None
