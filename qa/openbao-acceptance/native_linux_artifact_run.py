#!/usr/bin/env python3
"""Copy frozen native artifacts on their producer; run their exact Linux profile.

Neither subcommand invokes Cargo/rustc or modifies an existing run/source.
The producer and executor, source cohort, byte identities, native loader and
original test results remain separate evidence. Only NEW owned outputs and
synthetic test/server fixtures are created. No credential is supplied.
"""
from __future__ import annotations

import argparse
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import time


ARTIFACT_LIMIT = 2 * 1024 ** 3
LOG_LIMIT = 128 * 1024 ** 2
COMMAND_SECONDS = 1800
PROFILE_PATH = "qa/openbao-acceptance/native_candidate_host_run.py"
ROLES = {"server": ("heptabao-server", "heptabao_server"),
         "peer": ("heptabao-ha-service", "heptabao_ha_service")}
NATIVE_KV2_MOUNT_GROUP = [
    "native-kv2-mount", "server", "service::native_auth::mount_tests::native_kv2_mount_", 3]
RUNTIME_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
               "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


class Refusal(ValueError):
    pass


def need(condition, label):
    if not condition:
        raise Refusal(label)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact_hex(value, size):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(size) + r"}", value) is not None


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink)


def inspect_file(path, *, limit=ARTIFACT_LIMIT, system=False, copy_to=None):
    """Stream bytes; never materialize a GiB-scale libtest in Python memory."""
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_regular_file_required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    output = None
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == (0 if system else os.geteuid())
             and not before.st_mode & 0o022 and (system or before.st_nlink == 1)
             and 0 < before.st_size <= limit, "owned_bounded_regular_file_required")
        if copy_to is not None:
            output = os.open(copy_to, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            need(size <= limit, "input_grew_beyond_declared_bound")
            if output is not None:
                pending = memoryview(chunk)
                while pending:
                    written = os.write(output, pending)
                    need(written > 0, "artifact_copy_stalled")
                    pending = pending[written:]
        need(identity(before) == identity(os.fstat(descriptor)) == identity(path.lstat())
             and size == before.st_size, "input_changed_during_observation")
        if output is not None:
            os.fsync(output)
        return {"sha256": digest.hexdigest(), "bytes": size, "identity": list(identity(before))}
    finally:
        os.close(descriptor)
        if output is not None:
            os.close(output)


def read_owned(path, limit):
    observed = inspect_file(path, limit=limit)
    raw = Path(path).read_bytes()
    need(len(raw) == observed["bytes"] and sha(raw) == observed["sha256"], "metadata_changed_after_checked_read")
    return raw


def write_new(path, value, *, raw=False):
    payload = value if raw else (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def new_root(path):
    need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent
         and not path.exists() and not path.is_symlink(), "new_canonical_output_required")
    parent = path.parent.stat()
    need(parent.st_uid == os.geteuid() and not parent.st_mode & 0o022, "owned_output_parent_required")
    path.mkdir(mode=0o700)
    sync_directory(path.parent)


def profile_test_count(groups):
    """Keep historical 55 receipts distinct from the current 58-case profile.

    The source manifest and runner digest bind the full selector inventory.
    The added mount group must be exact; matching a total alone cannot replace
    its three cases with some other group or relabel an older capsule.
    """
    need(isinstance(groups, list) and all(
        isinstance(row, list) and len(row) == 4
        and isinstance(row[0], str) and bool(row[0])
        and isinstance(row[1], str) and row[1] in ROLES
        and isinstance(row[2], str) and bool(row[2])
        and type(row[3]) is int and row[3] > 0 for row in groups),
        "valid_native_artifact_group_profile_required")
    need(len({row[0] for row in groups}) == len(groups)
         and len({(row[1], row[2]) for row in groups}) == len(groups),
         "unique_native_artifact_groups_required")
    count = sum(row[3] for row in groups)
    mounts = [row for row in groups if row[0] == NATIVE_KV2_MOUNT_GROUP[0]]
    legacy = len(groups) == 17 and count == 55 and not mounts
    current = len(groups) == 18 and count == 58 and mounts == [NATIVE_KV2_MOUNT_GROUP]
    need(legacy or current, "exact_legacy55_or_mount58_profile_required")
    return count


def load_profile(source, manifest_path, commit, tree, runner_sha256):
    need(exact_hex(commit, 40) and exact_hex(tree, 40) and exact_hex(runner_sha256, 64), "exact_source_pins_required")
    need(source.is_absolute() and source.resolve(strict=True) == source
         and source.stat().st_uid == os.geteuid() and not source.stat().st_mode & 0o022,
         "canonical_owned_product_source_required")
    raw = read_owned(manifest_path, 32 * 1024 ** 2)
    manifest = json.loads(raw)
    need(manifest.get("commit") == commit and manifest.get("tree") == tree, "source_manifest_cohort_mismatch")
    entries = [row for row in manifest["files"] if row.get("path") == PROFILE_PATH]
    profile_path = source / PROFILE_PATH
    profile = read_owned(profile_path, 1024 ** 2)
    need(len(entries) == 1 and sha(profile) == runner_sha256
         and hashlib.sha1(b"blob " + str(len(profile)).encode() + b"\0" + profile).hexdigest() == entries[0]["sha"],
         "actual_product_profile_source_mismatch")
    # This exact Git-bound file only imports stdlib and defines functions; its
    # main guard remains false. Suppress pyc writes into the verified source.
    spec = importlib.util.spec_from_file_location("heptabao_pinned_native_profile", profile_path)
    module = importlib.util.module_from_spec(spec)
    prior = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = prior
    groups = [list(row) for row in module.GROUPS]
    profile_test_count(groups)
    return module, manifest, raw, groups


def command_row(summary, label, *, passed=True):
    matches = [row for row in summary["commands"] if row.get("label") == label]
    need(len(matches) == 1, "unique_actual_command_required")
    row = matches[0]
    need(type(row.get("exit_code")) is int and not row.get("timed_out")
         and row.get("status") in ("passed", "failed") and row.get("finished_utc"),
         "completed_original_command_required")
    if passed:
        need(row["status"] == "passed" and row["exit_code"] == 0, "original_required_command_did_not_pass")
    return row


def command_log(directory, row, retained):
    name = row.get("log")
    need(isinstance(name, str) and Path(name).name == name and name.endswith(".log"), "canonical_original_log_required")
    raw = read_owned(directory / name, LOG_LIMIT)
    need(sha(raw) == row.get("log_sha256"), "original_command_log_digest_mismatch")
    first, separator, body = raw.partition(b"\n")
    header = json.loads(first)
    need(separator and isinstance(header, dict) and header.get("argv") == row["argv"], "original_command_header_mismatch")
    retained[name] = raw
    return body.decode("utf-8", errors="strict")


def artifact_from_log(text, prefix, target_dir, *, compiled):
    kind = "Executable" if compiled else "Running"
    matches = re.findall(r"^\s*" + kind + r" unittests src/lib\.rs \(([^\r\n()]+)\)\s*$", text, re.MULTILINE)
    need(len(matches) == 1, "unique_logged_libtest_artifact_required")
    path = Path(matches[0])
    need(path.is_absolute() and path.parent == target_dir / "debug/deps"
         and re.fullmatch(re.escape(prefix) + r"-[0-9a-f]{16,64}", path.name),
         "logged_artifact_outside_exact_owned_target")
    return path


def listed_names(text, expected):
    names = re.findall(r"^([^\r\n]+): test$", text, re.MULTILINE)
    need(len(names) == expected and len(set(names)) == expected, "exact_original_selector_count_required")
    return names


def observed_test_result(text, count):
    """Preserve partial real libtest results without upgrading a failed group."""
    rows = re.findall(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", text)
    if len(rows) != 1:
        return None
    status, passed, failed, ignored = rows[0]
    values = [int(passed), int(failed), int(ignored)]
    if sum(values) != count or (status == "ok" and values[1] != 0) or (status == "FAILED" and values[1] == 0):
        return None
    return {"status": status, "passed": values[0], "failed": values[1], "ignored": values[2]}


def elf_interpreter(path):
    with Path(path).open("rb") as binary:
        header = binary.read(64)
        need(len(header) == 64 and header[:6] == b"\x7fELF\x02\x01", "linux_elf64_little_endian_required")
        fields = struct.unpack("<16sHHIQQQIHHHHHH", header)
        need(fields[1] in (2, 3) and fields[2] == 62 and fields[9] == 56
             and 0 < fields[10] <= 4096, "linux_x86_64_executable_required")
        interpreters = []
        for index in range(fields[10]):
            binary.seek(fields[5] + index * fields[9])
            raw = binary.read(56)
            need(len(raw) == 56, "truncated_elf_program_table")
            program = struct.unpack("<IIQQQQQQ", raw)
            if program[0] == 3:
                need(1 < program[5] <= 4096, "bounded_elf_interpreter_required")
                binary.seek(program[2])
                value = binary.read(program[5])
                need(value[-1:] == b"\0" and b"\0" not in value[:-1], "closed_elf_interpreter_required")
                interpreters.append(value[:-1].decode("ascii"))
        need(interpreters == ["/lib64/ld-linux-x86-64.so.2"], "original_gnu_linux_interpreter_required")
        return interpreters[0]


def bounded_metadata(argv, output, label):
    result = subprocess.run(argv, env=RUNTIME_ENV, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
    need(len(result.stdout) <= 8 * 1024 ** 2, "bounded_abi_metadata_required")
    raw = (json.dumps({"argv": argv}) + "\n").encode() + result.stdout
    write_new(output / (label + ".log"), raw, raw=True)
    need(result.returncode == 0, "native_abi_probe_failed_" + label)
    return result.stdout.decode("utf-8", errors="strict"), sha(raw)


def native_abi(path, output, label):
    need(platform.system() == "Linux" and platform.machine() == "x86_64", "actual_linux_x86_64_host_required")
    interpreter = elf_interpreter(path)
    file_text, file_sha = bounded_metadata(["/usr/bin/file", "--brief", str(path)], output, label + "-file")
    need("ELF 64-bit" in file_text and "x86-64" in file_text, "native_file_format_mismatch")
    readelf, readelf_sha = bounded_metadata(["/usr/bin/readelf", "--wide", "--file-header", "--program-headers",
                                            "--dynamic", "--version-info", "--notes", str(path)], output, label + "-readelf")
    need(not re.search(r"\((?:RPATH|RUNPATH)\)", readelf), "producer_private_loader_search_path_not_admitted")
    needed = re.findall(r"\(NEEDED\).*Shared library: \[([^\]\r\n]+)\]", readelf)
    need(len(needed) <= 128 and len(set(needed)) == len(needed), "bounded_unique_elf_needed_required")
    loader_path = Path(interpreter).resolve(strict=True)
    loader_identity = inspect_file(loader_path, limit=64 * 1024 ** 2, system=True)
    listing, loader_sha = bounded_metadata([interpreter, "--list", str(path)], output, label + "-loader")
    dependencies = []
    for line in listing.splitlines():
        if re.fullmatch(r"\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)\s*", line):
            continue
        match = re.fullmatch(r"\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)\s*", line)
        need(match is not None, "unresolved_or_unexpected_loader_dependency")
        actual = Path(match[2]).resolve(strict=True)
        need(str(actual).startswith(("/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/")),
             "non_system_native_dependency_rejected")
        observed = inspect_file(actual, limit=128 * 1024 ** 2, system=True)
        dependencies.append({"soname": match[1] or Path(match[2]).name,
                             "loader_path": match[2], "actual_path": str(actual), **observed})
    need(set(needed).issubset({row["soname"] for row in dependencies}), "needed_library_not_resolved")
    return {"native_abi": "x86_64-unknown-linux-gnu", "interpreter": interpreter,
            "actual_loader_path": str(loader_path), "loader_identity": loader_identity,
            "needed": needed, "dependencies": dependencies, "libc_observation": list(platform.libc_ver()),
            "file_log_sha256": file_sha, "readelf_log_sha256": readelf_sha,
            "loader_log_sha256": loader_sha, "loader_resolution_exit_code": 0,
            "application_entry_point_executed": False}


def expected_cargo(profile, owner):
    features = profile.SERVER_FEATURES if owner == "server" else profile.PEER_FEATURES
    return ["test", "--locked", "--offline", "-p", ROLES[owner][0], "--lib", "--features", features]


def producer_inventory(summary, directory, target, profile, groups):
    retained, artifacts, selections = {}, {}, []
    for owner, (_package, prefix) in ROLES.items():
        row = command_row(summary, "compile-" + owner + "-tests")
        need(row["argv"][1:] == expected_cargo(profile, owner) + ["--no-run"], "original_compile_flags_mismatch")
        log = command_log(directory, row, retained)
        artifacts[owner] = artifact_from_log(log, prefix, target, compiled=True)
    for label, owner, selector, count in groups:
        listing = command_row(summary, label + "-list")
        need(listing["argv"][1:] == expected_cargo(profile, owner) + [selector, "--", "--list", "--color=never"],
             "original_list_selector_or_flags_mismatch")
        text = command_log(directory, listing, retained)
        names = listed_names(text, count)
        need(artifact_from_log(text, ROLES[owner][1], target, compiled=False) == artifacts[owner]
             and names == listing.get("selected_test_names")
             and type(listing.get("expected_count")) is int and listing["expected_count"] == count,
             "original_list_artifact_or_name_inventory_mismatch")
        executed = command_row(summary, label, passed=False)
        need(executed["argv"][1:] == expected_cargo(profile, owner) + [selector, "--", "--nocapture", "--test-threads=1", "--color=never"],
             "original_run_selector_or_flags_mismatch")
        text = command_log(directory, executed, retained)
        need(artifact_from_log(text, ROLES[owner][1], target, compiled=False) == artifacts[owner], "original_executed_artifact_changed")
        selections.append({"label": label, "owner": owner, "selector": selector, "expected_count": count,
                           "producer_selected_test_names": names, "producer_test_status": executed["status"],
                           "producer_test_exit_code": executed["exit_code"],
                           "producer_list_log_sha256": listing["log_sha256"],
                           "producer_run_log_sha256": executed["log_sha256"]})
    build = command_row(summary, "build-server")
    need(build["argv"][1:] == ["build", "--locked", "--offline", "-p", "heptabao-server", "--bin", "heptabao-server",
                              "--features", profile.SERVER_FEATURES], "original_server_build_flags_mismatch")
    command_log(directory, build, retained)
    artifacts["server-bin"] = directory / "heptabao-server"
    need(build.get("binary") == str(artifacts["server-bin"]), "actual_server_build_path_mismatch")
    return artifacts, selections, retained, build


def pack(args):
    profile, manifest, manifest_raw, groups = load_profile(args.source, args.manifest, args.source_commit,
                                                          args.source_tree, args.producer_runner_sha256)
    required_test_count = profile_test_count(groups)
    raw = read_owned(args.summary, 16 * 1024 ** 2)
    need(sha(raw) == args.summary_sha256, "exact_producer_summary_required")
    summary = json.loads(raw)
    need(summary.get("runner_completed") is True and summary.get("source_unchanged") is True
         and summary.get("source_commit") == args.source_commit and summary.get("source_tree") == args.source_tree
         and summary.get("runner_sha256") == args.producer_runner_sha256
         and summary.get("manifest_sha256") == sha(manifest_raw)
         and summary.get("hostname") == platform.node() and summary.get("machine") == platform.machine()
         and summary.get("source") == str(args.source)
         and summary.get("status") in ("passed_scoped_host_recovery", "failed_or_blocked")
         and summary.get("selected_groups") == [row[0] for row in groups], "completed_exact_actual_producer_required")
    for side in ("source_before", "source_after"):
        value = summary.get(side, {})
        need(value.get("commit") == args.source_commit and value.get("tree") == args.source_tree
             and type(value.get("verified_files")) is int and value["verified_files"] == len(manifest["files"]),
             "producer_full_source_freeze_evidence_required")
    need(args.target_dir.resolve(strict=True) == args.target_dir, "canonical_producer_target_required")
    lock_path = args.target_dir / "heptabao-owned-candidate-run.lock"
    descriptor = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        # The existing runner takes the exclusive lock. Never modify its lock
        # record, cancel it, or race the next cooperative build on this target.
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        lock = json.loads(read_owned(lock_path, 65536))
        need(lock.get("pid") == summary.get("runner_pid") and lock.get("source_commit") == args.source_commit
             and lock.get("output") == str(args.summary.parent), "producer_target_lock_identity_mismatch")
        before = profile.verify_tree(args.source, manifest)
        artifacts, selections, retained, build = producer_inventory(summary, args.summary.parent, args.target_dir, profile, groups)
        new_root(args.output)
        write_new(args.output / "producer-summary.json", raw, raw=True)
        write_new(args.output / "product-source-manifest.json", manifest_raw, raw=True)
        for name, body in retained.items():
            write_new(args.output / ("producer-" + name), body, raw=True)
        actual = {}
        for role, original in artifacts.items():
            destination = args.output / role
            observed = inspect_file(original, copy_to=destination)
            copied = inspect_file(destination)
            need(copied["sha256"] == observed["sha256"] and copied["bytes"] == observed["bytes"], "artifact_copy_digest_mismatch")
            if role == "server-bin":
                need(observed["sha256"] == build.get("binary_sha256")
                     and observed["bytes"] == build.get("binary_bytes"), "actual_server_binary_differs_from_producer_receipt")
            actual[role] = {"name": role, "producer_path": str(original), "sha256": observed["sha256"],
                            "bytes": observed["bytes"], "producer_file_identity": observed["identity"],
                            "producer_abi": native_abi(destination, args.output, "producer-" + role)}
            need(inspect_file(original) == observed, "producer_artifact_changed_during_pack")
        after = profile.verify_tree(args.source, manifest)
        inventory = []
        for path in sorted(args.output.iterdir()):
            observed = inspect_file(path, limit=ARTIFACT_LIMIT)
            inventory.append({"name": path.name, "sha256": observed["sha256"], "bytes": observed["bytes"],
                              "mode": stat.S_IMODE(path.stat().st_mode)})
        capsule = {"schema": "heptabao.native-linux-artifact-capsule.v1", "created_utc": utc(),
                   "source_commit": args.source_commit, "source_tree": args.source_tree,
                   "product_manifest_sha256": sha(manifest_raw), "producer_runner_sha256": args.producer_runner_sha256,
                   "producer_summary_sha256": args.summary_sha256, "producer_role": "main",
                   "producer_hostname": platform.node(), "producer_platform": platform.platform(),
                   "producer_machine": platform.machine(), "producer_original_status": summary["status"],
                   "producer_compiler_resource_profile": summary.get("compiler_resource_profile"),
                   "producer_source_before_pack": before, "producer_source_after_pack": after,
                   "producer_target_shared_lock_held": True, "groups": groups, "selections": selections,
                   "required_test_count": required_test_count, "original_command_deadline_seconds": COMMAND_SECONDS,
                   "artifacts": actual, "files": inventory, "packer_sha256": sha(Path(__file__).read_bytes()),
                   "compiler_invocations_by_pack": 0, "executor_tests_performed_by_pack": False,
                   "production_authority": False}
        write_new(args.output / "capsule.json", capsule)
        sync_directory(args.output)
        print(json.dumps({"status": "actual_artifacts_copied", "capsule": str(args.output / "capsule.json"),
                          "capsule_sha256": sha((args.output / "capsule.json").read_bytes()),
                          "required_tests": required_test_count, "executor_tests_performed": False}), flush=True)
        return 0
    finally:
        os.close(descriptor)


def verify_capsule(root, expected_digest, commit, tree, runner, groups):
    required_test_count = profile_test_count(groups)
    need(root.is_absolute() and root.resolve(strict=True) == root and root.stat().st_uid == os.geteuid()
         and not root.stat().st_mode & 0o077, "canonical_private_capsule_required")
    raw = read_owned(root / "capsule.json", 16 * 1024 ** 2)
    need(sha(raw) == expected_digest, "exact_transferred_capsule_digest_required")
    value = json.loads(raw)
    need(value.get("schema") == "heptabao.native-linux-artifact-capsule.v1"
         and value.get("source_commit") == commit and value.get("source_tree") == tree
         and value.get("producer_runner_sha256") == runner and value.get("groups") == groups
         and value.get("required_test_count") == required_test_count
         and value.get("original_command_deadline_seconds") == COMMAND_SECONDS
         and value.get("producer_role") == "main" and value.get("producer_target_shared_lock_held") is True
         and value.get("production_authority") is False, "transferred_capsule_profile_mismatch")
    expected = {}
    for row in value["files"]:
        name = row.get("name")
        need(isinstance(name, str) and Path(name).name == name and name not in ("", ".", "..", "capsule.json")
             and name not in expected and row.get("mode") in (0o600, 0o700), "unique_flat_capsule_file_inventory_required")
        observed = inspect_file(root / name)
        need(observed["sha256"] == row.get("sha256") and observed["bytes"] == row.get("bytes")
             and stat.S_IMODE((root / name).stat().st_mode) == row["mode"], "transferred_artifact_changed")
        expected[name] = observed
    need({p.name for p in root.iterdir()} == set(expected) | {"capsule.json"}
         and set(value["artifacts"]) == {"server", "peer", "server-bin"}, "closed_capsule_inventory_required")
    for role, row in value["artifacts"].items():
        need(row.get("name") == role and expected.get(role, {}).get("sha256") == row.get("sha256")
             and expected[role]["bytes"] == row.get("bytes")
             and stat.S_IMODE((root / role).stat().st_mode) == 0o700, "capsule_artifact_role_binding_mismatch")
    need(expected.get("producer-summary.json", {}).get("sha256") == value.get("producer_summary_sha256")
         and expected.get("product-source-manifest.json", {}).get("sha256") == value.get("product_manifest_sha256"),
         "capsule_original_evidence_binding_mismatch")
    return value, expected


def proc_identity(pid):
    """Read only kernel identity fields; no command/environment inventory."""
    root = Path("/proc") / str(pid)
    try:
        raw = (root / "stat").read_bytes()
        uid = root.stat().st_uid
    except FileNotFoundError:
        return None
    need(len(raw) <= 8192, "bounded_process_identity_required")
    prefix, separator, remaining = raw.rpartition(b") ")
    fields = remaining.split()
    need(separator and len(fields) >= 20 and prefix.split(b" ", 1)[0] == str(pid).encode(),
         "kernel_process_identity_malformed")
    return {"pid": pid, "ppid": int(fields[1]), "pgid": int(fields[2]), "sid": int(fields[3]),
            "start_ticks": int(fields[19]), "uid": uid, "state": fields[0].decode("ascii")}


def session_identity(row):
    return {key: row[key] for key in ("pid", "ppid", "pgid", "sid", "start_ticks", "uid")}


def retain_owned_session(process):
    owner = proc_identity(process.pid)
    need(process.returncode is None and owner is not None and owner["ppid"] == os.getpid()
         and owner["pgid"] == owner["sid"] == process.pid and owner["uid"] == os.geteuid(),
         "new_owned_unreaped_session_required")
    return session_identity(owner)


def observed_owned_exit(process):
    need(process.returncode is None, "owner_was_reaped_before_group_cleanup")
    # WNOWAIT keeps the child leader's PID reserved until final group cleanup.
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


def wait_owned_exit(process, deadline):
    while time.monotonic() < deadline:
        event = observed_owned_exit(process)
        if event is not None:
            need(time.monotonic() < deadline, "response_after_original_command_deadline")
            return event.si_status if event.si_code == os.CLD_EXITED else -event.si_status
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    raise subprocess.TimeoutExpired(process.args, COMMAND_SECONDS)


def live_owned_group(owner, deadline):
    current = proc_identity(owner["pid"])
    need(current is not None and session_identity(current) == owner, "owned_leader_identity_changed_no_signal")
    members = []
    with os.scandir("/proc") as entries:
        for entry in entries:
            need(time.monotonic() < deadline, "original_cleanup_observation_deadline_expired")
            if not entry.name.isdecimal():
                continue
            row = proc_identity(int(entry.name))
            if row is not None and row["pgid"] == owner["pgid"]:
                need(row["sid"] == owner["sid"] and row["uid"] == owner["uid"]
                     and row["start_ticks"] >= owner["start_ticks"], "owned_group_member_identity_mismatch")
                if row["state"] != "Z":
                    members.append(row["pid"])
    return sorted(members)


def stop_owned(process, owner):
    receipt = {"leader_pid": process.pid, "owned_session_identity": owner, "leader_reaped": False,
               "owned_live_group_empty": False, "term_seconds": 5, "kill_seconds": 5, "signals": []}
    need(process.returncode is None, "reaped_leader_refuses_numeric_group_signal")
    current = retain_owned_session(process)
    need(current == owner, "owned_leader_identity_changed_no_signal")
    # The unreaped leader pins PID/SID/PGID even after normal completion. No
    # signal is sent after that leader is reaped or to a group found by name.
    started = time.monotonic()
    term_until, kill_until = started + 5, started + 10
    observation_error = None
    try:
        remaining = live_owned_group(owner, term_until)
        receipt["live_group_before"] = remaining
    except (OSError, Refusal) as error:
        remaining = [process.pid]
        observation_error = str(error) if isinstance(error, Refusal) else type(error).__name__
    os.killpg(process.pid, signal.SIGTERM)
    receipt["signals"].append("SIGTERM")
    while remaining and time.monotonic() < term_until:
        try:
            remaining = live_owned_group(owner, term_until)
        except (OSError, Refusal) as error:
            observation_error = str(error) if isinstance(error, Refusal) else type(error).__name__
            break
        if remaining:
            time.sleep(min(0.05, max(0, term_until - time.monotonic())))
    if remaining:
        os.killpg(process.pid, signal.SIGKILL)
        receipt["signals"].append("SIGKILL")
        while remaining and time.monotonic() < kill_until:
            try:
                remaining = live_owned_group(owner, kill_until)
            except (OSError, Refusal) as error:
                observation_error = str(error) if isinstance(error, Refusal) else type(error).__name__
                break
            if remaining:
                time.sleep(min(0.03, max(0, kill_until - time.monotonic())))
    receipt["live_group_before_leader_reap"] = remaining
    receipt["owned_live_group_empty"] = not remaining and observation_error is None and time.monotonic() < kill_until
    if observation_error is not None:
        receipt["group_observation_error"] = observation_error
    receipt["leader_exit_code"] = process.wait(timeout=max(0, kill_until - time.monotonic()))
    receipt["leader_reaped"] = True
    receipt["elapsed_seconds"] = round(time.monotonic() - started, 6)
    return receipt


def execute_command(output, label, argv, cwd, environment, summary, save):
    row = {"label": label, "argv": argv, "cwd": str(cwd), "status": "intent_saved",
           "started_utc": utc(), "timeout_seconds": COMMAND_SECONDS,
           "submission_count": 1, "automatic_retry": False, "log": label + ".log"}
    summary["commands"].append(row)
    save()
    process, owner = None, None
    started = time.monotonic()
    try:
        descriptor = os.open(output / row["log"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((json.dumps({"argv": argv, "cwd": str(cwd)}) + "\n").encode())
            stream.flush()
            process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            owner = retain_owned_session(process)
            row.update(pid=process.pid, status="running")
            save()
            try:
                code = wait_owned_exit(process, started + COMMAND_SECONDS)
            except subprocess.TimeoutExpired:
                row["timed_out"] = True
                code = 124
            row.update(exit_code=code, status="passed" if code == 0 else "failed")
    except BaseException:
        row["status"] = "failed_or_unknown"
        raise
    finally:
        if process is not None:
            try:
                cleanup = stop_owned(process, owner or retain_owned_session(process))
                row["owned_session_cleanup"] = cleanup
                row["owned_child_exit_code"] = cleanup["leader_exit_code"]
                row["owned_child_reaped"] = cleanup["leader_reaped"]
                if cleanup["owned_live_group_empty"] is not True:
                    row["status"] = "failed_or_unknown"
            except BaseException as error:
                row.update(status="failed_or_unknown", owned_cleanup_error=str(error) if isinstance(error, Refusal) else type(error).__name__)
        elapsed = time.monotonic() - started
        row.update(finished_utc=utc(), elapsed_seconds=round(elapsed, 6))
        if elapsed >= COMMAND_SECONDS and row.get("status") == "passed":
            row.update(status="failed", response_after_original_deadline=True)
        if (output / row["log"]).exists():
            observed = inspect_file(output / row["log"], limit=LOG_LIMIT)
            row.update(log_sha256=observed["sha256"], log_bytes=observed["bytes"])
        save()
    need(row.get("owned_session_cleanup", {}).get("owned_live_group_empty") is True
         and row.get("owned_child_reaped") is True, "owned_session_cleanup_not_proven_stop_executor")
    return row, read_owned(output / row["log"], LOG_LIMIT).decode("utf-8", errors="strict")


def load_source_helper(source, manifest, filename, label):
    name = "qa/openbao-acceptance/" + filename
    rows = [row for row in manifest["files"] if row.get("path") == name]
    raw = read_owned(source / name, 1024 ** 2)
    need(len(rows) == 1 and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == rows[0]["sha"],
         "actual_source_helper_blob_mismatch")
    spec = importlib.util.spec_from_file_location(label, source / name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[label] = module
    previous_path, previous_pyc = list(sys.path), sys.dont_write_bytecode
    try:
        sys.path.insert(0, str(source / "qa/openbao-acceptance"))
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.path[:], sys.dont_write_bytecode = previous_path, previous_pyc
    return module, {"path": name, "sha256": sha(raw), "git_blob": rows[0]["sha"]}


def probe_actual_server(source, manifest, binary, output, summary, save):
    # Reuse the cohort's real CA/leaf and complete-health helpers. This small
    # process check remains distinct from the source-bound libtest cases.
    base, base_identity = load_source_helper(source, manifest, "ha_multihost_live.py", "heptabao_artifact_fixture_base")
    probe, probe_identity = load_source_helper(source, manifest, "tls_complete_http_probe.py", "heptabao_artifact_tls_probe")
    root = output / "server-fixture"
    new_root(root)
    ca_key, ca_cert = root / "ca.key", root / "ca.crt"
    base.create_fixture_ca(ca_key, ca_cert)
    with socket.socket() as endpoint:
        endpoint.bind(("127.0.0.1", 0))
        port = endpoint.getsockname()[1]
    node = base.Node(1, "x230-owned-executor", "127.0.0.1", str(root), port, 46231)
    key, cert = base.create_fixture_node_certificate(node, root, ca_key, ca_cert)
    config = {"listen": "127.0.0.1:" + str(port), "data_dir": str(root / "data"),
              "audit_file": str(root / "audit.jsonl"), "tls_cert_file": str(cert), "tls_key_file": str(key),
              "max_connections": 64, "timeout_seconds": 15, "rate_limit_per_second": 2000,
              "rate_limit_burst": 4000, "rate_limit_entries": 512, "lifecycle_interval_seconds": 1}
    write_new(root / "server.json", config)
    record = {"status": "intent_saved", "binary": str(binary), "argv": [str(binary), "--config", str(root / "server.json")],
              "root": str(root), "helpers": [base_identity, probe_identity], "start_submission_count": 1,
              "automatic_retry": False, "initialization_performed": False, "credential_supplied": False,
              "listener_deadline_seconds": 45, "http_deadline_seconds": 15, "production_authority": False}
    summary["actual_server_probe"] = record
    save()
    process, owner = None, None
    try:
        with (root / "process.log").open("xb") as stream:
            process = subprocess.Popen(record["argv"], cwd=root, env=RUNTIME_ENV, stdin=subprocess.DEVNULL,
                                       stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        owner = retain_owned_session(process)
        record.update(pid=process.pid, status="running")
        save()
        deadline = time.monotonic() + 45
        ready = False
        while time.monotonic() < deadline:
            need(observed_owned_exit(process) is None, "owned_server_exited_before_listener")
            text = (root / "process.log").read_bytes()
            need(len(text) <= 1024 ** 2, "bounded_new_server_start_log_required")
            if b"TLS listener ready" in text:
                ready = time.monotonic() < deadline
                break
            time.sleep(0.1)
        need(ready, "original_server_listener_deadline_expired")
        need(os.readlink("/proc/" + str(process.pid) + "/exe") == str(binary)
             and os.getpgid(process.pid) == process.pid, "actual_owned_server_process_identity_mismatch")
        leaf = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
        observed = probe.probe("127.0.0.1", port, node.server_name, ca_cert, leaf, "x230-local-owned-fixture")
        record["complete_health"] = observed
        need(observed.get("passed") is True and observed.get("sealed") is True, "actual_server_complete_health_failed")
        record["status"] = "passed"
    finally:
        if process is not None:
            try:
                cleanup = stop_owned(process, owner or retain_owned_session(process))
                record["owned_session_cleanup"] = cleanup
                record["owned_exit_code"] = cleanup["leader_exit_code"]
                record["owned_process_stopped"] = cleanup["leader_reaped"] and cleanup["owned_live_group_empty"]
                if not record["owned_process_stopped"]:
                    record["status"] = "failed_or_unknown"
            except BaseException as error:
                record.update(status="failed_or_unknown", owned_cleanup_error=str(error) if isinstance(error, Refusal) else type(error).__name__)
        save()


def executor_host():
    cpu = {}
    with Path("/proc/cpuinfo").open() as stream:
        first = stream.read(65536).split("\n\n", 1)[0]
    for line in first.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() in ("model name", "cpu family", "model", "stepping", "flags"):
            cpu[key.strip()] = value.strip()
    return {"hostname": platform.node(), "platform": platform.platform(), "machine": platform.machine(),
            "python": platform.python_version(), "libc": list(platform.libc_ver()), "first_cpu": cpu}


def execute(args):
    profile, manifest, manifest_raw, groups = load_profile(args.source, args.manifest, args.source_commit,
                                                          args.source_tree, args.producer_runner_sha256)
    required_test_count = profile_test_count(groups)
    need(platform.node() == args.expected_executor_hostname, "actual_executor_hostname_mismatch")
    capsule, original_files = verify_capsule(args.capsule, args.capsule_sha256, args.source_commit,
                                              args.source_tree, args.producer_runner_sha256, groups)
    need(capsule["product_manifest_sha256"] == sha(manifest_raw)
         and capsule["producer_hostname"] != platform.node(), "separate_actual_producer_and_executor_required")
    selections = capsule["selections"]
    need([[row.get(k) for k in ("label", "owner", "selector", "expected_count")] for row in selections] == groups,
         "producer_selection_profile_mismatch")
    new_root(args.output)
    temp = args.output / "tmp"
    temp.mkdir(mode=0o700)
    summary = {"schema": "heptabao.native-linux-transferred-artifact-run.v1", "status": "running", "started_utc": utc(),
               "source_commit": args.source_commit, "source_tree": args.source_tree,
               "product_manifest_sha256": sha(manifest_raw), "capsule_sha256": args.capsule_sha256,
               "driver_sha256": sha(Path(__file__).read_bytes()), "producer_runner_sha256": args.producer_runner_sha256,
               "producer_role": "main", "producer_hostname": capsule["producer_hostname"],
               "producer_original_status": capsule["producer_original_status"], "producer_summary_sha256": capsule["producer_summary_sha256"],
               "executor_role": "x230", "executor_host": executor_host(), "compiled_on_executor": False,
               "compiler_invocations_on_executor": 0, "required_test_count": required_test_count, "selected_groups": groups,
               "original_command_deadline_seconds": COMMAND_SECONDS, "commands": [], "tests": [],
               "actual_executor_abi": {}, "production_authority": False, "physical_lan_fault_validation_performed": False,
               "real_credential_validation_performed": False, "full_openbao_271_replacement_proven": False}
    save = lambda: profile.write_json(args.output / "summary.json", summary)
    save()
    try:
        summary["source_before"] = profile.verify_tree(args.source, manifest)
        for role in ("server", "peer", "server-bin"):
            summary["actual_executor_abi"][role] = native_abi(args.capsule / role, args.output, "executor-" + role)
        save()
        for label, owner, selector, count in groups:
            expected = next(row for row in selections if row["label"] == label)
            command = [str(args.capsule / owner), selector]
            # Cargo's libtest working directory is its package root. Runtime
            # paths refer to this independently verified executor source copy;
            # compile-time embedded producer paths are never rewritten.
            cwd = args.source / "crates" / ROLES[owner][0]
            environment = {**RUNTIME_ENV, "TMPDIR": str(temp), "CARGO_MANIFEST_DIR": str(cwd),
                           "CARGO_TARGET_TMPDIR": str(temp)}
            listing, text = execute_command(args.output, label + "-list", command + ["--list", "--color=never"],
                                            cwd, environment, summary, save)
            names = re.findall(r"^([^\r\n]+): test$", text, re.MULTILINE)
            if (listing["status"] != "passed" or len(names) != count or len(set(names)) != count
                    or names != expected["producer_selected_test_names"]):
                summary["tests"].append({"label": label, "status": "blocked", "reason": "exact_original_test_name_inventory_differs",
                                         "expected_count": count, "observed_names": names})
                save()
                continue
            row, text = execute_command(args.output, label, command + ["--nocapture", "--test-threads=1", "--color=never"],
                                        cwd, environment, summary, save)
            terminal = observed_test_result(text, count)
            passed = row["status"] == "passed" and terminal == {"status": "ok", "passed": count, "failed": 0, "ignored": 0}
            summary["tests"].append({"label": label, "status": "passed" if passed else "failed",
                                     "expected_count": count, "actual_selected_test_names": names,
                                     "observed_test_result": terminal, "exit_code": row["exit_code"],
                                     "log_sha256": row["log_sha256"]})
            save()
        probe_actual_server(args.source, manifest, args.capsule / "server-bin", args.output, summary, save)
        summary["runner_completed"] = True
    except BaseException as error:
        summary.update(error=str(error) if isinstance(error, Refusal) else type(error).__name__, status="failed")
    finally:
        try:
            summary["source_after"] = profile.verify_tree(args.source, manifest)
            summary["source_unchanged"] = bool(summary.get("source_before"))
            _, final_files = verify_capsule(args.capsule, args.capsule_sha256, args.source_commit,
                                            args.source_tree, args.producer_runner_sha256, groups)
            summary["capsule_unchanged"] = original_files == final_files
            deps = [item for abi in summary["actual_executor_abi"].values() for item in
                    [{"actual_path": abi["actual_loader_path"], **abi["loader_identity"]}, *abi["dependencies"]]]
            summary["executor_system_dependencies_unchanged"] = all(
                inspect_file(Path(row["actual_path"]), limit=128 * 1024 ** 2, system=True)["sha256"] == row["sha256"] for row in deps)
        except BaseException as error:
            summary.update(final_verification_error=str(error) if isinstance(error, Refusal) else type(error).__name__)
        passed = (summary.get("runner_completed") is True and not summary.get("error")
                  and summary.get("source_unchanged") is True and summary.get("capsule_unchanged") is True
                  and summary.get("executor_system_dependencies_unchanged") is True
                  and len(summary["tests"]) == len(groups) and all(row["status"] == "passed" for row in summary["tests"])
                  and summary.get("actual_server_probe", {}).get("status") == "passed"
                  and summary["actual_server_probe"].get("owned_process_stopped") is True)
        summary.update(status="passed_scoped_transferred_artifacts" if passed else "failed_or_blocked", finished_utc=utc(),
                       actual_passed_test_count=sum((row.get("observed_test_result") or {}).get("passed", 0) for row in summary["tests"]))
        save()
    print(json.dumps({"status": summary["status"], "summary": str(args.output / "summary.json"),
                      "actual_passed_test_count": summary["actual_passed_test_count"], "required_test_count": required_test_count,
                      "compiled_on_executor": False}), flush=True)
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="mode", required=True)
    for name in ("pack", "execute"):
        sub = subcommands.add_parser(name)
        for field in ("source", "manifest", "output"):
            sub.add_argument("--" + field, type=Path, required=True)
        for field in ("source-commit", "source-tree", "producer-runner-sha256"):
            sub.add_argument("--" + field, required=True)
        if name == "pack":
            sub.add_argument("--summary", type=Path, required=True)
            sub.add_argument("--summary-sha256", required=True)
            sub.add_argument("--target-dir", type=Path, required=True)
        else:
            sub.add_argument("--capsule", type=Path, required=True)
            sub.add_argument("--capsule-sha256", required=True)
            sub.add_argument("--expected-executor-hostname", required=True)
    args = parser.parse_args(argv)
    for value in vars(args).values():
        if isinstance(value, Path) and not value.is_absolute():
            parser.error("all filesystem arguments must be absolute")
    def requested_stop(_number, _frame):
        raise InterruptedError("owned_artifact_controller_stop_requested")
    signal.signal(signal.SIGTERM, requested_stop)
    try:
        return pack(args) if args.mode == "pack" else execute(args)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "refused", "error": str(error) if isinstance(error, Refusal) else type(error).__name__,
                          "compiler_invocations": 0}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
