#!/usr/bin/env python3
"""MAIN -> Mac: install the frozen R8n shared reuse tree and run exactly 13 real shared-ciphertext tests.

The root owner reviews and executes this program on MAIN. It makes one
StrictHostKeyChecking SSH invocation; the Mac worker receives this same source
and the pinned overlay through private stdin. Both output directories and the
Mac destination source directory must be new. Existing source-r8m is read only.
No Git, deployment, retries, cargo clean, or unrelated process termination occurs.
"""

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import signal
import stat
import subprocess
import sys
import time


COMMIT = "a6b8990d40bac15b1d9a066dc2303658d73372cb"
TREE = "9277b345ca1f9c1117b03332958b51b7c25ed772"
PARENT = "090da802ce1d26c890f7c4100623f05bf488002f"
BASE_COMMIT = "090da802ce1d26c890f7c4100623f05bf488002f"
BASE_TREE = "f8413d46654dde2425260d044f0000ad3a2fda87"
ORIGINAL_BASE_COMMIT = "090da802ce1d26c890f7c4100623f05bf488002f"
OVERLAY_SHA = "05cdde442d3f7cc958edc1c3e0ad71801176d291299ca369d7caa5abf9369810"
OVERLAY_BYTES = 309512
MANIFEST_SHA = "22a6cd21a6f01ecd5c9ffc49cb5b6457587fc3366395efe2422557c1d0b588bc"
MAC_SECONDS = 1200
MAIN_SECONDS = 1450
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_RETURNED_LOG_BYTES = 8 * 1024 * 1024
FEATURE = "experimental-v6-raft-objects"
MAC_ROOT = "/Volumes/T5/hepta-vnext-recovery-20261013/v6-next-gates-20261017"
TOOLCHAIN = "/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin"
GROUPS = (("checked-existing", "v6_replica_blobs::checked", 13),)
OVERLAY_PATHS = {'crates/heptabao-raft-runtime/src/v6_replica_blobs_existing.rs', 'crates/heptabao-raft-runtime/src/v6_replica_blobs_existing_tests.rs', 'crates/heptabao-raft-runtime/src/v6_replica_blobs_checked.rs'}


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def remaining(deadline):
    value = deadline - time.monotonic()
    require(value > 0, "whole_process_deadline_expired")
    return value


def safe_name(name):
    require(isinstance(name, str), "source_name_not_string")
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and path.as_posix() == name
            and ".." not in path.parts and ".git" not in path.parts
            and "\\" not in name and "\0" not in name,
            "unsafe_source_name")
    return name


def manifest_shape(manifest, count, commit, tree):
    require(isinstance(manifest, dict)
            and manifest.get("schema") == "heptabao.source-freeze.v1"
            and manifest.get("source_commit") == commit
            and manifest.get("source_tree") == tree,
            "source_manifest_identity_mismatch")
    files, modes = manifest.get("files"), manifest.get("modes")
    require(isinstance(files, dict) and isinstance(modes, dict)
            and len(files) == count and set(files) == set(modes),
            "source_manifest_denominator_mismatch")
    for name, digest in files.items():
        safe_name(name)
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                and modes[name] in ("100644", "100755"),
                "source_manifest_entry_mismatch")


def decode_overlay(data):
    require(len(data) == OVERLAY_BYTES and sha256(data) == OVERLAY_SHA,
            "r8n-shared-01_overlay_byte_binding_mismatch")
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
        decoded = stream.read(8 * 1024 * 1024 + 1)
    require(len(decoded) <= 8 * 1024 * 1024, "overlay_json_too_large")
    value = json.loads(decoded)
    require(value.get("schema") == "heptabao.source-overlay.v1"
            and value.get("base_commit") == BASE_COMMIT
            and value.get("base_tree") == BASE_TREE,
            "overlay_base_identity_mismatch")
    manifest, base = value.get("manifest"), value.get("base_manifest")
    manifest_shape(manifest, 2590, COMMIT, TREE)
    manifest_shape(base, 2588, BASE_COMMIT, BASE_TREE)
    require(manifest.get("base_commit") == PARENT
            and sha256(json_bytes(manifest)) == MANIFEST_SHA,
            "r8n-shared-01_full_manifest_binding_mismatch")
    for field in ("files", "before", "after"):
        require(isinstance(value.get(field), dict)
                and set(value[field]) == OVERLAY_PATHS,
                "overlay_must_contain_exactly_three_paths")
    changed = {name for name in set(base["files"]) | set(manifest["files"])
               if (base["files"].get(name), base["modes"].get(name))
               != (manifest["files"].get(name), manifest["modes"].get(name))}
    require(changed == OVERLAY_PATHS and set(base["files"]) <= set(manifest["files"]),
            "unexpected_manifest_delta")
    files = {}
    for name in sorted(OVERLAY_PATHS):
        require(value["before"][name] == base["files"].get(name)
                and value["after"][name] == manifest["files"][name],
                "overlay_before_after_mismatch")
        raw = base64.b64decode(value["files"][name], validate=True)
        require(sha256(raw) == manifest["files"][name], "overlay_content_mismatch")
        files[name] = raw
    return value, files


def canonical_directory(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path
            and path.is_dir() and not path.is_symlink(), "directory_not_canonical")
    return path


def new_directory(path):
    path = Path(path)
    canonical_directory(path.parent)
    require(path.is_absolute() and not path.exists() and not path.is_symlink(),
            "destination_directory_must_be_new")
    path.mkdir(mode=0o700)
    sync_directory(path.parent)
    return path


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, deadline, maximum=None):
    remaining(deadline)
    require(path.resolve(strict=True) == path, "file_symlink_or_alias")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), "file_not_regular")
        if maximum is not None:
            require(before.st_size <= maximum, "file_exceeds_input_bound")
        pieces, observed = [], 0
        while True:
            remaining(deadline)
            piece = stream.read(64 * 1024)
            if not piece:
                break
            observed += len(piece)
            require(observed <= before.st_size, "file_grew_during_read")
            pieces.append(piece)
        data = b"".join(pieces)
        require(len(data) == before.st_size
                and file_identity(before) == file_identity(os.fstat(stream.fileno()))
                == file_identity(path.lstat()), "file_changed_during_read")
    remaining(deadline)
    return data, before


def write_new(path, data, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, mode), "wb") as output:
        output.write(data)
        output.flush()
        os.fchmod(output.fileno(), mode)
        os.fsync(output.fileno())
    sync_directory(path.parent)


def git_tree_digest(entries):
    """Compute Git's tree identity from observed blob bytes/modes, without Git."""
    root = {}
    for name, (mode, object_id) in entries.items():
        parts = PurePosixPath(safe_name(name)).parts
        directory = root
        for part in parts[:-1]:
            directory = directory.setdefault(part, {})
            require(isinstance(directory, dict), "source_file_directory_collision")
        require(parts[-1] not in directory, "duplicate_source_tree_entry")
        directory[parts[-1]] = (mode, object_id)

    def fold(directory):
        values = []
        for name, entry in directory.items():
            encoded = name.encode("utf-8")
            if isinstance(entry, dict):
                mode, object_id, order = "40000", fold(entry), encoded + b"/"
            else:
                mode, object_id = entry
                order = encoded
            values.append((order, mode.encode("ascii") + b" " + encoded + b"\0"
                           + bytes.fromhex(object_id)))
        raw = b"".join(value for _, value in sorted(values))
        return hashlib.sha1(b"tree " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    return fold(root)


def verify_source(root, manifest, deadline):
    canonical_directory(root)
    seen, entries, total = set(), {}, 0
    for parent, directories, names in os.walk(root, followlinks=False):
        remaining(deadline)
        for name in directories:
            require(not (Path(parent) / name).is_symlink(), "source_symlink_directory")
        for name in names:
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            require(relative in manifest["files"], "unexpected_source_file:" + relative)
            data, info = read_file(path, deadline)
            mode = manifest["modes"][relative]
            require(stat.S_IMODE(info.st_mode) == (0o755 if mode == "100755" else 0o644)
                    and sha256(data) == manifest["files"][relative],
                    "source_mode_or_content_mismatch:" + relative)
            seen.add(relative)
            total += len(data)
            entries[relative] = (mode, hashlib.sha1(
                b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest())
    require(seen == set(manifest["files"]), "source_file_set_mismatch")
    tree = git_tree_digest(entries)
    require(tree == manifest["source_tree"], "actual_source_git_tree_mismatch")
    return {"files": len(seen), "bytes": total, "tree": tree,
            "all_sha256_and_modes_verified": True}


def install_source(base_root, destination, overlay, replacements, deadline):
    manifest, base = overlay["manifest"], overlay["base_manifest"]
    destination = new_directory(destination)
    for name in sorted(manifest["files"]):
        remaining(deadline)
        path = destination / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if name in replacements:
            data, original_info = replacements[name], None
        else:
            data, original_info = read_file(base_root / name, deadline)
            require(sha256(data) == base["files"][name]
                    and base["modes"][name] == manifest["modes"][name],
                    "base_changed_while_copying:" + name)
        require(sha256(data) == manifest["files"][name], "installed_source_bytes_mismatch")
        mode = 0o755 if manifest["modes"][name] == "100755" else 0o644
        write_new(path, data, mode)
        if original_info is not None:
            copied = path.lstat()
            require((copied.st_dev, copied.st_ino) != (original_info.st_dev, original_info.st_ino),
                    "installed_source_cannot_hardlink_the_base")
    for parent, _, _ in os.walk(destination, topdown=False):
        sync_directory(Path(parent))
    return destination


def terminate_owned(process):
    """Only a process group created by this worker with start_new_session."""
    if process.poll() is not None:
        return False
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return False
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    return True


def run_owned_log(command, source, environment, path, deadline):
    started = time.monotonic()
    remaining(deadline)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    timed_out, oversized, terminated = False, False, False
    process = None
    with os.fdopen(os.open(path, flags, 0o600), "wb") as log:
        try:
            process = subprocess.Popen(command, cwd=source, env=environment,
                                       stdin=subprocess.DEVNULL, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            while process.poll() is None:
                timed_out = time.monotonic() >= deadline
                oversized = path.stat().st_size > MAX_LOG_BYTES
                if timed_out or oversized:
                    terminated = terminate_owned(process)
                    break
                time.sleep(min(0.2, max(0.001, deadline - time.monotonic())))
            returncode = process.wait()
        finally:
            if process is not None and process.poll() is None:
                terminated = terminate_owned(process) or terminated
            log.flush()
            os.fsync(log.fileno())
    return {"command": command, "owned_pid": process.pid, "owned_process_group": process.pid,
            "exit_code": returncode, "timed_out": timed_out,
            "log_limit_exceeded": oversized, "own_process_group_terminated": terminated,
            "elapsed_seconds": round(time.monotonic() - started, 3)}


def parse_test_summary(data, count):
    value = data.decode("utf-8", errors="replace")
    summaries = re.findall(r"(?m)^test result: .*?$", value)
    running = re.findall(r"(?m)^running ([0-9]+) tests?$", value)
    expected = (r"test result: ok\. " + str(count)
                + r" passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;.*")
    return {"summaries": summaries, "running_test_counts": running,
            "expected_tests": count,
            "denominator_and_summary_ok": len(summaries) == 1
            and re.fullmatch(expected, summaries[0]) is not None and running == [str(count)]}


def log_payload(path, deadline):
    data, _ = read_file(path, deadline)
    complete = len(data) <= MAX_RETURNED_LOG_BYTES
    returned = data if complete else data[-64 * 1024:]
    return {"path": str(path), "bytes": len(data), "sha256": sha256(data),
            "content_complete": complete, "returned_bytes": len(returned),
            "returned_sha256": sha256(returned),
            "content_base64": base64.b64encode(returned).decode("ascii")}


def mac_worker(packet):
    started = time.monotonic()
    deadline = started + MAC_SECONDS
    os.umask(0o077)
    logs, log_paths = {}, {}
    work = base_root = source = overlay = None
    receipt = {
        "schema": "heptabao.r8n-shared-01-mac-existing-ciphertext.v1", "ok": False,
        "source_commit": COMMIT, "source_tree": TREE, "source_manifest_sha256": MANIFEST_SHA,
        "overlay_sha256": OVERLAY_SHA, "overlay_base_commit": BASE_COMMIT,
        "overlay_base_tree": BASE_TREE, "host": platform.node(),
        "platform": platform.platform(), "machine": platform.machine(),
        "python_version": platform.python_version(), "worker_deadline_seconds": MAC_SECONDS,
        "cargo_build_jobs": 2, "groups": [
            {"group": name, "filter": filter_name, "expected_tests": count, "status": "not_run"}
            for name, filter_name, count in GROUPS],
        "service_http_recovery_enabled": False, "physical_89_executed": False,
        "production_cutover": False, "test_request_seconds": 15,
        "native_readindex_seconds": 8, "test_deadlines_modified": False,
    }
    try:
        require(packet.get("schema") == "heptabao.r8n-shared-01-mac-request.v1", "bad_worker_packet")
        config = packet["config"]
        worker = base64.b64decode(packet["worker_base64"], validate=True)
        require(sha256(worker) == packet["worker_sha256"], "worker_source_sha_mismatch")
        receipt["worker_sha256"] = sha256(worker)
        require(platform.system() == "Darwin" and platform.machine() == "arm64",
                "worker_must_run_on_actual_native_mac")
        raw_overlay = base64.b64decode(packet["overlay_base64"], validate=True)
        overlay, replacements = decode_overlay(raw_overlay)
        base_root = canonical_directory(config["base_root"])
        target = canonical_directory(config["target_dir"])
        cargo_home = canonical_directory(config["cargo_home"])
        destination = Path(config["source_root"])
        work_path = Path(config["work_root"])
        require(destination.is_absolute() and work_path.is_absolute()
                and destination != base_root and destination not in base_root.parents
                and base_root not in destination.parents
                and destination != target and destination not in target.parents
                and target not in destination.parents
                and destination != work_path and destination not in work_path.parents
                and work_path not in destination.parents
                and base_root != work_path and base_root not in work_path.parents,
                "source_work_or_target_roots_overlap")
        require(not destination.exists() and not destination.is_symlink(),
                "source_r8n-shared-01_destination_already_exists")
        work = new_directory(work_path)
        receipt.update(source_root=str(destination), base_root=str(base_root), work_root=str(work),
                       target_dir=str(target), cargo_home=str(cargo_home),
                       worker_sha256=sha256(worker))
        write_new(work / "run_native_shared_reuse_r8n_01.py", worker)
        write_new(work / "r8n-shared-01-source-overlay.json.gz", raw_overlay)
        write_new(work / "r8n-shared-01-source-manifest.json", json_bytes(overlay["manifest"]))
        write_new(work / "r8m-base-manifest.json", json_bytes(overlay["base_manifest"]))
        observed = {"path": None, "source_commit": None,
                    "identity_basis": "actual_complete_files_modes_and_git_tree"}
        if config.get("base_manifest"):
            observed_path = Path(config["base_manifest"])
            raw, _ = read_file(observed_path, deadline, 2 * 1024 * 1024)
            previous = json.loads(raw)
            previous_commit = previous.get("source_commit")
            require(previous_commit in (ORIGINAL_BASE_COMMIT, BASE_COMMIT),
                    "unexpected_retained_r8k_commit")
            manifest_shape(previous, 2588, previous_commit, BASE_TREE)
            require(previous["files"] == overlay["base_manifest"]["files"]
                    and previous["modes"] == overlay["base_manifest"]["modes"],
                    "retained_r8k_manifest_contents_differ")
            observed.update(path=str(observed_path), source_commit=previous_commit,
                            sha256=sha256(raw), source_tree=BASE_TREE,
                            original_receipt_rewritten=False)
        receipt["retained_base_manifest"] = observed
        receipt["base_before"] = verify_source(base_root, overlay["base_manifest"], deadline)
        source = install_source(base_root, destination, overlay, replacements, deadline)
        receipt["source_before"] = verify_source(source, overlay["manifest"], deadline)
        receipt["installed_by_independent_copies"] = True
        environment = dict(os.environ)
        for name in ("CARGO_BUILD_TARGET", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                     "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS",
                     "CARGO_ENCODED_RUSTDOCFLAGS"):
            environment.pop(name, None)
        cargo, rustc, cmake = (Path(config[name]) for name in ("cargo", "rustc", "cmake"))
        tool_info = {}
        for name, executable in (("cargo", cargo), ("rustc", rustc), ("cmake", cmake)):
            require(executable.is_absolute() and executable.is_file()
                    and os.access(executable, os.X_OK), "toolchain_executable_unavailable:" + name)
            resolved = executable.resolve(strict=True)
            data, _ = read_file(resolved, deadline)
            tool_info[name] = {"path": str(executable), "resolved_path": str(resolved),
                               "sha256": sha256(data)}
        temporary = new_directory(work / "tmp")
        environment.update(
            PATH=str(cargo.parent) + ":/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(target), RUSTC=str(rustc),
            CMAKE=str(cmake), CARGO_BUILD_JOBS="2", CARGO_TERM_COLOR="never",
            NO_COLOR="1", TERM="dumb", TMPDIR=str(temporary),
        )
        versions = {}
        for name, command in (("cargo", [str(cargo), "-V"]),
                              ("rustc", [str(rustc), "-vV"]),
                              ("cmake", [str(cmake), "--version"])):
            path = work / (name + "-version.log")
            log_paths[name + "-version"] = path
            result = run_owned_log(command, source, environment, path,
                                   min(deadline - 60, time.monotonic() + 20))
            require(result["exit_code"] == 0 and not result["timed_out"],
                    "tool_version_failed:" + name)
            versions[name] = read_file(path, deadline)[0].decode("utf-8", errors="replace")
        require(versions["cargo"].startswith("cargo 1.98.0 ")
                and "release: 1.98.0\n" in versions["rustc"]
                and "host: aarch64-apple-darwin\n" in versions["rustc"],
                "actual_rust_198_native_toolchain_not_verified")
        receipt.update(toolchain=tool_info, versions=versions, native_abi="aarch64-apple-darwin")
        write_new(work / "start-receipt.json", json_bytes(receipt))
        for index, (name, filter_name, count) in enumerate(GROUPS):
            remaining(deadline - 60)
            command = [str(cargo), "test", "--locked", "--offline", "-p", "heptabao-raft-runtime",
                       "--lib", "--features", FEATURE, filter_name, "--", "--nocapture",
                       "--test-threads=1", "--color=never"]
            path = work / (name + ".log")
            log_paths[name] = path
            receipt["groups"][index].update(status="started", command=command, log_path=str(path))
            result = run_owned_log(command, source, environment, path, deadline - 60)
            data = read_file(path, deadline)[0]
            result.update(parse_test_summary(data, count))
            result.update(group=name, filter=filter_name, log_path=str(path),
                          log_sha256=sha256(data), log_bytes=len(data), status="completed")
            result["ok"] = (result["exit_code"] == 0 and not result["timed_out"]
                            and not result["log_limit_exceeded"]
                            and result["denominator_and_summary_ok"])
            receipt["groups"][index] = result
            require(result["ok"], "actual_cargo_group_failed:" + name)
        receipt["tests_passed"] = 13
    except BaseException as error:
        receipt["error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        for key, root, manifest in (
            ("base_after", base_root, overlay["base_manifest"] if overlay else None),
            ("source_after", source, overlay["manifest"] if overlay else None),
        ):
            if root is not None and manifest is not None:
                try:
                    receipt[key] = verify_source(root, manifest, deadline)
                except BaseException as error:
                    receipt[key + "_error"] = (str(error) if isinstance(error, RuntimeError)
                                               else type(error).__name__)
        receipt["base_unchanged"] = bool(receipt.get("base_before")
                                          and receipt.get("base_before") == receipt.get("base_after"))
        receipt["source_unchanged"] = bool(receipt.get("source_before")
                                            and receipt.get("source_before") == receipt.get("source_after"))
        for name, path in log_paths.items():
            try:
                logs[name] = log_payload(path, deadline)
            except BaseException as error:
                receipt.setdefault("log_return_errors", {})[name] = type(error).__name__
        receipt["logs"] = {name: {key: value for key, value in item.items()
                                  if key != "content_base64"} for name, item in logs.items()}
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        receipt["ok"] = (not receipt.get("error") and not receipt.get("log_return_errors")
                         and receipt["base_unchanged"] and receipt["source_unchanged"]
                         and all(group.get("ok") is True for group in receipt["groups"])
                         and receipt.get("tests_passed") == 13)
        raw_receipt = json_bytes(receipt)
        if work is not None:
            write_new(work / "summary.json", raw_receipt)
        print(json.dumps({"schema": "heptabao.r8n-shared-01-mac-result.v1", "receipt": receipt,
                          "receipt_sha256": sha256(raw_receipt), "logs": logs}, sort_keys=True),
              flush=True)
    return 0 if receipt["ok"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--overlay", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--ssh-host", default="macbook-pro")
    parser.add_argument("--mac-python", default="python3")
    parser.add_argument("--mac-base-root", default=MAC_ROOT + "/source-r8m")
    parser.add_argument("--mac-source-root", default=MAC_ROOT + "/source-r8n-shared-01")
    parser.add_argument("--mac-work-root", default=MAC_ROOT + "/r8n-shared-reuse-verify-01")
    parser.add_argument("--mac-base-manifest")
    parser.add_argument("--mac-cargo", default=TOOLCHAIN + "/cargo")
    parser.add_argument("--mac-rustc", default=TOOLCHAIN + "/rustc")
    parser.add_argument("--mac-cmake", default="/opt/homebrew/bin/cmake")
    parser.add_argument("--mac-cargo-home", default="/Volumes/T5/hepta-vnext-recovery-20261013/r1190-offline-cargo")
    parser.add_argument("--mac-target-dir", default=MAC_ROOT + "/target")
    args = parser.parse_args(argv)
    started, deadline = time.monotonic(), time.monotonic() + MAIN_SECONDS
    os.umask(0o077)
    require(not args.ssh_host.startswith("-")
            and re.fullmatch(r"[A-Za-z0-9_.@-]+", args.ssh_host), "invalid_ssh_destination")
    raw_overlay, _ = read_file(args.overlay, deadline, OVERLAY_BYTES)
    decode_overlay(raw_overlay)
    worker, _ = read_file(Path(__file__).resolve(), deadline, 128 * 1024)
    work = new_directory(args.output_dir)
    config = {name: getattr(args, "mac_" + name) for name in (
        "base_root", "source_root", "work_root", "base_manifest", "cargo", "rustc",
        "cmake", "cargo_home", "target_dir")}
    packet = {"schema": "heptabao.r8n-shared-01-mac-request.v1", "config": config,
              "worker_base64": base64.b64encode(worker).decode("ascii"),
              "worker_sha256": sha256(worker),
              "overlay_base64": base64.b64encode(raw_overlay).decode("ascii")}
    request = {"schema": packet["schema"], "config": config, "worker_sha256": sha256(worker),
               "overlay_sha256": OVERLAY_SHA, "source_commit": COMMIT, "source_tree": TREE,
               "source_manifest_sha256": MANIFEST_SHA, "ssh_host": args.ssh_host,
               "main_host": platform.node(), "main_python_version": platform.python_version(),
               "outer_deadline_seconds": MAIN_SECONDS}
    write_new(work / "request.json", json_bytes(request))
    bootstrap = (
        "import base64,hashlib,json,sys; "
        "raw=sys.stdin.buffer.read(2*1024*1024+1); "
        "assert len(raw)<=2*1024*1024; p=json.loads(raw); "
        "s=base64.b64decode(p['worker_base64'],validate=True); "
        "assert hashlib.sha256(s).hexdigest()==" + repr(sha256(worker)) + "; "
        "n={'__name__':'heptabao_r8n_shared_mac_worker','__file__':'<r8n-shared-01-stdin-worker>'}; "
        "exec(compile(s,'<r8n-shared-01-stdin-worker>','exec'),n); "
        "sys.exit(n['mac_worker'](p))"
    )
    remote = shlex.quote(args.mac_python) + " -c " + shlex.quote(bootstrap)
    command = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15",
               "-o", "ServerAliveCountMax=3", args.ssh_host, remote]
    stdout_path, stderr_path = work / "ssh-stdout.json", work / "ssh-stderr.log"
    timed_out, own_ssh_terminated = False, False
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                   start_new_session=True)
        try:
            process.communicate(input=json_bytes(packet), timeout=min(1400, remaining(deadline) - 20))
        except subprocess.TimeoutExpired:
            timed_out = True
            own_ssh_terminated = terminate_owned(process)
        finally:
            if process.poll() is None:
                own_ssh_terminated = terminate_owned(process) or own_ssh_terminated
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
    summary = dict(request, schema="heptabao.r8n-shared-01-main-existing-ciphertext.v1", ok=False,
                   ssh_exit_code=process.returncode, ssh_timed_out=timed_out,
                   own_ssh_process_group_terminated=own_ssh_terminated,
                   no_automatic_retry=True, production_cutover=False)
    try:
        raw_result, _ = read_file(stdout_path, deadline, 64 * 1024 * 1024)
        stderr_data, _ = read_file(stderr_path, deadline, 4 * 1024 * 1024)
        summary.update(ssh_stdout_sha256=sha256(raw_result), ssh_stderr_sha256=sha256(stderr_data))
        result = json.loads(raw_result)
        require(result.get("schema") == "heptabao.r8n-shared-01-mac-result.v1", "missing_complete_mac_result")
        receipt = result["receipt"]
        require(receipt.get("source_commit") == COMMIT and receipt.get("source_tree") == TREE
                and receipt.get("source_manifest_sha256") == MANIFEST_SHA
                and receipt.get("worker_sha256") == sha256(worker)
                and sha256(json_bytes(receipt)) == result.get("receipt_sha256"),
                "mac_receipt_binding_mismatch")
        write_new(work / "mac-summary.json", json_bytes(receipt))
        returned = {}
        for name, item in result.get("logs", {}).items():
            require(re.fullmatch(r"[a-z0-9-]+", name), "invalid_returned_log_name")
            data = base64.b64decode(item["content_base64"], validate=True)
            require(len(data) == item["returned_bytes"] and sha256(data) == item["returned_sha256"]
                    and (not item["content_complete"]
                         or (len(data) == item["bytes"] and sha256(data) == item["sha256"])),
                    "returned_log_sha256_mismatch")
            require(receipt.get("logs", {}).get(name)
                    == {key: value for key, value in item.items() if key != "content_base64"},
                    "returned_log_not_bound_to_mac_receipt")
            output = work / (name + (".log" if item["content_complete"] else ".tail.log"))
            write_new(output, data)
            returned[name] = {"main_path": str(output), "main_sha256": sha256(data),
                              "mac_full_sha256": item["sha256"],
                              "full_log_returned": item["content_complete"]}
        require(set(returned) == set(receipt.get("logs", {})), "returned_log_set_mismatch")
        summary.update(mac=receipt, mac_summary_sha256=result["receipt_sha256"], returned_logs=returned)
        summary["ok"] = not timed_out and process.returncode == 0 and receipt.get("ok") is True
    except BaseException as error:
        summary["error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
    write_new(work / "summary.json", json_bytes(summary))
    print(json.dumps(summary, sort_keys=True, indent=2), flush=True)
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
