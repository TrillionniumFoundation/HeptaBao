#!/usr/bin/env python3
"""Run exact candidate recovery groups on an owned physical host checkout.

The manifest describes a Git tree materialized without .git metadata. This
runner verifies all blobs, executable modes, directory closure and the root
tree before and after execution. Receipts describe the executed fixture scope;
they never promote a component pass to a production replacement verdict.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback


GROUPS = [
    ("native-kv2-import", "server", "native_kv2_graph_import_", 8),
    ("historical-service", "server", "native_ha_historical_restore_", 6),
    ("snapshot-service", "server", "native_ha_snapshot_", 7),
    ("archive-34mib", "server", "native_ha_archive_real_34mib_dual_pack_roundtrip_and_hostile_inputs", 1),
    ("http-repair-admission", "server", "current_root_repair_retains_binary_header_admission_and_bounded_json_lane", 1),
    ("http-pending-admission", "server", "native_ha_pending_restore_query_reaches_empty_binary_lane_and_rejects_other_routes", 1),
    ("private-transport-diagnostic", "peer", "private_forward_stage_observation_preserves_existing_transport_errors", 1),
    ("private-frame-diagnostic", "peer", "private_frame_diagnostics_preserve_io_order_errors_and_wire_bytes", 1),
]
SERVER_FEATURES = "experimental-native-v6-ha,private-ha-forward-diagnostic"
PEER_FEATURES = "experimental-v6-peer-ingress,private-forward-stage-diagnostic"


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest_file(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_json(path, data):
    temporary = path.with_name(path.name + ".new")
    with temporary.open("w", encoding="utf-8") as stream:
        stream.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def verify_tree(source, manifest):
    wanted = {}
    tree = {}
    for item in manifest["files"]:
        relative = pathlib.PurePosixPath(item["path"])
        if (relative.is_absolute() or ".." in relative.parts or not relative.parts
                or str(relative) != item["path"] or item["path"] in wanted
                or item["mode"] not in ("100644", "100755")):
            raise ValueError("invalid or duplicate manifest path or mode")
        wanted[item["path"]] = item
        path = source / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("missing or non-regular source blob: " + item["path"])
        content = path.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        mode = "100755" if path.stat().st_mode & 0o111 else "100644"
        if actual != item["sha"] or mode != item["mode"]:
            raise ValueError("source blob or mode differs: " + item["path"])
        node = tree
        for component in relative.parts[:-1]:
            child = node.setdefault(component, {})
            if not isinstance(child, dict):
                raise ValueError("manifest file/directory collision")
            node = child
        if relative.name in node:
            raise ValueError("manifest file/directory collision")
        node[relative.name] = (mode, actual)
    actual_paths = set()
    for directory, children, files in os.walk(source, followlinks=False):
        for child in children:
            if (pathlib.Path(directory) / child).is_symlink():
                raise ValueError("symlink source directory")
        for name in files:
            actual_paths.add((pathlib.Path(directory) / name).relative_to(source).as_posix())
    if actual_paths != set(wanted):
        raise ValueError("source closure differs: " + json.dumps({
            "extra": sorted(actual_paths - set(wanted)),
            "missing": sorted(set(wanted) - actual_paths),
        }))

    def hash_tree(node):
        entries = []
        for name, value in node.items():
            if isinstance(value, dict):
                mode, sha, key = "40000", hash_tree(value), name.encode() + b"/"
            else:
                mode, sha = value
                key = name.encode()
            entries.append((key, mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(sha)))
        body = b"".join(value for _, value in sorted(entries))
        return hashlib.sha1(b"tree " + str(len(body)).encode() + b"\0" + body).hexdigest()

    actual_tree = hash_tree(tree)
    if actual_tree != manifest["tree"]:
        raise ValueError("recursive Git tree mismatch")
    return {"verified_at_utc": utc(), "commit": manifest["commit"],
            "tree": actual_tree, "verified_files": len(wanted)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "manifest", "output", "cargo", "rustc", "cargo-home", "target-dir"):
        parser.add_argument("--" + name, required=True, type=pathlib.Path)
    parser.add_argument("--groups", default="all", help="all or comma-separated group labels")
    parser.add_argument("--build-server", action="store_true")
    parser.add_argument("--command-timeout", type=int, default=1800)
    args = parser.parse_args()
    for name in ("source", "manifest", "output", "cargo", "rustc", "cargo_home", "target_dir"):
        path = getattr(args, name)
        if not path.is_absolute():
            parser.error(name + " must be absolute")
    if args.command_timeout != 1800:
        parser.error("this receipt profile fixes the existing per-command build budget at 1800 seconds")
    requested = {entry[0] for entry in GROUPS} if args.groups == "all" else set(filter(None, args.groups.split(",")))
    if requested - {entry[0] for entry in GROUPS} or (not requested and not args.build_server):
        parser.error("unknown group or empty execution request")
    selected = [entry for entry in GROUPS if entry[0] in requested]
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    manifest = json.loads(args.manifest.read_text())
    records = []
    summary = {"status": "running", "started_utc": utc(), "runner_pid": os.getpid(),
               "source": str(args.source), "source_commit": manifest["commit"],
               "source_tree": manifest["tree"], "manifest_sha256": digest_file(args.manifest),
               "runner_sha256": digest_file(pathlib.Path(__file__)), "commands": records,
               "platform": platform.platform(), "machine": platform.machine(),
               "hostname": platform.node(), "python": platform.python_version(),
               "selected_groups": [entry[0] for entry in selected],
               "scope": "Exact-candidate native recovery and import fixtures on this physical host",
               "physical_lan_fault_validation_performed": False,
               "actual_openbao_271_process_migration_performed": False,
               "real_credential_validation_performed": False,
               "production_cutover_performed": False,
               "full_openbao_271_replacement_proven": False}

    def save():
        write_json(args.output / "summary.json", summary)

    env = os.environ.copy()
    for key in ("CARGO_BUILD_TARGET", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        env.pop(key, None)
    env.update(PATH=str(args.rustc.parent) + ":/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
               CARGO_HOME=str(args.cargo_home), CARGO_TARGET_DIR=str(args.target_dir), RUSTC=str(args.rustc),
               CARGO_BUILD_JOBS="2", CMAKE_BUILD_PARALLEL_LEVEL="2", CARGO_TERM_COLOR="never", CARGO_NET_OFFLINE="true")

    def run(label, command):
        record = {"label": label, "argv": [str(item) for item in command], "started_utc": utc(),
                  "status": "running", "log": label + ".log"}
        records.append(record)
        save()
        started = time.monotonic()
        log_path = args.output / record["log"]
        with log_path.open("wb") as stream:
            stream.write((json.dumps({"argv": record["argv"]}) + "\n").encode())
            stream.flush()
            process = subprocess.Popen(record["argv"], cwd=args.source, env=env,
                                       stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            record["pid"] = process.pid
            save()
            try:
                code = process.wait(timeout=args.command_timeout)
            except subprocess.TimeoutExpired:
                record["timed_out"] = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                code = 124
        record.update(exit_code=code, status="passed" if code == 0 else "failed", finished_utc=utc(),
                      elapsed_seconds=round(time.monotonic() - started, 3), log_sha256=digest_file(log_path))
        save()
        print(json.dumps({"label": label, "status": record["status"], "exit_code": code}), flush=True)
        return record

    def blocked(label, reason):
        records.append({"label": label, "status": "blocked", "reason": reason})
        save()

    save()
    lock_stream = None
    try:
        args.target_dir.mkdir(parents=True, exist_ok=True)
        lock_stream = (args.target_dir / "heptabao-owned-candidate-run.lock").open("a+")
        fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_stream.seek(0)
        lock_stream.truncate()
        lock_stream.write(json.dumps({"pid": os.getpid(), "source_commit": manifest["commit"], "output": str(args.output)}) + "\n")
        lock_stream.flush()
        summary["source_before"] = verify_tree(args.source, manifest)
        save()
        run("cargo-version", [args.cargo, "--version", "--verbose"])
        run("rustc-version", [args.rustc, "--version", "--verbose"])
        common = [str(args.cargo), "test", "--locked", "--offline"]
        commands = {
            "server": common + ["-p", "heptabao-server", "--lib", "--features", SERVER_FEATURES],
            "peer": common + ["-p", "heptabao-ha-service", "--lib", "--features", PEER_FEATURES],
        }
        compiled = {}
        for owner in dict.fromkeys(entry[1] for entry in selected):
            compiled[owner] = run("compile-" + owner + "-tests", commands[owner] + ["--no-run"])["exit_code"] == 0
        for label, owner, selector, expected in selected:
            if not compiled[owner]:
                blocked(label, owner + " test compilation failed")
                continue
            command = commands[owner] + [selector]
            listing = run(label + "-list", command + ["--", "--list", "--color=never"])
            text = (args.output / listing["log"]).read_text(errors="replace")
            names = re.findall(r"^([^\r\n]+): test$", text, re.MULTILINE)
            listing.update(expected_count=expected, selected_test_names=names)
            if listing["exit_code"] != 0 or len(names) != expected:
                listing["status"] = "failed"
                blocked(label, "test discovery differs from exact required count")
                continue
            executed = run(label, command + ["--", "--nocapture", "--test-threads=1", "--color=never"])
            text = (args.output / executed["log"]).read_text(errors="replace")
            results = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", text)
            executed.update(expected_count=expected, selected_test_names=names, terminal_test_summaries=results)
            if executed["exit_code"] != 0 or results != [(str(expected), "0", "0")]:
                executed["status"] = "failed"
            save()
        if args.build_server:
            build = run("build-server", [args.cargo, "build", "--locked", "--offline", "-p", "heptabao-server",
                                         "--bin", "heptabao-server", "--features", SERVER_FEATURES])
            if build["exit_code"] == 0:
                binary = args.target_dir / "debug" / "heptabao-server"
                destination = args.output / "heptabao-server"
                if binary.is_symlink() or not binary.is_file():
                    raise RuntimeError("build did not leave a regular requested server binary")
                shutil.copy2(binary, destination)
                if digest_file(binary) != digest_file(destination):
                    raise RuntimeError("built binary changed during owned copy")
                build.update(binary=str(destination), binary_sha256=digest_file(destination), binary_bytes=destination.stat().st_size)
                run("built-binary-format", ["/usr/bin/file", str(destination)])
        summary["runner_completed"] = True
    except BaseException as error:
        summary.update(status="failed", error=str(error))
        (args.output / "runner-error.txt").write_text(traceback.format_exc())
    finally:
        try:
            summary["source_after"] = verify_tree(args.source, manifest)
            summary["source_unchanged"] = bool(summary.get("source_before"))
        except BaseException as error:
            summary.update(source_unchanged=False, source_after_error=str(error))
        passed = (summary.get("runner_completed") and summary.get("source_unchanged") and records
                  and not summary.get("error") and all(item["status"] == "passed" for item in records))
        summary.update(status="passed_scoped_host_recovery" if passed else "failed_or_blocked", finished_utc=utc())
        save()
        if lock_stream is not None:
            lock_stream.close()
    print(json.dumps({"status": summary["status"], "summary": str(args.output / "summary.json")}), flush=True)
    return 0 if summary["status"] == "passed_scoped_host_recovery" else 1


if __name__ == "__main__":
    sys.exit(main())
