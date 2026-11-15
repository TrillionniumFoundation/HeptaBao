#!/usr/bin/env python3
"""One submission of the exact R6 plain-source native55 cohort on main or Mac."""

import argparse
import datetime
import fcntl
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True

BASE_COMMIT = "b24c6de7831a7389e39ac069277a9e85e858ef98"
BASE_TREE = "3356f0a94616e9e1804f497239f33546e16db577"
COMMIT = "07a3dda57c2996787825ced49e630bb0bf7a30b9"
TREE = "8c2b23cd1c66ac16b466f16ea97c201e852125aa"
BASE_MANIFEST_SHA = "739ffe3589e8b8c6ddca5efe56b4ef3d33a2633fce4451853413b14a6be6c3e1"
MANIFEST_SHA = "84c27124f6dc213d2199c7cab5797d5cb22dabf4ad8b2947650ae8fa7928f8a8"
CANDIDATE_SHA = "7545ab85ea2eb6185ab4f4ad1c3fb93164c13b5514bf2595fcbcba97cf062713"
BINDING_SHA = "829b7f513002bea7eb69081906d7331d8a1f30d520f8c163ae58ce52c123be87"
RUNNER_SHA = "587eb864f424b236fbc98e41fbc26c5e6c8713ded2e3dee0f2230df7447f66dd"
RUNNER_PATH = "qa/openbao-acceptance/native_candidate_host_run.py"
MAX_PACKET_BYTES = 8 * 1024 * 1024
STAGING_SECONDS = 120

PROFILES = {
    "main": {
        "root": "/home/qian-qi/heptabao-next-gates-20261017",
        "system": "Linux", "machine": "x86_64", "hostname": "qian-qi",
        "python_version": (3, 12, 3),
        "cargo": "/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo",
        "rustc": "/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc",
        "cargo_home": "/home/qian-qi/.cargo",
        "target": "/home/qian-qi/heptabao-next-gates-20261017/native55-target-20261019",
        "jobs": 8,
    },
    "mac": {
        "root": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261018",
        "system": "Darwin", "machine": "arm64", "hostname": "MacBook-Pro.local",
        "python_version": (3, 14, 3),
        "python_sha256": "cbf84109626aa1013bbe408fbb9590bd0f1c1548f038b2221c6b8b87de26ca43",
        "cargo": "/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin/cargo",
        "rustc": "/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin/rustc",
        "cargo_home": "/Volumes/T5/hepta-vnext-recovery-20261013/r1190-offline-cargo",
        "target": "/Volumes/T5/hepta-vnext-recovery-20261013/v6-next-gates-20261017/target",
        "jobs": 2,
    },
}


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def parse(raw):
    def pairs(items):
        value = {}
        for key, child in items:
            require(key not in value, "duplicate_json_key")
            value[key] = child
        return value
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(RuntimeError("nonfinite_json")))


def relative(value):
    path = PurePosixPath(value)
    require(isinstance(value, str) and path.parts and not path.is_absolute()
            and str(path) == value and ".." not in path.parts
            and "." not in path.parts and "\\" not in value
            and not any(c < " " for c in value)
            and ".git" not in [part.lower() for part in path.parts],
            "noncanonical_manifest_path")
    return path


def owned_directory(path):
    require(path.is_absolute() and path.resolve() == path and path.is_dir()
            and path.stat().st_uid == os.geteuid(), "owned_directory_required:" + str(path))


def exact_regular(path, expected, maximum=MAX_PACKET_BYTES):
    require(not path.is_symlink(), "symlink_input_refused")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum
                and before.st_uid in (0, os.geteuid()), "regular_bounded_input_required")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns), "input_changed_during_read")
    finally:
        os.close(descriptor)
    require(len(raw) == before.st_size and digest(raw) == expected, "input_sha256_differs")
    return raw


def new_file(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def new_json(path, value):
    new_file(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def map_manifest(manifest):
    result = {}
    for row in manifest["files"]:
        path = str(relative(row["path"]))
        require(path not in result and row["mode"] in ("100644", "100755")
                and row.get("type", "blob") == "blob"
                and re.fullmatch("[0-9a-f]{40}", row["sha"]), "invalid_manifest_member")
        result[path] = row
    return result


def validate_delta(base, target, candidate):
    old = map_manifest(base)
    wanted = map_manifest(target)
    require(set(old) <= set(wanted), "source_deletion_not_authorized")
    supplied = {}
    for row in candidate["files"]:
        name = str(relative(row["path"]))
        require(name not in supplied and name in wanted, "duplicate_or_extra_delta")
        require(row["expected_base_git_blob"] == old.get(name, {}).get("sha"),
                "delta_before_blob_differs:" + name)
        raw = row["content"].encode("utf-8")
        require(digest(raw) == row["sha256"] and blob(raw) == row["sha"]
                and len(raw) == row["size"] and row["mode"] == wanted[name]["mode"]
                and row["sha"] == wanted[name]["sha"]
                and len(raw) == wanted[name]["size"], "delta_content_or_target_differs:" + name)
        supplied[name] = row
    expected = {name for name, row in wanted.items()
                if name not in old or (row["sha"], row["mode"]) !=
                (old[name]["sha"], old[name]["mode"])}
    require(set(supplied) == expected, "delta_does_not_cover_exact_target_difference")
    return supplied


def materialize(old_source, new_source, base, target, candidate, checker, until):
    """Stage only an owned new copy, preserving the original on every path."""
    require(not os.path.lexists(new_source), "new_source_already_exists")
    changes = validate_delta(base, target, candidate)
    require(time.monotonic() < until, "original_staging_deadline_expired")
    before = checker.verify_tree(old_source, base)
    # verify_tree rejects extra entries and symlinks before any copy is made.
    shutil.copytree(old_source, new_source, copy_function=shutil.copy2, symlinks=False)
    for name, row in changes.items():
        require(time.monotonic() < until, "original_staging_deadline_expired")
        target_path = new_source / relative(name)
        target_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not target_path.is_symlink(), "staged_symlink_refused")
        target_path.write_bytes(row["content"].encode("utf-8"))
        target_path.chmod(0o755 if row["mode"] == "100755" else 0o644)
    actual = checker.verify_tree(new_source, target)
    after = checker.verify_tree(old_source, base)
    require(time.monotonic() < until, "original_staging_deadline_expired")
    return {"source_before": before, "source_after": after, "candidate": actual,
            "changed_files": len(changes), "old_source_unchanged": True,
            "source_verified_before_launch": True}


def load_packet(path, expected):
    compressed = exact_regular(path, expected)
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        raw = stream.read(MAX_PACKET_BYTES + 1)
    require(len(raw) <= MAX_PACKET_BYTES, "decompressed_packet_too_large")
    packet = parse(raw)
    require(packet["schema"] == "heptabao.exact-r6-materialization.v1", "packet_schema_differs")
    documents = {}
    for name, expected_sha in (("base_manifest", BASE_MANIFEST_SHA),
                               ("target_manifest", MANIFEST_SHA),
                               ("candidate", CANDIDATE_SHA), ("github_binding", BINDING_SHA)):
        document = packet[name].encode("utf-8")
        require(digest(document) == expected_sha, "packet_document_digest_differs:" + name)
        documents[name] = (document, parse(document))
    base = documents["base_manifest"][1]
    target = documents["target_manifest"][1]
    candidate = documents["candidate"][1]
    binding = documents["github_binding"][1]
    require((base["commit"], base["tree"], len(base["files"])) ==
            (BASE_COMMIT, BASE_TREE, 3142), "committed_base_identity_differs")
    require((target["commit"], target["tree"], len(target["files"])) ==
            (COMMIT, TREE, 3507), "real_target_commit_or_tree_differs")
    require((candidate["base_commit"], candidate["base_tree"], candidate["target_tree"],
             len(candidate["files"])) == (BASE_COMMIT, BASE_TREE, TREE, 371),
            "frozen_candidate_identity_differs")
    require(binding["commit"] == COMMIT and binding["tree"] == TREE
            and binding["ref_update_success"] is True
            and binding["candidate_sha256"] == CANDIDATE_SHA, "Git_binding_differs")
    validate_delta(base, target, candidate)
    return documents, {"compressed_sha256": digest(compressed), "compressed_bytes": len(compressed),
                       "packet_sha256": digest(raw), "packet_bytes": len(raw)}


def run(profile_name, packet_path, packet_sha):
    os.umask(0o077)
    started = time.monotonic()
    until = started + STAGING_SECONDS
    config = PROFILES[profile_name]
    root = Path(config["root"])
    owned_directory(root)
    require((platform.system(), platform.machine(), platform.node()) ==
            (config["system"], config["machine"], config["hostname"]), "physical_host_identity_differs")
    require(tuple(sys.version_info[:3]) == config["python_version"], "original_python_version_differs")
    python_real = Path(sys.executable).resolve()
    python_sha = file_digest(python_real)
    if "python_sha256" in config:
        require(python_sha == config["python_sha256"], "original_Mac_python_binary_differs")
    require(packet_path.is_absolute() and packet_path.resolve() == packet_path
            and packet_path.is_relative_to(root), "packet_must_be_in_owned_task_root")
    documents, packet_receipt = load_packet(packet_path, packet_sha)
    base = documents["base_manifest"][1]
    manifest_raw, target = documents["target_manifest"]
    candidate = documents["candidate"][1]
    old_source = root / "source-b24c6de"
    new_source = root / "source-07a3dda"
    manifest_path = root / "source-07a3dda-manifest.json"
    controller = root / f"native-full55-07a3dda-{profile_name}-r1-controller"
    output = root / f"native-full55-07a3dda-{profile_name}-r1"
    owned_directory(old_source)
    exact_regular(root / "source-b24c6de-manifest.json", BASE_MANIFEST_SHA)
    for path in (new_source, manifest_path, controller, output):
        require(not os.path.lexists(path), "fresh_path_already_exists:" + str(path))
    for key in ("cargo_home", "target"):
        owned_directory(Path(config[key]))
    for key in ("cargo", "rustc"):
        path = Path(config[key])
        require(path.is_file() and os.access(path, os.X_OK), "original_toolchain_unavailable:" + key)
    for key in ("CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CARGO_INCREMENTAL"):
        require(not os.environ.get(key), "inherited_compiler_profile_differs:" + key)
    require(os.cpu_count() >= config["jobs"], "original_build_parallelism_unavailable")
    old_runner = old_source / RUNNER_PATH
    exact_regular(old_runner, RUNNER_SHA)
    spec = importlib.util.spec_from_file_location("exact_original_native55_runner", old_runner)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    require(len(checker.GROUPS) == 17 and sum(item[3] for item in checker.GROUPS) == 55,
            "original_55_group_contract_differs")
    controller.mkdir(mode=0o700)
    lock = None
    child = None
    try:
        new_json(controller / "intent.json", {
            "schema": "heptabao.r6-source-and-native55-intent.v1", "created_utc": utc(),
            "source_commit": COMMIT, "source_tree": TREE, "source": str(new_source),
            "output": str(output), "profile": profile_name, "submission_limit": 1,
            "automatic_retry": False, "runner_sha256": RUNNER_SHA,
            "manifest_sha256": MANIFEST_SHA, "candidate_sha256": CANDIDATE_SHA,
            "python": str(python_real), "python_binary_sha256": python_sha,
            "staging_seconds": STAGING_SECONDS, "per_command_seconds": 1800,
            "original_groups": checker.GROUPS, "packet": packet_receipt})
        lock_path = Path(config["target"]) / "heptabao-owned-candidate-run.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        lock = os.fdopen(descriptor, "r+")
        require(os.fstat(descriptor).st_uid == os.geteuid(), "candidate_target_lock_owner_differs")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        materialization = materialize(old_source, new_source, base, target, candidate, checker, until)
        new_file(manifest_path, manifest_raw)
        exact_regular(new_source / RUNNER_PATH, RUNNER_SHA)
        materialization.update(schema="heptabao.r6-plain-source-materialization.v1",
                               status="verified_exact_source", source=str(new_source),
                               manifest_sha256=MANIFEST_SHA, packet=packet_receipt,
                               finished_utc=utc())
        new_json(controller / "materialization.json", materialization)
        require(time.monotonic() < until, "original_staging_deadline_expired_before_submission")
        argv = [sys.executable, "-B", str(new_source / RUNNER_PATH),
                "--source", str(new_source), "--manifest", str(manifest_path),
                "--output", str(output), "--cargo", config["cargo"], "--rustc", config["rustc"],
                "--cargo-home", config["cargo_home"], "--target-dir", config["target"],
                "--groups", "all", "--build-server", "--build-jobs", str(config["jobs"]),
                "--command-timeout", "1800"]
        new_json(controller / "submission-intent.json", {
            "created_utc": utc(), "argv": argv, "submission_count": 1,
            "automatic_retry": False, "source_commit": COMMIT,
            "target_lock_preflight_acquired": True,
            "target_lock_final_admission": "original runner independently acquires same nonblocking lock",
            "source_staging_complete_before_submission": True})
        # Preserve the original runner's lock protocol. A conflicting admission
        # after this release is rejected by that runner, never retried here.
        lock.close()
        lock = None
        with (controller / "stdout.log").open("xb") as stdout, (controller / "stderr.log").open("xb") as stderr:
            child = subprocess.Popen(argv, cwd=new_source, stdout=stdout, stderr=stderr,
                                     start_new_session=True)
        # This is a submission receipt, not a completion or group-clean claim.
        # Darwin may reject getpgid for a zombie; retain uncertainty explicitly.
        try:
            pgid = os.getpgid(child.pid)
            identity_error = None
        except ProcessLookupError:
            pgid = None
            identity_error = "leader may already be a zombie; reconcile original runner receipt"
        launch = {"schema": "heptabao.r6-native55-submission.v1", "status": "submitted_once",
                  "created_utc": utc(), "pid": child.pid, "observed_pgid": pgid,
                  "process_identity_observation_error": identity_error,
                  "requested_new_session": True, "argv": argv, "submission_count": 1,
                  "automatic_retry": False, "source_commit": COMMIT, "source_tree": TREE,
                  "manifest_sha256": MANIFEST_SHA, "runner_sha256": RUNNER_SHA,
                  "output": str(output), "controller": str(controller),
                  "runner_completed": None, "test_pass_claim": False}
        new_json(controller / "launch.json", launch)
        print(json.dumps(launch, sort_keys=True), flush=True)
        return 0
    except BaseException as error:
        failure = {"schema": "heptabao.r6-one-shot-failure.v1", "created_utc": utc(),
                   "error_type": type(error).__name__, "reason": str(error),
                   "source_commit": COMMIT, "automatic_retry": False,
                   "child_submission_occurred": child is not None,
                   "child_pid": child.pid if child else None,
                   "preserved_partial_paths": [str(new_source), str(manifest_path), str(controller)],
                   "action": "retain and reconcile this one-shot intent; do not blindly resubmit"}
        try:
            new_json(controller / "failure.json", failure)
            new_file(controller / "failure.log", traceback.format_exc().encode())
        finally:
            print(json.dumps(failure, sort_keys=True), flush=True)
        return 1
    finally:
        if lock is not None:
            lock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=tuple(PROFILES), required=True)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--packet-sha256", required=True)
    args = parser.parse_args()
    require(re.fullmatch("[0-9a-f]{64}", args.packet_sha256), "invalid_packet_sha256")
    return run(args.profile, args.packet, args.packet_sha256)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        print(json.dumps({"status": "rejected_before_submission", "error": type(error).__name__,
                          "reason": str(error), "automatic_retry": False}), flush=True)
        raise SystemExit(1)
