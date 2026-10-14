#!/usr/bin/env python3
"""Owned HTTPS NativeV6 paged-history lifecycle; no production endpoints.

A clean native-build receipt and frozen libtest listing are mandatory. This
runner preserves the server's default 15-second budget; it has no override.
All tokens, unseal material, TLS private key and audit remain in its new private
case directory. Public output contains only status, sizes and controlled hashes.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import ssl
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request

HISTORY_VERSIONS = 40
PAYLOAD_BYTES = (33 * 1024 * 1024 // 10) // 4 * 4
MIN_HISTORY_BYTES = 128 * 1024 * 1024
DURABLE_ARTIFACT_LIMIT = 64 * 1024 * 1024
SERVER_DEFAULT_TIMEOUT = 15
CLIENT_TIMEOUT = SERVER_DEFAULT_TIMEOUT + 5
PAGED_FORMAT = "heptabao-kv2-native-paged-v2"
BLOCK_BYTES = 256 * 1024
PAYLOAD_OBJECT_HEADER_BYTES = 25
REQUESTED_FEATURES = ["fixture-native-v6-service"]
RESOLVED_FEATURES = ["default", "fixture-native-v6-service"]
RESOURCE_SAMPLE_INTERVAL_SECONDS = 0.2


class TrialFailure(Exception):
    """Only deliberately public, credential-free messages may use this type."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def fixture(version, payload_bytes=PAYLOAD_BYTES):
    # Distinct deterministic pseudorandom content in every block/version avoids
    # accidentally proving only deduplicated copies of a repeated small value.
    seed = b"heptabao-owned-paged128-fixture-v1/version/" + str(version).encode()
    raw = hashlib.shake_256(seed).digest(payload_bytes // 4 * 3)
    payload = base64.b64encode(raw).decode("ascii")
    return {"fixture": "shake256-base64-v1", "version": version, "payload": payload}


def file_sha(path):
    digest = hashlib.sha256()
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise TrialFailure("evidence input is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns
        ):
            raise TrialFailure("evidence file identity changed before immutable read")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        finished = os.fstat(stream.fileno())
    after = path.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if identity(before) != identity(finished) or identity(before) != identity(after):
        raise TrialFailure("evidence file changed during descriptor-bound read")
    return digest.hexdigest()


def git_state(repo):
    def run(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()
    return {"commit": run("rev-parse", "HEAD"), "tree": run("rev-parse", "HEAD^{tree}"),
            "clean": run("status", "--porcelain", "--untracked-files=all") == ""}


def server_feature_manifest(repo):
    """The compiled server package owns features; workspace Cargo.toml does not."""
    root = Path(subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
        stderr=subprocess.DEVNULL, text=True,
    ).strip()).resolve(strict=True)
    for member in (root / "crates", root / "crates/heptabao-server"):
        if not stat.S_ISDIR(member.lstat().st_mode):
            raise TrialFailure("server feature manifest member is not a regular source-tree directory")
    manifest = root / "crates/heptabao-server/Cargo.toml"
    if not stat.S_ISREG(manifest.lstat().st_mode):
        raise TrialFailure("server feature manifest is not a regular source file")
    return manifest


def empty_default_umbrella(repo):
    """Fail closed on anything except this source's literal empty umbrella."""
    contents = server_feature_manifest(repo).read_text()
    sections = re.findall(r"(?ms)^\[features\][ \t]*(?:#[^\n]*)?\n(.*?)(?=^\[|\Z)", contents)
    if len(sections) != 1:
        return False
    definitions = re.findall(r"(?m)^default[ \t]*=([^\n]*)$", sections[0])
    return len(definitions) == 1 and re.fullmatch(r"[ \t]*\[[ \t]*\][ \t]*(?:#[^\n]*)?", definitions[0]) is not None


def native_abi(binary, target):
    if not isinstance(target, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", target) is None:
        raise TrialFailure("native ABI receipt is invalid")
    description = subprocess.check_output(["file", "-b", str(binary)], stderr=subprocess.DEVNULL).decode().strip()
    machine = platform.machine().lower()
    system = platform.system()
    if system == "Darwin":
        valid_os = "Mach-O" in description and "apple-darwin" in target
    elif system == "Linux":
        valid_os = "ELF" in description and "linux" in target
    else:
        raise TrialFailure("only native Mac and Linux runners are admitted")
    if machine in ("arm64", "aarch64"):
        valid_arch = ("arm64" in description or "aarch64" in description.lower()) and "aarch64" in target
    elif machine in ("amd64", "x86_64"):
        valid_arch = ("x86-64" in description or "x86_64" in description) and "x86_64" in target
    else:
        valid_arch = False
    if not valid_os or not valid_arch:
        raise TrialFailure("binary is not the host's admitted native ABI")
    return {"target": target, "description": description, "system": system, "machine": machine}


def admit(args):
    binary = args.binary.resolve(strict=True)
    repo = args.source_repo.resolve(strict=True)
    custody_path = args.build_custody.resolve(strict=True)
    list_path = args.frozen_test_manifest.resolve(strict=True)
    for value in (args.build_custody_sha256, args.frozen_test_manifest_sha256):
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise TrialFailure("pinned evidence hash is invalid")
    if file_sha(custody_path) != args.build_custody_sha256:
        raise TrialFailure("build custody hash changed")
    if file_sha(list_path) != args.frozen_test_manifest_sha256 or list_path.stat().st_size == 0:
        raise TrialFailure("frozen libtest manifest hash changed or is empty")
    try:
        custody = json.loads(custody_path.read_text())
    except (ValueError, UnicodeError):
        raise TrialFailure("build custody is not a valid JSON document")
    if custody.get("schema") != "heptabao.native-build.v1":
        raise TrialFailure("historical or non-native build custody is not admitted")
    for field, length in (("source_commit", 40), ("source_tree", 40), ("binary_sha256", 64)):
        if not isinstance(custody.get(field), str) or re.fullmatch("[0-9a-f]{%d}" % length, custody[field]) is None:
            raise TrialFailure("build custody identity is invalid")
    if type(custody.get("build_exit_code")) is not int or custody["build_exit_code"] != 0:
        raise TrialFailure("actual native build did not exit successfully")
    if custody.get("source_freeze_verified") is not True:
        raise TrialFailure("source freeze was not actually verified")
    if not isinstance(custody.get("build_job_id"), str) or not custody["build_job_id"]:
        raise TrialFailure("actual native build job identity is missing")
    if custody.get("features") != RESOLVED_FEATURES:
        raise TrialFailure("native feature profile does not match this trial")
    if custody.get("requested_features") != REQUESTED_FEATURES:
        raise TrialFailure("requested native feature profile does not match this trial")
    if custody.get("no_default_features") is not False:
        raise TrialFailure("native Cargo default-feature setting does not match this trial")
    if custody.get("default_umbrella_is_empty") is not True or not empty_default_umbrella(repo):
        raise TrialFailure("actual source does not verify the empty Cargo default umbrella")
    feature_manifest = server_feature_manifest(repo)
    feature_manifest_sha256 = file_sha(feature_manifest)
    if custody.get("frozen_libtest_list_sha256") != args.frozen_test_manifest_sha256:
        raise TrialFailure("libtest list is not bound to this native build")
    observed = git_state(repo)
    if not observed["clean"] or observed["commit"] != custody["source_commit"] or observed["tree"] != custody["source_tree"]:
        raise TrialFailure("actual source checkout is not the frozen clean build source")
    if file_sha(binary) != custody["binary_sha256"]:
        raise TrialFailure("actual candidate binary hash does not match the native build")
    abi = native_abi(binary, custody.get("native_abi"))
    listing = list_path.read_text()
    tests = re.findall(r"(?m)^.+: test$", listing)
    summaries = re.findall(r"(?m)^(\d+) tests?, (\d+) benchmarks?$", listing)
    if len(summaries) != 1 or int(summaries[0][0]) != len(tests) or not tests or int(summaries[0][1]) != 0:
        raise TrialFailure("frozen libtest listing has no exact nonzero test denominator")
    return {"schema": custody["schema"], "source_commit": custody["source_commit"],
            "source_tree": custody["source_tree"], "source_clean_before": True,
            "build_job_id": custody["build_job_id"], "build_exit_code": 0,
            "source_freeze_verified": True, "features": custody["features"],
            "requested_features": custody["requested_features"],
            "no_default_features": custody["no_default_features"],
            "default_umbrella_is_empty": True, "frozen_libtest_test_count": len(tests),
            "server_feature_manifest_path": str(feature_manifest),
            "server_feature_manifest_sha256": feature_manifest_sha256,
            "source_repository_root": str(feature_manifest.parents[2]),
            "binary_sha256": custody["binary_sha256"], "native_abi": abi,
            "build_custody_sha256": args.build_custody_sha256,
            "frozen_libtest_list_sha256": args.frozen_test_manifest_sha256}


def physical_inventory(data_dir):
    blobs, artifacts = [], []
    for path in sorted(data_dir.rglob("*")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise TrialFailure("owned data directory unexpectedly contains a symlink")
        if not stat.S_ISREG(info.st_mode):
            continue
        relative = str(path.relative_to(data_dir))
        if path.suffix == ".hbo":
            if info.st_nlink != 1:
                raise TrialFailure("ciphertext inventory includes an unexpected hard link")
            blobs.append({"file": relative, "bytes": info.st_size, "sha256": file_sha(path)})
        elif path.name in ("state.hbs", "journal.hbj", "ledger.hbl"):
            artifacts.append({"file": relative, "bytes": info.st_size, "sha256": file_sha(path)})
    return {"ciphertext_blob_count": len(blobs), "ciphertext_blob_bytes": sum(row["bytes"] for row in blobs),
            "ciphertext_full_block_count": sum(row["bytes"] >= BLOCK_BYTES for row in blobs),
            "ciphertext_distinct_hash_count": len(set(row["sha256"] for row in blobs)),
            "ciphertext_hash_set_sha256": hashlib.sha256(canonical(sorted(row["sha256"] for row in blobs))).hexdigest(),
            "ciphertext_blobs": blobs, "durable_artifacts": artifacts,
            "device_id": data_dir.stat().st_dev, "data_dir": str(data_dir)}


def required_case_names():
    """Fixed complete scenario; failures retain their actual partial denominator."""
    names = []
    def check(name):
        names.append(name)
    def request(name, expected=200):
        names.extend((name, name + "-response-json"))
        if expected >= 400:
            names.extend((name + "-error-json-object", name + "-no-auth-or-wrap"))
            if expected == 403:
                check(name + "-no-secret-data")
    def inputs(name):
        names.extend(name + suffix for suffix in ("-source-clean", "-binary-hash", "-build-custody-hash", "-frozen-libtest-list-hash"))
    def start(number):
        inputs("start-%d" % number)
        check("start-%d-owned-sealed-https-readiness" % number)
    def read(name):
        blocks(name + "-blocks-before")
        request(name)
        names.extend((name + "-exact-json-sha256", name + "-metadata-version"))
        blocks(name + "-blocks-after")
        check(name + "-exact-selected-payload-block-count")
    def blocks(name):
        request(name)
        check(name + "-actual-payload-block-counter")
    def metadata(name):
        request(name)
        check(name + "-current-version")
    def capacity(name):
        request(name)
        names.extend(name + suffix for suffix in (
            "-native-root", "-genuine-reader-floor2", "-exact-logical-payload",
            "-unchanged-64mib-artifact-limit", "-bounded-metadata"))
        request(name + "-alias")
        names.extend((name + "-alias-exact-stored-value-bytes", name + "-alias-unchanged-artifact-limit"))
    def inventory(name):
        names.extend(name + suffix for suffix in (
            "-ciphertext-above-128mib", "-new-ciphertext-above-128mib",
            "-actual-full-ciphertext-block-growth", "-distinct-physical-ciphertexts",
            "-all-durable-artifacts-under-64mib", "-actual-journal-observed"))
    def finite(prefix):
        for kind in ("activation", "permit", "deny"):
            request(prefix + "-finite-" + kind, 403)
    check("actual-default-15s-config-has-no-timeout-override")
    start(1)
    request("initialize")
    request("unseal-source")
    request("mount-root-kv2", 204)
    request("source-record-upgrade")
    request("retain-64", 204)
    for kind in ("activation", "permit", "deny"):
        request("mint-finite-" + kind)
    request("activate-native-root", 204)
    request("activation-one-use-consumed", 403)
    request("finite-permitted-first")
    request("finite-denied-first", 403)
    for kind in ("permit", "deny"):
        request("finite-" + kind + "-second-use", 403)
    request("capacity-before-history")
    names.extend(("baseline-logical-payload-observed", "baseline-genuine-reader-floor2", "baseline-actual-ciphertext-observed"))
    for version in range(1, HISTORY_VERSIONS + 1):
        blocks("write-history-%d-blocks-before" % version)
        request("write-history-%d" % version)
        check("write-version-%d" % version)
        blocks("write-history-%d-blocks-after" % version)
        check("write-history-%d-no-old-payload-opens" % version)
    names.extend(("actual-distinct-history-json-above-128mib", "all-40-history-json-hashes-distinct"))
    capacity("capacity-after-40")
    for name in ("history-first", "history-middle", "history-latest"):
        read(name)
    for version in range(1, HISTORY_VERSIONS + 1):
        read("all-committed-history-version-%d" % version)
    request("stale-cas-39", 400)
    metadata("stale-cas-metadata-unchanged")
    read("stale-cas-value-unchanged")
    request("delete-specific-versions", 204)
    for version in (3, 17):
        request("deleted-%d" % version, 404)
        check("deleted-%d-actual-metadata" % version)
    read("retained-old-after-delete")
    capacity("capacity-after-delete")
    check("first-process-actually-closed")
    inventory("before-cold-open")
    start(2)
    request("first-cold-unseal")
    blocks("first-cold-payload-blocks")
    check("first-cold-no-payload-open")
    finite("first-cold")
    metadata("first-cold-metadata")
    check("first-cold-delete-state-preserved")
    read("first-cold-old-version")
    read("first-cold-latest-version")
    for version in (3, 17):
        request("first-cold-deleted-%d" % version, 404)
    capacity("capacity-first-cold")
    check("second-process-actually-closed")
    inventory("after-first-cold-open")
    start(3)
    request("second-cold-unseal")
    blocks("second-cold-payload-blocks")
    check("second-cold-no-payload-open")
    finite("second-cold")
    metadata("second-cold-metadata")
    read("second-cold-old-version")
    read("second-cold-latest-version")
    for version in (3, 17):
        request("second-cold-deleted-%d" % version, 404)
    blocks("second-cold-point-blocks-before")
    request("second-cold-cas40-to41")
    check("second-cold-point-version41")
    blocks("second-cold-point-blocks-after")
    check("second-cold-point-no-old-payload-opens")
    read("second-cold-point-exact")
    read("second-cold-old-after-point")
    metadata("final-current-version")
    capacity("capacity-after-point41")
    blocks("second-cold-patch-blocks-before")
    request("second-cold-patch41-to42")
    check("second-cold-patch-version42")
    blocks("second-cold-patch-blocks-after")
    check("second-cold-patch-exact-current-payload-block-count")
    read("second-cold-patch-exact")
    read("second-cold-prepatch-version41-retained")
    read("second-cold-old-after-patch")
    metadata("final-current-version-after-patch")
    capacity("capacity-after-patch42")
    check("third-process-actually-closed")
    inventory("after-second-cold-point")
    start(4)
    request("post-patch-cold-unseal")
    blocks("post-patch-cold-payload-blocks")
    check("post-patch-cold-no-payload-open")
    finite("post-patch-cold")
    metadata("post-patch-cold-metadata")
    read("post-patch-cold-version42-exact")
    read("post-patch-cold-version41-retained")
    read("post-patch-cold-version1-retained")
    for version in (3, 17):
        request("post-patch-cold-deleted-%d" % version, 404)
    capacity("capacity-post-patch-cold")
    inputs("final")
    inputs("post-cleanup")
    return names


def required_resource_snapshot_names():
    cases = required_case_names()
    point_reads = {name[:-len("-exact-json-sha256")] for name in cases if name.endswith("-exact-json-sha256")}
    operations = point_reads | {"unseal-source", "first-cold-unseal", "second-cold-unseal", "post-patch-cold-unseal",
                               "second-cold-patch41-to42"}
    for prefix in ("", "first-cold-", "second-cold-", "post-patch-cold-"):
        for version in (3, 17):
            operations.add(prefix + "deleted-%d" % version)
    return [name + suffix for name in cases if name in operations
            for suffix in ("-resource-before", "-resource-after")]


class OwnedProcessResources:
    """Sample only the unreaped child held by this Popen, never an arbitrary PID.

    Every poll/wait in the serving Trial uses ownership_lock. A sample holds it
    through OS reads, preventing a competing wait from reaping the child and
    releasing its PID for reuse. Values are sampled observations, not a claim
    about an absolute peak between samples. No ulimit or server budget changes.
    """
    def __init__(self, process, cycle, data_dir):
        self.process, self.cycle = process, cycle
        self.data_dir = str(data_dir.resolve()) + os.sep
        self.ownership_lock = threading.RLock()
        self.samples_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.samples, self.errors = [], []
        self.thread = None
        self.system = platform.system()

    def alive(self):
        with self.ownership_lock:
            return self.process.poll() is None

    def owned_ciphertext(self, target):
        if target.endswith(" (deleted)"):
            target = target[:-10]
        return target.startswith(self.data_dir) and target.endswith(".hbo")

    def linux_metrics(self):
        root = Path("/proc") / str(self.process.pid)
        status = (root / "status").read_text()
        rss = re.search(r"(?m)^VmRSS:[ \t]+([0-9]+)[ \t]+kB$", status)
        high = re.search(r"(?m)^VmHWM:[ \t]+([0-9]+)[ \t]+kB$", status)
        if rss is None or high is None:
            raise TrialFailure("owned /proc status has no valid VmRSS/VmHWM")
        fds, cipher_fds, disappeared = 0, 0, 0
        with os.scandir(root / "fd") as entries:
            for entry in entries:
                if not entry.name.isdigit():
                    continue
                fds += 1
                try:
                    if self.owned_ciphertext(os.readlink(entry.path)):
                        cipher_fds += 1
                except FileNotFoundError:
                    disappeared += 1
        return {"fd_count": fds, "owned_ciphertext_fd_count": cipher_fds,
                "fd_links_disappeared_during_scan": disappeared,
                "rss_bytes": int(rss.group(1)) * 1024,
                "kernel_vmhwm_bytes": int(high.group(1)) * 1024,
                "method": "owned-pid-/proc-fd-and-status"}

    def mac_metrics(self):
        rss = subprocess.run(["/bin/ps", "-o", "rss=", "-p", str(self.process.pid)],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, timeout=1, check=False)
        value = rss.stdout.strip()
        if rss.returncode != 0 or not value.isdigit():
            raise TrialFailure("owned ps RSS observation failed")
        # -n/-P avoids name-service lookups; -a/-p restricts this owned PID.
        # Path fields are inspected locally only and never emitted in evidence.
        listing = subprocess.run(["/usr/sbin/lsof", "-n", "-P", "-w", "-a", "-p", str(self.process.pid), "-F", "fn"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 text=True, timeout=1, check=False)
        if listing.returncode != 0:
            raise TrialFailure("owned lsof FD observation failed")
        fds, cipher_fds, current_fd = set(), set(), None
        observed_pid = None
        for field in listing.stdout.splitlines():
            if field.startswith("p"):
                observed_pid = field[1:]
                if observed_pid != str(self.process.pid):
                    raise TrialFailure("lsof returned a different process identity")
            elif field.startswith("f"):
                current_fd = field[1:] if field[1:].isdigit() else None
                if current_fd is not None:
                    fds.add(current_fd)
            elif field.startswith("n") and current_fd is not None and self.owned_ciphertext(field[1:]):
                cipher_fds.add(current_fd)
        if observed_pid is None or not fds:
            raise TrialFailure("owned lsof numeric FD inventory was empty")
        return {"fd_count": len(fds), "owned_ciphertext_fd_count": len(cipher_fds),
                "rss_bytes": int(value) * 1024, "kernel_vmhwm_bytes": None,
                "kernel_vmhwm_available": False, "method": "owned-pid-ps-rss-and-lsof-numeric-fd"}

    def capture(self, label):
        started = time.monotonic_ns()
        sample = {"label": label, "process_cycle": self.cycle, "pid": self.process.pid,
                  "started_unix_ns": time.time_ns(), "started_monotonic_ns": started,
                  "process_alive_before": False, "observation_valid": False}
        with self.ownership_lock:
            if self.process.poll() is None:
                sample["process_alive_before"] = True
                try:
                    if self.system == "Linux":
                        sample.update(self.linux_metrics())
                    elif self.system == "Darwin":
                        sample.update(self.mac_metrics())
                    else:
                        raise TrialFailure("resource sampler requires native Mac or Linux")
                    sample["process_alive_after"] = self.process.poll() is None
                    sample["observation_valid"] = sample["process_alive_after"]
                except Exception as error:
                    sample["failure_type"] = type(error).__name__
                    if isinstance(error, TrialFailure):
                        sample["public_reason"] = str(error)
                    sample["process_alive_after"] = self.process.poll() is None
            else:
                sample["process_alive_after"] = False
                sample["public_reason"] = "owned process has already exited; no PID query performed"
        sample["completed_monotonic_ns"] = time.monotonic_ns()
        sample["observation_duration_ms"] = (sample["completed_monotonic_ns"] - started) // 1_000_000
        with self.samples_lock:
            self.samples.append(sample)
            if sample.get("failure_type"):
                self.errors.append({"label": label, "failure_type": sample["failure_type"],
                                    "public_reason": sample.get("public_reason")})
        return sample

    def start(self):
        self.capture("process-start")
        def sample_loop():
            try:
                while not self.stop_event.is_set():
                    started = time.monotonic()
                    if not self.alive():
                        break
                    self.capture("interval")
                    self.stop_event.wait(max(0.01, RESOURCE_SAMPLE_INTERVAL_SECONDS - (time.monotonic() - started)))
            except Exception as error:
                with self.samples_lock:
                    self.errors.append({"failure_type": type(error).__name__, "public_reason": "owned resource sampler loop failed"})
        self.thread = threading.Thread(target=sample_loop, name="owned-resource-cycle-%d" % self.cycle, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread is not None:
            if self.thread.ident is None:
                with self.samples_lock:
                    self.errors.append({"failure_type": "SamplerThreadNotStarted", "public_reason": "owned resource sampler thread did not start"})
                return
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                with self.samples_lock:
                    self.errors.append({"failure_type": "SamplerJoinTimeout", "public_reason": "owned resource sampler did not close within 5 seconds"})

    def summary(self):
        with self.samples_lock:
            samples, errors = list(self.samples), list(self.errors)
        valid = [row for row in samples if row["observation_valid"]]
        peak = lambda field: max((row[field] for row in valid if type(row.get(field)) is int), default=None)
        return {"process_cycle": self.cycle, "pid": self.process.pid, "system": self.system,
                "target_sample_interval_seconds": RESOURCE_SAMPLE_INTERVAL_SECONDS,
                "attempted_sample_count": len(samples), "valid_sample_count": len(valid),
                "observed_fd_peak": peak("fd_count"),
                "observed_owned_ciphertext_fd_peak": peak("owned_ciphertext_fd_count"),
                "observed_rss_peak_bytes": peak("rss_bytes"),
                "observed_kernel_vmhwm_peak_bytes": peak("kernel_vmhwm_bytes"),
                "absolute_peak_claimed": False, "fd_snapshot_atomic": False,
                "server_budget_changed": False, "ulimit_changed": False,
                "sampler_closed": self.thread is None or not self.thread.is_alive(),
                "observation_errors": errors, "samples": samples}


class Trial:
    def __init__(self, args, provenance):
        self.args, self.provenance = args, provenance
        self.runner_sha256_before = file_sha(Path(__file__).resolve())
        self.root = args.evidence.resolve()
        self.binary = args.binary.resolve(strict=True)
        self.repo = args.source_repo.resolve(strict=True)
        self.rows, self.processes, self.physical, self.capacities = [], [], {}, {}
        self.expected, self.tokens = {}, {}
        self.source_states = {}
        self.payload_block_observations = {}
        self.resource_sampler = None
        self.resource_cycles, self.resource_snapshots, self.resource_setup_errors = {}, [], []
        self.process, self.server_log, self.active_process = None, None, None
        self.config = self.root / "server.json"
        self.root_token, self.unseal_key = None, None
        self.written = 0
        self.created = False
        self.complete = False
        self.cleanup_errors = []
        self.base = "https://127.0.0.1:%d/v1/" % args.port

    def check(self, condition, name, **metadata):
        self.rows.append({"case": name, "passed": bool(condition), **metadata})
        if not condition:
            raise TrialFailure(name)

    def input_unchanged(self, name):
        observed = git_state(self.repo)
        self.source_states[name] = observed
        self.check(observed["clean"] and observed["commit"] == self.provenance["source_commit"]
                   and observed["tree"] == self.provenance["source_tree"], name + "-source-clean")
        self.check(file_sha(self.binary) == self.provenance["binary_sha256"], name + "-binary-hash")
        self.check(file_sha(self.args.build_custody.resolve(strict=True)) == self.args.build_custody_sha256,
                   name + "-build-custody-hash")
        self.check(file_sha(self.args.frozen_test_manifest.resolve(strict=True)) == self.args.frozen_test_manifest_sha256,
                   name + "-frozen-libtest-list-hash")

    def prepare(self):
        if self.repo == self.root or self.repo in self.root.parents:
            raise TrialFailure("case data must remain outside the frozen source checkout")
        self.root.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.created = True
        cert, key = self.root / "server.crt", self.root / "server.key"
        (self.root / "certificate.conf").write_text(
            "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
            "[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n"
            "extendedKeyUsage=serverAuth\n")
        with (self.root / "certificate-generation.log").open("wb") as log:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-config", str(self.root / "certificate.conf"), "-keyout", str(key), "-out", str(cert)],
                           check=True, stdout=log, stderr=log)
        self.config = self.root / "server.json"
        config = {"listen": "127.0.0.1:%d" % self.args.port, "data_dir": str(self.root / "data"),
                  "audit_file": str(self.root / "audit.private.jsonl"), "tls_cert_file": str(cert),
                  "tls_key_file": str(key), "lifecycle_interval_seconds": 0, "max_connections": 8}
        # timeout_seconds is intentionally absent; this is the original server default.
        self.config.write_bytes(canonical(config))
        actual_config = json.loads(self.config.read_bytes())
        self.check("timeout_seconds" not in actual_config, "actual-default-15s-config-has-no-timeout-override")
        self.context = ssl.create_default_context(cafile=str(cert))

    def save_credentials(self):
        (self.root / "credentials.private.json").write_bytes(canonical({
            "root_token": self.root_token, "unseal_key": self.unseal_key, "finite_tokens": self.tokens}))

    def resource_snapshot(self, label):
        if self.resource_sampler is None:
            sample = {"label": label, "observation_valid": False,
                      "public_reason": "owned process resource sampler is unavailable"}
        else:
            try:
                sample = self.resource_sampler.capture(label)
            except Exception as error:
                sample = {"label": label, "observation_valid": False,
                          "failure_type": type(error).__name__,
                          "public_reason": "owned resource snapshot failed"}
        self.resource_snapshots.append(sample)

    def request(self, name, method, path, body=None, expected=200, token=None, anonymous=False):
        tracked = ((method == "POST" and path == "sys/unseal")
                   or (method == "GET" and path.startswith("secret/data/history?version="))
                   or (method == "PATCH" and path == "secret/data/history"))
        if tracked:
            self.resource_snapshot(name + "-resource-before")
        try:
            return self._request(name, method, path, body, expected, token, anonymous)
        finally:
            if tracked:
                self.resource_snapshot(name + "-resource-after")

    def _request(self, name, method, path, body=None, expected=200, token=None, anonymous=False):
        payload = None if body is None else canonical(body)
        headers = {"Content-Type": "application/merge-patch+json" if method == "PATCH" else "application/json"}
        selected_token = None if anonymous else (self.root_token if token is None else token)
        if selected_token:
            headers["X-Vault-Token"] = selected_token
        request = urllib.request.Request(self.base + path, data=payload, headers=headers, method=method)
        started = time.monotonic()
        try:
            try:
                with urllib.request.urlopen(request, context=self.context, timeout=CLIENT_TIMEOUT) as response:
                    status, data = response.status, response.read()
            except urllib.error.HTTPError as response:
                status, data = response.code, response.read()
        except (OSError, urllib.error.URLError) as error:
            self.rows.append({"case": name, "expected": expected, "passed": False,
                              "transport_failure_type": type(error).__name__,
                              "elapsed_ms": int((time.monotonic() - started) * 1000)})
            raise TrialFailure(name + ": transport failure")
        self.rows.append({"case": name, "status": status, "expected": expected, "passed": status == expected,
                          "elapsed_ms": int((time.monotonic() - started) * 1000), "response_bytes": len(data)})
        if status != expected:
            raise TrialFailure("%s: expected %d, got %d" % (name, expected, status))
        try:
            parsed = json.loads(data) if data else None
        except (ValueError, UnicodeError):
            self.check(False, name + "-response-json")
        self.check(parsed is None and not data or isinstance(parsed, dict), name + "-response-json")
        if expected >= 400:
            self.check(isinstance(parsed, dict), name + "-error-json-object")
            self.check(not parsed.get("auth") and not parsed.get("wrap_info"), name + "-no-auth-or-wrap")
            if expected == 403:
                self.check("data" not in parsed or parsed["data"] is None, name + "-no-secret-data")
        return parsed

    def start(self, number):
        self.input_unchanged("start-%d" % number)
        self.server_log = (self.root / ("server-%d.log" % number)).open("wb")
        self.process = subprocess.Popen([str(self.binary), "--config", str(self.config), "--fixture-native-v6-service"],
                                        stdout=self.server_log, stderr=self.server_log, cwd="/", start_new_session=True)
        self.active_process = {"cycle": number, "pid": self.process.pid, "started_unix_ns": time.time_ns(),
                               "binary_sha256": self.provenance["binary_sha256"]}
        self.processes.append(self.active_process)
        self.resource_sampler = OwnedProcessResources(self.process, number, self.root / "data")
        try:
            self.resource_sampler.start()
        except Exception as error:
            self.resource_setup_errors.append({"process_cycle": number, "failure_type": type(error).__name__})
        limit = time.monotonic() + 15
        while time.monotonic() < limit:
            if not self.resource_sampler.alive():
                raise TrialFailure("owned candidate exited before HTTPS readiness")
            try:
                request = urllib.request.Request(self.base + "sys/health", method="GET")
                try:
                    with urllib.request.urlopen(request, context=self.context, timeout=1) as response:
                        status, data = response.status, response.read()
                except urllib.error.HTTPError as response:
                    status, data = response.code, response.read()
                health = json.loads(data)
                self.check(status == (501 if number == 1 else 503)
                           and isinstance(health, dict)
                           and health.get("initialized") is (number != 1)
                           and health.get("sealed") is True
                           and self.resource_sampler.alive(),
                           "start-%d-owned-sealed-https-readiness" % number, status=status)
                return
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        raise TrialFailure("owned candidate HTTPS readiness timed out")

    def stop(self):
        sampler = self.resource_sampler
        try:
            if self.process is not None:
                if sampler is not None:
                    sampler.capture("before-stop")
                process = self.process
                ownership_lock = sampler.ownership_lock if sampler is not None else threading.RLock()
                with ownership_lock:
                    already_exited = process.poll() is not None
                    self.active_process["exited_before_stop_request"] = already_exited
                    if already_exited:
                        self.cleanup_errors.append("owned process exited before its stop request")
                    else:
                        process.send_signal(signal.SIGTERM)
                        self.active_process["stop_signal"] = "SIGTERM"
                        try:
                            process.wait(timeout=20)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=10)
                            self.cleanup_errors.append("owned process required SIGKILL after SIGTERM timeout")
                    self.active_process["exit_code"] = process.returncode
                    self.active_process["closed_unix_ns"] = time.time_ns()
                    self.active_process["actual_process_closed"] = process.poll() is not None
                    if process.returncode not in (0, -signal.SIGTERM):
                        self.cleanup_errors.append("owned process had an unexpected exit code")
                    self.process = None
        finally:
            if sampler is not None:
                sampler.stop()
                self.resource_cycles[sampler.cycle] = sampler.summary()
                if self.resource_cycles[sampler.cycle]["sampler_closed"]:
                    self.resource_sampler = None
                else:
                    self.cleanup_errors.append("owned resource sampler did not close")
            if self.server_log is not None:
                self.server_log.close()
                self.server_log = None

    def metadata(self, name, version):
        data = self.request(name, "GET", "secret/metadata/history")["data"]
        self.check(type(data["current_version"]) is int and data["current_version"] == version,
                   name + "-current-version", observed=data["current_version"])
        return data

    def payload_blocks(self, name):
        data = self.request(name, "GET", "sys/internal/capacity")["data"]
        count = data.get("native_kv2_payload_blocks_opened")
        observations = {field: data.get("native_kv2_payload_" + field) for field in (
            "positioned_read_calls", "positioned_bytes_returned", "positioned_read_failures",
            "ciphertext_bytes_read", "plaintext_bytes_opened")}
        self.check(all(type(value) is int and 0 <= value <= (1 << 64) - 1
                       for value in [count, *observations.values()]),
                   name + "-actual-payload-block-counter", observed=count, **observations)
        self.payload_block_observations[name] = {"process_cycle": self.active_process["cycle"],
                                                 "count": count, **observations}
        return count

    def payload_io_unchanged(self, before, after):
        left, right = self.payload_block_observations[before], self.payload_block_observations[after]
        return left["process_cycle"] == right["process_cycle"] and all(
            left[field] == right[field] for field in ("positioned_read_calls", "positioned_bytes_returned",
                                                      "positioned_read_failures", "ciphertext_bytes_read",
                                                      "plaintext_bytes_opened"))

    def payload_io_zero(self, name):
        return all(value == 0 for field, value in self.payload_block_observations[name].items()
                   if field != "process_cycle")

    def selected_io_delta(self, before, after, logical_bytes, selected_blocks):
        left, right = self.payload_block_observations[before], self.payload_block_observations[after]
        delta = {field: right[field] - left[field] for field in left if field != "process_cycle"}
        return (left["process_cycle"] == right["process_cycle"]
                and delta["count"] == selected_blocks
                and delta["positioned_read_calls"] >= selected_blocks
                and delta["positioned_read_failures"] == 0
                and delta["positioned_bytes_returned"] == delta["ciphertext_bytes_read"]
                and delta["ciphertext_bytes_read"] > logical_bytes + PAYLOAD_OBJECT_HEADER_BYTES * selected_blocks
                and delta["plaintext_bytes_opened"] == logical_bytes + PAYLOAD_OBJECT_HEADER_BYTES * selected_blocks)

    def read_version(self, name, version):
        before = self.payload_blocks(name + "-blocks-before")
        response = self.request(name, "GET", "secret/data/history?version=%d" % version)
        data = response["data"]["data"]
        digest = hashlib.sha256(canonical(data)).hexdigest()
        self.check(digest == self.expected[version]["json_sha256"], name + "-exact-json-sha256", json_sha256=digest)
        self.check(type(response["data"]["metadata"]["version"]) is int
                   and response["data"]["metadata"]["version"] == version, name + "-metadata-version")
        after = self.payload_blocks(name + "-blocks-after")
        selected_blocks = (self.expected[version]["json_bytes"] + BLOCK_BYTES - 1) // BLOCK_BYTES
        self.check(after - before == selected_blocks
                   and self.selected_io_delta(name + "-blocks-before", name + "-blocks-after",
                                              self.expected[version]["json_bytes"], selected_blocks),
                   name + "-exact-selected-payload-block-count",
                   before=before, after=after, expected_blocks=selected_blocks)

    def capacity(self, name, expected_logical):
        data = self.request(name, "GET", "sys/internal/capacity")["data"]
        self.check(data.get("state_storage_format") == "heptabao-state-records-v6", name + "-native-root")
        self.check(type(data.get("native_kv2_reader_format")) is int
                   and data["native_kv2_reader_format"] == 2, name + "-genuine-reader-floor2")
        self.check(type(data.get("native_kv2_logical_payload_bytes")) is int
                   and data["native_kv2_logical_payload_bytes"] == expected_logical,
                   name + "-exact-logical-payload", observed=data.get("native_kv2_logical_payload_bytes"), expected=expected_logical)
        self.check(data.get("durable_artifact_limit_bytes") == DURABLE_ARTIFACT_LIMIT, name + "-unchanged-64mib-artifact-limit")
        self.check(type(data.get("native_kv2_metadata_bytes")) is int
                   and data["native_kv2_metadata_bytes"] <= DURABLE_ARTIFACT_LIMIT,
                   name + "-bounded-metadata")
        alias = self.request(name + "-alias", "GET", "sys/internal/storage/capacity")["data"]
        # The storage route exposes aggregate stored_value_bytes; the detailed
        # service capacity route owns the typed point-read observations.
        self.check(type(alias.get("stored_value_bytes")) is int
                   and alias["stored_value_bytes"] == data["state_bytes"],
                   name + "-alias-exact-stored-value-bytes")
        self.check(alias.get("durable_artifact_limit_bytes") == DURABLE_ARTIFACT_LIMIT,
                   name + "-alias-unchanged-artifact-limit")
        allowed = ("profile", "state_schema", "state_storage_format", "state_bytes", "state_limit_bytes", "state_size_basis",
                   "durable_payload_bytes", "durable_artifact_limit_bytes", "native_kv2_logical_payload_bytes",
                   "native_kv2_metadata_bytes", "native_kv2_reader_format")
        self.capacities[name] = {key: data[key] for key in allowed if key in data}

    def inventory(self, name):
        observed = physical_inventory(self.root / "data")
        self.physical[name] = observed
        self.check(observed["ciphertext_blob_bytes"] > MIN_HISTORY_BYTES, name + "-ciphertext-above-128mib",
                   observed=observed["ciphertext_blob_bytes"])
        baseline = self.physical["before-history"]
        growth = observed["ciphertext_blob_bytes"] - baseline["ciphertext_blob_bytes"]
        full_blocks = observed["ciphertext_full_block_count"] - baseline["ciphertext_full_block_count"]
        self.check(growth > MIN_HISTORY_BYTES, name + "-new-ciphertext-above-128mib", observed=growth)
        self.check(full_blocks >= HISTORY_VERSIONS * (PAYLOAD_BYTES // BLOCK_BYTES),
                   name + "-actual-full-ciphertext-block-growth", observed=full_blocks)
        self.check(observed["ciphertext_distinct_hash_count"] == observed["ciphertext_blob_count"],
                   name + "-distinct-physical-ciphertexts")
        self.check(bool(observed["durable_artifacts"]) and all(row["bytes"] <= DURABLE_ARTIFACT_LIMIT
                   for row in observed["durable_artifacts"]), name + "-all-durable-artifacts-under-64mib")
        self.check(any(Path(row["file"]).name == "journal.hbj" for row in observed["durable_artifacts"]), name + "-actual-journal-observed")
        return observed

    def finite_after_cold(self, prefix):
        for kind in ("activation", "permit", "deny"):
            self.request(prefix + "-finite-" + kind, "GET", "secret/data/source", token=self.tokens[kind], expected=403)

    def run(self):
        self.prepare()
        self.start(1)
        initialized = self.request("initialize", "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}, anonymous=True)
        self.root_token = initialized["root_token"]
        self.unseal_key = initialized["keys_base64"][0]
        self.save_credentials()
        self.request("unseal-source", "POST", "sys/unseal", {"key": self.unseal_key}, anonymous=True)
        self.request("mount-root-kv2", "POST", "sys/mounts/secret", {"type": "kv", "options": {"version": "2"}}, expected=204)
        self.request("source-record-upgrade", "POST", "secret/data/source", {"data": {"value": "source"}})
        self.request("retain-64", "POST", "secret/config", {"max_versions": 64}, expected=204)
        for kind, policies in (("activation", ["root"]), ("permit", ["root"]), ("deny", ["default"])):
            minted = self.request("mint-finite-" + kind, "POST", "auth/token/create", {"num_uses": 1, "policies": policies, "no_parent": True})
            self.tokens[kind] = minted["auth"]["client_token"]
        self.save_credentials()
        self.request("activate-native-root", "POST", "sys/internal/native-v6/activate", {}, token=self.tokens["activation"], expected=204)
        self.request("activation-one-use-consumed", "GET", "secret/data/source", token=self.tokens["activation"], expected=403)
        self.request("finite-permitted-first", "GET", "secret/data/source", token=self.tokens["permit"])
        self.request("finite-denied-first", "GET", "secret/data/source", token=self.tokens["deny"], expected=403)
        for kind in ("permit", "deny"):
            self.request("finite-" + kind + "-second-use", "GET", "secret/data/source", token=self.tokens[kind], expected=403)
        baseline = self.request("capacity-before-history", "GET", "sys/internal/capacity")["data"]
        baseline_logical = baseline.get("native_kv2_logical_payload_bytes")
        self.check(type(baseline_logical) is int and baseline_logical > 0, "baseline-logical-payload-observed")
        self.check(type(baseline.get("native_kv2_reader_format")) is int
                   and baseline["native_kv2_reader_format"] == 2, "baseline-genuine-reader-floor2")
        self.physical["before-history"] = physical_inventory(self.root / "data")
        self.check(self.physical["before-history"]["ciphertext_blob_count"] > 0,
                   "baseline-actual-ciphertext-observed")
        history_bytes = 0
        for version in range(1, HISTORY_VERSIONS + 1):
            data = fixture(version)
            encoded = canonical(data)
            self.expected[version] = {"json_sha256": hashlib.sha256(encoded).hexdigest(), "json_bytes": len(encoded),
                                      "fixture_payload_bytes": len(data["payload"])}
            opened_before = self.payload_blocks("write-history-%d-blocks-before" % version)
            response = self.request("write-history-%d" % version, "POST", "secret/data/history", {"options": {"cas": version - 1}, "data": data})
            self.check(type(response["data"]["version"]) is int
                       and response["data"]["version"] == version, "write-version-%d" % version)
            opened_after = self.payload_blocks("write-history-%d-blocks-after" % version)
            self.check(opened_after == opened_before
                       and self.payload_io_unchanged("write-history-%d-blocks-before" % version,
                                                     "write-history-%d-blocks-after" % version),
                       "write-history-%d-no-old-payload-opens" % version,
                       before=opened_before, after=opened_after)
            self.written = version
            history_bytes += len(encoded)
            del data, encoded
        self.check(history_bytes > MIN_HISTORY_BYTES, "actual-distinct-history-json-above-128mib", observed=history_bytes)
        self.check(len({self.expected[version]["json_sha256"] for version in range(1, HISTORY_VERSIONS + 1)})
                   == HISTORY_VERSIONS, "all-40-history-json-hashes-distinct")
        expected_logical = baseline_logical + history_bytes
        self.capacity("capacity-after-40", expected_logical)
        self.read_version("history-first", 1)
        self.read_version("history-middle", 20)
        self.read_version("history-latest", 40)
        for version in range(1, HISTORY_VERSIONS + 1):
            self.read_version("all-committed-history-version-%d" % version, version)
        self.request("stale-cas-39", "POST", "secret/data/history", {"options": {"cas": 39}, "data": {"value": "stale"}}, expected=400)
        self.metadata("stale-cas-metadata-unchanged", 40)
        self.read_version("stale-cas-value-unchanged", 40)
        self.request("delete-specific-versions", "POST", "secret/delete/history", {"versions": [3, 17]}, expected=204)
        for version in (3, 17):
            response = self.request("deleted-%d" % version, "GET", "secret/data/history?version=%d" % version, expected=404)
            metadata = response["data"]["metadata"]
            self.check(metadata["version"] == version and bool(metadata["deletion_time"]) and not metadata["destroyed"],
                       "deleted-%d-actual-metadata" % version)
        self.read_version("retained-old-after-delete", 1)
        self.capacity("capacity-after-delete", expected_logical)
        self.stop()
        self.check(self.processes[-1]["actual_process_closed"], "first-process-actually-closed")
        self.inventory("before-cold-open")
        self.start(2)
        self.request("first-cold-unseal", "POST", "sys/unseal", {"key": self.unseal_key}, anonymous=True)
        self.check(self.payload_blocks("first-cold-payload-blocks") == 0
                   and self.payload_io_zero("first-cold-payload-blocks"), "first-cold-no-payload-open")
        self.finite_after_cold("first-cold")
        metadata = self.metadata("first-cold-metadata", 40)
        self.check(all(metadata["versions"][str(version)]["deletion_time"] for version in (3, 17)), "first-cold-delete-state-preserved")
        self.read_version("first-cold-old-version", 1)
        self.read_version("first-cold-latest-version", 40)
        for version in (3, 17):
            self.request("first-cold-deleted-%d" % version, "GET", "secret/data/history?version=%d" % version, expected=404)
        self.capacity("capacity-first-cold", expected_logical)
        self.stop()
        self.check(self.processes[-1]["actual_process_closed"], "second-process-actually-closed")
        self.inventory("after-first-cold-open")
        self.start(3)
        self.request("second-cold-unseal", "POST", "sys/unseal", {"key": self.unseal_key}, anonymous=True)
        self.check(self.payload_blocks("second-cold-payload-blocks") == 0
                   and self.payload_io_zero("second-cold-payload-blocks"), "second-cold-no-payload-open")
        self.finite_after_cold("second-cold")
        self.metadata("second-cold-metadata", 40)
        self.read_version("second-cold-old-version", 1)
        self.read_version("second-cold-latest-version", 40)
        for version in (3, 17):
            self.request("second-cold-deleted-%d" % version, "GET", "secret/data/history?version=%d" % version, expected=404)
        data = {**fixture(41), "fixture": "after-two-actual-cold-opens"}
        encoded = canonical(data)
        self.expected[41] = {"json_sha256": hashlib.sha256(encoded).hexdigest(), "json_bytes": len(encoded)}
        opened_before = self.payload_blocks("second-cold-point-blocks-before")
        response = self.request("second-cold-cas40-to41", "POST", "secret/data/history", {"options": {"cas": 40}, "data": data})
        self.check(type(response["data"]["version"]) is int
                   and response["data"]["version"] == 41, "second-cold-point-version41")
        opened_after = self.payload_blocks("second-cold-point-blocks-after")
        self.check(opened_after == opened_before
                   and self.payload_io_unchanged("second-cold-point-blocks-before", "second-cold-point-blocks-after"),
                   "second-cold-point-no-old-payload-opens",
                   before=opened_before, after=opened_after)
        self.read_version("second-cold-point-exact", 41)
        self.read_version("second-cold-old-after-point", 1)
        self.metadata("final-current-version", 41)
        self.capacity("capacity-after-point41", expected_logical + len(encoded))
        patched = {**data, "version": 42, "patched": True}
        patched_encoded = canonical(patched)
        self.expected[42] = {"json_sha256": hashlib.sha256(patched_encoded).hexdigest(), "json_bytes": len(patched_encoded)}
        opened_before = self.payload_blocks("second-cold-patch-blocks-before")
        response = self.request("second-cold-patch41-to42", "PATCH", "secret/data/history",
                                {"options": {"cas": 41}, "data": {"version": 42, "patched": True}})
        self.check(type(response["data"]["version"]) is int
                   and response["data"]["version"] == 42, "second-cold-patch-version42")
        opened_after = self.payload_blocks("second-cold-patch-blocks-after")
        current_blocks = (len(encoded) + BLOCK_BYTES - 1) // BLOCK_BYTES
        self.check(current_blocks > 1 and opened_after - opened_before == current_blocks
                   and self.selected_io_delta("second-cold-patch-blocks-before", "second-cold-patch-blocks-after",
                                              len(encoded), current_blocks),
                   "second-cold-patch-exact-current-payload-block-count",
                   before=opened_before, after=opened_after, expected_blocks=current_blocks)
        self.read_version("second-cold-patch-exact", 42)
        self.read_version("second-cold-prepatch-version41-retained", 41)
        self.read_version("second-cold-old-after-patch", 1)
        self.metadata("final-current-version-after-patch", 42)
        self.capacity("capacity-after-patch42", expected_logical + len(encoded) + len(patched_encoded))
        self.stop()
        self.check(self.processes[-1]["actual_process_closed"], "third-process-actually-closed")
        self.inventory("after-second-cold-point")
        self.start(4)
        self.request("post-patch-cold-unseal", "POST", "sys/unseal", {"key": self.unseal_key}, anonymous=True)
        self.check(self.payload_blocks("post-patch-cold-payload-blocks") == 0
                   and self.payload_io_zero("post-patch-cold-payload-blocks"), "post-patch-cold-no-payload-open")
        self.finite_after_cold("post-patch-cold")
        self.metadata("post-patch-cold-metadata", 42)
        self.read_version("post-patch-cold-version42-exact", 42)
        self.read_version("post-patch-cold-version41-retained", 41)
        self.read_version("post-patch-cold-version1-retained", 1)
        for version in (3, 17):
            self.request("post-patch-cold-deleted-%d" % version, "GET", "secret/data/history?version=%d" % version, expected=404)
        self.capacity("capacity-post-patch-cold", expected_logical + len(encoded) + len(patched_encoded))
        self.input_unchanged("final")
        self.complete = True

    def receipt(self, failure):
        logs = []
        for path in sorted(self.root.glob("server-*.log")):
            logs.append({"file": path.name, "bytes": path.stat().st_size, "sha256": file_sha(path)})
        planned = required_case_names()
        actual = [row["case"] for row in self.rows]
        denominator_complete = actual == planned and len(set(actual)) == len(actual)
        all_rows_passed = bool(self.rows) and all(row["passed"] is True for row in self.rows)
        all_processes_closed = (len(self.processes) == 4
                                and [row["cycle"] for row in self.processes] == [1, 2, 3, 4]
                                and all(row.get("actual_process_closed") is True for row in self.processes)
                                and all(row.get("exited_before_stop_request") is False for row in self.processes))
        actual_config = json.loads(self.config.read_bytes()) if self.config.exists() else {}
        override_present = "timeout_seconds" in actual_config
        runner_after = file_sha(Path(__file__).resolve())
        runner_unchanged = runner_after == self.runner_sha256_before
        resource_cycles = [self.resource_cycles[key] for key in sorted(self.resource_cycles)]
        resource_plan = required_resource_snapshot_names()
        resource_plan_complete = [row["label"] for row in self.resource_snapshots] == resource_plan
        resources_complete = (len(resource_cycles) == 4 and not self.resource_setup_errors
                              and all(row["valid_sample_count"] > 0 and not row["observation_errors"]
                                      and row["sampler_closed"] for row in resource_cycles)
                              and resource_plan_complete
                              and all(row["observation_valid"] for row in self.resource_snapshots))
        return {"schema": "heptabao.native-paged128-https-lifecycle.v1", "provenance": self.provenance,
                "runner_sha256": runner_after, "runner_sha256_before": self.runner_sha256_before,
                "runner_source_freeze_verified": runner_unchanged, "platform": platform.system(),
                "candidate_profile": "explicit-native-v6-feature-root-namespace-single-node",
                "https_endpoint": self.base, "server_timeout_seconds": SERVER_DEFAULT_TIMEOUT,
                "server_timeout_override_present": override_present,
                "actual_config_sha256": file_sha(self.config) if self.config.exists() else None,
                "client_transport_timeout_seconds": CLIENT_TIMEOUT,
                "history_versions_requested": HISTORY_VERSIONS, "history_versions_written": self.written,
                "fixture_payload_bytes_each": PAYLOAD_BYTES, "expected_fixture_hashes": self.expected,
                "history_json_bytes": sum(row["json_bytes"] for version, row in self.expected.items() if version <= HISTORY_VERSIONS),
                "processes": self.processes, "physical": self.physical, "capacity": self.capacities,
                "server_logs": logs, "rows": self.rows, "executed_cases": len(self.rows),
                "required_cases": len(planned), "required_case_names": planned,
                "scenario_denominator_complete": denominator_complete, "all_rows_passed": all_rows_passed,
                "source_freeze_checkpoints": self.source_states,
                "payload_block_observations": self.payload_block_observations,
                "payload_block_plaintext_header_bytes": PAYLOAD_OBJECT_HEADER_BYTES,
                "patch_current_payload_json_bytes": self.expected.get(41, {}).get("json_bytes"),
                "resource_observations": {
                    "scope": "only-four-owned-unreaped-Popen-children",
                    "target_sample_interval_seconds": RESOURCE_SAMPLE_INTERVAL_SECONDS,
                    "absolute_peak_claimed": False, "fd_snapshot_atomic": False,
                    "resources_complete": resources_complete,
                    "required_request_snapshots": len(resource_plan),
                    "actual_request_snapshots": len(self.resource_snapshots),
                    "request_snapshot_plan_complete": resource_plan_complete,
                    "observation_errors": self.resource_setup_errors,
                    "cycles": resource_cycles, "request_snapshots": self.resource_snapshots,
                    "server_budget_changed": False, "ulimit_changed": False,
                    "qualification_scope": "observed-FD-and-RSS-samples; source-and-lifetime-proof-needed-for-an-absolute-bound"},
                "cold_integrity_scope": "authenticated-typed-root-metadata-descriptors-and-actual-ciphertext-locator-pins",
                "cold_entire_payload_reauthenticated": False,
                "binary_execution_identity_scope": "owned-native-path-hash-before-and-after",
                "passed_cases": sum(row["passed"] for row in self.rows), "full_lifecycle_executed": self.complete,
                "passed": (failure is None and self.complete and not self.cleanup_errors
                           and denominator_complete and all_rows_passed and all_processes_closed
                           and resources_complete and not override_present and runner_unchanged),
                "failure": failure, "cleanup_errors": self.cleanup_errors,
                "cleanup": {"owned_process_running": self.process is not None and (
                                self.resource_sampler.alive() if self.resource_sampler is not None else self.process.poll() is None),
                            "all_four_actual_owned_processes_closed": all_processes_closed, "private_case_retained": True},
                "production_default_admitted": False, "ha_qualified": False,
                "namespace_qualified": False, "full_replacement_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--build-custody", type=Path, required=True)
    parser.add_argument("--build-custody-sha256", required=True)
    parser.add_argument("--frozen-test-manifest", type=Path, required=True)
    parser.add_argument("--frozen-test-manifest-sha256", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--port", type=int, default=38316)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("owned loopback port must be between 1024 and 65535")
    os.umask(0o077)
    try:
        provenance = admit(args)
    except Exception as error:
        failure = str(error) if isinstance(error, TrialFailure) else type(error).__name__
        print(json.dumps({"passed": False, "phase": "native-source-admission", "failure": failure}))
        return 2
    trial = Trial(args, provenance)
    failure = None
    try:
        trial.run()
    except Exception as error:
        failure = str(error) if isinstance(error, TrialFailure) else type(error).__name__
    finally:
        try:
            trial.stop()
        except Exception as error:
            trial.cleanup_errors.append("owned process cleanup failure: " + type(error).__name__)
            if failure is None:
                failure = "owned process cleanup failed"
        if trial.created:
            try:
                trial.input_unchanged("post-cleanup")
            except Exception as error:
                trial.cleanup_errors.append("post-cleanup source custody failure: " + type(error).__name__)
                if failure is None:
                    failure = "post-cleanup source custody failed"
            try:
                receipt = trial.receipt(failure)
                (trial.root / "receipt.json").write_bytes(json.dumps(receipt, indent=2).encode())
                print(json.dumps({"passed": receipt["passed"], "cases": receipt["executed_cases"],
                                  "passed_cases": receipt["passed_cases"], "failure": failure,
                                  "receipt": str(trial.root / "receipt.json")}))
            except Exception as error:
                print(json.dumps({"passed": False, "phase": "receipt-write", "failure_type": type(error).__name__}))
                return 3
        else:
            print(json.dumps({"passed": False, "phase": "owned-fixture-create", "failure": failure}))
    return 0 if trial.created and receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
