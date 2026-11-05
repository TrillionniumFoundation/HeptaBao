#!/usr/bin/env python3
'Stage the fixed native OpenAI/Undici profile once under the original 180-second outer deadline. Reuse the R4 owned-session and private-ancestor SDK input custody; the native driver retains its original owned-process registry for separate native and SDK child sessions.'
from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import tarfile
import time


HOST_ROOT = Path("/home/qian-qi/heptabao-next-gates-20261017")
SDK_ROOT = HOST_ROOT / "authbus-admission-sdk-20261018-01/openclaw"
NODE = Path("/usr/bin/node")
NODE_BYTES = 124827920
NODE_SHA = "fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48"
PACKET_BYTES = 103129
PACKET_SHA = '8d28e749fa6eae979092387cdb65c8b5c31d5a1f9d794f889c614914556243b6'
MANIFEST_BYTES = 39415
MANIFEST_SHA = 'fec7c304c098f36da547a664173900415d1330f5cbe37a1cdcc0c098ac1b7139'
SDK_MANIFEST_SHA = "b4aad3e15807db250900505d3cf5ab0e1d319d762c08cdb5a839edf214fb3a65"
OVERLAY_SHA = '236bc6d9d93263077b0d550f2fb3be8c3864c9db2c51f6366e1609482cd237b5'
PREFIX = "qa/openbao-acceptance/authbus/"
ENTRYPOINT = 'qa/openbao-acceptance/native_v6_authbus_openai_refresh_live.py'
PROFILE_SECONDS = 180
LOG_LIMIT = 16 * 1024 * 1024
PUBLIC_LIMIT = 4 * 1024 * 1024
MAX_SOURCE_FILE = 262144
SIGNALS = []


class Refusal(RuntimeError):
    """Closed diagnostic label; no credential or arbitrary log text."""


def need(condition, label):
    if not condition:
        raise Refusal(label)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def closed_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate_json_field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: need(False, "non_json_number"))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)


def check_deadline(deadline_ns):
    need(not SIGNALS, "owned_controller_interrupted")
    need(time.monotonic_ns() < deadline_ns, "original_180_second_deadline_expired")


def safe_directory(path, *, owner=True):
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_directory_required")
    value = path.lstat()
    need(stat.S_ISDIR(value.st_mode) and not value.st_mode & 0o022
         and (not owner or value.st_uid == os.geteuid()), "owned_directory_custody_required")


def read_regular(path, *, maximum, deadline_ns=None, owner=True, expected=None, collect=True, allow_empty=False):
    path = Path(path)
    need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
         "canonical_regular_file_required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    chunks, size, digest = [], 0, hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and (0 if allow_empty else 1) <= before.st_size <= maximum
             and not before.st_mode & 0o022 and (not owner or before.st_uid == os.geteuid()),
             "bounded_regular_file_custody_required")
        while True:
            if deadline_ns is not None:
                check_deadline(deadline_ns)
            chunk = os.read(descriptor, 262144)
            if not chunk:
                break
            size += len(chunk)
            need(size <= maximum, "bounded_file_grew")
            digest.update(chunk)
            if collect:
                chunks.append(chunk)
        need(identity(before) == identity(os.fstat(descriptor)) == identity(path.lstat())
             and size == before.st_size, "file_changed_during_checked_read")
        observed = {"bytes": size, "sha256": digest.hexdigest(), "identity": list(identity(before))}
        if expected is not None:
            need(observed["sha256"] == expected, "file_hash_mismatch")
        return (b"".join(chunks) if collect else None), observed
    finally:
        os.close(descriptor)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw, *, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), mode)


def canonical_relative(value):
    need(isinstance(value, str) and value and "\\" not in value, "canonical_relative_name_required")
    relative = PurePosixPath(value)
    need(not relative.is_absolute() and ".." not in relative.parts and str(relative) == value,
         "canonical_relative_name_required")
    return relative


def decode_packet(raw):
    need(len(raw) == PACKET_BYTES and sha(raw) == PACKET_SHA, "exact_frozen_packet_required")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        members = archive.getmembers()
        need(len(members) == len({member.name for member in members}) == 23,
             "exact_twenty_three_archive_members_required")
        for member in members:
            canonical_relative(member.name)
            need(member.isfile() and member.mode == 0o644 and 0 < member.size <= MAX_SOURCE_FILE,
                 "bounded_regular_archive_members_required")
        manifest_raw = archive.extractfile("source-manifest.json").read(MAX_SOURCE_FILE + 1)
        need(len(manifest_raw) == MANIFEST_BYTES and sha(manifest_raw) == MANIFEST_SHA,
             "exact_frozen_manifest_required")
        manifest = closed_json(manifest_raw)
        need(manifest["schema"] == "authbus-r5-native-openai-cold-runtime-v1"
             and manifest["entrypoint"] == ENTRYPOINT and manifest["runtimeFiles"] == 22
             and manifest["originalOuterBudgetSeconds"] == PROFILE_SECONDS
             and len(manifest["files"]) == 22, "manifest_runtime_binding_required")
        need(manifest["expectedScenarios"] == ["manager-success", "intent-ack-lost", "provider-ack-lost",
             "sqlite-abort", "guard-after-await"] and manifest["expectedControllerCheckCount"] == 141,
             "exact_native_openai_five_case_inventory_required")
        need(sha(encoded(manifest["sdkInputs"])) == SDK_MANIFEST_SHA, "exact_sdk_input_manifest_required")
        need({member.name for member in members} == {"source-manifest.json"} | {item["path"] for item in manifest["files"]},
             "closed_archive_source_inventory_required")
        python_paths = {"qa/openbao-acceptance/native_v6_authbus_openai_refresh_live.py",
            "qa/openbao-acceptance/native_v6_authbus_client_live.py", "qa/openbao-acceptance/owned_process.py",
            "qa/openbao-acceptance/cert_auth_live.py", "qa/openbao-acceptance/fixture_mounts.py", "qa/single-node/smoke.py"}
        need({item["path"] for item in manifest["files"] if item["path"].endswith(".py")} == python_paths,
             "six_exact_native_python_dependencies_required")
        payloads = {"source-manifest.json": manifest_raw}
        for item in manifest["files"]:
            name = item["path"]
            canonical_relative(name)
            need((name in python_paths or name.startswith(PREFIX) and name.endswith(".mjs"))
                 and item["mode"] == "100644", "exact_qa_source_scope_required")
            body = archive.extractfile(name).read(MAX_SOURCE_FILE + 1)
            need(len(body) == item["bytes"] and sha(body) == item["sha256"] and blob(body) == item["git_blob"],
                 "archive_source_pin_mismatch")
            payloads[name] = body
    return manifest, payloads


def stage_source(source, payloads, deadline_ns):
    source.mkdir(mode=0o700)
    for name, body in payloads.items():
        check_deadline(deadline_ns)
        target = source / name
        component = source
        for part in PurePosixPath(name).parts[:-1]:
            component = component / part
            try:
                component.mkdir(mode=0o700)
            except FileExistsError:
                info = component.lstat()
                need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                     and stat.S_IMODE(info.st_mode) == 0o700, "private_staging_directory_required")
        write_new(target, body, mode=0o644)
    for parent in sorted({source, *(path.parent for path in source.rglob("*") if path.is_file())}, key=str, reverse=True):
        sync_directory(parent)
    sync_directory(source.parent)


def verify_source(source, payloads, deadline_ns=None):
    safe_directory(source)
    files, directories = set(), set()
    for path in source.rglob("*"):
        relative = path.relative_to(source).as_posix()
        info = path.lstat()
        need(not stat.S_ISLNK(info.st_mode), "source_symlink_forbidden")
        if stat.S_ISDIR(info.st_mode):
            need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                 "private_source_parent_required")
            directories.add(relative)
        else:
            files.add(relative)
    expected_dirs = {str(parent) for name in payloads for parent in PurePosixPath(name).parents if str(parent) != "."}
    need(files == set(payloads) and directories == expected_dirs, "closed_staged_source_tree_required")
    for name, raw in payloads.items():
        observed, _ = read_regular(source / name, maximum=MAX_SOURCE_FILE,
                                   deadline_ns=deadline_ns, expected=sha(raw))
        need(observed == raw and stat.S_IMODE((source / name).stat().st_mode) == 0o644,
             "exact_staged_source_bytes_and_mode_required")
    return {"runtimeFiles": 22, "manifestFiles": 1, "exactClosedTree": True, "allPinsMatched": True}


def read_pinned_sdk_input(path, *, maximum, expected, deadline_ns=None):
    """Read only fixed SDK inputs protected by the existing private ancestor.

    Actual SDK files retain group-write bits. The owner-only 0700 HOST_ROOT
    prevents traversal to them by other users. Keep each directory fd and use
    O_NOFOLLOW relative opens; no caller can apply this rule outside SDK_ROOT.
    Generic inputs continue to use the unchanged stricter read_regular rule.
    """
    need(path.is_absolute() and path.is_relative_to(SDK_ROOT)
         and SDK_ROOT.is_relative_to(HOST_ROOT) and SDK_ROOT != HOST_ROOT
         and path.resolve(strict=True) == path, "fixed_sdk_private_read_scope_required")
    need(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
         "pinned_sdk_hash_required")
    relative = canonical_relative(path.relative_to(HOST_ROOT).as_posix())
    need(HOST_ROOT.resolve(strict=True) == HOST_ROOT, "canonical_sdk_private_ancestor_required")
    directories, descriptor = [], None

    def directory_identity(info):
        # Child creation in the shared task root can legitimately change its
        # timestamps/link count; inode, UID and permissions must remain bound.
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid)

    def retain_directory(current, name=None):
        if deadline_ns is not None:
            check_deadline(deadline_ns)
        fd = os.open(current if name is None else name,
                     os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                     **({} if name is None else {"dir_fd": directories[-1][1]}))
        directories.append((current, fd, None))
        info = os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
             and not info.st_mode & 0o002, "sdk_directory_owner_custody_required")
        if current == HOST_ROOT:
            need(stat.S_IMODE(info.st_mode) == 0o700, "sdk_private_ancestor_0700_required")
        bound = directory_identity(info)
        need(bound == directory_identity(current.lstat()), "sdk_directory_alias_or_change")
        directories[-1] = (current, fd, bound)

    try:
        retain_directory(HOST_ROOT)
        current = HOST_ROOT
        for component in relative.parts[:-1]:
            current = current / component
            retain_directory(current, component)
        descriptor = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directories[-1][1])
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.geteuid() and not before.st_mode & 0o002
             and 1 <= before.st_size <= maximum, "pinned_sdk_regular_custody_required")
        chunks, size, digest = [], 0, hashlib.sha256()
        while True:
            if deadline_ns is not None:
                check_deadline(deadline_ns)
            chunk = os.read(descriptor, 262144)
            if not chunk:
                break
            size += len(chunk)
            need(size <= maximum, "bounded_file_grew")
            digest.update(chunk)
            chunks.append(chunk)
        need(size == before.st_size and identity(before) == identity(os.fstat(descriptor))
             == identity(os.stat(relative.name, dir_fd=directories[-1][1], follow_symlinks=False))
             == identity(path.lstat()), "file_changed_during_checked_read")
        evidence = []
        for directory, fd, bound in directories:
            need(bound == directory_identity(os.fstat(fd)) == directory_identity(directory.lstat())
                 and directory.resolve(strict=True) == directory, "sdk_directory_changed_during_read")
            evidence.append({"relativeToPrivateAncestor": directory.relative_to(HOST_ROOT).as_posix(),
                             "device": bound[0], "inode": bound[1],
                             "mode": format(stat.S_IMODE(bound[2]), "04o"), "uid": bound[3]})
        need(digest.hexdigest() == expected, "file_hash_mismatch")
        return b"".join(chunks), {"bytes": size, "sha256": digest.hexdigest(),
                                  "identity": list(identity(before)),
                                  "mode": format(stat.S_IMODE(before.st_mode), "04o"),
                                  "uid": before.st_uid, "directories": evidence}
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for _path, fd, _bound in reversed(directories):
            os.close(fd)


def verify_sdk(sdk, manifest, deadline_ns=None):
    need(sdk == SDK_ROOT, "fixed_sdk_root_required")
    sdk_inputs = manifest["sdkInputs"]
    modules, metadata, discovery = sdk_inputs["modules"], sdk_inputs["metadata"], sdk_inputs["discoveryBindings"]
    need(len(modules) == 35 and len(metadata) == 1 and len(discovery) == 2,
         "exact_sdk_input_inventory_required")
    entries = [(item, MAX_SOURCE_FILE) for item in modules + discovery] + [(item, 65536) for item in metadata]
    need(len({item["relative"] for item, _ in entries}) == 38, "unique_sdk_inputs_required")
    result, directories = [], {}
    for item, limit in entries:
        relative = canonical_relative(item["relative"])
        path = sdk / str(relative)
        need(path.resolve(strict=True) == path, "sdk_input_alias_forbidden")
        raw, observed = read_pinned_sdk_input(path, maximum=limit, deadline_ns=deadline_ns,
                                              expected=item["originalSha256"])
        if item in metadata:
            data = closed_json(raw)
            need(data["id"] == "openai" and data["enabledByDefault"] is True,
                 "actual_openai_activation_metadata_required")
        if item["relative"] == "package.json":
            data = closed_json(raw)
            need(data["name"] == "openclaw" and data["version"] == "2026.7.1-2"
                 and data["bin"]["openclaw"] == "openclaw.mjs", "actual_sdk_package_binding_required")
        result.append({"relative": str(relative), "bytes": observed["bytes"], "sha256": observed["sha256"],
                       "mode": observed["mode"], "uid": observed["uid"], "identity": observed["identity"]})
        for row in observed["directories"]:
            name = row["relativeToPrivateAncestor"]
            need(name not in directories or directories[name] == row, "sdk_directory_changed_between_inputs")
            directories[name] = row
    return {"jsModules": 35, "activationMetadata": 1, "packageDiscoveryFiles": 2, "files": result,
            "privateAncestor": str(HOST_ROOT), "privateAncestorMode": "0700",
            "groupWritableInputsConfinedToPrivateAncestor": True,
            "directoryCustody": [directories[name] for name in sorted(directories)],
            "recursiveInstalledSdkTreeAttested": False}


def proc_identity(pid):
    """Kernel identity only; this never reads cmdline, environment or secrets."""
    root = Path("/proc") / str(pid)
    try:
        with (root / "stat").open("rb") as stream:
            raw = stream.read(8193)
        uid = root.stat().st_uid
    except (FileNotFoundError, ProcessLookupError):
        return None
    need(len(raw) <= 8192, "bounded_process_identity_required")
    prefix, separator, remaining = raw.rpartition(b") ")
    fields = remaining.split()
    need(separator and len(fields) >= 20 and prefix.split(b" ", 1)[0] == str(pid).encode(),
         "kernel_process_identity_malformed")
    return {"pid": pid, "ppid": int(fields[1]), "pgid": int(fields[2]), "sid": int(fields[3]),
            "start_ticks": int(fields[19]), "uid": uid, "state": fields[0].decode("ascii")}


def stable_identity(row):
    return {key: row[key] for key in ("pid", "ppid", "pgid", "sid", "start_ticks", "uid")}


def retain_owned_session(process):
    owner = proc_identity(process.pid)
    need(process.returncode is None and owner is not None and owner["ppid"] == os.getpid()
         and owner["pgid"] == owner["sid"] == process.pid and owner["uid"] == os.geteuid(),
         "new_owned_unreaped_session_required")
    return stable_identity(owner)


def observe_unreaped_exit(process):
    need(process.returncode is None, "owner_reaped_before_session_cleanup")
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


def live_owned_session(process, owner, deadline_ns):
    need(retain_owned_session(process) == owner, "owned_leader_identity_changed_no_signal")
    members = []
    with os.scandir("/proc") as entries:
        for entry in entries:
            need(time.monotonic_ns() < deadline_ns, "bounded_cleanup_observation_expired")
            if not entry.name.isdecimal():
                continue
            row = proc_identity(int(entry.name))
            if row is not None and row["sid"] == owner["sid"]:
                need(row["uid"] == owner["uid"] and row["start_ticks"] >= owner["start_ticks"],
                     "owned_session_member_identity_mismatch")
                if row["state"] != "Z":
                    members.append(row)
    return sorted(members, key=lambda row: row["pid"])


def signal_owned_session(process, owner, members, signum, receipt):
    need(retain_owned_session(process) == owner, "owned_leader_identity_changed_no_signal")
    # The original leader is still unreaped: its numeric group cannot have
    # been recycled. Normal SDK/openssl descendants inherit this group.
    os.killpg(process.pid, signum)
    receipt["signals"].append({"signal": int(signum), "authority": "original_unreaped_group", "pgid": process.pid})
    # A descendant that changes only PGID remains in this uniquely owned SID.
    # Bind it to a kernel pidfd and recheck identity before signaling; no
    # numeric signal is sent to a discovered/reused descendant PID or PGID.
    for row in members:
        if row["pgid"] == owner["pgid"]:
            continue
        try:
            fd = os.pidfd_open(row["pid"], 0)
        except ProcessLookupError:
            continue
        try:
            current = proc_identity(row["pid"])
            if current is None:
                continue
            # A stopped leader reparents its descendants. PPID is therefore
            # an observation, not part of their retained kernel identity.
            need(all(current[key] == row[key] for key in ("pid", "pgid", "sid", "start_ticks", "uid")),
                 "owned_descendant_identity_changed_no_signal")
            signal.pidfd_send_signal(fd, signum)
            receipt["signals"].append({"signal": int(signum), "authority": "owned_session_descendant_pidfd", "pid": row["pid"]})
        except ProcessLookupError:
            pass
        finally:
            os.close(fd)


def stop_owned(process, owner):
    """Never reap the leader until its retained session has no live members."""
    receipt = {"leaderPid": process.pid, "ownedSessionIdentity": owner, "leaderReaped": False,
               "ownedLiveSessionEmpty": False, "signals": [], "cleanupOnlySeconds": 10,
               "cleanupDoesNotExtendPassingDeadline": True, "observationFailures": []}
    need(retain_owned_session(process) == owner, "owned_leader_identity_changed_no_cleanup_signal")
    started_ns = time.monotonic_ns()
    term_ns, kill_ns = started_ns + 5_000_000_000, started_ns + 10_000_000_000
    members = live_owned_session(process, owner, term_ns)
    receipt["liveMembersBefore"] = [stable_identity(row) for row in members]
    for signum, until in ((signal.SIGTERM, term_ns), (signal.SIGKILL, kill_ns)):
        if not members:
            break
        signal_owned_session(process, owner, members, signum, receipt)
        while members and time.monotonic_ns() < until:
            try:
                members = live_owned_session(process, owner, until)
            except Refusal as error:
                # TERM grace expiring during a bounded scan must still reach
                # the declared KILL phase with the last owned observations.
                if str(error) != "bounded_cleanup_observation_expired":
                    receipt["observationFailures"].append(str(error))
                break
            if members:
                time.sleep(min(0.03, max(0, (until - time.monotonic_ns()) / 1e9)))
    receipt["liveMembersBeforeLeaderReap"] = [stable_identity(row) for row in members]
    need(not members, "owned_session_survivors_no_clean_receipt")
    receipt["ownedLiveSessionEmpty"] = True
    receipt["leaderExitCode"] = process.wait(timeout=max(0, (kill_ns - time.monotonic_ns()) / 1e9))
    receipt["leaderReaped"] = True
    receipt["sameOriginalPopenWaitCount"] = 1
    receipt["elapsedSeconds"] = (time.monotonic_ns() - started_ns) / 1e9
    return receipt


def run_owned_once(argv, *, cwd, environment, stdout_path, stderr_path, deadline_ns, journal, save):
    process, owner = None, None
    journal.update(status="submission_intent_saved", submissionCount=1, automaticRetry=False,
                   argv=list(argv), originalDeadlineNs=deadline_ns)
    save()
    try:
        check_deadline(deadline_ns)
        with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
            process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, start_new_session=True)
            journal.update(status="original_child_created", childPid=process.pid)
            save()
            # Signal handlers only record interruption until this original
            # Popen handle and birth identity have been durably registered.
            owner = retain_owned_session(process)
            journal.update(status="running", childPid=process.pid, ownedSessionIdentity=owner)
            save()
            while True:
                check_deadline(deadline_ns)
                need(stdout_path.stat().st_size <= LOG_LIMIT and stderr_path.stat().st_size <= LOG_LIMIT,
                     "owned_output_log_bound_exceeded")
                event = observe_unreaped_exit(process)
                if event is not None:
                    journal["observedChildExitCode"] = event.si_status if event.si_code == os.CLD_EXITED else -event.si_status
                    journal["childExitObservedNs"] = time.monotonic_ns()
                    check_deadline(deadline_ns)
                    break
                time.sleep(min(0.05, max(0, (deadline_ns - time.monotonic_ns()) / 1e9)))
    finally:
        if process is not None:
            try:
                owner = owner if owner is not None else retain_owned_session(process)
                journal["cleanup"] = stop_owned(process, owner)
            except BaseException as error:
                journal["cleanupFailure"] = str(error) if isinstance(error, Refusal) else type(error).__name__
                # Retain failure even if direct-child cleanup succeeds. This
                # fallback uses only the original handle, never guessed PIDs.
                try:
                    if process.returncode is None:
                        process.kill()
                        process.wait(timeout=5)
                    journal["failedCleanupOriginalLeaderReaped"] = process.returncode is not None
                except BaseException as cleanup_error:
                    journal["leaderCleanupUnresolved"] = type(cleanup_error).__name__
            journal["executionFinishedNs"] = time.monotonic_ns()
            save()
    need("cleanupFailure" not in journal and journal["cleanup"]["leaderReaped"]
         and journal["cleanup"]["ownedLiveSessionEmpty"] and not journal["cleanup"]["observationFailures"],
         "owned_process_cleanup_not_qualified")
    check_deadline(deadline_ns)
    return journal["observedChildExitCode"]


def verify_native_product(manifest, deadline_ns=None):
    product = manifest["productBuild"]
    need(product["sourceCommit"] == "b24c6de7831a7389e39ac069277a9e85e858ef98"
         and product["sourceTree"] == "3356f0a94616e9e1804f497239f33546e16db577"
         and product["binarySha256"] == "71b90de8a6ddb1723454a2623b970e915d64565b570cd8dd8342f5f0ffa6dc53"
         and product["binaryBytes"] == 779962728, "exact_r5_native_product_required")
    paths = {"buildReceiptPath": HOST_ROOT / "native-full55-b24c6de-main-r1/summary.json",
             "sourceManifestPath": HOST_ROOT / "source-b24c6de-manifest.json",
             "binaryPath": HOST_ROOT / "native-full55-b24c6de-main-r1/heptabao-server"}
    need(all(product[key] == str(value) for key, value in paths.items()), "fixed_native_product_paths_required")
    raw, receipt_pin = read_regular(paths["buildReceiptPath"], maximum=54396, deadline_ns=deadline_ns,
        expected="39c4990b541f8ca827791088c1ef1e669a6cc7f45f000728aa664e22b0765d73")
    receipt = closed_json(raw)
    need(receipt_pin["bytes"] == 54396 and receipt["source_commit"] == product["sourceCommit"]
         and receipt["source_tree"] == product["sourceTree"] and receipt["source_unchanged"] is True,
         "native_build_source_provenance_required")
    artifacts = [item for item in receipt["commands"] if item["label"] == "build-server"]
    need(len(artifacts) == 1 and artifacts[0]["status"] == "passed"
         and artifacts[0]["binary"] == product["binaryPath"] and artifacts[0]["binary_sha256"] == product["binarySha256"]
         and artifacts[0]["binary_bytes"] == product["binaryBytes"], "native_actual_build_artifact_required")
    raw, source_pin = read_regular(paths["sourceManifestPath"], maximum=663186, deadline_ns=deadline_ns,
        expected="739ffe3589e8b8c6ddca5efe56b4ef3d33a2633fce4451853413b14a6be6c3e1")
    source = closed_json(raw)
    need(source_pin["bytes"] == 663186 and source["commit"] == product["sourceCommit"]
         and source["tree"] == product["sourceTree"] and len(source["files"]) == 3142,
         "native_exact_build_manifest_required")
    _, binary_pin = read_regular(paths["binaryPath"], maximum=product["binaryBytes"], deadline_ns=deadline_ns,
        expected=product["binarySha256"], collect=False)
    need(binary_pin["bytes"] == product["binaryBytes"] and paths["binaryPath"].stat().st_mode & 0o111,
         "native_exact_executable_required")
    return {"sourceCommit": product["sourceCommit"], "sourceTree": product["sourceTree"], "sourceFiles": 3142,
            "buildReceipt": receipt_pin, "sourceManifest": source_pin, "binary": binary_pin,
            "artifactSizeLimitScope": "exact_pinned_debug_binary_only_no_product_request_limit_change"}

def exact_checks(value, names, label):
    checks = value.get("checks", [])
    need(value.get("ok") is True and [row.get("case") for row in checks] == names
         and value.get("checksPassed") == len(names) and all(row.get("passed") is True for row in checks), label)


def validate_public(value, manifest, pid, fixture, deadline_ns):
    need(value.get("schema") == "authbus-refresh-r5-native-openai-cold-live" and value.get("pid") == pid
         and value.get("parentPid") == os.getpid(), "public_original_native_driver_binding_required")
    need(value.get("nodeVersion") == "v22.23.3" and value.get("originalProfileSeconds") == 180
         and value.get("originalDeadlineNs") == str(deadline_ns) and 0 < value.get("elapsedSeconds", 181) < 180,
         "native_original_runtime_and_deadline_required")
    need(value.get("scenarioInventory") == manifest["expectedScenarios"], "all_five_native_openai_scenarios_required")
    need(len(manifest["orderedControllerCheckNames"]) == 141, "native_controller_manifest_inventory_required")
    exact_checks(value, manifest["orderedControllerCheckNames"], "all_141_native_openai_controller_assertions_required")
    for key in ("actualSdk", "actualSqlite", "actualSdkOAuthManager", "actualProviderHttps", "actualOpenAiSdkOAuthManager",
                "actualOpenAiSdkGuard", "actualOpenAiFacade", "actualUndiciRefreshTransport", "syntheticCredentials",
                "syntheticProvider", "actualNativeHeptaBao", "actualColdSdkProcess", "actualNativeSigkillRecovery"):
        need(value.get(key) is True, "required_public_boolean_" + key)
    for key in ("tlsControlEmulator", "realExternalProvider", "productionMutation", "realCredentialMigration",
                "originalNativeFourCaseResultInherited", "sdk32ScenarioResultInherited"):
        need(value.get(key) is False, "forbidden_public_qualification_" + key)
    need(value.get("originalNativeFourCaseDenominator") == 120
         and value.get("binarySha256") == manifest["productBuild"]["binarySha256"], "native_original_provenance_scope_required")
    source = value.get("sourceManifest", {})
    need(source.get("sha256") == MANIFEST_SHA and source.get("files") == [
        {key: row[key] for key in ("path", "sha256", "git_blob", "bytes")} for row in manifest["files"]],
        "native_public_exact_source_closure_required")
    worker_rows = value.get("workerReceipts", [])
    phases = ["warm", "cold-before-server", "cold-after-server"]
    need([row.get("phase") for row in worker_rows] == phases and len({row.get("pid") for row in worker_rows}) == 3
         and all(row.get("pid") not in (pid, os.getpid()) for row in worker_rows), "three_distinct_native_sdk_workers_required")
    source_modules = {Path(row["path"]).name: row["sha256"] for row in manifest["files"] if row["path"].endswith(".mjs")}
    need(len(source_modules) == 16, "sixteen_exact_worker_modules_required")
    expected_sdk = {row["relative"]: row["originalSha256"] for row in manifest["sdkInputs"]["modules"]}
    qualifications = []
    for phase, row in zip(phases, worker_rows):
        raw, pin = read_regular(fixture / "sdk/reports" / (phase + ".json"), maximum=2 * 1024 * 1024,
            deadline_ns=deadline_ns, expected=row["sha256"])
        worker = closed_json(raw)
        expectation = manifest["workerExpectations"][phase]
        need(row["exitCode"] == 0 and row["bytes"] == pin["bytes"] and worker.get("pid") == row["pid"]
             and worker.get("parentPid") == pid and worker.get("phase") == phase
             and worker.get("schema") == "authbus-refresh-r5-native-openai-sdk-worker", "native_worker_original_process_binding_required")
        need(expectation["expectedChecks"] == (87 if phase == "warm" else 80)
             and len(expectation["orderedCheckNames"]) == expectation["expectedChecks"], "worker_manifest_exact_inventory_required")
        exact_checks(worker, expectation["orderedCheckNames"], "native_worker_all_exact_assertions_required")
        need(row["checksPassed"] == row["checksTotal"] == expectation["expectedChecks"]
             and worker.get("nodeVersion") == "v22.23.3" and worker.get("sdkVersion") == "2026.7.1-2"
             and worker.get("originalDeadlineNs") == str(deadline_ns), "worker_runtime_and_original_clock_required")
        for key in ("actualSdk", "actualSqlite", "actualUndiciRuntimeBound", "nativeBackendQualifiedByParentOnly",
                    "syntheticCredentials", "syntheticProvider", "installedSdkUnchanged", "sourceFilesUnchanged",
                    "configUnchanged", "fixtureProcessContextRestored"):
            need(worker.get(key) is True, "required_worker_boolean_" + key)
        for key in ("actualNativeHeptaBao", "tlsControlEmulator", "realExternalProvider", "productionMutation"):
            need(worker.get(key) is False, "forbidden_worker_qualification_" + key)
        need(worker.get("actualColdSdkProcess") is (phase != "warm"), "worker_cold_process_scope_required")
        if phase == "warm":
            need(all(worker.get(key) is True for key in ("actualSdkOAuthManager", "actualProviderHttps",
                "actualOpenAiSdkOAuthManager", "actualOpenAiSdkGuard", "actualOpenAiFacade", "actualUndiciRefreshTransport")),
                "warm_actual_openai_dispatch_qualifications_required")
        for key in ("externalNetworkAttempts", "externalProcessAttempts", "outsideFixtureWriteAttempts", "outsideFixtureHomeReadAttempts"):
            need(worker.get(key) == 0, "forbidden_worker_attempt_" + key)
        need(worker.get("blockedHomeReads") == [], "worker_private_home_reads_forbidden")
        need(len(worker.get("sourceManifest", [])) == 16
             and {item["name"]: item["sha256"] for item in worker["sourceManifest"]} == source_modules,
             "worker_exact_source_closure_required")
        need(len(worker.get("oauthRefreshSdkModules", [])) == 35
             and {item["relative"]: item["originalSha256"] for item in worker["oauthRefreshSdkModules"]} == expected_sdk,
             "worker_exact_sdk_binding_required")
        need(worker.get("oauthRefreshSdkMetadata") == [{**manifest["sdkInputs"]["metadata"][0], "bytes": 16632, "usedAsCodeOverlay": False}],
             "worker_exact_activation_metadata_required")
        binding = worker.get("undiciRuntimeBinding", {})
        need(binding.get("packageVersion") == "8.5.0" and binding.get("actualPackageFetchIdentity") is True
             and binding.get("testRuntimeOverride") is False and binding.get("dnsOverride") is False
             and binding.get("packageSha256") == "4eed584bdf6a1545381c24674dfe8938421f7c66313c8960fb40f28f3a55c306"
             and binding.get("entrySha256") == "93fc85c00a59b58f410c901e5477d56770de3816bfbe183e751624aeb4a5e6a5",
             "worker_actual_undici_library_binding_required")
        need([item.get("scenario") for item in worker.get("cases", [])] == manifest["expectedScenarios"],
             "worker_exact_case_inventory_required")
        expected_counts = [1, 0, 1, 1, 0] if phase == "warm" else [0] * 5
        for item, count in zip(worker["cases"], expected_counts):
            need(item.get("undiciConnects") == item.get("providerDispatches") == count
                 and item.get("transport") == "actual-sdk-undici-owned-connect"
                 and item.get("oauthSdkObservations", {}).get("guardedRuntimeEntries") == count,
                 "worker_undici_single_dispatch_or_cold_zero_required")
            entry = "registered-fault-adapter-to-actual-sdk-refresh" if phase == "warm" and item["scenario"] == "guard-after-await" else "actual-sdk-shared-manager"
            need(item.get("entrypoint") == entry, "worker_entrypoint_scope_required")
        need(worker.get("ownedUndiciProxy") == {"connections": sum(expected_counts), "denials": 0, "upstreamFailures": 0},
             "worker_exact_owned_connect_totals_required")
        qualifications.append({"phase": phase, "pid": row["pid"], "checks": expectation["expectedChecks"], "receipt": pin})
    transport = value.get("transport", {})
    need(transport.get("counts") is not None and set(transport["counts"]) == set(manifest["expectedScenarios"]),
         "native_exact_transport_case_inventory_required")
    for case, count in manifest["expectedWarmProviderCounts"].items():
        row = transport["counts"][case]
        need(row.get("providerRequests") == row.get("unknownAtProvider") == count
             and row.get("unknownAckDrops") == (1 if case == "intent-ack-lost" else 0),
             "native_durable_unknown_and_send_vector_required")
    need(transport.get("localDenials") == 0 and transport.get("failures") == []
         and transport.get("rootBearerGivenToSdk") is False and transport.get("nativeDateForwarded") is True,
         "native_transport_custody_required")
    cycles = value.get("nativeProcessCycles", [])
    need(len(cycles) == 1 and cycles[0].get("stop") == "SIGKILL" and cycles[0].get("exitCode") == -9
         and cycles[0].get("oldPid") != cycles[0].get("newPid"), "native_actual_sigkill_reopen_required")
    ownership = value.get("ownedProcesses", {})
    need(ownership.get("passed_process_method") is True and ownership.get("same_originals_closed") is True
         and ownership.get("external_original_deadline") is True and ownership.get("original_deadline_ns") == deadline_ns
         and ownership.get("profile") == "authbus_refresh_native_openai_cold_r1" and ownership.get("children")
         and all(item.get("original_SID_retired_observed") is True and item.get("same_original_Popen_wait") is True
                 and item.get("completed_original_wait_count") == 1 and item.get("gaps") == []
                 and item.get("fallback") is False for item in ownership["children"]),
         "all_nested_original_children_and_sessions_closed_required")
    return {"cases": 5, "controllerChecks": 141, "workerQualifications": qualifications,
            "actualUndiciCases": 5, "actualNativeHeptaBao": True, "actualNativeSigkillRecovery": True,
            "actualColdSdkProcesses": 2, "realExternalProvider": False,
            "originalNative120ResultInherited": False, "sdk32ResultInherited": False}


def execute(args):
    os.umask(0o077)
    started_ns = time.monotonic_ns()
    deadline_ns = started_ns + PROFILE_SECONDS * 1_000_000_000
    root = args.run_root
    safe_directory(HOST_ROOT)
    need(root.is_absolute() and root.parent == HOST_ROOT
         and re.fullmatch(r"authbus-r5-native-openai-r1-actual-20261019-[0-9]{2}", root.name),
         "new_scoped_native_openai_run_directory_required")
    need(args.packet.is_absolute() and args.packet.parent == HOST_ROOT,
         "owned_host_root_packet_file_required")
    # mkdir is the durable one-submission claim. An existing/unknown run is
    # never adopted, overwritten, resumed or automatically retried.
    root.mkdir(mode=0o700)
    sync_directory(HOST_ROOT)
    journal = {"schema": "heptabao.authbus-native-openai-r1-once-controller.v1", "status": "preflight_intent_saved",
               "controllerPid": os.getpid(), "startedUtc": utc(), "startedNs": started_ns,
               "originalDeadlineNs": deadline_ns, "originalBudgetSeconds": PROFILE_SECONDS,
               "submissionCount": 0, "automaticRetry": False, "frozenOverlaySha256": OVERLAY_SHA,
               "sourcePacketSha256": PACKET_SHA, "sourceManifestSha256": MANIFEST_SHA,
               "sdkInputManifestSha256": SDK_MANIFEST_SHA, "actualNativeHeptaBao": False,
               "realExternalProvider": False, "realCredentials": False, "productionMutation": False,
               "controllerScriptSha256": sha(Path(__file__).read_bytes()), "interruptionSignals": SIGNALS}
    sequence = 0
    def save():
        nonlocal sequence
        sequence += 1
        journal["journalSequence"] = sequence
        temporary = root / ("controller.json.new-" + str(sequence))
        write_new(temporary, encoded(journal))
        os.replace(temporary, root / "controller.json")
        sync_directory(root)
    save()
    source = root / "source"
    fixture = root / "fixture"
    stdout, stderr = root / "driver.stdout.log", root / "driver.stderr.log"
    manifest, payloads = None, None
    source_before = sdk_before = product_before = None
    original_handlers = {}
    def interrupted(signum, _frame):
        SIGNALS.append({"signal": int(signum), "observedNs": time.monotonic_ns()})
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        original_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, interrupted)
    try:
        need(sys.platform == "linux" and hasattr(os, "waitid") and hasattr(os, "WNOWAIT")
             and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
             "linux_original_process_custody_required")
        journal["controllerIdentity"] = proc_identity(os.getpid())
        journal["bootId"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        raw, packet_pin = read_regular(args.packet, maximum=PACKET_BYTES, deadline_ns=deadline_ns, expected=PACKET_SHA)
        journal["packetInput"] = packet_pin
        manifest, payloads = decode_packet(raw)
        product_before = verify_native_product(manifest, deadline_ns)
        journal["productBefore"] = product_before
        sdk_before = verify_sdk(SDK_ROOT, manifest, deadline_ns)
        journal["sdkBefore"] = sdk_before
        _, node_pin = read_regular(NODE, maximum=NODE_BYTES, deadline_ns=deadline_ns,
                                   owner=False, expected=NODE_SHA, collect=False)
        need(node_pin["bytes"] == NODE_BYTES and NODE.stat().st_uid == 0
             and stat.S_IMODE(NODE.stat().st_mode) & 0o111, "observed_main_node_executable_required")
        journal["nodeInput"] = {"path": str(NODE), **node_pin, "versionFromSuccessfulNativeR1": "v22.23.3"}
        stage_source(source, payloads, deadline_ns)
        source_before = verify_source(source, payloads, deadline_ns)
        journal["sourceBefore"] = source_before
        product = manifest["productBuild"]
        interpreter = Path(sys.executable).resolve(strict=True)
        _, interpreter_pin = read_regular(interpreter, maximum=64 * 1024 * 1024, deadline_ns=deadline_ns,
                                           owner=False, collect=False)
        need(interpreter.stat().st_mode & 0o111, "current_python_interpreter_executable_required")
        journal["driverPythonInput"] = {"path": str(interpreter), **interpreter_pin}
        argv = [str(interpreter), "-B", str(source / ENTRYPOINT), "--binary", product["binaryPath"],
                "--binary-sha256", product["binarySha256"], "--node", str(NODE), "--openclaw-root", str(SDK_ROOT),
                "--source-manifest", str(source / "source-manifest.json"), "--work-dir", str(fixture),
                "--original-deadline-ns", str(deadline_ns)]
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8",
                       "LC_ALL": "C.UTF-8", "TZ": "UTC", "TMPDIR": str(root / "tmp"),
                       "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        (root / "tmp").mkdir(mode=0o700)
        # The SDK's explicit state/config/OAuth directories are set to the
        # fixture by its frozen runner. No host credentials or NODE_OPTIONS
        # are inherited from the controller's environment. HOME stays absent:
        # Node os.homedir() must still resolve the real account home so the
        # frozen runner's private-home read guard covers that actual location.
        journal["childExitCode"] = run_owned_once(argv, cwd=source, environment=environment,
            stdout_path=stdout, stderr_path=stderr, deadline_ns=deadline_ns, journal=journal, save=save)
        need(journal["childExitCode"] == 0, "actual_native_openai_driver_failed")
        public_raw, public_pin = read_regular(fixture / "public-receipt.json", maximum=PUBLIC_LIMIT,
                                             deadline_ns=deadline_ns)
        journal["publicReceipt"] = {"path": str(fixture / "public-receipt.json"), **public_pin}
        journal["actualResult"] = validate_public(closed_json(public_raw), manifest, journal["childPid"], fixture, deadline_ns)
        journal["actualNativeHeptaBao"] = True
        journal["status"] = "passed"
    except BaseException as error:
        journal["status"] = "failed_or_blocked"
        journal["failure"] = str(error) if isinstance(error, Refusal) else type(error).__name__
        journal["timedOut"] = time.monotonic_ns() >= deadline_ns
    finally:
        # Reconciliation reads after a timeout are bounded but cannot reset
        # its deadline or upgrade its recorded failure to PASS.
        if source_before is not None:
            try:
                journal["sourceAfter"] = verify_source(source, payloads)
                journal["sourceUnchanged"] = journal["sourceAfter"] == source_before
            except BaseException as error:
                journal["sourceUnchanged"] = False
                journal["sourceAfterFailure"] = str(error) if isinstance(error, Refusal) else type(error).__name__
        if product_before is not None:
            try:
                journal["productAfter"] = verify_native_product(manifest)
                journal["productUnchanged"] = journal["productAfter"] == product_before
            except BaseException as error:
                journal["productUnchanged"] = False
                journal["productAfterFailure"] = str(error) if isinstance(error, Refusal) else type(error).__name__
        if sdk_before is not None:
            try:
                journal["sdkAfter"] = verify_sdk(SDK_ROOT, manifest)
                journal["sdkUnchanged"] = journal["sdkAfter"] == sdk_before
            except BaseException as error:
                journal["sdkUnchanged"] = False
                journal["sdkAfterFailure"] = str(error) if isinstance(error, Refusal) else type(error).__name__
        for label, path, limit in (("stdout", stdout, LOG_LIMIT), ("stderr", stderr, LOG_LIMIT),
                                   ("originalPublicReceipt", fixture / "public-receipt.json", PUBLIC_LIMIT)):
            try:
                if path.exists():
                    _, journal[label] = read_regular(path, maximum=limit, collect=False,
                                                     allow_empty=label != "originalPublicReceipt")
            except BaseException as error:
                journal[label + "ReconciliationFailure"] = str(error) if isinstance(error, Refusal) else type(error).__name__
                journal["status"] = "failed_or_blocked"
        journal["finishedNs"] = time.monotonic_ns()
        journal["finishedUtc"] = utc()
        journal["elapsedSeconds"] = (journal["finishedNs"] - started_ns) / 1e9
        journal["withinOriginal180Seconds"] = journal["finishedNs"] < deadline_ns
        if not journal["withinOriginal180Seconds"] or not journal.get("sourceUnchanged") or not journal.get("sdkUnchanged") or not journal.get("productUnchanged") or SIGNALS:
            journal["status"] = "failed_or_blocked"
        save()
        # The inherited clock also covers durable terminal publication. A
        # late fsync preserves failure; it never earns a fresh passing budget.
        if time.monotonic_ns() >= deadline_ns or SIGNALS:
            journal["status"] = "failed_or_blocked"
            journal["withinOriginal180Seconds"] = False
            journal["terminalPublicationExceededOriginalBudget"] = True
            journal["finishedNs"] = time.monotonic_ns()
            journal["elapsedSeconds"] = (journal["finishedNs"] - started_ns) / 1e9
            save()
        for signum, handler in original_handlers.items():
            signal.signal(signum, handler)
    print(json.dumps({"status": journal["status"], "controller": str(root / "controller.json"),
                      "controllerPid": os.getpid(), "childPid": journal.get("childPid"),
                      "submissionCount": journal["submissionCount"], "childExitCode": journal.get("childExitCode", journal.get("observedChildExitCode")),
                      "elapsedSeconds": journal["elapsedSeconds"], "actualResult": journal.get("actualResult")}), flush=True)
    return 0 if journal["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    return execute(parser.parse_args())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, Refusal, ValueError) as error:
        print(json.dumps({"status": "refused_without_retry", "failure": str(error) if isinstance(error, Refusal) else type(error).__name__}), flush=True)
        raise SystemExit(2)
