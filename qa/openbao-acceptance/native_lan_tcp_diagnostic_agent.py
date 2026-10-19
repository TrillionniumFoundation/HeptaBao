#!/usr/bin/env python3
"""Owned, bounded pre-TLS observation. No init, unseal or activation requests."""
from __future__ import annotations

import base64
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid


ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
LISTENER_SECONDS = 25
NATIVE_SECONDS = 12
NATIVE_OBSERVE_SECONDS = 10
CONNECT_SECONDS = 2
IPS = {"macbook-pro": "192.168.0.7", "rog": "192.168.0.10", "pocket4": "192.168.0.9"}
HOSTS = {"macbook-pro": "MacBook-Pro.local", "rog": "qian-qi-ROG-Flow-Z13-GZ302EA-GZ302EA",
         "pocket4": "alex-G1628-04"}
ORIGINAL_MAC_ROOT = "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261018/native-lan98-0f1c-20261019-r1"
ORIGINAL_BINARY_SHA = "228bafc8cacc99c5a161f3a3b9892ead6839a65fd524765e1db384130c30abb7"
ORIGINAL_HA_SHA = "aa8c32decc5f1e0b907528cc33242d2954be575ac0a29aa948523fb0e2acbcb7"
ORIGINAL_SERVER_SHA = "d9d78790f4e074b5f0da2527395cb3799f44e5a2b379e2d0693837109891db63"


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def new_file(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def checked_file(path, *, limit=1024 ** 2, private=True):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_input_required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
             and not before.st_mode & (0o077 if private else 0o022)
             and 0 < before.st_size <= limit, "owned_input_required")
        h, size, chunks = hashlib.sha256(), 0, []
        while part := os.read(fd, 1024 ** 2):
            h.update(part)
            size += len(part)
            need(size <= limit, "input_bound_exceeded")
            if limit <= 1024 ** 2:
                chunks.append(part)
        def identity(s):
            return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_uid, s.st_mode, s.st_nlink)
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.stat()),
             "input_changed_during_read")
        return h.hexdigest(), b"".join(chunks)
    finally:
        os.close(fd)


def metadata(argv, seconds=0.5):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=ENV, timeout=seconds)
    need(len(result.stdout) <= 1024 ** 2 and len(result.stderr) <= 65536, "metadata_output_bound")
    return result


def process_identity(pid):
    result = metadata(["/bin/ps", "-p", str(pid), "-o", "pid=,ppid=,pgid=,uid=,stat=,lstart="])
    if result.returncode == 1 and not result.stdout.strip():
        return None
    need(result.returncode == 0, "process_identity_unavailable")
    fields = result.stdout.decode("ascii").strip().split(None, 5)
    need(len(fields) == 6, "process_identity_malformed")
    return {"pid": int(fields[0]), "ppid": int(fields[1]), "pgid": int(fields[2]), "uid": int(fields[3]),
            "sid": os.getsid(pid), "state": fields[4], "start_identity": fields[5]}


def stable_identity(row):
    return {key: row[key] for key in ("pid", "ppid", "pgid", "sid", "uid", "start_identity")}


def parent_chain(pid):
    """Public ownership metadata, without commands, arguments or environment."""
    chain = []
    for _ in range(6):
        if pid <= 0 or any(row["pid"] == pid for row in chain):
            break
        row = process_identity(pid)
        if row is None:
            break
        chain.append(stable_identity(row))
        pid = row["ppid"]
    return chain


def group_live_members(pgid):
    result = metadata(["/bin/ps", "-axo", "pid=,pgid=,stat="])
    need(result.returncode == 0, "owned_group_observation_unavailable")
    members = []
    for line in result.stdout.decode("ascii").splitlines():
        fields = line.split()
        need(len(fields) == 3, "owned_group_observation_malformed")
        if int(fields[1]) == pgid and not fields[2].startswith("Z"):
            members.append(int(fields[0]))
    return sorted(members)


def stop_unreaped_owned(process, owner):
    """Never call poll/wait before the final group signal: PID stays reserved."""
    receipt = {"leader_pid": process.pid, "group_id": process.pid, "ownership_verified": False,
               "leader_reaped": False, "owned_live_group_empty": False, "signals": []}
    need(process.returncode is None, "leader_already_reaped_no_group_signal")
    current = process_identity(process.pid)
    need(current is not None and stable_identity(current) == stable_identity(owner)
         and current["ppid"] == os.getpid() and current["pgid"] == process.pid
         and current["uid"] == os.geteuid() and os.getsid(process.pid) == process.pid,
         "owned_session_identity_changed_no_signal")
    receipt["ownership_verified"] = True
    before = group_live_members(process.pid)
    receipt["live_group_before"] = before
    # The leader cannot be reused until this function's final wait. Even an
    # already exited leader pins the same group while descendants are stopped.
    os.killpg(process.pid, signal.SIGTERM)
    receipt["signals"].append("SIGTERM")
    until = time.monotonic() + 0.7
    remaining = before
    while time.monotonic() < until:
        remaining = group_live_members(process.pid)
        if not remaining:
            break
        time.sleep(min(0.03, max(0, until - time.monotonic())))
    if remaining:
        os.killpg(process.pid, signal.SIGKILL)
        receipt["signals"].append("SIGKILL")
        until = time.monotonic() + 0.35
        while time.monotonic() < until:
            remaining = group_live_members(process.pid)
            if not remaining:
                break
            time.sleep(min(0.02, max(0, until - time.monotonic())))
    receipt["live_group_before_leader_reap"] = remaining
    receipt["owned_live_group_empty"] = not remaining
    receipt["leader_exit_code"] = process.wait(timeout=0.5)
    receipt["leader_reaped"] = True
    return receipt


def check_root(payload, *, existing):
    alias = payload["alias"]
    need(alias in IPS and platform.node() == HOSTS[alias], "actual_host_mismatch")
    root = Path(payload["root"])
    need(re.fullmatch(r"[a-zA-Z0-9_-]{8,96}", payload["run_id"]) is not None, "run_id_invalid")
    parents = {"macbook-pro": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261018",
               "rog": "/home/qian-qi", "pocket4": "/home/alex"}
    need(root.is_absolute() and str(root.parent) == parents[alias] and root.parent.resolve(strict=True) == root.parent
         and "heptabao" in root.name and payload["run_id"] in root.name,
         "new_task_root_outside_exact_parent")
    parent = root.parent.stat()
    need(parent.st_uid == os.geteuid() and not parent.st_mode & 0o022, "owned_root_parent_required")
    if existing:
        info = root.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077
             and root.resolve(strict=True) == root, "owned_task_root_required")
    else:
        need(not root.exists() and not root.is_symlink(), "diagnostic_root_already_exists_no_retry")
    return root


def ports_empty(alias):
    if alias == "macbook-pro":
        result = metadata(["/usr/sbin/lsof", "-nP", "-iTCP:46230", "-iTCP:46231", "-sTCP:LISTEN"], 2)
        need(result.returncode == 1 and not result.stdout.strip(), "mac_fixture_port_already_listening")
    else:
        result = metadata(["/usr/bin/ss", "-H", "-ltn", "sport = :46231"], 2)
        need(result.returncode == 0 and not result.stdout.strip(), "linux_fixture_port_already_listening")


def prepare(payload):
    root = check_root(payload, existing=False)
    ports_empty(payload["alias"])
    source = base64.b64decode(payload["agent_base64"], validate=True)
    need(len(source) <= 65536 and digest(source) == payload["agent_sha256"], "agent_digest_mismatch")
    root.mkdir(mode=0o700)
    marker = {key: payload[key] for key in ("alias", "run_id", "root", "agent_sha256")}
    marker.update(schema="heptabao.native-lan-tcp-diagnostic-owner.v1", root_device=root.stat().st_dev,
                  root_inode=root.stat().st_ino, production_authority=False, initialization_performed=False)
    new_file(root / "agent.py", source)
    if payload["alias"] == "macbook-pro":
        old = Path(ORIGINAL_MAC_ROOT)
        binary = old / "heptabao-server"
        need(checked_file(binary, limit=2 * 1024 ** 3, private=False)[0] == ORIGINAL_BINARY_SHA,
             "original_native_binary_pin_mismatch")
        ha_sha, ha_raw = checked_file(old / "ha.json")
        server_sha, server_raw = checked_file(old / "server.json")
        need(ha_sha == ORIGINAL_HA_SHA and server_sha == ORIGINAL_SERVER_SHA, "original_config_pin_mismatch")
        ha, server = json.loads(ha_raw), json.loads(server_raw)
        need(ha["node_id"] == 1 and ha["bootstrap"] is True and ha["listen"] == "192.168.0.7:46231"
             and server["listen"] == "192.168.0.7:46230", "original_local_endpoint_mismatch")
        need({key: value["address"] for key, value in ha["peers"].items()} ==
             {"1": "192.168.0.7:46231", "2": "192.168.0.10:46231", "3": "192.168.0.9:46231"},
             "original_peer_map_mismatch")
        # TLS and replication material never leaves this owner/host. Original
        # data and raft directories are neither read nor copied nor opened.
        private_inputs = {}
        for field in ("ca_file", "cert_file", "key_file", "replication_key_file"):
            before = Path(ha[field])
            need(before.parent == old, "owned_original_tls_path_required")
            value_sha, value_raw = checked_file(before)
            private_inputs[str(before)] = value_sha
            after = root / before.name
            if not after.exists():
                new_file(after, value_raw)
            ha[field] = str(after)
        ha["cluster_id"] = str(uuid.uuid4())
        ha["raft_dir"] = str(root / "raft")
        server.update(data_dir=str(root / "data"), audit_file=str(root / "audit.jsonl"),
                      tls_cert_file=ha["cert_file"], tls_key_file=ha["key_file"])
        (root / "data").mkdir(mode=0o700)
        (root / "raft").mkdir(mode=0o700)
        new_file(root / "ha.json", canonical(ha))
        new_file(root / "server.json", canonical(server))
        marker.update(original_binary=str(binary), original_binary_sha256=ORIGINAL_BINARY_SHA,
                      original_ha_sha256=ha_sha, original_server_sha256=server_sha,
                      private_input_hashes=private_inputs)
    new_file(root / "owner.json", canonical(marker))
    return {"prepared": True, "alias": payload["alias"], "root": str(root), "run_id": payload["run_id"],
            "actual_hostname": platform.node(), "ports_observed_empty": True,
            "agent_sha256": payload["agent_sha256"], "production_authority": False}


def load_marker(payload):
    root = check_root(payload, existing=True)
    _, raw = checked_file(root / "owner.json")
    marker = json.loads(raw)
    need(all(marker[key] == payload[key] for key in ("alias", "run_id", "root", "agent_sha256"))
         and marker["root_device"] == root.stat().st_dev and marker["root_inode"] == root.stat().st_ino
         and marker["production_authority"] is False, "owned_marker_mismatch")
    need(checked_file(root / "agent.py")[0] == marker["agent_sha256"], "actual_agent_source_mismatch")
    return root, marker


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def listener(root, marker, receipt):
    accepted = []
    start = time.monotonic()
    # Reserve half a second for close/projection before the original 25s
    # ceiling. No success condition gains a scheduler-grace extension.
    deadline = start + LISTENER_SECONDS - 0.5
    receipt.update(listener_deadline_seconds=LISTENER_SECONDS, bind_ip=IPS[marker["alias"]], port=46231,
                   payload_read_count=0, accepted=[], socket_closed=False)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((IPS[marker["alias"]], 46231))
        server.listen(64)
        emit({"ready": True, "alias": marker["alias"], "pid": os.getpid(), "pgid": os.getpgrp(),
              "listen_deadline_seconds": LISTENER_SECONDS, "wall_time_ns": time.time_ns()})
        while time.monotonic() < deadline:
            server.settimeout(min(0.15, deadline - time.monotonic()))
            try:
                client, address = server.accept()
            except socket.timeout:
                continue
            with client:
                need(len(accepted) < 4096, "bounded_accept_observations_exhausted")
                accepted.append({"from_expected_mac": address[0] == IPS["macbook-pro"],
                                 "source_port": address[1], "wall_time_ns": time.time_ns()})
    receipt.update(accepted=accepted, socket_closed=True, accepted_count=len(accepted),
                   expected_mac_accept_count=sum(row["from_expected_mac"] for row in accepted),
                   active_elapsed_seconds=round(time.monotonic() - start, 6))
    # Scheduling may finish the final close after the absolute endpoint. Keep
    # its actual time; an overshoot never extends this experiment's admission.
    receipt["listener_original_deadline_observed"] = receipt["active_elapsed_seconds"] <= LISTENER_SECONDS


def native_window(root, marker, receipt):
    binary = Path(marker["original_binary"])
    need(checked_file(binary, limit=2 * 1024 ** 3, private=False)[0] == ORIGINAL_BINARY_SHA,
         "original_binary_changed_before_launch")
    need(not any((root / "data").iterdir()) and not any((root / "raft").iterdir()),
         "native_start_requires_new_empty_data_and_raft")
    argv = [str(binary), "--config", str(root / "server.json"), "--ha-config", str(root / "ha.json"),
            "--experimental-native-v6-ha"]
    receipt.update(native_argv=argv, original_binary_sha256=ORIGINAL_BINARY_SHA, native_window_limit_seconds=NATIVE_SECONDS,
                   observation_seconds=NATIVE_OBSERVE_SECONDS, native_submission_count=1, native_exited_early=False,
                   api_request_count=0, initialization_performed=False, unseal_performed=False, activation_performed=False)
    new_file(root / "native-intent.json", canonical({"argv": argv, "binary_sha256": ORIGINAL_BINARY_SHA,
                                                   "submission_count": 1, "automatic_retry": False}))
    child, owner = None, None
    began = time.monotonic()
    try:
        with (root / "process.log").open("xb") as stream:
            os.chmod(root / "process.log", 0o600)
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                                     cwd=root, env=ENV, start_new_session=True)
        owner = process_identity(child.pid)
        need(owner is not None and owner["ppid"] == os.getpid() and owner["pgid"] == child.pid
             and owner["uid"] == os.geteuid() and os.getsid(child.pid) == child.pid, "native_owned_session_required")
        receipt["native_identity"] = stable_identity(owner)
        receipt["native_parent_chain"] = parent_chain(child.pid)
        new_file(root / "native-identity.json", canonical(stable_identity(owner)))
        emit({"ready": True, "alias": "macbook-pro", "pid": os.getpid(), "pgid": os.getpgrp(),
              "native_identity": stable_identity(owner), "wall_time_ns": time.time_ns()})
        until = began + NATIVE_OBSERVE_SECONDS
        while time.monotonic() + 0.5 < until:
            current = process_identity(child.pid)
            need(current is not None and stable_identity(current) == stable_identity(owner), "native_identity_changed")
            if current["state"].startswith("Z"):
                receipt["native_exited_early"] = True
                break
            time.sleep(min(0.1, max(0, until - time.monotonic() - 0.5)))
    finally:
        if child is not None:
            # Popen.poll/wait/communicate have not reaped this leader.
            if owner is None:
                owner = process_identity(child.pid)
            need(owner is not None, "native_owner_unavailable_cleanup_not_claimed")
            last_observation = process_identity(child.pid)
            if last_observation is not None and last_observation["state"].startswith("Z"):
                receipt["native_exited_early"] = True
            receipt["native_cleanup"] = stop_unreaped_owned(child, owner)
            receipt["native_elapsed_seconds"] = round(time.monotonic() - began, 6)
            receipt["native_within_original_deadline"] = receipt["native_elapsed_seconds"] <= NATIVE_SECONDS
    # Each control is one connect, after the exact native session has stopped.
    need(receipt["native_cleanup"]["leader_reaped"] and receipt["native_cleanup"]["owned_live_group_empty"],
         "native_session_not_closed_no_python_control")
    controls = []
    for alias in ("rog", "pocket4"):
        before = time.monotonic()
        row = {"target": IPS[alias] + ":46231", "submission_count": 1, "automatic_retry": False,
               "deadline_seconds": CONNECT_SECONDS, "connected": False, "wall_time_ns": time.time_ns()}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as endpoint:
                endpoint.settimeout(CONNECT_SECONDS)
                endpoint.connect((IPS[alias], 46231))
                row.update(connected=True, source_ip=endpoint.getsockname()[0], source_port=endpoint.getsockname()[1])
        except OSError as error:
            row.update(error_type=type(error).__name__, errno=error.errno)
        row["elapsed_seconds"] = round(time.monotonic() - before, 6)
        row["response_within_original_deadline"] = row["elapsed_seconds"] < CONNECT_SECONDS
        controls.append(row)
    receipt["python_controls"] = controls
    raw = (root / "process.log").read_bytes()
    need(len(raw) <= 1024 ** 2, "bounded_native_diagnostic_log_required")
    stages = collections.Counter()
    for match in re.finditer(rb"HBHA-PRIVATE-STAGE phase=([a-z_]+) category=([A-Za-z]+)(?: io_kind=([A-Za-z]+))?", raw):
        stages["/".join(value.decode("ascii") for value in match.groups() if value)] += 1
    receipt.update(native_log_sha256=digest(raw), native_log_bytes=len(raw), native_stage_counts=dict(stages),
                   native_tls_listener_ready=b"HeptaBao HA TLS listener ready" in raw,
                   expected_dummy_listener_tls_eof_is_ha_pass=False)
    unchanged = checked_file(binary, limit=2 * 1024 ** 3, private=False)[0] == ORIGINAL_BINARY_SHA
    unchanged &= checked_file(Path(ORIGINAL_MAC_ROOT) / "ha.json")[0] == ORIGINAL_HA_SHA
    unchanged &= checked_file(Path(ORIGINAL_MAC_ROOT) / "server.json")[0] == ORIGINAL_SERVER_SHA
    for path, expected in marker["private_input_hashes"].items():
        unchanged &= checked_file(Path(path))[0] == expected
    receipt["original_binary_configs_and_copied_inputs_unchanged"] = bool(unchanged)
    receipt["original_data_and_raft_opened_by_diagnostic"] = False


def run(payload):
    root, marker = load_marker(payload)
    ports_empty(marker["alias"])
    # A second start, including an unknown first result, always refuses here.
    new_file(root / "active-once.json", canonical({"pid": os.getpid(), "started_wall_time_ns": time.time_ns()}))
    receipt = {"schema": "heptabao.native-lan-tcp-diagnostic-agent.v1", "alias": marker["alias"],
               "run_id": marker["run_id"], "root": str(root), "agent_sha256": marker["agent_sha256"],
               "actual_hostname": platform.node(), "started_wall_time_ns": time.time_ns(),
               "watchdog_identity": process_identity(os.getpid()), "production_authority": False,
               "watchdog_parent_chain": parent_chain(os.getpid()),
               "launcher_lifecycle": "foreground SSH/Python watchdog stays alive until owned native child cleanup",
               "ha_qualification": False, "original_lan98_passed": 36, "original_lan98_required": 98,
               "automatic_retry": False, "status": "running"}
    try:
        if marker["alias"] == "macbook-pro":
            native_window(root, marker, receipt)
        else:
            listener(root, marker, receipt)
        receipt["status"] = "observed"
    except BaseException as error:
        receipt.update(status="failed_or_unknown", failure_code=str(error) if isinstance(error, Refusal) else type(error).__name__)
    finally:
        receipt["finished_wall_time_ns"] = time.time_ns()
        new_file(root / "summary.json", canonical(receipt))
    emit({"finished": True, "alias": marker["alias"], "status": receipt["status"],
          "summary_sha256": digest(canonical(receipt))})
    return 0 if receipt["status"] == "observed" else 1


def collect(payload):
    root, _ = load_marker(payload)
    observed, raw = checked_file(root / "summary.json")
    result = json.loads(raw)
    previous = result["watchdog_identity"]
    current = process_identity(previous["pid"])
    result["watchdog_identity_no_longer_running"] = (current is None or current["state"].startswith("Z")
                                                    or stable_identity(current) != stable_identity(previous))
    return {"summary_sha256": observed, "summary": result}


def main():
    action, encoded = sys.argv[1:]
    payload = json.loads(base64.b64decode(encoded, validate=True))
    def interrupted(_signal, _frame):
        raise InterruptedError("owned_diagnostic_interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if action == "prepare":
        emit(prepare(payload))
        return 0
    if action == "run":
        return run(payload)
    if action == "collect":
        emit(collect(payload))
        return 0
    raise Refusal("unknown_action")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        emit({"status": "refused", "failure_code": str(error) if isinstance(error, Refusal) else type(error).__name__})
        raise SystemExit(2)
