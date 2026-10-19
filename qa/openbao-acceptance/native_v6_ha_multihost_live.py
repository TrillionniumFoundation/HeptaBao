#!/usr/bin/env python3
"""Real native V6 HA on three NEW physical-host fixture roots.

Use the same source/binary/build-receipt arguments as ha_multihost_live.py.
The existing complete SSH mesh transports end-to-end pinned mTLS. This profile
has its own fixed denominator; none of the separate baseline's 62 checks or
unsupported native HA backup/snapshot checks are borrowed. All HTTP operations
retain 15 seconds; a failed/unknown mutation is never retried. The runtime's
independent native ReadIndex/closure admission cap remains eight seconds.

Seventeen 2 MiB values remain in one real KV2 history. Large bodies are read
directly from an elected leader; the existing 1 MiB HTTP forwarding frame is
not enlarged. A separate small KV request checks actual standby forwarding.
Only newly owned process identities and roots are touched. Missing-ciphertext
injection moves immutable fixture leaves into an owner-only quarantine after
their processes stop, retaining all manifests, locks, Raft and local barriers.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import ssl
import stat
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse

import ha_multihost_live as base
import ha_three_host_loopback_live as loopback
import native_fixture_recovery as recovery

MIB = 1024 * 1024
PAYLOAD_BYTES = 2 * MIB
HISTORY_WRITES = 17
TARGET_BYTES = PAYLOAD_BYTES * HISTORY_WRITES
REQUEST_SECONDS = 15
NATIVE_ADMISSION_SECONDS = 8
SCHEMA = "heptabao.native-v6-physical-ha.v1"
MARKER = "native-ha-fixture.json"
QUARANTINE = "native-cipher-quarantine"
BASELINE_62_CHECK_COUNT = len(base.REQUIRED_CHECKS) + 3 + 1 + 4
REQUIRED_CHECKS = frozenset({
    "candidate_binary_digest", "same_source_native_abis",
    "three_distinct_physical_hosts", "complete_loopback_mesh",
    "seed_fresh_uninitialized", "seed_initialized_once", "seed_unsealed",
    "seed_v5_and_kv2_history", "seed_stopped_cold_archive",
    "three_raft_elected_before_unseal", "native_activate_once",
    "native_noop_config_accepted", "native_delete_missing_accepted",
    "native_v5_history_preserved", "native_history_34mib_capacity",
    "native_history_all_retained_exact", "native_history_soft_delete_once",
    "native_history_destroy_once", "native_history_retention_states",
    "native_standby_small_write_once", "native_standby_small_readindex",
    "leader_sigkill_identity_verified", "different_leader_after_sigkill",
    "new_leader_retained_history_exact", "failover_write_once",
    "failover_survivors_readindex", "old_leader_cold_restart",
    "old_leader_local_raft_caught_up", "old_leader_forwarded_readindex",
    "single_survivor_loses_authority", "quorum_loss_write_denied_no_ack",
    "quorum_loss_read_denied_no_payload", "quorum_restored",
    "denied_quorum_write_absent", "quorum_recovery_write_once",
    "all_voters_stopped_for_cold_restart", "all_voters_cold_unsealed",
    "all_voters_local_raft_persistent", "cold_leader_retained_history_exact",
    "cold_restart_new_write_once", "cold_restart_all_hosts_readindex",
    "missing_cipher_targets_stopped", "missing_cipher_two_targets_quarantined",
    "missing_cipher_sealed_pair_elected", "missing_cipher_source_rejoined",
    "missing_cipher_leader_empty_before_unseal", "missing_cipher_leader_unsealed",
    "missing_cipher_leader_exact_history", "missing_cipher_actual_leaves_rebuilt",
    "missing_cipher_remaining_nodes_unsealed", "missing_cipher_all_hosts_readindex",
    "synthetic_metadata_cleanup_once", "synthetic_metadata_absent",
    "source_and_binaries_unchanged", "report_excludes_runtime_secrets",
    "owned_processes_stopped", "owned_mesh_stopped", "native.complete",
    *(f"node_{node}_build_receipt" for node in (1, 2, 3)),
    *(f"node_{node}_new_private_root" for node in (1, 2, 3)),
    *(f"node_{node}_binary_digest" for node in (1, 2, 3)),
    *(f"node_{node}_initial_unseal" for node in (1, 2, 3)),
    *(f"node_{node}_cold_clone" for node in (2, 3)),
    *(f"native_history_write_{version:02d}" for version in range(1, HISTORY_WRITES + 1)),
})


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def data_digest(value: dict) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def write_private(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


@contextlib.contextmanager
def strict_shared_transport():
    """Reuse unchanged helpers, adding mandatory SSH host-key verification."""
    original = base.checked_run

    def checked(argv, **options):
        if argv and argv[0] in ("ssh", "scp"):
            argv = [argv[0], "-o", "StrictHostKeyChecking=yes", *argv[1:]]
        return original(argv, **options)

    base.checked_run = checked
    try:
        yield
    finally:
        base.checked_run = original


class StrictCompleteMesh(loopback.CompleteLoopbackMesh):
    """The existing exact six-link mesh, with strict keys on owned SSH children."""

    def start(self, nodes, work, event):
        if (len(nodes) != 3 or {node.node_id for node in nodes} != {1, 2, 3}
                or len({node.raft_port for node in nodes}) != 1):
            raise base.FixtureError("exact_three_node_mesh_required")
        plan = loopback.mesh_plan([node.alias for node in nodes], nodes[0].raft_port,
                                  self.local_base, self.reverse_base)
        for node in nodes:
            for port in (self.local_base + node.node_id, self.api_base + node.node_id):
                with socket.socket() as endpoint:
                    endpoint.bind(("127.0.0.1", port))
            ports = [self.reverse_base + peer for peer in (1, 2, 3) if peer != node.node_id]
            base.ssh(node, "python3 - <<'PY2'\nimport socket\n"
                     + f"for port in {ports!r}:\n"
                     + "    s=socket.socket(); s.bind(('127.0.0.1',port)); s.close()\nPY2\n",
                     timeout=15)
        for command in plan["commands"]:
            node = next(node for node in nodes if node.node_id == command["node_id"])
            command["args"][0:0] = ["-o", "StrictHostKeyChecking=yes"]
            command["args"][-1:-1] = [
                "-L", f"127.0.0.1:{self.api_base + node.node_id}:127.0.0.1:{node.api_port}",
            ]
            with (work / f"ssh-mesh-node-{node.node_id}.log").open("xb") as output:
                child = subprocess.Popen([command["executable"], *command["args"]],
                                         stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                         start_new_session=True, close_fds=True)
            self.processes.append((node.node_id, child))
            time.sleep(1)
            if child.poll() is not None:
                raise base.FixtureError(f"mesh_node_{node.node_id}_ssh_failed")
            event("owned_mesh_started", node=node.node_id, pid=child.pid)
        if any(child.poll() is not None for _, child in self.processes):
            raise base.FixtureError("mesh_lost_before_raft_start")
        write_private(work / "loopback-mesh-plan.json", canonical(plan) + b"\n")


def native_process_script() -> str:
    """Extend the reviewed PID/start-time contract only for the explicit flag.

    Exact substitutions fail if the shared ownership script changes. This does
    not admit baseline HA argv, a different executable, or another fixture PID.
    """
    source = base.REMOTE_PROCESS_SCRIPT
    changes = {
        "action, raw_root, has_ha = sys.argv[1:]":
            "action, raw_root, has_ha, run_id = sys.argv[1:]",
        "if has_ha == '1':\n    argv += ['--ha-config', str(root / 'ha.json')]":
            "if has_ha == '1':\n    argv += ['--ha-config', str(root / 'ha.json'), "
            "'--experimental-native-v6-ha']",
        "[exe, '--config', config, '--ha-config', str(root / 'ha.json')]":
            "[exe, '--config', config, '--ha-config', str(root / 'ha.json'), "
            "'--experimental-native-v6-ha']",
        "*([argv[-1]] if has_ha == '1' else [])":
            "*([str(root / 'ha.json')] if has_ha == '1' else [])",
    }
    expected_counts = (1, 1, 2, 1)
    for (old, new), expected in zip(changes.items(), expected_counts):
        if source.count(old) != expected:
            raise base.FixtureError("shared_process_identity_contract_changed")
        source = source.replace(old, new)
    anchor = "exe = str(root / 'heptabao-server')"
    if source.count(anchor) != 1:
        raise base.FixtureError("shared_process_root_contract_changed")
    marker = """
marker_path = root / 'native-ha-fixture.json'
entry = marker_path.lstat()
if not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid() or entry.st_mode & 0o077:
    raise SystemExit(84)
marker = json.loads(marker_path.read_text())
if (marker.get('run_id') != run_id or marker.get('root') != str(root)
        or marker.get('production_authority') is not False
        or marker.get('root_device') != info.st_dev or marker.get('root_inode') != info.st_ino):
    raise SystemExit(85)
"""
    return source.replace(anchor, marker + "\n" + anchor)


def process_action(node, run_id: str, action: str, *, native=True):
    if action not in ("start", "stop"):
        raise base.FixtureError("invalid_owned_process_action")
    script = native_process_script()
    output = base.ssh(node, f"python3 - {action} {shlex.quote(node.root)} "
                      f"{1 if native else 0} {shlex.quote(run_id)} <<'PY2'\n"
                      + script + "\nPY2\n")
    value = output.strip().splitlines()[-1] if output.strip() else ""
    if action == "stop" and value == "none":
        return None
    if not value.isdecimal() or int(value) <= 0:
        raise base.FixtureError("owned_process_receipt_unavailable")
    return int(value)


STOPPED_CHECK = r"""
if (root / 'process.pid').exists() or (root / 'process.identity.json').exists():
    raise SystemExit(91)
observed = subprocess.run(['ps', '-axo', 'args='], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=5).stdout.decode()
exe = str(root / 'heptabao-server')
config = str(root / 'server.json')
for line in observed.splitlines():
    if exe not in line or config not in line:
        continue
    try:
        args = shlex.split(line)
    except ValueError:
        raise SystemExit(92)
    if args and args[0] == exe and '--config' in args and config in args:
        raise SystemExit(93)
"""


def assert_stopped(node) -> None:
    base.ssh(node, "python3 - " + shlex.quote(node.root) + " <<'PY2'\n"
             + "from pathlib import Path\nimport shlex, subprocess, sys\nroot=Path(sys.argv[1])\n"
             + STOPPED_CHECK + "\nPY2\n", timeout=15)


def setup_root(node, run_id: str) -> dict:
    script = r"""
from pathlib import Path
import json, os, platform, socket, stat, sys
root, run_id, node_id, api_port, raft_port = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
parent = root.parent
entry = parent.stat()
if (parent.resolve(strict=True) != parent or root.exists() or root.is_symlink()
        or not parent.is_dir() or entry.st_uid != os.getuid() or entry.st_mode & 0o022):
    raise SystemExit(70)
for port in (api_port, raft_port):
    with socket.socket() as endpoint:
        endpoint.bind(('127.0.0.1', port))
root.mkdir(mode=0o700)
info = root.stat()
marker = {'schema':'heptabao.native-v6-fixture-owner.v1', 'run_id':run_id,
          'root':str(root), 'node_id':node_id, 'production_authority':False,
          'root_device':info.st_dev, 'root_inode':info.st_ino}
descriptor = os.open(root/'native-ha-fixture.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, 'w') as output:
    json.dump(marker, output, sort_keys=True); output.write('\n'); output.flush(); os.fsync(output.fileno())
for path in (parent, root):
    descriptor = os.open(path, os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
print(json.dumps({'host':socket.gethostname(), 'system':platform.system(),
                  'machine':platform.machine(), 'uid':os.getuid()}, sort_keys=True))
"""
    output = base.ssh(node, f"python3 - {shlex.quote(node.root)} {shlex.quote(run_id)} "
                     f"{node.node_id} {node.api_port} {node.raft_port} <<'PY2'\n"
                     + script + "\nPY2\n")
    result = json.loads(output)
    if (not isinstance(result, dict) or result.get("system") not in ("Linux", "Darwin")
            or not isinstance(result.get("host"), str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", result["host"]) is None):
        raise base.FixtureError("physical_host_identity_invalid")
    return result


def abi_matches(receipt_abi: str, actual: dict) -> bool:
    return receipt_abi in {
        ("Darwin", "arm64"): {"aarch64-apple-darwin"},
        ("Darwin", "x86_64"): {"x86_64-apple-darwin"},
        ("Linux", "x86_64"): {"x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"},
        ("Linux", "aarch64"): {"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl"},
    }.get((actual.get("system"), actual.get("machine")), set())


def validate_seed_archive(path: Path) -> None:
    total, seen = 0, set()
    with tarfile.open(path, "r:gz") as archive:
        for entry in archive:
            name = Path(entry.name)
            if (name.is_absolute() or not name.parts or name.parts[0] != "data"
                    or any(part in ("", ".", "..") for part in name.parts)
                    or entry.name in seen or not (entry.isdir() or entry.isfile())):
                raise base.FixtureError("cold_seed_archive_unsafe_entry")
            total += entry.size
            seen.add(entry.name)
            if total > 128 * MIB or len(seen) > 16_384:
                raise base.FixtureError("cold_seed_archive_bound_exceeded")
    if not seen or total == 0:
        raise base.FixtureError("cold_seed_archive_empty")


def install_seed(node, archive: Path) -> None:
    base.upload(node, archive, node.root + "/seed-data.tgz", 0o600)
    base.ssh(node, "python3 - " + shlex.quote(node.root) + " <<'PY2'\n" + r"""
from pathlib import Path
import os, stat, sys, tarfile
root=Path(sys.argv[1]); archive_path=root/'seed-data.tgz'
if root.resolve(strict=True)!=root or (root/'data').exists() or (root/'data').is_symlink():
    raise SystemExit(70)
with tarfile.open(archive_path, 'r:gz') as archive:
    entries=archive.getmembers(); names=set(); total=0
    for entry in entries:
        name=Path(entry.name)
        if (name.is_absolute() or not name.parts or name.parts[0]!='data'
                or any(part in ('','.','..') for part in name.parts)
                or entry.name in names or not (entry.isfile() or entry.isdir())):
            raise SystemExit(71)
        total+=entry.size; names.add(entry.name)
        if total>128*1024*1024 or len(names)>16384: raise SystemExit(72)
    archive.extractall(root)
    for entry in entries:
        path=root/entry.name
        if path.is_symlink() or path.resolve(strict=True)!=path: raise SystemExit(73)
        path.chmod(0o700 if entry.isdir() else 0o600)
archive_path.unlink()
descriptor=os.open(root, os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
try: os.fsync(descriptor)
finally: os.close(descriptor)
""" + "\nPY2\n")


CIPHER_INVENTORY_SCRIPT = r"""
from pathlib import Path
import hashlib, json, os, re, shlex, stat, subprocess, sys
action, raw_root, run_id = sys.argv[1:]
root = Path(raw_root)
if root.resolve(strict=True) != root or root.is_symlink(): raise SystemExit(70)
info = root.stat()
if info.st_uid != os.getuid() or info.st_mode & 0o077: raise SystemExit(71)
marker_path=root/'native-ha-fixture.json'
mi=marker_path.lstat()
if not stat.S_ISREG(mi.st_mode) or mi.st_uid!=os.getuid() or mi.st_mode&0o077:
    raise SystemExit(72)
marker=json.loads(marker_path.read_text())
if (marker.get('run_id')!=run_id or marker.get('root')!=str(root)
        or marker.get('production_authority') is not False
        or marker.get('root_device')!=info.st_dev or marker.get('root_inode')!=info.st_ino):
    raise SystemExit(73)
store=root/'raft'/'native-v6-ciphertext'
quarantine=root/'native-cipher-quarantine'
for directory in (root/'raft', store):
    di=directory.lstat()
    if (directory.resolve(strict=True)!=directory or not stat.S_ISDIR(di.st_mode)
            or di.st_uid!=os.getuid() or di.st_mode&0o077): raise SystemExit(74)
store_fd=os.open(store, os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_DIRECTORY',0))
pattern=re.compile(r'v6-[0-9a-f]{64}\.blob\Z')
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def read_entry(directory, name):
    descriptor=os.open(name, os.O_RDONLY|os.O_NOFOLLOW, dir_fd=directory)
    try:
        before=os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid()
                or before.st_mode&0o077 or before.st_nlink!=1
                or not 0<before.st_size<=1024*1024): raise SystemExit(75)
        digest=hashlib.sha256()
        size=0
        while True:
            raw=os.read(descriptor,64*1024)
            if not raw: break
            digest.update(raw); size+=len(raw)
        after=os.fstat(descriptor)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) or size!=before.st_size:
            raise SystemExit(76)
        return {'sha256':digest.hexdigest(),'bytes':size}, before
    finally: os.close(descriptor)
def leaves(directory):
    names=sorted(name for name in os.listdir(directory) if pattern.fullmatch(name))
    if len(names)>131072: raise SystemExit(77)
    return names
names=leaves(store_fd)
if action=='quarantine':
    __STOPPED_CHECK__
    if quarantine.exists() or quarantine.is_symlink() or not names: raise SystemExit(78)
    quarantine.mkdir(mode=0o700)
    quarantine_fd=os.open(quarantine,os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_DIRECTORY',0))
    index={}; identities={}
    try:
        for name in names:
            metadata, original=read_entry(store_fd,name)
            current=os.stat(name,dir_fd=store_fd,follow_symlinks=False)
            if (current.st_dev,current.st_ino,current.st_size)!=(original.st_dev,original.st_ino,original.st_size):
                raise SystemExit(79)
            # A no-replace hard link reserves the destination atomically. Do
            # not unlink any source until every destination plus its directory
            # and parent are fsynced, so an interrupted injection keeps bytes.
            os.link(name,name,src_dir_fd=store_fd,dst_dir_fd=quarantine_fd,follow_symlinks=False)
            actual=os.stat(name,dir_fd=quarantine_fd,follow_symlinks=False)
            if (actual.st_dev,actual.st_ino)!=(original.st_dev,original.st_ino): raise SystemExit(80)
            index[name]=metadata
            identities[name]=(original.st_dev,original.st_ino,original.st_size)
        raw=canonical({'schema':'heptabao.native-cipher-quarantine.v1', 'run_id':run_id,
                       'root_device':info.st_dev,'root_inode':info.st_ino,'leaves':index})
        descriptor=os.open('inventory.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                           0o600,dir_fd=quarantine_fd)
        with os.fdopen(descriptor,'wb') as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
        os.fsync(quarantine_fd)
        root_fd=os.open(root,os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_DIRECTORY',0))
        try: os.fsync(root_fd)
        finally: os.close(root_fd)
        for name in names:
            actual=os.stat(name,dir_fd=store_fd,follow_symlinks=False)
            if ((actual.st_dev,actual.st_ino,actual.st_size)!=identities[name]
                    or actual.st_nlink!=2): raise SystemExit(89)
            os.unlink(name,dir_fd=store_fd)
        os.fsync(store_fd); os.fsync(quarantine_fd)
        if leaves(store_fd): raise SystemExit(81)
        print(json.dumps({'quarantined_count':len(index),
            'quarantined_bytes':sum(entry['bytes'] for entry in index.values()),
            'inventory_sha256':hashlib.sha256(raw).hexdigest(),'remaining_count':0},sort_keys=True))
    finally: os.close(quarantine_fd)
elif action in ('empty','recovered'):
    qi=quarantine.lstat()
    if (quarantine.resolve(strict=True)!=quarantine or not stat.S_ISDIR(qi.st_mode)
            or qi.st_uid!=os.getuid() or qi.st_mode&0o077): raise SystemExit(82)
    path=quarantine/'inventory.json'
    ii=path.lstat()
    if not stat.S_ISREG(ii.st_mode) or ii.st_uid!=os.getuid() or ii.st_mode&0o077 or ii.st_size>24*1024*1024:
        raise SystemExit(83)
    raw=path.read_bytes(); index=json.loads(raw)
    if (index.get('run_id')!=run_id or index.get('root_device')!=info.st_dev
            or index.get('root_inode')!=info.st_ino or canonical(index)!=raw): raise SystemExit(84)
    original=index['leaves']
    if action=='empty':
        if names: raise SystemExit(85)
        result={'remaining_count':0,'inventory_sha256':hashlib.sha256(raw).hexdigest()}
    else:
        if not names: raise SystemExit(86)
        total=0
        for name in names:
            metadata,_=read_entry(store_fd,name)
            if original.get(name)!=metadata: raise SystemExit(87)
            total+=metadata['bytes']
        result={'restored_count':len(names),'restored_bytes':total,
                'quarantined_count':len(original),
                'unreferenced_quarantined_count':len(original)-len(names),
                'every_restored_sha_and_size_match':True,
                'inventory_sha256':hashlib.sha256(raw).hexdigest()}
    print(json.dumps(result,sort_keys=True))
else: raise SystemExit(88)
os.close(store_fd)
"""


def cipher_inventory(node, run_id: str, action: str) -> dict:
    if action not in ("quarantine", "empty", "recovered"):
        raise base.FixtureError("invalid_cipher_fixture_action")
    script = CIPHER_INVENTORY_SCRIPT.replace("    __STOPPED_CHECK__",
                                           "\n".join("    " + line for line in STOPPED_CHECK.splitlines()))
    output = base.ssh(node, f"python3 - {action} {shlex.quote(node.root)} "
                     f"{shlex.quote(run_id)} <<'PY2'\n" + script + "\nPY2\n", timeout=60)
    result = json.loads(output)
    if not isinstance(result, dict):
        raise base.FixtureError("cipher_fixture_receipt_invalid")
    return result


class NativeRun:
    required_checks = REQUIRED_CHECKS

    def __init__(self, args, nodes, mesh, sources, receipts, expected):
        self.args, self.nodes, self.mesh = args, nodes, mesh
        self.sources, self.receipts, self.expected = sources, receipts, expected
        self.work = args.work_root
        self.run_id = secrets.token_hex(16)
        self.created, self.started = set(), set()
        self.context = None
        self.root_token = self.unseal_key = ""
        self.confidential = []
        self.checks, self.events = [], []
        self.acknowledged, self.history = {}, {}
        self.retired = {1: "deleted", 2: "destroyed"}
        self.path = "native-ha-" + self.run_id + "/history"
        self.stage = "preflight"
        self.phase_number = 0
        self.phases = self.work / "phases"
        self.phases.mkdir(mode=0o700)
        paths = (Path(__file__), Path(base.__file__), Path(loopback.__file__),
                 Path(loopback.mesh_plan.__code__.co_filename), Path(recovery.__file__),
                 Path(base.provision_secret_kv2.__code__.co_filename))
        self.source_files = {str(path.resolve()): base.sha256_file(path) for path in paths}
        self.local_binaries = {}
        self.recovery = recovery.FixtureRecoveryLedger(
            self.work, self.run_id, args.source_commit, args.source_tree,
            nodes, expected, error_type=base.FixtureError)
        self.report = {
            "schema": SCHEMA, "status": "failed", "source_commit": args.source_commit,
            "source_tree": args.source_tree, "runner_sha256": base.sha256_file(Path(__file__)),
            "fixture_run_id": self.run_id,
            "node_roots": {str(node.node_id): {"alias": node.alias, "root": node.root}
                           for node in nodes},
            "helper_sha256": self.source_files, "expected_node_binary_sha256": expected,
            "required_check_count": len(self.required_checks), "checks": self.checks,
            "events": self.events, "host_count": 3,
            "scope": "synthetic-native-v6-physical-hosts-pinned-tls-original-budgets",
            "transport": "coordinator-mediated-ssh-with-end-to-end-mtls",
            "separate_baseline_check_count": BASELINE_62_CHECK_COUNT,
            "baseline_checks_executed": False, "native_ha_backup_verified": False,
            "http_request_budget_seconds": REQUEST_SECONDS,
            "native_admission_budget_seconds": NATIVE_ADMISSION_SECONDS,
            "large_http_forwarding_verified": False,
            "history_payload_target_bytes": TARGET_BYTES,
            "mutating_requests_retried": False,
            "fixture_recovery": self.recovery.public_receipt,
            "qualification": False, "independent_qualification": False,
            "production_authority": False, "direct_lan_qualification": False,
            "full_openbao_compatibility": False,
            "process_identity_scope": "Linux pidfd/start ticks; Darwin exact BSD ps/start time, non-atomic PID scope",
            "uncovered": ["native_ha_snapshot_export_restore", "large_http_forwarding",
                          "physical_power_loss", "disk_full", "long_horizon_linearizability",
                          "production_traffic_switch", "old_production_asset_cleanup"],
        }

    def secrets(self):
        return (self.root_token, self.unseal_key, *self.confidential)

    def checkpoint(self):
        self.phase_number += 1
        safe = base.secret_safe_report(self.report, self.secrets())
        write_private(self.phases / f"{self.phase_number:05d}.json", canonical(safe) + b"\n")

    def check(self, name, condition, **details):
        if name not in self.required_checks or any(row["case"] == name for row in self.checks):
            raise base.FixtureError("native_check_denominator_or_duplicate")
        self.checks.append({"case": name, "passed": condition is True, **details})
        self.checkpoint()
        if condition is not True:
            raise base.FixtureError(name)

    def event(self, name, **details):
        self.events.append({"event": name, "at": time.time(), **details})
        self.checkpoint()

    def request(self, node, method, path, body=None, *, authenticate=True, timeout=REQUEST_SECONDS):
        if not 0 < timeout <= REQUEST_SECONDS:
            raise base.FixtureError("original_http_budget_must_not_increase")
        mutation = method not in ("GET", "HEAD", "LIST")
        intent = self.recovery.begin(node, method, path, body, stage=self.stage,
                                     timeout=timeout) if mutation else None
        started = time.monotonic()
        try:
            status, response = base.api(self.context, node, method, path, body,
                                        self.root_token if authenticate else "", timeout=timeout)
        except BaseException as error:
            if mutation:
                self.recovery.outcome(intent, elapsed=time.monotonic() - started,
                                      timeout=timeout, error=error)
            raise
        elapsed = time.monotonic() - started
        if mutation:
            if method == "POST" and path == "sys/init" and status == 200:
                # Capture before any public checkpoint, so a custody failure
                # cannot make an initialization response evade secret redaction.
                value = response.get("root_token") if isinstance(response, dict) else None
                keys = response.get("keys_base64") if isinstance(response, dict) else None
                if isinstance(value, str):
                    self.root_token = value
                if isinstance(keys, list) and len(keys) == 1 and isinstance(keys[0], str):
                    self.unseal_key = keys[0]
                self.recovery.preserve_initialization(node, response)
            self.recovery.outcome(intent, status=status, response=response,
                                  elapsed=elapsed, timeout=timeout)
        if elapsed > timeout:
            raise base.FixtureError("response_arrived_after_original_http_budget")
        if mutation:
            self.event("mutation_attempted_once", node=node.node_id, method=method,
                       path_kind=path.split("/")[0:2], status=status,
                       elapsed_ms=round(elapsed * 1000, 3))
        return status, response

    def owned_process_action(self, node, action, *, native=True):
        return process_action(node, self.run_id, action, native=native)

    def start(self, node, *, native=True):
        # An uncertain SSH return is not authority to repeat this startup.
        # Cleanup will inspect only this newly owned root's identity files.
        self.started.add(node)
        pid = self.owned_process_action(node, "start", native=native)
        self.event("owned_server_started", node=node.node_id, pid=pid, native=native)
        return pid

    def stop(self, node):
        pid = self.owned_process_action(node, "stop")
        assert_stopped(node)
        self.started.discard(node)
        self.event("owned_server_stopped", node=node.node_id, pid=pid)
        return pid

    def unseal(self, node):
        base.wait_listener(self.context, node)
        status, body = self.request(node, "POST", "sys/unseal", {"key": self.unseal_key},
                                    authenticate=False)
        if status != 200 or body.get("sealed") is not False:
            raise base.FixtureError(f"node_{node.node_id}_native_cold_unseal_failed")

    def wait_sealed_leader(self, nodes, *, expected=None):
        """Sealed local-role observation only; it grants no application read."""
        deadline, candidate, since = time.monotonic() + 60, None, 0.0
        while time.monotonic() < deadline:
            active = []
            for node in nodes:
                try:
                    _, body = self.request(node, "GET", "sys/health", authenticate=False, timeout=2)
                except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
                    continue
                if body.get("sealed") is not True:
                    raise base.FixtureError("sealed_election_observed_unsealed_service")
                if body.get("ha_active") is True and body.get("standby") is False:
                    active.append(node)
            if len(active) > 1:
                raise base.FixtureError("sealed_pair_reported_multiple_leaders")
            observed = active[0] if active else None
            now = time.monotonic()
            if now >= deadline:
                break
            if observed is not None and (expected is None or observed == expected):
                if observed == candidate and now - since >= 2.2:
                    return observed
                if observed != candidate:
                    candidate, since = observed, now
            else:
                candidate, since = None, 0.0
            time.sleep(0.1)
        raise base.FixtureError("sealed_native_leader_timeout")

    def leader(self, nodes, *, previous=None):
        return base.wait_leader(self.context, list(nodes), self.root_token,
                                previous=previous, seconds=60)

    def write_small(self, node, label):
        path = "native-ha-" + self.run_id + "/" + label
        if path in self.acknowledged:
            raise base.FixtureError("synthetic_mutation_would_be_retried")
        value = {"value": secrets.token_hex(24)}
        status, body = self.request(node, "POST", "secret/data/" + path,
                                    {"options": {"cas": 0}, "data": value})
        if status != 200 or body.get("data", {}).get("version") != 1:
            raise base.FixtureError("native_small_write_not_acknowledged_once_"
                                    + base.response_failure_code(status, body))
        self.acknowledged[path] = data_digest(value)
        return path

    def read_data(self, node, path, *, version=None):
        # The real HTTP GET parser selects KV2 fields from the URL only.
        route = "secret/data/" + path
        if version is not None:
            if type(version) is not int or version < 1:
                raise base.FixtureError("exact_history_version_must_be_positive_integer")
            route += "?" + urllib.parse.urlencode({"version": version})
        return self.request(node, "GET", route)

    def exact_read(self, node, path, expected, *, version=None):
        status, body = self.read_data(node, path, version=version)
        data = body.get("data", {})
        if (status != 200 or not isinstance(data, dict) or not isinstance(data.get("data"), dict)
                or data_digest(data["data"]) != expected
                or data.get("metadata", {}).get("version") != (1 if version is None else version)):
            # A successful stale result is a failure, never converted to polling.
            raise base.FixtureError(f"native_exact_read_failed_node_{node.node_id}")

    def small_reads(self, nodes):
        for node in nodes:
            for path, expected in self.acknowledged.items():
                self.exact_read(node, path, expected)

    def history_reads(self, leader, *, retired=True):
        for version, expected in sorted(self.history.items()):
            if retired and version in self.retired:
                status, body = self.read_data(leader, self.path, version=version)
                data = body.get("data")
                metadata = data.get("metadata") if isinstance(data, dict) else None
                if (status != 404 or not isinstance(data, dict) or data.get("data") is not None
                        or not isinstance(metadata, dict) or metadata.get("version") != version
                        or metadata.get("destroyed") is not (self.retired[version] == "destroyed")
                        or (self.retired[version] == "deleted"
                            and not metadata.get("deletion_time"))):
                    raise base.FixtureError("retired_native_version_disclosed_payload")
            else:
                self.exact_read(leader, self.path, expected, version=version)

    def metadata(self, leader):
        status, body = self.request(leader, "GET", "secret/metadata/" + self.path)
        data = body.get("data", {})
        versions = data.get("versions", {})
        if (status != 200 or data.get("current_version") != len(self.history)
                or set(versions) != {str(version) for version in self.history}):
            raise base.FixtureError("native_retained_version_inventory_differs")
        return versions

    def absent(self, node, path):
        status, body = self.request(node, "GET", "secret/data/" + path)
        if status != 404 or body.get("data") not in (None, {}):
            raise base.FixtureError("denied_or_cleaned_native_write_has_effect")

    def prepare(self):
        self.stage = "source_and_native_build_receipts"
        self.abis = {}
        for node in self.nodes:
            alias, path, digest = self.receipts[node.alias]
            destination = self.work / f"native-build-{node.node_id}.json"
            base.copy_candidate_source(alias, path, destination, executable=False)
            destination.chmod(0o600)
            if destination.stat().st_size > 64 * 1024 or base.sha256_file(destination) != digest:
                raise base.FixtureError("native_build_receipt_digest_mismatch")
            self.abis[node.alias] = base.validate_build_receipt(
                json.loads(destination.read_text()), self.args.source_commit,
                self.args.source_tree, self.expected[str(node.node_id)])
            self.check(f"node_{node.node_id}_build_receipt", True,
                       receipt_sha256=digest, native_abi=self.abis[node.alias])

        source_alias, source_path = base.parse_binary_source(self.args.binary_source)
        default = (source_alias, source_path, self.args.expected_binary_sha256)
        payloads, artifacts = {}, {}
        for node in self.nodes:
            source = self.sources.get(node.alias, default)
            if source not in artifacts:
                alias, path, expected = source
                local = self.work / f"candidate-{node.node_id}"
                base.copy_candidate_source(alias, path, local)
                local.chmod(0o500)
                if base.sha256_file(local) != expected:
                    raise base.FixtureError("native_candidate_binary_digest_mismatch")
                compressed = self.work / f"candidate-{node.node_id}.gz"
                base.compress_candidate(local, compressed)
                artifacts[source] = (local, compressed)
            local, payload = artifacts[source]
            self.local_binaries[node.alias] = local
            payloads[node.alias] = payload
        self.check("candidate_binary_digest", True,
                   distinct_artifact_count=len(artifacts), source_and_tree_exact=True)

        self.stage = "new_physical_roots_and_tls"
        ca_key, ca_cert = self.work / "ca.key", self.work / "ca.crt"
        base.create_fixture_ca(ca_key, ca_cert)
        self.confidential.append(ca_key.read_text())
        self.context = ssl.create_default_context(cafile=str(ca_cert))
        self.hosts, self.node_files, self.peers = {}, {}, {}
        for node in self.nodes:
            actual = setup_root(node, self.run_id)
            self.created.add(node)
            self.hosts[node.alias] = actual
            self.check(f"node_{node.node_id}_new_private_root", True,
                       system=actual["system"], machine=actual["machine"])
            directory = self.work / node.name
            directory.mkdir(mode=0o700)
            self.node_files[node] = directory
            key, cert = base.create_fixture_node_certificate(node, directory, ca_key, ca_cert)
            self.confidential.append(key.read_text())
            leaf = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            self.peers[str(node.node_id)] = {
                "node_name": node.name, "address": f"{node.ip}:{node.raft_port}",
                "api_address": node.api_origin, "server_name": node.server_name,
                "certificate_sha256": leaf,
            }
            server = self.mesh.configure_server(node, {
                "listen": f"{node.ip}:{node.api_port}", "data_dir": node.root + "/data",
                "audit_file": node.root + "/audit.jsonl", "tls_cert_file": node.root + "/tls.crt",
                "tls_key_file": node.root + "/tls.key", "max_connections": 64,
                "timeout_seconds": REQUEST_SECONDS, "rate_limit_per_second": 2000,
                "rate_limit_burst": 4000, "rate_limit_entries": 512,
                "lifecycle_interval_seconds": 1,
            })
            config = directory / "server.json"
            write_private(config, canonical(server) + b"\n")
            base.install_candidate(node, payloads[node.alias], self.expected[str(node.node_id)])
            for path, name in ((ca_cert, "ca.crt"), (cert, "tls.crt"),
                               (key, "tls.key"), (config, "server.json")):
                base.upload(node, path, node.root + "/" + name, 0o600)
            remote = base.remote_binary_digest(node)
            self.check(f"node_{node.node_id}_binary_digest",
                       remote == self.expected[str(node.node_id)], sha256=remote)
        self.check("three_distinct_physical_hosts",
                   len({actual["host"] for actual in self.hosts.values()}) == 3
                   and {actual["system"] for actual in self.hosts.values()} == {"Linux", "Darwin"},
                   hostnames={alias: actual["host"] for alias, actual in self.hosts.items()})
        self.check("same_source_native_abis", all(
            abi_matches(self.abis[alias], actual) for alias, actual in self.hosts.items()),
            actual_native_abis=self.abis)
        self.mesh.start(self.nodes, self.work, self.event)
        self.transport_ready()

    def transport_ready(self):
        self.check("complete_loopback_mesh", True, physical_hosts=3, directed_peer_links=6)

    def provision_fixture_kv2(self, node):
        # Route the unchanged mount contract through this run's recorded
        # request boundary; the shared helper otherwise bypasses NativeRun.
        def submit(method, path, body=None, **options):
            return self.request(node, method, path, body, **options)
        base.provision_secret_kv2(submit, error_type=base.FixtureError, timeout=12)
        status, body = self.request(node, "GET", "sys/mounts", timeout=12)
        mounts = body.get("data") if isinstance(body, dict) else None
        mount = mounts.get("secret/") if isinstance(mounts, dict) else None
        options = mount.get("options") if isinstance(mount, dict) else None
        if (type(status) is not int or status != 200 or not isinstance(mount, dict)
                or mount.get("type") != "kv" or not isinstance(options, dict)
                or options.get("version") != "2"):
            raise base.FixtureError("fixture_exact_kv2_inventory_failed")
        metadata = base.completed_kv2_mount_metadata()
        metadata["inventory_confirmed"] = True
        return metadata

    def bootstrap_v5(self):
        self.stage = "fresh_standalone_v5_seed"
        seed = self.nodes[0]
        self.start(seed, native=False)
        status, _ = base.wait_listener(self.context, seed)
        self.check("seed_fresh_uninitialized", status == 501)
        status, body = self.request(seed, "POST", "sys/init",
                                    {"secret_shares": 1, "secret_threshold": 1}, authenticate=False)
        value, keys = body.get("root_token"), body.get("keys_base64")
        if isinstance(value, str):
            self.root_token = value
        if isinstance(keys, list) and len(keys) == 1 and isinstance(keys[0], str):
            self.unseal_key = keys[0]
        self.check("seed_initialized_once", status == 200 and bool(self.root_token)
                   and bool(self.unseal_key))
        self.unseal(seed)
        self.check("seed_unsealed", True)
        # The original mount helper sends each mount mutation once.
        self.report["fixture_mount_setup"] = self.provision_fixture_kv2(seed)
        status, _ = self.request(seed, "POST", "secret/config",
                                 {"max_versions": 32, "cas_required": True})
        if status != 204:
            raise base.FixtureError("seed_retained_history_configuration_failed")
        for version in (1, 2):
            value = {"version": version, "value": "synthetic-v5-history-" + secrets.token_hex(16)}
            status, body = self.request(seed, "POST", "secret/data/" + self.path,
                                        {"options": {"cas": version - 1}, "data": value})
            if status != 200 or body.get("data", {}).get("version") != version:
                raise base.FixtureError("seed_v5_version_not_acknowledged_once")
            self.history[version] = data_digest(value)
        self.history_reads(seed, retired=False)
        status, body = self.request(seed, "GET", "sys/internal/capacity")
        status_health, health = self.request(seed, "GET", "sys/health", authenticate=False)
        self.cluster_id = health.get("cluster_id")
        self.check("seed_v5_and_kv2_history", status == 200
                   and body.get("data", {}).get("state_storage_format") == "heptabao-state-records-v5"
                   and status_health == 200 and isinstance(self.cluster_id, str)
                   and bool(self.cluster_id), retained_versions=2)
        self.stop(seed)
        archive = self.work / "seed-data.tgz"
        with archive.open("xb") as output:
            base.checked_run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                              seed.alias, "tar", "-C", seed.root, "-czf", "-", "data"],
                             timeout=120, stdout=output)
            output.flush()
            os.fsync(output.fileno())
        validate_seed_archive(archive)
        self.check("seed_stopped_cold_archive", archive.stat().st_size > 0,
                   archive_sha256=base.sha256_file(archive))
        for node in self.nodes[1:]:
            install_seed(node, archive)
            self.check(f"node_{node.node_id}_cold_clone", True)

        self.stage = "native_ha_initial_start"
        replication = self.work / "replication.key"
        raw = secrets.token_bytes(32)
        self.confidential.append(raw.hex())
        write_private(replication, raw)
        for node in self.nodes:
            config = self.mesh.configure(node, {
                "node_id": node.node_id, "cluster_id": self.cluster_id,
                "raft_dir": node.root + "/raft", "listen": f"{node.ip}:{node.raft_port}",
                "ca_file": node.root + "/ca.crt", "cert_file": node.root + "/tls.crt",
                "key_file": node.root + "/tls.key",
                "replication_key_file": node.root + "/replication.key",
                "peers": self.peers, "bootstrap": node.node_id == 1,
                "peer_timeout_ms": 1500, "forward_timeout_ms": 8000, "max_inflight": 32,
            })
            path = self.node_files[node] / "ha.json"
            write_private(path, canonical(config) + b"\n")
            base.upload(node, replication, node.root + "/replication.key", 0o600)
            base.upload(node, path, node.root + "/ha.json", 0o600)
        for node in self.nodes[1:] + self.nodes[:1]:
            self.start(node)
        for node in self.nodes:
            base.wait_listener(self.context, node)
        self.wait_sealed_leader(self.nodes)
        self.check("three_raft_elected_before_unseal", True)
        for node in self.nodes:
            self.unseal(node)
            self.check(f"node_{node.node_id}_initial_unseal", True)
        return self.leader(self.nodes)

    def capacity(self, node):
        status, body = self.request(node, "GET", "sys/internal/capacity")
        data = body.get("data", {})
        if (status != 200 or not isinstance(data, dict)
                or data.get("state_storage_format") != "heptabao-state-records-v6"
                or data.get("native_kv2_reader_format") != 2
                or type(data.get("generation")) is not int):
            raise base.FixtureError("actual_native_paged_capacity_unavailable")
        return data

    def activate_and_grow(self, leader):
        self.stage = "actual_native_ha_activation"
        status, body = self.request(leader, "POST", "sys/internal/native-v6/activate", {})
        self.check("native_activate_once", status == 204 and body in (None, {}))
        self.capacity(leader)
        for node in self.nodes:
            self.history_reads(node, retired=False)
        self.check("native_v5_history_preserved", True, retained_v5_versions=2)
        # A stable committed frontier plus the actual local durable generation
        # must remain unchanged. This observes no new Raft command; it does not
        # invent a public root hash or loosen the intent's unequal-root rule.
        for name, method, path, payload in (
            ("native_noop_config_accepted", "POST", "secret/config",
             {"max_versions": 32, "cas_required": True}),
            ("native_delete_missing_accepted", "DELETE",
             "secret/metadata/native-ha-" + self.run_id + "/never-created", None),
        ):
            before = self.capacity(leader)["generation"]
            frontier = base.capture_committed_frontier(self.context, leader)
            status, _ = self.request(leader, method, path, payload)
            after = self.capacity(leader)["generation"]
            observed = base.capture_committed_frontier(self.context, leader)
            self.check(name, status == 204 and after == before and observed == frontier,
                       http_status=status, durable_generation_before=before,
                       durable_generation_after=after, committed_index_before=frontier,
                       committed_index_after=observed)

        self.stage = "seventeen_actual_native_history_writes"
        for ordinal in range(1, HISTORY_WRITES + 1):
            payload = secrets.token_urlsafe(PAYLOAD_BYTES * 3 // 4)
            if len(payload) != PAYLOAD_BYTES:
                raise base.FixtureError("native_payload_generator_bound_changed")
            value = {"ordinal": ordinal, "payload": payload}
            version = len(self.history) + 1
            digest = data_digest(value)
            began = time.monotonic()
            status, body = self.request(leader, "POST", "secret/data/" + self.path,
                                        {"options": {"cas": version - 1}, "data": value})
            elapsed = time.monotonic() - began
            self.check(f"native_history_write_{ordinal:02d}", status == 200
                       and body.get("data", {}).get("version") == version,
                       http_status=status, version=version, payload_bytes=PAYLOAD_BYTES,
                       payload_sha256=digest, elapsed_ms=round(elapsed * 1000, 3))
            self.history[version] = digest
            self.exact_read(leader, self.path, digest, version=version)
        capacity = self.capacity(leader)
        logical = capacity.get("native_kv2_logical_payload_bytes")
        self.check("native_history_34mib_capacity", type(logical) is int and logical >= TARGET_BYTES,
                   logical_payload_bytes=logical, minimum_expected_bytes=TARGET_BYTES)
        self.metadata(leader)
        self.history_reads(leader, retired=False)
        self.check("native_history_all_retained_exact", len(self.history) == HISTORY_WRITES + 2,
                   retained_versions=len(self.history), large_history_versions=HISTORY_WRITES)
        status, _ = self.request(leader, "POST", "secret/delete/" + self.path, {"versions": [1]})
        self.check("native_history_soft_delete_once", status == 204)
        status, _ = self.request(leader, "POST", "secret/destroy/" + self.path, {"versions": [2]})
        self.check("native_history_destroy_once", status == 204)
        versions = self.metadata(leader)
        self.history_reads(leader)
        self.check("native_history_retention_states",
                   bool(versions["1"].get("deletion_time"))
                   and versions["1"].get("destroyed") is False
                   and versions["2"].get("destroyed") is True,
                   unchanged_large_payload_bytes=TARGET_BYTES)
        standby = next(node for node in self.nodes if node != leader)
        self.write_small(standby, "standby-forwarded")
        self.check("native_standby_small_write_once", True, standby_node=standby.node_id)
        self.small_reads(self.nodes)
        self.check("native_standby_small_readindex", True, observed_hosts=3,
                   forwarding_payload_bytes_below=1024 * 1024)

    def failover_and_quorum(self, original):
        self.stage = "actual_native_leader_sigkill"
        killed = self.stop(original)
        self.check("leader_sigkill_identity_verified", killed is not None,
                   node=original.node_id, pid=killed)
        survivors = [node for node in self.nodes if node != original]
        # Three production election maxima, without a stream of expensive
        # health/ReadIndex requests starving the real two-voter election.
        time.sleep(6)
        successor = self.leader(survivors, previous=original)
        self.check("different_leader_after_sigkill", successor != original,
                   before=original.node_id, after=successor.node_id)
        self.history_reads(successor)
        self.check("new_leader_retained_history_exact", True, leader=successor.node_id)
        self.write_small(successor, "after-failover")
        self.check("failover_write_once", True)
        self.small_reads(survivors)
        self.check("failover_survivors_readindex", True, observed_hosts=2)
        frontier = base.capture_committed_frontier(self.context, successor)
        self.start(original)
        self.unseal(original)
        self.check("old_leader_cold_restart", True, node=original.node_id)
        observed = base.wait_local_frontier(self.context, original, frontier,
                                            seconds=60, record=self.event)
        self.check("old_leader_local_raft_caught_up", observed[1] >= frontier,
                   required_index=frontier, actual_applied_index=observed[1])
        self.small_reads([original])
        self.check("old_leader_forwarded_readindex", True, node=original.node_id)

        self.stage = "actual_native_quorum_loss"
        survivor = self.leader(self.nodes)
        peers = [node for node in self.nodes if node != survivor]
        for node in peers:
            self.stop(node)
        deadline, closed = time.monotonic() + 35, False
        while time.monotonic() < deadline:
            try:
                status, body = self.request(survivor, "GET", "sys/health",
                                            authenticate=False, timeout=3)
                closed = status == 503 and body.get("ha_active") is False
            except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
                closed = False
            if closed:
                break
            time.sleep(0.1)
        self.check("single_survivor_loses_authority",
                   closed and time.monotonic() < deadline, node=survivor.node_id)
        denied_path = "native-ha-" + self.run_id + "/quorum-denied"
        status, body = self.request(survivor, "POST", "secret/data/" + denied_path,
                                    {"options": {"cas": 0}, "data": {"value": "must-not-commit"}})
        self.check("quorum_loss_write_denied_no_ack", status == 503
                   and body.get("data") in (None, {}) and body.get("auth") is None,
                   http_status=status)
        status, body = self.read_data(survivor, self.path, version=len(self.history))
        self.check("quorum_loss_read_denied_no_payload", status == 503
                   and body.get("data") in (None, {}) and body.get("auth") is None,
                   http_status=status)
        for node in peers:
            self.start(node)
        for node in peers:
            self.unseal(node)
        leader = self.leader(self.nodes)
        self.check("quorum_restored", True, leader=leader.node_id)
        for node in self.nodes:
            self.absent(node, denied_path)
        self.check("denied_quorum_write_absent", True, observed_hosts=3)
        self.write_small(leader, "after-quorum-recovery")
        self.check("quorum_recovery_write_once", True)
        self.small_reads(self.nodes)
        return leader, denied_path

    def full_cold_restart(self, leader, denied_path):
        self.stage = "all_three_persistent_cold_restart"
        frontier = base.capture_committed_frontier(self.context, leader)
        for node in self.nodes:
            self.stop(node)
        self.check("all_voters_stopped_for_cold_restart", not self.started)
        for node in self.nodes[1:] + self.nodes[:1]:
            self.start(node)
        for node in self.nodes:
            base.wait_listener(self.context, node)
        self.wait_sealed_leader(self.nodes)
        for node in self.nodes:
            self.unseal(node)
        self.check("all_voters_cold_unsealed", True, no_reseed=True, original_keys=True)
        leader = self.leader(self.nodes)
        observed = {}
        for node in self.nodes:
            value = base.wait_local_frontier(self.context, node, frontier,
                                             seconds=60, record=self.event)
            observed[str(node.node_id)] = value[1]
            self.absent(node, denied_path)
        self.check("all_voters_local_raft_persistent", all(value >= frontier for value in observed.values()),
                   required_index=frontier, actual_applied_indices=observed)
        self.history_reads(leader)
        self.check("cold_leader_retained_history_exact", True, leader=leader.node_id)
        self.write_small(leader, "after-all-cold-restart")
        self.check("cold_restart_new_write_once", True)
        self.small_reads(self.nodes)
        self.check("cold_restart_all_hosts_readindex", True)
        return leader

    def missing_cipher_leader(self, healthy):
        self.stage = "owned_missing_cipher_leader_recovery"
        # Bring each actual local native store to the current selected closure
        # through an ordinary cold unseal before choosing a healthy source.
        # This is necessary because a prior quorum ACK required only two stores.
        for node in self.nodes:
            self.stop(node)
            self.start(node)
            self.unseal(node)
        healthy = self.leader(self.nodes)
        for node in self.nodes:
            self.stop(node)
        self.check("missing_cipher_targets_stopped", not self.started)
        missing = [node for node in self.nodes if node != healthy]
        inventories = {node: cipher_inventory(node, self.run_id, "quarantine") for node in missing}
        self.check("missing_cipher_two_targets_quarantined", all(
            receipt.get("remaining_count") == 0
            and receipt.get("quarantined_count", 0) > 0
            and receipt.get("quarantined_bytes", 0) >= TARGET_BYTES
            for receipt in inventories.values()),
            nodes={str(node.node_id): receipt for node, receipt in inventories.items()})
        for node in missing:
            self.start(node)
            base.wait_listener(self.context, node)
        elected = self.wait_sealed_leader(missing)
        self.check("missing_cipher_sealed_pair_elected", elected in missing,
                   leader=elected.node_id, both_voters_have_no_native_ciphertext=True)
        self.start(healthy)
        base.wait_listener(self.context, healthy)
        still_elected = self.wait_sealed_leader(self.nodes, expected=elected)
        self.check("missing_cipher_source_rejoined", still_elected == elected,
                   source=healthy.node_id, selected_missing_leader_is_current=elected.node_id)
        empty = cipher_inventory(elected, self.run_id, "empty")
        self.check("missing_cipher_leader_empty_before_unseal", empty.get("remaining_count") == 0
                   and empty.get("inventory_sha256") == inventories[elected]["inventory_sha256"],
                   leader=elected.node_id)
        self.unseal(elected)
        self.check("missing_cipher_leader_unsealed", True, original_http_budget_seconds=REQUEST_SECONDS)
        status, local = self.request(elected, "GET", "sys/leader", authenticate=False)
        if status != 200 or local.get("is_self") is not True:
            raise base.FixtureError("missing_cipher_reader_was_not_actual_leader")
        self.history_reads(elected)
        self.check("missing_cipher_leader_exact_history", True,
                   leader=elected.node_id, retained_large_payload_bytes=TARGET_BYTES)
        recovered = cipher_inventory(elected, self.run_id, "recovered")
        self.check("missing_cipher_actual_leaves_rebuilt",
                   recovered.get("restored_count", 0) > 0
                   and recovered.get("restored_bytes", 0) >= TARGET_BYTES
                   and recovered.get("every_restored_sha_and_size_match") is True
                   and recovered.get("inventory_sha256") == inventories[elected]["inventory_sha256"],
                   **recovered)
        # Old, unreachable ciphertext remains quarantined; recovery is required
        # to rebuild the committed closure, not resurrect every prior orphan.
        for node in self.nodes:
            if node != elected:
                self.unseal(node)
        self.check("missing_cipher_remaining_nodes_unsealed", True)
        self.small_reads(self.nodes)
        self.check("missing_cipher_all_hosts_readindex", True)
        return self.leader(self.nodes)

    def finish_application(self, leader):
        self.stage = "owned_synthetic_metadata_cleanup"
        paths = [self.path, *self.acknowledged]
        for path in paths:
            status, _ = self.request(leader, "DELETE", "secret/metadata/" + path)
            if status != 204:
                raise base.FixtureError("synthetic_metadata_cleanup_not_acknowledged_once")
        self.check("synthetic_metadata_cleanup_once", True, paths=len(paths))
        for node in self.nodes:
            for path in paths:
                self.absent(node, path)
        self.check("synthetic_metadata_absent", True, observed_hosts=3)
        self.stage = "final_same_source_integrity"
        remote = {str(node.node_id): base.remote_binary_digest(node) for node in self.nodes}
        unchanged = remote == self.expected and all(
            base.sha256_file(path) == self.source_files[str(path)]
            for path in map(Path, self.source_files)) and all(
            base.sha256_file(self.local_binaries[node.alias]) == self.expected[str(node.node_id)]
            for node in self.nodes)
        self.check("source_and_binaries_unchanged", unchanged, remote_binary_sha256=remote)
        self.check("report_excludes_runtime_secrets", base.report_is_secret_safe(self.report, self.secrets()))

    def execute(self):
        self.prepare()
        leader = self.bootstrap_v5()
        self.activate_and_grow(leader)
        leader, denied = self.failover_and_quorum(leader)
        leader = self.full_cold_restart(leader, denied)
        leader = self.missing_cipher_leader(leader)
        self.finish_application(leader)

    def cleanup(self):
        # Do not let a checkpoint or one unresolved process stop prevent the
        # remaining owned children from receiving their own bounded cleanup.
        # Report failure only after both process and SSH cleanup were attempted.
        failed = []
        for node in reversed(self.nodes):
            if node not in self.started:
                continue
            try:
                pid = self.owned_process_action(node, "stop")
                assert_stopped(node)
                self.started.discard(node)
                self.events.append({"event": "final_owned_server_stopped", "at": time.time(),
                                    "node": node.node_id, "pid": pid})
            except Exception:
                failed.append(node.node_id)
        if failed:
            self.report["cleanup_failure"] = failed
            self.report.setdefault("failure_code", "owned_process_cleanup_unresolved")
        try:
            self.mesh.stop(lambda name, **details: self.events.append(
                {"event": name, "at": time.time(), **details}))
            stopped = True
        except Exception:
            stopped = False
            self.report.setdefault("failure_code", "owned_mesh_cleanup_unresolved")
        for name, passed in (("owned_processes_stopped", not failed and not self.started),
                             ("owned_mesh_stopped", stopped)):
            if any(row["case"] == name for row in self.checks):
                raise base.FixtureError("duplicate_owned_cleanup_observation")
            self.checks.append({"case": name, "passed": passed})
        self.report["retained_owned_evidence_roots"] = [
            {"node": node.node_id, "root": node.root,
             "files": [*base.REMOTE_EVIDENCE_FILES, MARKER]}
            for node in self.nodes if node in self.created
        ]
        self.checkpoint()
        return not failed and not self.started and stopped


def parsed_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-source", required=True,
                        help="ssh-alias:/absolute/path/to/heptabao-server")
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--node-binary", action="append", default=[],
                        help="node-alias,source-alias:absolute-path,SHA256,source-commit,source-tree")
    parser.add_argument("--native-build-receipt", action="append", default=[], required=True,
                        help="node-alias,source-alias:absolute-receipt-path,SHA256; exactly one per voter")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--node", action="append", required=True,
                        help="ssh-alias,private-ip,absolute-NEW-root; specify Mac, ROG and Pocket4")
    parser.add_argument("--api-port", type=int, default=46230)
    parser.add_argument("--raft-port", type=int, default=46231)
    parser.add_argument("--mesh-local-port-base", type=int, default=55200)
    parser.add_argument("--mesh-reverse-port-base", type=int, default=55300)
    parser.add_argument("--mesh-api-port-base", type=int, default=55400)
    parser.add_argument("--work-root", type=Path, required=True)
    network = parser.add_mutually_exclusive_group(required=True)
    network.add_argument("--allow-private-tailnet", action="store_true")
    network.add_argument("--allow-private-lan", action="store_true")
    args = parser.parse_args(argv)
    if len(args.node) != 3 or len(set(args.node)) != 3:
        parser.error("exactly three distinct physical nodes are required")
    if (re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is None
            or re.fullmatch(r"[0-9a-f]{40}", args.source_tree) is None):
        parser.error("source commit and tree must be exact SHA-1 values")
    if re.fullmatch(r"[0-9a-f]{64}", args.expected_binary_sha256) is None:
        parser.error("invalid binary SHA-256")
    ports = [args.api_port, args.raft_port,
             *range(args.mesh_local_port_base + 1, args.mesh_local_port_base + 4),
             *range(args.mesh_reverse_port_base + 1, args.mesh_reverse_port_base + 4),
             *range(args.mesh_api_port_base + 1, args.mesh_api_port_base + 4)]
    if len(set(ports)) != len(ports) or any(not 1024 <= port <= 65535 for port in ports):
        parser.error("all API, Raft and owned loopback mesh ports must be distinct and unprivileged")
    mesh = StrictCompleteMesh(args.mesh_local_port_base, args.mesh_reverse_port_base,
                              args.mesh_api_port_base)
    sources, receipts = {}, {}
    try:
        base.parse_binary_source(args.binary_source)
        nodes = [base.parse_node(value, index + 1, args.api_port, args.raft_port,
                                 allow_private_lan=args.allow_private_lan)
                 for index, value in enumerate(args.node)]
        aliases = {node.alias for node in nodes}
        if (len(aliases) != 3 or len({node.ip for node in nodes}) != 3
                or len({node.root for node in nodes}) != 3
                or any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", alias) is None
                       for alias in aliases)):
            parser.error("node aliases, IPs and roots must each be distinct")
        # Pure argument checks happen before creating a local directory or
        # opening any network connection, including the inherited mesh checks.
        loopback.mesh_plan([node.alias for node in nodes], args.raft_port,
                           args.mesh_local_port_base, args.mesh_reverse_port_base)
        nodes = mesh.prepare_nodes(nodes)
        for specification in args.node_binary:
            alias, source = base.parse_node_binary(specification, args.source_commit, args.source_tree)
            if alias not in aliases or alias in sources:
                parser.error("native artifact must name one unique configured node")
            sources[alias] = source
        for specification in args.native_build_receipt:
            alias, receipt = base.parse_build_receipt(specification)
            if alias not in aliases or alias in receipts:
                parser.error("native receipt must name one unique configured node")
            receipts[alias] = receipt
    except (argparse.ArgumentTypeError, ValueError, base.FixtureError):
        parser.error("invalid host, source, receipt or complete-mesh binding")
    if set(receipts) != aliases:
        parser.error("each of the three voters requires its own exact source/build/ABI receipt")
    work = args.work_root
    if not work.is_absolute() or work.name in ("", ".", ".."):
        parser.error("work-root must be a new absolute canonical path")
    try:
        parent = work.parent.resolve(strict=True)
        entry = parent.stat()
    except OSError:
        parser.error("work-root parent must already exist")
    if (parent / work.name != work or work.exists() or work.is_symlink() or not parent.is_dir()
            or entry.st_uid != os.getuid() or entry.st_mode & 0o022):
        parser.error("work-root must be new, under a canonical owner-controlled parent")
    expected = {str(node.node_id): sources.get(
        node.alias, (None, None, args.expected_binary_sha256))[2] for node in nodes}
    # Detect ownership-script drift before the first externally visible effect.
    compile(native_process_script(), "native-owned-process-script", "exec")
    compile(CIPHER_INVENTORY_SCRIPT.replace("    __STOPPED_CHECK__", "    pass"),
            "native-owned-cipher-script", "exec")
    return args, nodes, mesh, sources, receipts, expected


def failure_code(error):
    if isinstance(error, base.FixtureInterrupted):
        return "controller_interrupted"
    if isinstance(error, base.FixtureError):
        value = str(error)
        if re.fullmatch(r"[a-zA-Z0-9_]{1,160}", value):
            return value
        return "native_fixture_contract_failed"
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return "original_operation_timeout"
    if isinstance(error, subprocess.CalledProcessError):
        return "owned_remote_operation_rejected"
    if isinstance(error, (OSError, ssl.SSLError, urllib.error.URLError)):
        return "transport_or_private_storage_failed"
    return "native_fixture_exception"


def main(argv=None):
    args, nodes, mesh, sources, receipts, expected = parsed_arguments(argv)
    return execute_fixture(args, nodes, mesh, sources, receipts, expected)


def execute_fixture(args, nodes, mesh, sources, receipts, expected, run_type=NativeRun):
    os.umask(0o077)
    args.work_root.mkdir(mode=0o700)
    run = run_type(args, nodes, mesh, sources, receipts, expected)
    completed, cleanup = False, False
    handlers = base.install_signal_handlers()
    try:
        with strict_shared_transport():
            try:
                run.checkpoint()
                run.execute()
                completed = True
            except Exception as error:
                run.report["failure_code"] = failure_code(error)
                run.report["failure_stage"] = run.stage
                run.report["failure_type"] = type(error).__name__
            finally:
                try:
                    cleanup = run.cleanup()
                except Exception as error:
                    run.report.setdefault("failure_code", failure_code(error))
                    run.report["cleanup_reporting_failure"] = True
    finally:
        base.restore_signal_handlers(handlers)
    complete_before_final = (
        completed and cleanup and not run.report.get("failure_code")
        and len(run.checks) == len(run.required_checks) - 1
        and {row["case"] for row in run.checks} == run.required_checks - {"native.complete"}
        and all(row.get("passed") is True for row in run.checks)
        and base.report_is_secret_safe(run.report, run.secrets())
    )
    if complete_before_final:
        run.stage = "completed_after_owned_cleanup"
        try:
            run.check("native.complete", True)
            run.report["status"] = "passed"
        except Exception as error:
            run.report.setdefault("failure_code", failure_code(error))
    elif completed and cleanup:
        run.report.setdefault("failure_code", "native_fixed_denominator_incomplete")
    run.report["observed_check_count"] = len(run.checks)
    run.report["passed_check_count"] = sum(row.get("passed") is True for row in run.checks)
    run.report["missing_checks"] = sorted(run.required_checks - {row["case"] for row in run.checks})
    final = base.secret_safe_report(run.report, run.secrets())
    # Runtime secrets stay only in the private test roots and are never copied
    # into the public receipt. The existing remote evidence files are retained
    # in those private roots for an explicit subsequent inspection, not emitted.
    run.root_token = run.unseal_key = ""
    run.confidential.clear()
    try:
        write_private(args.work_root / "summary.json", canonical(final) + b"\n")
    except OSError:
        print(json.dumps({"status": "failed", "checks": len(run.checks),
                          "failure_code": "private_report_unavailable"}, sort_keys=True))
        return 1
    passed = (final.get("status") == "passed" and cleanup
              and len(run.checks) == len(run.required_checks)
              and {row["case"] for row in run.checks} == run.required_checks
              and all(row.get("passed") is True for row in run.checks))
    print(json.dumps({"status": "passed" if passed else "failed", "checks": len(run.checks),
                      "failure_code": None if passed else "fixture_failed"}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

