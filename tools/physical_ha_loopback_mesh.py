#!/usr/bin/env python3
"""Run real three-host synthetic Raft via complete loopback SSH forwarding.

The coordinator carries opaque mTLS streams. Node identities, enrolled leaf
pins, SNI, CA and replication keys remain unchanged. This transports actual
physical-host processes but does not qualify direct-LAN routing or partitions.

`plan` emits three argv arrays for the existing durable process supervisor.
`patch` changes only an explicitly synthetic, stopped fixture's peer addresses.
`restore` reinstates the exact saved config after those fixture processes stop.
No SSH credentials, firewall changes, production services or raw logs are used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys

from physical_ha_peer_preflight import Refusal, load_fixture, private_regular

SCHEMA = "heptabao.synthetic-three-host-loopback-mesh.v1"
BACKUP = "ha.direct-before-loopback.json"
RECEIPT = "ha.loopback-mesh.receipt.json"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate_ports(listener: int, local_base: int, reverse_base: int) -> None:
    ports = [listener, *range(local_base+1, local_base+4), *range(reverse_base+1, reverse_base+4)]
    if len(set(ports)) != len(ports) or any(not 1024 <= p <= 65535 for p in ports):
        raise Refusal("INVALID_MESH_PORTS")


def mesh_plan(aliases: list[str], listener: int, local_base: int, reverse_base: int) -> dict:
    validate_ports(listener, local_base, reverse_base)
    if (len(aliases) != 3 or len(set(aliases)) != 3
            or any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", name) is None for name in aliases)):
        raise Refusal("THREE_DISTINCT_SSH_ALIASES_REQUIRED")
    commands = []
    endpoints = {}
    for node_id, alias in enumerate(aliases, 1):
        argv = ["ssh", "-N", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                "-o", "ConnectionAttempts=1", "-o", "ExitOnForwardFailure=yes",
                "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3",
                "-o", "ControlMaster=no", "-o", "ControlPath=none",
                "-L", f"127.0.0.1:{local_base+node_id}:127.0.0.1:{listener}"]
        for peer_id in range(1, 4):
            if peer_id != node_id:
                argv += ["-R", f"127.0.0.1:{reverse_base+peer_id}:127.0.0.1:{local_base+peer_id}"]
        argv.append(alias)
        commands.append({"node_id": node_id, "executable": argv[0], "args": argv[1:]})
        endpoints[str(node_id)] = {str(peer): f"127.0.0.1:{listener if peer == node_id else reverse_base+peer}"
                                   for peer in range(1, 4)}
    return {"schema": SCHEMA, "synthetic_only": True, "production_authority": False,
            "physical_host_count": 3, "directed_raft_links": 6,
            "transport": "coordinator-mediated-ssh-with-end-to-end-mtls",
            "direct_lan_qualification": False, "commands": commands, "node_peer_addresses": endpoints}


def stopped(config_path: Path) -> None:
    """Refuse an exact HA config currently named by a visible process."""
    try:
        output = subprocess.run(["ps", "-axo", "args="], check=True, capture_output=True,
                                text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        raise Refusal("PROCESS_INVENTORY_UNAVAILABLE") from None
    needle = str(config_path)
    for line in output.splitlines():
        if needle not in line:
            continue
        try:
            argv = shlex.split(line)
        except ValueError:
            raise Refusal("PROCESS_IDENTITY_UNCERTAIN") from None
        for i, part in enumerate(argv):
            if (part == "--ha-config" and i+1 < len(argv) and argv[i+1] == needle
                    or part == "--ha-config="+needle):
                raise Refusal("FIXTURE_PROCESS_MUST_BE_STOPPED")


def write_new(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise Refusal("RECEIPT_OR_BACKUP_ALREADY_EXISTS") from None
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def fsync_parent(root: Path) -> None:
    fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def patch(root: Path, manifest: Path, listener: int, local_base: int, reverse_base: int) -> dict:
    validate_ports(listener, local_base, reverse_base)
    config, marker, root = load_fixture(root, manifest)
    if root.resolve(strict=True) != root:
        raise Refusal("NON_CANONICAL_FIXTURE_ROOT")
    if set(config["peers"]) != {"1", "2", "3"} or config["node_id"] not in (1, 2, 3):
        raise Refusal("EXACT_THREE_VOTERS_REQUIRED")
    if marker.get("allow_production") is not False:
        raise Refusal("EXPLICIT_NON_PRODUCTION_MARKER_REQUIRED")
    path = root / "ha.json"
    stopped(path)
    original = private_regular(path).read_bytes()
    # Refuse source changes since identity, pins and file ownership were checked.
    if json.loads(original) != config:
        raise Refusal("CONFIG_CHANGED_DURING_READ")
    transformed = json.loads(original)
    transformed["listen"] = f"127.0.0.1:{listener}"
    node_id = config["node_id"]
    for peer_id, peer in transformed["peers"].items():
        port = listener if int(peer_id) == node_id else reverse_base+int(peer_id)
        peer["address"] = f"127.0.0.1:{port}"
    # Deliberately constrain the complete mutation surface to transport addresses.
    comparison = json.loads(json.dumps(transformed))
    comparison["listen"] = config["listen"]
    for peer_id in comparison["peers"]:
        comparison["peers"][peer_id]["address"] = config["peers"][peer_id]["address"]
    if comparison != config:
        raise Refusal("NON_TRANSPORT_CHANGE_REFUSED")
    changed = (json.dumps(transformed, sort_keys=True, indent=2)+"\n").encode()
    receipt = {"schema": SCHEMA, "node_id": node_id, "synthetic_only": True,
               "production_authority": False, "direct_lan_qualification": False,
               "before_sha256": digest(original), "after_sha256": digest(changed),
               "changed_fields": ["listen", "peers.*.address"],
               "peer_identity_unchanged": True, "restored": False}
    backup, receipt_path = root/BACKUP, root/RECEIPT
    if backup.exists() or receipt_path.exists():
        raise Refusal("RECEIPT_OR_BACKUP_ALREADY_EXISTS")
    write_new(backup, original)
    write_new(receipt_path, (json.dumps(receipt, sort_keys=True)+"\n").encode())
    temporary = root / "ha.loopback-mesh.copying"
    write_new(temporary, changed)
    if private_regular(path).read_bytes() != original:
        temporary.unlink()
        raise Refusal("CONFIG_CHANGED_BEFORE_PUBLISH")
    stopped(path)
    os.replace(temporary, path)
    fsync_parent(root)
    return receipt


def restore(root: Path, manifest: Path) -> dict:
    _, marker, root = load_fixture(root, manifest)
    if root.resolve(strict=True) != root or marker.get("allow_production") is not False:
        raise Refusal("EXPLICIT_NON_PRODUCTION_MARKER_REQUIRED")
    path = root / "ha.json"
    stopped(path)
    receipt = json.loads(private_regular(root/RECEIPT).read_bytes())
    old = private_regular(root/BACKUP).read_bytes()
    current = private_regular(path).read_bytes()
    if receipt.get("schema") != SCHEMA or digest(old) != receipt.get("before_sha256"):
        raise Refusal("BACKUP_IDENTITY_MISMATCH")
    if digest(current) == receipt["before_sha256"]:
        return {"schema": SCHEMA, "status": "already_restored", "node_id": receipt["node_id"]}
    if digest(current) != receipt["after_sha256"]:
        raise Refusal("CONFIG_CHANGED_AFTER_MESH_PATCH")
    temporary = root / "ha.loopback-restore.copying"
    write_new(temporary, old)
    if private_regular(path).read_bytes() != current:
        temporary.unlink()
        raise Refusal("CONFIG_CHANGED_BEFORE_RESTORE")
    stopped(path)
    os.replace(temporary, path)
    fsync_parent(root)
    return {"schema": SCHEMA, "status": "restored", "node_id": receipt["node_id"],
            "config_sha256": digest(old), "backup_retained": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--ssh-alias", action="append", required=True,
                      help="Exactly 3 aliases in node 1,2,3 order; run resulting jobs on one coordinator")
    update = sub.add_parser("patch")
    undo = sub.add_parser("restore")
    for target in (update, undo):
        target.add_argument("--fixture-root", required=True, type=Path)
        target.add_argument("--manifest", required=True, type=Path)
    for target in (plan, update):
        target.add_argument("--listener-port", required=True, type=int)
        target.add_argument("--local-port-base", default=55200, type=int)
        target.add_argument("--reverse-port-base", default=55300, type=int)
    args = parser.parse_args()
    try:
        if args.action == "plan":
            result = mesh_plan(args.ssh_alias, args.listener_port, args.local_port_base, args.reverse_port_base)
        elif args.action == "patch":
            result = patch(args.fixture_root, args.manifest, args.listener_port,
                           args.local_port_base, args.reverse_port_base)
        else:
            result = restore(args.fixture_root, args.manifest)
    except Refusal as error:
        result = {"schema": SCHEMA, "status": "refused", "reason": error.label}
    except (OSError, ValueError, KeyError, TypeError):
        result = {"schema": SCHEMA, "status": "refused", "reason": "FIXTURE_FILE_OR_SCHEMA_ERROR"}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 77 if result.get("status") == "refused" else 0


if __name__ == "__main__":
    sys.exit(main())
