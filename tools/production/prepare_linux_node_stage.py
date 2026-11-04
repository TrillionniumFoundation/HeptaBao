#!/usr/bin/env python3
"""Prepare a new Linux node directory and CSR without starting any service.

The private key stays on this host. Only the CSR and public receipt are exported.
The existing Mac CA signs the CSR separately; this command neither initializes
Bao storage nor creates unseal, root-token, AppRole or activation material.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import time


class Refused(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def put(path, raw, mode=0o600):
    if not isinstance(raw, bytes):
        raw = (json.dumps(raw, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    sync_dir(path.parent)
    return sha(raw)


def private_command(argv, timeout=30):
    # Output is retained only in process memory. OpenSSL diagnostics can contain
    # private paths; never include them in an exception or public receipt.
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout, check=False)
    need(p.returncode == 0 and len(p.stdout) < 1024 * 1024,
         "offline_crypto_command_failed")
    return p.stdout


def copy_pinned_binary(source, target, expected):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid(),
             "source_binary_owner_or_type")
        h = hashlib.sha256()
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
        with os.fdopen(out, "wb") as f:
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                h.update(block)
                f.write(block)
            f.flush()
            os.fsync(f.fileno())
        after = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(fields(before) == fields(after), "source_binary_changed")
        need(h.hexdigest() == expected, "source_binary_hash_mismatch")
        with target.open("rb") as f:
            need(hashlib.file_digest(f, "sha256").hexdigest() == expected,
                 "copied_binary_hash_mismatch")
        sync_dir(target.parent)
        return before.st_size
    finally:
        os.close(fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for field in ("root", "binary", "binary-sha256", "source-commit", "source-tree",
                  "node-name", "hostname", "ip"):
        p.add_argument("--" + field, required=True)
    p.add_argument("--uid", type=int, required=True)
    p.add_argument("--node-id", type=int, choices=(2, 3), required=True)
    args = p.parse_args()
    os.umask(0o077)
    root, binary = Path(args.root), Path(args.binary)
    need(sys.platform == "linux", "linux_required")
    need(os.getuid() == args.uid and socket.gethostname() == args.hostname,
         "host_or_owner_mismatch")
    need(root.is_absolute() and root.parent == Path.home()
         and root.name == "heptabao-production-20261104-r1"
         and not root.exists() and not root.is_symlink(), "new_owned_stage_required")
    need(not root.parent.is_symlink() and root.parent.stat().st_uid == args.uid,
         "parent_custody")
    need(args.node_name in ("rog", "pocket4"), "named_node_required")
    need((args.node_id, args.node_name, args.ip) in
         ((2, "rog", "192.168.0.10"), (3, "pocket4", "192.168.0.9")),
         "registered_peer_binding")
    need(len(args.source_commit) == 40 and len(args.source_tree) == 40
         and all(c in "0123456789abcdef" for c in args.source_commit + args.source_tree),
         "source_identity_shape")
    need(len(args.binary_sha256) == 64
         and all(c in "0123456789abcdef" for c in args.binary_sha256), "binary_pin_shape")
    unit = Path.home() / ".config/systemd/user/heptabao-node.service"
    need(not unit.exists() and not unit.is_symlink(), "existing_node_registration")
    # Binding proves the requested address exists and is currently free. It
    # neither reserves the port nor changes firewall or routing configuration.
    for port in (8200, 8201):
        with socket.socket() as s:
            s.bind((args.ip, port))
    openssl = Path(shutil.which("openssl") or "/nonexistent").resolve(strict=True)
    python = Path(sys.executable).resolve(strict=True)
    root.mkdir(mode=0o700)
    sync_dir(root.parent)
    for rel in ("release", "control", "config", "tls", "node", "node/state",
                "node/raft", "logs", "service"):
        dest = root / rel
        dest.mkdir(mode=0o700)
        sync_dir(dest.parent)
    base = {
        "schema": "heptabao.linux-offline-node-preparation.v1",
        "root": str(root), "uid": args.uid, "hostname": args.hostname,
        "node_id": args.node_id, "node_name": args.node_name, "ip": args.ip,
        "source_commit": args.source_commit, "source_tree": args.source_tree,
        "binary_sha256": args.binary_sha256, "created_unix_ns": time.time_ns(),
        "service_started": False, "service_loaded": False, "traffic_cutover": False,
        "seed_initialized": False, "approles_generated": False,
        "firewall_or_routing_changed": False, "production_client_changed": False,
    }
    put(root / "control/preparation-intent.private.json", base)
    size = copy_pinned_binary(binary, root / "release/heptabao-server", args.binary_sha256)
    key = root / "tls/tls.key"
    put(key, private_command([str(openssl), "genpkey", "-algorithm", "RSA",
                             "-pkeyopt", "rsa_keygen_bits:3072"]))
    csr = private_command([str(openssl), "req", "-new", "-key", str(key), "-sha256",
                           "-subj", "/CN=" + args.hostname,
                           "-addext", "subjectAltName=DNS:" + args.hostname
                           + ",IP:" + args.ip + ",IP:127.0.0.1"])
    csr_sha = put(root / "tls/tls.csr", csr)
    private_command([str(openssl), "req", "-in", str(root / "tls/tls.csr"),
                     "-verify", "-noout"])
    config = {
        "listen": args.ip + ":8200", "data_dir": str(root / "node/state"),
        "storage": {"native_v6_raft": {"path": str(root / "node"),
            "node_id": args.node_name, "cluster_addr": "https://" + args.ip + ":8201",
            "api_addr": "https://" + args.ip + ":8200"}},
        "audit_file": str(root / "node/audit.jsonl"),
        "tls_cert_file": str(root / "tls/tls.crt"), "tls_key_file": str(key),
        "max_connections": 64, "timeout_seconds": 12,
        "rate_limit_per_second": 2000, "rate_limit_burst": 4000,
        "rate_limit_entries": 512, "lifecycle_interval_seconds": 1,
    }
    config_sha = put(root / "config/server.json", config)
    for rel in ("logs/node.stdout.log", "logs/node.stderr.log"):
        put(root / rel, b"")
    for path in root.rglob("*"):
        info = path.lstat()
        need(not path.is_symlink() and info.st_uid == args.uid
             and info.st_dev == root.stat().st_dev, "staged_path_custody")
        need(stat.S_IMODE(info.st_mode) == (0o700 if path.is_dir()
             or path.name == "heptabao-server" else 0o600), "staged_mode")
    result = dict(base, ok=True, binary_bytes=size, csr_sha256=csr_sha,
                  csr_signature_verified=True, private_key_exported=False,
                  ca_certificate_installed=False, leaf_certificate_installed=False,
                  replication_key_installed=False, ha_config_generated=False,
                  activation_created=False, server_config_sha256=config_sha,
                  openssl_path=str(openssl), openssl_sha256=sha(openssl.read_bytes()),
                  python_path=str(python), python_sha256=sha(python.read_bytes()),
                  script_sha256=sha(Path(__file__).read_bytes()),
                  api_port_available_at_prepare=True, raft_port_available_at_prepare=True,
                  api_port_reserved=False, raft_port_reserved=False)
    digest = put(root / "prepared-csr.public.json", result)
    print(json.dumps({"ok": True, "root": str(root), "receipt_sha256": digest,
                      "csr_sha256": csr_sha, "service_started": False}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"ok": False, "service_started": False,
                          "error": str(exc) if isinstance(exc, Refused)
                          else "offline_prepare_" + type(exc).__name__}))
        raise SystemExit(2)
