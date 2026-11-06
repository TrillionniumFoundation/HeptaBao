#!/usr/bin/env python3
"""Create a fresh synthetic Rust-format vault and an RSA-OAEP enrollment capsule.

The capsule contains only newly generated QA material for one authenticated peer.
This is a test fixture transport, not a product pairing or recovery mechanism.
Passwords enter the Rust CLI through stdin; secret outputs stay in the private root.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vault-bin", type=Path, required=True)
    parser.add_argument("--peer-public-key", type=Path, required=True)
    parser.add_argument("--peer-key-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary, peer, root = (p.resolve() for p in (args.vault_bin, args.peer_public_key, args.output))
    if peer.stat().st_size > 4096 or digest(peer) != args.peer_key_sha256:
        raise RuntimeError("peer_key_binding_failed")
    os.umask(0o077); root.mkdir(mode=0o700, exist_ok=False)
    private = root / "private"; private.mkdir(mode=0o700)
    password = secrets.token_urlsafe(24)
    (private / "master.private").write_bytes(password.encode())
    recovery_path = private / "recovery.private.json"
    vault_root = private / "seed"
    vault_root.mkdir(mode=0o700)
    result = subprocess.run([str(binary), str(vault_root), "init"], input=json.dumps({"password": password, "output": str(recovery_path)}).encode(), capture_output=True)
    if result.returncode:
        raise RuntimeError("synthetic_vault_init_failed")
    metadata = json.loads(result.stdout)
    if not metadata.get("ok"):
        raise RuntimeError("synthetic_vault_init_unconfirmed")
    recovery = json.loads(recovery_path.read_bytes())
    clear = json.dumps({"password": password, "recovery": recovery}, separators=(",", ":")).encode()
    if len(clear) > 318:
        raise RuntimeError("capsule_limit")
    capsule = subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", str(peer), "-pkeyopt", "rsa_padding_mode:oaep",
                              "-pkeyopt", "rsa_oaep_md:sha256", "-pkeyopt", "rsa_mgf1_md:sha256"], input=clear, capture_output=True)
    if capsule.returncode:
        raise RuntimeError("capsule_encryption_failed")
    (root / "seed.hbv").write_bytes((vault_root / "vault.hbv").read_bytes())
    (root / "enrollment.oaep").write_bytes(capsule.stdout)
    receipt = {"schema": 1, "scope": "synthetic_fixture_transport_only", "vault_binary_sha256": digest(binary),
               "peer_public_key_sha256": digest(peer), "ciphertext_sha256": digest(root / "seed.hbv"),
               "capsule_sha256": digest(root / "enrollment.oaep"), "vault_id": metadata["metadata"]["vault_id"]}
    (root / "receipt.public.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
