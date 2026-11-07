#!/usr/bin/env python3
"""Create a private, random synthetic .hbv through the actual Rust vault executable.

Only ciphertext and hash commitments may be included in an APK. master.private and
recovery.private.json stay in the private QA fixture directory, never in source/APKs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vault", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.output.resolve()
    root.mkdir(mode=0o700, exist_ok=False)
    vault_root = root / "rust-vault"
    vault_root.mkdir(mode=0o700)
    master = secrets.token_urlsafe(32)
    user = "synthetic-" + secrets.token_hex(12)
    password = secrets.token_urlsafe(32)
    expected = {"schema": 1, "entry_id": "android-fixture", "origin": "https://native-fixture.heptabao.invalid", "username_sha256": hashlib.sha256(user.encode()).hexdigest(), "password_sha256": hashlib.sha256(password.encode()).hexdigest(), "rust_vault_sha256": hashlib.sha256(args.vault.read_bytes()).hexdigest()}
    def command(operation, request):
        result = subprocess.run([str(args.vault.resolve()), str(vault_root), operation], input=json.dumps(request).encode(), capture_output=True, check=False)
        if result.returncode != 0:
            raise RuntimeError("rust_fixture_operation_failed")
        response = json.loads(result.stdout)
        if response.get("ok") is not True:
            raise RuntimeError("rust_fixture_response_failed")
        return response
    command("init", {"password": master, "output": str(root / "recovery.private.json")})
    response = command("put", {"password": master, "expected_revision": 0, "item": {"id": expected["entry_id"], "kind": "login", "title": "Android synthetic fixture", "username": user, "origin": expected["origin"], "secret": password, "notes": "Synthetic qualification only", "totp": None}})
    assert response["metadata"]["revision"] == 1
    command("backup", {"password": master, "output": str(root / "vault.hbv")})
    (root / "master.private").write_text(master)
    expected["ciphertext_sha256"] = hashlib.sha256((root / "vault.hbv").read_bytes()).hexdigest()
    (root / "expected.json").write_text(json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps({"ok": True, "fixture": str(root), "ciphertext_sha256": expected["ciphertext_sha256"], "rust_vault_sha256": expected["rust_vault_sha256"]}))


if __name__ == "__main__":
    main()
