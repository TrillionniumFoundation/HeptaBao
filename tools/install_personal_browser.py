#!/usr/bin/env python3
"""Create a new private native-host installation, without modifying a profile.

Pass the chosen browser's native host manifest directory explicitly. No actual
credential, master password or recovery key is accepted by this installer.
The unpacked extension ID identifies routing, not a hostile same-UID process.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import stat


def no_links(path: Path):
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute_no_symlink_path_required")
    for parent in (path, *path.parents):
        if parent.exists() and stat.S_ISLNK(parent.lstat().st_mode):
            raise ValueError("symlink_rejected")


def create(path: Path, data: bytes, mode=0o600):
    no_links(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def install(binary: Path, vault: Path, root: Path, manifests: Path, extension_id: str, seconds: int):
    if not re.fullmatch("[a-p]{32}", extension_id) or not 1 <= seconds <= 300:
        raise ValueError("invalid_extension_or_expiry")
    for path in (binary, vault, root, manifests):
        no_links(path)
    if not binary.is_file() or not os.access(binary, os.X_OK) or not vault.is_dir():
        raise ValueError("binary_and_existing_vault_required")
    if vault.stat().st_mode & 0o077 or vault.stat().st_uid != os.getuid():
        raise ValueError("private_vault_required")
    # Existing installation roots are deliberately refused: upgrades must retain
    # a separate old installation and switch one exact manifest after review.
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    manifests.mkdir(mode=0o700, parents=True, exist_ok=True)
    config = root / "config.json"
    create(config, json.dumps({"vault_root": str(vault), "extension_id": extension_id, "unlock_seconds": seconds}).encode())
    launcher = root / "native-host"
    create(launcher, ("#!/bin/sh\nexec " + shlex.quote(str(binary)) + " --config " + shlex.quote(str(config)) + ' "$@"\n').encode(), 0o700)
    manifest = manifests / "org.heptabao.personal_vault.json"
    create(manifest, json.dumps({"name": "org.heptabao.personal_vault", "description": "HeptaBao local encrypted personal vault preview", "path": str(launcher), "type": "stdio", "allowed_origins": [f"chrome-extension://{extension_id}/"]}).encode())
    return {"installed": True, "manifest": str(manifest), "config": str(config), "synthetic_qualification_required": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--native-manifest-dir", type=Path, required=True)
    parser.add_argument("--extension-id", required=True)
    parser.add_argument("--unlock-seconds", type=int, default=60)
    args = parser.parse_args()
    print(json.dumps(install(args.binary, args.vault, args.install_root, args.native_manifest_dir, args.extension_id, args.unlock_seconds)))
