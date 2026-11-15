#!/usr/bin/env python3
"""Create a new private native-host installation, without modifying a profile.

Pass the chosen browser's native host manifest directory explicitly. No actual
credential, master password or recovery key is accepted by this installer.
The unpacked extension ID identifies routing, not a hostile same-UID process.
The executable must be owned and protected from other accounts' writes. The
installation parent and manifest directory must be private, with no replaceable
or symlinked ancestor paths. Existing output is never overwritten.
"""
import argparse
import hashlib
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
        try:
            mode = parent.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValueError("symlink_rejected")


def protected_path(path: Path):
    """Do not publish a launcher through another account's replaceable path.

    A private leaf alone is insufficient when an ancestor can be renamed.
    Sticky temporary directories protect each owned child and remain usable.
    This is local filesystem admission, not protection from the same UID/root.
    """
    no_links(path)
    for parent in path.parents:
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
            raise ValueError("unprotected_parent")


def private_directory(path: Path):
    protected_path(path)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("private_directory_required")
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode


def binary_identity(path: Path):
    protected_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or not before.st_mode & 0o100 or before.st_mode & 0o6022):
            raise ValueError("owned_executable_required")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        identity = tuple(getattr(before, key) for key in fields)
        if (tuple(getattr(after, key) for key in fields) != identity
                or tuple(getattr(path.lstat(), key) for key in fields) != identity):
            raise ValueError("binary_changed")
        return identity, digest
    finally:
        os.close(descriptor)


def create_manifest_directory(path: Path):
    protected_path(path)
    missing = []
    parent = path
    while not os.path.lexists(parent):
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=False)
    return private_directory(path)


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
        protected_path(path)
    binary_before = binary_identity(binary)
    vault_before = private_directory(vault)
    parent_before = private_directory(root.parent)
    if os.path.lexists(manifests):
        private_directory(manifests)
    # Existing installation roots are deliberately refused: upgrades must retain
    # a separate old installation and switch one exact manifest after review.
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    root_before = private_directory(root)
    manifests_before = create_manifest_directory(manifests)
    config = root / "config.json"
    create(config, json.dumps({"vault_root": str(vault), "extension_id": extension_id, "unlock_seconds": seconds}).encode())
    launcher = root / "native-host"
    create(launcher, ("#!/bin/sh\nexec " + shlex.quote(str(binary)) + " --config " + shlex.quote(str(config)) + ' "$@"\n').encode(), 0o700)
    manifest = manifests / "org.heptabao.personal_vault.json"
    create(manifest, json.dumps({"name": "org.heptabao.personal_vault", "description": "HeptaBao local encrypted personal vault preview", "path": str(launcher), "type": "stdio", "allowed_origins": [f"chrome-extension://{extension_id}/"]}).encode())
    if (binary_identity(binary) != binary_before or private_directory(vault) != vault_before
            or private_directory(root.parent) != parent_before or private_directory(root) != root_before
            or private_directory(manifests) != manifests_before):
        raise ValueError("installation_changed")
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
