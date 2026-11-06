#!/usr/bin/env python3
"""Prepare one new private Firefox native-host installation.

This candidate stages its manifest under the explicit installation root. It does
not register a browser-wide host, change a profile, install an extension or alter
Snap/portal permissions. The launch interface is Firefox's actual manifest-path
and add-on-ID pair. Local owner routing is not process or Runtime attestation.
No credential, password or recovery key is accepted by this installer.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys

ADDON_ID = "heptabao-firefox-feasibility@heptabao.invalid"
HOST_NAME = "org.heptabao.personal_vault_firefox_feasibility"
DESCRIPTION = "HeptaBao local encrypted vault Firefox candidate"


class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def no_links(path):
    require(path.is_absolute() and ".." not in path.parts, "absolute_path_required")
    for part in (path, *path.parents):
        try:
            mode = part.lstat().st_mode
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(mode), "symlink_rejected")


def private_directory(path):
    no_links(path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "private_directory_required")


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


def binary_identity(path):
    no_links(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and before.st_mode & 0o100
                and not before.st_mode & 0o6022, "owned_executable_required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns), "binary_changed")
        named = path.lstat()
        require(stat.S_ISREG(named.st_mode) and (named.st_dev, named.st_ino)
                == (before.st_dev, before.st_ino), "binary_changed")
        return {"bytes": before.st_size, "sha256": digest}
    finally:
        os.close(fd)


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def install(binary, vault, root, addon_id, seconds):
    require(addon_id == ADDON_ID and 1 <= seconds <= 300, "invalid_addon_or_expiry")
    for path in (binary, vault, root):
        no_links(path)
    private_directory(root.parent)
    private_directory(vault)
    require(not os.path.lexists(root), "installation_exists")
    # Canonical paths are recorded before launch: aliases are not accepted as
    # browser arguments by the native host.
    binary = binary.resolve(strict=True)
    vault = vault.resolve(strict=True)
    root = root.parent.resolve(strict=True) / root.name
    binary_before = binary_identity(binary)
    root.mkdir(mode=0o700, exist_ok=False)
    sync_directory(root.parent)
    manifests = root / "native-messaging-hosts"
    manifests.mkdir(mode=0o700, exist_ok=False)
    sync_directory(root)
    config = root / "firefox-config.json"
    launcher = root / "native-host"
    manifest = manifests / (HOST_NAME + ".json")
    manifest_raw = json_bytes({"name": HOST_NAME, "description": DESCRIPTION,
        "path": str(launcher), "type": "stdio", "allowed_extensions": [addon_id]})
    manifest_digest = hashlib.sha256(manifest_raw).hexdigest()
    config_raw = json_bytes({"vault_root": str(vault), "addon_id": addon_id,
        "unlock_seconds": seconds, "manifest_path": str(manifest),
        "manifest_sha256": manifest_digest, "launcher_path": str(launcher)})
    create(config, config_raw)
    launcher_raw = ("#!/bin/sh\nexec " + shlex.quote(str(binary))
        + " --firefox-config " + shlex.quote(str(config)) + ' "$@"\n').encode()
    create(launcher, launcher_raw, 0o700)
    create(manifest, manifest_raw)
    require(binary_identity(binary) == binary_before, "binary_changed")
    for path, expected in ((config, config_raw), (launcher, launcher_raw), (manifest, manifest_raw)):
        require(path.read_bytes() == expected, "installation_readback_failed")
    return {"prepared": True, "browser_registered": False,
        "scope": "explicit_private_native_host_staging_only", "manifest": str(manifest),
        "config": str(config), "launcher": str(launcher), "addon_id": addon_id,
        "host_name": HOST_NAME, "manifest_sha256": manifest_digest,
        "config_sha256": hashlib.sha256(config_raw).hexdigest(),
        "launcher_sha256": hashlib.sha256(launcher_raw).hexdigest(),
        "binary": binary_before, "browser_profile_modified": False,
        "snap_or_portal_permissions_modified": False, "end_to_end_qualified": False,
        "production_qualified": False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--addon-id", default=ADDON_ID)
    parser.add_argument("--unlock-seconds", type=int, default=60)
    args = parser.parse_args()
    try:
        result = install(args.binary, args.vault, args.install_root, args.addon_id,
                         args.unlock_seconds)
    except Refused as error:
        print(json.dumps({"prepared": False, "error": str(error)}))
        return 1
    except (OSError, ValueError):
        # Partial create-only output is retained. No automatic cleanup or retry
        # can turn an uncertain filesystem publication into a successful setup.
        print(json.dumps({"prepared": False, "error": "installation_io_failure"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
