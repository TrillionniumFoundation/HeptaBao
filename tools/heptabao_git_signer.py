#!/usr/bin/env python3
"""Git SSH signing adapter for one owner-authorized synthetic broker operation.

Configure gpg.ssh.program to this executable and HEPTABAO_GIT_SIGNER_CONFIG to
an owner-private configuration file. Only -Y sign -n git -f PUBLIC_KEY FILE is
accepted. This adapter does not issue grants or read the broker's secret store.
Use an owner-private TMPDIR for Git's temporary signing payload.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import re
import stat
import struct
import subprocess
import sys

MAX_DOCUMENT = 128 * 1024
MAX_PAYLOAD = 32 * 1024
MAX_SIGNATURE = 4096
CONFIG_FIELDS = {
    "schema",
    "root",
    "op",
    "grant",
    "broker_executable",
    "expected_repository",
    "expected_repository_identity",
    "expected_tree",
}
OPERATION_FIELDS = {
    "operation_id", "task_id", "run_id", "credential_id",
    "target", "method", "path", "body_base64",
}


class Denied(Exception):
    """A fixed, non-sensitive failure, never an input or operating-system error."""


def require(condition: bool) -> None:
    if not condition:
        raise Denied()


def absolute_path(value: object) -> str:
    require(isinstance(value, str))
    require(0 < len(value) <= 4096 and "\0" not in value)
    require(value.startswith("/") and not value.startswith("//"))
    require(os.path.normpath(value) == value)
    return value


def private_directory(fd: int) -> None:
    meta = os.fstat(fd)
    require(stat.S_ISDIR(meta.st_mode))
    require(meta.st_uid == os.geteuid() and stat.S_IMODE(meta.st_mode) == 0o700)


@contextlib.contextmanager
def directory(path: str, private: bool = True):
    path = absolute_path(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in path.split("/")[1:]:
            if part:
                following = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = following
        if private:
            private_directory(fd)
        yield fd
    finally:
        os.close(fd)


def regular_file(fd: int, cap: int, private: bool) -> None:
    meta = os.fstat(fd)
    require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1)
    require(meta.st_uid == os.geteuid() and 0 <= meta.st_size <= cap)
    require(not (meta.st_mode & (0o077 if private else 0o022)))


@contextlib.contextmanager
def opened_file(path: str, cap: int, private: bool = True):
    path = absolute_path(path)
    parent, leaf = os.path.split(path)
    require(bool(leaf))
    with directory(parent) as parent_fd:
        fd = os.open(
            leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=parent_fd,
        )
        try:
            regular_file(fd, cap, private)
            yield parent_fd, leaf, fd
        finally:
            os.close(fd)


def read_fd(fd: int, cap: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) <= cap:
        chunk = os.read(fd, min(8192, cap + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    require(len(data) <= cap)
    return bytes(data)


def read_private(path: str, cap: int = MAX_DOCUMENT) -> bytes:
    with opened_file(path, cap) as (_, _, fd):
        return read_fd(fd, cap)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def document(data: bytes) -> dict:
    require(len(data) <= MAX_DOCUMENT)
    value = json.loads(data, object_pairs_hook=unique_object)
    require(type(value) is dict)
    return value


def public_key(data: bytes) -> bytes:
    lines = data.decode("ascii").splitlines()
    require(len(lines) == 1)
    fields = lines[0].split()
    require(len(fields) >= 2 and fields[0] == "ssh-ed25519")
    encoded = fields[1]
    raw = base64.b64decode(encoded, validate=True)
    require(base64.b64encode(raw).decode("ascii") == encoded)
    require(len(raw) == 51 and raw[:19] == b"\0\0\0\x0bssh-ed25519\0\0\0\x20")
    return raw


def signature(pem: object, expected_key: bytes) -> bytes:
    require(type(pem) is str and len(pem) <= MAX_SIGNATURE)
    lines = pem.splitlines()
    require(len(lines) >= 3)
    require(lines[0] == "-----BEGIN SSH SIGNATURE-----")
    require(lines[-1] == "-----END SSH SIGNATURE-----")
    raw = base64.b64decode("".join(lines[1:-1]), validate=True)
    require(raw[:10] == b"SSHSIG\0\0\0\x01")
    remaining = raw[10:]

    def field() -> bytes:
        nonlocal remaining
        require(len(remaining) >= 4)
        length = struct.unpack(">I", remaining[:4])[0]
        require(length <= len(remaining) - 4)
        value, remaining = remaining[4:4 + length], remaining[4 + length:]
        return value

    require(field() == expected_key)
    require(field() == b"git" and field() == b"" and field() == b"sha512")
    signed = field()
    require(not remaining)
    # Ed25519 SSH signature: algorithm string followed by a 64-byte signature.
    require(len(signed) == 83)
    require(signed[:19] == b"\0\0\0\x0bssh-ed25519\0\0\0\x40")
    return ("\n".join(lines) + "\n").encode("ascii")


def repository(config: dict) -> None:
    expected = absolute_path(config["expected_repository"])
    require(os.getcwd() == expected)
    identity = config["expected_repository_identity"]
    require(type(identity) is dict)
    require(set(identity) == {"device", "inode", "git_device", "git_inode"})
    require(all(type(x) is int and x >= 0 for x in identity.values()))
    with directory(expected) as root_fd:
        meta = os.fstat(root_fd)
        require((meta.st_dev, meta.st_ino) == (identity["device"], identity["inode"]))
        git_fd = os.open(
            ".git", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        try:
            meta = os.fstat(git_fd)
            require(meta.st_uid == os.geteuid() and not meta.st_mode & 0o022)
            require((meta.st_dev, meta.st_ino) == (identity["git_device"], identity["git_inode"]))
        finally:
            os.close(git_fd)
    # Check Git's actual effective context, including GIT_DIR/core.worktree.
    # This command reads repository metadata and never accesses credentials.
    context = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--absolute-git-dir", "--show-toplevel", "--git-common-dir"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=5, check=False,
    )
    require(context.returncode == 0 and len(context.stdout) <= 8192)
    require(context.stdout.decode("utf-8").splitlines() == [expected + "/.git", expected, expected + "/.git"])


def publish_signature(parent_fd: int, leaf: str, data: bytes) -> None:
    name = leaf + ".sig"
    fd = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600, dir_fd=parent_fd,
    )
    try:
        remaining = memoryview(data)
        while remaining:
            count = os.write(fd, remaining)
            require(count > 0)
            remaining = remaining[count:]
        os.fsync(fd)
        os.fsync(parent_fd)
    except BaseException:
        # Only this process's create-only output can be removed on failure.
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)


def run(arguments: list[str]) -> None:
    require(len(arguments) == 7)
    require(arguments[:5] == ["-Y", "sign", "-n", "git", "-f"])
    key_path, payload_path = map(absolute_path, arguments[5:])
    config_path = absolute_path(os.environ.get("HEPTABAO_GIT_SIGNER_CONFIG"))
    config = document(read_private(config_path))
    require(set(config) == CONFIG_FIELDS and type(config["schema"]) is int and config["schema"] == 1)
    for field in ("root", "op", "grant", "broker_executable", "expected_repository"):
        config[field] = absolute_path(config[field])
    require(type(config["expected_tree"]) is str)
    require(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", config["expected_tree"]) is not None)
    # Request files are separate from the owner store. No owner key or
    # credential config is read, and the only broker command below is execute.
    for path in (config_path, config["op"], config["grant"], key_path, payload_path):
        require(os.path.commonpath([config["root"], path]) != config["root"])
    with directory(config["root"]):
        pass
    repository(config)
    operation = document(read_private(config["op"]))
    require(set(operation) == OPERATION_FIELDS)
    require(all(type(value) is str for value in operation.values()))
    require(operation["method"] == "SIGN" and operation["path"] == "git")
    require(re.fullmatch(r"git:[a-zA-Z0-9_.:-]{1,128}", operation["target"]) is not None)
    body = operation["body_base64"]
    require(len(body) <= 2 * MAX_PAYLOAD)
    granted = base64.b64decode(body + "=" * (-len(body) % 4), altchars=b"-_", validate=True)
    require(len(granted) <= MAX_PAYLOAD)
    require(base64.urlsafe_b64encode(granted).rstrip(b"=").decode("ascii") == body)
    require(granted.split(b"\n", 1)[0] == b"tree " + config["expected_tree"].encode("ascii"))
    # Check the grant's private file boundary without loading it into Python.
    with opened_file(config["grant"], MAX_DOCUMENT):
        pass
    with opened_file(key_path, 16384, private=False) as (_, _, key_fd):
        expected_key = public_key(read_fd(key_fd, 16384))
    with opened_file(payload_path, MAX_PAYLOAD) as (parent_fd, leaf, payload_fd):
        require(read_fd(payload_fd, MAX_PAYLOAD) == granted)
        # The fixed argv never creates authority and contains paths only.
        result = subprocess.run(
            [config["broker_executable"], "execute", config["root"], config["op"], config["grant"]],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=25, check=False,
        )
        require(result.returncode == 0)
        response = document(result.stdout)
        require(set(response) == {"ok", "receipt"} and response["ok"] is True)
        receipt = response["receipt"]
        require(type(receipt) is dict)
        require(set(receipt) == {"operation_id", "outcome", "http_status", "http_success", "signature_pem", "public_key"})
        require(receipt["operation_id"] == operation["operation_id"] and receipt["outcome"] == "completed")
        require(receipt["http_status"] is None and receipt["http_success"] is None)
        require(type(receipt["public_key"]) is str)
        require(public_key(receipt["public_key"].encode("ascii")) == expected_key)
        pem = signature(receipt["signature_pem"], expected_key)
        repository(config)
        require(read_fd(payload_fd, MAX_PAYLOAD) == granted)
        current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        opened = os.fstat(payload_fd)
        require((current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino))
        publish_signature(parent_fd, leaf, pem)


def main() -> int:
    try:
        run(sys.argv[1:])
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.SubprocessError, RecursionError):
        # Neither Git payloads, paths, grants nor upstream error text are logged.
        print('{"ok":false,"error":"git_signing_denied"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
