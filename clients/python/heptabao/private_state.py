"""Descriptor-bound Linux/POSIX state publication. Same-UID processes are trusted.

The final directory must already be 0700 and caller-owned. No component may be a
symlink. Atomic rename, fsync and a single-writer flock implement crash-safe local
publication; this is not encryption or protection from root/the same OS user.
"""
from __future__ import annotations
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
import stat
from .transport import BaoError, canonical, decode_json

MAX_STATE = 65536


def _name(value: str) -> str:
    if not value or len(value) > 128 or not all(c.isascii() and (c.isalnum() or c in '._-') for c in value) or value in ('.', '..'):
        raise BaoError('invalid_state_name')
    return value


def _open_directory(path: str | Path) -> int:
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise BaoError('absolute_private_directory_required')
    fd = None
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for part in path.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700 or info.st_nlink == 0:
            raise BaoError('private_state_directory_requires_0700')
        result, fd = fd, None
        return result
    except OSError:
        raise BaoError('private_state_directory_open_failed') from None
    finally:
        if fd is not None:
            os.close(fd)


class StateDirectory:
    def __init__(self, path: str | Path, *, writer: bool = False):
        self.path = Path(path)
        self.fd = _open_directory(self.path)
        self.lock_fd = None
        try:
            if writer:
                self.lock_fd = os.open('.agent.lock', os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                                       0o600, dir_fd=self.fd)
                self._file_ok(os.fstat(self.lock_fd))
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.fsync(self.fd)
        except (OSError, BaoError):
            self.close()
            raise BaoError('state_writer_fenced') from None

    def _file_ok(self, info):
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise BaoError('state_file_requires_single_private_regular_file')

    def check(self):
        current = _open_directory(self.path)
        try:
            a, b = os.fstat(self.fd), os.fstat(current)
            if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                raise BaoError('state_directory_replaced')
            if self.lock_fd is not None:
                a = os.fstat(self.lock_fd)
                b = os.stat('.agent.lock', dir_fd=self.fd, follow_symlinks=False)
                self._file_ok(a)
                if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                    raise BaoError('state_writer_lock_replaced')
        except OSError:
            raise BaoError('state_directory_integrity_failed') from None
        finally:
            os.close(current)

    def read(self, name: str, *, optional: bool = False) -> bytes | None:
        self.check()
        try:
            fd = os.open(_name(name), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
            with os.fdopen(fd, 'rb') as f:
                self._file_ok(os.fstat(f.fileno()))
                value = f.read(MAX_STATE + 1)
                if len(value) > MAX_STATE:
                    raise BaoError('state_file_exceeds_bound')
                return value
        except FileNotFoundError:
            if optional:
                return None
            raise BaoError('state_file_missing') from None
        except OSError:
            raise BaoError('state_file_read_failed') from None

    def write(self, name: str, raw: bytes):
        if self.lock_fd is None:
            raise BaoError('state_writer_required')
        self.check()
        _name(name)
        if not isinstance(raw, bytes) or len(raw) > MAX_STATE:
            raise BaoError('state_publication_exceeds_bound')
        temporary = '.state-' + secrets.token_hex(16)
        try:
            try:
                self._file_ok(os.stat(name, dir_fd=self.fd, follow_symlinks=False))
            except FileNotFoundError:
                pass
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=self.fd)
            with os.fdopen(fd, 'wb') as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            self.check()
            os.rename(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        except OSError:
            raise BaoError('state_publication_unknown') from None
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def remove(self, name: str):
        if self.lock_fd is None:
            raise BaoError('state_writer_required')
        self.check()
        try:
            self._file_ok(os.stat(_name(name), dir_fd=self.fd, follow_symlinks=False))
            os.unlink(name, dir_fd=self.fd)
            os.fsync(self.fd)
        except FileNotFoundError:
            pass
        except OSError:
            raise BaoError('state_removal_unknown') from None

    def json(self, name: str, *, optional=False):
        raw = self.read(name, optional=optional)
        return None if raw is None else decode_json(raw)

    def publish(self, name: str, value):
        self.write(name, canonical(value) + b'\n')

    def close(self):
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def token_snapshot(directory: StateDirectory, now: float, expected_binding: str) -> tuple[str, dict]:
    """Read two identical metadata generations around the secret. Never use a
    partly published, expired, clock-rollback or differently configured token.
    The server still performs authoritative token/identity revocation checks.
    """
    before = directory.read('state.json')
    state = decode_json(before)
    if (not isinstance(state, dict) or type(state.get('schema')) is not int or state.get('schema') != 1 or state.get('phase') != 'ready'
            or state.get('binding') != expected_binding):
        raise BaoError('agent_not_ready')
    if (type(state.get('observed_wall')) not in (int, float)
            or type(state.get('expires_at')) not in (int, float)
            or not state['observed_wall'] <= now < state['expires_at']):
        raise BaoError('agent_expired_or_clock_regressed')
    raw = directory.read('token')
    if hashlib.sha256(raw).hexdigest() != state.get('token_sha256') or directory.read('state.json') != before:
        raise BaoError('agent_snapshot_changed')
    try:
        token = raw.decode('ascii').strip()
    except UnicodeError:
        raise BaoError('agent_token_invalid') from None
    if not token or len(token) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise BaoError('agent_token_invalid')
    return token, state


def read_trusted_ca(path: str) -> bytes:
    """Bounded descriptor read of a non-writable trust root. Pass these very
    bytes into TLS so a concurrent pathname replacement cannot swap the root.
    Public certificates need not be secret, but untrusted users must not write.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or info.st_mode & 0o022 or not 0 < info.st_size <= 1024 * 1024):
                raise BaoError('trust_root_requires_bounded_nonwritable_regular_file')
            raw = handle.read(1024 * 1024 + 1)
            if not 0 < len(raw) <= 1024 * 1024:
                raise BaoError('trust_root_size_limit')
            return raw
    except OSError:
        raise BaoError('trust_root_open_failed') from None
