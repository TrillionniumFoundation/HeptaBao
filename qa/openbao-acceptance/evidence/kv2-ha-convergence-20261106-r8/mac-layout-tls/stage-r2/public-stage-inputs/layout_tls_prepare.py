"""One create-only Mac layout/TLS preparation; never starts or initializes Bao.

This is an unexecuted implementation proposal. The entry point requires a
separately staged, exactly pinned input set and an explicit new Runtime request.
Private key bytes and their hashes never enter the public result or stdout.
Failures preserve every created object; neither retry nor cleanup deletion is
implemented. The normal binaries are copied, never executed by this module.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import importlib.metadata
import ipaddress
import json
import os
from pathlib import Path
import platform
import signal
import stat
import sys
import time
ENTRY = time.monotonic()
import types
from typing import Any

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
PRODUCTION = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1')
CURRENT_BASE = Path('/Users/qianqi/heptabao-formal-kv2-current-20261106-r1')
SERVICE = PRODUCTION / 'formal-kv2-current-20261106-r1'
AUTHORITY = CURRENT_BASE / 'service-authority-current-20261106-r1'
INPUTS = ROOT / 'control/formal-kv2-layout-tls-inputs-r2'
OUTPUT = ROOT / 'control/formal-kv2-layout-tls-prepare-r1'
VENV = ROOT / 'control/formal-kv2-python-env-50-0-2-r3/venv'
HOMEBREW_PYTHON = '/opt/homebrew/bin/python3'
UID = 501
GID = 20
WORK_SECONDS = 110
RUNTIME_SECONDS = 120
PYTHON_PIN = (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13')
VENV_CONFIG_PIN = (424, 'b6229612749d7d4ba76ba83f0b65c4b80ebd88dfa82eac845d1e65dd1ef83851')
RENDERER_PIN = (6288, '98cd7196e9306b095ca3d25d41f9cb712767e17ed671b5560f02be21c6e4ef1b')
SOURCE_COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
SOURCE_TREE = 'f08493a23f8ea0637073651231865ea9607b790e'
ARTIFACTS = {
    'server': ('heptabao-server', 92359328, '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'),
    'seed': ('heptabao-seed', 86355760, '203c7af52c0f9aa4ca71e591c1428acac9382f3c4105036a494631b0e1cae8e7'),
}
GATES = {
    'mac107-result.public.json': (181226, '90753d3b4f9b966c43d3e29919239f8d9aa879616c821a3d9ce0b6aa854054d6'),
    'mac107-runtime-terminal.original.json': (734, 'f8e6a055c1f68eb63094964f7623155de44202a70bfb6da36fa8fc7eb09f821c'),
    'environment-result.public.json': (3886, 'fabe693cfc1764f4686abaff7a5425ea0e5067c2bd036fa26e22fec7dfd6e1bb'),
    'environment-runtime-terminal.original.json': (731, 'b64376669e1cf91017a374010f353187db2fa17950c7719ad783bb2a5b884c6f'),
    'readback-result.public.json': (10944, 'f0db2d9807b73fa7723b1030ddc9c4d70dd7fbb077855cafe560988d0dfff397'),
    'readback-runtime-terminal.original.json': (731, 'b2f396467eed32d27d71a3cf13de64341152f4bf980cae4e6d738d4a81a8fd51'),
    'service-preflight-result.public.json': (9165, '0f8cd353190687433ea915a361f83e687db942d9ff3d6df638eb2dc17ae3b539'),
    'service-preflight-runtime-terminal.original.json': (731, 'cf67c020d26cc2d7d3ee8892c00b1f2e03885dff8369afeeb0206dbbaa15db0d'),
}
STABLE_DIRECTORY_FIELDS = ('dev', 'inode', 'uid', 'gid', 'mode', 'kind')
SERVICE_DIRS = ('runtime', 'config', 'manager', 'data', 'audit', 'logs', 'tls')
AUTHORITY_DIRS = ('tls', 'issuer', 'root', 'bootstrap', 'share-1', 'pending-share-2', 'pending-share-3', 'preparation', 'manager-admissions')


class Rejected(RuntimeError):
    pass


class Interrupted(BaseException):
    pass


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Rejected(code)


def encoded(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode('utf-8')


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        need(key not in result, 'duplicate_json_field')
        result[key] = value
    return result


def parse(raw: bytes) -> Any:
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda _v: (_ for _ in ()).throw(Rejected('nonfinite_json')))


def identity(s: os.stat_result) -> dict[str, Any]:
    return {
        'dev': s.st_dev, 'inode': s.st_ino, 'uid': s.st_uid, 'gid': s.st_gid,
        'mode': stat.S_IMODE(s.st_mode), 'nlink': s.st_nlink, 'bytes': s.st_size,
        'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns,
        'file_type': stat.S_IFMT(s.st_mode),
        'kind': 'directory' if stat.S_ISDIR(s.st_mode) else 'file' if stat.S_ISREG(s.st_mode) else 'other',
    }


def stable(i: dict[str, Any]) -> dict[str, Any]:
    return {k: i[k] for k in STABLE_DIRECTORY_FIELDS}


def root_binding(path: Path, current: dict[str, Any]) -> dict[str, Any]:
    return {'path': str(path), **{k: current[k] for k in ('dev', 'inode', 'uid', 'gid', 'mode')}}


def file_binding(i: dict[str, Any]) -> dict[str, Any]:
    return {k: i[k] for k in ('dev', 'inode', 'uid', 'gid', 'mode', 'nlink', 'bytes', 'mtime_ns', 'ctime_ns', 'file_type')}


def canonical(path: Path) -> None:
    need(path.is_absolute() and str(path.resolve(strict=True)) == str(path), 'canonical_existing_path_required')


def leaf(name: str) -> None:
    need(type(name) is str and name not in ('', '.', '..') and '/' not in name and '\x00' not in name,
         'single_path_component_required')


class Clock:
    """The one original entry clock; pending signals never become a PASS."""
    def __init__(self, entry: float):
        self.entry = entry
        self.end = entry + WORK_SECONDS
        self.protected = 0
        self.signal_number: int | None = None
        self.deadline_fired = False
        self.old_handlers: dict[int, Any] = {}
        self.timer_owned = False

    def check(self) -> None:
        if self.signal_number is not None or self.deadline_fired or time.monotonic() >= self.end:
            raise Interrupted()

    def interrupt(self, signum: int, _frame: Any) -> None:
        if self.signal_number is None:
            self.signal_number = signum
        if signum == signal.SIGALRM:
            self.deadline_fired = True
        if not self.protected:
            raise Interrupted()

    @contextlib.contextmanager
    def critical(self):
        self.protected += 1
        try:
            yield
        finally:
            self.protected -= 1

    def start(self) -> None:
        need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'existing_timer_refused')
        for signum in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            self.old_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, self.interrupt)
        with self.critical():
            self.timer_owned = True
            signal.setitimer(signal.ITIMER_REAL, max(0.000001, self.end - time.monotonic()))
        self.check()

    def finish(self) -> None:
        if self.timer_owned:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            self.timer_owned = False
        for signum, old in self.old_handlers.items():
            signal.signal(signum, old)


class Directory:
    def __init__(self, path: Path, fd: int, first: dict[str, Any] | None, role: str):
        self.path, self.fd, self.first, self.role = path, fd, first, role
        self.closed = False


class Filesystem:
    """Held parent FDs, create-only leaves, full file identity and readback."""
    def __init__(self, clock: Clock, uid: int = UID, gid: int = GID):
        self.clock, self.uid, self.gid = clock, uid, gid
        self.directories: list[Directory] = []
        self.files: dict[str, dict[str, Any]] = {}
        self.sources: list[dict[str, Any]] = []
        self.created_directory_roles: list[str] = []
        self.file_opened = 0
        self.file_closed = 0
        self.file_fds: dict[int, dict[str, Any] | None] = {}

    def directory(self, path: Path, role: str, expected: dict[str, Any] | None = None) -> Directory:
        self.clock.check()
        canonical(path)
        before = identity(path.lstat())
        need(before['kind'] == 'directory' and before['uid'] == self.uid and before['gid'] == self.gid
             and before['mode'] == 0o700, 'private_directory_identity')
        if expected is not None:
            need(stable(before) == stable(expected), 'prior_directory_identity_changed')
        with self.clock.critical():
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            item = Directory(path, fd, None, role)
            self.directories.append(item)
            need(identity(os.fstat(fd)) == before, 'directory_open_identity_changed')
            item.first = before
        self.verify_directory(item)
        self.clock.check()
        return item

    def verify_directory(self, item: Directory) -> None:
        need(not item.closed, 'closed_directory_handle')
        need(item.first is not None, 'directory_birth_identity_not_verified')
        canonical(item.path)
        need(stable(identity(item.path.lstat())) == stable(item.first)
             == stable(identity(os.fstat(item.fd))), 'directory_path_or_handle_changed')

    def absent(self, parent: Directory, name: str) -> None:
        leaf(name)
        self.verify_directory(parent)
        try:
            os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise Rejected('create_only_target_already_exists')

    def mkdir(self, parent: Directory, name: str, role: str) -> Directory:
        self.clock.check()
        self.absent(parent, name)
        with self.clock.critical():
            os.mkdir(name, 0o700, dir_fd=parent.fd)
            self.created_directory_roles.append(role)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent.fd)
            item = Directory(parent.path / name, fd, None, role)
            self.directories.append(item)
            item.first = identity(os.fstat(fd))
            os.fsync(parent.fd)
        need(item.first['uid'] == self.uid and item.first['gid'] == self.gid
             and item.first['mode'] == 0o700 and item.first['kind'] == 'directory', 'created_directory_identity')
        self.verify_directory(parent)
        self.verify_directory(item)
        self.clock.check()
        return item

    def _open_file(self, path: Path, mode: int, *, dir_fd: int | None = None) -> int:
        with self.clock.critical():
            fd = os.open(path, mode | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            self.file_opened += 1
            self.file_fds[fd] = None
            self.file_fds[fd] = identity(os.fstat(fd))
        return fd

    def _close_file(self, fd: int) -> None:
        with self.clock.critical():
            need(fd in self.file_fds, 'unknown_file_handle_close_refused')
            old = self.file_fds[fd]
            if old is not None:
                now = identity(os.fstat(fd))
                need(stable(old) == stable(now), 'original_file_handle_identity_changed')
            # An errored close is an unknown retirement, never permission to
            # issue another close against a possibly reused numeric descriptor.
            del self.file_fds[fd]
            os.close(fd)
            self.file_closed += 1

    def _regular(self, item: dict[str, Any], *, executable: bool = False,
                 trusted_system_binary: bool = False) -> None:
        owners = (0, self.uid) if trusted_system_binary else (self.uid,)
        need(item['kind'] == 'file' and item['nlink'] == 1 and item['uid'] in owners
             and not item['mode'] & 0o022, 'regular_owned_single_link_file_required')
        need(item['mode'] in ((0o700, 0o755) if executable else (0o600, 0o644)), 'source_file_mode_rejected')

    def read(self, path: Path, expected: tuple[int, str], *, executable: bool = False,
             retain_bytes: bool = True, trusted_system_binary: bool = False) -> tuple[bytes, dict[str, Any]]:
        self.clock.check()
        canonical(path)
        initial = identity(path.lstat())
        self._regular(initial, executable=executable, trusted_system_binary=trusted_system_binary)
        need(initial['bytes'] == expected[0], 'fixed_file_length_mismatch')
        fd = self._open_file(path, os.O_RDONLY)
        chunks: list[bytes] = []
        h = hashlib.sha256()
        total = 0
        try:
            need(identity(os.fstat(fd)) == initial, 'fixed_file_open_identity_changed')
            while True:
                self.clock.check()
                data = os.read(fd, min(1024 * 1024, expected[0] + 1 - total))
                if not data:
                    break
                total += len(data)
                need(total <= expected[0], 'fixed_file_grew')
                h.update(data)
                if retain_bytes:
                    chunks.append(data)
            need(total == expected[0] and h.hexdigest() == expected[1], 'fixed_file_hash_mismatch')
            need(identity(os.fstat(fd)) == initial == identity(path.lstat()), 'fixed_file_changed_during_read')
        finally:
            self._close_file(fd)
        pin = {'path': str(path), 'bytes': total, 'sha256': h.hexdigest(), 'identity': initial}
        return b''.join(chunks), pin

    def put(self, parent: Directory, name: str, data: bytes, role: str, *, mode: int = 0o600) -> dict[str, Any]:
        self.clock.check()
        need(type(data) is bytes and mode in (0o600, 0o700), 'create_file_input')
        self.absent(parent, name)
        fd: int | None = None
        try:
            with self.clock.critical():
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             mode, dir_fd=parent.fd)
                self.file_opened += 1
                self.file_fds[fd] = None
                self.file_fds[fd] = identity(os.fstat(fd))
            offset = 0
            while offset < len(data):
                self.clock.check()
                wrote = os.write(fd, memoryview(data)[offset:offset + 1024 * 1024])
                need(wrote > 0, 'short_write_without_progress')
                offset += wrote
            os.fsync(fd)
            first = identity(os.fstat(fd))
            need(first['mode'] == mode and first['uid'] == self.uid and first['gid'] == self.gid
                 and first['nlink'] == 1 and first['bytes'] == len(data) and first['kind'] == 'file', 'created_file_identity')
            os.fsync(parent.fd)
        finally:
            if fd is not None:
                self._close_file(fd)
        path = parent.path / name
        raw, pin = self.read(path, (len(data), hashlib.sha256(data).hexdigest()), executable=mode == 0o700)
        need(raw == data and pin['identity'] == first, 'created_file_readback_changed')
        self.verify_directory(parent)
        self.files[role] = pin
        return pin

    def copy(self, source: Path, parent: Directory, name: str, role: str,
             expected: tuple[int, str]) -> dict[str, Any]:
        """Streaming original-source copy, then full destination readback."""
        self.clock.check()
        canonical(source)
        initial = identity(source.lstat())
        self._regular(initial, executable=True)
        need(initial['bytes'] == expected[0], 'artifact_length_mismatch')
        self.absent(parent, name)
        src: int | None = None
        dst: int | None = None
        h = hashlib.sha256()
        total = 0
        try:
            src = self._open_file(source, os.O_RDONLY)
            need(identity(os.fstat(src)) == initial, 'artifact_source_changed_before_copy')
            with self.clock.critical():
                dst = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o700, dir_fd=parent.fd)
                self.file_opened += 1
                self.file_fds[dst] = None
                self.file_fds[dst] = identity(os.fstat(dst))
            while True:
                self.clock.check()
                chunk = os.read(src, min(1024 * 1024, expected[0] + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                need(total <= expected[0], 'artifact_source_grew')
                h.update(chunk)
                offset = 0
                while offset < len(chunk):
                    self.clock.check()
                    wrote = os.write(dst, memoryview(chunk)[offset:])
                    need(wrote > 0, 'artifact_write_without_progress')
                    offset += wrote
            need(total == expected[0] and h.hexdigest() == expected[1], 'artifact_source_hash_mismatch')
            need(identity(os.fstat(src)) == initial == identity(source.lstat()), 'artifact_source_changed_during_copy')
            os.fsync(dst)
            created = identity(os.fstat(dst))
            need(created['mode'] == 0o700 and created['uid'] == self.uid and created['gid'] == self.gid
                 and created['nlink'] == 1 and created['bytes'] == total and created['kind'] == 'file', 'copied_artifact_identity')
            need((created['dev'], created['inode']) != (initial['dev'], initial['inode']), 'artifact_not_independent_copy')
            os.fsync(parent.fd)
        finally:
            try:
                if dst is not None:
                    self._close_file(dst)
            finally:
                if src is not None:
                    self._close_file(src)
        _, pin = self.read(parent.path / name, expected, executable=True, retain_bytes=False)
        need(pin['identity'] == created, 'copied_artifact_readback_identity')
        self.verify_directory(parent)
        self.files[role] = pin
        self.sources.append({'path': str(source), 'identity': initial, 'bytes': expected[0], 'sha256': expected[1]})
        return pin

    def verify_all(self) -> None:
        for item in self.directories:
            self.clock.check()
            self.verify_directory(item)
        for pin in [*self.sources, *self.files.values()]:
            self.clock.check()
            p = Path(pin['path'])
            canonical(p)
            need(identity(p.lstat()) == pin['identity'], 'retained_file_identity_changed')
        need(self.file_opened == self.file_closed and not self.file_fds, 'file_handles_not_retired')

    def close(self) -> list[str]:
        errors: list[str] = []
        with self.clock.critical():
            for fd in list(self.file_fds):
                try:
                    self._close_file(fd)
                except BaseException:
                    errors.append('original_file_handle_cleanup_failed')
            for item in reversed(self.directories):
                if not item.closed:
                    try:
                        if item.first is not None:
                            self.verify_directory(item)
                    except BaseException:
                        errors.append('final_directory_identity_changed')
                    try:
                        os.close(item.fd)
                        item.closed = True
                    except OSError:
                        errors.append('owned_directory_close_failed')
        return errors


def generate_tls(now: dt.datetime) -> tuple[dict[str, bytes], dict[str, Any]]:
    """New local issuer and leaf. No existing key is read or reused."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    need(now.tzinfo == dt.timezone.utc and now.microsecond == 0, 'utc_second_timestamp_required')
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'HeptaBao Mac Current KV2 CA')])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    before = now - dt.timedelta(minutes=5)
    ca_end = now + dt.timedelta(days=3650)
    leaf_end = now + dt.timedelta(days=365)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(before).not_valid_after(ca_end)
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(before).not_valid_after(leaf_end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
                                                        x509.DNSName('localhost')]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca.public_key().verify(ca.signature, ca.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    need(cert.public_key().public_numbers() == leaf_key.public_key().public_numbers(), 'tls_leaf_key_pair_mismatch')
    need(ca.public_key().public_numbers() != cert.public_key().public_numbers(), 'tls_issuer_and_server_keys_not_distinct')
    pem = serialization.Encoding.PEM
    data = {
        'ca_certificate': ca.public_bytes(pem),
        'server_certificate': cert.public_bytes(pem),
        'ca_private_key': ca_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        'server_private_key': leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    }
    public = {
        'algorithm': 'ECDSA_P256_SHA256', 'ca_lifetime_days_after_generation': 3650,
        'leaf_lifetime_days_after_generation': 365, 'not_before_skew_seconds': 300,
        'generated_at_utc': now.isoformat(), 'not_before_utc': before.isoformat(),
        'ca_not_after_utc': ca_end.isoformat(), 'leaf_not_after_utc': leaf_end.isoformat(),
        'ca_path_length': 0, 'leaf_eku': ['serverAuth'],
        'ip_sans': ['127.0.0.1'], 'dns_sans': ['localhost'],
        'ca_self_signature_verified': True, 'leaf_signature_and_key_pair_verified': True,
        'separate_issuer_and_server_keys': True, 'ca_crl_or_ocsp_service_available': False,
        'automatic_certificate_rotation_implemented': False,
        'private_key_encryption_at_rest_claimed': False,
        'remote_tls_endpoint_verified': False,
    }
    return data, public


def fixed_inputs() -> dict[str, Any]:
    return {
        'schema': 'heptabao.normal-kv2-layout-tls-inputs.v1',
        'manager_domain': 'gui/501',
        'budgets': {'work': WORK_SECONDS, 'runtime': RUNTIME_SECONDS, 'cleanup_reserve': 10},
        'renderer': {'bytes': RENDERER_PIN[0], 'sha256': RENDERER_PIN[1]},
        'public_gates': {name: {'bytes': pin[0], 'sha256': pin[1]} for name, pin in GATES.items()},
        'private_key_root': str(AUTHORITY),
        'service_root': str(SERVICE),
        'tls': {'curve': 'P256', 'digest': 'SHA256', 'ca_days': 3650, 'leaf_days': 365,
                'not_before_skew_seconds': 300, 'ip_sans': ['127.0.0.1'], 'dns_sans': ['localhost'],
                'leaf_eku': ['serverAuth']},
        'service_start_authorized_by_this_step': False,
    }


def layout_input() -> dict[str, Any]:
    return {
        'schema': 'heptabao.normal-kv2-bootstrap-layout.v1', 'service_root': str(SERVICE),
        'key_root': str(AUTHORITY), 'manager_domain': 'gui/501', 'manager_uid': UID,
        'manager_label': 'org.heptabao.kv2', 'python_executable': HOMEBREW_PYTHON,
        'listen_address': '127.0.0.1', 'listen_port': 18240,
    }


def execute(fs: Filesystem, args: argparse.Namespace, public: dict[str, Any]) -> None:
    need(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'fixed_darwin_arm64_required')
    need(os.geteuid() == UID and os.getegid() == GID, 'fixed_operator_identity_required')
    need(sys.version_info[:3] == (3, 14, 3) and sys.flags.isolated == 1 and sys.dont_write_bytecode,
         'fixed_isolated_python_required')
    need(Path(sys.prefix) == VENV and Path(sys.executable) == VENV / 'bin/python3', 'qualified_venv_required')
    need(importlib.metadata.version('cryptography') == '50.0.2', 'qualified_crypto_version_required')
    need(Path(args.inputs) == INPUTS / 'fixed-inputs.public.json', 'fixed_inputs_path_required')
    need(len(args.inputs_sha256) == 64 and len(args.code_sha256) == 64, 'explicit_source_pins_required')
    code = Path(__file__).resolve(strict=True)
    raw, codepin = fs.read(code, (code.stat().st_size, args.code_sha256))
    del raw
    python = Path(sys.executable).resolve(strict=True)
    # The interpreter is an existing trusted system installation, not a
    # user-owned source artifact. Keep its real original FD in the same
    # registry while allowing only root or the fixed actual operator owner.
    _, pythonpin = fs.read(python, PYTHON_PIN, executable=True, trusted_system_binary=True)
    _, venvpin = fs.read(VENV / 'pyvenv.cfg', VENV_CONFIG_PIN)
    input_dir = fs.directory(INPUTS, 'fixed_inputs')
    raw, inputpin = fs.read(Path(args.inputs), (len(encoded(fixed_inputs())), args.inputs_sha256))
    need(parse(raw) == fixed_inputs(), 'exact_fixed_inputs_required')
    public['fixed_input_and_source_pins_verified'] = True
    gates: dict[str, Any] = {}
    for name, pin in GATES.items():
        raw, readpin = fs.read(INPUTS / name, pin)
        gates[name] = parse(raw)
        fs.sources.append(readpin)
    preflight = gates['service-preflight-result.public.json']
    need(preflight['point_in_time_user_manager_preflight_clear'] is True, 'prior_preflight_not_clear')
    need(preflight['metadata']['proposed_new_native_root'] == {'exists': False}, 'prior_candidate_root_not_absent')
    need(gates['readback-result.public.json']['status'] == 'passed', 'prior_readback_not_passed')
    need(gates['mac107-result.public.json']['status'] == 'passed', 'prior_normal_build_not_passed')
    renderer_raw, renderer_pin = fs.read(INPUTS / 'bootstrap_layout.py', RENDERER_PIN)
    fs.sources.extend([codepin, pythonpin, venvpin, inputpin, renderer_pin])
    renderer = types.ModuleType('_frozen_bootstrap_layout')
    exec(compile(renderer_raw, 'bootstrap_layout.py', 'exec'), renderer.__dict__)
    layout = layout_input()
    rendered = renderer.render(layout)
    need(rendered['runtime_admission_performed'] is False, 'renderer_cannot_grant_admission')
    production = fs.directory(PRODUCTION, 'existing_production_parent', preflight['metadata']['existing_production_root'])
    current = fs.directory(CURRENT_BASE, 'existing_internal_parent', preflight['metadata']['current_internal_base'])
    control = fs.directory(ROOT / 'control', 'control_parent')
    need(production.first['dev'] == 16777244 and current.first['dev'] == 16777233
         and production.first['dev'] != current.first['dev'], 'expected_distinct_volume_devices_required')
    fs.absent(production, SERVICE.name)
    fs.absent(current, AUTHORITY.name)
    fs.absent(control, OUTPUT.name)
    # Filesystem capacity is a bounded prerequisite, not a performance claim.
    t5_free = os.fstatvfs(production.fd).f_bavail * os.fstatvfs(production.fd).f_frsize
    internal_free = os.fstatvfs(current.fd).f_bavail * os.fstatvfs(current.fd).f_frsize
    need(t5_free >= sum(p[1] for p in ARTIFACTS.values()) + 32 * 1024 * 1024
         and internal_free >= 16 * 1024 * 1024, 'preparation_capacity_insufficient')
    public['capacity_before'] = {'external_available_bytes': t5_free, 'internal_available_bytes': internal_free}
    output = fs.mkdir(control, OUTPUT.name, 'output')
    service = fs.mkdir(production, SERVICE.name, 'service')
    authority = fs.mkdir(current, AUTHORITY.name, 'key_authority')
    sd = {name: fs.mkdir(service, name, 'service_' + name) for name in SERVICE_DIRS}
    kd = {name: fs.mkdir(authority, name, 'authority_' + name) for name in AUTHORITY_DIRS}
    public['created_layout_directories'] = len(fs.created_directory_roles)
    for role, (basename, size, digest) in ARTIFACTS.items():
        source = ROOT / 'build-test-4bde9-r1/artifacts' / basename
        fs.copy(source, sd['runtime'], basename, role, (size, digest))
    fs.clock.check()
    tls_data, tls_public = generate_tls(dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
    fs.clock.check()
    fs.put(kd['issuer'], 'ca.key', tls_data['ca_private_key'], 'ca_private_key')
    fs.put(kd['tls'], 'server.key', tls_data['server_private_key'], 'server_private_key')
    fs.put(sd['tls'], 'ca.crt', tls_data['ca_certificate'], 'ca_certificate')
    fs.put(sd['tls'], 'server.crt', tls_data['server_certificate'], 'server_certificate')
    del tls_data
    fs.put(sd['config'], 'server.json', renderer.config_bytes(rendered), 'server_config')
    fs.put(sd['manager'], 'org.heptabao.kv2.plist', renderer.plist_bytes(rendered), 'uninstalled_plist')
    # No guard, binding, root token, nonce or share exists at this boundary.
    for name in ('launch_guard.py', 'launch-binding.private.json'):
        fs.absent(sd['manager'], name)
    for name in ('root', 'bootstrap', 'share-1', 'pending-share-2', 'pending-share-3', 'manager-admissions'):
        need(os.listdir(kd[name].fd) == [], 'authority_reserved_directory_not_empty')
    need(os.listdir(sd['data'].fd) == [], 'preinitialization_data_directory_not_empty')
    fs.verify_all()
    private = {
        'schema': 'heptabao.normal-kv2-layout-tls.private.v1', 'status': 'prepared_not_started',
        'roots': {'service': root_binding(SERVICE, identity(os.fstat(service.fd))),
                  'key': root_binding(AUTHORITY, identity(os.fstat(authority.fd)))},
        'directories': {d.role: root_binding(d.path, identity(os.fstat(d.fd)))
                        for d in fs.directories},
        'files': {role: {**pin, 'identity': file_binding(pin['identity'])} for role, pin in fs.files.items()},
        'layout': layout, 'rendered': rendered,
        'source_bindings': {'commit': SOURCE_COMMIT, 'tree': SOURCE_TREE, 'source': codepin,
                            'fixed_inputs': inputpin, 'renderer': renderer_pin, 'venv': venvpin, 'python': pythonpin,
                            'read_only_inputs': fs.sources.copy()},
        'initial_empty_data_binding': {'identity': root_binding(sd['data'].path, identity(os.fstat(sd['data'].fd))),
                                       'scope': 'before_init_only_not_a_permanent_initialized_inode'},
        'public_result_ref': str(OUTPUT / 'result.public.json'),
        'service_started': False, 'root_token_or_unseal_share_created': False,
        'initialization_nonce_created': False, 'cross_host_share_custody_verified': False,
        'formal_kv2_qualified': False,
    }
    privatepin = fs.put(kd['preparation'], 'layout-tls.private.json', encoded(private), 'preparation_private_record')
    fs.verify_all()
    public.update({
        'status': 'prepared_not_started', 'preparation_complete': True,
        'normal_product_commit': SOURCE_COMMIT, 'normal_product_tree': SOURCE_TREE,
        'copied_artifacts': {role: {'bytes': fs.files[role]['bytes'], 'sha256': fs.files[role]['sha256']}
                             for role in ARTIFACTS},
        'public_certificates': {role: {'bytes': fs.files[role]['bytes'], 'sha256': fs.files[role]['sha256']}
                                for role in ('ca_certificate', 'server_certificate')},
        'tls': tls_public,
        'private_record_identity': file_binding(privatepin['identity']),
        'private_record_content_hash_published': False,
        'created_file_count_before_public_receipt': len(fs.files),
        'initial_empty_data_observed': True,
        'original_sources_and_all_created_file_identities_unchanged': True,
        'directory_metadata_excludes_expected_child_count_and_time_changes': True,
        'prior_domain_preflight_is_point_in_time_only': True,
        'current_domain_or_listener_reobserved_by_preparation': False,
        'automatic_unseal_implemented': False,
        'all_key_roles_separate_directories': True,
        'issuer_and_server_keys_on_different_devices': False,
        'data_and_private_key_devices_differ': True,
        'whole_internal_device_loss_recoverable': False,
        'private_role_directory_count': len(AUTHORITY_DIRS),
    })
    public['elapsed_observation_before_receipt_publication_seconds'] = time.monotonic() - fs.clock.entry
    public['file_handles_opened_before_public_receipt'] = fs.file_opened
    public['file_handles_closed_before_public_receipt'] = fs.file_closed
    fs.clock.check()
    fs.put(output, 'result.public.json', encoded(public), 'public_result')
    fs.verify_all()


def main() -> int:
    entry = ENTRY
    parser = argparse.ArgumentParser()
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--code-sha256', required=True)
    args = parser.parse_args()
    clock = Clock(entry)
    fs = Filesystem(clock)
    public: dict[str, Any] = {
        'schema': 'heptabao.normal-kv2-layout-tls.public.v1', 'status': 'failed',
        'preparation_complete': False, 'primary_failure_code': None, 'cleanup_failure_codes': [],
        'runtime_seconds': RUNTIME_SECONDS, 'work_seconds': WORK_SECONDS,
        'cleanup_reserve_seconds': 10, 'deadline_renewed': False, 'automatic_retry': False,
        'service_started': False, 'product_executed': False, 'child_processes_created': 0,
        'launch_agents_configuration_written': False, 'bootstrap_or_bootout_called': False,
        'root_token_or_unseal_share_created': False, 'initialization_nonce_created': False,
        'old_key_or_credential_content_opened': False, 'business_source_opened': False,
        'provider_or_j3160_contacted': False, 'network_or_http_performed': False,
        'cross_host_share_custody_verified': False, 'formal_kv2_qualified': False,
        'ha_qualified': False, 'authbus_qualified': False, 'traffic_cutover_performed': False,
        'old_assets_removed': False, 'failed_objects_deleted': False,
        'current_product_ci_hold_resolved': False,
        'durable_completion_authority': 'original_runtime_terminal_and_final_stdout_with_120_second_cap',
    }
    old_umask = os.umask(0o077)
    try:
        clock.start()
        execute(fs, args, public)
    except Rejected as exc:
        public['primary_failure_code'] = str(exc)
    except Interrupted:
        public['primary_failure_code'] = 'deadline_or_signal_interrupted'
    except BaseException as exc:
        public['primary_failure_code'] = 'unexpected_' + type(exc).__name__
    finally:
        with clock.critical():
            public['cleanup_failure_codes'].extend(fs.close())
            if fs.file_opened != fs.file_closed:
                public['cleanup_failure_codes'].append('unretired_owned_file_handles')
            public['owned_directory_handles'] = len(fs.directories)
            public['owned_directory_handles_closed'] = sum(d.closed for d in fs.directories)
            public['owned_file_handles_opened'] = fs.file_opened
            public['owned_file_handles_closed'] = fs.file_closed
            # Retire our timer/handlers before taking the final sticky signal
            # snapshot. A signal during protected cleanup cannot be omitted by
            # an earlier successful observation. Native terminal is still the
            # authority for interruption after this final userspace boundary.
            clock.finish()
            os.umask(old_umask)
            public['deadline_fired'] = clock.deadline_fired
            public['interrupted_signal'] = clock.signal_number
            public['elapsed_final_observation_seconds'] = time.monotonic() - entry
            if clock.deadline_fired or clock.signal_number is not None or time.monotonic() >= clock.end:
                public['cleanup_failure_codes'].append('original_work_deadline_or_signal_not_clear')
            if public['primary_failure_code'] is not None or public['cleanup_failure_codes']:
                public['status'] = 'failed'
                public['preparation_complete'] = False
    print(json.dumps(public, sort_keys=True, allow_nan=False), flush=True)
    return 0 if public['status'] == 'prepared_not_started' else 1


if __name__ == '__main__':
    raise SystemExit(main())
