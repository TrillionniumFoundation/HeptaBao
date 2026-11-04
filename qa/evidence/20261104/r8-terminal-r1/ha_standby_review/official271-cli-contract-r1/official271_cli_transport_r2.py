#!/usr/bin/env python3
"""Observe the pinned OpenBao 2.7.1 snapshot CLI against owned TLS peers.

This is a client-contract observation, not a backup/restore qualification.
It never starts a Bao server and never submits a valid restore archive.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import threading
import time

BASE = Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
BINARY = BASE / 'official271-standby-oracle-control-r1/artifacts/bao'
BINARY_SHA = '535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea'
SOURCE_COMMIT = 'a5db72cef75c24b920ade02065b18dd8eb666bac'
ROOT = BASE / 'official271-cli-transport-live-r1'
PORTS = (48740, 48742)
HTTP_SECONDS = 15.0
WHOLE_SECONDS = 300.0
MAX_HEAD = 64 * 1024
MAX_BODY = 1024 * 1024
MAX_CAPTURE = 64 * 1024
MAX_CONNECTIONS = 4
INVALID = b'owned-invalid-snapshot'
ROUTE = '/v1/sys/storage/raft/snapshot'
OLD_FENCES = {
    'official271-standby-oracle-live-r1/result.public.json': 'd84a783d817ee7827496182b6f750a1cd995424e554b287f602fd9204f289975',
    'official271-standby-oracle-live-r1/boundary-assessment.public.json': '4588e9f3a8fff060d4ac7ea035f85b5bcf58cc9874e839d9797bc75023068391',
    'normal33-standby-oracle-live-r2/result.public.json': '12cdeb32dc89a7f0af5d1950a2c14a02581a8e98cefd3719c0673a0bd38e68d4',
    'normal33-standby-oracle-live-r3/result.public.json': 'f5a44d25e6f33e562b492e050242f36cc2744417a13a01db4beab1c0422ae590',
}
CASES = [
    ('S01_save_direct_200', 'save', 'archive', None, False),
    ('S02_save_307_then_200', 'save', 'redirect', 'archive', False),
    ('S03_restore_direct_400', 'restore', 'error400', None, False),
    ('S04_restore_direct_500', 'restore', 'error500', None, False),
    ('S05_restore_307_then_400', 'restore', 'redirect', 'error400', False),
    ('S06_save_redirects_disabled', 'save', 'redirect', 'archive', True),
    ('S07_restore_redirects_disabled', 'restore', 'redirect', 'error400', True),
    ('S08_save_redirect_untrusted_CA', 'save', 'redirect', 'bad_ca', False),
    ('S09_save_redirect_protocol_downgrade', 'save', 'downgrade', 'plain', False),
    ('S10_save_second_redirect_limit', 'save', 'redirect', 'redirect_back', False),
]
os.umask(0o077)


class Refused(Exception):
    pass


def digest(path: Path) -> str:
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def regular(path: Path) -> os.stat_result:
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
        raise Refused('regular_single_link_file_required')
    return s


def write_new(path: Path, value: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(value)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path: Path, value: object) -> None:
    write_new(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def process_identity(pid: int) -> dict | None:
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
        fields = raw[raw.rfind(')') + 2:].split()
        return {'pid': pid, 'state': fields[0], 'ppid': int(fields[1]),
                'pgid': int(fields[2]), 'start_ticks': int(fields[19]),
                'exe': os.readlink(f'/proc/{pid}/exe')}
    except (FileNotFoundError, ProcessLookupError):
        return None


def group_members(pgid: int) -> list[dict]:
    members = []
    for entry in Path('/proc').iterdir():
        if entry.name.isdecimal():
            try:
                identity = process_identity(int(entry.name))
            except PermissionError:
                continue
            if identity and identity['pgid'] == pgid:
                members.append(identity)
    return members


def stop_provisional(p: subprocess.Popen) -> dict:
    group_changed = False
    same_group = None
    if p.poll() is None:
        try:
            same_group = os.getpgid(p.pid) == p.pid
        except ProcessLookupError:
            pass
        group_changed = same_group is False
        try:
            if same_group:
                os.killpg(p.pid, signal.SIGTERM)
            else:
                p.terminate()
        except ProcessLookupError:
            pass
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if p.poll() is None:
                try:
                    same_group_now = os.getpgid(p.pid) == p.pid
                    group_changed = group_changed or not same_group_now
                    if same_group_now:
                        os.killpg(p.pid, signal.SIGKILL)
                    else:
                        p.kill()
                except ProcessLookupError:
                    pass
            p.wait(timeout=5)
    else:
        p.wait()
    remaining = group_members(p.pid)
    return {'pid': p.pid, 'start_ticks': None, 'wait_returncode': p.returncode,
            'identity_capture_completed': False, 'group_changed': group_changed,
            'group_verified_before_signal': same_group, 'remaining': remaining,
            'owned_stopped': p.returncode is not None and not group_changed and not remaining}


def stop_owned(p: subprocess.Popen, captured: dict) -> dict:
    current = process_identity(p.pid)
    if current and current['start_ticks'] != captured['start_ticks']:
        raise Refused('owned_process_identity_changed')
    if p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            current = process_identity(p.pid)
            if not current or current['start_ticks'] != captured['start_ticks']:
                raise Refused('owned_process_identity_lost_before_kill')
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=5)
    else:
        p.wait()
    remaining = group_members(p.pid)
    return {'pid': p.pid, 'start_ticks': captured['start_ticks'],
            'wait_returncode': p.returncode, 'remaining': remaining,
            'owned_stopped': not remaining}


def remaining(until: int) -> float:
    left = (until - time.monotonic_ns()) / 1e9
    if left <= 0:
        raise Refused('original_absolute_deadline_expired')
    return left


class ExactReader:
    def __init__(self, sock: socket.socket, until: int):
        self.sock, self.until = sock, until
        self.pending = bytearray()
        self.received = 0

    def fill(self) -> None:
        self.sock.settimeout(remaining(self.until))
        chunk = self.sock.recv(4096)
        if not chunk:
            raise EOFError('peer_eof')
        self.received += len(chunk)
        self.pending.extend(chunk)
        if self.received > MAX_HEAD + MAX_BODY + MAX_HEAD:
            raise Refused('request_wire_bound')

    def exact(self, count: int) -> bytes:
        if count < 0 or count > MAX_BODY:
            raise Refused('request_read_bound')
        while len(self.pending) < count:
            self.fill()
        value = bytes(self.pending[:count])
        del self.pending[:count]
        return value

    def line(self, limit: int = MAX_HEAD) -> bytes:
        while True:
            at = self.pending.find(b'\n')
            if at >= 0:
                if at + 1 > limit:
                    raise Refused('request_line_bound')
                value = bytes(self.pending[:at + 1])
                del self.pending[:at + 1]
                if not value.endswith(b'\r\n'):
                    raise Refused('request_line_requires_crlf')
                return value
            if len(self.pending) >= limit:
                raise Refused('request_line_bound')
            self.fill()


def read_request(reader: ExactReader, token: bytes, projection: dict) -> dict:
    line = reader.line()
    fields = line[:-2].split(b' ')
    if len(fields) != 3 or fields[0] not in (b'GET', b'POST') or fields[2] != b'HTTP/1.1':
        raise Refused('closed_http11_request_line_required')
    target = fields[1]
    if target not in (ROUTE.encode(), (ROUTE + '?second=1').encode()):
        raise Refused('closed_snapshot_route_required')
    headers: dict[bytes, list[bytes]] = {}
    head_bytes = len(line)
    while True:
        line = reader.line(MAX_HEAD - head_bytes)
        head_bytes += len(line)
        if line == b'\r\n':
            break
        if b':' not in line or line[:1] in (b' ', b'\t'):
            raise Refused('request_header_shape')
        key, value = line[:-2].split(b':', 1)
        if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
            raise Refused('request_header_name')
        headers.setdefault(key.lower(), []).append(value.strip(b' \t'))
    length, coding = headers.get(b'content-length', []), headers.get(b'transfer-encoding', [])
    if len(length) > 1 or len(coding) > 1 or (length and coding):
        raise Refused('request_ambiguous_framing')
    supplied = headers.get(b'x-vault-token', [])
    host = headers.get(b'host', [])
    host_class = next((str(i + 1) for i, port in enumerate(PORTS)
                       if host == [f'127.0.0.1:{port}'.encode()]), 'other')
    projection.update(method=fields[0].decode(), route='snapshot' if target == ROUTE.encode() else 'snapshot_second',
                      request_head_complete=True, head_bytes=head_bytes,
                      original_token_equal=len(supplied) == 1 and hmac.compare_digest(supplied[0], token),
                      token_header_count=len(supplied), host_header_origin=host_class)
    body = bytearray()
    def payload(count: int) -> None:
        # Retain an exact partial-body count even when the original framing
        # ends prematurely. The bytes themselves are never made public.
        while count:
            if not reader.pending:
                reader.fill()
            take = min(count, len(reader.pending))
            body.extend(reader.pending[:take])
            del reader.pending[:take]
            count -= take
    mode = 'none'
    chunks = 0
    try:
        if length:
            if not re.fullmatch(rb'[0-9]{1,7}', length[0]) or int(length[0]) > MAX_BODY:
                raise Refused('request_content_length')
            mode = 'content_length'
            payload(int(length[0]))
        elif coding:
            if coding != [b'chunked']:
                raise Refused('request_transfer_encoding')
            mode = 'chunked'
            framing_bytes = 0
            while True:
                size_line = reader.line()
                framing_bytes += len(size_line)
                number = size_line[:-2]
                if not re.fullmatch(rb'[0-9a-fA-F]{1,8}', number):
                    raise Refused('request_chunk_size')
                size = int(number, 16)
                if len(body) + size > MAX_BODY or framing_bytes > MAX_HEAD:
                    raise Refused('request_chunk_bound')
                if size == 0:
                    if reader.line() != b'\r\n':
                        raise Refused('request_unexpected_trailer')
                    break
                payload(size)
                if reader.exact(2) != b'\r\n':
                    raise Refused('request_chunk_delimiter')
                chunks += 1
        if reader.pending:
            raise Refused('request_unexpected_pipelined_bytes')
        projection['request_complete'] = True
        return projection
    finally:
        projection.update(framing=mode, chunks=chunks, body_bytes=len(body),
                          body_sha256=hashlib.sha256(body).hexdigest(),
                          body_equals_fixed_invalid=hmac.compare_digest(body, INVALID),
                          body_empty=not body, request_wire_bytes_received=reader.received)


def synthetic_archive() -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w|') as tar:
            for name, data in [('state.bin', b'synthetic-cli-shape-only'),
                               ('SHA256SUMS.sealed', b'synthetic-nonempty-sealed-member')]:
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode, entry.mtime = len(data), 0o600, 0
                tar.addfile(entry, io.BytesIO(data))
    return output.getvalue()


class Peer:
    def __init__(self, owner: 'Owner', case: dict, index: int, behavior: str | None, until: int):
        self.owner, self.case, self.index, self.behavior, self.until = owner, case, index, behavior, until
        self.stop = threading.Event()
        self.listener: socket.socket | None = None
        self.active: socket.socket | None = None
        self.events: list[dict] = []
        self.error_type: str | None = None
        self.accepts = 0
        self.closed = False
        self.close_errors: list[dict] = []
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        # Owner registers this object before any socket/thread is created.
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', PORTS[self.index]))
        self.listener.listen(4)
        self.listener.settimeout(min(0.1, remaining(self.until)))
        self.thread = threading.Thread(target=self.run, name='owned-cli-peer-' + str(self.index + 1), daemon=False)
        self.thread.start()

    def response(self) -> tuple[bytes, int]:
        body = b''
        status, extra = 307, b''
        if self.behavior == 'archive':
            status, body = 200, self.owner.archive
            extra = b'Content-Type: application/gzip\r\n'
        elif self.behavior in ('error400', 'error500', 'plain', 'bad_ca', None):
            status = 500 if self.behavior == 'error500' else 400
            body = b'{"errors":["controlled_invalid_snapshot_fixture"]}'
            extra = b'Content-Type: application/json\r\n'
        elif self.behavior in ('redirect', 'downgrade'):
            scheme = 'http' if self.behavior == 'downgrade' else 'https'
            extra = f'Location: {scheme}://127.0.0.1:{PORTS[1]}{ROUTE}\r\n'.encode()
        elif self.behavior == 'redirect_back':
            extra = f'Location: https://127.0.0.1:{PORTS[0]}{ROUTE}?second=1\r\n'.encode()
        else:
            raise Refused('closed_peer_behavior_required')
        reason = {200: 'OK', 307: 'Temporary Redirect', 400: 'Bad Request', 500: 'Internal Server Error'}[status]
        head = (f'HTTP/1.1 {status} {reason}\r\nContent-Length: {len(body)}\r\n'.encode()
                + extra + b'Connection: close\r\n\r\n')
        return head + body, status

    def run(self) -> None:
        try:
            while not self.stop.is_set():
                self.listener.settimeout(min(0.1, remaining(self.until)))
                try:
                    raw, _address = self.listener.accept()
                except socket.timeout:
                    continue
                self.active = raw
                self.accepts += 1
                if self.accepts > MAX_CONNECTIONS:
                    raw.close()
                    self.active = None
                    raise Refused('peer_connection_bound')
                event = {'connection': self.accepts, 'peer': self.index + 1,
                         'request_complete': False, 'response_write_complete': False,
                         'tls_complete': False, 'http_bytes_received': 0}
                self.events.append(event)
                reader = None
                try:
                    raw.settimeout(remaining(self.until))
                    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    if self.behavior != 'plain':
                        context = self.owner.bad_tls if self.behavior == 'bad_ca' else self.owner.good_tls
                        stream = context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
                        self.active = stream
                        stream.settimeout(remaining(self.until))
                        stream.do_handshake()
                        event.update(tls_complete=True, tls_version=stream.version(), alpn=stream.selected_alpn_protocol())
                    else:
                        stream = raw
                        event['plain_listener'] = True
                    reader = ExactReader(stream, self.until)
                    observed = read_request(reader, self.owner.token, event)
                    event.update(observed)
                    wire, status = self.response()
                    # One complete small response is offered; no deliberately
                    # incomplete HTTP fixture is used in this client matrix.
                    stream.settimeout(remaining(self.until))
                    stream.sendall(wire)
                    event.update(response_status=status, response_wire_bytes=len(wire),
                                 response_wire_sha256=hashlib.sha256(wire).hexdigest(),
                                 response_write_complete=True)
                except Exception as exc:
                    event['error_type'] = type(exc).__name__
                    event['error_phase'] = ('tls' if not event['tls_complete'] and self.behavior != 'plain'
                                            else 'response' if event['request_complete'] else 'request')
                    event['expected_bad_ca_handshake_refusal'] = (
                        self.behavior == 'bad_ca' and isinstance(exc, ssl.SSLError)
                        and not event['tls_complete'])
                finally:
                    if reader is not None:
                        event['http_bytes_received'] = reader.received
                    active, self.active = self.active, None
                    if active is not None:
                        active.close()
        except Exception as exc:
            if not self.stop.is_set():
                self.error_type = type(exc).__name__

    def close(self) -> dict:
        def failed(stage: str, exc: Exception) -> None:
            self.close_errors.append({'stage': stage, 'error_type': type(exc).__name__})
        try:
            self.stop.set()
        except Exception as exc:
            failed('stop_flag', exc)
        try:
            if self.listener is not None:
                self.listener.close()
        except Exception as exc:
            failed('listener_close', exc)
        active = self.active
        if active is not None:
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            except Exception as exc:
                failed('active_shutdown', exc)
            finally:
                try:
                    active.close()
                except Exception as exc:
                    failed('active_close', exc)
        try:
            if self.thread is not None and self.thread.ident is not None:
                self.thread.join(timeout=5)
        except Exception as exc:
            failed('thread_join', exc)
        thread_joined, listener_closed, active_closed = False, False, False
        try:
            thread_joined = self.thread is None or not self.thread.is_alive()
            listener_closed = self.listener is None or self.listener.fileno() == -1
            active_closed = active is None or active.fileno() == -1
        except Exception as exc:
            failed('closed_state_observation', exc)
        self.closed = thread_joined and listener_closed and active_closed and not self.close_errors
        return {'peer': self.index + 1, 'accepts': self.accepts,
                'thread_joined': thread_joined, 'listener_closed': listener_closed,
                'active_socket_closed': active_closed, 'cleanup_errors': list(self.close_errors),
                'owned_stopped': self.closed,
                'error_type': self.error_type, 'events': self.events}


class Owner:
    def __init__(self, prepared: dict):
        self.prepared = prepared
        self.created_root = False
        self.private = ROOT / 'private'
        self.children: list[tuple[subprocess.Popen, dict | None]] = []
        self.peers: list[Peer] = []
        self.completed_cases: list[dict] = []
        self.creating_child = False
        self.pending_signal: int | None = None
        self.started = time.monotonic_ns()
        self.until = self.started + int(WHOLE_SECONDS * 1e9)
        self.token = secrets.token_urlsafe(32).encode()
        self.archive = synthetic_archive()
        self.unknown = False

    def interrupted(self, signum, _frame) -> None:
        if self.creating_child:
            if self.pending_signal is None:
                self.pending_signal = signum
            return
        raise Refused('owner_signal_' + str(signum))

    def start_child(self, argv: list[str], *, until: int, **options) -> subprocess.Popen:
        # Only the main thread creates children. Defer its Python signal
        # exception until the returned Popen is registered provisionally.
        if self.creating_child:
            raise Refused('nested_owned_child_creation')
        self.creating_child = True
        try:
            remaining(until)
            child = subprocess.Popen(argv, **options)
            self.children.append((child, None))
        finally:
            self.creating_child = False
            pending, self.pending_signal = self.pending_signal, None
            if pending is not None:
                raise Refused('owner_signal_' + str(pending))
        identity = process_identity(child.pid)
        if identity is None or identity['pgid'] != child.pid:
            raise Refused('owned_child_identity_unavailable')
        self.children[-1] = (child, identity)
        actual = (Path('/proc') / str(child.pid) / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        if identity['exe'] != str(Path(argv[0]).resolve(strict=True)) or actual != [x.encode() for x in argv]:
            raise Refused('owned_child_executable_or_argv_changed')
        return child

    def close_peers(self, peers: list[Peer]) -> list[dict]:
        results = []
        for peer in peers:
            try:
                results.append(peer.close())
            except Exception as exc:
                peer.closed = False
                results.append({'peer': peer.index + 1, 'accepts': peer.accepts,
                                'thread_joined': False, 'listener_closed': False,
                                'owned_stopped': False, 'error_type': type(exc).__name__,
                                'cleanup_errors': [{'stage': 'peer_close', 'error_type': type(exc).__name__}],
                                'events': list(peer.events)})
        return results

    def run_private(self, argv: list[str], label: str, until: int, env: dict[str, str]) -> dict:
        stdout_path, stderr_path = self.private / (label + '.stdout'), self.private / (label + '.stderr')
        started = time.monotonic_ns()
        timed_out = False
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
            remaining(until)
            child = self.start_child(argv, until=until, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stdout,
                                     stderr=stderr, start_new_session=True, env=env)
            try:
                child.wait(timeout=remaining(until))
            except (subprocess.TimeoutExpired, Refused):
                timed_out = True
                current = process_identity(child.pid)
                captured = self.children[-1][1]
                if captured is None or (current and current['start_ticks'] != captured['start_ticks']):
                    raise Refused('owned_child_identity_changed_before_deadline_kill')
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
        survivors = group_members(child.pid)
        if stdout_path.stat().st_size > MAX_CAPTURE or stderr_path.stat().st_size > MAX_CAPTURE:
            raise Refused('private_cli_capture_bound')
        out, err = stdout_path.read_bytes(), stderr_path.read_bytes()
        return {'pid': child.pid, 'returncode': child.returncode, 'timed_out': timed_out,
                'direct_child_reaped': child.returncode is not None, 'remaining': survivors,
                'elapsed_ms': (time.monotonic_ns() - started) / 1e6,
                'stdout_bytes': len(out), 'stdout_sha256': hashlib.sha256(out).hexdigest(),
                'stderr_bytes': len(err), 'stderr_sha256': hashlib.sha256(err).hexdigest(),
                'error_class': classify_error(child.returncode, err)}

    def setup(self) -> None:
        ROOT.mkdir(mode=0o700)
        self.created_root = True
        self.private.mkdir(mode=0o700)
        (ROOT / 'cases').mkdir(mode=0o700)
        write_json(ROOT / 'prepared.public.json', self.prepared)
        write_new(self.private / 'synthetic-token', self.token)
        write_new(self.private / 'synthetic-archive-shape.bin', self.archive)
        commands = []
        for prefix in ('good', 'bad'):
            key, cert = self.private / (prefix + '.key'), self.private / (prefix + '.crt')
            commands.append((prefix, ['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                                       '-keyout', str(key), '-out', str(cert), '-days', '1',
                                       '-subj', '/CN=owned-cli-fixture-' + prefix,
                                       '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost']))
        for label, argv in commands:
            result = self.run_private(argv, 'openssl-' + label,
                                      min(self.until, time.monotonic_ns() + int(HTTP_SECONDS * 1e9)),
                                      {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
            write_json(ROOT / ('openssl-' + label + '.public.json'), result)
            if result['returncode'] != 0 or result['timed_out'] or result['remaining']:
                raise Refused('owned_tls_generation_failed')
        self.good_tls = self.tls_context('good')
        self.bad_tls = self.tls_context('bad')

    def tls_context(self, prefix: str) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        context.load_cert_chain(str(self.private / (prefix + '.crt')), str(self.private / (prefix + '.key')))
        return context

    def case(self, sequence: int, definition: tuple) -> None:
        label, command, behavior1, behavior2, disabled = definition
        directory = ROOT / 'cases' / label
        directory.mkdir(mode=0o700)
        input_path, output_path = self.private / (label + '.invalid'), self.private / (label + '.snapshot')
        if command == 'restore':
            write_new(input_path, INVALID)
        until = min(self.until, time.monotonic_ns() + int(HTTP_SECONDS * 1e9))
        intent = {'sequence': sequence, 'case': label, 'command': command, 'http_seconds': HTTP_SECONDS,
                  'deadline_monotonic_ns': until, 'intent_unix_ns': time.time_ns(),
                  'address': f'https://127.0.0.1:{PORTS[0]}', 'redirects_disabled': disabled,
                  'valid_restore_body': False, 'restore_input_bytes': len(INVALID) if command == 'restore' else 0,
                  'restore_input_sha256': hashlib.sha256(INVALID).hexdigest() if command == 'restore' else None,
                  'private_credential_source': 'fresh_synthetic_fixture_only',
                  'tls_skip_verify': False, 'inherited_environment': False,
                  'controller_retries': 0, 'http_body_and_token_values_public': False}
        write_json(directory / 'intent.public.json', intent)
        local_peers: list[Peer] = []
        process = None
        failure = None
        try:
            for index, behavior in enumerate((behavior1, behavior2)):
                peer = Peer(self, intent, index, behavior, until)
                self.peers.append(peer)
                local_peers.append(peer)
                self.creating_child = True
                try:
                    peer.start()
                finally:
                    self.creating_child = False
                    pending, self.pending_signal = self.pending_signal, None
                    if pending is not None:
                        raise Refused('owner_signal_' + str(pending))
            env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                   'BAO_ADDR': intent['address'], 'BAO_CACERT': str(self.private / 'good.crt'),
                   'BAO_TOKEN': self.token.decode(), 'BAO_CLIENT_TIMEOUT': '15s', 'BAO_TLS_SKIP_VERIFY': 'false'}
            if disabled:
                env['BAO_DISABLE_REDIRECTS'] = 'true'
            argv = [str(BINARY), 'operator', 'raft', 'snapshot', command,
                    str(input_path if command == 'restore' else output_path)]
            process = self.run_private(argv, label, until, env)
        except Exception as exc:
            failure = str(exc) if isinstance(exc, Refused) else type(exc).__name__
        finally:
            peer_results = self.close_peers(local_peers)
        file_observation = {'exists': output_path.exists()}
        if output_path.exists():
            st = regular(output_path)
            if st.st_size > MAX_BODY:
                failure = failure or 'snapshot_output_bound'
            else:
                data = output_path.read_bytes()
                file_observation.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                        exact_synthetic_archive=data == self.archive,
                                        mode=oct(stat.S_IMODE(st.st_mode)))
        incomplete = []
        for peer in peer_results:
            for event in peer['events']:
                if not (event.get('request_complete') and event.get('response_write_complete')):
                    expected_tls = label == 'S08_save_redirect_untrusted_CA' and peer['peer'] == 2 and event.get('expected_bad_ca_handshake_refusal')
                    # A clean TLS connection with no HTTP bytes followed by a
                    # terminal CLI transport refusal is observed separately.
                    no_http = (event.get('http_bytes_received') == 0
                               and event.get('error_type') in ('EOFError', 'SSLEOFError')
                               and process is not None and process['returncode'] == 2 and not process['timed_out'])
                    event['known_pre_http_refusal'] = bool(expected_tls or no_http)
                    if not event['known_pre_http_refusal']:
                        incomplete.append({'peer': peer['peer'], 'connection': event['connection']})
        complete_process = (process is not None and process['direct_child_reaped'] and not process['remaining']
                            and not process['timed_out'] and process['returncode'] in (0, 1, 2))
        cleanup = len(peer_results) == 2 and all(p['owned_stopped'] for p in peer_results)
        peer_errors = [p['peer'] for p in peer_results if p['error_type']]
        unknown = not complete_process or bool(incomplete) or not cleanup or bool(peer_errors)
        observation = {'sequence': sequence, 'case': label, 'intent': intent, 'process': process,
                       'peers': peer_results, 'output': file_observation, 'failure_code': failure,
                       'incomplete_exchanges': incomplete, 'peer_controller_errors': peer_errors,
                       'outcome_unknown': unknown, 'all_case_owned_stopped': cleanup,
                       'actual_http_request_counts': [sum(e.get('request_complete', False) for e in p['events']) for p in peer_results],
                       'source_prediction_used_as_pass_predicate': False,
                       'positive_save_control': (process is not None and process['returncode'] == 0 and file_observation.get('exact_synthetic_archive') is True) if sequence == 1 else None,
                       'classification': classify_case(label, process, peer_results, file_observation),
                       'terminal_unix_ns': time.time_ns()}
        self.completed_cases.append(observation)
        write_json(directory / 'outcome.public.json', observation)
        if unknown:
            self.unknown = True
            raise Refused('unknown_cli_exchange_no_replay')
        if failure:
            raise Refused('owned_fixture_failure')

    def finish(self, failure: str | None) -> int:
        peer_cleanup = self.close_peers([peer for peer in self.peers if not peer.closed])
        process_cleanup = []
        for child, identity in reversed(self.children):
            try:
                process_cleanup.append(stop_owned(child, identity) if identity is not None else stop_provisional(child))
            except Exception as exc:
                process_cleanup.append({'pid': child.pid, 'owned_stopped': False, 'error_type': type(exc).__name__})
        cleanup = (all(p['owned_stopped'] for p in process_cleanup)
                   and all(p['owned_stopped'] for p in peer_cleanup)
                   and all(p.closed for p in self.peers))
        after, fence_error = None, None
        try:
            after = static_fences()
            if after != self.prepared['static'] or digest(Path(__file__)) != self.prepared['controller_sha256']:
                raise Refused('source_or_prior_evidence_changed')
        except Exception as exc:
            fence_error = str(exc) if isinstance(exc, Refused) else type(exc).__name__
        expected = [x[0] for x in CASES]
        actual = [x['case'] for x in self.completed_cases]
        intent_labels = [label for label in expected if (ROOT / 'cases' / label / 'intent.public.json').exists()]
        outcome_labels = [label for label in expected if (ROOT / 'cases' / label / 'outcome.public.json').exists()]
        missing_outcomes = sorted(set(intent_labels) - set(outcome_labels))
        self.unknown = self.unknown or bool(missing_outcomes)
        complete = (actual == expected and intent_labels == expected and outcome_labels == expected
                    and not self.unknown and cleanup and not failure and not fence_error)
        result = {'schema': 'openbao271.snapshot-cli-transport-observation.v1', 'prepared': self.prepared,
                  'status': 'completed_observation' if complete else 'failed_observation',
                  'failure_code': failure, 'fence_error': fence_error, 'static_after': after,
                  'case_count_planned': len(CASES), 'case_count_observed': len(actual), 'cases': self.completed_cases,
                  'intent_count': len(intent_labels), 'outcome_count': len(outcome_labels),
                  'intent_labels_without_durable_outcome': missing_outcomes,
                  'unknown': self.unknown, 'process_cleanup': process_cleanup, 'peer_cleanup': peer_cleanup,
                  'all_owned_stopped': cleanup, 'production_services_changed': False,
                  'valid_restore_bodies': 0, 'actual_bao_servers_started': 0,
                  'cli_contract_observation_only': True, 'full_replacement_qualification': False,
                  'source_predictions_are_not_pass_predicates': True,
                  'elapsed_ms': (time.monotonic_ns() - self.started) / 1e6,
                  'terminal_unix_ns': time.time_ns()}
        write_json(ROOT / 'result.public.json', result)
        print(json.dumps({'status': result['status'], 'case_count_observed': len(actual), 'unknown': self.unknown,
                          'all_owned_stopped': cleanup, 'result': str(ROOT / 'result.public.json'),
                          'sha256': digest(ROOT / 'result.public.json')}, sort_keys=True), flush=True)
        return 0 if complete else 1


def classify_error(returncode: int | None, stderr: bytes) -> str:
    if returncode == 0:
        return 'cli_success'
    if b'incomplete snapshot, unable to read SHA256SUMS.sealed file' in stderr:
        return 'incomplete_snapshot'
    codes = [code for code in (400, 500) if f'Code: {code}.'.encode() in stderr]
    if len(codes) == 1:
        return 'api_' + str(codes[0])
    if b'redirect would cause protocol downgrade' in stderr:
        return 'redirect_protocol_downgrade'
    if b'x509:' in stderr or b'certificate' in stderr:
        return 'tls_certificate_refusal'
    if b'Error taking the snapshot:' in stderr or b'Error installing the snapshot:' in stderr:
        return 'snapshot_transport_or_other_error'
    return 'unclassified_cli_exit'


def classify_case(label: str, process: dict | None, peers: list[dict], output: dict) -> str:
    if process is None:
        return 'no_terminal_cli_receipt'
    if process['timed_out']:
        return 'original_cli_deadline_expired'
    statuses = [e.get('response_status') for p in peers for e in p['events'] if e.get('response_write_complete')]
    if process['returncode'] == 0 and label.startswith(('S05_', 'S07_')):
        return 'cli_success_without_any_valid_restore_input'
    if process['returncode'] == 0 and output.get('exact_synthetic_archive'):
        return 'exact_archive_shape_file_saved'
    if process['error_class'] == 'incomplete_snapshot' and 307 in statuses:
        return 'redirect_observed_but_cli_reported_incomplete_snapshot'
    return process['error_class']


def static_fences() -> dict:
    if BASE.resolve(strict=True) != BASE or BASE.stat().st_uid != os.getuid():
        raise Refused('owned_base_required')
    st = regular(BINARY)
    actual = digest(BINARY)
    if actual != BINARY_SHA or not os.access(BINARY, os.X_OK):
        raise Refused('pinned_official_binary_required')
    fences = {}
    for relative, expected in OLD_FENCES.items():
        path = BASE / relative
        regular(path)
        value = digest(path)
        if value != expected:
            raise Refused('prior_evidence_changed')
        fences[relative] = {'bytes': path.stat().st_size, 'sha256': value}
    return {'official_binary': str(BINARY), 'binary_bytes': st.st_size, 'binary_sha256': actual,
            'official_source_commit': SOURCE_COMMIT, 'old_evidence': fences}


def prepare() -> dict:
    if ROOT.exists() or ROOT.is_symlink():
        raise Refused('fresh_fixture_root_required')
    if len(INVALID) != 22 or len(CASES) != 10 or len(set(c[0] for c in CASES)) != 10:
        raise Refused('frozen_case_contract_changed')
    for port in PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(('127.0.0.1', port))
    return {'schema': 'openbao271.snapshot-cli-transport-prepare.v1', 'static': static_fences(),
            'controller_sha256': digest(Path(__file__)), 'work_root': str(ROOT), 'ports': list(PORTS),
            'loopback_only': True, 'case_labels': [x[0] for x in CASES],
            'http_seconds': HTTP_SECONDS, 'whole_phase_seconds': WHOLE_SECONDS,
            'original_restore_input_bytes': len(INVALID), 'valid_restore_bodies': 0,
            'source_predictions_are_not_pass_predicates': True, 'credential_helpers_used': False,
            'inherited_bao_vault_proxy_environment': False, 'tls_skip_verify': False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    prepared = prepare()
    if args.prepare_only:
        print(json.dumps(prepared, sort_keys=True), flush=True)
        return 0
    owner = Owner(prepared)
    signal.signal(signal.SIGTERM, owner.interrupted)
    signal.signal(signal.SIGINT, owner.interrupted)
    failure = None
    try:
        owner.setup()
        for sequence, case in enumerate(CASES, 1):
            owner.case(sequence, case)
    except Exception as exc:
        failure = str(exc) if isinstance(exc, Refused) else type(exc).__name__
    finally:
        if owner.created_root:
            return owner.finish(failure)
    raise Refused(failure or 'failure_before_owned_root')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'status': 'failed_before_or_during_receipt', 'error_type': type(exc).__name__}), flush=True)
        raise SystemExit(2) from None
