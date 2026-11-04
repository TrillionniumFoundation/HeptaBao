#!/usr/bin/env python3
"""Bounded, fresh, loopback-only OpenBao 2.7.1 standby wire observation.

No redirect following, no valid restore body, no operation replay.  Bootstrap
credentials and all raw HTTP bodies stay in the owned 0700 fixture.  Public
receipts contain only fixed labels, status/header shapes, sizes and digests.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time

BASE = Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
EXPECTED_SHA = '535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea'
OFFICIAL_COMMIT = 'a5db72cef75c24b920ade02065b18dd8eb666bac'
HTTP_SECONDS = 15.0
READINESS_SECONDS = 45.0
MAX_RESPONSE = 16 * 1024 * 1024
API_PORTS = {1: 48710, 2: 48712, 3: 48714}
CLUSTER_PORTS = {n: p + 1 for n, p in API_PORTS.items()}
os.umask(0o077)


class Refused(Exception):
    pass


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(d)
    finally:
        os.close(d)


def write_json(path: Path, obj: object) -> None:
    write_new(path, (json.dumps(obj, sort_keys=True, indent=2) + '\n').encode())


def regular(path: Path) -> os.stat_result:
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
        raise Refused('regular_single_link_file_required')
    return s


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
    result = []
    for entry in Path('/proc').iterdir():
        if entry.name.isdecimal():
            try:
                ident = process_identity(int(entry.name))
            except PermissionError:
                continue
            if ident and ident['pgid'] == pgid:
                result.append(ident)
    return result


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
    members = group_members(p.pid)
    return {'pid': p.pid, 'start_ticks': captured['start_ticks'],
            'wait_returncode': p.returncode, 'remaining': members,
            'owned_stopped': not members}


def stop_provisional(p: subprocess.Popen) -> dict:
    """Retain the actual unreaped Popen child when identity capture fails.

    A live, unreaped direct child cannot have its PID reused. Signals address
    its new session group only after getpgid confirms that exact Popen PID.
    If the group changed, stop only the direct child and refuse full cleanup.
    """
    group_changed = False
    group_verified_before_signal = None
    if p.poll() is None:
        try:
            group_verified_before_signal = os.getpgid(p.pid) == p.pid
        except ProcessLookupError:
            group_verified_before_signal = None
        group_changed = group_verified_before_signal is False
        try:
            if group_verified_before_signal:
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
                    same_group = os.getpgid(p.pid) == p.pid
                    group_changed = group_changed or not same_group
                    if same_group:
                        os.killpg(p.pid, signal.SIGKILL)
                    else:
                        p.kill()
                except ProcessLookupError:
                    pass
            p.wait(timeout=5)
    else:
        p.wait()
    members = group_members(p.pid)
    return {'pid': p.pid, 'start_ticks': None, 'identity_capture_completed': False,
            'cleanup_authority': 'actual_owned_unreaped_popen_direct_child',
            'group_verified_before_signal': group_verified_before_signal,
            'group_changed': group_changed, 'wait_returncode': p.returncode,
            'direct_child_reaped': p.returncode is not None, 'remaining': members,
            'owned_stopped': p.returncode is not None and not group_changed and not members}


class HeaderRecorder:
    def __init__(self, source):
        self.source, self.raw, self.recording = source, bytearray(), True
    def readline(self, *args, **kwargs):
        value = self.source.readline(*args, **kwargs)
        if self.recording:
            if len(self.raw) + len(value) > 65536:
                raise Refused('response_header_record_bound')
            self.raw.extend(value)
        return value
    def __getattr__(self, name):
        return getattr(self.source, name)


class ObservedHTTPResponse(http.client.HTTPResponse):
    def begin(self):
        recorder = HeaderRecorder(self.fp)
        self.fp = recorder
        try:
            super().begin()
        finally:
            recorder.recording = False
            self.header_record = bytes(recorder.raw)


def child_request(spec_path: Path) -> int:
    """One exchange.  The parent also enforces the same absolute deadline."""
    spec = json.loads(spec_path.read_text())
    until = int(spec['deadline_monotonic_ns'])
    phase = 'before_connect'
    sent = False
    connection = None
    summary = {'response_complete': False, 'request_sent': False,
               'outcome_unknown': False, 'phase': phase}
    started = time.monotonic_ns()
    try:
        def remaining() -> float:
            left = (until - time.monotonic_ns()) / 1e9
            if left <= 0:
                raise TimeoutError('original_deadline')
            return left

        context = ssl.create_default_context(cafile=spec['ca_file'])
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        connection = http.client.HTTPSConnection('127.0.0.1', spec['port'],
                                                 context=context, timeout=remaining())
        connection.response_class = ObservedHTTPResponse
        connection.connect()
        phase = 'connected_tls'
        connection.sock.settimeout(remaining())
        body = Path(spec['body_file']).read_bytes() if spec['body_file'] else b''
        headers = {'Connection': 'close', 'Content-Type': spec['content_type']}
        if spec['credential'] == 'root':
            bootstrap = json.loads(Path(spec['bootstrap_file']).read_text())
            headers['X-Vault-Token'] = bootstrap['root_token']
        elif spec['credential'] == 'invalid':
            headers['X-Vault-Token'] = 'hvs.owned-invalid-standby-oracle'
        elif spec['credential'] in ('finite2-default', 'finite1-default', 'ttl-default', 'finite2-disabled', 'snapshot-read', 'snapshot-update'):
            headers['X-Vault-Token'] = json.loads(Path(spec['token_file']).read_text())['token']
        headers.update(spec['headers'])
        # Mark ambiguous dispatch conservatively before any request bytes.
        sent = True
        phase = 'request_dispatch'
        connection.request(spec['method'], spec['path'], body=body, headers=headers)
        connection.sock.settimeout(remaining())
        phase = 'response_headers'
        response = connection.getresponse()
        raw = bytearray()
        phase = 'response_body'
        while True:
            if connection.sock is not None:
                connection.sock.settimeout(remaining())
            chunk = response.read(min(65536, MAX_RESPONSE + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_RESPONSE:
                raise Refused('response_exceeds_fixed_bound')
        remaining()
        lengths = response.headers.get_all('Content-Length') or []
        if lengths and (len(lengths) != 1 or not lengths[0].isascii()
                        or not lengths[0].isdigit() or int(lengths[0]) != len(raw)):
            raise Refused('response_content_length_incomplete_or_ambiguous')
        if lengths and response.chunked:
            raise Refused('response_framing_ambiguous')
        write_new(Path(spec['response_body_file']), bytes(raw))
        location = response.getheader('Location')
        expected_locations = {f'https://127.0.0.1:{p}' + spec['path']
                              for p in API_PORTS.values()}
        summary.update(header_wire_bytes=len(response.header_record),
                       header_wire_sha256=hashlib.sha256(response.header_record).hexdigest(),
                       header_wire_has_terminal_crlf=response.header_record.endswith(b'\r\n\r\n'),
                       location_bytes=len(location.encode()) if location is not None else None,
                       location_sha256=hashlib.sha256(location.encode()).hexdigest() if location is not None else None,
                       location_is_prefix_of_enrolled_exact_target=bool(location) and any(v.startswith(location) for v in expected_locations),
                       location_common_prefix_lengths={str(n): len(os.path.commonprefix([location or '', f'https://127.0.0.1:{port}' + spec['path']])) for n, port in API_PORTS.items()})
        summary.update(response_complete=True, request_sent=True,
                       outcome_unknown=False, phase='complete', status=response.status,
                       response_bytes=len(raw), response_sha256=hashlib.sha256(raw).hexdigest(),
                       header_names=sorted({k.lower() for k, _ in response.getheaders()}),
                       content_type=response.getheader('Content-Type'),
                       content_length=response.getheader('Content-Length'),
                       location_present=location is not None,
                       location_matches_enrolled_origin_and_exact_target=location in expected_locations,
                       location_node=next((n for n, port in API_PORTS.items()
                           if location == f'https://127.0.0.1:{port}' + spec['path']), None))
        if not summary['header_wire_has_terminal_crlf']:
            summary.update(response_complete=False, outcome_unknown=True, phase='response_headers_incomplete')
            returncode = 2
        else:
            returncode = 0
    except Exception as exc:
        summary.update(request_sent=sent, outcome_unknown=sent,
                       phase=phase, error_type=type(exc).__name__)
        returncode = 2
    finally:
        if connection is not None:
            connection.close()
        summary['elapsed_ms'] = (time.monotonic_ns() - started) / 1e6
        write_json(Path(spec['response_meta_file']), summary)
    return returncode


def check_prepared(binary: Path, work: Path) -> dict:
    regular(binary)
    if digest(binary) != EXPECTED_SHA:
        raise Refused('official_binary_digest_mismatch')
    if work.parent != BASE or not re.fullmatch(r'official271-standby-ttl-restore-oracle-live-61ff-r[0-9]+', work.name):
        raise Refused('work_root_outside_owned_namespace')
    if work.exists() or work.is_symlink():
        raise Refused('fresh_work_root_required')
    for port in [*API_PORTS.values(), *CLUSTER_PORTS.values()]:
        with socket.socket() as s:
            s.bind(('127.0.0.1', port))
    version = subprocess.run([str(binary), 'version'], capture_output=True, timeout=15,
                             check=False, env={'PATH': '/usr/bin:/bin', 'HOME': str(BASE)})
    if version.returncode != 0 or b'OpenBao v2.7.1 ' not in version.stdout:
        raise Refused('official_version_banner_mismatch')
    return {'binary': str(binary), 'binary_sha256': EXPECTED_SHA,
            'binary_bytes': binary.stat().st_size, 'official_tag': 'v2.7.1',
            'official_source_commit': OFFICIAL_COMMIT,
            'version_stdout_sha256': hashlib.sha256(version.stdout).hexdigest(),
            'controller_sha256': digest(Path(__file__)), 'work_root': str(work),
            'api_ports': API_PORTS, 'cluster_ports': CLUSTER_PORTS,
            'loopback_only': True, 'http_seconds': HTTP_SECONDS,
            'readiness_seconds': READINESS_SECONDS, 'max_response_bytes': MAX_RESPONSE,
            'node_disable_standby_reads_config': {1: 'omitted', 2: 'omitted', 3: 'omitted'},
            'node_consistency_missing_header_forward': {1: False, 2: False, 3: True},
            'node3_local_setup_and_role_control': 'X-Vault-Inconsistent: fail; business cases retain their declared headers',
            'redirect_following': False, 'valid_restore_bodies': 0,
            'old_generations_reopened': False}


class Fixture:
    def __init__(self, binary: Path, root: Path, prepared: dict):
        self.binary, self.root, self.prepared = binary, root, prepared
        self.seq, self.procs, self.observations, self.checks = 0, [], [], []
        self.private = root / 'private'
        self.public = root / 'operations'
        self.outcome_unknown = False
        self.clients, self.cases = [], []
        self.created_root = False
        self.creating_child = False
        self.pending_signal = None
        self.started_unix_ns = time.time_ns()
        self.started_monotonic_ns = time.monotonic_ns()

    def interrupted(self, signum, _frame) -> None:
        if self.creating_child:
            if self.pending_signal is None:
                self.pending_signal = signum
            return
        raise Refused('owner_signal_' + str(signum))

    def start_owned_child(self, collection: list, *args, **options) -> subprocess.Popen:
        # This controller is single-threaded. Defer only the Python exception
        # between Popen construction and tracking its provisional ownership.
        # The child inherits no changed signal mask, handler or preexec hook.
        if self.creating_child:
            raise Refused('nested_owned_child_creation')
        self.creating_child = True
        try:
            child = subprocess.Popen(*args, **options)
            collection.append((child, None))
        finally:
            self.creating_child = False
            pending, self.pending_signal = self.pending_signal, None
            if pending is not None:
                raise Refused('owner_signal_' + str(pending))
        return child

    def check(self, name: str, ok: bool) -> None:
        self.checks.append({'name': name, 'passed': bool(ok)})
        if not ok:
            raise Refused(name)

    def request(self, node: int, method: str, path: str, label: str, *, body: object = None,
                raw_body: bytes | None = None, credential: str = 'root',
                content_type: str = 'application/json', headers: dict | None = None,
                allow_preconnect_failure: bool = False,
                parent_deadline_ns: int | None = None) -> tuple[dict, bytes]:
        if parent_deadline_ns is not None and time.monotonic_ns() >= parent_deadline_ns:
            raise Refused('parent_deadline_expired_before_request')
        self.seq += 1
        number = f'{self.seq:04d}'
        payload = raw_body if raw_body is not None else (
            json.dumps(body, separators=(',', ':')).encode() if body is not None else b'')
        body_file = self.private / f'{number}.request-body'
        write_new(body_file, payload)
        meta_file = self.private / f'{number}.response-meta.json'
        response_file = self.private / f'{number}.response-body'
        until = time.monotonic_ns() + int(HTTP_SECONDS * 1e9)
        if parent_deadline_ns is not None:
            until = min(until, parent_deadline_ns)
        intent = {'sequence': self.seq, 'node': node, 'method': method, 'path': path,
                  'label': label, 'credential_class': credential, 'body_bytes': len(payload),
                  'body_sha256': hashlib.sha256(payload).hexdigest(),
                  'headers': headers or {}, 'http_seconds': HTTP_SECONDS,
                  'deadline_monotonic_ns': until, 'parent_deadline_monotonic_ns': parent_deadline_ns,
                  'intent_unix_ns': time.time_ns(),
                  'redirect_following': False, 'valid_restore_body': False}
        write_json(self.public / f'{number}.intent.public.json', intent)
        spec = dict(port=API_PORTS[node], method=method, path=path, credential=credential,
                    body_file=str(body_file), response_meta_file=str(meta_file),
                    response_body_file=str(response_file), content_type=content_type,
                    headers=headers or {}, ca_file=str(self.root / 'ca.crt'),
                    bootstrap_file=str(self.private / 'bootstrap.json'), deadline_monotonic_ns=until,
                    token_file=str(self.private / (credential + '.token.json')))
        spec_path = self.private / f'{number}.spec.json'
        write_json(spec_path, spec)
        out = self.private / f'{number}.client.stdout'
        err = self.private / f'{number}.client.stderr'
        started = time.monotonic_ns()
        with out.open('xb') as stdout, err.open('xb') as stderr:
            proc = self.start_owned_child(self.clients, [sys.executable, str(Path(__file__).resolve()),
                                     '--child-request', str(spec_path)],
                                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    start_new_session=True, env={'PATH': '/usr/bin:/bin'})
            ident = process_identity(proc.pid)
            if ident is None:
                raise Refused('client_identity_unavailable')
            self.clients[-1] = (proc, ident)
            timed_out = False
            try:
                proc.wait(timeout=max(0.001, (until - time.monotonic_ns()) / 1e9))
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
        members = group_members(proc.pid)
        observation = json.loads(meta_file.read_text()) if meta_file.exists() else {
            'response_complete': False, 'request_sent': None,
            'outcome_unknown': True, 'phase': 'child_no_terminal_receipt'}
        observation.update(sequence=self.seq, label=label, node=node,
                           caller_elapsed_ms=(time.monotonic_ns() - started) / 1e6,
                           child_returncode=proc.returncode, caller_timed_out=timed_out,
                           child_reaped=True, child_remaining=members)
        if timed_out or members:
            observation['outcome_unknown'] = True
        self.observations.append(observation)
        write_json(self.public / f'{number}.outcome.public.json', observation)
        if observation['outcome_unknown']:
            self.outcome_unknown = True
            raise Refused('single_exchange_outcome_unknown_no_replay')
        if not observation['response_complete']:
            if allow_preconnect_failure and observation['request_sent'] is False:
                return observation, b''
            raise Refused('exchange_failed_without_response')
        return observation, response_file.read_bytes()

    def ready(self, node: int, *, initialized: bool | None = None, sealed: bool | None = None) -> dict:
        until = time.monotonic_ns() + int(READINESS_SECONDS * 1e9)
        if node == 3 and initialized is False:
            # Observe one complete original-header response on the actual
            # business listener, retrying only a definite preconnect failure.
            # Both controls consume the same original readiness deadline.
            while time.monotonic_ns() < until:
                o, b = self.request(node, 'GET', '/v1/sys/health?standbyok=true',
                                    'setup_missing_header_control', credential='none',
                                    allow_preconnect_failure=True, parent_deadline_ns=until)
                self.cases.append({'kind': 'setup_missing_header_control', **o})
                if o['response_complete']:
                    self.check('node_3_original_header_sealed_refusal',
                               o['status'] == 503 and json.loads(b) == {'errors': ['Vault is sealed']})
                    break
                time.sleep(min(0.1, max(0, (until - time.monotonic_ns()) / 1e9)))
            else:
                raise Refused('original_readiness_deadline')
        while time.monotonic_ns() < until:
            o, b = self.request(node, 'GET', '/v1/sys/health?standbyok=true',
                                'readiness', credential='none', allow_preconnect_failure=True,
                                headers={'X-Vault-Inconsistent': 'fail'} if node == 3 else None,
                                parent_deadline_ns=until)
            if o['response_complete']:
                h = json.loads(b)
                if ((initialized is None or h.get('initialized') is initialized)
                        and (sealed is None or h.get('sealed') is sealed)):
                    self.check(f'node_{node}_official_version', h.get('version') == '2.7.1')
                    return h
            time.sleep(min(0.1, max(0, (until - time.monotonic_ns()) / 1e9)))
        raise Refused('original_readiness_deadline')

    def roles(self, label: str) -> dict:
        records = {}
        for n in API_PORTS:
            o, b = self.request(n, 'GET', '/v1/sys/leader', label, credential='none',
                                headers={'X-Vault-Inconsistent': 'fail'} if n == 3 else None)
            self.check(f'{label}_node_{n}_leader_response', o['status'] == 200)
            d = json.loads(b)
            records[n] = {'is_self': d.get('is_self'), 'ha_enabled': d.get('ha_enabled'),
                          'leader_node': next((i for i, p in API_PORTS.items()
                              if d.get('leader_address') == f'https://127.0.0.1:{p}'), None),
                          'performance_standby': d.get('performance_standby'),
                          'raft_committed_index': d.get('raft_committed_index'),
                          'raft_applied_index': d.get('raft_applied_index')}
        leaders = [n for n, r in records.items() if r['is_self'] is True]
        self.check(label + '_single_actual_leader', len(leaders) == 1)
        leader = leaders[0]
        self.check(label + '_all_report_same_leader', all(r['leader_node'] == leader for r in records.values()))
        result = {'label': label, 'actual_leader': leader, 'nodes': records}
        write_json(self.root / (label + '.public.json'), result)
        return result

    def wait_initial_leader(self) -> None:
        until = time.monotonic_ns() + int(READINESS_SECONDS * 1e9)
        while time.monotonic_ns() < until:
            o, b = self.request(1, 'GET', '/v1/sys/leader', 'initial_leader_readiness',
                                credential='none', parent_deadline_ns=until)
            if o['status'] == 200 and json.loads(b).get('is_self') is True:
                return
            time.sleep(min(0.1, max(0, (until - time.monotonic_ns()) / 1e9)))
        raise Refused('original_leader_readiness_deadline')

    def raft_observation(self, label: str) -> None:
        o, b = self.request(1, 'GET', '/v1/sys/storage/raft/autopilot/state', label)
        self.check(label + '_complete', o['status'] == 200)
        data = json.loads(b).get('data', {})
        servers = data.get('servers', {})
        allowed = {f'owned-oracle-{n}': n for n in API_PORTS}
        projected = []
        for ident, value in servers.items():
            if ident not in allowed:
                raise Refused('unexpected_raft_peer_identity')
            projected.append({'node': allowed[ident], 'node_status': value.get('node_status'),
                              'status': value.get('status'), 'healthy': value.get('healthy'),
                              'last_term': value.get('last_term'), 'last_index': value.get('last_index')})
        write_json(self.root / (label + '.public.json'),
                   {'leader_node': allowed.get(data.get('leader')), 'healthy': data.get('healthy'),
                    'observed_servers': projected, 'expected_nodes': [1, 2, 3],
                    'observation_only_no_term_inference': True})

    def openssl(self, args: list[str], label: str) -> None:
        r = subprocess.run(['/usr/bin/openssl', *args], cwd=self.root,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        write_new(self.private / (label + '.openssl.stdout'), r.stdout)
        write_new(self.private / (label + '.openssl.stderr'), r.stderr)
        if r.returncode:
            raise Refused('fixture_tls_generation_failed')

    def setup(self) -> None:
        self.root.mkdir(mode=0o700)
        self.created_root = True
        self.private.mkdir(mode=0o700)
        self.public.mkdir(mode=0o700)
        write_json(self.root / 'prepared.public.json', self.prepared)
        self.openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
                      '-subj', '/CN=Owned OpenBao standby oracle CA', '-keyout', 'ca.key',
                      '-out', 'ca.crt', '-addext', 'basicConstraints=critical,CA:TRUE'], 'ca')
        for n in API_PORTS:
            node = self.root / f'node{n}'
            node.mkdir(mode=0o700)
            (node / 'data').mkdir(mode=0o700)
            self.openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
                          '-subj', f'/CN=owned-oracle-node{n}', '-keyout', f'node{n}/tls.key',
                          '-out', f'node{n}/tls.csr'], f'node{n}-csr')
            write_new(node / 'extensions.cnf',
                      b'basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n'
                      b'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n')
            self.openssl(['x509', '-req', '-in', f'node{n}/tls.csr', '-CA', 'ca.crt',
                          '-CAkey', 'ca.key', '-set_serial', str(n), '-days', '1', '-sha256',
                          '-extfile', f'node{n}/extensions.cnf', '-out', f'node{n}/tls.crt'], f'node{n}-cert')
            config = '\n'.join([
                'disable_mlock = true', 'ui = false', 'log_level = "warn"',
                f'api_addr = "https://127.0.0.1:{API_PORTS[n]}"',
                f'cluster_addr = "https://127.0.0.1:{CLUSTER_PORTS[n]}"',
                'listener "tcp" {', f'  address = "127.0.0.1:{API_PORTS[n]}"',
                f'  cluster_address = "127.0.0.1:{CLUSTER_PORTS[n]}"',
                f'  tls_cert_file = "{node / "tls.crt"}"',
                f'  tls_key_file = "{node / "tls.key"}"',
                *(['  consistency_missing_header_forward = true'] if n == 3 else []),
                '  max_request_duration = "15s"', '}', 'storage "raft" {',
                f'  path = "{node / "data"}"', f'  node_id = "owned-oracle-{n}"', '}', ''])
            config_path = node / 'server.hcl'
            write_new(config_path, config.encode())
            with (node / 'server.stdout.private.log').open('xb') as out, (node / 'server.stderr.private.log').open('xb') as err:
                p = self.start_owned_child(self.procs, [str(self.binary), 'server', '-config', str(config_path)],
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                     start_new_session=True, env={'PATH': '/usr/bin:/bin', 'HOME': str(node)})
                ident = process_identity(p.pid)
                if ident is None:
                    raise Refused('server_identity_unavailable')
                self.procs[-1] = (p, ident)
            self.ready(n, initialized=False, sealed=True)
        o, b = self.request(1, 'POST', '/v1/sys/init', 'initialize_once',
                            body={'secret_shares': 1, 'secret_threshold': 1}, credential='none')
        self.check('initialize_complete', o['status'] == 200)
        bootstrap = json.loads(b)
        write_json(self.private / 'bootstrap.json', bootstrap)
        o, _ = self.request(1, 'POST', '/v1/sys/unseal', 'node1_unseal_once',
                            body={'key': bootstrap['keys_base64'][0]}, credential='none')
        self.check('node1_unseal_complete', o['status'] == 200)
        self.ready(1, initialized=True, sealed=False)
        self.wait_initial_leader()
        for n in (2, 3):
            o, b = self.request(n, 'POST', '/v1/sys/storage/raft/join', f'node{n}_join_once',
                                body={'leader_api_addr': f'https://127.0.0.1:{API_PORTS[1]}',
                                      'leader_ca_cert': (self.root / 'ca.crt').read_text()}, credential='none',
                                headers={'X-Vault-Inconsistent': 'fail'} if n == 3 else None)
            self.check(f'node{n}_joined', o['status'] == 200 and json.loads(b).get('joined') is True)
            o, _ = self.request(n, 'POST', '/v1/sys/unseal', f'node{n}_unseal_once',
                                body={'key': bootstrap['keys_base64'][0]}, credential='none',
                                headers={'X-Vault-Inconsistent': 'fail'} if n == 3 else None)
            self.check(f'node{n}_unseal_complete', o['status'] == 200)
            self.ready(n, initialized=True, sealed=False)

    def snapshot_shape(self, body: bytes) -> dict:
        # Archive names and total lengths only; never extract or emit contents.
        total = 0
        members = []
        with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
            for member in archive:
                if not member.isfile() or member.size > MAX_RESPONSE or len(members) >= 16:
                    raise Refused('snapshot_archive_shape_bound')
                total += member.size
                if total > MAX_RESPONSE:
                    raise Refused('snapshot_archive_uncompressed_bound')
                members.append({'name': member.name, 'size': member.size})
        return {'gzip_magic': body[:2] == b'\x1f\x8b', 'members': members,
                'sealed_hashes_nonempty': any(m['name'] == 'SHA256SUMS.sealed' and m['size'] > 0 for m in members)}

    def create_token(self, label, uses):
        o, raw = self.request(1, 'POST', '/v1/auth/token/create', label + '_create_once',
            body={'policies':['root'], 'no_default_policy':True, 'num_uses':uses,
                  'ttl':'10m', 'renewable':False, 'display_name':'owned-standby-token-oracle'})
        value = json.loads(raw)
        self.check(label + '_token_created', o['status'] == 200
                   and isinstance(value.get('auth', {}).get('client_token'), str)
                   and value['auth']['policies'] == ['root'])
        token = value['auth']['client_token']
        write_json(self.private / (label + '.token.json'), {'token':token})
        return self.lookup_token(label, 'before')

    def lookup_token(self, label, phase):
        token = json.loads((self.private / (label + '.token.json')).read_text())['token']
        o, raw = self.request(1, 'POST', '/v1/auth/token/lookup', label + '_lookup_' + phase,
                              body={'token':token})
        value = json.loads(raw)
        data = value.get('data', {})
        self.check(label + '_lookup_' + phase + '_bounded_result', o['status'] in (200, 400, 403))
        observed = {'label':label, 'phase':phase, 'status':o['status'],
                    'num_uses':data.get('num_uses'), 'ttl':data.get('ttl'),
                    'policies':data.get('policies'), 'renewable':data.get('renewable')}
        self.cases.append({'token_lookup':observed})
        return observed

    def create_policy_token(self, label, capabilities):
        name = 'ha61ff-' + label
        rule = 'path "sys/storage/raft/snapshot" { capabilities = ' + json.dumps(capabilities) + ' }\n'
        if 'update' in capabilities:
            rule += 'path "sys/storage/raft/snapshot-force" { capabilities = ["update"] }\n'
        o, _ = self.request(1, 'PUT', '/v1/sys/policies/acl/' + name,
                            label + '_policy_write_once', body={'policy': rule})
        self.check(label + '_policy_acknowledged', o['status'] == 204)
        o, raw = self.request(1, 'POST', '/v1/auth/token/create', label + '_token_create_once',
            body={'policies': [name], 'no_default_policy': False, 'num_uses': 0,
                  'ttl': '10m', 'renewable': False, 'display_name': 'owned-policy-standby-oracle'})
        auth = json.loads(raw).get('auth', {})
        self.check(label + '_actual_non_root_policy_token', o['status'] == 200
                   and isinstance(auth.get('client_token'), str)
                   and name in auth.get('policies', []) and 'root' not in auth.get('policies', []))
        write_json(self.private / (label + '.token.json'), {'token': auth['client_token']})
        o, raw = self.request(2, 'GET', '/v1/auth/token/lookup-self',
                              label + '_actual_standby_authentication', credential=label)
        data = json.loads(raw).get('data', {})
        self.check(label + '_actual_standby_authentication', o['status'] == 200
                   and name in data.get('policies', []) and 'root' not in data.get('policies', [])
                   and data.get('num_uses') == 0)
        self.cases.append({'kind': 'actual_policy_identity', 'label': label,
                           'policies': data['policies'], 'num_uses': data['num_uses'], **o})

    def observed(self, node, method, path, label, *, credential='root', headers=None, body=None,
                 raw_body=None, content_type='application/json'):
        o, raw = self.request(node, method, path, label, credential=credential,
                              headers=headers, body=body, raw_body=raw_body, content_type=content_type)
        row = {'kind': 'scoped_acl_and_consistency', 'node': node, 'method': method,
               'route': path, 'credential_class': credential, 'headers': headers or {}, **o}
        if o['status'] == 307:
            self.check(label + '_complete_exact_redirect', o['location_node'] == 1
                       and o['location_matches_enrolled_origin_and_exact_target']
                       and o['content_length'] == '0' and raw == b'')
        if o['status'] == 200 and path.endswith('/snapshot'):
            row['archive'] = self.snapshot_shape(raw)
            self.check(label + '_complete_actual_archive', row['archive']['sealed_hashes_nonempty'])
        if o['status'] == 200 and path == '/v1/owned/data/read-marker':
            self.check(label + '_exact_kv_value',
                       json.loads(raw).get('data', {}).get('data') == {'marker': 'owned-policy-oracle'})
        self.cases.append(row)
        return o, raw

    def observe(self) -> None:
        before = self.roles('roles_before')
        self.check('actual_initial_leader', before['actual_leader'] == 1)
        o, _ = self.request(1, 'POST', '/v1/sys/mounts/owned', 'owned_kv_mount_once',
                            body={'type': 'kv', 'options': {'version': '2'}})
        self.check('owned_kv_mount_acknowledged', o['status'] in (200, 204))
        o, _ = self.request(1, 'POST', '/v1/owned/data/read-marker', 'owned_kv_write_once',
                            body={'options': {'cas': 0}, 'data': {'marker': 'owned-policy-oracle'}})
        self.check('owned_kv_write_acknowledged', o['status'] == 200)
        initial = self.create_token('ttl-default', 0)
        self.check('ttl_root_unlimited_actual', initial['status'] == 200 and initial['num_uses'] == 0)
        for node, credential in [(2, 'root'), (2, 'ttl-default'), (3, 'root'), (3, 'ttl-default')]:
            for header in ('1', 'false'):
                self.observed(node, 'GET', '/v1/owned/data/read-marker',
                              f'ttl_kv_node{node}_{credential}_{header}', credential=credential,
                              headers={'X-Vault-No-Request-Forwarding': header})
        for label, capabilities in [('snapshot-read', ['read']),
                                    ('snapshot-update', ['read', 'update'])]:
            self.create_policy_token(label, capabilities)
            for node in (1, 2, 3):
                self.observed(node, 'GET', '/v1/sys/storage/raft/snapshot',
                              f'{label}_node{node}_snapshot', credential=label)
            self.observed(2, 'GET', '/v1/sys/storage/raft/snapshot',
                          label + '_node2_snapshot_no_forward_false', credential=label,
                          headers={'X-Vault-No-Request-Forwarding': 'false'})
            for node in (1, 2):
                self.observed(node, 'POST', '/v1/sys/storage/raft/snapshot',
                              f'{label}_node{node}_invalid_restore', credential=label,
                              raw_body=b'owned-invalid-snapshot', content_type='application/octet-stream')
            if 'update' in capabilities:
                self.observed(2, 'PUT', '/v1/sys/storage/raft/snapshot-force',
                              label + '_node2_invalid_force_restore', credential=label,
                              raw_body=b'owned-invalid-snapshot', content_type='application/octet-stream')
        for node, with_policy in [(2, False), (3, False), (3, True)]:
            suffix = f'node{node}_explicit_policy_{str(with_policy).lower()}'
            headers = {'X-Vault-No-Request-Forwarding': '1'}
            if with_policy:
                headers['X-Vault-Inconsistent'] = 'forward-active-node'
            self.observed(node, 'GET', '/v1/owned/data/read-marker',
                          'consistency_read_' + suffix, headers=headers)
            path = '/v1/owned/data/precedence-' + suffix
            o, _ = self.observed(node, 'POST', path, 'consistency_write_' + suffix,
                                body={'options': {'cas': 0}, 'data': {'marker': suffix}}, headers=headers)
            effect, raw = self.observed(1, 'GET', path, 'consistency_write_effect_' + suffix)
            self.check('consistency_write_exact_effect_' + suffix,
                       (o['status'] == 307 and effect['status'] == 404)
                       or (o['status'] == 200 and effect['status'] == 200
                           and json.loads(raw).get('data', {}).get('data') == {'marker': suffix}))
        # Supplemental reference: authenticate the actual expiring, unlimited
        # root-policy token on the default read standby, then issue the exact
        # snapshot GET and invalid-body POST used by the normal observer.
        o, raw = self.request(2, 'GET', '/v1/auth/token/lookup-self',
                              'ttl_root_default_standby_actual_authentication',
                              credential='ttl-default')
        data = json.loads(raw).get('data', {})
        self.check('ttl_root_default_standby_actual_identity',
                   o['status'] == 200 and data.get('policies') == ['root']
                   and data.get('num_uses') == 0
                   and isinstance(data.get('ttl'), int) and 0 < data['ttl'] <= 600)
        self.cases.append({'kind': 'actual_ttl_policy_identity',
                           'credential_class': 'ttl-default',
                           'policies': data['policies'], 'num_uses': data['num_uses'],
                           'ttl': data['ttl'], **o})
        self.observed(2, 'GET', '/v1/sys/storage/raft/snapshot',
                      'ttl_root_default_standby_snapshot', credential='ttl-default')
        self.observed(2, 'POST', '/v1/sys/storage/raft/snapshot',
                      'ttl_root_default_standby_invalid_restore', credential='ttl-default',
                      raw_body=b'owned-invalid-snapshot', content_type='application/octet-stream')
        after_invalid = self.lookup_token('ttl-default', 'after_invalid_restore')
        self.check('ttl_root_after_invalid_restore_still_unlimited_and_valid',
                   after_invalid['status'] == 200 and after_invalid['num_uses'] == 0
                   and after_invalid['policies'] == ['root']
                   and isinstance(after_invalid['ttl'], int) and after_invalid['ttl'] > 0)
        for label in ('ttl-default', 'snapshot-read', 'snapshot-update'):
            token = json.loads((self.private / (label + '.token.json')).read_text())['token']
            o, _ = self.request(1, 'POST', '/v1/auth/token/revoke', label + '_revoke_once',
                                body={'token': token})
            self.check(label + '_revocation_acknowledged', o['status'] == 204)
        after = self.roles('roles_after')
        self.check('actual_leader_unchanged', after['actual_leader'] == 1)
        write_json(self.root / 'wire-observations.public.json', {'cases': self.cases,
            'qualification': 'official271_scoped_acl_consistency_and_ttl_restore_reference_only',
            'default_read_standby_node': 2, 'consistency_missing_header_forward_node': 3,
            'disable_standby_reads': False, 'automatic_redirect_following': False,
            'unknown_mutation_replay': False, 'cold_restart_tested': False,
            'physical_hosts': 1, 'process_nodes': 3})

    def finish(self, failed: str | None) -> int:
        cleanup, client_cleanup = [], []
        for collection, destination in ((self.clients,client_cleanup),(self.procs,cleanup)):
            for proc, captured in reversed(collection):
                try:
                    destination.append(stop_owned(proc,captured) if captured is not None else stop_provisional(proc))
                except Exception as exc:
                    destination.append({'pid':proc.pid,'owned_stopped':False,'error_type':type(exc).__name__})
        clean = all(row['owned_stopped'] for row in cleanup+client_cleanup)
        missing = sorted(set(range(1,self.seq+1)) - {row['sequence'] for row in self.observations})
        unknown = sum(bool(row['outcome_unknown']) for row in self.observations) + len(missing)
        complete = self.seq == len(self.observations) and unknown == 0 and not self.outcome_unknown
        unchanged = digest(self.binary) == EXPECTED_SHA and digest(Path(__file__)) == self.prepared['controller_sha256']
        status = 'completed_observation' if not failed and clean and complete and unchanged else 'failed'
        report = {'schema':'official271_ttl_restore_reference_61ff_r1','status':status,
            'prepared':self.prepared,'failure_code':failed,'checks':self.checks,
            'http_intents':self.seq,'http_outcomes':len(self.observations),'http_unknown':unknown,
            'missing_outcome_sequences':missing,'all_owned_stopped':clean,
            'server_cleanup':cleanup,'client_cleanup':client_cleanup,'pinned_files_unchanged':unchanged,
            'original_deadlines_preserved':True,'redirect_following':False,'operation_replayed':False,
            'formal_heptabao_qualification':False,'cold_restart_tested':False,
            'production_services_touched':False,'terminal_unix_ns':time.time_ns()}
        write_json(self.root/'result.public.json',report)
        print(json.dumps({'status':status,'result':str(self.root/'result.public.json'),
                          'result_sha256':digest(self.root/'result.public.json'),
                          'http_intents':self.seq,'http_outcomes':len(self.observations),
                          'http_unknown':unknown,'all_owned_stopped':clean},sort_keys=True))
        return 0 if status == 'completed_observation' else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', type=Path)
    ap.add_argument('--work-dir', type=Path)
    ap.add_argument('--prepare-only', action='store_true')
    ap.add_argument('--child-request', type=Path)
    args = ap.parse_args()
    if args.child_request:
        return child_request(args.child_request)
    if args.binary is None or args.work_dir is None:
        raise Refused('explicit_binary_and_owned_work_root_required')
    binary, work = args.binary.absolute(), args.work_dir.absolute()
    prepared = check_prepared(binary, work)
    if args.prepare_only:
        print(json.dumps(prepared, sort_keys=True))
        return 0
    fixture = Fixture(binary, work, prepared)
    signal.signal(signal.SIGTERM, fixture.interrupted)
    signal.signal(signal.SIGINT, fixture.interrupted)
    failure = None
    try:
        fixture.setup()
        fixture.observe()
    except Exception as exc:
        failure = str(exc) if isinstance(exc, Refused) else type(exc).__name__
    finally:
        if fixture.created_root:
            return fixture.finish(failure)
    raise Refused(failure or 'fixture_failed_before_root')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'failed_before_fixture', 'error_type': type(error).__name__,
                          'errno':getattr(error,'errno',None),
                          'refusal':str(error) if isinstance(error,Refused) else None}, sort_keys=True))
        raise SystemExit(2) from None
