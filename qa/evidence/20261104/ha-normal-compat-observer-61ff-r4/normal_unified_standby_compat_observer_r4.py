#!/usr/bin/env python3
"""Bounded, fresh, loopback-only normal HeptaBao compatibility observation.

No redirect following, no valid restore body, no operation replay.  Bootstrap
credentials and all raw HTTP bodies stay in the owned 0700 fixture.  Public
receipts contain only fixed labels, status/header shapes, sizes and digests.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import platform
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time

BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-unified-normal-61ff-r1')
EXPECTED_SHA = None
EXPECTED_BUILD_RESULT = None
EXPECTED_NATIVE_RECEIPT = None
COMMIT = None
TREE = None
CONTROL = BASE / 'control'
SOURCE = BASE / 'source'
BUILD = BASE / 'normal-default-r1'
ARTIFACTS = BUILD / 'artifacts'
OPENSSL = Path('/opt/homebrew/Cellar/openssl@3/3.6.3/bin/openssl')
OPENSSL_SHA = '103fc7706cf6646f226d96f29242d81890363499afc730e7ef1fadd64b3a123c'
LIBPROC = ctypes.CDLL('/usr/lib/libproc.dylib')
LIBPROC.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
LIBPROC.proc_pidpath.restype = ctypes.c_int


NATIVE_LARGE_MEDIA = 'application/vnd.heptabao.kv2-lossless+json'
NATIVE_LARGE_ROUTE = '/v1/sys/migration/openbao/kv2/native-large?mount=wire'
ELECTION_SECONDS = 60.0
STABLE_LEADER_SECONDS = 2.2
HTTP_SECONDS = 15.0
READINESS_SECONDS = 45.0
MAX_RESPONSE = 16 * 1024 * 1024
API_PORTS = {1: 48680, 2: 48682, 3: 48684}
CLUSTER_PORTS = {n: p + 1 for n, p in API_PORTS.items()}
os.umask(0o077)


# All 34 status references are now grounded in exact fixed OpenBao 2.7.1 wire.
# The missing TTL restore case was separately observed in cd035b00, sequence 68;
# it is never attributed to the older 070f token oracle or an unrelated actor.
OFFICIAL_REFERENCE_COMPLETE = True
UNVERIFIED_REFERENCE_LABELS = []

OFFICIAL_STATUS = {
    "ttl_kv_node2_root_1": 200,
    "ttl_kv_node2_root_false": 200,
    "ttl_kv_node2_ttl-default_1": 200,
    "ttl_kv_node2_ttl-default_false": 200,
    "ttl_kv_node3_root_1": 307,
    "ttl_kv_node3_root_false": 307,
    "ttl_kv_node3_ttl-default_1": 307,
    "ttl_kv_node3_ttl-default_false": 307,
    "snapshot-read_node1_snapshot": 200,
    "snapshot-read_node2_snapshot": 200,
    "snapshot-read_node3_snapshot": 307,
    "snapshot-read_node2_snapshot_no_forward_false": 200,
    "snapshot-read_node1_invalid_restore": 403,
    "snapshot-read_node2_invalid_restore": 403,
    "snapshot-update_node1_snapshot": 200,
    "snapshot-update_node2_snapshot": 200,
    "snapshot-update_node3_snapshot": 307,
    "snapshot-update_node2_snapshot_no_forward_false": 200,
    "snapshot-update_node1_invalid_restore": 500,
    "snapshot-update_node2_invalid_restore": 500,
    "snapshot-update_node2_invalid_force_restore": 500,
    "consistency_read_node2_explicit_policy_false": 200,
    "consistency_write_node2_explicit_policy_false": 307,
    "consistency_write_effect_node2_explicit_policy_false": 404,
    "consistency_read_node3_explicit_policy_false": 307,
    "consistency_write_node3_explicit_policy_false": 307,
    "consistency_write_effect_node3_explicit_policy_false": 404,
    "consistency_read_node3_explicit_policy_true": 200,
    "consistency_write_node3_explicit_policy_true": 307,
    "consistency_write_effect_node3_explicit_policy_true": 404,
    "ttl_root_default_standby_snapshot": 200,
    "ttl_root_default_standby_invalid_restore": 500,
    "finite1_default_snapshot": 307,
    "finite2_default_snapshot": 307
}


def scoped_coverage(cases):
    rows = [case for case in cases if case.get('kind') == 'scoped_status_case']
    counts = {}
    for row in rows:
        label = row.get('label')
        counts[label] = counts.get(label, 0) + 1
    expected = sorted(OFFICIAL_STATUS)
    observed = sorted(label for label in counts if isinstance(label, str))
    missing = [label for label in expected if label not in counts]
    duplicates = {label: count for label, count in counts.items() if count != 1}
    unexpected = [label for label in observed if label not in OFFICIAL_STATUS]
    differences = [{'label': row.get('label'), 'sequence': row.get('sequence'),
                    'expected_status': OFFICIAL_STATUS.get(row.get('label')),
                    'observed_status': row.get('status')}
                   for row in rows if row.get('label') in OFFICIAL_STATUS
                   and row.get('status') != OFFICIAL_STATUS[row['label']]]
    complete = (len(rows) == len(expected) and not missing and not duplicates
                and not unexpected and all(row.get('response_complete') is True
                    and type(row.get('status')) is int for row in rows))
    return {'expected_case_count': len(expected), 'observed_case_count': len(rows),
            'expected_labels': expected, 'observed_labels': observed,
            'missing_labels': missing, 'duplicate_labels': duplicates,
            'unexpected_labels': unexpected, 'coverage_complete': complete,
            'status_differences': differences,
            'official_reference_complete': OFFICIAL_REFERENCE_COMPLETE,
            'unverified_reference_labels': UNVERIFIED_REFERENCE_LABELS,
            'scoped_status_compatibility_passed': (complete and not differences
                and OFFICIAL_REFERENCE_COMPLETE and not UNVERIFIED_REFERENCE_LABELS)}


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
    result = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'pid=,ppid=,pgid=,lstart='],
                            capture_output=True, text=True, timeout=3)
    fields = result.stdout.strip().split()
    if result.returncode != 0 or len(fields) != 8:
        return None
    path = ctypes.create_string_buffer(4096)
    size = LIBPROC.proc_pidpath(pid, path, len(path))
    return {'pid': int(fields[0]), 'ppid': int(fields[1]), 'pgid': int(fields[2]),
            'start_identity': ' '.join(fields[3:]), 'identity_kind': 'mac_ps_lstart',
            'exe': path.value.decode() if size > 0 else None}


def process_argv(pid: int) -> list[bytes]:
    result = subprocess.run(['/bin/ps', '-ww', '-p', str(pid), '-o', 'command='],
                            capture_output=True, timeout=3)
    if result.returncode != 0:
        raise Refused('owned_command_observation_unavailable')
    return result.stdout.strip().split(b' ')


def group_members(pgid: int) -> list[dict]:
    result = subprocess.run(['/bin/ps', '-axo', 'pid=,pgid='],
                            capture_output=True, text=True, timeout=3)
    if result.returncode != 0:
        raise Refused('owned_group_observation_unavailable')
    members = []
    for row in result.stdout.splitlines():
        fields = row.split()
        if len(fields) == 2 and int(fields[1]) == pgid:
            ident = process_identity(int(fields[0]))
            if ident and ident['pgid'] == pgid:
                members.append(ident)
    return members


def stop_owned(p: subprocess.Popen, captured: dict) -> dict:
    current = process_identity(p.pid)
    if current and current['start_identity'] != captured['start_identity']:
        raise Refused('owned_process_identity_changed')
    if p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            current = process_identity(p.pid)
            if not current or current['start_identity'] != captured['start_identity']:
                raise Refused('owned_process_identity_lost_before_kill')
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=5)
    else:
        p.wait()
    members = group_members(p.pid)
    return {'pid': p.pid, 'start_identity': captured['start_identity'],
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
    return {'pid': p.pid, 'start_identity': None, 'identity_capture_completed': False,
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
        leaf_sha256 = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        if leaf_sha256 != spec['expected_leaf_sha256']:
            raise Refused('exact_tls_leaf_mismatch')
        summary.update(tls_version=connection.sock.version(), peer_leaf_sha256=leaf_sha256,
                       tls_hostname_and_ca_verified=True)
        body = Path(spec['body_file']).read_bytes() if spec['body_file'] else b''
        headers = {'Host': f"127.0.0.1:{spec['port']}",
                   'Connection': 'close', 'Content-Type': spec['content_type']}
        if spec['credential'] == 'root':
            bootstrap = json.loads(Path(spec['bootstrap_file']).read_text())
            headers['X-Vault-Token'] = bootstrap['root_token']
        elif spec['credential'] == 'invalid':
            headers['X-Vault-Token'] = 'hvs.owned-invalid-standby-oracle'
        elif spec['credential'] in ('ttl-default', 'snapshot-read', 'snapshot-update',
                                     'finite1-default', 'finite2-default'):
            headers['X-Vault-Token'] = json.loads(Path(spec['token_file']).read_text())['token']
        elif spec['credential'] != 'none':
            raise Refused('unknown_private_credential_class')
        headers.update(spec['headers'])
        if 'Transfer-Encoding' not in headers:
            headers['Content-Length'] = str(len(body))
        prefix = f"{spec['method']} {spec['path']} HTTP/1.1\r\n"
        if spec.get('max_namespace_fill'):
            if spec['credential'] != 'none' or spec['method'] != 'POST':
                raise Refused('max_header_case_requires_uncredentialed_redirect')
            current_size = len(prefix) + sum(len(f'{k}: {v}\r\n') for k, v in headers.items()) + 2
            namespace_size = 16 * 1024 + 4 - current_size - len('X-Vault-Namespace: \r\n')
            if namespace_size <= 0:
                raise Refused('max_header_case_shape')
            headers['X-Vault-Namespace'] = 'n' * namespace_size
        request_header_bytes = len(prefix) + sum(len(f'{k}: {v}\r\n') for k, v in headers.items()) + 2
        if spec.get('max_namespace_fill') and request_header_bytes != 16 * 1024 + 4:
            raise Refused('max_header_case_exact_boundary')
        summary['request_header_bytes'] = request_header_bytes
        # Mark ambiguous dispatch conservatively before any request bytes.
        sent = True
        phase = 'request_dispatch'
        connection.putrequest(spec['method'], spec['path'], skip_host=True, skip_accept_encoding=True)
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.endheaders(body, encode_chunked=spec.get('encode_chunked', False))
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
                       response_end='complete_content_length' if response.getheader('Content-Length') is not None else 'complete_http_body',
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


def verify_artifacts() -> dict:
    if not all(isinstance(v, str) and re.fullmatch('[0-9a-f]{40}', v) for v in (COMMIT, TREE)):
        raise Refused('explicit_source_commit_and_tree_pins_required')
    for value in (EXPECTED_SHA, EXPECTED_BUILD_RESULT, EXPECTED_NATIVE_RECEIPT):
        if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
            raise Refused('explicit_independent_artifact_pins_required')
    paths = {'binary': ARTIFACTS/'heptabao-server', 'result': BUILD/'result.public.json',
             'receipt': BUILD/'native-build.public.json'}
    expected = {'binary': EXPECTED_SHA, 'result': EXPECTED_BUILD_RESULT, 'receipt': EXPECTED_NATIVE_RECEIPT}
    for name, path in paths.items():
        regular(path)
        if digest(path) != expected[name]:
            raise Refused('normal_artifact_digest_mismatch')
    result, receipt = [json.loads(paths[n].read_text()) for n in ('result', 'receipt')]
    for record in (result, receipt):
        if (record.get('source_commit') != COMMIT or record.get('source_tree') != TREE
                or record.get('source_freeze_verified') is not True or record.get('build_exit_code') != 0
                or record.get('native_abi') != 'aarch64-apple-darwin'):
            raise Refused('normal_build_source_binding_mismatch')
    artifact = result['artifacts']['heptabao-server']
    features = ['default', 'native-v6-ha', 'native-v6-storage']
    profile = artifact['profile']
    if (result.get('normal_default_candidate') is not True or result.get('timed_out') is not False
            or result.get('owned_group_survivors_after_wait') is not False
            or artifact['path'] != str(paths['binary']) or artifact['sha256'] != EXPECTED_SHA
            or artifact['bytes'] != paths['binary'].stat().st_size or sorted(artifact['features']) != features
            or str(profile.get('opt_level')) != '3' or profile.get('debug_assertions') is not True
            or profile.get('overflow_checks') is not True or profile.get('test') is not False
            or receipt.get('binary_sha256') != EXPECTED_SHA
            or receipt.get('provenance', {}).get('result_sha256') != EXPECTED_BUILD_RESULT):
        raise Refused('normal_default_release_profile_mismatch')
    return {'binary_sha256': EXPECTED_SHA, 'build_result_sha256': EXPECTED_BUILD_RESULT,
            'native_receipt_sha256': EXPECTED_NATIVE_RECEIPT, 'features': features, 'profile': profile}


def source_and_fences() -> dict:
    def git(*args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(SOURCE), *args],
                                       text=True, timeout=10).strip()
    if git('rev-parse', 'HEAD') != COMMIT or git('rev-parse', 'HEAD^{tree}') != TREE or git('status', '--porcelain'):
        raise Refused('frozen_normal_source_changed')
    return {'source_commit': COMMIT, 'source_tree': TREE, 'source_clean': True}


def check_prepared(binary: Path, work: Path) -> dict:
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise Refused('normal_artifact_native_host_abi_required')
    if binary != ARTIFACTS/'heptabao-server' or work.parent != BASE or not re.fullmatch(r'http-compat-standby-live-r[0-9]+', work.name):
        raise Refused('explicit_owned_fresh_paths_required')
    if any(c.isspace() for c in str(binary)+str(work)) or work.exists() or work.is_symlink():
        raise Refused('fresh_ascii_argv_safe_work_root_required')
    regular(OPENSSL)
    if digest(OPENSSL) != OPENSSL_SHA:
        raise Refused('pinned_openssl_changed')
    artifacts = verify_artifacts()
    before = source_and_fences()
    for port in [*API_PORTS.values(), *CLUSTER_PORTS.values()]:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', port))
    return {'binary': str(binary), 'binary_sha256': EXPECTED_SHA, 'binary_bytes': binary.stat().st_size,
            'artifacts': artifacts, **before, 'controller_sha256': digest(Path(__file__)),
            'work_root': str(work), 'api_ports': API_PORTS, 'cluster_ports': CLUSTER_PORTS,
            'loopback_only': True, 'http_seconds': HTTP_SECONDS, 'readiness_seconds': READINESS_SECONDS,
            'election_seconds': ELECTION_SECONDS, 'stable_leader_seconds': STABLE_LEADER_SECONDS,
            'max_response_bytes': MAX_RESPONSE, 'redirect_following': False, 'valid_restore_bodies': 0,
            'old_generations_reopened': False, 'physical_hosts': 1,
            'openssl_sha256': OPENSSL_SHA, 'production_services_touched': False,
            'fixture_product_features': False}


class Fixture:
    def __init__(self, binary: Path, root: Path, prepared: dict):
        self.binary, self.root, self.prepared = binary, root, prepared
        self.seq, self.procs, self.observations, self.checks = 0, [], [], []
        self.clients, self.seed_cleanup, self.cases = [], [], []
        self.actual_leader = None
        self.created_root = False
        self.creating_child = False
        self.pending_signal = None
        self.private = root / 'private'
        self.public = root / 'operations'
        self.outcome_unknown = False
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
                parent_deadline_ns: int | None = None, encode_chunked: bool = False,
                max_namespace_fill: bool = False) -> tuple[dict, bytes]:
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
        intent = {'sequence': self.seq, 'node': node, 'method': method, 'route': path.split('?')[0],
                  'target_bytes': len(path), 'target_sha256': hashlib.sha256(path.encode()).hexdigest(),
                  'label': label, 'credential_class': credential, 'body_bytes': len(payload),
                  'body_sha256': hashlib.sha256(payload).hexdigest(),
                  'headers': headers or {}, 'header_names': sorted((headers or {}).keys()),
                  'http_seconds': HTTP_SECONDS,
                  'encode_chunked': encode_chunked, 'max_namespace_fill': max_namespace_fill,
                  'deadline_monotonic_ns': until, 'parent_deadline_monotonic_ns': parent_deadline_ns,
                  'intent_unix_ns': time.time_ns(),
                  'redirect_following': False, 'valid_restore_body': False}
        write_json(self.public / f'{number}.intent.public.json', intent)
        spec = dict(port=API_PORTS[node], method=method, path=path, credential=credential,
                    body_file=str(body_file), response_meta_file=str(meta_file),
                    response_body_file=str(response_file), content_type=content_type,
                    headers=headers or {}, ca_file=str(self.root / 'ca.crt'),
                    bootstrap_file=str(self.private / 'bootstrap.json'), deadline_monotonic_ns=until,
                    token_file=str(self.private / (credential + '.token.json')),
                    encode_chunked=encode_chunked, max_namespace_fill=max_namespace_fill,
                    expected_leaf_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert(
                        (self.root / f'node{node}/tls.crt').read_text())).hexdigest())
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
            # Actual tracked Popen ownership remains valid even if a short
            # client exits before the independent ps observation can complete.
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

    @staticmethod
    def control_headers(node):
        # Setup/role controls are explicit. Business calls retain their exact
        # fixed-oracle headers, including the absence of this control.
        return {'X-Vault-Inconsistent': 'fail'} if node == 3 else None

    def ready(self, node: int, *, initialized: bool | None = None, sealed: bool | None = None) -> dict:
        until = time.monotonic_ns() + int(READINESS_SECONDS * 1e9)
        while time.monotonic_ns() < until:
            o, b = self.request(node, 'GET', '/v1/sys/health?standbyok=true',
                                'readiness', credential='none', allow_preconnect_failure=True,
                                headers=self.control_headers(node), parent_deadline_ns=until)
            if o['response_complete']:
                h = json.loads(b)
                if (time.monotonic_ns() < until
                        and (initialized is None or h.get('initialized') is initialized)
                        and (sealed is None or h.get('sealed') is sealed)):
                    return h
            time.sleep(min(0.1, max(0.0, (until - time.monotonic_ns()) / 1e9)))
        raise Refused('original_readiness_deadline')

    def roles(self, label: str) -> dict:
        records = {}
        for n in API_PORTS:
            o, b = self.request(n, 'GET', '/v1/sys/leader', label, credential='none',
                                headers=self.control_headers(n))
            self.check(f'{label}_node_{n}_leader_response', o['status'] == 200)
            d = json.loads(b)
            h, hb = self.request(n, 'GET', '/v1/sys/health?standbyok=true', label + '_health', credential='none',
                                 headers=self.control_headers(n))
            health = json.loads(hb)
            records[n] = {'is_self': d.get('is_self'), 'ha_enabled': d.get('ha_enabled'),
                          'leader_node': next((i for i, p in API_PORTS.items()
                              if d.get('leader_address') == f'https://127.0.0.1:{p}'), None),
                          'performance_standby': d.get('performance_standby'),
                          'raft_committed_index': d.get('raft_committed_index'),
                          'raft_applied_index': d.get('raft_applied_index'),
                          'health_status': h['status'],
                          'health': {name: health.get(name) for name in
                              ('initialized', 'sealed', 'standby', 'ha_active', 'ha_application_ready', 'recovery_required')}}
            self.check(f'{label}_node_{n}_unsealed_ha', d.get('ha_enabled') is True
                       and health.get('initialized') is True and health.get('sealed') is False)
        leaders = [n for n, r in records.items() if r['is_self'] is True]
        self.check(label + '_single_actual_leader', len(leaders) == 1)
        leader = leaders[0]
        self.check(label + '_all_report_same_leader', all(r['leader_node'] == leader for r in records.values()))
        self.check(label + '_health_agrees_with_actual_roles', all(
            r['health']['ha_active'] is (n == leader) and r['health']['standby'] is (n != leader)
            for n, r in records.items()))
        result = {'label': label, 'actual_leader': leader, 'nodes': records,
                  'role_observation_does_not_grant_application_authority': True}
        write_json(self.root / (label + '.public.json'), result)
        return result

    def stable_leader(self, *, sealed: bool) -> int:
        until = time.monotonic_ns() + int(ELECTION_SECONDS * 1e9)
        candidate, since = None, 0
        while time.monotonic_ns() < until:
            active = []
            for node in API_PORTS:
                if time.monotonic_ns() >= until:
                    raise Refused('original_stable_election_deadline')
                o, b = self.request(node, 'GET', '/v1/sys/health',
                                    'sealed_election' if sealed else 'unsealed_election', credential='none',
                                    headers=self.control_headers(node), parent_deadline_ns=until)
                h = json.loads(b)
                if h.get('sealed') is not sealed:
                    raise Refused('election_seal_state_changed')
                if h.get('ha_active') is True and h.get('standby') is False:
                    if not sealed and h.get('ha_application_ready') is not True:
                        continue
                    active.append(node)
            if len(active) > 1:
                raise Refused('multiple_actual_leaders')
            observed = active[0] if active else None
            now = time.monotonic_ns()
            if now >= until:
                break
            if observed is not None:
                if observed == candidate and now - since >= int(STABLE_LEADER_SECONDS * 1e9):
                    return observed
                if observed != candidate:
                    candidate, since = observed, now
            else:
                candidate, since = None, 0
            time.sleep(min(0.1, max(0.0, (until - time.monotonic_ns()) / 1e9)))
        raise Refused('original_stable_election_deadline')

    def raft_observation(self, label: str) -> None:
        o, b = self.request(self.actual_leader, 'GET', '/v1/sys/storage/raft/autopilot/state', label)
        data = json.loads(b).get('data', {})
        servers = data.get('servers', {}) if isinstance(data, dict) else {}
        aliases = {str(n): n for n in API_PORTS}
        aliases.update({f'owned-normal33-node{n}': n for n in API_PORTS})
        projected = []
        unknown_peer_names = 0
        if isinstance(servers, dict):
            for ident, value in servers.items():
                if ident not in aliases or not isinstance(value, dict):
                    unknown_peer_names += 1
                    continue
                projected.append({'node': aliases[ident], 'node_status': value.get('node_status'),
                                  'status': value.get('status'), 'healthy': value.get('healthy'),
                                  'last_term': value.get('last_term'), 'last_index': value.get('last_index')})
        write_json(self.root / (label + '.public.json'),
                   {'status': o['status'], 'leader_node': aliases.get(data.get('leader')),
                    'healthy': data.get('healthy'), 'observed_servers': projected,
                    'unknown_peer_names_count': unknown_peer_names,
                    'expected_nodes': [1, 2, 3], 'observation_only_no_term_inference': True})

    def openssl(self, args: list[str], label: str) -> None:
        r = subprocess.run([str(OPENSSL), *args], cwd=self.root,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        write_new(self.private / (label + '.openssl.stdout'), r.stdout)
        write_new(self.private / (label + '.openssl.stderr'), r.stderr)
        if r.returncode:
            raise Refused('fixture_tls_generation_failed')

    def spawn(self, node: int, *, native: bool) -> tuple[subprocess.Popen, dict]:
        directory = self.root / f'node{node}'
        kind = 'native' if native else 'seed'
        argv = [str(self.binary), '--config', str(directory / f'server-{kind}.json')]
        if native:
            argv += ['--ha-config', str(directory / 'ha.json')]
        with (directory / f'{kind}.stdout.private.log').open('xb') as out, (directory / f'{kind}.stderr.private.log').open('xb') as err:
            p = self.start_owned_child(self.procs, argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                 start_new_session=True, env={'PATH': '/usr/bin:/bin'})
            ident = process_identity(p.pid)
            if ident is None:
                raise Refused('owned_server_identity_unavailable')
            self.procs[-1] = (p, ident)
            # Popen ownership is retained while the kernel exec identity settles.
            # The exact process/start identity, group, executable and argv gate
            # still must all succeed before any HTTP request is issued.
            captured_ticks = ident['start_identity']
            probe_until = time.monotonic() + 1.0
            attempts = 0
            while True:
                attempts += 1
                current = process_identity(p.pid)
                if current is None or current['start_identity'] != captured_ticks:
                    raise Refused('owned_server_identity_changed_during_exec_observation')
                ident = current
                actual_argv = process_argv(p.pid)
                group_ok = ident['pgid'] == p.pid
                executable_ok = ident['exe'] == str(self.binary)
                argv_ok = actual_argv == [x.encode() for x in argv]
                if group_ok and executable_ok and argv_ok:
                    break
                if time.monotonic() >= probe_until or p.poll() is not None:
                    write_json(directory / f'{kind}.exec-refusal.public.json', {
                        'group_matches': group_ok, 'executable_matches': executable_ok,
                        'argv_matches': argv_ok, 'attempts': attempts,
                        'argv_entry_lengths': [len(x) for x in actual_argv],
                        'argv_sha256': hashlib.sha256(b'\0'.join(actual_argv)).hexdigest(),
                        'expected_argv_sha256': hashlib.sha256(b'\0'.join(x.encode() for x in argv)).hexdigest()})
                    raise Refused('owned_server_exact_argv_or_executable_mismatch')
                time.sleep(0.01)
            self.procs[-1] = (p, ident)
        write_json(directory / f'{kind}.identity.public.json', ident)
        return p, ident

    def cold_clone(self) -> None:
        source = self.root / 'node1/state'
        def inventory(root):
            entries = []
            for p in sorted(root.rglob('*')):
                st = p.lstat()
                if stat.S_ISDIR(st.st_mode):
                    continue
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid():
                    raise Refused('owned_seed_nonregular_or_foreign_file')
                entries.append({'path': p.relative_to(root).as_posix(), 'bytes': st.st_size, 'sha256': digest(p)})
            if not entries:
                raise Refused('cold_seed_empty')
            return entries
        baseline = inventory(source)
        def copy_owned(src, dst):
            with open(src, 'rb') as a, open(dst, 'xb') as b:
                shutil.copyfileobj(a, b, 1024 * 1024)
                b.flush()
                os.fsync(b.fileno())
            os.chmod(dst, 0o600)
            return dst
        for n in (2, 3):
            dest = self.root / f'node{n}/state'
            shutil.copytree(source, dest, copy_function=copy_owned, symlinks=False)
            for directory, _, _ in os.walk(dest, topdown=False):
                os.chmod(directory, 0o700)
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            fd = os.open(dest.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            self.check(f'node{n}_stopped_seed_exact_clone', inventory(dest) == baseline)
        self.check('stopped_seed_source_unchanged', inventory(source) == baseline)
        write_json(self.private / 'cold-seed-files.json', baseline)
        write_json(self.root / 'cold-seed.public.json', {
            'source_owned_stopped': bool(self.seed_cleanup) and self.seed_cleanup[0]['owned_stopped'],
            'files': len(baseline), 'total_bytes': sum(x['bytes'] for x in baseline),
            'inventory_sha256': hashlib.sha256(json.dumps(baseline, sort_keys=True).encode()).hexdigest(),
            'clones': [2, 3], 'all_files_exact': True, 'no_old_generation_read': True})

    def setup(self) -> None:
        self.root.mkdir(mode=0o700)
        self.created_root = True
        self.private.mkdir(mode=0o700)
        self.public.mkdir(mode=0o700)
        write_json(self.root / 'prepared.public.json', self.prepared)
        self.openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
                      '-subj', '/CN=Owned normal33 standby oracle CA', '-keyout', 'ca.key',
                      '-out', 'ca.crt', '-addext', 'basicConstraints=critical,CA:TRUE',
                      '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                      '-addext', 'subjectKeyIdentifier=hash', '-addext', 'authorityKeyIdentifier=keyid:always'], 'ca')
        servers, peers = {}, {}
        for n in API_PORTS:
            node = self.root / f'node{n}'
            node.mkdir(mode=0o700)
            name = f'owned-normal33-node{n}'
            self.openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
                          '-subj', f'/CN={name}', '-keyout', f'node{n}/tls.key',
                          '-out', f'node{n}/tls.csr'], f'node{n}-csr')
            extension = ('basicConstraints=critical,CA:FALSE\n'
                         f'subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:{name}\n'
                         'keyUsage=critical,digitalSignature,keyEncipherment\n'
                         'extendedKeyUsage=serverAuth,clientAuth\n'
                         'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
            write_new(node / 'extensions.cnf', extension.encode())
            self.openssl(['x509', '-req', '-in', f'node{n}/tls.csr', '-CA', 'ca.crt',
                          '-CAkey', 'ca.key', '-set_serial', str(n), '-days', '1', '-sha256',
                          '-extfile', f'node{n}/extensions.cnf', '-out', f'node{n}/tls.crt'], f'node{n}-cert')
            servers[n] = {'listen': f'127.0.0.1:{API_PORTS[n]}', 'data_dir': str(node / 'state'),
                          'audit_file': str(node / 'audit.jsonl'), 'tls_cert_file': str(node / 'tls.crt'),
                          'tls_key_file': str(node / 'tls.key'), 'max_connections': 64,
                          'timeout_seconds': int(HTTP_SECONDS), 'rate_limit_per_second': 2000,
                          'rate_limit_burst': 4000, 'rate_limit_entries': 512, 'lifecycle_interval_seconds': 1}
            peers[str(n)] = {'node_name': name, 'address': f'127.0.0.1:{CLUSTER_PORTS[n]}',
                            'cluster_address': f'https://127.0.0.1:{CLUSTER_PORTS[n]}',
                            'api_address': f'https://127.0.0.1:{API_PORTS[n]}', 'server_name': name,
                            'certificate_sha256': hashlib.sha256(ssl.PEM_cert_to_DER_cert((node / 'tls.crt').read_text())).hexdigest()}
        write_json(self.root / 'node1/server-seed.json', servers[1])
        seed, seed_id = self.spawn(1, native=False)
        self.ready(1, initialized=False, sealed=True)
        o, b = self.request(1, 'POST', '/v1/sys/init', 'seed_initialize_once',
                            body={'secret_shares': 1, 'secret_threshold': 1}, credential='none')
        self.check('seed_initialize_complete', o['status'] == 200)
        bootstrap = json.loads(b)
        self.check('seed_exact_single_unseal_share', isinstance(bootstrap.get('root_token'), str)
                   and isinstance(bootstrap.get('keys_base64'), list) and len(bootstrap['keys_base64']) == 1)
        write_json(self.private / 'bootstrap.json', bootstrap)
        o, b = self.request(1, 'POST', '/v1/sys/unseal', 'seed_unseal_once',
                            body={'key': bootstrap['keys_base64'][0]}, credential='none')
        self.check('seed_unseal_complete', o['status'] == 200 and json.loads(b).get('sealed') is False)
        self.ready(1, initialized=True, sealed=False)
        o, _ = self.request(1, 'POST', '/v1/sys/mounts/wire', 'seed_mount_kv2_once',
                            body={'type': 'kv', 'options': {'version': '2'}})
        self.check('seed_mount_kv2_created', o['status'] in (200, 204))
        for version in (1, 2):
            o, b = self.request(1, 'POST', '/v1/wire/data/seed', f'seed_version_{version}_once',
                                body={'options': {'cas': version - 1}, 'data': {'marker': f'normal33-wire-seed-{version}'}})
            self.check(f'seed_version_{version}_acknowledged_once', o['status'] == 200 and json.loads(b)['data']['version'] == version)
        o, b = self.request(1, 'GET', '/v1/sys/internal/capacity', 'seed_capacity')
        self.check('actual_v5_seed', o['status'] == 200 and json.loads(b)['data']['state_storage_format'] == 'heptabao-state-records-v5')
        o, b = self.request(1, 'GET', '/v1/sys/health', 'seed_cluster_identity', credential='none')
        cluster_id = json.loads(b).get('cluster_id')
        self.check('fresh_cluster_identity', o['status'] == 200 and isinstance(cluster_id, str) and bool(cluster_id))
        self.seed_cleanup.append(stop_owned(seed, seed_id))
        self.check('seed_reaped_before_cold_copy', self.seed_cleanup[-1]['owned_stopped'])
        self.cold_clone()
        replication = os.urandom(32)
        for n in API_PORTS:
            node = self.root / f'node{n}'
            write_new(node / 'replication.key', replication)
            write_new(node / 'ca.crt', (self.root / 'ca.crt').read_bytes())
            ha = {'node_id': n, 'cluster_id': cluster_id, 'raft_dir': str(node / 'raft'),
                  'listen': f'127.0.0.1:{CLUSTER_PORTS[n]}', 'ca_file': str(node / 'ca.crt'),
                  'cert_file': str(node / 'tls.crt'), 'key_file': str(node / 'tls.key'),
                  'replication_key_file': str(node / 'replication.key'), 'peers': peers, 'bootstrap': n == 1,
                  'peer_timeout_ms': 1500, 'forward_timeout_ms': 8000, 'max_inflight': 32}
            native = dict(servers[n])
            if n == 3:
                native['consistency_missing_header_forward'] = True
            native['storage'] = {'native_v6_raft': {'path': str(node), 'node_id': peers[str(n)]['node_name'],
                                'cluster_addr': peers[str(n)]['cluster_address'], 'api_addr': peers[str(n)]['api_address']}}
            write_json(node / 'server-native.json', native)
            write_json(node / 'ha.json', ha)
        for n in (2, 3, 1):
            self.spawn(n, native=True)
        for n in API_PORTS:
            self.ready(n, initialized=True, sealed=True)
        self.stable_leader(sealed=True)
        for n in API_PORTS:
            o, b = self.request(n, 'POST', '/v1/sys/unseal', f'node{n}_native_unseal_once',
                                body={'key': bootstrap['keys_base64'][0]}, credential='none',
                                headers=self.control_headers(n))
            self.check(f'node{n}_native_unseal_complete', o['status'] == 200 and json.loads(b).get('sealed') is False)
        self.actual_leader = self.stable_leader(sealed=False)
        o, _ = self.request(self.actual_leader, 'POST', '/v1/sys/storage/native-v6/activate',
                            'native_v6_activate_once', body={})
        self.check('native_v6_activate_complete', o['status'] == 204)
        o, b = self.request(self.actual_leader, 'GET', '/v1/sys/internal/capacity', 'native_v6_capacity')
        cap = json.loads(b).get('data', {})
        self.check('actual_normal_native_v6', o['status'] == 200
                   and cap.get('state_storage_format') == 'heptabao-state-records-v6'
                   and cap.get('native_kv2_reader_format') == 2 and type(cap.get('generation')) is int)
        write_json(self.root / 'native-capacity.public.json', {'node': self.actual_leader,
            'state_storage_format': cap['state_storage_format'], 'native_kv2_reader_format': cap['native_kv2_reader_format'],
            'generation': cap['generation']})
        for n in API_PORTS:
            for version in (1, 2):
                o, b = self.request(n, 'GET', f'/v1/wire/data/seed?version={version}', f'node{n}_native_seed_version_{version}',
                                    headers=self.control_headers(n))
                value = json.loads(b).get('data', {})
                self.check(f'node{n}_actual_native_seed_version_{version}', o['status'] == 200
                           and value.get('data') == {'marker': f'normal33-wire-seed-{version}'}
                           and value.get('metadata', {}).get('version') == version)

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
                'scope': 'bounded archive shape only', 'restore_attempted': False,
                'openbao_archive_or_restore_compatibility_proven': False,
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
        if label not in OFFICIAL_STATUS:
            raise Refused('unlisted_scoped_business_case')
        o, raw = self.request(node, method, path, label, credential=credential,
                              headers=headers, body=body, raw_body=raw_body, content_type=content_type)
        row = {'kind': 'scoped_status_case', 'node': node, 'method': method, 'route': path,
               'credential_class': credential, 'headers': headers or {},
               'expected_status': OFFICIAL_STATUS[label],
               'official_reference_verified': label not in UNVERIFIED_REFERENCE_LABELS,
               'same_status_as_official_default': o['status'] == OFFICIAL_STATUS[label], **o}
        # Persist every completed business observation even if a later shape,
        # effect, cleanup or coverage check fails.
        self.cases.append(row)
        if o['status'] == 307:
            self.check(label + '_complete_exact_redirect', o['location_node'] == 1
                       and o['location_matches_enrolled_origin_and_exact_target']
                       and o['header_wire_has_terminal_crlf']
                       and o['content_length'] == '0' and raw == b'')
        if o['status'] == 200 and path.endswith('/snapshot'):
            row['archive_shape'] = self.snapshot_shape(raw)
            self.check(label + '_bounded_archive_shape',
                       row['archive_shape']['sealed_hashes_nonempty'])
        if o['status'] == 200 and path == '/v1/owned/data/read-marker':
            self.check(label + '_exact_kv_value',
                       json.loads(raw).get('data', {}).get('data') == {'marker': 'owned-policy-oracle'})
        return o, raw

    def observe(self) -> None:
        before = self.roles('roles_before')
        self.check('actual_initial_leader', before['actual_leader'] == 1
                   and self.actual_leader == 1)
        self.raft_observation('raft_before')
        o, _ = self.request(1, 'POST', '/v1/sys/mounts/owned', 'owned_kv_mount_once',
                            body={'type': 'kv', 'options': {'version': '2'}})
        self.check('owned_kv_mount_acknowledged', o['status'] in (200, 204))
        o, _ = self.request(1, 'POST', '/v1/owned/data/read-marker', 'owned_kv_write_once',
                            body={'options': {'cas': 0}, 'data': {'marker': 'owned-policy-oracle'}})
        self.check('owned_kv_write_acknowledged', o['status'] == 200)
        initial = self.create_token('ttl-default', 0)
        self.check('ttl_root_unlimited_actual', initial['status'] == 200
                   and initial['num_uses'] == 0 and type(initial['ttl']) is int
                   and 0 < initial['ttl'] <= 600)
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
                       (o['status'] >= 300 and effect['status'] == 404)
                       or (o['status'] == 200 and effect['status'] == 200
                           and json.loads(raw).get('data', {}).get('data') == {'marker': suffix}))
        self.observed(2, 'GET', '/v1/sys/storage/raft/snapshot',
                      'ttl_root_default_standby_snapshot', credential='ttl-default')
        self.observed(2, 'POST', '/v1/sys/storage/raft/snapshot',
                      'ttl_root_default_standby_invalid_restore', credential='ttl-default',
                      raw_body=b'owned-invalid-snapshot', content_type='application/octet-stream')
        for uses in (1, 2):
            label = f'finite{uses}-default'
            before = self.create_token(label, uses)
            self.check(label + '_actual_finite_uses_before',
                       before['status'] == 200 and before['num_uses'] == uses)
            self.observed(2, 'GET', '/v1/sys/storage/raft/snapshot',
                          f'finite{uses}_default_snapshot', credential=label)
            after = self.lookup_token(label, 'after')
            self.check(label + '_not_spent_by_standby_redirect',
                       after['status'] == 200 and after['num_uses'] == uses)
        for label in ('ttl-default', 'snapshot-read', 'snapshot-update',
                      'finite1-default', 'finite2-default'):
            token = json.loads((self.private / (label + '.token.json')).read_text())['token']
            o, _ = self.request(1, 'POST', '/v1/auth/token/revoke', label + '_revoke_once',
                                body={'token': token})
            self.check(label + '_revocation_acknowledged', o['status'] == 204)
        after = self.roles('roles_after')
        self.check('actual_leader_unchanged', after['actual_leader'] == 1)
        self.raft_observation('raft_after')

    def finish(self, failed: str | None) -> int:
        coverage = scoped_coverage(self.cases)
        wire_error, wire_sha256 = None, None
        wire = {'schema': 'heptabao-normal-standby-scoped-wire-r4',
                'cases': self.cases, 'coverage': coverage,
                'default_read_standby_node': 2,
                'consistency_missing_header_forward_node': 3,
                'physical_hosts': 1, 'process_nodes': 3,
                'qualification': 'scoped status observation; no full replacement qualification',
                'archive_scope': 'bounded shape only; no restore or format compatibility proof',
                'official_policy_wire_sha256': 'd1f40a22db1a2e1b53e282191976e4eb44d96cd870ec046b91c31f891da58cf0',
                'official_token_wire_sha256': '070f7234092f9799b85af95f600e1d0519ddc9c3ed81f132e21ef2af86f7cf97',
                'official_token_wire_covers_only': ['ttl_root_default_standby_snapshot',
                    'finite1_default_snapshot', 'finite2_default_snapshot'],
                'official_ttl_restore_wire_sha256': 'cd035b00b7d382d9966652774281b18840b99ce77ad9adc7d10a8f3e2b3ef83b',
                'official_ttl_restore_wire_covers_only': ['ttl_root_default_standby_invalid_restore'],
                'official_reference_complete': OFFICIAL_REFERENCE_COMPLETE,
                'unverified_reference_labels': UNVERIFIED_REFERENCE_LABELS,
                'automatic_redirect_following': False, 'unknown_mutation_replay': False,
                'cold_restart_tested': False, 'full_replacement_qualification': False}
        # This is attempted even after an incomplete setup or business failure.
        # An archive error must never bypass cleanup of owned real processes.
        try:
            write_json(self.root / 'wire-observations.public.json', wire)
            wire_sha256 = digest(self.root / 'wire-observations.public.json')
        except Exception as exc:
            wire_error = type(exc).__name__
        cleanup, client_cleanup = [], []
        for collection, destination in ((self.clients, client_cleanup), (self.procs, cleanup)):
            for p, captured in reversed(collection):
                try:
                    destination.append(stop_owned(p, captured) if captured is not None else stop_provisional(p))
                except Exception as exc:
                    destination.append({'pid': p.pid, 'owned_stopped': False, 'error_type': type(exc).__name__})
        clean = all(item['owned_stopped'] for item in cleanup + client_cleanup)
        after, artifact_after, verification_error = None, None, None
        controller_sha_after = None
        try:
            controller_sha_after = digest(Path(__file__))
            if controller_sha_after != self.prepared['controller_sha256']:
                raise Refused('controller_changed_after_prepare')
            artifact_after = verify_artifacts()
            after = source_and_fences()
        except Exception as exc:
            verification_error = str(exc) if isinstance(exc, Refused) else type(exc).__name__
        incomplete_sequences = sorted(set(range(1, self.seq + 1)) - {o['sequence'] for o in self.observations})
        unknown = sum(bool(o['outcome_unknown']) for o in self.observations) + len(incomplete_sequences)
        complete = (not incomplete_sequences and self.seq == len(self.observations)
                    and unknown == 0 and not self.outcome_unknown)
        status = ('completed_observation' if not failed and not verification_error
                  and not wire_error and clean and complete and coverage['coverage_complete'] else 'failed')
        scoped_pass = status == 'completed_observation' and coverage['scoped_status_compatibility_passed']
        report = {'schema': 'heptabao-normal-standby-scoped-observer-r3', 'prepared': self.prepared,
                  'status': status, 'failure_code': failed, 'verification_error': verification_error,
                  'wire_archive_error': wire_error, 'wire_observations_sha256': wire_sha256,
                  'checks': self.checks, 'checks_total': len(self.checks),
                  'checks_passed': sum(x['passed'] for x in self.checks),
                  'checks_are_dynamic_observation_invariants_not_a_qualification_denominator': True,
                  'coverage': coverage, 'scoped_status_compatibility_passed': scoped_pass,
                  'http_intents': self.seq, 'http_outcomes': len(self.observations),
                  'http_unknown': unknown, 'intent_sequences_without_terminal_outcome': incomplete_sequences,
                  'complete_http_responses': sum(bool(o['response_complete']) for o in self.observations),
                  'preconnect_failures': sum(not o['response_complete'] and o['request_sent'] is False for o in self.observations),
                  'owned_cleanup': cleanup, 'client_cleanup': client_cleanup, 'all_owned_stopped': clean,
                  'source_and_fences_after': after, 'artifacts_after': artifact_after,
                  'controller_sha256_after': controller_sha_after, 'valid_restore_bodies': 0,
                  'terminal_unix_ns': time.time_ns(), 'started_unix_ns': self.started_unix_ns,
                  'elapsed_ms': (time.monotonic_ns() - self.started_monotonic_ns) / 1e6,
                  'operation_boundary_complete': complete, 'physical_hosts': 1,
                  'original_deadlines_preserved': True, 'cold_restart_tested': False,
                  'production_services_touched': False, 'full_replacement_qualification': False,
                  'compatibility_status_differences': coverage['status_differences']}
        write_json(self.root / 'result.public.json', report)
        print(json.dumps({'status': status, 'result': str(self.root / 'result.public.json'),
                          'result_sha256': digest(self.root / 'result.public.json'),
                          'checks_passed': report['checks_passed'], 'checks_total': report['checks_total'],
                          'expected_scoped_cases': coverage['expected_case_count'],
                          'observed_scoped_cases': coverage['observed_case_count'],
                          'scoped_status_compatibility_passed': scoped_pass,
                          'http_intents': self.seq, 'http_outcomes': len(self.observations),
                          'complete_http_responses': report['complete_http_responses'],
                          'preconnect_failures': report['preconnect_failures'],
                          'http_unknown': unknown, 'all_owned_stopped': clean,
                          'compatibility_status_differences': report['compatibility_status_differences']}, sort_keys=True))
        return 0 if status == 'completed_observation' else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', type=Path)
    ap.add_argument('--work-dir', type=Path)
    ap.add_argument('--prepare-only', action='store_true')
    ap.add_argument('--expected-binary-sha256')
    ap.add_argument('--expected-build-result-sha256')
    ap.add_argument('--expected-native-build-sha256')
    ap.add_argument('--expected-source-commit')
    ap.add_argument('--expected-source-tree')
    ap.add_argument('--child-request', type=Path)
    args = ap.parse_args()
    if args.child_request:
        return child_request(args.child_request)
    global EXPECTED_SHA, EXPECTED_BUILD_RESULT, EXPECTED_NATIVE_RECEIPT, COMMIT, TREE
    EXPECTED_SHA = args.expected_binary_sha256
    EXPECTED_BUILD_RESULT = args.expected_build_result_sha256
    EXPECTED_NATIVE_RECEIPT = args.expected_native_build_sha256
    COMMIT = args.expected_source_commit
    TREE = args.expected_source_tree
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
        print(json.dumps({'status': 'failed_before_fixture', 'error_type': type(error).__name__}, sort_keys=True))
        raise SystemExit(2) from None
