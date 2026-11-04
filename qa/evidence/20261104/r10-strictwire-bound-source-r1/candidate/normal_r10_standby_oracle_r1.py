#!/usr/bin/env python3
"""Bounded, fresh, loopback-only normal R10 HeptaBao standby wire observation.

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
from urllib.parse import urlsplit

BASE = Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
EXPECTED_SHA = '67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113'
COMMIT = '49503322c7f446e5eb41e7744f1fdbd7f1192ecc'
TREE = '1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
CONTROL = BASE / 'normal-r10-standby-oracle-control-r1'
SOURCE = BASE / 'normal-r10-validation-source-r1'
ARTIFACTS = CONTROL / 'artifacts'
ARTIFACT_SOURCES = {
    'heptabao-server': (BASE / 'normal-r10-shared-artifacts-r1/incoming/heptabao-server', EXPECTED_SHA),
    'native-build.public.json': (BASE / 'normal-r10-shared-artifacts-r1/incoming/native-build.public.json', '0e3d1ae800820d33f0d5369968cbccbab8fa62b077b142f87c9f52b31cd09c77'),
    'build-result.public.json': (BASE / 'normal-r10-shared-artifacts-r1/incoming/normal-release-result.public.json', '75f858b280249dcc981eee3e4340982a58027e8ca40217244ae029bb8e9011ee'),
}
OLD_FENCES = {
    'normal-r8-standby-oracle-live-r1/result.public.json': '88477fe316686727aca2439ecd839beb2403a607b05ede1e1df63441aef2567b',
    'normal33-standby-oracle-live-r3/result.public.json': 'f5a44d25e6f33e562b492e050242f36cc2744417a13a01db4beab1c0422ae590',
    'normal33-standby-oracle-live-r2/result.public.json': '12cdeb32dc89a7f0af5d1950a2c14a02581a8e98cefd3719c0673a0bd38e68d4',
    'normal33-standby-oracle-live-r2/partial-wire-assessment.public.json': '3172100f22faa9f23992bf8c6f806ead6c20ff8b68f5821203745c86424c74db',
    'formal-33cafa-normal-full128-r2/summary.json': '8f7285ffad498ec0b6eeaca48e255790776a15ec62c218e195cf5e7ce0f2e8f1',
    'formal-33cafa-pocket3-mac1-direct98-r1/summary.json': 'b02a111b487e33065117fc88596113c7e8a7695feb283331165381fafd3c167f',
    'official271-standby-oracle-live-r1/result.public.json': 'd84a783d817ee7827496182b6f750a1cd995424e554b287f602fd9204f289975',
    'official271-standby-oracle-live-r1/wire-observations.public.json': '45d2039f2e68e006cb10dc80925f9d6719fa16dfa433bf22bf5b538e9adfae02',
    'official271-standby-oracle-live-r1/boundary-assessment.public.json': '4588e9f3a8fff060d4ac7ea035f85b5bcf58cc9874e839d9797bc75023068391',
}
NATIVE_LARGE_MEDIA = 'application/vnd.heptabao.kv2-lossless+json'
NATIVE_LARGE_ROUTE = '/v1/sys/migration/openbao/kv2/native-large?mount=wire'
ELECTION_SECONDS = 60.0
STABLE_LEADER_SECONDS = 2.2
HTTP_SECONDS = 15.0
READINESS_SECONDS = 45.0
MAX_RESPONSE = 16 * 1024 * 1024
MAX_RESPONSE_HEADERS = 64 * 1024
API_PORTS = {1: 48630, 2: 48632, 3: 48634}
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


class HeaderLineCapture:
    """Observe only the exact readline calls made by HTTPResponse.begin.

    This does not read ahead, issue an extra socket read, change the socket
    timeout, or infer that bytes accepted by http.client form a complete head.
    Raw bytes are bounded and later written only to the owned private folder.
    """
    def __init__(self, source):
        self.source = source
        self.raw = bytearray()
        self.enabled = True
        self.eof_during_headers = False
        self.line_reads = 0
        self.bound_exceeded = False
        self.chunk_line_mode = None
        self.chunk_size_lines = 0
        self.chunk_size_lines_valid = True
        self.trailer_lines = 0
        self.trailer_bytes = 0
        self.trailer_eof = False
        self.trailer_complete = False
        self.trailer_lines_valid = True

    def readline(self, size=-1):
        line = self.source.readline(size)
        if self.enabled:
            self.line_reads += 1
            if not line:
                self.eof_during_headers = True
            room = MAX_RESPONSE_HEADERS - len(self.raw)
            self.raw.extend(line[:room])
            if len(line) > room:
                self.bound_exceeded = True
                raise Refused('response_header_capture_exceeds_fixed_bound')
        elif self.chunk_line_mode == 'size':
            self.chunk_size_lines += 1
            size = line[:-2].split(b';', 1)[0] if line.endswith(b'\r\n') else b''
            valid = bool(size) and all(byte in b'0123456789abcdefABCDEF' for byte in size)
            self.chunk_size_lines_valid = self.chunk_size_lines_valid and valid
            if not valid:
                raise Refused('response_chunk_size_line_not_hex_crlf')
        elif self.chunk_line_mode == 'trailer':
            self.trailer_lines += 1
            self.trailer_bytes += len(line)
            self.trailer_eof = self.trailer_eof or not line
            self.trailer_complete = self.trailer_complete or line == b'\r\n'
            self.trailer_lines_valid = self.trailer_lines_valid and line.endswith(b'\r\n')
            if self.trailer_bytes > MAX_RESPONSE_HEADERS:
                raise Refused('response_chunk_trailer_exceeds_fixed_header_bound')
        return line

    def __getattr__(self, name):
        return getattr(self.source, name)


class CapturedHTTPResponse(http.client.HTTPResponse):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.header_capture = HeaderLineCapture(self.fp)
        self.fp = self.header_capture
        self.chunk_delimiter_pending = False
        self.chunk_delimiters = 0
        self.chunk_delimiters_valid = True
        self.zero_chunks = 0

    def begin(self):
        try:
            return super().begin()
        finally:
            self.header_capture.enabled = False

    # Observe the stdlib's existing reads. These methods never ask the socket
    # for extra bytes, replace its parser, or change the original timeout.
    def _get_chunk_left(self):
        self.chunk_delimiter_pending = self.chunk_left == 0
        try:
            return super()._get_chunk_left()
        finally:
            self.chunk_delimiter_pending = False

    def _safe_read(self, amount):
        raw = super()._safe_read(amount)
        if self.chunk_delimiter_pending:
            self.chunk_delimiter_pending = False
            self.chunk_delimiters += 1
            valid = amount == 2 and raw == b'\r\n'
            self.chunk_delimiters_valid = self.chunk_delimiters_valid and valid
            if not valid:
                raise Refused('response_chunk_data_delimiter_not_crlf')
        return raw

    def _read_next_chunk_size(self):
        self.header_capture.chunk_line_mode = 'size'
        try:
            size = super()._read_next_chunk_size()
            if size == 0:
                self.zero_chunks += 1
            return size
        finally:
            self.header_capture.chunk_line_mode = None

    def _read_and_discard_trailer(self):
        self.header_capture.chunk_line_mode = 'trailer'
        try:
            return super()._read_and_discard_trailer()
        finally:
            self.header_capture.chunk_line_mode = None

    def chunk_framing_projection(self):
        capture = self.header_capture
        complete = (self.zero_chunks == 1 and capture.chunk_size_lines >= 1
                    and self.chunk_delimiters == capture.chunk_size_lines - 1
                    and self.chunk_delimiters_valid and capture.chunk_size_lines_valid
                    and capture.trailer_complete and not capture.trailer_eof
                    and capture.trailer_lines_valid and capture.trailer_bytes <= MAX_RESPONSE_HEADERS)
        return {'chunk_size_lines': capture.chunk_size_lines,
                'chunk_size_lines_valid': capture.chunk_size_lines_valid,
                'chunk_data_delimiters': self.chunk_delimiters,
                'chunk_data_delimiters_valid': self.chunk_delimiters_valid,
                'zero_chunk_count': self.zero_chunks,
                'trailer_lines': capture.trailer_lines,
                'trailer_bytes': capture.trailer_bytes,
                'trailer_eof': capture.trailer_eof,
                'trailer_terminated_crlf': capture.trailer_complete,
                'trailer_lines_valid': capture.trailer_lines_valid,
                'chunked_framing_complete': complete}


def safe_response_head_projection(response, target: str) -> dict:
    capture = response.header_capture
    raw = bytes(capture.raw)
    fields = response.headers.get_all('Location', []) if response.headers is not None else []
    target_parts = urlsplit(target)
    projections = []
    for value in fields:
        encoded = value.encode('iso-8859-1')
        projected = {
            'value_bytes': len(encoded), 'value_sha256': hashlib.sha256(encoded).hexdigest(),
            'printable_ascii_uri': bool(value) and all(33 <= ord(c) <= 126 for c in value),
            'parse_succeeded': False, 'enrolled_origin_node': None,
            'enrolled_origin_exact_match': False, 'requested_path_exact_match': False,
            'requested_query_exact_match': False, 'known_route': 'other',
            'scheme_is_https': False, 'userinfo_present': False, 'fragment_present': False,
        }
        if projected['printable_ascii_uri']:
            try:
                parts = urlsplit(value)
                # Parsing is observational. No parsed location is ever opened.
                origin = parts.scheme + '://' + parts.netloc
                node = next((n for n, port in API_PORTS.items()
                             if origin == f'https://127.0.0.1:{port}'
                             and value.startswith(origin)), None)
                route = {'/v1/sys/storage/raft/snapshot': 'snapshot',
                         '/v1/sys/storage/raft/snapshot-force': 'snapshot_force',
                         '/v1/sys/storage/raft/snapshot-repair': 'snapshot_repair'}.get(parts.path, 'other')
                projected.update(parse_succeeded=True, enrolled_origin_node=node,
                                 enrolled_origin_exact_match=node is not None,
                                 requested_path_exact_match=parts.path == target_parts.path,
                                 requested_query_exact_match=parts.query == target_parts.query,
                                 known_route=route, scheme_is_https=parts.scheme == 'https',
                                 userinfo_present='@' in parts.netloc, fragment_present=bool(parts.fragment))
            except ValueError:
                pass
        projections.append(projected)
    return {'response_header_bytes': len(raw), 'response_header_sha256': hashlib.sha256(raw).hexdigest(),
            'response_header_line_reads': capture.line_reads,
            'response_header_capture_bound_exceeded': capture.bound_exceeded,
            'response_header_eof_during_headers': capture.eof_during_headers,
            'response_header_ends_crlf_crlf': raw.endswith(b'\r\n\r\n'),
            'response_header_strict_termination': bool(raw) and raw.endswith(b'\r\n\r\n')
                and not capture.eof_during_headers and not capture.bound_exceeded,
            'location_header_count': len(fields),
            'location_distinct_value_count': len(set(fields)),
            'location_projections': projections,
            'raw_response_head_private_only': True}


def response_body_framing(response, method: str) -> dict:
    """Project only closed framing facts, never arbitrary field values."""
    lengths = response.headers.get_all('Content-Length', [])
    encodings = response.headers.get_all('Transfer-Encoding', [])
    length = lengths[0].strip(' \t') if len(lengths) == 1 else None
    numeric = (length is not None and bool(length) and length.isascii()
               and all('0' <= char <= '9' for char in length))
    # The capture already caps the header. Avoid converting an attacker-sized
    # integer; even the longest admissible response has at most eight digits.
    digits = (length.lstrip('0') or '0') if numeric else None
    bounded_integer = digits is not None and len(digits) <= len(str(MAX_RESPONSE))
    declared = int(digits) if bounded_integer else None
    chunked = (len(encodings) == 1 and encodings[0].strip(' \t').lower() == 'chunked')
    body_forbidden = method == 'HEAD' or response.status in (204, 304) or 100 <= response.status < 200
    ambiguous = (len(lengths) > 1 or len(encodings) > 1 or bool(lengths and encodings)
                 or bool(lengths) and not numeric or bool(encodings) and not chunked)
    # A 204 has no message body or framing field. HEAD/304 may describe the
    # selected representation's length without transferring those bytes.
    invalid_204 = response.status == 204 and bool(lengths or encodings)
    exceeds_bound = bool(lengths) and not body_forbidden and (declared is None or declared > MAX_RESPONSE)
    mode = ('no_body' if body_forbidden else 'fixed_length' if lengths else
            'chunked' if encodings else 'close_delimited')
    return {'content_length_header_count': len(lengths),
            'transfer_encoding_header_count': len(encodings),
            'content_length_is_single_decimal': len(lengths) == 1 and numeric,
            'content_length_is_within_response_bound': declared is not None and declared <= MAX_RESPONSE,
            'declared_content_length': declared,
            'body_framing_mode': mode,
            'body_expected_bytes': 0 if body_forbidden else declared,
            'body_framing_ambiguous': ambiguous,
            'body_framing_valid': not ambiguous and not invalid_204 and not exceeds_bound}


def child_request(spec_path: Path) -> int:
    """One exchange.  The parent also enforces the same absolute deadline."""
    spec = json.loads(spec_path.read_text())
    until = int(spec['deadline_monotonic_ns'])
    phase = 'before_connect'
    sent = False
    connection = None
    captured_responses = []
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
        def record_response(*args, **kwargs):
            response = CapturedHTTPResponse(*args, **kwargs)
            captured_responses.append(response)
            return response
        connection.response_class = record_response
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
        headers.update(spec['headers'])
        # Mark ambiguous dispatch conservatively before any request bytes.
        sent = True
        phase = 'request_dispatch'
        connection.request(spec['method'], spec['path'], body=body, headers=headers)
        connection.sock.settimeout(remaining())
        phase = 'response_headers'
        response = connection.getresponse()
        head_projection = safe_response_head_projection(response, spec['path'])
        summary.update(status=response.status, http_client_accepted_headers=True, **head_projection)
        if not head_projection['response_header_strict_termination']:
            raise Refused('response_header_missing_strict_terminator')
        framing = response_body_framing(response, spec['method'])
        summary.update(response_body_framing=framing)
        if not framing['body_framing_valid']:
            raise Refused('response_body_framing_invalid_or_ambiguous')
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
        expected = framing['body_expected_bytes']
        length_matches = expected is None or len(raw) == expected
        summary.update(response_bytes=len(raw),
                       response_body_length_matches=length_matches,
                       response_content_length_remaining=response.length)
        if not length_matches:
            raise Refused('response_body_truncated_before_declared_length')
        if framing['body_framing_mode'] == 'chunked':
            chunked = response.chunk_framing_projection()
            summary.update(response_chunked_framing=chunked)
            if not chunked['chunked_framing_complete']:
                raise Refused('response_chunked_terminator_incomplete')
        remaining()
        write_new(Path(spec['response_body_file']), bytes(raw))
        location = response.getheader('Location')
        expected_locations = {f'https://127.0.0.1:{p}' + spec['path']
                              for p in API_PORTS.values()}
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
        returncode = 0
    except Exception as exc:
        summary.update(request_sent=sent, outcome_unknown=sent,
                       phase=phase, error_type=type(exc).__name__)
        returncode = 2
    finally:
        try:
            if captured_responses:
                captured = captured_responses[-1]
                summary.update(safe_response_head_projection(captured, spec['path']))
                if captured.chunked is True:
                    summary.update(response_chunked_framing=captured.chunk_framing_projection())
                write_new(Path(spec['response_head_file']), bytes(captured.header_capture.raw))
        except Exception as exc:
            # Diagnostic persistence cannot turn an unrecorded head into a
            # completed exchange or skip the original connection cleanup.
            summary.update(response_complete=False, request_sent=sent, outcome_unknown=sent,
                           phase='response_header_capture_failed', capture_error_type=type(exc).__name__)
            returncode = 2
        finally:
            try:
                if connection is not None:
                    connection.close()
            except Exception as exc:
                summary.update(response_complete=False, request_sent=sent, outcome_unknown=sent,
                               phase='connection_close_failed', close_error_type=type(exc).__name__)
                returncode = 2
            finally:
                summary['elapsed_ms'] = (time.monotonic_ns() - started) / 1e6
                # If this write also fails, the parent keeps the durable intent
                # and its existing missing-terminal-outcome unknown fence.
                write_json(Path(spec['response_meta_file']), summary)
    return returncode


def verify_artifacts() -> dict:
    observed = {}
    for name, (_, expected) in ARTIFACT_SOURCES.items():
        p = ARTIFACTS / name
        regular(p)
        value = digest(p)
        if value != expected:
            raise Refused('normal_artifact_digest_mismatch')
        observed[name] = {'path': str(p), 'bytes': p.stat().st_size, 'sha256': value}
    native = json.loads((ARTIFACTS / 'native-build.public.json').read_text())
    result = json.loads((ARTIFACTS / 'build-result.public.json').read_text())
    features = ['default', 'native-v6-ha', 'native-v6-storage']
    for receipt in (native, result):
        if (receipt.get('source_commit') != COMMIT or receipt.get('source_tree') != TREE
                or receipt.get('source_freeze_verified') is not True
                or receipt.get('build_exit_code') != 0
                or receipt.get('native_abi') != 'x86_64-unknown-linux-gnu'):
            raise Refused('normal_build_source_binding_mismatch')
    artifact = result['artifacts']['heptabao-server']
    if (native['binary_sha256'] != EXPECTED_SHA or native['features'] != features
            or artifact['sha256'] != EXPECTED_SHA or artifact['features'] != features
            or result.get('normal_default_candidate') is not True
            or result.get('timed_out') is not False
            or result.get('owned_group_survivors_after_wait') is not False
            or artifact['profile'] != {'debug_assertions': True, 'debuginfo': 0,
                                     'opt_level': '3', 'overflow_checks': True, 'test': False}):
        raise Refused('normal_default_feature_or_profile_binding_mismatch')
    return observed


def source_and_fences() -> dict:
    def git(*args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(SOURCE), *args],
                                       timeout=15).decode().strip()
    if git('rev-parse', 'HEAD') != COMMIT or git('rev-parse', 'HEAD^{tree}') != TREE or git('status', '--porcelain'):
        raise Refused('frozen_normal_source_changed')
    fences = {}
    for name, expected in OLD_FENCES.items():
        p = BASE / name
        regular(p)
        actual = digest(p)
        if actual != expected:
            raise Refused('existing_evidence_fence_changed')
        fences[name] = {'bytes': p.stat().st_size, 'sha256': actual}
    return {'source_commit': COMMIT, 'source_tree': TREE, 'source_clean': True, 'old_fences': fences}


def stage_artifacts() -> dict:
    if (CONTROL.resolve(strict=True) != CONTROL or CONTROL.stat().st_uid != os.getuid()
            or stat.S_IMODE(CONTROL.stat().st_mode) != 0o700):
        raise Refused('owned_control_required')
    if ARTIFACTS.exists() or ARTIFACTS.is_symlink():
        raise Refused('create_only_artifacts_required')
    before = source_and_fences()
    sources = {}
    for name, (p, expected) in ARTIFACT_SOURCES.items():
        st = regular(p)
        if digest(p) != expected:
            raise Refused('original_artifact_changed')
        sources[name] = {'path': str(p), 'device': st.st_dev, 'inode': st.st_ino,
                         'bytes': st.st_size, 'mtime_ns': st.st_mtime_ns, 'sha256': expected}
    write_json(CONTROL / 'artifact-stage-intent.public.json', {'sources': sources, 'before': before})
    ARTIFACTS.mkdir(mode=0o700)
    copied = {}
    for name, (source, expected) in ARTIFACT_SOURCES.items():
        target = ARTIFACTS / name
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with source.open('rb') as src, os.fdopen(fd, 'wb') as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        if name == 'heptabao-server':
            target.chmod(0o500)
        st = regular(source)
        current = {'path': str(source), 'device': st.st_dev, 'inode': st.st_ino,
                   'bytes': st.st_size, 'mtime_ns': st.st_mtime_ns, 'sha256': digest(source)}
        if current != sources[name] or digest(target) != expected:
            raise Refused('artifact_copy_identity_or_hash_changed')
        copied[name] = {'source': sources[name], 'target': str(target), 'target_sha256': expected}
    fd = os.open(ARTIFACTS, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    report = {'status': 'staged', 'copies': copied, 'verified': verify_artifacts(),
              'after': source_and_fences(), 'source_data_reopened': False,
              'server_processes_started': 0, 'network_requests': 0}
    write_json(CONTROL / 'artifact-stage-result.public.json', report)
    return report


def check_prepared(binary: Path, work: Path) -> dict:
    if binary != ARTIFACTS / 'heptabao-server':
        raise Refused('exact_staged_normal_binary_required')
    artifacts = verify_artifacts()
    before = source_and_fences()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise Refused('normal_artifact_native_host_abi_required')
    if work.parent != BASE or not re.fullmatch(r'normal-r10-standby-oracle-live-r[0-9]+', work.name):
        raise Refused('work_root_outside_owned_namespace')
    if work.exists() or work.is_symlink() or work.parent.resolve(strict=True) != BASE:
        raise Refused('fresh_work_root_required')
    for port in [*API_PORTS.values(), *CLUSTER_PORTS.values()]:
        with socket.socket() as s:
            s.bind(('127.0.0.1', port))
    return {'binary': str(binary), 'binary_sha256': EXPECTED_SHA,
            'binary_bytes': binary.stat().st_size, 'artifacts': artifacts, **before,
            'controller_sha256': digest(Path(__file__)), 'work_root': str(work),
            'api_ports': API_PORTS, 'raft_ports': CLUSTER_PORTS,
            'physical_hosts': 1, 'process_nodes': 3, 'loopback_only': True,
            'http_seconds': HTTP_SECONDS, 'readiness_seconds': READINESS_SECONDS,
            'election_seconds': ELECTION_SECONDS, 'stable_leader_seconds': STABLE_LEADER_SECONDS,
            'original_peer_timeout_ms': 1500, 'original_forward_timeout_ms': 8000,
            'max_response_bytes': MAX_RESPONSE, 'max_response_header_capture_bytes': MAX_RESPONSE_HEADERS,
            'response_header_capture': 'passive_readline_tap_private_raw_strict_crlf_terminator',
            'normal_default_features': True,
            'node_disable_standby_reads_config': 'not_set_by_this_observer',
            'redirect_following': False, 'valid_restore_bodies': 0,
            'old_generations_reopened': False,
            'comparison_scope': 'actual_wire_observation_not_full_replacement_qualification'}


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
                    response_body_file=str(response_file),
                    response_head_file=str(self.private / f'{number}.response-head'), content_type=content_type,
                    headers=headers or {}, ca_file=str(self.root / 'ca.crt'),
                    bootstrap_file=str(self.private / 'bootstrap.json'), deadline_monotonic_ns=until)
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
        while time.monotonic_ns() < until:
            o, b = self.request(node, 'GET', '/v1/sys/health?standbyok=true',
                                'readiness', credential='none', allow_preconnect_failure=True,
                                parent_deadline_ns=until)
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
            o, b = self.request(n, 'GET', '/v1/sys/leader', label, credential='none')
            self.check(f'{label}_node_{n}_leader_response', o['status'] == 200)
            d = json.loads(b)
            h, hb = self.request(n, 'GET', '/v1/sys/health?standbyok=true', label + '_health', credential='none')
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
                                    parent_deadline_ns=until)
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
        r = subprocess.run(['/usr/bin/openssl', *args], cwd=self.root,
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
                                 start_new_session=True, env={'PATH': '/usr/bin:/bin', 'HOME': str(directory)})
            ident = process_identity(p.pid)
            if ident is None:
                raise Refused('owned_server_identity_unavailable')
            self.procs[-1] = (p, ident)
            actual_argv = (Path('/proc') / str(p.pid) / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
            if (ident['pgid'] != p.pid or ident['exe'] != str(self.binary)
                    or actual_argv != [x.encode() for x in argv]):
                raise Refused('owned_server_exact_argv_or_executable_mismatch')
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
                                body={'key': bootstrap['keys_base64'][0]}, credential='none')
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
                o, b = self.request(n, 'GET', f'/v1/wire/data/seed?version={version}', f'node{n}_native_seed_version_{version}')
                value = json.loads(b).get('data', {})
                self.check(f'node{n}_actual_native_seed_version_{version}', o['status'] == 200
                           and value.get('data') == {'marker': f'normal33-wire-seed-{version}'}
                           and value.get('metadata', {}).get('version') == version)

    def snapshot_shape(self, body: bytes) -> dict:
        # Different archive representations are not presumed compatible from HTTP status.
        # The complete bounded body is private; this observer never restores it.
        return {'body_nonempty': bool(body), 'gzip_magic': body[:2] == b'\x1f\x8b',
                'archive_format_and_member_integrity_verified': False,
                'restore_not_attempted': True}

    def observe(self) -> None:
        before = self.roles('roles_before')
        leader = before['actual_leader']
        self.check('leader_stable_from_activation', leader == self.actual_leader)
        standbys = [n for n in API_PORTS if n != leader]
        self.raft_observation('raft_before')
        cases = self.cases
        for node in API_PORTS:
            for credential in ('none', 'invalid', 'root'):
                label = f'node{node}_snapshot_get_{credential}'
                o, b = self.request(node, 'GET', '/v1/sys/storage/raft/snapshot', label, credential=credential)
                expected = (200 if credential == 'root' else 403) if node == leader else (200 if credential == 'root' else 307)
                case = {'label': label, 'role': 'leader' if node == leader else 'standby', 'credential': credential,
                        'official_default_observed_status': expected, 'same_status_as_official_default': o['status'] == expected, **o}
                if o['status'] == 200:
                    case['archive_shape'] = self.snapshot_shape(b)
                if o['status'] == 307:
                    self.check(label + '_safe_exact_leader_location', o['location_matches_enrolled_origin_and_exact_target'] and o['location_node'] == leader)
                cases.append(case)
        for node in API_PORTS:
            for route in ('snapshot', 'snapshot-force'):
                label = f'node{node}_{route}_invalid_restore'
                o, _ = self.request(node, 'POST', f'/v1/sys/storage/raft/{route}', label,
                                    raw_body=b'owned-invalid-snapshot', content_type='application/octet-stream')
                self.check(label + '_no_success', o['status'] >= 300)
                if o['status'] == 307:
                    self.check(label + '_safe_exact_leader_location', o['location_matches_enrolled_origin_and_exact_target'] and o['location_node'] == leader)
                cases.append({'label': label, 'role': 'leader' if node == leader else 'standby',
                              'official_default_observed_status': 500, 'same_status_as_official_default': o['status'] == 500, **o})
        for node in standbys:
            label = f'node{node}_ordinary_256k_write_once'
            payload = {'options': {'cas': 0}, 'data': {'marker': 'x' * (256 * 1024)}}
            o, _ = self.request(node, 'POST', f'/v1/wire/data/from_node{node}', label, body=payload)
            cases.append({'label': label, 'role': 'standby', 'official_default_observed_status': 200,
                          'same_status_as_official_default': o['status'] == 200, **o})
            self.check(label + '_forward_completed', o['status'] == 200)
            o, b = self.request(leader, 'GET', f'/v1/wire/data/from_node{node}', label + '_leader_read')
            value = json.loads(b)
            self.check(label + '_exact_persisted_body', o['status'] == 200 and value['data']['data'] == payload['data'])
        node = standbys[0]
        o, _ = self.request(node, 'POST', '/v1/wire/data/no_forward', 'ordinary_write_explicit_no_forward',
                            body={'options': {'cas': 0}, 'data': {'marker': 'never-followed'}},
                            headers={'X-Vault-No-Request-Forwarding': '1'})
        if o['status'] == 307:
            self.check('no_forward_safe_exact_location', o['location_matches_enrolled_origin_and_exact_target'] and o['location_node'] == leader)
        cases.append({'label': 'ordinary_write_explicit_no_forward', 'role': 'standby',
                      'official_default_observed_status': 307, 'same_status_as_official_default': o['status'] == 307, **o})
        outcome, b = self.request(leader, 'GET', '/v1/wire/data/no_forward', 'no_forward_effect_observation')
        if o['status'] == 307:
            self.check('no_forward_redirect_was_not_followed_or_committed', outcome['status'] == 404)
        elif o['status'] == 200:
            self.check('completed_no_forward_ignored_write_exact_readback', outcome['status'] == 200
                       and json.loads(b)['data']['data'] == {'marker': 'never-followed'})
        cases.append({'label': 'no_forward_effect_observation', 'role': 'leader', **outcome})
        # This HeptaBao-only ingress has no official OpenBao counterpart. Invalid schema cannot publish a bundle.
        for node in API_PORTS:
            o, _ = self.request(node, 'POST', NATIVE_LARGE_ROUTE, f'node{node}_native_large_invalid_schema',
                                raw_body=b'{}', content_type=NATIVE_LARGE_MEDIA)
            self.check(f'node{node}_native_large_invalid_schema_no_success', o['status'] >= 300)
            cases.append({'label': f'node{node}_native_large_invalid_schema',
                          'role': 'leader' if node == leader else 'standby',
                          'official_counterpart': False, **o})
        after = self.roles('roles_after')
        self.check('observed_leader_remained_exact', after['actual_leader'] == leader)
        self.raft_observation('raft_after')
        write_json(self.root / 'wire-observations.public.json', {'cases': cases,
            'actual_leader': leader, 'actual_standbys': standbys,
            'qualification': 'normal33_wire_observation_not_compatibility_pass',
            'physical_hosts': 1, 'process_nodes': 3, 'no_failure_injection': True,
            'official_default_comparison_includes_original_nonvoter_standby_limit': True,
            'official_source_result_sha256': OLD_FENCES['official271-standby-oracle-live-r1/result.public.json'],
            'compatibility_status_differences': [c['label'] for c in cases if c.get('same_status_as_official_default') is False]})

    def finish(self, failed: str | None) -> int:
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
        complete = not incomplete_sequences and self.seq == len(self.observations) and not self.outcome_unknown
        status = 'completed_observation' if not failed and not verification_error and clean and complete else 'failed'
        report = {'schema': 'heptabao-normal33-standby-wire-header-diagnostic-r1', 'prepared': self.prepared,
                  'status': status, 'failure_code': failed, 'verification_error': verification_error,
                  'checks': self.checks, 'checks_total': len(self.checks),
                  'checks_passed': sum(x['passed'] for x in self.checks),
                  'checks_are_dynamic_observation_invariants_not_a_qualification_denominator': True,
                  'http_intents': self.seq, 'http_outcomes': len(self.observations),
                  'http_unknown': sum(bool(o['outcome_unknown']) for o in self.observations) + len(incomplete_sequences),
                  'intent_sequences_without_terminal_outcome': incomplete_sequences,
                  'complete_http_responses': sum(bool(o['response_complete']) for o in self.observations),
                  'preconnect_failures': sum(not o['response_complete'] and o['request_sent'] is False for o in self.observations),
                  'owned_cleanup': cleanup, 'client_cleanup': client_cleanup, 'all_owned_stopped': clean,
                  'source_and_fences_after': after, 'artifacts_after': artifact_after,
                  'controller_sha256_after': controller_sha_after, 'valid_restore_bodies': 0,
                  'terminal_unix_ns': time.time_ns(), 'started_unix_ns': self.started_unix_ns,
                  'elapsed_ms': (time.monotonic_ns() - self.started_monotonic_ns) / 1e6,
                  'operation_boundary_complete': complete, 'physical_hosts': 1,
                  'production_services_touched': False, 'full_replacement_qualification': False,
                  'compatibility_status_differences': [c['label'] for c in self.cases if c.get('same_status_as_official_default') is False]}
        write_json(self.root / 'result.public.json', report)
        print(json.dumps({'status': status, 'result': str(self.root / 'result.public.json'),
                          'result_sha256': digest(self.root / 'result.public.json'),
                          'checks_passed': report['checks_passed'], 'checks_total': report['checks_total'],
                          'http_intents': self.seq, 'http_outcomes': len(self.observations),
                          'http_unknown': report['http_unknown'], 'all_owned_stopped': clean,
                          'compatibility_status_differences': report['compatibility_status_differences']}, sort_keys=True))
        return 0 if status == 'completed_observation' else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', type=Path)
    ap.add_argument('--work-dir', type=Path)
    ap.add_argument('--prepare-only', action='store_true')
    ap.add_argument('--stage-artifacts-only', action='store_true')
    ap.add_argument('--child-request', type=Path)
    args = ap.parse_args()
    if args.child_request:
        return child_request(args.child_request)
    if args.stage_artifacts_only:
        print(json.dumps(stage_artifacts(), sort_keys=True))
        return 0
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
