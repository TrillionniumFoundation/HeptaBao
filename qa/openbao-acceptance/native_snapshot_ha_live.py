#!/usr/bin/env python3
"""Three-process TLS native HA leader export, using the pinned OpenBao CLI.

The CLI is a transport client, not a second storage implementation. HA restore
and standby streaming remain explicit refusals. Every listener keeps its original
five-second deadline. No writes, failed exports, or ambiguous responses retry.
"""
from __future__ import annotations
import gzip
import http.client
import json
from pathlib import Path
import re
import shutil
import signal
import socket
import tarfile
import tempfile
import time
from types import SimpleNamespace
import zlib

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from ha_destructive import FixtureError
from ha_network_partition import PartitionCluster, inactive_health
from kv1_record_scale_live import Dataset, MIB
from native_snapshot_cli_live import (ARCHIVE_LIMIT, BLOCK, NAMES, cli, contains_any,
    inspect_archive, private_parent)
from official_openbao_launcher import pinned_artifact, verify_inputs
from online_evidence import admit_output, complete_checks, source_identity

MOUNT = 'native-ha-save'
LISTENER_SECONDS = 5
REQUIRED = frozenset({'three_processes', 'listener_deadlines', 'distinct_api_raft_addresses',
    'mounted', 'payload_ready', 'all_initial', 'initial_addresses', 'leader_cli_save',
    'leader_archive_complete', 'leader_save_unchanged', 'leader_head', 'head_unchanged',
    'acl_save_denied', 'acl_head_denied', 'acl_unchanged', 'finite_created',
    'finite_first_save', 'finite_consumed_once', 'finite_final_head', 'finite_exhausted',
    'standby_get_denied', 'standby_head_denied', 'standby_unchanged',
    'restore_denied', 'force_restore_denied', 'restore_unchanged',
    'quorum_lost', 'quorum_save_denied', 'quorum_recovered', 'all_quorum_retained', 'quorum_unchanged',
    'step_down', 'successor_changed', 'successor_addresses', 'successor_cli_save',
    'successor_archive_complete', 'successor_save_unchanged', 'all_final', 'all_voters_final',
    'processes_stopped', 'plaintext_absent', 'complete'})


def complete(rows):
    return (complete_checks(rows, required_cases=REQUIRED)
            and rows[-1]['case'] == 'complete')


class SaveCluster(PartitionCluster):
    def configure(self):
        super().configure()
        # Public API authority is explicit; the directed Raft proxies never
        # become API targets. The original five-second HTTP deadline is retained.
        for node in self.nodes:
            self.peers[str(node.node_id)]['api_address'] = f'https://127.0.0.1:{node.http_port}'
            path = node.root / 'server.json'
            config = json.loads(path.read_text())
            config['lifecycle_interval_seconds'] = 0
            private_write(path, config, replace=True)


def client_view(cluster, node, token=None):
    return SimpleNamespace(address=f'https://127.0.0.1:{node.http_port}', root=cluster.root,
        token=cluster.root_token if token is None else token)


def native_response(node, token, method='GET', route='snapshot', declared_body=None):
    """Small response only; unexpected archive bodies cannot be buffered here.

    HEAD inspects actual bytes after the headers, rather than relying on the
    HTTPResponse HEAD shortcut, which could hide an incorrectly emitted body.
    Restore sends headers only: unsupported HA admission must reject before body.
    """
    fields = (f'{method} /v1/sys/storage/raft/{route} HTTP/1.1\r\nHost: localhost\r\n'
              f'X-Vault-Token: {token}\r\nConnection: close\r\n')
    if declared_body is not None:
        fields += f'Content-Length: {declared_body}\r\n'
    with socket.create_connection(('127.0.0.1', node.http_port), timeout=15) as raw:
        with node.context.wrap_socket(raw, server_hostname='localhost') as tls:
            tls.sendall((fields + '\r\n').encode())
            response = http.client.HTTPResponse(tls)
            response.begin()
            body = response.fp.read(65537) if method == 'HEAD' else response.read(65537)
            if len(body) > 65536:
                raise FixtureError('unexpected_archive_body')
            result = (response.status, dict((k.lower(), v) for k, v in response.getheaders()), body)
            response.close()
            return result


def denied(response, expected, *, head=False):
    status, headers, body = response
    if status != expected or headers.get('content-type', '').startswith('application/gzip'):
        return False
    if head:
        return body == b''
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError):
        return False
    return (isinstance(value, dict) and isinstance(value.get('errors'), list)
            and bool(value['errors']) and not any(value.get(k) for k in ('auth', 'data', 'wrap_info')))


def good_head(response):
    status, headers, body = response
    length = headers.get('content-length', '')
    return (status == 200 and headers.get('content-type') == 'application/gzip'
            and length.isdigit() and 0 < int(length) <= ARCHIVE_LIMIT and body == b'')


def strict_archive(path):
    """Full stream framing/checksum inspection, not HBB2/AEAD authentication."""
    if not 0 < path.stat().st_size <= ARCHIVE_LIMIT:
        raise ValueError('archive_size')
    # Reject concatenated gzip streams, ignored trailing bytes, and truncated
    # trailers. max_length prevents compressed inputs from allocating a huge chunk.
    decoder, expanded = zlib.decompressobj(31), 0
    with path.open('rb') as stream:
        while chunk := stream.read(BLOCK):
            pending = chunk
            while pending:
                expanded += len(decoder.decompress(pending, BLOCK))
                if expanded > ARCHIVE_LIMIT:
                    raise ValueError('archive_expanded_bound')
                pending = decoder.unconsumed_tail
                if decoder.eof:
                    if decoder.unused_data or stream.read(1):
                        raise ValueError('archive_gzip_trailing')
                    break
            if decoder.eof:
                break
    if not decoder.eof:
        raise ValueError('archive_gzip_truncated')
    # Existing inspector validates exact members, v2 seal binding, HBB2 magic,
    # state length and both plaintext hashes. Add canonical headers/padding/end.
    summary = inspect_archive(path)
    with gzip.open(path, 'rb') as stream:
        for name in NAMES:
            header = stream.read(512)
            if len(header) != 512:
                raise ValueError('archive_header')
            length = int(header[124:136].rstrip(b'\0 '), 8)
            member = tarfile.TarInfo(name); member.size = length; member.mode = 0o600
            if header != member.tobuf(format=tarfile.USTAR_FORMAT):
                raise ValueError('archive_noncanonical_header')
            remaining = length
            while remaining:
                chunk = stream.read(min(BLOCK, remaining))
                if not chunk:
                    raise ValueError('archive_truncated_member')
                remaining -= len(chunk)
            padding = (-length) % 512
            if stream.read(padding) != b'\0' * padding:
                raise ValueError('archive_padding')
        if stream.read(1024) != b'\0' * 1024 or stream.read(1):
            raise ValueError('archive_terminal_blocks')
    if type(summary['generation']) is not int or summary['generation'] < 0:
        raise ValueError('archive_generation')
    return {**summary, 'archive_bytes': path.stat().st_size, 'archive_sha256': file_hash(path),
            'cryptographic_authenticity_verified': False}


def capacity_data(node, token):
    status, body = node.call('GET', 'sys/internal/capacity', token=token, timeout=15)
    generation = body.get('data', {}).get('generation')
    if status != 200 or type(generation) is not int or type(body.get('data', {}).get('state_bytes')) is not int:
        raise FixtureError('capacity_unavailable')
    return body['data']


def capacity(node, token):
    return capacity_data(node, token)['generation']


def lookup_uses(node, root_token, token):
    status, body = node.call('POST', 'auth/token/lookup', {'token': token}, token=root_token)
    return status, body.get('data', {}).get('num_uses')


def assert_addresses(cluster, expected_leader, check, phase):
    expected = f'https://127.0.0.1:{expected_leader.http_port}'
    # Current candidate sys/leader requires auth and forwards standby requests,
    # unlike the official standalone handler. Select leadership via Cluster's
    # independent health checks and query that leader directly; do not disguise
    # the existing standby/anonymous status gap as a passing comparison.
    end = time.monotonic() + 10
    while True:
        status, body = expected_leader.call('GET', 'sys/leader', token=cluster.root_token)
        if status == 200 and body.get('leader_address') == expected and body.get('is_self') is True:
            break
        if time.monotonic() >= end:
            check(phase + '_leader', False)
        time.sleep(0.05)
    check(phase + '_leader', True)
    check(phase, True)


def run(binary, bao, work, checks, observations):
    cluster, tokens, dataset = None, [], Dataset()
    def check(name, condition):
        checks.append({'case': name, 'passed': condition is True})
        if condition is not True:
            raise FixtureError(name)
    def verify(node, phase):
        for index, key in enumerate(sorted(dataset.hashes)):
            status, body = node.call('GET', MOUNT + '/' + key, token=cluster.root_token)
            check(phase + '_' + str(index), dataset.matches(key, status, body))
        check('all_' + phase, True)
    def export(node, token, phase):
        archive = work / (phase + '.snap')
        start = time.monotonic()
        check(phase + '_cli_save', cli(bao, client_view(cluster, node, token), work, 'save', archive) == 0)
        elapsed = time.monotonic() - start
        try:
            summary = strict_archive(archive)
        except (ValueError, EOFError, OSError, zlib.error, tarfile.TarError):
            check(phase + '_archive_complete', False)
        check(phase + '_archive_complete', summary['state_bytes'] >= dataset.logical_bytes)
        summary['cli_elapsed_ms'] = round(elapsed * 1000, 3)
        observations.setdefault('archives', {})[phase] = summary
        return archive
    try:
        cluster = SaveCluster(binary, work / 'cluster')
        cluster.bootstrap()
        observations['bootstrap_checks'] = list(cluster.scenarios)
        check('three_processes', len({n.process.pid for n in cluster.nodes}) == 3)
        check('listener_deadlines', all(json.loads((n.root / 'server.json').read_text())['timeout_seconds']
              == LISTENER_SECONDS for n in cluster.nodes))
        check('distinct_api_raft_addresses', all(
            peer['api_address'] == f'https://127.0.0.1:{target.http_port}'
            and int(peer['address'].rsplit(':', 1)[1]) != target.http_port
            for n in cluster.nodes for target in cluster.nodes
            for peer in [json.loads(n.ha_config.read_text())['peers'][str(target.node_id)]]))
        leader = cluster.leader()
        assert_addresses(cluster, leader, check, 'initial_addresses')
        check('mounted', leader.call('POST', 'sys/mounts/' + MOUNT,
              {'type': 'kv', 'options': {'version': '1'}}, token=cluster.root_token)[0] == 204)
        ordinal = 0
        while dataset.logical_bytes < 8 * MIB:
            key, value = f'bulk/{ordinal:04d}', dataset.make_value(ordinal)
            check('write_' + str(ordinal), leader.call('PUT', MOUNT + '/' + key, value,
                  token=cluster.root_token, timeout=15)[0] == 204)
            dataset.remember(key, value); ordinal += 1
        observations.update(logical_value_bytes=dataset.logical_bytes, record_count=len(dataset.hashes))
        check('payload_ready', dataset.logical_bytes >= 8 * MIB)
        verify(leader, 'initial')
        before = capacity(leader, cluster.root_token)
        archive = export(leader, cluster.root_token, 'leader')
        check('leader_save_unchanged', capacity(leader, cluster.root_token) == before)
        check('leader_head', good_head(native_response(leader, cluster.root_token, 'HEAD')))
        check('head_unchanged', capacity(leader, cluster.root_token) == before)
        status, body = leader.call('POST', 'auth/token/create', {'policies': ['default'], 'ttl': 600},
                                   token=cluster.root_token)
        check('acl_token_created', status == 200 and bool(body.get('auth', {}).get('client_token')))
        restricted = body['auth']['client_token']; tokens.append(restricted)
        before = capacity(leader, cluster.root_token)
        check('acl_save_denied', denied(native_response(leader, restricted), 403))
        check('acl_head_denied', denied(native_response(leader, restricted, 'HEAD'), 403, head=True))
        check('acl_unchanged', capacity(leader, cluster.root_token) == before)
        status, body = leader.call('POST', 'auth/token/create', {'policies': ['root'], 'num_uses': 2,
                                   'ttl': 600}, token=cluster.root_token)
        check('finite_created', status == 200 and bool(body.get('auth', {}).get('client_token')))
        finite = body['auth']['client_token']; tokens.append(finite)
        finite_archive = work / 'finite.snap'
        check('finite_first_save', cli(bao, client_view(cluster, leader, finite), work, 'save', finite_archive) == 0)
        observations['archives']['finite'] = strict_archive(finite_archive)
        check('finite_consumed_once', lookup_uses(leader, cluster.root_token, finite) == (200, 1))
        check('finite_final_head', good_head(native_response(leader, finite, 'HEAD')))
        check('finite_exhausted', denied(native_response(leader, finite), 403))
        before = capacity(leader, cluster.root_token)
        standby = next(n for n in cluster.nodes if n is not leader)
        check('standby_get_denied', denied(native_response(standby, cluster.root_token), 503))
        check('standby_head_denied', denied(native_response(standby, cluster.root_token, 'HEAD'), 503, head=True))
        check('standby_unchanged', capacity(leader, cluster.root_token) == before)
        check('restore_denied', denied(native_response(leader, cluster.root_token, 'POST',
              declared_body=archive.stat().st_size), 409))
        check('force_restore_denied', denied(native_response(leader, cluster.root_token, 'POST',
              route='snapshot-force', declared_body=archive.stat().st_size), 409))
        check('restore_unchanged', capacity(leader, cluster.root_token) == before)
        state_bytes_before_quorum = capacity_data(leader, cluster.root_token)['state_bytes']
        for link in cluster.links.values():
            link.set_blocked(True)
        time.sleep(3)
        health = [n.call('GET', 'sys/health', timeout=15) for n in cluster.nodes]
        check('quorum_lost', all(inactive_health(status, body) for status, body in health))
        start = time.monotonic()
        try:
            response = native_response(leader, cluster.root_token)
        except (OSError, http.client.HTTPException):
            observations['quorum_denial'] = {'http_status': None, 'transport_terminated': True,
                'elapsed_ms': round((time.monotonic() - start) * 1000, 3)}
            check('quorum_save_denied', False)
        observations['quorum_denial'] = {'http_status': response[0],
            'transport_terminated': False,
            'elapsed_ms': round((time.monotonic() - start) * 1000, 3)}
        # EOF/transport errors fail this explicit HTTP assertion; never count
        # them as 503 or silently relax the listener's original deadline.
        check('quorum_save_denied', denied(response, 503))
        cluster._heal(); recovered = cluster.leader()
        check('quorum_recovered', recovered.process is not None)
        verify(recovered, 'quorum_retained')
        # Physical durable generations are process-local and cannot be compared
        # across leaders. Check the full application values and logical byte count.
        check('quorum_unchanged', capacity_data(recovered, cluster.root_token)['state_bytes']
              == state_bytes_before_quorum)
        check('step_down', recovered.call('POST', 'sys/step-down', {}, token=cluster.root_token)[0] == 204)
        successor = cluster.leader()
        check('successor_changed', successor.node_id != recovered.node_id)
        assert_addresses(cluster, successor, check, 'successor_addresses')
        before = capacity(successor, cluster.root_token)
        export(successor, cluster.root_token, 'successor')
        check('successor_save_unchanged', capacity(successor, cluster.root_token) == before)
        verify(successor, 'final')
        for node in cluster.nodes:
            if node is not successor:
                verify(node, 'replica_' + str(node.node_id))
        check('all_voters_final', True)
        samples = [cluster.root_token.encode(), cluster.unseal_key.encode(),
                   *[t.encode() for t in tokens], *[s.encode() for s in dataset.sample_prefixes]]
        cluster.close()
        check('processes_stopped', all(n.process is None for n in cluster.nodes))
        files = [p for n in cluster.nodes for base in (n.data_dir, n.root / 'raft')
                 for p in base.rglob('*') if p.is_file() and not p.is_symlink()]
        files += [p for n in cluster.nodes for p in (n.root / 'audit.jsonl', n.root / 'process.log') if p.exists()]
        files += list(work.glob('*.snap'))
        check('plaintext_absent', bool(files) and all(not contains_any(p, samples) for p in files))
        check('complete', True)
    finally:
        if cluster is not None:
            cluster.close()


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--build-source-commit', required=True)
    parser.add_argument('--work-parent', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.build_source_commit):
        parser.error('full build commit required')
    binary, output = args.binary.resolve(strict=True), args.output.absolute()
    parent, admitted = private_parent(args.work_parent), admit_output(output)
    bao = verify_inputs(); cli_hash = file_hash(bao)
    before = source_identity(ROOT, binary); runner_hash = file_hash(Path(__file__))
    work = Path(tempfile.mkdtemp(prefix='native-snapshot-ha-', dir=parent))
    checks, observations, failure = [], {}, None
    def interrupted(signum, frame):
        raise FixtureError('fixture_interrupted')
    handlers = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGTERM, signal.SIGINT)}
    try:
        run(binary, bao, work, checks, observations)
    except Exception as error:
        failure = next((r['case'] for r in reversed(checks) if r['passed'] is not True),
                       'fixture_' + type(error).__name__)
    finally:
        for kind, handler in handlers.items():
            signal.signal(kind, handler)
    after = source_identity(ROOT, binary)
    runner_unchanged, cli_unchanged = runner_hash == file_hash(Path(__file__)), cli_hash == file_hash(bao)
    if before != after or not runner_unchanged or not cli_unchanged:
        failure = 'source_binary_cli_or_runner_changed'
    if before['source_dirty'] or after['source_dirty']:
        failure = 'source_dirty'
    if not complete(checks):
        failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.native-snapshot-ha.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': checks, 'observations': observations,
        'source_identity': before, 'source_identity_after': after,
        'source_and_binary_unchanged': before == after, 'build_source_commit': args.build_source_commit,
        'runner_sha256': runner_hash, 'runner_unchanged': runner_unchanged,
        'official_cli_version': '2.6.2', 'official_cli_sha256': cli_hash, 'official_cli_unchanged': cli_unchanged,
        'official_cli_artifact_sha256': pinned_artifact()['artifact_sha256'],
        'retained_failure_work_dir': str(work) if failure else None, 'node_count': 3,
        'listener_timeout_seconds': LISTENER_SECONDS, 'mutation_retry': False,
        'official_cli_transport_covered': failure is None, 'native_archive_version': 2,
        'ha_leader_save_covered': failure is None, 'head_wire_body_checked': failure is None,
        'ha_restore_covered': False, 'standby_streaming_covered': False,
        'anonymous_or_standby_sys_leader_compatibility': False,
        'unset_api_address_covered': False, 'concurrent_write_during_export_covered': False,
        'openbao_state_interoperability': False, 'full_openbao_compatibility': False,
        'multi_host_covered': False, 'independent_qualification': False, 'production_authority': False}
    if admit_output(output) != admitted:
        raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    if not failure:
        shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'checks': len(checks), 'failure': failure}))
    return int(failure is not None)


if __name__ == '__main__':
    raise SystemExit(main())
