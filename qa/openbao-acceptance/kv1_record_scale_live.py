#!/usr/bin/env python3
"""Real KV1 payload growth beyond the old 16 MiB whole-state limit.

Only fixture-owned local TLS processes and storage are used. This measures the
public API and operating-system counters, not internal object serialization or
an unlimited storage profile. Timings and write bytes are observations, never a
hard-coded speedup gate.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import time

from bao_http import Client, SafeArgumentParser, canonical, private_write
from capacity_live import percentile, tree_bytes
from core_isolation import ROOT, ScenarioFailure, file_hash
from online_evidence import admit_output, source_identity
from remote_jwks_live import Instance

MIB = 1024 * 1024
PAYLOAD_BYTES = 224 * 1024
OLD_STATE_LIMIT = 16 * MIB
DURABLE_ARTIFACT_LIMIT = 64 * MIB
MOUNT = 'record-scale'
SMALL_WRITES = 3
REQUIRED = frozenset({'initialized', 'mount_created', 'above_old_limit', 'growth_complete',
    'all_records_before_edits', 'large_replaced', 'large_deleted', 'all_records_after_edits',
    'restarted', 'all_records_after_restart', 'deleted_absent_after_restart',
    'small_value_after_restart', 'secrets_absent', 'complete'})


def canonical_hash(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def process_observation(pid):
    """Linux server-only counters; missing counters fail rather than becoming zero."""
    proc = Path('/proc') / str(pid)
    stat_fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    status = dict((line.split(':', 1)[0], line.split(':', 1)[1].strip())
                  for line in (proc / 'status').read_text().splitlines() if ':' in line)
    io = dict((line.split(':', 1)[0], int(line.split(':', 1)[1]))
              for line in (proc / 'io').read_text().splitlines() if ':' in line)
    return {'cpu_ticks': int(stat_fields[11]) + int(stat_fields[12]),
            'rss_kib': int(status['VmRSS'].split()[0]), 'peak_rss_kib': int(status['VmHWM'].split()[0]),
            'write_bytes': io['write_bytes'], 'wchar': io['wchar']}


def measurement_delta(before, after):
    if any(type(before.get(k)) is not int or type(after.get(k)) is not int or after[k] < before[k]
           for k in ('cpu_ticks', 'write_bytes', 'wchar')):
        raise ScenarioFailure('kv1_scale.invalid_process_counters')
    return {'server_cpu_seconds': round((after['cpu_ticks'] - before['cpu_ticks']) / os.sysconf('SC_CLK_TCK'), 6),
            'process_write_bytes': after['write_bytes'] - before['write_bytes'],
            'process_wchar': after['wchar'] - before['wchar'],
            'rss_kib_after': after['rss_kib'], 'peak_rss_kib_after': after['peak_rss_kib']}


def disk_observation(root):
    sizes = []
    for path in root.rglob('*'):
        if path.is_file() and not path.is_symlink():
            try:
                sizes.append(path.stat().st_size)
            except FileNotFoundError:
                # A checkpoint can atomically replace a discovered artifact.
                continue
    return {'file_count':len(sizes), 'tree_bytes':sum(sizes), 'largest_file_bytes':max(sizes,default=0)}


class Dataset:
    """Keep expected hashes, never a duplicate in-memory copy of all large values."""
    def __init__(self):
        self.hashes = {}
        self.payload_sizes = {}
        self.sample_prefixes = []

    def make_value(self, ordinal):
        # Distinct random bytes prevent content deduplication from turning a
        # claimed 32 MiB dataset into one repeatedly referenced identical value.
        payload = secrets.token_urlsafe(PAYLOAD_BYTES * 3 // 4)
        if len(payload) != PAYLOAD_BYTES:
            raise ScenarioFailure('kv1_scale.invalid_payload_generation')
        self.sample_prefixes.append(payload[:48])
        return {'ordinal': ordinal, 'payload': payload}

    def remember(self, key, value):
        self.hashes[key] = canonical_hash(value)
        self.payload_sizes[key] = len(canonical(value))

    def forget(self, key):
        del self.hashes[key]; del self.payload_sizes[key]

    @property
    def logical_bytes(self):
        return sum(self.payload_sizes.values())

    def matches(self, key, status, body):
        return (type(status) is int and status == 200 and isinstance(body, dict)
                and isinstance(body.get('data'), dict)
                and canonical_hash(body['data']) == self.hashes[key])


def complete(checks, target_mib, points):
    if target_mib not in (24, 32) or not isinstance(checks, list) or not checks:
        return False
    names = []
    for row in checks:
        if (not isinstance(row, dict) or set(row) != {'case', 'passed'} or row['passed'] is not True
                or not isinstance(row['case'], str) or re.fullmatch(r'[a-z0-9_]{1,120}', row['case']) is None):
            return False
        names.append(row['case'])
    expected = [4, 24] + ([32] if target_mib == 32 else [])
    return (len(names) == len(set(names)) and names[-1] == 'complete' and REQUIRED.issubset(names)
            and isinstance(points, list) and all(isinstance(p, dict) for p in points)
            and [p.get('target_mib') for p in points] == expected
            and all(type(p.get('logical_payload_bytes')) is int and p['logical_payload_bytes'] >= p['target_mib'] * MIB
                    and p.get('small_writes') == SMALL_WRITES for p in points))


def run(binary, root, target_mib, checks, points, observations):
    instance = None
    def check(name, condition):
        checks.append({'case': name, 'passed': condition is True})
        if condition is not True:
            raise ScenarioFailure(name)
    try:
        instance = Instance(binary, root / 'instance')
        settings_path = instance.root / 'server.json'
        settings = json.loads(settings_path.read_text())
        settings.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
        private_write(settings_path, settings, replace=True)
        instance.start()
        status, initialized = instance.call('POST', 'sys/init', {'secret_shares':1, 'secret_threshold':1})
        check('initialized', status == 200 and isinstance(initialized.get('root_token'), str)
              and isinstance(initialized.get('keys_base64'), list) and len(initialized['keys_base64']) == 1)
        instance.token, unseal_key = initialized['root_token'], initialized['keys_base64'][0]
        check('unsealed', instance.call('POST', 'sys/unseal', {'key':unseal_key})[0] == 200)
        client = Client(instance.address, str(instance.root / 'ca.crt'), instance.token, timeout=30)
        def request(method, path, body=None):
            result = client.request(method, '/v1/' + path, body)
            return result.status, result.body
        check('mount_created', request('POST', 'sys/mounts/' + MOUNT, {'type':'kv', 'options':{'version':'1'}})[0] == 204)
        dataset, ordinal, sequence = Dataset(), 0, 0
        def verify_all(phase):
            for key in sorted(dataset.hashes):
                status, body = request('GET', MOUNT + '/' + key)
                check(phase + '_' + key.rsplit('/', 1)[-1], dataset.matches(key, status, body))
        for target in [4, 24] + ([32] if target_mib == 32 else []):
            while dataset.logical_bytes < target * MIB:
                key = f'bulk/{ordinal:04d}'
                value = dataset.make_value(ordinal)
                # No retry: a lost acknowledgement is an ambiguous mutation.
                status, _ = request('PUT', MOUNT + '/' + key, value)
                check(f'growth_{ordinal}', status == 204)
                dataset.remember(key, value); ordinal += 1
            status, body = request('GET', 'sys/internal/capacity')
            capacity = body.get('data') or {}
            check(f'format_{target}', status == 200 and capacity.get('state_storage_format') == 'heptabao-state-records-v5'
                  and type(capacity.get('state_bytes')) is int and capacity['state_bytes'] >= dataset.logical_bytes)
            capacity_counts = {key:value for key,value in capacity.items()
                               if type(value) is int and value >= 0}
            before = process_observation(instance.process.pid)
            disk_before = tree_bytes(instance.root / 'data')
            timings, per_write = [], []
            for repeat in range(SMALL_WRITES):
                previous = process_observation(instance.process.pid)
                sequence += 1
                started = time.perf_counter_ns()
                status, _ = request('PUT', MOUNT + '/small', {'sequence': sequence})
                elapsed = (time.perf_counter_ns() - started) / 1_000_000
                check(f'small_{target}_{repeat}', status == 204)
                current = process_observation(instance.process.pid)
                timings.append(elapsed)
                per_write.append({'ordinal': repeat, 'latency_ms': round(elapsed, 3),
                                  **measurement_delta(previous, current)})
            after = process_observation(instance.process.pid)
            disk_after = disk_observation(instance.root / 'data')
            check(f'durable_artifact_bound_{target}', disk_after['largest_file_bytes'] <= DURABLE_ARTIFACT_LIMIT)
            points.append({'target_mib': target, 'large_records': len(dataset.hashes),
                'logical_payload_bytes': dataset.logical_bytes, 'small_writes': SMALL_WRITES,
                'latency_ms': {name:round(percentile(timings, q), 3) for name,q in [('p50',.5),('p95',.95)]},
                'durable_tree_bytes_before': disk_before, 'durable_tree_bytes_after': tree_bytes(instance.root / 'data'),
                'durable_artifacts_after': disk_after, 'durable_artifact_limit_bytes': DURABLE_ARTIFACT_LIMIT,
                'capacity_numeric_observation': capacity_counts,
                'process_before': before, 'process_after': after, 'per_write': per_write,
                **measurement_delta(before, after)})
        check('above_old_limit', dataset.logical_bytes > OLD_STATE_LIMIT)
        check('growth_complete', dataset.logical_bytes >= target_mib * MIB)
        verify_all('before_edits')
        check('all_records_before_edits', True)
        replacement = dataset.make_value(1_000_000)
        check('large_replaced', request('PUT', MOUNT + '/bulk/0000', replacement)[0] == 204)
        dataset.remember('bulk/0000', replacement)
        check('large_deleted', request('DELETE', MOUNT + '/bulk/0001')[0] == 204)
        dataset.forget('bulk/0001')
        status, body = request('GET', MOUNT + '/bulk/0001')
        check('deleted_absent_before_restart', status == 404 and not body.get('data'))
        verify_all('after_edits')
        check('all_records_after_edits', True)
        status, body = request('LIST', MOUNT + '/bulk')
        expected = [key.split('/', 1)[1] for key in sorted(dataset.hashes)]
        check('list_after_delete', status == 200 and body.get('data', {}).get('keys') == expected)
        instance.stop(); instance.start()
        check('restarted', instance.call('POST', 'sys/unseal', {'key':unseal_key})[0] == 200)
        verify_all('after_restart')
        check('all_records_after_restart', True)
        status, body = request('GET', MOUNT + '/bulk/0001')
        check('deleted_absent_after_restart', status == 404 and not body.get('data'))
        status, body = request('GET', MOUNT + '/small')
        check('small_value_after_restart', status == 200 and body.get('data') == {'sequence':sequence})
        observations.update(logical_bytes_after_delete=dataset.logical_bytes, records_after_delete=len(dataset.hashes),
                            durable_tree_bytes_after_restart=tree_bytes(instance.root / 'data'),
                            process_after_restart=process_observation(instance.process.pid))
        instance.stop()
        samples = [instance.token, unseal_key, *dataset.sample_prefixes]
        files = [p for p in (instance.root / 'data').rglob('*') if p.is_file()]
        files += [instance.root / 'audit.jsonl', instance.root / 'server.log']
        samples = [sample.encode() for sample in samples]
        safe = True
        for path in files:
            if path.exists():
                stored = path.read_bytes()
                safe &= not any(sample in stored for sample in samples)
        check('secrets_absent', safe)
        check('complete', True)
    finally:
        if instance is not None:
            instance.stop()


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--build-source-commit', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--target-mib', type=int, choices=(24, 32), default=32)
    args = parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}', args.build_source_commit) is None:
        parser.error('full build source commit required')
    binary, output = args.binary.resolve(strict=True), args.output.absolute()
    admitted = admit_output(output)
    before, runner_hash = source_identity(ROOT, binary), file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix='heptabao-kv1-record-scale-')); root.chmod(0o700)
    checks, points, observations, failure = [], [], {}, None
    try:
        run(binary, root, args.target_mib, checks, points, observations)
    except Exception as error:
        failure = next((row['case'] for row in reversed(checks) if row['passed'] is not True),
                       'fixture_' + type(error).__name__)
    finally:
        shutil.rmtree(root)
    unchanged = before == source_identity(ROOT, binary)
    runner_unchanged = runner_hash == file_hash(Path(__file__))
    if not unchanged or not runner_unchanged:
        failure = 'source_binary_or_runner_changed'
    if not complete(checks, args.target_mib, points):
        failure = failure or 'incomplete_observations'
    report = {'schema':'heptabao.kv1-record-scale.v1', 'status':'passed' if failure is None else 'failed',
        'failure':failure, 'source_identity':before, 'source_and_binary_unchanged':unchanged,
        'build_source_commit':args.build_source_commit, 'runner_sha256':runner_hash, 'runner_unchanged':runner_unchanged,
        'target_payload_mib':args.target_mib, 'checks':checks, 'points':points, 'observations':observations,
        'storage':'local', 'internal_object_counts_observed':False, 'speedup_or_amplification_gate':False,
        'whole_state_serialization_eliminated_proven':False, 'ha_or_postgresql_covered':False,
        'synthetic_only':True, 'full_openbao_compatibility':False, 'independent_qualification':False,
        'production_authority':False}
    if admit_output(output) != admitted:
        raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status':report['status'], 'checks':len(checks), 'points':len(points), 'failure':failure}))
    return 0 if failure is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
