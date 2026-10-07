#!/usr/bin/env python3
"""Measure audited KV reads against growing synthetic state in a real TLS process.

No external endpoint or credential input is accepted. Growth is materialized
through the current KV1 record owner so this read-path profile does not spend its
budget repeatedly serializing the legacy opaque KV2 owner. The logical payload,
three growth points and read/audit checks are unchanged. Baseline mode records
the same workload without asserting the new fast-path counter; it never qualifies
a candidate. Timings are observations on this host, not a production SLA.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from bao_http import BaoError, SafeArgumentParser, private_write
from heptabao.private_state import StateDirectory
from core_isolation import ROOT, ScenarioFailure, file_hash
from capacity_live import percentile, process_rss_kib

PAYLOAD_BYTES = 224 * 1024
GROWTH_COUNTS = (8, 32, 64)
READS_PER_POINT = 24


def durable_fields(data):
    return {name: data[name] for name in (
        'state_bytes', 'generation', 'retained_operations', 'journal_bytes')}


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--build-source', type=Path, default=ROOT, help='caller-supplied build checkout metadata, not binary attestation')
    args = parser.parse_args(argv)
    output = args.output.absolute()
    if os.path.lexists(output):
        raise BaoError('output_already_exists')
    with StateDirectory(output.parent):
        pass
    return run(args.binary, output, args.baseline, args.build_source)


def run(binary: Path, output: Path, baseline=False, build_source=ROOT):
    binary = binary.resolve(strict=True)
    build_source = build_source.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='heptabao-kv-read-scaling-'))
    root.chmod(0o700)
    report = {
        'schema': 'heptabao.kv-read-scaling.v1', 'status': 'failed',
        'synthetic_only': True, 'baseline_only': baseline,
        'binary_sha256': file_hash(binary), 'runner_sha256': file_hash(Path(__file__)),
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=build_source, text=True).strip(),
        'source_tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=build_source, text=True).strip(),
        'source_worktree_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=build_source)),
        'source_binding_basis': 'caller_build_source_not_binary_attestation',
        'full_openbao_compatibility': False, 'production_qualified': False,
        'record_oriented_writes': True, 'cases': [], 'points': [],
    }
    instance = None

    def check(name, condition):
        report['cases'].append({'case': name, 'passed': bool(condition)})
        if not condition:
            raise ScenarioFailure(name)

    def observe():
        status, body = instance.call('GET', 'sys/internal/capacity')
        check('capacity_observed', status == 200 and isinstance(body.get('data'), dict))
        return body['data']

    try:
        spec = importlib.util.spec_from_file_location('read_scaling_smoke', ROOT / 'qa/single-node/smoke.py')
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        instance = smoke.Instance(binary, root / 'node')
        instance.start()
        status, initialized = instance.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
        check('initialized', status == 200)
        instance.token = initialized['root_token']
        key = initialized['keys_base64'][0]
        check('unsealed', instance.call('POST', 'sys/unseal', {'key': key})[0] == 200)
        check('record_mount', instance.call('POST', 'sys/mounts/read-scale',
              {'type':'kv', 'options':{'version':'1'}})[0] == 204)
        check('seed_small', instance.call('POST', 'read-scale/small',
              {'value': 'synthetic-small'})[0] == 204)
        written = 0
        for count in GROWTH_COUNTS:
            while written < count:
                status, _ = instance.call('POST', f'read-scale/growth/{written:04d}',
                                           {'payload': 'x' * PAYLOAD_BYTES})
                check('growth_write', status == 204)
                written += 1
            before = observe()
            check('record_storage_format',
                  before.get('state_storage_format') == 'heptabao-state-records-v5')
            check('logical_state_floor', before.get('state_bytes', -1) >= count * PAYLOAD_BYTES)
            if report['points']:
                check('state_growth_monotonic',
                      before['state_bytes'] > report['points'][-1]['state_bytes'])
            audit_before = len((instance.root / 'audit.jsonl').read_bytes().splitlines())
            rss_before = process_rss_kib(instance.process.pid)
            durations = []
            for _ in range(READS_PER_POINT):
                start = time.perf_counter_ns()
                status, body = instance.call('GET', 'read-scale/small')
                durations.append((time.perf_counter_ns() - start) / 1_000_000)
                check('read_exact', status == 200 and body.get('data') == {'value': 'synthetic-small'})
            status, body = instance.call('LIST', 'read-scale?limit=1')
            check('shallow_list', status == 200
                  and body['data']['keys'] == ['growth/', 'small'])
            status, body = instance.call('SCAN', 'read-scale',
                                         {'after': f'growth/{count-3:04d}', 'limit': 2})
            check('scan_ignores_pagination', status == 200 and body['data']['keys'] == ['small'] + [f'growth/{index:04d}' for index in range(count)])
            audit_after = len((instance.root / 'audit.jsonl').read_bytes().splitlines())
            after = observe()
            check('no_read_state_or_replay_mutation', durable_fields(after) == durable_fields(before))
            check('every_read_audited', audit_after - audit_before == 2 * (READS_PER_POINT + 2))
            if not baseline:
                check('actual_immutable_dispatch', after.get('kv_read_only_dispatches', -1) - before.get('kv_read_only_dispatches', -1) == READS_PER_POINT + 2)
            report['points'].append({
                'stored_growth_keys': count, 'state_bytes': before['state_bytes'],
                'read_samples': len(durations),
                'read_latency_ms': {label: round(percentile(durations, q), 3)
                                    for label, q in (('p50', .5), ('p95', .95), ('p99', .99))},
                'rss_before_kib': rss_before, 'rss_after_kib': process_rss_kib(instance.process.pid),
                'generation_delta': after['generation'] - before['generation'],
                'replay_identity_delta': after['retained_operations'] - before['retained_operations'],
            })
            print(json.dumps({'event': 'read_growth_point', **report['points'][-1]}, sort_keys=True), flush=True)
        instance.stop()
        instance.start()
        check('reopened_sealed', instance.call('GET', 'read-scale/small')[0] == 503)
        check('reopened_unseal', instance.call('POST', 'sys/unseal', {'key': key})[0] == 200)
        if not baseline:
            check('counter_is_process_local', observe()['kv_read_only_dispatches'] == 0)
        check('reopened_read_exact', instance.call('GET', 'read-scale/small')[1]['data'] == {'value': 'synthetic-small'})
        check('all_declared_growth_points',
              [point['stored_growth_keys'] for point in report['points']] == list(GROWTH_COUNTS))
        check('unchanged_logical_payload_scale',
              report['points'][-1]['state_bytes'] >= GROWTH_COUNTS[-1] * PAYLOAD_BYTES)
        check('binary_unchanged', report['binary_sha256'] == file_hash(binary))
        report['status'] = 'passed_scoped_read_measurements'
    except Exception as error:
        report['reason'] = type(error).__name__  # No request, credential or raw error body.
    finally:
        if instance is not None:
            instance.stop()
        shutil.rmtree(root)
    private_write(output, report, replace=False)
    print(json.dumps({'status': report['status'], 'baseline_only': baseline,
                      'points': len(report['points']), 'checks': len(report['cases'])}, sort_keys=True))
    return 0 if report['status'] == 'passed_scoped_read_measurements' else 2


if __name__ == '__main__':
    raise SystemExit(main())
