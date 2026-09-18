#!/usr/bin/env python3
"""Measure the real bounded service on a new synthetic loopback TLS instance.

No existing endpoint, credentials or data directory can be supplied. A pass
proves the current 16 MiB chunked whole-state profile's refusal/reopen semantics,
never production scale or record-oriented scalability.
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

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash

CURRENT_STATE_LIMIT_BYTES = 16 * 1024 * 1024
LEGACY_STATE_LIMIT_BYTES = 768 * 1024
SATURATION_PAYLOAD_BYTES = 224 * 1024
MAX_SATURATION_WRITES = 96


def tree_bytes(path: Path) -> int:
    total = 0
    if not path.exists():
        return total
    for entry in path.rglob('*'):
        try:
            if entry.is_file() and not entry.is_symlink():
                total += entry.stat().st_size
        except FileNotFoundError:
            # Atomic publication may replace a generation between discovery/stat.
            continue
    return total


def process_rss_kib(pid: int | None) -> int | None:
    if pid is None:
        return None
    status = Path('/proc') / str(pid) / 'status'
    try:
        for line in status.read_text().splitlines():
            if line.startswith('VmRSS:'):
                fields = line.split()
                return int(fields[1]) if len(fields) >= 2 else None
    except (OSError, ValueError):
        return None
    return None


def validate_observation(data: dict) -> None:
    names = ('state_bytes', 'state_limit_bytes', 'state_remaining_bytes', 'generation',
             'retained_operations', 'operation_limit', 'operations_remaining',
             'journal_bytes', 'journal_limit_bytes')
    if not isinstance(data, dict) or any(type(data.get(k)) is not int or data[k] < 0 for k in names):
        raise ScenarioFailure('capacity.invalid_observation')
    for used, limit, remaining in (
        ('state_bytes', 'state_limit_bytes', 'state_remaining_bytes'),
        ('retained_operations', 'operation_limit', 'operations_remaining'),
    ):
        if data[used] > data[limit] or data[remaining] != data[limit] - data[used]:
            raise ScenarioFailure('capacity.inconsistent_bound')
    if data['journal_bytes'] > data['journal_limit_bytes']:
        raise ScenarioFailure('capacity.journal_bound')
    for key in ('admission_reserved', 'compaction_reclaims_operation_identities',
                'full_openbao_compatibility', 'production_qualified'):
        if data.get(key) is not False:
            raise ScenarioFailure('capacity.inflated_claim')


def main() -> int:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    binary = Path(args.binary).resolve(strict=True)
    output = Path(args.output).absolute()
    info = output.parent.stat()
    if os.path.lexists(output) or output.parent.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        parser.error('new output in private caller-owned directory required')
    root = Path(tempfile.mkdtemp(prefix='heptabao-capacity-live-'))
    root.chmod(0o700)
    instance = None
    started = time.monotonic()
    stage = 'setup'
    report = {'schema': 'heptabao.capacity-live.v2', 'synthetic_only': True, 'cases': [],
              'binary_sha256': file_hash(binary), 'runner_sha256': file_hash(Path(__file__)),
              'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'source_tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT, text=True).strip(),
              'source_worktree_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
              'production_qualified': False, 'full_openbao_compatibility': False,
              'started_at_unix': time.time(), 'status': 'failed'}

    def check(name, condition):
        report['cases'].append({'case': name, 'passed': bool(condition)})
        if not condition:
            raise ScenarioFailure(name)

    def progress(event, **fields):
        safe = {
            'schema': 'heptabao.capacity-live-progress.v1',
            'event': event,
            'elapsed_ms': int((time.monotonic() - started) * 1000),
        }
        safe.update(fields)
        print(json.dumps(safe, sort_keys=True), flush=True)

    def observe():
        status, body = instance.call('GET', 'sys/internal/capacity')
        check('capacity.observation.' + str(len(report['cases'])), status == 200)
        data = body.get('data')
        validate_observation(data)
        return data

    try:
        stage = 'initialize'
        progress('phase', stage=stage)
        spec = importlib.util.spec_from_file_location('capacity_smoke', ROOT/'qa/single-node/smoke.py')
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        instance = smoke.Instance(binary, root/'server')
        instance.start()
        status, init = instance.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
        check('capacity.init', status == 200)
        instance.token = init['root_token']
        key = init['keys_base64'][0]
        check('capacity.unseal', instance.call('POST', 'sys/unseal', {'key': key})[0] == 200)
        initial = observe()
        check('capacity.profile_is_current_bound', initial['state_limit_bytes'] == CURRENT_STATE_LIMIT_BYTES)
        check('capacity.legacy_bound_retired', initial['state_limit_bytes'] > LEGACY_STATE_LIMIT_BYTES)
        original = instance.token
        instance.token = 'synthetic-invalid-token'
        check('capacity.anonymous_denied', instance.call('GET', 'sys/internal/capacity')[0] == 403)
        instance.token = original

        stage = 'saturation'
        progress('phase', stage=stage, state_limit_bytes=initial['state_limit_bytes'],
                 payload_bytes=SATURATION_PAYLOAD_BYTES, max_writes=MAX_SATURATION_WRITES)
        payload = {'data': {'synthetic': 'x' * SATURATION_PAYLOAD_BYTES}}
        previous = observe()
        latencies = []
        growth_samples = []
        accepted = 0
        crossed_legacy = False
        for number in range(MAX_SATURATION_WRITES):
            start = time.monotonic()
            status, _ = instance.call('POST', 'secret/data/capacity-' + str(number), payload)
            latencies.append((time.monotonic() - start) * 1000)
            if status == 507:
                report['rejected_key_index'] = number
                progress('saturation_refused', attempt=number, accepted=accepted,
                         state_bytes=previous['state_bytes'], journal_bytes=previous['journal_bytes'],
                         retained_operations=previous['retained_operations'])
                break
            check('capacity.write.' + str(number), status == 200)
            accepted += 1
            previous = observe()
            rss_kib = process_rss_kib(instance.process.pid if instance.process else None)
            disk_bytes = tree_bytes(instance.root / 'data')
            growth_samples.append({
                'accepted_writes': accepted,
                'state_bytes': previous['state_bytes'],
                'durable_data_bytes': disk_bytes,
                'write_latency_ms': round(latencies[-1], 3),
                'rss_kib': rss_kib,
            })
            if accepted == 1 or accepted % 8 == 0:
                progress('saturation_progress', accepted=accepted,
                         state_bytes=previous['state_bytes'],
                         state_remaining_bytes=previous['state_remaining_bytes'],
                         journal_bytes=previous['journal_bytes'],
                         retained_operations=previous['retained_operations'],
                         durable_data_bytes=disk_bytes, rss_kib=rss_kib,
                         last_write_ms=round(latencies[-1], 3))
            if previous['state_bytes'] > LEGACY_STATE_LIMIT_BYTES:
                crossed_legacy = True
        else:
            raise ScenarioFailure('capacity.did_not_reach_declared_bound')

        check('capacity.nontrivial_growth', accepted > 1)
        check('capacity.crossed_legacy_ceiling_before_refusal', crossed_legacy)
        saturated = observe()
        check('capacity.rejection_no_state_or_identity_effect', saturated == previous)
        check('capacity.rejected_key_absent', instance.call('GET', 'secret/data/capacity-' + str(accepted))[0] == 404)
        check('capacity.committed_value_readable', instance.call('GET', 'secret/data/capacity-0')[1].get('data', {}).get('data') == payload['data'])
        stage = 'compaction'
        progress('phase', stage=stage, accepted=accepted, state_bytes=saturated['state_bytes'],
                 journal_bytes=saturated['journal_bytes'], retained_operations=saturated['retained_operations'])
        check('capacity.compact', instance.call('POST', 'sys/storage/raft/compact', {})[0] == 200)
        compacted = observe()
        check('capacity.compaction_not_ledger_gc', compacted['retained_operations'] == saturated['retained_operations'])
        check('capacity.compaction_not_state_growth', compacted['state_bytes'] == saturated['state_bytes'])
        stage = 'restart'
        progress('phase', stage=stage, generation=compacted['generation'])
        instance.stop()
        instance.start()
        check('capacity.reopen_sealed', instance.call('GET', 'sys/internal/capacity')[0] == 503)
        check('capacity.reopen_unseal', instance.call('POST', 'sys/unseal', {'key': key})[0] == 200)
        reopened = observe()
        check('capacity.reopen_exact', reopened == compacted)
        check('capacity.reopen_rejected_key_absent', instance.call('GET', 'secret/data/capacity-' + str(accepted))[0] == 404)
        check('capacity.binary_unchanged', file_hash(binary) == report['binary_sha256'])
        report.update(status='passed', initial=initial, saturated=saturated, after_compaction=compacted,
                      accepted_writes=accepted,
                      legacy_state_limit_bytes=LEGACY_STATE_LIMIT_BYTES,
                      current_state_limit_bytes=CURRENT_STATE_LIMIT_BYTES,
                      saturation_payload_bytes=SATURATION_PAYLOAD_BYTES,
                      latency_ms={'min': min(latencies), 'max': max(latencies),
                                  'mean': sum(latencies)/len(latencies)},
                      growth_samples=growth_samples,
                      peak_rss_kib=max((sample['rss_kib'] for sample in growth_samples
                                        if sample['rss_kib'] is not None), default=None),
                      durable_bytes_at_refusal=tree_bytes(instance.root / 'data'),
                      scope='bounded_chunked_whole_state_refusal_with_growth_curve_not_scale_qualification')
    except Exception as error:
        progress('failure', stage=stage, failure_type=type(error).__name__)
        report['failure'] = str(error) if isinstance(error, ScenarioFailure) else type(error).__name__
    finally:
        if instance is not None:
            try:
                instance.stop()
            except Exception:
                report['status'], report['failure'] = 'failed', 'cleanup_failed'
        try:
            shutil.rmtree(root)
        except OSError:
            report['status'], report['failure'] = 'failed', 'private_fixture_cleanup_failed'
        report['finished_at_unix'] = time.time()
        private_write(output, report, replace=False)
    print(json.dumps({
        'status': report['status'],
        'cases': len(report['cases']),
        'failure': report.get('failure'),
        'accepted_writes': report.get('accepted_writes'),
        'peak_rss_kib': report.get('peak_rss_kib'),
        'durable_bytes_at_refusal': report.get('durable_bytes_at_refusal'),
        'mean_write_latency_ms': report.get('latency_ms', {}).get('mean'),
    }, sort_keys=True))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
