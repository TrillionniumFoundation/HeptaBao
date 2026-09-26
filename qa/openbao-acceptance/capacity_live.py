#!/usr/bin/env python3
"""Measure the real V4-to-V5 capacity boundary on a synthetic TLS instance.

No existing endpoint, credentials or data directory can be supplied. The
qualification binary enables a lower-only opaque-owner limit so the same
production admission path can reach refusal quickly. The seam cannot raise the
canonical 16 MiB ceiling and does not qualify production scale.
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

DEFAULT_OPAQUE_OWNER_LIMIT_BYTES = 16 * 1024 * 1024
QUALIFICATION_OPAQUE_OWNER_LIMIT_BYTES = 2 * 1024 * 1024
KV1_ENCODED_GRAPH_LIMIT_BYTES = 64 * 1024 * 1024
PRE_RECORD_STATE_FLOOR_BYTES = 768 * 1024
SATURATION_PAYLOAD_BYTES = 224 * 1024
MAX_SATURATION_WRITES = 16


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


def process_write_bytes(pid: int | None) -> int | None:
    if pid is None:
        return None
    path = Path('/proc') / str(pid) / 'io'
    try:
        for line in path.read_text().splitlines():
            if line.startswith('write_bytes:'):
                return int(line.split(':', 1)[1].strip())
    except (OSError, ValueError):
        return None
    return None


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) * quantile + 0.999999) - 1)))
    return ordered[index]


def growth_curve(samples: list[dict], baseline_write_bytes: int | None) -> list[dict]:
    points = []
    previous_count = 0
    previous_elapsed = 0.0
    previous_write_bytes = baseline_write_bytes
    for end in list(range(8, len(samples) + 1, 8)) + ([len(samples)] if len(samples) % 8 else []):
        window = samples[previous_count:end]
        end_sample = samples[end - 1]
        elapsed = max(0.000001, end_sample['elapsed_seconds'] - previous_elapsed)
        latencies = [sample['write_latency_ms'] for sample in window]
        current_write_bytes = end_sample.get('process_write_bytes')
        physical_delta = (
            current_write_bytes - previous_write_bytes
            if current_write_bytes is not None and previous_write_bytes is not None
            else None
        )
        logical_bytes = len(window) * SATURATION_PAYLOAD_BYTES
        points.append({
            'accepted_writes': end,
            'state_bytes': end_sample['state_bytes'],
            'durable_data_bytes': end_sample['durable_data_bytes'],
            'window_writes': len(window),
            'throughput_writes_per_second': round(len(window) / elapsed, 3),
            'latency_ms': {
                'p50': round(percentile(latencies, 0.50), 3),
                'p95': round(percentile(latencies, 0.95), 3),
                'p99': round(percentile(latencies, 0.99), 3),
                'max': round(max(latencies), 3),
            },
            'peak_rss_kib': max(
                (sample['rss_kib'] for sample in window if sample['rss_kib'] is not None),
                default=None,
            ),
            'process_write_bytes_delta': physical_delta,
            'logical_payload_bytes': logical_bytes,
            'physical_write_amplification': (
                round(physical_delta / logical_bytes, 3)
                if physical_delta is not None and logical_bytes
                else None
            ),
        })
        previous_count = end
        previous_elapsed = end_sample['elapsed_seconds']
        previous_write_bytes = current_write_bytes
    return points


def validate_observation(data: dict) -> None:
    names = (
        'state_schema', 'state_bytes', 'state_limit_bytes', 'state_remaining_bytes',
        'generation', 'retained_operations', 'operation_limit', 'operations_remaining',
        'journal_bytes', 'journal_limit_bytes', 'state_chunk_target_bytes',
        'durable_payload_bytes', 'durable_artifact_limit_bytes',
        'opaque_owner_limit_bytes', 'kv1_encoded_graph_limit_bytes',
        'kv_read_only_dispatches',
    )
    if not isinstance(data, dict) or any(
        type(data.get(key)) is not int or data[key] < 0 for key in names
    ):
        raise ScenarioFailure('capacity.invalid_observation')
    if data.get('scope') != 'serving-leader-local':
        raise ScenarioFailure('capacity.invalid_scope')
    opaque_limit = data['opaque_owner_limit_bytes']
    graph_limit = data['kv1_encoded_graph_limit_bytes']
    if not 1024 * 1024 <= opaque_limit <= DEFAULT_OPAQUE_OWNER_LIMIT_BYTES:
        raise ScenarioFailure('capacity.invalid_opaque_owner_limit')
    if graph_limit != KV1_ENCODED_GRAPH_LIMIT_BYTES:
        raise ScenarioFailure('capacity.kv1_graph_limit_drift')
    profile = data.get('profile')
    if profile == 'bounded-owner-state-v4':
        valid_profile = (
            data.get('state_storage_format') == 'heptabao-state-owners-v4'
            and data.get('state_size_basis') == 'canonical-state-json'
            and data['state_chunk_target_bytes'] == 512 * 1024
            and data['state_limit_bytes'] == opaque_limit
        )
    elif profile == 'bounded-record-state-v5':
        valid_profile = (
            data.get('state_storage_format') == 'heptabao-state-records-v5'
            and data.get('state_size_basis')
                == 'opaque-owner-json-plus-kv1-canonical-values'
            and data['state_chunk_target_bytes'] == 256 * 1024
            and data['state_limit_bytes'] == opaque_limit + graph_limit
        )
    else:
        valid_profile = False
    if not valid_profile:
        raise ScenarioFailure('capacity.storage_profile_drift')
    for used, limit, remaining in (
        ('state_bytes', 'state_limit_bytes', 'state_remaining_bytes'),
        ('retained_operations', 'operation_limit', 'operations_remaining'),
    ):
        if data[used] > data[limit] or data[remaining] != data[limit] - data[used]:
            raise ScenarioFailure('capacity.inconsistent_bound')
    if data['journal_bytes'] > data['journal_limit_bytes']:
        raise ScenarioFailure('capacity.journal_bound')
    for key in (
        'state_remaining_is_admission_budget', 'admission_reserved',
        'compaction_reclaims_operation_identities', 'full_openbao_compatibility',
        'production_qualified',
    ):
        if data.get(key) is not False:
            raise ScenarioFailure('capacity.inflated_claim')


def main(argv=None) -> int:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output.absolute()
    if os.path.lexists(output):
        raise BaoError('output_already_exists')
    with StateDirectory(output.parent):
        pass
    return run(args.binary, output)


def run(binary: Path, output: Path) -> int:
    binary = binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='heptabao-capacity-live-'))
    root.chmod(0o700)
    instance = None
    started = time.monotonic()
    stage = 'setup'
    report = {'schema': 'heptabao.capacity-live.v3', 'synthetic_only': True, 'cases': [],
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

    recovery_samples = []

    def restart_and_measure(label, expected, key):
        state_bytes = expected['state_bytes']
        durable_bytes = tree_bytes(instance.root / 'data')
        started_recovery = time.monotonic()
        instance.stop()
        instance.start()
        startup_ms = (time.monotonic() - started_recovery) * 1000
        check(f'capacity.{label}.reopen_sealed',
              instance.call('GET', 'sys/internal/capacity')[0] == 503)
        unseal_started = time.monotonic()
        check(f'capacity.{label}.reopen_unseal',
              instance.call('POST', 'sys/unseal', {'key': key})[0] == 200)
        reopened = observe()
        unseal_and_load_ms = (time.monotonic() - unseal_started) * 1000
        total_ms = (time.monotonic() - started_recovery) * 1000
        check(f'capacity.{label}.read_counter_reset', reopened.get('kv_read_only_dispatches') == 0)
        check(f'capacity.{label}.reopen_exact',
              {k: v for k, v in reopened.items() if k != 'kv_read_only_dispatches'} ==
              {k: v for k, v in expected.items() if k != 'kv_read_only_dispatches'})
        recovery_samples.append({
            'label': label,
            'state_bytes': state_bytes,
            'durable_data_bytes': durable_bytes,
            'startup_ms': round(startup_ms, 3),
            'unseal_and_load_ms': round(unseal_and_load_ms, 3),
            'total_recovery_ms': round(total_ms, 3),
            'rss_after_recovery_kib': process_rss_kib(
                instance.process.pid if instance.process else None
            ),
        })
        progress('recovery_sample', label=label, state_bytes=state_bytes,
                 durable_data_bytes=durable_bytes, total_recovery_ms=round(total_ms, 3))
        return reopened

    try:
        stage = 'initialize'
        progress('phase', stage=stage)
        spec = importlib.util.spec_from_file_location('capacity_smoke', ROOT/'qa/single-node/smoke.py')
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        instance = smoke.Instance(binary, root/'server')
        config_path = instance.root / 'server.json'
        config = json.loads(config_path.read_text())
        config['fixture_opaque_owner_limit_bytes'] = QUALIFICATION_OPAQUE_OWNER_LIMIT_BYTES
        config_path.write_text(json.dumps(config, sort_keys=True))
        config_path.chmod(0o600)
        instance.start()
        status, init = instance.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
        check('capacity.init', status == 200)
        instance.token = init['root_token']
        key = init['keys_base64'][0]
        check('capacity.unseal', instance.call('POST', 'sys/unseal', {'key': key})[0] == 200)
        initial = observe()
        check('capacity.initial_profile_is_v4', initial['profile'] == 'bounded-owner-state-v4')
        check(
            'capacity.qualification_limit_is_exact_lower_only',
            initial['opaque_owner_limit_bytes'] == QUALIFICATION_OPAQUE_OWNER_LIMIT_BYTES
            and initial['state_limit_bytes'] == QUALIFICATION_OPAQUE_OWNER_LIMIT_BYTES
            and initial['opaque_owner_limit_bytes'] < DEFAULT_OPAQUE_OWNER_LIMIT_BYTES,
        )
        check(
            'capacity.pre_record_floor_retired',
            initial['state_limit_bytes'] > PRE_RECORD_STATE_FLOOR_BYTES,
        )
        original = instance.token
        instance.token = 'synthetic-invalid-token'
        check('capacity.anonymous_denied', instance.call('GET', 'sys/internal/capacity')[0] == 403)
        instance.token = original
        stage = 'initial-recovery'
        progress('phase', stage=stage, state_bytes=initial['state_bytes'])
        initial = restart_and_measure('initial', initial, key)

        stage = 'saturation'
        progress(
            'phase', stage=stage,
            opaque_owner_limit_bytes=initial['opaque_owner_limit_bytes'],
            aggregate_diagnostic_limit_bytes=initial['state_limit_bytes'],
            payload_bytes=SATURATION_PAYLOAD_BYTES,
            max_writes=MAX_SATURATION_WRITES,
        )
        payload = {'data': {'synthetic': 'x' * SATURATION_PAYLOAD_BYTES}}
        previous = observe()
        latencies = []
        growth_samples = []
        saturation_started = time.monotonic()
        saturation_io_baseline = process_write_bytes(
            instance.process.pid if instance.process else None
        )
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
            check(
                'capacity.v5_profile_after_write.' + str(number),
                previous['profile'] == 'bounded-record-state-v5'
                and previous['opaque_owner_limit_bytes']
                    == QUALIFICATION_OPAQUE_OWNER_LIMIT_BYTES
                and previous['state_limit_bytes']
                    == QUALIFICATION_OPAQUE_OWNER_LIMIT_BYTES
                    + KV1_ENCODED_GRAPH_LIMIT_BYTES,
            )
            rss_kib = process_rss_kib(instance.process.pid if instance.process else None)
            disk_bytes = tree_bytes(instance.root / 'data')
            growth_samples.append({
                'accepted_writes': accepted,
                'state_bytes': previous['state_bytes'],
                'durable_data_bytes': disk_bytes,
                'write_latency_ms': round(latencies[-1], 3),
                'rss_kib': rss_kib,
                'process_write_bytes': process_write_bytes(
                    instance.process.pid if instance.process else None
                ),
                'elapsed_seconds': round(time.monotonic() - saturation_started, 6),
            })
            if accepted == 1 or accepted % 8 == 0:
                progress('saturation_progress', accepted=accepted,
                         state_bytes=previous['state_bytes'],
                         state_remaining_bytes=previous['state_remaining_bytes'],
                         journal_bytes=previous['journal_bytes'],
                         retained_operations=previous['retained_operations'],
                         durable_data_bytes=disk_bytes, rss_kib=rss_kib,
                         last_write_ms=round(latencies[-1], 3))
            if previous['state_bytes'] > PRE_RECORD_STATE_FLOOR_BYTES:
                crossed_legacy = True
        else:
            raise ScenarioFailure('capacity.did_not_reach_declared_bound')

        check('capacity.nontrivial_growth', accepted > 1)
        check('capacity.crossed_pre_record_floor_before_refusal', crossed_legacy)
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
        stage = 'lowered-limit-reopen'
        progress('phase', stage=stage)
        check('capacity.lowered_limit_below_existing_state', compacted['state_bytes'] > 1024 * 1024)
        instance.stop()
        config = json.loads(config_path.read_text())
        config['fixture_opaque_owner_limit_bytes'] = 1024 * 1024
        config_path.write_text(json.dumps(config, sort_keys=True))
        instance.start()
        status, body = instance.call('POST', 'sys/unseal', {'key': key})
        check('capacity.lowered_limit_rejects_existing_state',
              status == 507 and body.get('errors') == ['opaque owner capacity exhausted'])
        check('capacity.lowered_limit_keeps_server_sealed',
              instance.call('GET', 'sys/health')[0] == 503)
        check('capacity.lowered_limit_releases_no_capacity_view',
              instance.call('GET', 'sys/internal/capacity')[0] == 503)
        instance.stop()
        config['fixture_opaque_owner_limit_bytes'] = QUALIFICATION_OPAQUE_OWNER_LIMIT_BYTES
        config_path.write_text(json.dumps(config, sort_keys=True))
        stage = 'restart'
        progress('phase', stage=stage, generation=compacted['generation'])
        reopened = restart_and_measure('near-capacity', compacted, key)
        check('capacity.reopen_rejected_key_absent', instance.call('GET', 'secret/data/capacity-' + str(accepted))[0] == 404)
        check('capacity.binary_unchanged', file_hash(binary) == report['binary_sha256'])
        report.update(status='passed', initial=initial, saturated=saturated, after_compaction=compacted,
                      accepted_writes=accepted,
                      pre_record_state_floor_bytes=PRE_RECORD_STATE_FLOOR_BYTES,
                      default_opaque_owner_limit_bytes=DEFAULT_OPAQUE_OWNER_LIMIT_BYTES,
                      configured_opaque_owner_limit_bytes=QUALIFICATION_OPAQUE_OWNER_LIMIT_BYTES,
                      kv1_encoded_graph_limit_bytes=KV1_ENCODED_GRAPH_LIMIT_BYTES,
                      saturation_payload_bytes=SATURATION_PAYLOAD_BYTES,
                      latency_ms={'min': min(latencies), 'max': max(latencies),
                                  'mean': sum(latencies)/len(latencies),
                                  'p50': percentile(latencies, 0.50),
                                  'p95': percentile(latencies, 0.95),
                                  'p99': percentile(latencies, 0.99)},
                      growth_samples=growth_samples,
                      growth_curve=growth_curve(growth_samples, saturation_io_baseline),
                      recovery_curve=recovery_samples,
                      peak_rss_kib=max((sample['rss_kib'] for sample in growth_samples
                                        if sample['rss_kib'] is not None), default=None),
                      durable_bytes_at_refusal=tree_bytes(instance.root / 'data'),
                      scope='lower_only_real_v4_to_v5_opaque_owner_admission_with_physical_write_amplification_throughput_tail_latency_rss_and_recovery_curves_not_scale_qualification')
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
        'max_recovery_ms': max(
            (sample['total_recovery_ms'] for sample in report.get('recovery_curve', [])),
            default=None,
        ),
    }, sort_keys=True))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
