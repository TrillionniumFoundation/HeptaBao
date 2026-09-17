#!/usr/bin/env python3
"""Measure the real bounded service on a new synthetic loopback TLS instance.

No existing endpoint, credentials or data directory can be supplied. A pass
proves the bounded profile's refusal/reopen semantics, never production scale.
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
    report = {'schema': 'heptabao.capacity-live.v1', 'synthetic_only': True, 'cases': [],
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

    def observe():
        status, body = instance.call('GET', 'sys/internal/capacity')
        check('capacity.observation.' + str(len(report['cases'])), status == 200)
        data = body.get('data')
        validate_observation(data)
        return data

    try:
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
        check('capacity.profile_is_bounded', initial['state_limit_bytes'] == 16 * 1024 * 1024)
        original = instance.token
        instance.token = 'synthetic-invalid-token'
        check('capacity.anonymous_denied', instance.call('GET', 'sys/internal/capacity')[0] == 403)
        instance.token = original
        # Stay below the normal 256 KiB request-body limit while reaching the
        # current 16 MiB aggregate state bound in a bounded number of writes.
        # This intentionally exercises whole-state growth; it is not a scale SLO.
        payload = {'data': {'synthetic': 'x' * (224 * 1024)}}
        previous = observe()
        latencies = []
        accepted = 0
        for number in range(96):
            start = time.monotonic()
            status, _ = instance.call('POST', 'secret/data/capacity-' + str(number), payload)
            latencies.append((time.monotonic() - start) * 1000)
            if status == 507:
                report['rejected_key_index'] = number
                break
            check('capacity.write.' + str(number), status == 200)
            accepted += 1
            previous = observe()
        else:
            raise ScenarioFailure('capacity.did_not_reach_declared_bound')
        check('capacity.nontrivial_growth', accepted > 1)
        saturated = observe()
        check('capacity.rejection_no_state_or_identity_effect', saturated == previous)
        check('capacity.rejected_key_absent', instance.call('GET', 'secret/data/capacity-' + str(accepted))[0] == 404)
        check('capacity.committed_value_readable', instance.call('GET', 'secret/data/capacity-0')[1].get('data', {}).get('data') == payload['data'])
        check('capacity.compact', instance.call('POST', 'sys/storage/raft/compact', {})[0] == 200)
        compacted = observe()
        check('capacity.compaction_not_ledger_gc', compacted['retained_operations'] == saturated['retained_operations'])
        check('capacity.compaction_not_state_growth', compacted['state_bytes'] == saturated['state_bytes'])
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
                      latency_ms={'min': min(latencies), 'max': max(latencies),
                                  'mean': sum(latencies)/len(latencies)},
                      scope='bounded_capacity_refusal_not_scale_qualification')
    except Exception as error:
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
    print(json.dumps({'status': report['status'], 'cases': len(report['cases']), 'failure': report.get('failure')}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
