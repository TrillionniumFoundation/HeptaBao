#!/usr/bin/env python3
"""Prove the current server safely crosses the historical 768 KiB state ceiling.

This is a compatibility/regression fixture for the former PR96 bounded-state
profile. It no longer expects the obsolete 768 KiB limit: the current server
uses a 16 MiB chunked whole-state representation. The fixture deliberately
writes enough synthetic state to exceed the historical ceiling, then verifies
restart/readback and replay-ledger preservation. It is not a scale claim.
"""
from pathlib import Path
import importlib.util
import json
import os
import tempfile
from bao_http import BaoError, SafeArgumentParser, private_write
from heptabao.private_state import StateDirectory
from official_openbao_launcher import file_digest

ROOT = Path(__file__).resolve().parents[2]
LEGACY_STATE_LIMIT_BYTES = 768 * 1024
CURRENT_STATE_LIMIT_BYTES = 16 * 1024 * 1024
PAYLOAD_BYTES = 192 * 1024
CROSSING_WRITES = 6


def run(binary, output):
    checks = []

    def check(name, value):
        if not value:
            raise BaoError('capacity_legacy_' + name)
        checks.append(name)

    spec = importlib.util.spec_from_file_location('capacity_smoke', ROOT / 'qa/single-node/smoke.py')
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    with tempfile.TemporaryDirectory(prefix='heptabao-capacity-legacy-live-') as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        instance = smoke.Instance(binary.resolve(), root / 'candidate')
        try:
            instance.start()
            status, init = instance.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
            check('init', status == 200)
            instance.token = init['root_token']
            key = init['keys_base64'][0]
            check('unseal', instance.call('POST', 'sys/unseal', {'key': key})[0] == 200)
            path = 'sys/internal/storage/capacity'
            status, response = instance.call('GET', path)
            data = response.get('data', {})
            check(
                'current_limit_visible',
                status == 200 and data.get('state_limit_bytes') == CURRENT_STATE_LIMIT_BYTES,
            )
            check('legacy_limit_retired', data.get('state_limit_bytes', 0) > LEGACY_STATE_LIMIT_BYTES)
            check('unauthenticated_denied', instance.call('GET', path, token='not-authorized')[0] == 403)

            payload = {'data': {'v': 'synthetic-capacity-' + 'x' * PAYLOAD_BYTES}}
            for n in range(CROSSING_WRITES):
                status, _ = instance.call('POST', 'secret/data/capacity-legacy-' + str(n), payload)
                check('accepted_' + str(n), status == 200)

            status, crossed = instance.call('GET', path)
            crossed_data = crossed.get('data', {})
            check('crossed_observation', status == 200)
            check(
                'historical_ceiling_crossed',
                crossed_data.get('state_bytes', 0) > LEGACY_STATE_LIMIT_BYTES,
            )
            check('crossing_does_not_poison_service', crossed_data.get('recovery_required') is False)
            check(
                'current_bound_still_enforced',
                crossed_data.get('state_bytes', CURRENT_STATE_LIMIT_BYTES + 1) < CURRENT_STATE_LIMIT_BYTES,
            )

            status, compacted = instance.call('POST', 'sys/storage/raft/compact', {})
            check(
                'explicit_compaction_preserves_ids',
                status == 200
                and compacted.get('data', {}).get('retained_requests')
                == crossed_data.get('retained_requests'),
            )
            instance.stop()
            instance.start()
            check('restart_unseal', instance.call('POST', 'sys/unseal', {'key': key})[0] == 200)
            for n in (0, CROSSING_WRITES - 1):
                status, body = instance.call('GET', 'secret/data/capacity-legacy-' + str(n))
                check(
                    'acknowledged_readback_' + str(n),
                    status == 200 and body['data']['data']['v'].startswith('synthetic-capacity-'),
                )
            status, after = instance.call('GET', path)
            check(
                'restart_preserves_ledger',
                status == 200
                and after.get('data', {}).get('retained_requests') == crossed_data.get('retained_requests'),
            )
            check(
                'restart_preserves_crossed_state',
                after.get('data', {}).get('state_bytes', 0) > LEGACY_STATE_LIMIT_BYTES,
            )
            result = {
                'schema': 'heptabao.capacity-legacy-crossing.v2',
                'status': 'passed_legacy_ceiling_crossing',
                'count': len(checks),
                'checks': checks,
                'crossing_writes': CROSSING_WRITES,
                'payload_bytes_per_write': PAYLOAD_BYTES,
                'candidate_binary_sha256': file_digest(binary),
                'legacy_state_limit_bytes': LEGACY_STATE_LIMIT_BYTES,
                'current_state_limit_bytes': CURRENT_STATE_LIMIT_BYTES,
                'observed_state_bytes_after_crossing': after.get('data', {}).get('state_bytes'),
                'production_capacity_qualified': False,
                'compatibility_claim': False,
            }
            private_write(output, result, replace=False)
            return result
        finally:
            instance.stop()


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    with StateDirectory(args.output.absolute().parent):
        if os.path.lexists(args.output):
            raise BaoError('output_already_exists')
    result = run(args.binary, args.output)
    print(json.dumps({
        k: result[k]
        for k in ('status', 'count', 'crossing_writes', 'production_capacity_qualified')
    }))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        reason = (
            str(error)
            if isinstance(error, BaoError) and str(error).startswith('capacity_legacy_')
            else 'capacity_legacy_fixture_failed'
        )
        print(json.dumps({'status': 'failed', 'reason': reason, 'production_capacity_qualified': False}))
        raise SystemExit(2) from None
