#!/usr/bin/env python3
"""Prove the legacy 768 KiB ceiling is retired without claiming production scale."""
from pathlib import Path
import importlib.util
import json
import os
import tempfile
from bao_http import BaoError, SafeArgumentParser, private_write
from heptabao.private_state import StateDirectory
from official_openbao_launcher import file_digest

ROOT = Path(__file__).resolve().parents[2]
LEGACY_STATE_LIMIT = 768 * 1024
CURRENT_STATE_LIMIT = 16 * 1024 * 1024
OBJECT_COUNT = 56
OBJECT_BYTES = 16 * 1024


def run(binary, output):
    checks = []

    def check(name, value):
        if not value:
            raise BaoError('capacity_legacy_' + name)
        checks.append(name)

    spec = importlib.util.spec_from_file_location(
        'capacity_smoke', ROOT / 'qa/single-node/smoke.py'
    )
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    with tempfile.TemporaryDirectory(prefix='heptabao-capacity-legacy-') as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        instance = smoke.Instance(binary.resolve(), root / 'candidate')
        try:
            instance.start()
            status, init = instance.call(
                'POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1}
            )
            check('init', status == 200)
            instance.token = init['root_token']
            key = init['keys_base64'][0]
            check('unseal', instance.call('POST', 'sys/unseal', {'key': key})[0] == 200)

            path = 'sys/internal/storage/capacity'
            status, response = instance.call('GET', path)
            check(
                'current_limit_visible',
                status == 200
                and response['data']['state_limit_bytes'] == CURRENT_STATE_LIMIT,
            )
            check(
                'unauthenticated_denied',
                instance.call('GET', path, token='not-authorized')[0] == 403,
            )

            # This profile intentionally crosses the historical 768 KiB aggregate
            # state ceiling. The current-bound saturation fixture is capacity_live.py;
            # this fixture must not duplicate it or encode a stale rejection point.
            payload = 'synthetic-capacity-' + 'x' * OBJECT_BYTES
            for n in range(OBJECT_COUNT):
                status, _ = instance.call(
                    'POST',
                    'secret/data/capacity-' + str(n),
                    {'data': {'v': payload + str(n)}},
                )
                check('write_' + str(n), status == 200)

            status, before = instance.call('GET', path)
            check('capacity_readback', status == 200)
            check(
                'legacy_ceiling_crossed',
                before['data']['stored_value_bytes'] > LEGACY_STATE_LIMIT,
            )
            check(
                'current_bound_retained',
                before['data']['state_limit_bytes'] == CURRENT_STATE_LIMIT
                and before['data']['stored_value_bytes'] < CURRENT_STATE_LIMIT,
            )
            check(
                'service_not_poisoned',
                before['data']['recovery_required'] is False,
            )

            status, compacted = instance.call('POST', 'sys/storage/raft/compact', {})
            check(
                'explicit_compaction_preserves_ids',
                status == 200
                and compacted['data']['retained_requests']
                == before['data']['retained_requests'],
            )

            instance.stop()
            instance.start()
            check(
                'restart_unseal',
                instance.call('POST', 'sys/unseal', {'key': key})[0] == 200,
            )
            for n in (0, OBJECT_COUNT - 1):
                status, data = instance.call('GET', 'secret/data/capacity-' + str(n))
                check(
                    'acknowledged_readback_' + str(n),
                    status == 200
                    and data['data']['data']['v'].startswith('synthetic-capacity-'),
                )

            status, after = instance.call('GET', path)
            check(
                'restart_preserves_ledger',
                status == 200
                and after['data']['retained_requests']
                == before['data']['retained_requests'],
            )
            check(
                'restart_preserves_legacy_ceiling_exit',
                after['data']['stored_value_bytes'] > LEGACY_STATE_LIMIT,
            )

            result = {
                'schema': 'heptabao.capacity-legacy-transition.v2',
                'status': 'passed_legacy_ceiling_retired',
                'count': len(checks),
                'checks': checks,
                'accepted_16k_objects': OBJECT_COUNT,
                'candidate_binary_sha256': file_digest(binary),
                'legacy_state_limit_bytes': LEGACY_STATE_LIMIT,
                'current_state_limit_bytes': CURRENT_STATE_LIMIT,
                'observed_state_bytes': after['data']['stored_value_bytes'],
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
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    'status',
                    'count',
                    'accepted_16k_objects',
                    'current_state_limit_bytes',
                    'production_capacity_qualified',
                )
            }
        )
    )
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        reason = (
            str(error)
            if isinstance(error, BaoError)
            and str(error).startswith('capacity_legacy_')
            else 'capacity_legacy_fixture_failed'
        )
        print(
            json.dumps(
                {
                    'status': 'failed',
                    'reason': reason,
                    'production_capacity_qualified': False,
                }
            )
        )
        raise SystemExit(2) from None
