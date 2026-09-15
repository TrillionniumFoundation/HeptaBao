#!/usr/bin/env python3
"""Exercise the real server's current capacity refusal/recovery, not a scale claim."""
from pathlib import Path
import importlib.util
import json
import os
import tempfile
from bao_http import BaoError, SafeArgumentParser, private_write
from heptabao.private_state import StateDirectory
from official_openbao_launcher import file_digest

ROOT = Path(__file__).resolve().parents[2]


def run(binary, output):
    checks = []
    def check(name, value):
        if not value:
            raise BaoError('capacity_live_' + name)
        checks.append(name)
    spec = importlib.util.spec_from_file_location('capacity_smoke', ROOT / 'qa/single-node/smoke.py')
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    with tempfile.TemporaryDirectory(prefix='heptabao-capacity-live-') as temporary:
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
            check('current_limit_visible', status == 200 and response['data']['state_limit_bytes'] == 768 * 1024)
            check('unauthenticated_denied', instance.call('GET', path, token='not-authorized')[0] == 403)
            accepted = 0
            for n in range(80):
                status, _ = instance.call('POST', 'secret/data/capacity-' + str(n), {'data': {'v': 'synthetic-capacity-' + 'x' * 16384}})
                if status == 507:
                    break
                check('accepted_' + str(n), status == 200)
                accepted += 1
            check('bounded_capacity_refusal_observed', status == 507 and 1 <= accepted < 80)
            check('rejected_key_absent', instance.call('GET', 'secret/data/capacity-' + str(accepted))[0] == 404)
            status, before = instance.call('GET', path)
            check('refusal_does_not_poison_service', status == 200 and before['data']['recovery_required'] is False)
            status, compacted = instance.call('POST', 'sys/storage/raft/compact', {})
            check('explicit_compaction_preserves_ids', status == 200 and compacted['data']['retained_requests'] == before['data']['retained_requests'])
            instance.stop()
            instance.start()
            check('restart_unseal', instance.call('POST', 'sys/unseal', {'key': key})[0] == 200)
            for n in (0, accepted - 1):
                status, data = instance.call('GET', 'secret/data/capacity-' + str(n))
                check('acknowledged_readback_' + str(n), status == 200 and data['data']['data']['v'].startswith('synthetic-capacity-'))
            status, after = instance.call('GET', path)
            check('restart_preserves_ledger', status == 200 and after['data']['retained_requests'] == before['data']['retained_requests'])
            result = {'schema': 'heptabao.capacity-live.v1', 'status': 'passed_bounded_capacity',
                      'count': len(checks), 'checks': checks, 'accepted_16k_objects': accepted,
                      'candidate_binary_sha256': file_digest(binary), 'state_limit_bytes': 768 * 1024,
                      'production_capacity_qualified': False, 'compatibility_claim': False}
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
    print(json.dumps({k: result[k] for k in ('status', 'count', 'accepted_16k_objects', 'production_capacity_qualified')}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        reason = str(error) if isinstance(error, BaoError) and str(error).startswith('capacity_live_') else 'capacity_fixture_failed'
        print(json.dumps({'status': 'failed', 'reason': reason, 'production_capacity_qualified': False}))
        raise SystemExit(2) from None
