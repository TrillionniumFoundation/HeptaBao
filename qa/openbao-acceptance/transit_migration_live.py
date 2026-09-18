#!/usr/bin/env python3
"""Real pinned OpenBao -> HeptaBao Transit re-encryption; synthetic loopback only."""
from pathlib import Path
import base64
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile

from bao_http import BaoError, Client, SafeArgumentParser, private_write, private_json
from official_openbao_launcher import start_oracle, stop_oracle, file_digest, private_text, BINARY_SHA256
from heptabao.private_state import StateDirectory
from heptabao.transit_migration import TransitMigrator, client_for

ROOT = Path(__file__).resolve().parents[2]


def run(binary, output):
    checks = []
    def check(name, condition):
        if not condition:
            raise BaoError('transit_live_' + name)
        checks.append(name)
    if not all(Path(os.environ.get(name, '/absent-oracle')).is_file() for name in ('HB_ORACLE_BINARY', 'HB_ORACLE_ARCHIVE')):
        raise FileNotFoundError('pinned oracle prerequisite missing')
    with tempfile.TemporaryDirectory(prefix='heptabao-transit-live-') as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        oracle = instance = None
        spec = importlib.util.spec_from_file_location('transit_migration_smoke', ROOT / 'qa/single-node/smoke.py')
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        try:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            oracle = start_oracle(port)
            source = Client(oracle['address'], oracle['ca_file'], Path(oracle['token_file']).read_text().strip())
            instance = smoke.Instance(binary.resolve(), root / 'candidate')
            instance.start()
            status, init = instance.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
            check('candidate_init', status == 200)
            instance.token = init['root_token']
            key = init['keys_base64'][0]
            check('candidate_unseal', instance.call('POST', 'sys/unseal', {'key': key})[0] == 200)
            target = Client(instance.address, str(instance.root / 'ca.crt'), instance.token)
            check('source_mount', source.request('POST', '/v1/sys/mounts/transit', {'type': 'transit'}).status == 204)
            check('source_key', source.request('POST', '/v1/transit/keys/source', {'type': 'aes256-gcm96'}).status in (200, 204))
            check('target_key', target.request('POST', '/v1/transit/keys/destination', {'type': 'aes256-gcm96'}).status in (200, 204))
            check('target_rotate', target.request('POST', '/v1/transit/keys/destination/rotate', {}).status in (200, 204))
            check('disable_target_upsert', target.request('POST', '/v1/transit/config/keys', {'disable_upsert': True}).status in (200, 204))
            records = []
            plaintexts = [b'synthetic-transit-migration-v1', b'synthetic-transit-migration-v2']
            for number, plaintext in enumerate(plaintexts, 1):
                if number == 2:
                    check('source_rotate', source.request('POST', '/v1/transit/keys/source/rotate', {}).status in (200, 204))
                encrypted = source.request('POST', '/v1/transit/encrypt/source', {'plaintext': base64.b64encode(plaintext).decode(), 'associated_data': 'YWFk'})
                check('source_encrypt_' + str(number), encrypted.status == 200)
                records.append({'id': 'record-' + str(number), 'ciphertext': encrypted.data()['ciphertext'], 'associated_data': 'YWFk'})
            check('source_old_and_new_versions', records[0]['ciphertext'].startswith('vault:v1:') and records[1]['ciphertext'].startswith('vault:v2:'))
            private_text(root / 'target.token', instance.token)
            config = {'target_key_version': 2,
                'source': {'address': oracle['address'], 'ca_file': oracle['ca_file'], 'token_file': oracle['token_file'],
                           'namespace': '', 'mount': 'transit', 'key': 'source'},
                'target': {'address': instance.address, 'ca_file': str(instance.root / 'ca.crt'), 'token_file': str(root / 'target.token'),
                           'namespace': '', 'mount': 'transit', 'key': 'destination'}}
            private_write(root / 'config.json', config, replace=False)
            private_write(root / 'input.json', records, replace=False)
            state = root / 'state'
            state.mkdir(mode=0o700)
            command = [sys.executable, str(ROOT / 'qa/openbao-acceptance/migrate_transit.py'),
                       '--config', str(root / 'config.json'), '--input', str(root / 'input.json'), '--state-dir', str(state)]
            dry = subprocess.run(command, capture_output=True, timeout=30)
            check('dry_run_no_network', dry.returncode == 0 and json.loads(dry.stdout)['status'] == 'dry_run_no_network' and not list(state.iterdir()))
            applied = subprocess.run(command + ['--allow-reencryption'], capture_output=True, timeout=60)
            check('actual_cli_reencryption', applied.returncode == 0)
            report = json.loads(applied.stdout)
            check('all_records_verified_without_cutover', report['converted'] == 2 and report['source_cutover'] is False)
            for index, row in enumerate(records):
                import hashlib
                filename = 'transit-' + hashlib.sha256(row['id'].encode()).hexdigest() + '.json'
                checkpoint = private_json(state / filename)
                check('persisted_target_version_' + str(index), checkpoint['phase'] == 'verified' and checkpoint['target_ciphertext'].startswith('vault:v2:'))
                plain = target.request('POST', '/v1/transit/decrypt/destination', {'ciphertext': checkpoint['target_ciphertext'], 'associated_data': 'YWFk'})
                check('independent_target_readback_' + str(index), plain.status == 200 and base64.b64decode(plain.data()['plaintext']) == plaintexts[index])
            before = target.request('GET', '/v1/sys/internal/storage/capacity').data()['generation']
            instance.stop()
            instance.start()
            check('restart_unseal', instance.call('POST', 'sys/unseal', {'key': key})[0] == 200)
            repeated = subprocess.run(command + ['--allow-reencryption'], capture_output=True, timeout=60)
            check('restart_resume_reuses_verified_outputs', repeated.returncode == 0 and json.loads(repeated.stdout)['reused'] == 2)
            after = target.request('GET', '/v1/sys/internal/storage/capacity').data()['generation']
            check('resume_does_not_reencrypt', before == after)
            for path in state.iterdir():
                raw = path.read_bytes()
                check('checkpoint_private_' + str(len(checks)), path.stat().st_mode & 0o777 == 0o600)
                for plaintext in plaintexts:
                    check('no_plaintext_' + str(len(checks)), plaintext not in raw and base64.b64encode(plaintext) not in raw)
            # Discard an ACTUAL successful encryption reply before the tool sees it.
            class LostReply:
                def health(self):
                    return target.health()
                def request(self, method, path, payload=None):
                    response = target.request(method, path, payload)
                    if '/encrypt/' in path and response.status == 200:
                        raise BaoError('injected_real_committed_reply_loss')
                    return response
            lost_root = root / 'lost-reply'
            lost_root.mkdir(mode=0o700)
            _, source_ca = client_for(config['source'])
            _, target_ca = client_for(config['target'])
            with StateDirectory(lost_root, writer=True) as directory:
                try:
                    TransitMigrator(directory, config, records[:1], clients=(source, LostReply(), source_ca, target_ca)).migrate()
                    check('lost_reply_must_not_pass', False)
                except BaoError as error:
                    check('real_lost_reply_observed', str(error) == 'injected_real_committed_reply_loss')
                before = target.request('GET', '/v1/sys/internal/storage/capacity').data()['generation']
                try:
                    TransitMigrator(directory, config, records[:1], clients=(source, target, source_ca, target_ca)).migrate()
                    check('pending_must_not_retry', False)
                except BaoError as error:
                    check('pending_lost_reply_blocked', str(error) == 'migration_outcome_unknown_no_automatic_retry')
                after = target.request('GET', '/v1/sys/internal/storage/capacity').data()['generation']
                check('pending_resume_no_new_effect', before == after)
            result = {'schema': 'heptabao.transit-migration-live.v1', 'status': 'passed_scoped_reencryption',
                      'checks': checks, 'count': len(checks), 'candidate_binary_sha256': file_digest(binary),
                      'oracle_binary_sha256': BINARY_SHA256, 'full_format_migration': False,
                      'source_cutover': False, 'independent_qualification': False}
            private_write(output, result, replace=False)
            return result
        finally:
            if instance is not None:
                instance.stop()
            if oracle is not None:
                stop_oracle(oracle)
                shutil.rmtree(oracle['root'], ignore_errors=True)


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if os.path.lexists(args.output):
        raise BaoError('output_already_exists')
    with StateDirectory(args.output.absolute().parent):
        pass
    result = run(args.binary, args.output)
    print(json.dumps({key: result[key] for key in ('status', 'count', 'full_format_migration')}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except FileNotFoundError:
        print(json.dumps({'status': 'blocked_prerequisite', 'full_format_migration': False}))
        raise SystemExit(77) from None
    except Exception as error:
        # Fixed fixture scenario IDs only, never raw external exceptions.
        reason = str(error) if isinstance(error, BaoError) and str(error).startswith('transit_live_') else 'live_reencryption_failed'
        print(json.dumps({'status': 'failed', 'reason': reason, 'full_format_migration': False}))
        raise SystemExit(2) from None
