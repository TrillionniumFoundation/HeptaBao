#!/usr/bin/env python3
"""Privately prepare one validated native account, prove SDK rollback and V6 recovery."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

def main():
    p = argparse.ArgumentParser()
    for name in ('work-dir', 'helpers', 'native-proof', 'native-capture', 'native-source', 'prepare-child', 'read-child', 'binary', 'server-source', 'client-modules'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--binary-sha256', required=True)
    args = p.parse_args(); os.umask(0o077)
    spec = importlib.util.spec_from_file_location('private_stage_helpers', args.helpers)
    h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
    root = args.work_dir; root.mkdir(mode=0o700); (root / 'tmp').mkdir(mode=0o700)
    report = {'schema': 'heptabao.native-profile-private-v6-stage.v1', 'ok': False,
              'productionChanged': False, 'productionTrafficCutover': False, 'providerMutationAttempted': False,
              'providerReadsInThisRun': 0, 'modelCalled': False, 'j3160Contacted': False,
              'allAccountsQualified': False, 'productionGatewaySelectionQualified': False,
              'credentialValuesPublished': False, 'checks': []}
    instance = None
    def check(name, value, **detail):
        report['checks'].append({'case': name, 'passed': bool(value), **detail}); h.need(value, name)
    try:
        proof = json.loads(args.native_proof.read_bytes())
        check('current_native_proof', proof.get('ok') is True and proof.get('singleCurrentNativeCredentialValidated') is True)
        check('native_capture_current_before', h.file_sha(args.native_source) == h.file_sha(args.native_capture) == proof['sourceSha256'])
        source = Path('/Users/qianqi/.openclaw')
        config_sha = 'ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d'
        captured = h.capture(source, config_sha)
        h.private(root / 'source-auth-rows.private.json', captured)
        private_state = root / 'private-sdk-state'; h.materialize(private_state, captured)
        document_path = root / 'prepared-profile.private.json'
        plan = {'workRoot': str(root), 'privateStateRoot': str(private_state), 'sdkRoot': '/opt/homebrew/lib/node_modules/openclaw',
                'nativeCapture': str(args.native_capture), 'nativeProof': str(args.native_proof),
                'profileDocument': str(document_path), 'rollbackPlan': str(root / 'profile-change-plan.private.json')}
        h.private(root / 'prepare.plan.private.json', plan)
        env = {'PATH': '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR': str(root / 'tmp'),
               'OPENCLAW_STATE_DIR': str(private_state), 'OPENCLAW_CONFIG_PATH': str(private_state / 'openclaw.json'),
               'OPENCLAW_OAUTH_DIR': str(private_state / 'oauth')}
        r = subprocess.run(['/opt/homebrew/bin/node', str(args.prepare_child), str(root / 'prepare.plan.private.json')], env=env, capture_output=True, timeout=60)
        h.private(root / 'prepare.stdout', r.stdout); h.private(root / 'prepare.stderr', r.stderr)
        prepared = json.loads(r.stdout); report['sdkPreparation'] = prepared
        check('private_sdk_preparation', r.returncode == 0 and prepared.get('ok') is True)
        document = json.loads(document_path.read_bytes())
        report['profileDocumentSha256'] = h.digest(document); report['nativeProofSha256'] = h.file_sha(args.native_proof)
        check('binary_identity', h.file_sha(args.binary) == args.binary_sha256)
        report['binarySha256'] = args.binary_sha256
        sys.path.insert(0, str(args.server_source / 'qa/openbao-acceptance'))
        from native_v6_authbus_client_live import smoke
        from cert_auth_live import cert_sha256
        instance = smoke.Instance(args.binary, root / 'server')
        config_path = instance.root / 'server.json'; config = json.loads(config_path.read_bytes())
        config['storage'] = {'native_v6_file': {'path': config['data_dir']}}
        config_path.write_bytes(h.encoded(config)); instance.start()
        def call(name, method, path, body=None, *, token=None, expected=200):
            status, value = instance.call(method, path, body, token=token)
            check(name, status == expected, status=status); return value
        init = call('initialize', 'POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1}, token='')
        instance.token, unseal = init['root_token'], init['keys_base64'][0]
        h.private(root / 'server-recovery.private.json', {'rootToken': instance.token, 'unsealKey': unseal})
        call('unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        call('kv2_mount', 'POST', 'sys/mounts/openclaw-auth', {'type': 'kv', 'options': {'version': '2'}}, expected=204)
        call('approle_mount', 'POST', 'sys/auth/approle', {'type': 'approle'}, expected=204)
        call('formal_activation', 'POST', 'sys/storage/native-v6/activate', {}, expected=204)
        check('formal_format2', call('capacity', 'GET', 'sys/internal/capacity')['data'].get('native_kv2_reader_format') == 2)
        key = 'validated/mac/native-profile-2'
        call('validated_profile_import', 'POST', 'openclaw-auth/data/' + key, {'data': document, 'options': {'cas': 0}})
        policy = 'path "openclaw-auth/data/' + key + '" { capabilities=["read"] }\npath "auth/token/revoke-self" { capabilities=["update"] }\npath "auth/token/lookup-self" { capabilities=["read"] }'
        call('reader_policy', 'PUT', 'sys/policies/acl/native-profile-reader', {'policy': policy}, expected=204)
        route = 'auth/approle/role/native-profile-reader'
        call('reader_role', 'POST', route, {'token_policies': ['native-profile-reader'], 'token_ttl': '120s', 'token_max_ttl': '180s', 'secret_id_ttl': '600s'}, expected=204)
        role = call('role_id', 'GET', route + '/role-id')['data']['role_id']
        secret = call('secret_id', 'POST', route + '/secret-id', {})['data']['secret_id']
        credentials = root / 'credentials'; credentials.mkdir(mode=0o700)
        h.private(credentials / 'role_id', role.encode()); h.private(credentials / 'secret_id', secret.encode())
        h.private(credentials / 'ca.crt', (instance.root / 'ca.crt').read_bytes())
        def read(name):
            output = root / (name + '.documents.private.json')
            plan = {'moduleRoot': str(args.client_modules), 'privateOutput': str(output), 'entries': [{
                'agent': 'native-profile-2', 'address': instance.address, 'caFile': str(credentials / 'ca.crt'),
                'roleIdFile': str(credentials / 'role_id'), 'secretIdFile': str(credentials / 'secret_id'),
                'serverCertificateSha256': cert_sha256(instance.root / 'tls.crt'), 'key': key,
                'deniedKey': 'validated/mac/unassigned', 'expectedSha256': h.digest(document), 'stateDir': str(root / (name + '-state'))}]}
            h.private(root / (name + '.plan.private.json'), plan)
            r = subprocess.run(['/opt/homebrew/bin/node', str(args.read_child), str(root / (name + '.plan.private.json'))], capture_output=True, timeout=45)
            h.private(root / (name + '.stdout'), r.stdout); h.private(root / (name + '.stderr'), r.stderr)
            result = json.loads(r.stdout); report[name] = result
            check(name, r.returncode == 0 and result.get('ok') is True)
            check(name + '.exact', json.loads(output.read_bytes()) == [document])
        read('initial-read')
        child = instance.process; instance.stop(); check('actual_sigkill_waited', child.returncode == -9)
        instance.start(); call('cold_sealed', 'GET', 'sys/health', expected=503)
        call('cold_unseal', 'POST', 'sys/unseal', {'key': unseal}, token=''); read('cold-read')
        after = h.capture(source, config_sha)
        check('production_auth_rows_unchanged', all(a['rows'] == b['rows'] for a, b in zip(captured, after)))
        check('native_source_still_current', h.file_sha(args.native_source) == proof['sourceSha256'])
        literals = [v.encode() for k, v in document['credential'].items() if k in ('access', 'refresh', 'key', 'token', 'idToken') and isinstance(v, str) and len(v) >= 8]
        files = [p for p in (instance.root / 'data').rglob('*') if p.is_file()]
        check('service_disk_no_credential_plaintext', all(all(secret not in p.read_bytes() for secret in literals) for p in files))
        diagnostics = [p for p in root.rglob('*') if p.is_file() and (p.name.endswith(('.stdout', '.stderr')) or p.name in ('server.log', 'audit.jsonl'))]
        check('diagnostics_no_credential_values', all(all(secret not in p.read_bytes() for secret in literals) for p in diagnostics)
              and all(secret not in h.encoded(report) for secret in literals))
        report.update(ok=True, preparedProfiles=1, nativeCurrentCredentialMirroredIntoFormalV6=True,
                      privateSdkAtomicRollbackQualified=True, actualServerColdRecoveryQualified=True)
    except Exception as error:
        report['error'] = str(error) if isinstance(error, h.Refused) else type(error).__name__
    finally:
        if instance is not None and instance.process is not None: instance.stop()
    h.private(root / 'result.public.json', report)
    print(json.dumps({'ok': report['ok'], 'error': report.get('error'), 'result': str(root / 'result.public.json')}))
    return 0 if report['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
