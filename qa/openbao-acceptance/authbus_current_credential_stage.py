#!/usr/bin/env python3
"""Capture only current auth rows, stage in formal HeptaBao and prove SDK recovery.

Production services, config, credentials and databases are never written by this
driver. All new credentials and reconstructed auth-only databases stay below a
new private directory. Public results contain counts, identities and digests.
The rollback proof covers auth rows in isolation, not production traffic or the
complete OpenClaw databases. Provider validity is deliberately not asserted.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import time

AGENTS = ('main', 'trnm', 'hepta-ui', 'hepta', 'hepta-backend')
TABLES = {'store': ('auth_profile_store', 'store_key', 'store_json'),
          'state': ('auth_profile_state', 'state_key', 'state_json')}

class Refused(Exception):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()

def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()

def private(path, value):
    data = value if isinstance(value, bytes) else encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())

def identity(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink]

def capture(source, config_sha):
    config_path = source / 'openclaw.json'
    need(file_sha(config_path) == config_sha, 'current_config_changed')
    config = json.loads(config_path.read_bytes())
    declared = config.get('agents', {}).get('list', [])
    need(tuple(item.get('id') for item in declared) == AGENTS, 'configured_agent_scope_changed')
    output = []
    for item in declared:
        agent = item['id']; directory = source / 'agents' / agent / 'agent'
        need(Path(item.get('agentDir', directory)) == directory, 'configured_agent_directory_changed')
        for parent in (source, source / 'agents', directory.parent, directory):
            info = parent.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not parent.is_symlink()
                 and stat.S_IMODE(info.st_mode) & 0o022 == 0, 'source_parent_custody')
        pathname = directory / 'openclaw-agent.sqlite'
        fd = os.open(pathname, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                 and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1, 'source_database_custody')
            sidecars_before = {}
            for suffix in ('-wal', '-shm'):
                target = Path(str(pathname) + suffix)
                if target.exists():
                    info = target.lstat()
                    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                         and stat.S_IMODE(info.st_mode) & 0o077 == 0 and info.st_nlink == 1,
                         'source_sidecar_custody')
                    sidecars_before[suffix] = identity(info)
            need('-wal' not in sidecars_before or '-shm' in sidecars_before, 'readonly_wal_requires_existing_shm')
            db = sqlite3.connect(pathname.as_uri() + '?mode=ro', uri=True, timeout=3)
            try:
                db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA temp_store=MEMORY'); db.execute('BEGIN')
                document = {'schema': 'heptabao.current-openclaw-auth-rows.v1', 'host': 'mac', 'agent': agent, 'rows': {}}
                for kind, (table, key, column) in TABLES.items():
                    rows = db.execute('SELECT ' + key + ',' + column + ',updated_at FROM ' + table + ' WHERE ' + key + '=?', ('primary',)).fetchall()
                    need(len(rows) <= 1 and all(isinstance(row[1], str) and len(row[1].encode()) <= 1024 * 1024 for row in rows), 'auth_row_bound')
                    document['rows'][kind] = [list(row) for row in rows]
                need(len(document['rows']['store']) == 1, 'current_store_missing')
                parsed = json.loads(document['rows']['store'][0][1])
                need(isinstance(parsed.get('profiles'), dict) and len(parsed['profiles']) <= 128, 'current_profile_shape')
                document['sourceIdentity'] = identity(before)
                db.rollback()
            finally:
                db.close()
            need(identity(os.fstat(fd)) == identity(pathname.lstat()) == identity(before), 'source_database_identity_changed')
            for suffix in ('-wal', '-shm'):
                target = Path(str(pathname) + suffix)
                need(target.exists() == (suffix in sidecars_before), 'source_sidecar_presence_changed')
                if target.exists():
                    need(identity(target.lstat()) == sidecars_before[suffix], 'source_sidecar_identity_changed')
            output.append(document)
        finally:
            os.close(fd)
    return output

def materialize(root, documents):
    root.mkdir(mode=0o700)
    (root / 'oauth').mkdir(mode=0o700)
    for document in documents:
        directory = root / 'agents' / document['agent'] / 'agent'
        directory.mkdir(mode=0o700, parents=True)
        db = sqlite3.connect(directory / 'openclaw-agent.sqlite')
        try:
            db.execute('PRAGMA journal_mode=DELETE'); db.execute('PRAGMA synchronous=FULL')
            for kind, (table, key, column) in TABLES.items():
                db.execute('CREATE TABLE ' + table + ' (' + key + ' TEXT PRIMARY KEY,' + column + ' TEXT NOT NULL,updated_at INTEGER NOT NULL)')
                db.executemany('INSERT INTO ' + table + ' VALUES (?,?,?)', document['rows'][kind])
            db.commit()
        finally:
            db.close()
        (directory / 'openclaw-agent.sqlite').chmod(0o600)
    private(root / 'openclaw.json', {'agents': {'list': [{'id': agent, 'agentDir': str(root / 'agents' / agent / 'agent')} for agent in AGENTS]}})

def run(args, report):
    root = args.work_dir
    root.mkdir(mode=0o700, exist_ok=False)
    (root / 'tmp').mkdir(mode=0o700)
    report.update(checks=[], phases=[], source=str(args.source), binarySha256=file_sha(args.binary),
                  sdkPins={str(path): file_sha(path) for path in [args.sdk / 'package.json', args.sdk / 'dist/store-DH33UrUj.js', args.sdk / 'dist/sqlite-B1ze-fre.js']})
    need(report['binarySha256'] == args.binary_sha256, 'binary_hash_mismatch')
    started = time.monotonic()
    instance = None
    logs = []
    secrets_seen = []
    def check(name, condition, **detail):
        report['checks'].append({'case': name, 'passed': bool(condition), **detail})
        need(condition, name)
    def sdk_read(name, documents):
        target = root / name
        materialize(target, documents)
        plan = {'sdkStoreModule': str(args.sdk / 'dist/store-DH33UrUj.js'),
                'sdkStoreSha256': report['sdkPins'][str(args.sdk / 'dist/store-DH33UrUj.js')],
                'stateRoot': str(target), 'agents': AGENTS}
        private(root / (name + '.plan.private.json'), plan)
        env = {'PATH': '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR': str(root / 'tmp'),
               'OPENCLAW_STATE_DIR': str(target), 'OPENCLAW_CONFIG_PATH': str(target / 'openclaw.json'),
               'OPENCLAW_OAUTH_DIR': str(target / 'oauth'), 'OPENCLAW_AUTH_STORE_READONLY': '1'}
        result = subprocess.run([args.node, str(args.sdk_reader), str(root / (name + '.plan.private.json'))],
                                env=env, capture_output=True, timeout=45)
        logs.extend((result.stdout, result.stderr))
        private(root / (name + '.stdout'), result.stdout); private(root / (name + '.stderr'), result.stderr)
        value = json.loads(result.stdout); report['phases'].append({'case': name, **value})
        check(name, result.returncode == 0 and value.get('ok') is True and value.get('networkOrChildOperationsAttempted') == 0)
        return value['stores']
    try:
        captured = capture(args.source, args.config_sha256)
        private(root / 'captured-auth-rows.private.json', captured)
        total, literal, expired, future, refs = 0, 0, 0, 0, 0
        for document in captured:
            for credential in json.loads(document['rows']['store'][0][1])['profiles'].values():
                total += 1
                for name in ('key', 'token', 'access', 'refresh'):
                    if isinstance(credential.get(name), str) and credential[name]:
                        literal += 1; secrets_seen.append(credential[name])
                refs += sum(name in credential for name in ('keyRef', 'tokenRef', 'accessRef', 'refreshRef'))
                if credential.get('type') == 'oauth' and isinstance(credential.get('expires'), (int, float)):
                    if credential['expires'] <= time.time() * 1000: expired += 1
                    else: future += 1
        report['capture'] = {'agents': len(captured), 'profileRows': total, 'literalCredentialFields': literal,
                             'expiredOAuthProfiles': expired, 'futureDatedOAuthProfiles': future, 'secretReferenceFields': refs,
                             'documentsSha256': digest(captured), 'freshCurrentSource': True, 'oldBackupUsed': False,
                             'authTablesOnly': True}
        check('actual_current_credentials_present', literal > 0)
        baseline_sdk = sdk_read('baseline-sdk', captured)
        sys.path.insert(0, str(args.server_source / 'qa/openbao-acceptance'))
        from native_v6_authbus_client_live import smoke
        from cert_auth_live import cert_sha256
        instance = smoke.Instance(args.binary, root / 'server')
        config_path = instance.root / 'server.json'
        config = json.loads(config_path.read_text()); config['storage'] = {'native_v6_file': {'path': config['data_dir']}}
        config_path.write_bytes(encoded(config)); config_path.chmod(0o600)
        instance.start()
        def call(name, method, route, body=None, *, token=None, expected=200):
            status, value = instance.call(method, route, body, token=token)
            check(name, status == expected, status=status, expected=expected)
            return value
        initialized = call('initialize', 'POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1}, token='')
        instance.token, unseal = initialized['root_token'], initialized['keys_base64'][0]
        secrets_seen.extend((instance.token, unseal))
        private(root / 'server-recovery.private.json', {'rootToken': instance.token, 'unsealKey': unseal})
        call('unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        call('kv2_mount', 'POST', 'sys/mounts/openclaw-auth', {'type': 'kv', 'options': {'version': '2'}}, expected=204)
        call('approle_mount', 'POST', 'sys/auth/approle', {'type': 'approle'}, expected=204)
        call('formal_activation', 'POST', 'sys/storage/native-v6/activate', {}, expected=204)
        check('formal_v6_format2', call('capacity', 'GET', 'sys/internal/capacity')['data'].get('native_kv2_reader_format') == 2)
        entries = []
        for index, document in enumerate(captured):
            agent = document['agent']; key = 'current/mac/' + agent; name = 'current-' + agent
            call(agent + '.credential_import', 'POST', 'openclaw-auth/data/' + key, {'data': document, 'options': {'cas': 0}})
            policy = 'path "openclaw-auth/data/' + key + '" { capabilities=["read"] }\npath "auth/token/revoke-self" { capabilities=["update"] }\npath "auth/token/lookup-self" { capabilities=["read"] }'
            call(agent + '.policy', 'PUT', 'sys/policies/acl/' + name, {'policy': policy}, expected=204)
            route = 'auth/approle/role/' + name
            call(agent + '.role', 'POST', route, {'token_policies': [name], 'token_ttl': '120s', 'token_max_ttl': '180s',
                 'secret_id_ttl': '600s', 'secret_id_num_uses': 0}, expected=204)
            role_id = call(agent + '.role_id', 'GET', route + '/role-id')['data']['role_id']
            secret_id = call(agent + '.secret_id', 'POST', route + '/secret-id', {})['data']['secret_id']
            secrets_seen.extend((role_id, secret_id))
            credentials = root / ('credentials-' + agent); credentials.mkdir(mode=0o700)
            private(credentials / 'role_id', role_id.encode()); private(credentials / 'secret_id', secret_id.encode())
            private(credentials / 'ca.crt', (instance.root / 'ca.crt').read_bytes())
            entries.append({'agent': agent, 'address': instance.address, 'caFile': str(credentials / 'ca.crt'),
                            'roleIdFile': str(credentials / 'role_id'), 'secretIdFile': str(credentials / 'secret_id'),
                            'serverCertificateSha256': cert_sha256(instance.root / 'tls.crt'), 'key': key,
                            'deniedKey': 'current/mac/' + AGENTS[(index + 1) % len(AGENTS)], 'expectedSha256': digest(document)})
        def client_read(name):
            output = root / (name + '.documents.private.json')
            plan = {'moduleRoot': str(args.client_modules), 'privateOutput': str(output),
                    'entries': [{**entry, 'stateDir': str(root / (name + '-state-' + entry['agent']))} for entry in entries]}
            private(root / (name + '.plan.private.json'), plan)
            result = subprocess.run([args.node, str(args.client_reader), str(root / (name + '.plan.private.json'))],
                                    capture_output=True, timeout=90)
            logs.extend((result.stdout, result.stderr)); private(root / (name + '.stdout'), result.stdout); private(root / (name + '.stderr'), result.stderr)
            value = json.loads(result.stdout); report['phases'].append({'case': name, **value})
            check(name, result.returncode == 0 and value.get('ok') is True)
            documents = json.loads(output.read_bytes()); check(name + '.full_rows_exact', documents == captured)
            return documents
        migrated = client_read('initial-read')
        check('current_sdk_reads_migrated_credentials_exactly', sdk_read('migrated-sdk', migrated) == baseline_sdk)
        original = instance.process; instance.stop(); check('actual_server_sigkill_waited', original.returncode == -9)
        instance.start(); call('cold_sealed', 'GET', 'sys/health', expected=503)
        call('cold_unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        recovered = client_read('cold-read')
        check('cold_recovery_rows_exact', recovered == captured)
        rollback = json.loads((root / 'captured-auth-rows.private.json').read_bytes())
        check('current_sdk_reads_auth_only_rollback_exactly', sdk_read('rollback-sdk', rollback) == baseline_sdk)
        fresh = capture(args.source, args.config_sha256)
        check('source_credential_store_still_current', all(left['rows']['store'][0][1] == right['rows']['store'][0][1] for left, right in zip(captured, fresh)))
        report['sourceAuthStateStillExact'] = all(left['rows']['state'] == right['rows']['state'] for left, right in zip(captured, fresh))
        check('sdk_sources_unchanged', all(file_sha(path) == expected for path, expected in report['sdkPins'].items()))
        check('binary_unchanged', file_sha(args.binary) == args.binary_sha256)
        public = encoded(report) + b''.join(logs) + (instance.root / 'server.log').read_bytes()
        check('diagnostics_no_credential_values', all(value.encode() not in public for value in secrets_seen if len(value) >= 8))
        report.update(ok=True, formalV6Staging=True, stagingCurrentSdkRecoveryQualified=True,
                      actualServiceColdRestart=True, stagedAuthOnlyRollbackQualified=True,
                      elapsedSeconds=round(time.monotonic() - started, 3))
    finally:
        if instance is not None and instance.process is not None:
            instance.stop()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('work-dir', 'source', 'sdk', 'binary', 'server-source', 'sdk-reader', 'client-reader', 'client-modules'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--binary-sha256', required=True); p.add_argument('--config-sha256', required=True)
    p.add_argument('--node', required=True)
    args = p.parse_args(); os.umask(0o077)
    report = {'schema': 'heptabao.current-private-auth-stage.v1', 'ok': False, 'providerCalled': False,
              'providerCredentialValidityQualified': False, 'productionChanged': False, 'productionTrafficCutover': False,
              'productionTrafficRollbackTested': False, 'completeOpenClawDatabaseRecoveryQualified': False,
              'credentialValuesPublished': False, 'fullReplacementQualified': False, 'j3160Contacted': False}
    try:
        run(args, report)
    except Exception as error:
        report['error'] = str(error) if isinstance(error, Refused) else type(error).__name__
    if args.work_dir.is_dir():
        private(args.work_dir / 'result.public.json', report)
    print(json.dumps({'ok': report['ok'], 'error': report.get('error'), 'result': str(args.work_dir / 'result.public.json')}))
    return 0 if report['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
