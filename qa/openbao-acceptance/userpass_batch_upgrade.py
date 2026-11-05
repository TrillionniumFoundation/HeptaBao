#!/usr/bin/env python3
"""Real schema40 -> 41 batch authority upgrade; no fabricated stored state.

Separate stores keep pure-read evidence independent of the pre-existing SSH
lease-clock maintenance writes. Fresh-key history uses the candidate's JSON
backup profile, not an OpenBao native/Raft snapshot interoperability claim.
"""
from __future__ import annotations
import importlib
import json
from pathlib import Path
import re
import secrets
import shutil
import tempfile

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from online_evidence import admit_output, complete_checks, source_identity
from provider_renewal_upgrade import durable_manifest
from userpass_password_live import private_parent, safe_files
from userpass_names_live import complete as legacy_complete, complete_deviations

LEGACY_SOURCE = '6f641ffd9eca33910673b239e6f15c7794b86a92'
LEGACY_SHA256 = '346fc4fb464d0e49857a9e7348cc006ac9ab5bcaf0a436f1458da32197c310a7'
LEGACY_RECEIPT = ROOT/'qa/openbao-acceptance/evidence/userpass-names-live-6f641ff.json'
MOUNT = 'batch-upgrade'
NAMESPACE = 'batch-team'
POLICY = 'batch-upgrade-read'
POLICY_TEXT = 'path "secret/data/upgrade" { capabilities = ["read"] }'
REQUIRED = frozenset({
    'legacy_root_service_shape', 'legacy_namespace_service_shape',
    'pure_application_unchanged', 'pure_reads_unchanged',
    'pure_restart_application_unchanged', 'pure_restart_reads_unchanged',
    'old_read_control_application_unchanged', 'old_read_control_root_service_shape',
    'failed_batch_unchanged', 'migration_batch_shape', 'migration_batch_read_value',
    'first_batch_downgrade_unseal_status', 'first_batch_downgrade_application_unchanged',
    'first_batch_recovery_shape',
    'migration_root_service_shape', 'migration_namespace_service_shape',
    'migration_user_batch_shape', 'migration_namespace_batch_shape',
    'migration_cross_namespace_status', 'reopen_application_unchanged',
    'reopen_batch_shape', 'reopen_user_batch_shape', 'reopen_namespace_batch_shape',
    'reopen_root_service_shape', 'reopen_namespace_service_shape',
    'downgrade_unseal_status', 'downgrade_health_status', 'downgrade_application_unchanged',
    'recovery_batch_shape', 'recovery_root_service_shape',
    'ssh_legacy_service_shape', 'ssh_legacy_lease_shape', 'ssh_current_service_shape',
    'ssh_first_verify_shape', 'ssh_first_replay_status', 'ssh_reopen_second_verify_shape',
    'ssh_owner_revoke_status', 'ssh_revoked_verify_status',
    'fresh_pre_batch_archive_shape', 'fresh_batch_shape', 'fresh_restore_status',
    'fresh_after_restore_batch_shape', 'fresh_later_absent_status',
    'fresh_reopen_batch_shape', 'upgrade_secrets_absent', 'ssh_secrets_absent',
    'fresh_secrets_absent', 'complete',
})


def admit_legacy_receipt(receipt):
    before = receipt.get('candidate_source') or {}
    sides = receipt.get('cases') or {}
    deviations = receipt.get('deliberate_divergences') or {}
    if (receipt.get('schema') != 'heptabao.userpass-names-comparison.v1'
        or receipt.get('status') != 'passed' or receipt.get('oracle_only') is not False
        or receipt.get('build_source_commit') != LEGACY_SOURCE
        or before.get('source_commit') != LEGACY_SOURCE
        or before.get('binary_sha256') != LEGACY_SHA256 or before.get('source_dirty') is not False
        or receipt.get('candidate_source_after') != before
        or any(receipt.get(k) is not True for k in ('cases_match', 'source_and_binary_unchanged',
            'runner_unchanged', 'helpers_unchanged', 'oracle_binary_unchanged'))
        or receipt.get('failures') or set(sides) != {'candidate', 'oracle'}
        or sides['candidate'] != sides['oracle'] or not all(legacy_complete(v) for v in sides.values())
        or set(deviations) != {'candidate', 'oracle'}
        or not all(complete_deviations(v) for v in deviations.values())):
        raise ValueError('qualified_schema40_names_receipt_required')


def old_reader_observed(rows):
    return any(row.get('case') in ('first_batch_downgrade_unseal_status', 'downgrade_unseal_status') for row in rows)


def complete(rows):
    if not isinstance(rows, list) or any(not isinstance(row, dict)
        or set(row)-{'case', 'passed', 'status'}
        or 'status' in row and (type(row['status']) is not int or not 100 <= row['status'] <= 599)
        for row in rows):
        return False
    stripped = [{'case': row.get('case'), 'passed': row.get('passed')} for row in rows]
    return complete_checks(stripped, required_cases=REQUIRED) and rows[-1].get('case') == 'complete'


def helpers():
    names = ('bao_http', 'heptabao.transport', 'core_isolation', 'identity_upgrade',
             'online_evidence', 'provider_renewal_upgrade', 'userpass_password_live',
             'userpass_names_live', 'remote_jwks_live')
    return {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}


class Trace:
    def __init__(self, instance, rows):
        self.instance, self.rows = instance, rows
        self.sensitive = []

    def check(self, name, condition, *, status=None):
        if not isinstance(name, str) or re.fullmatch('[a-z0-9_]{1,120}', name) is None:
            raise ValueError('unsafe_case')
        row = {'case': name, 'passed': condition is True}
        if status is not None:
            if type(status) is not int or not 100 <= status <= 599:
                raise ValueError('unsafe_status')
            row['status'] = status
        self.rows.append(row)
        if condition is not True:
            raise ScenarioFailure(name)

    def call(self, name, method, path, body=None, *, token=None, namespace='', status=200):
        client = Client(self.instance.address, str(self.instance.root/'ca.crt'), self.instance.token, namespace)
        result = client.request(method, '/v1/'+path, body, token=token)
        self.check(name+'_status', result.status == status, status=result.status)
        if status >= 400:
            self.check(name+'_no_credentials', not result.body.get('auth') and not result.body.get('wrap_info'))
        return result.body

    def issued(self, name, body, kind):
        auth = body.get('auth') or {}
        token = auth.get('client_token')
        valid = isinstance(token, str) and token.startswith('hvb.' if kind == 'batch' else 'hvs.')
        valid = valid and auth.get('token_type') == kind and type(auth.get('lease_duration')) is int and auth['lease_duration'] > 0
        if kind == 'batch':
            valid = valid and auth.get('accessor') in ('', None) and auth.get('renewable') is False
        else:
            valid = valid and isinstance(auth.get('accessor'), str) and bool(auth['accessor'])
        self.check(name+'_shape', valid)
        self.sensitive.extend(x for x in (token, auth.get('accessor')) if isinstance(x, str) and x)
        return auth

    def lookup(self, name, auth, kind, *, namespace=''):
        data = self.call(name, 'GET', 'auth/token/lookup-self', token=auth['client_token'], namespace=namespace).get('data') or {}
        valid = (data.get('id') == auth['client_token'] and data.get('type') == kind
                 and type(data.get('ttl')) is int and data['ttl'] > 0)
        if kind == 'batch':
            valid = valid and data.get('accessor') in ('', None) and data.get('renewable') is False
        else:
            valid = valid and data.get('accessor') == auth['accessor']
        self.check(name+'_shape', valid)
        return data

    def value(self, name, auth, *, namespace=''):
        body = self.call(name, 'GET', 'secret/data/upgrade', token=auth['client_token'], namespace=namespace)
        self.check(name+'_value', (body.get('data') or {}).get('data') == {'value': 'synthetic-upgrade-value'})


def initialize(instance, rows, phase):
    instance.start()
    status, init = instance.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
    if status != 200:
        raise ScenarioFailure(phase+'_initialization_failed')
    instance.token, key = init['root_token'], init['keys_base64'][0]
    t = Trace(instance, rows)
    t.sensitive.extend((instance.token, key))
    t.call(phase+'_unseal', 'POST', 'sys/unseal', {'key': key})
    return t, key


def restart(instance, binary, trace, key, phase):
    instance.stop()
    instance.binary = binary
    instance.start()
    trace.call(phase+'_unseal', 'POST', 'sys/unseal', {'key': key})


def retained_config(current, previous):
    # schema41 adds only readback's type default; the old persisted user is not rewritten.
    if not isinstance(current, dict) or not isinstance(previous, dict):
        return False
    current = dict(current)
    if current.pop('token_type', 'default') != 'default':
        return False
    return current == previous


def prepare_account(t, name, password, *, namespace=''):
    t.call(name+'_mount', 'POST', 'sys/auth/'+MOUNT, {'type': 'userpass'}, namespace=namespace, status=204)
    t.call(name+'_policy', 'POST', 'sys/policies/acl/'+POLICY, {'policy': POLICY_TEXT}, namespace=namespace, status=204)
    t.call(name+'_value', 'POST', 'secret/data/upgrade', {'data': {'value': 'synthetic-upgrade-value'}}, namespace=namespace)
    t.call(name+'_user', 'POST', f'auth/{MOUNT}/users/alice', {
        'password': password, 'token_ttl': 900, 'token_max_ttl': 1200, 'token_policies': [POLICY]}, namespace=namespace, status=204)
    auth = t.issued(name+'_service', t.call(name+'_login', 'POST', f'auth/{MOUNT}/login/alice',
        {'password': password}, token='', namespace=namespace), 'service')
    config = t.call(name+'_config', 'GET', f'auth/{MOUNT}/users/alice', namespace=namespace)['data']
    return auth, config


def run_upgrade(instance, candidate, legacy, rows):
    t, key = initialize(instance, rows, 'legacy')
    passwords = [secrets.token_urlsafe(24) for _ in range(2)]
    t.sensitive.extend(passwords)
    root_auth, root_config = prepare_account(t, 'legacy_root', passwords[0])
    t.call('legacy_namespace_create', 'POST', 'sys/namespaces/'+NAMESPACE, {}, status=204)
    ns_auth, ns_config = prepare_account(t, 'legacy_namespace', passwords[1], namespace=NAMESPACE)
    held = [('', 'root', root_auth, root_config), (NAMESPACE, 'namespace', ns_auth, ns_config)]
    store = instance.root/'data'
    instance.stop()
    original = durable_manifest(store, application_only=True)
    for phase in ('pure', 'pure_restart'):
        restart(instance, candidate, t, key, phase)
        t.check(phase+'_application_unchanged', durable_manifest(store, application_only=True) == original)
        before = durable_manifest(store)
        for ns, label, auth, config in held:
            got = t.call(phase+'_'+label+'_config', 'GET', f'auth/{MOUNT}/users/alice', namespace=ns)['data']
            t.check(phase+'_'+label+'_config_preserved', retained_config(got, config))
            t.lookup(phase+'_'+label+'_service', auth, 'service', namespace=ns)
            t.value(phase+'_'+label+'_read', auth, namespace=ns)
        t.check(phase+'_reads_unchanged', durable_manifest(store) == before)
    # Positive control: a real old process still reads the untouched store.
    restart(instance, legacy, t, key, 'old_read_control')
    t.check('old_read_control_application_unchanged', durable_manifest(store, application_only=True) == original)
    t.lookup('old_read_control_root_service', root_auth, 'service')
    restart(instance, candidate, t, key, 'before_migration')
    before = durable_manifest(store)
    t.call('failed_batch', 'POST', 'auth/token/create-orphan', {'type': 'batch', 'ttl': 'invalid', 'policies': [POLICY]}, status=400)
    t.check('failed_batch_unchanged', durable_manifest(store) == before)
    batch = t.issued('migration_batch', t.call('migration_issue', 'POST', 'auth/token/create-orphan',
        {'type': 'batch', 'ttl': 900, 'policies': [POLICY]}), 'batch')
    t.value('migration_batch_read', batch)
    # Isolate the format transition caused by this first issuance: no new
    # token_type configuration marker can make a missing authority fence pass.
    instance.stop()
    first_batch = durable_manifest(store, application_only=True)
    instance.binary = legacy
    instance.start()
    t.call('first_batch_downgrade_unseal', 'POST', 'sys/unseal', {'key': key}, status=503)
    instance.stop()
    t.check('first_batch_downgrade_application_unchanged', durable_manifest(store, application_only=True) == first_batch)
    restart(instance, candidate, t, key, 'first_batch_recovery')
    t.lookup('first_batch_recovery', batch, 'batch')
    for ns, label, auth, config in held:
        t.lookup('migration_'+label+'_service', auth, 'service', namespace=ns)
        got = t.call('migration_'+label+'_config', 'GET', f'auth/{MOUNT}/users/alice', namespace=ns)['data']
        t.check('migration_'+label+'_config_preserved', retained_config(got, config))
    batches = [('', 'batch', batch)]
    for ns, label, password in [('', 'user_batch', passwords[0]), (NAMESPACE, 'namespace_batch', passwords[1])]:
        t.call('migration_'+label+'_configure', 'POST', f'auth/{MOUNT}/users/alice', {'token_type': 'batch'}, namespace=ns, status=204)
        issued = t.issued('migration_'+label, t.call('migration_'+label+'_login', 'POST', f'auth/{MOUNT}/login/alice',
            {'password': password}, token='', namespace=ns), 'batch')
        t.value('migration_'+label+'_read', issued, namespace=ns)
        batches.append((ns, label, issued))
    t.call('migration_cross_namespace', 'GET', 'secret/data/upgrade', token=batches[-1][2]['client_token'], status=403)
    instance.stop()
    published = durable_manifest(store, application_only=True)
    restart(instance, candidate, t, key, 'reopen')
    t.check('reopen_application_unchanged', durable_manifest(store, application_only=True) == published)
    for ns, label, auth in batches:
        t.lookup('reopen_'+label, auth, 'batch', namespace=ns)
        t.value('reopen_'+label+'_read', auth, namespace=ns)
    for ns, label, auth, _ in held:
        t.lookup('reopen_'+label+'_service', auth, 'service', namespace=ns)
    instance.stop()
    published = durable_manifest(store, application_only=True)
    instance.binary = legacy
    instance.start()
    t.call('downgrade_unseal', 'POST', 'sys/unseal', {'key': key}, status=503)
    t.call('downgrade_health', 'GET', 'sys/health', status=503)
    instance.stop()
    t.check('downgrade_application_unchanged', durable_manifest(store, application_only=True) == published)
    restart(instance, candidate, t, key, 'recovery')
    t.lookup('recovery_batch', batch, 'batch')
    t.lookup('recovery_root_service', root_auth, 'service')
    for ns, label, auth in batches:
        t.value('recovery_'+label+'_read', auth, namespace=ns)
    instance.stop()
    t.check('upgrade_secrets_absent', safe_files(instance.root, t.sensitive))


def run_ssh(instance, candidate, rows):
    t, key = initialize(instance, rows, 'ssh_legacy')
    password = secrets.token_urlsafe(24)
    t.sensitive.append(password)
    auth, _ = prepare_account(t, 'ssh_account', password)
    policy = POLICY_TEXT+' path "upgrade-ssh/creds/deploy" { capabilities = ["update"] }'
    t.call('ssh_legacy_policy', 'POST', 'sys/policies/acl/'+POLICY, {'policy': policy}, status=204)
    t.lookup('ssh_legacy_service', auth, 'service')
    t.call('ssh_mount', 'POST', 'sys/mounts/upgrade-ssh', {'type': 'ssh', 'config': {'default_lease_ttl': 600, 'max_lease_ttl': 900}}, status=204)
    t.call('ssh_role', 'POST', 'upgrade-ssh/roles/deploy', {'key_type': 'otp', 'default_user': 'deploy', 'cidr_list': '127.0.0.0/8'}, status=204)
    leases = []
    for index in range(3):
        issued = t.call('ssh_issue_'+str(index), 'POST', 'upgrade-ssh/creds/deploy', {'ip': '127.0.0.1'}, token=auth['client_token'])
        otp, lease = issued['data']['key'], issued['lease_id']
        t.sensitive.append(otp)
        t.check('ssh_issue_'+str(index)+'_shape', isinstance(otp, str) and bool(otp) and lease.startswith('upgrade-ssh/creds/deploy/') and 0 < issued.get('lease_duration', 0) <= 600)
        leases.append((otp, lease))
    data = t.call('ssh_legacy_lease', 'POST', 'sys/leases/lookup', {'lease_id': leases[0][1]})['data']
    t.check('ssh_legacy_lease_shape', data.get('id') == leases[0][1] and data.get('renewable') is False and data.get('ttl', 0) > 0)
    restart(instance, candidate, t, key, 'ssh_current')
    t.lookup('ssh_current_service', auth, 'service')
    t.call('ssh_current_lease', 'POST', 'sys/leases/lookup', {'lease_id': leases[0][1]})
    first = t.call('ssh_first_verify', 'POST', 'upgrade-ssh/verify', {'otp': leases[0][0]}, token='')
    t.check('ssh_first_verify_shape', first.get('data') == {'ip': '127.0.0.1', 'username': 'deploy', 'role_name': 'deploy'})
    t.call('ssh_first_replay', 'POST', 'upgrade-ssh/verify', {'otp': leases[0][0]}, token='', status=400)
    restart(instance, candidate, t, key, 'ssh_reopen')
    second = t.call('ssh_reopen_second_verify', 'POST', 'upgrade-ssh/verify', {'otp': leases[1][0]}, token='')
    t.check('ssh_reopen_second_verify_shape', second.get('data') == {'ip': '127.0.0.1', 'username': 'deploy', 'role_name': 'deploy'})
    t.call('ssh_owner_revoke', 'POST', 'auth/token/revoke', {'token': auth['client_token']}, status=204)
    t.call('ssh_revoked_verify', 'POST', 'upgrade-ssh/verify', {'otp': leases[2][0]}, token='', status=400)
    instance.stop()
    t.check('ssh_secrets_absent', safe_files(instance.root, t.sensitive))


def run_fresh(instance, candidate, rows):
    t, key = initialize(instance, rows, 'fresh')
    # No application mutation between initialization/unseal and this archive.
    data = t.call('fresh_pre_batch_archive', 'GET', 'sys/storage/raft/snapshot')['data']
    archive = data.get('snapshot')
    t.check('fresh_pre_batch_archive_shape', isinstance(archive, str) and bool(archive)
            and data.get('format') == 'heptabao-encrypted-backup-v1')
    batch = t.issued('fresh_batch', t.call('fresh_issue', 'POST', 'auth/token/create-orphan',
        {'type': 'batch', 'ttl': 900, 'policies': ['default']}), 'batch')
    t.call('fresh_later_write', 'POST', 'secret/data/post-backup', {'data': {'value': 'later'}})
    t.call('fresh_restore', 'POST', 'sys/storage/raft/snapshot-force', {'snapshot': archive})
    t.lookup('fresh_after_restore_batch', batch, 'batch')
    t.call('fresh_later_absent', 'GET', 'secret/data/post-backup', status=404)
    restart(instance, candidate, t, key, 'fresh_reopen')
    t.lookup('fresh_reopen_batch', batch, 'batch')
    instance.stop()
    t.check('fresh_secrets_absent', safe_files(instance.root, t.sensitive))


def make_instance(binary, path):
    from remote_jwks_live import Instance
    instance = Instance(binary, path)
    config_path = instance.root/'server.json'
    config = json.loads(config_path.read_text())
    config.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
    private_write(config_path, config, replace=True)
    return instance


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--legacy-binary', type=Path, required=True)
    parser.add_argument('--build-source-commit', required=True)
    parser.add_argument('--expected-binary-sha256', required=True)
    parser.add_argument('--work-parent', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.build_source_commit) or not re.fullmatch('[0-9a-f]{64}', args.expected_binary_sha256):
        parser.error('invalid_candidate_pins')
    candidate, legacy = args.binary.resolve(strict=True), args.legacy_binary.resolve(strict=True)
    candidate_hash, legacy_hash = validate_binary_pins(candidate, legacy, LEGACY_SHA256)
    if candidate_hash != args.expected_binary_sha256:
        parser.error('candidate_binary_sha256_mismatch')
    receipt_hash = file_hash(LEGACY_RECEIPT)
    admit_legacy_receipt(json.loads(LEGACY_RECEIPT.read_text()))
    output = args.output.absolute()
    admitted = admit_output(output)
    before, runner_hash, helper_hashes = source_identity(ROOT, candidate), file_hash(Path(__file__)), helpers()
    root = Path(tempfile.mkdtemp(prefix='userpass-batch-upgrade-', dir=private_parent(args.work_parent)))
    root.chmod(0o700)
    rows, instances, failure = [], [], None
    try:
        for name, binary, scenario in [('upgrade', legacy, run_upgrade), ('ssh', legacy, run_ssh), ('fresh', candidate, run_fresh)]:
            instance = make_instance(binary, root/name)
            instances.append(instance)
            if name == 'upgrade':
                scenario(instance, candidate, legacy, rows)
            else:
                scenario(instance, candidate, rows)
        Trace(instances[-1], rows).check('complete', True)
    except Exception as error:
        failure = next((row['case'] for row in reversed(rows) if row['passed'] is not True), 'fixture_'+type(error).__name__)
    finally:
        for instance in instances:
            instance.stop()
    after = source_identity(ROOT, candidate)
    unchanged = before == after and file_hash(candidate) == candidate_hash and file_hash(legacy) == legacy_hash
    runner_ok = file_hash(Path(__file__)) == runner_hash
    helpers_ok = helpers() == helper_hashes
    if not unchanged or not runner_ok or not helpers_ok or file_hash(LEGACY_RECEIPT) != receipt_hash:
        failure = 'source_binary_or_runner_changed'
    if before['source_dirty'] or after['source_dirty']:
        failure = 'source_dirty'
    if not complete(rows):
        failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.userpass-batch-upgrade.v1', 'status': 'passed' if failure is None else 'failed',
        'failure': failure, 'checks': rows, 'source_identity': before, 'source_identity_after': after,
        'source_and_binary_unchanged': unchanged, 'runner_sha256': runner_hash, 'runner_unchanged': runner_ok,
        'helper_sha256': helper_hashes, 'helpers_unchanged': helpers_ok, 'build_source_commit': args.build_source_commit,
        'legacy_source_commit': LEGACY_SOURCE, 'legacy_binary_sha256': legacy_hash, 'legacy_receipt_sha256': receipt_hash,
        'from_schema': 40, 'minimum_to_schema': 41, 'credential_storage_fabricated': False,
        'old_reader_actually_executed': old_reader_observed(rows), 'mutation_retries': 0,
        'pure_read_profile': 'separate_store_without_dynamic_leases',
        'ssh_maintenance_may_write_clock_and_schema': True, 'database_or_pki_or_ldap_leases_covered': False,
        'fresh_key_history_profile': 'candidate_specific_JSON_backup_before_first_batch_then_orphan_survives_restore',
        'native_or_openbao_snapshot_interoperability_covered': False, 'HA_covered': False,
        'application_artifact_scope': 'all entries except root ledger.hbl re-sealed before schema admission',
        'retained_failure_work_dir': str(root) if failure else None, 'synthetic_only': True,
        'full_openbao_compatibility': False, 'independent_qualification': False, 'production_authority': False}
    if admit_output(output) != admitted:
        raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    if failure is None:
        shutil.rmtree(root)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return int(failure is not None)


if __name__ == '__main__':
    raise SystemExit(main())
