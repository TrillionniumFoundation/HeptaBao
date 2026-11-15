#!/usr/bin/env python3
"""Actual schema42 -> 43 AppRole issued-token CIDR upgrade, two private stores.

The historical binary creates every role, SecretID and token. No fabricated
serialized state, OpenBao state interoperability, or HA qualification is used.
"""
from __future__ import annotations
import importlib
import json
from pathlib import Path
import re
import shutil
import signal
import tempfile

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from online_evidence import admit_output, complete_checks, source_identity
from provider_renewal_upgrade import durable_manifest
from radius_cidrs_live import SourceClient
from userpass_password_live import private_parent, safe_files
from userpass_batch_upgrade import Trace as BaseTrace, initialize, make_instance, restart
from approle_batch_live import complete as legacy_complete

LEGACY_SOURCE = 'cdf3b98746eaf89b257b2744d493227606b29ab5'
LEGACY_SHA256 = '1a12d1633ef2f009b60c46d1c3c6ae8355b855c85f61a412c3a92f4741e1435e'
LEGACY_RECEIPT = ROOT/'qa/openbao-acceptance/evidence/approle-batch-live-cdf3b98.json'
LEGACY_RECEIPT_SHA256 = '0cd13f85515f04b83b9b0e008dc2cf2e7eef7248943a3d3e70b61a7fcaf5c767'
FIELD = 'token_bound_cidrs'
BOUND = ['127.0.0.1/32']
CANONICAL = ['127.0.0.1']
VALUE = {'value': 'synthetic-upgrade-value'}
POLICY = 'cidr-upgrade'
KINDS = ('service', 'batch')
REQUIRED = frozenset({'complete', 'processes_stopped'}) | frozenset(
    mode+'_'+case for mode in ('empty', 'bound') for case in (
        'pure_application_unchanged', 'pure_reads_unchanged',
        'pure_restart_application_unchanged', 'pure_restart_reads_unchanged',
        'old_read_control', 'first_cidr_status', 'first_cidr_shape',
        'downgrade_unseal_status', 'downgrade_health_status',
        'downgrade_application_unchanged', 'secrets_absent')) | frozenset(
    f'{mode}_{phase}_{kind}_{case}' for mode in ('empty', 'bound')
    for phase in ('pure', 'pure_restart', 'migrated_old', 'reopened_old')
    for kind in KINDS for case in ('one_value', 'two_value')) | frozenset(
    f'{mode}_{kind}_{case}' for mode in ('empty', 'bound') for kind in KINDS
    for case in ('pure_role_preserved', 'pure_sid_preserved', 'new_shape',
                 'new_one_value', 'new_two_status', 'new_two_no_credentials',
                 'new_sid_remaining', 'delete_status', 'deleted_null',
                 'unbound_two_value', 'deleted_issued_two_status',
                 'reopened_bound_one_value', 'reopened_bound_two_status',
                 'reopened_unbound_two_value')) | frozenset(
    f'{mode}_historical_{repair}_{case}' for mode in ('empty', 'bound')
    for repair in ('secret', 'cidr') for case in (
        'legacy_login_shape', 'current_login_shape', 'invalid_status',
        'invalid_unchanged', 'repaired_status', 'repaired_login_shape',
        'reopened_login_shape'))


def complete(rows):
    if not isinstance(rows, list) or any(not isinstance(row, dict)
        or set(row)-{'case', 'passed', 'status'}
        or 'status' in row and (type(row['status']) is not int or not 100 <= row['status'] <= 599)
        for row in rows):
        return False
    return (complete_checks([{'case': r.get('case'), 'passed': r.get('passed')} for r in rows],
                            required_cases=REQUIRED) and rows[-1]['case'] == 'complete')


def admit_legacy(receipt, digest):
    before, sides = receipt.get('candidate_source') or {}, receipt.get('cases') or {}
    finished, divergences = receipt.get('completed_scenarios') or {}, receipt.get('documented_divergences') or {}
    if (digest != LEGACY_RECEIPT_SHA256 or receipt.get('schema') != 'heptabao.approle-batch-comparison.v1'
        or receipt.get('status') != 'passed' or receipt.get('build_source_commit') != LEGACY_SOURCE
        or before.get('source_commit') != LEGACY_SOURCE or before.get('binary_sha256') != LEGACY_SHA256
        or before.get('source_dirty') is not False or receipt.get('candidate_source_after') != before
        or receipt.get('oracle_only') is not False or receipt.get('failures')
        or set(sides) != {'candidate', 'oracle'} or set(finished) != set(sides)
        or set(divergences) != set(sides)
        or not all(legacy_complete(sides[s], finished[s], s) for s in sides)
        or not all(divergences[s].get('passed') is True for s in sides)
        or receipt.get('secrets_absent') != {'candidate': True, 'oracle': True}
        or any(receipt.get(name) is not True for name in ('source_and_binary_unchanged', 'equal_lane_matches',
            'runner_unchanged', 'helpers_unchanged', 'oracle_binary_unchanged'))):
        raise ValueError('qualified_schema42_binary_receipt_required')


def retained_role(current, old):
    if not isinstance(current, dict) or not isinstance(old, dict) or FIELD in old:
        return False
    current = dict(current)
    return FIELD in current and current.pop(FIELD) == [] and current == old


def path(kind): return 'auth/approle/role/preserved-'+kind


class Trace(BaseTrace):
    def call(self, name, method, route, body=None, *, token=None, namespace='', status=200,
             source='127.0.0.1', spoof=False):
        if namespace: raise ValueError('unexpected_namespace')
        client = SourceClient(self.instance.address, self.instance.root/'ca.crt', self.instance.token)
        result = client.request(method, route, body, token=token, source=source, spoof=spoof)
        self.check(name+'_status', result.status == status, status=result.status)
        if status >= 400:
            self.check(name+'_no_credentials', not result.body.get('auth') and not result.body.get('wrap_info')
                       and not result.body.get('data'))
        return result.body

    def bearer(self, prefix, auth, *, restricted):
        for label, source in (('one', '127.0.0.1'), ('two', '127.0.0.2')):
            denied = restricted and label == 'two'
            response = self.call(prefix+'_'+label, 'GET', 'secret/data/upgrade',
                token=auth['client_token'], source=source, spoof=denied, status=403 if denied else 200)
            if not denied: self.check(prefix+'_'+label+'_value', (response.get('data') or {}).get('data') == VALUE)


def seed(instance, rows, mode):
    base, key = initialize(instance, rows, mode+'_legacy')
    t = Trace(instance, rows); t.sensitive = base.sensitive
    t.call(mode+'_policy', 'PUT', 'sys/policies/acl/'+POLICY,
           {'policy': 'path "secret/data/upgrade" { capabilities=["read"] }'}, status=204)
    t.call(mode+'_value', 'POST', 'secret/data/upgrade', {'data': VALUE})
    saved = {}
    for kind in KINDS:
        prefix = mode+'_'+kind
        t.call(prefix+'_role', 'POST', path(kind), {'token_type': kind, 'token_ttl': 900,
            'token_max_ttl': 1200, 'token_policies': [POLICY],
            'secret_id_num_uses': 6, 'secret_id_ttl': 1800}, status=204)
        role = t.call(prefix+'_old_role', 'GET', path(kind))['data']
        t.check(prefix+'_old_cidr_absent', FIELD not in role)
        role_id = t.call(prefix+'_role_id', 'GET', path(kind)+'/role-id')['data']['role_id']
        sid = t.call(prefix+'_secret', 'POST', path(kind)+'/secret-id', {})['data']
        t.sensitive.extend((role_id, sid['secret_id'], sid['secret_id_accessor']))
        login = {'role_id': role_id, 'secret_id': sid['secret_id']}
        auth = t.issued(prefix+'_old', t.call(prefix+'_old_login', 'POST', 'auth/approle/login', login, token=''), kind)
        sid_data = t.call(prefix+'_old_sid', 'POST', path(kind)+'/secret-id/lookup', {'secret_id': sid['secret_id']})['data']
        t.check(prefix+'_old_remaining', sid_data.get('secret_id_num_uses') == 5)
        saved[kind] = {'role': role, 'sid': sid_data, 'login': login, 'auth': auth}
    historical = {}
    for repair in ('secret', 'cidr'):
        prefix, route = mode+'_historical_'+repair, 'auth/approle/role/historical-'+repair
        t.call(prefix+'_legacy_role', 'POST', route, {'bind_secret_id': False,
            'token_ttl': 900, 'token_max_ttl': 1200, 'token_policies': [POLICY]}, status=204)
        role = t.call(prefix+'_legacy_read', 'GET', route)['data']
        role_id = t.call(prefix+'_role_id', 'GET', route+'/role-id')['data']['role_id']
        t.sensitive.append(role_id)
        login = {'role_id': role_id}
        t.issued(prefix+'_legacy_login', t.call(prefix+'_legacy_issue', 'POST', 'auth/approle/login', login, token=''), 'service')
        historical[repair] = {'route': route, 'role': role, 'login': login}
    return t, key, saved, historical


def downgrade(instance, candidate, legacy, t, key, mode):
    instance.stop()
    before = durable_manifest(instance.root/'data', application_only=True)
    instance.binary = legacy; instance.start()
    t.call(mode+'_downgrade_unseal', 'POST', 'sys/unseal', {'key': key}, status=503)
    t.call(mode+'_downgrade_health', 'GET', 'sys/health', status=503)
    instance.stop()
    t.check(mode+'_downgrade_application_unchanged', durable_manifest(instance.root/'data', application_only=True) == before)
    restart(instance, candidate, t, key, mode+'_recover')


def run_store(instance, candidate, legacy, rows, mode):
    t, key, saved, historical = seed(instance, rows, mode)
    store = instance.root/'data'; instance.stop()
    original = durable_manifest(store, application_only=True)
    for phase in ('pure', 'pure_restart'):
        restart(instance, candidate, t, key, mode+'_'+phase)
        t.check(mode+'_'+phase+'_application_unchanged', durable_manifest(store, application_only=True) == original)
        before = durable_manifest(store)
        for kind, old in saved.items():
            prefix = mode+'_'+kind+'_'+phase
            current = t.call(prefix+'_role', 'GET', path(kind))['data']
            t.check(prefix+'_role_preserved', retained_role(current, old['role']))
            field = t.call(prefix+'_field', 'GET', path(kind)+'/token-bound-cidrs')['data']
            t.check(prefix+'_field_nil', FIELD in field and field[FIELD] is None)
            current_sid = t.call(prefix+'_sid', 'POST', path(kind)+'/secret-id/lookup', {'secret_id': old['login']['secret_id']})['data']
            t.check(prefix+'_sid_preserved', current_sid == old['sid'])
            t.lookup(prefix+'_lookup', old['auth'], kind)
            t.bearer(mode+'_'+phase+'_'+kind, old['auth'], restricted=False)
        for repair, old in historical.items():
            current = t.call(mode+'_'+phase+'_historical_'+repair, 'GET', old['route'])['data']
            t.check(mode+'_'+phase+'_historical_'+repair+'_preserved', retained_role(current, old['role']))
        t.check(mode+'_'+phase+'_reads_unchanged', durable_manifest(store) == before)
    restart(instance, legacy, t, key, mode+'_old_control')
    for kind, old in saved.items(): t.lookup(mode+'_control_'+kind, old['auth'], kind)
    t.check(mode+'_old_read_control', durable_manifest(store, application_only=True) == original)
    restart(instance, candidate, t, key, mode+'_current')
    target = path('service')+('/token-bound-cidrs' if mode == 'empty' else '')
    value = [] if mode == 'empty' else BOUND
    t.call(mode+'_first_cidr', 'POST', target, {FIELD: value}, status=204)
    # Nothing that could independently advance schema may precede this old-reader fence.
    downgrade(instance, candidate, legacy, t, key, mode)
    current = t.call(mode+'_first_read', 'GET', path('service'))['data']
    t.check(mode+'_first_cidr_shape', current.get(FIELD) == ([] if mode == 'empty' else CANONICAL))
    new, unbound = {}, {}
    for kind, old in saved.items():
        prefix = mode+'_'+kind
        t.bearer(mode+'_migrated_old_'+kind, old['auth'], restricted=False)
        t.call(prefix+'_bounds', 'POST', path(kind), {FIELD: BOUND}, status=204)
        auth = t.issued(prefix+'_new', t.call(prefix+'_new_login', 'POST', 'auth/approle/login', old['login'],
            token='', source='127.0.0.2'), kind)
        new[kind] = auth
        t.bearer(prefix+'_new', auth, restricted=True)
        sid = t.call(prefix+'_new_sid', 'POST', path(kind)+'/secret-id/lookup', {'secret_id': old['login']['secret_id']})['data']
        t.check(prefix+'_new_sid_remaining', sid.get('secret_id_num_uses') == 4)
        # An administrator outside target CIDRs can inspect the target.
        data = t.call(prefix+'_admin_lookup', 'POST', 'auth/token/lookup', {'token': auth['client_token']}, source='127.0.0.2')['data']
        t.check(prefix+'_issued_bounds', data.get('bound_cidrs') == CANONICAL)
        t.call(prefix+'_delete', 'DELETE', path(kind)+'/token-bound-cidrs', status=204)
        data = t.call(prefix+'_deleted_read', 'GET', path(kind)+'/token-bound-cidrs')['data']
        t.check(prefix+'_deleted_null', FIELD in data and data[FIELD] is None)
        whole = t.call(prefix+'_deleted_whole', 'GET', path(kind))['data']
        t.check(prefix+'_deleted_whole_empty', whole.get(FIELD) == [])
        t.bearer(prefix+'_deleted_issued', auth, restricted=True)
        unbound[kind] = t.issued(prefix+'_unbound', t.call(prefix+'_unbound_login', 'POST', 'auth/approle/login',
            old['login'], token='', source='127.0.0.2'), kind)
        t.bearer(prefix+'_unbound', unbound[kind], restricted=False)
    for repair, old in historical.items():
        prefix = mode+'_historical_'+repair
        t.issued(prefix+'_current_login', t.call(prefix+'_current_issue', 'POST', 'auth/approle/login', old['login'], token=''), 'service')
        before = durable_manifest(store)
        t.call(prefix+'_invalid', 'POST', old['route'], {'token_ttl': 901}, status=500)
        t.check(prefix+'_invalid_unchanged', durable_manifest(store) == before)
        fields = {'bind_secret_id': True} if repair == 'secret' else {FIELD: BOUND}
        t.call(prefix+'_repaired', 'POST', old['route'], fields, status=204)
        if repair == 'secret':
            sid = t.call(prefix+'_new_sid', 'POST', old['route']+'/secret-id', {})['data']
            t.sensitive.extend((sid['secret_id'], sid['secret_id_accessor']))
            old['login'] = dict(old['login'], secret_id=sid['secret_id'])
        auth = t.issued(prefix+'_repaired_login', t.call(prefix+'_repaired_issue', 'POST', 'auth/approle/login',
            old['login'], token='', source='127.0.0.2'), 'service')
        t.bearer(prefix+'_repaired', auth, restricted=repair == 'cidr')
    restart(instance, candidate, t, key, mode+'_reopened')
    for kind, old in saved.items():
        t.bearer(mode+'_reopened_old_'+kind, old['auth'], restricted=False)
        t.bearer(mode+'_'+kind+'_reopened_bound', new[kind], restricted=True)
        t.bearer(mode+'_'+kind+'_reopened_unbound', unbound[kind], restricted=False)
    for repair, old in historical.items():
        prefix = mode+'_historical_'+repair
        auth = t.issued(prefix+'_reopened_login', t.call(prefix+'_reopened_issue', 'POST', 'auth/approle/login', old['login'], token=''), 'service')
        t.bearer(prefix+'_reopened', auth, restricted=repair == 'cidr')
    instance.stop()
    t.check(mode+'_secrets_absent', safe_files(instance.root, t.sensitive))


def helpers():
    names = ('bao_http', 'heptabao.transport', 'core_isolation', 'identity_upgrade', 'online_evidence',
        'provider_renewal_upgrade', 'remote_jwks_live', 'smoke', 'userpass_password_live',
        'userpass_batch_upgrade', 'radius_cidrs_live', 'approle_batch_live', 'approle_batch_probe')
    result = {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}
    calibration = ROOT/'qa/openbao-acceptance/evidence/approle-batch-official-probe-v2-20260922.json'
    result['official_role_type_calibration'] = file_hash(calibration)
    return result


def main():
    parser = SafeArgumentParser(description=__doc__)
    for name in ('binary', 'legacy-binary', 'work-parent', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--build-source-commit', required=True); parser.add_argument('--expected-binary-sha256', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.build_source_commit) or not re.fullmatch('[0-9a-f]{64}', args.expected_binary_sha256):
        parser.error('candidate_pins_required')
    candidate, legacy = args.binary.resolve(strict=True), args.legacy_binary.resolve(strict=True)
    actual, legacy_hash = validate_binary_pins(candidate, legacy, LEGACY_SHA256)
    if actual != args.expected_binary_sha256: parser.error('candidate_binary_mismatch')
    admit_legacy(json.loads(LEGACY_RECEIPT.read_text()), file_hash(LEGACY_RECEIPT))
    output = args.output.absolute(); admitted = admit_output(output)
    before, runner, helper = source_identity(ROOT, candidate), file_hash(Path(__file__)), helpers()
    work = Path(tempfile.mkdtemp(prefix='approle-cidrs-upgrade-', dir=private_parent(args.work_parent))); work.chmod(0o700)
    rows, instances, failure = [], [], None
    def interrupted(signum, frame): raise ScenarioFailure('fixture_interrupted')
    signals = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGTERM, signal.SIGINT)}
    try:
        for mode in ('empty', 'bound'):
            instance = make_instance(legacy, work/mode); instances.append(instance)
            run_store(instance, candidate, legacy, rows, mode)
    except Exception as error:
        failure = next((r['case'] for r in reversed(rows) if r['passed'] is not True), 'fixture_'+type(error).__name__)
    finally:
        try:
            for instance in instances:
                try: instance.stop()
                except Exception: failure = failure or 'candidate_cleanup_failed'
        finally:
            for kind, handler in signals.items(): signal.signal(kind, handler)
    stopped = all(instance.process is None for instance in instances)
    rows.append({'case': 'processes_stopped', 'passed': stopped})
    if not stopped: failure = failure or 'candidate_cleanup_failed'
    if failure is None: BaseTrace(instances[-1], rows).check('complete', True)
    after = source_identity(ROOT, candidate)
    unchanged = before == after and file_hash(legacy) == legacy_hash
    runner_ok, helper_ok = file_hash(Path(__file__)) == runner, helpers() == helper
    if not unchanged or not runner_ok or not helper_ok or file_hash(LEGACY_RECEIPT) != LEGACY_RECEIPT_SHA256:
        failure = 'source_binary_or_helpers_changed'
    if before['source_dirty'] or after['source_dirty']: failure = 'source_dirty'
    if not complete(rows): failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.approle-cidrs-upgrade.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': rows, 'source_identity': before, 'source_identity_after': after,
        'source_and_binary_unchanged': unchanged, 'build_source_commit': args.build_source_commit,
        'runner_sha256': runner, 'runner_unchanged': runner_ok, 'helper_sha256': helper, 'helpers_unchanged': helper_ok,
        'legacy_source_commit': LEGACY_SOURCE, 'legacy_binary_sha256': legacy_hash,
        'legacy_receipt_sha256': LEGACY_RECEIPT_SHA256, 'from_schema': 42, 'minimum_to_schema': 43,
        'credential_storage_fabricated': False, 'mutating_requests_retried': False,
        'pure_read_profile': 'two actual old stores, application bytes across reopen and all durable artifacts across reads',
        'downgrade_ledger_exception': 'historical reopen may reseal ledger; application snapshot and journal must not change',
        'first_mutations': ['explicit_empty_cidrs', 'nonempty_cidrs'],
        'source_profile': 'real IPv4 loopback sockets with TLS; denied bearer attempts spoof the allowed source in headers',
        'retained_failure_work_dir': str(work) if failure else None, 'synthetic_only': True,
        'HA_covered': False, 'physical_failure_covered': False, 'openbao_state_interoperability': False,
        'full_openbao_compatibility': False, 'independent_qualification': False, 'production_authority': False}
    if admit_output(output) != admitted: raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    if failure is None: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return int(failure is not None)


if __name__ == '__main__': raise SystemExit(main())
