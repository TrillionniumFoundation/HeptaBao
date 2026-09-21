#!/usr/bin/env python3
"""Actual schema44 -> 45 role SecretID source CIDRs, qualified old binary via CLI."""
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
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from radius_cidrs_live import SourceClient
from userpass_password_live import private_parent, safe_files
from userpass_batch_upgrade import Trace as BaseTrace, initialize, make_instance, restart
from jwt_batch_live import complete as legacy_complete, calibrated_rows as legacy_calibration
from approle_secret_cidrs_upgrade_contract import (
    FIELD, MODES, KINDS, complete, retained_role, admit_legacy, old_reader_observed, denied_journal_append)

BOUND = ['127.0.0.1/32']
VALUE = {'value': 'synthetic-upgrade-value'}
POLICY = 'secret-source-upgrade'


def role_path(kind): return 'auth/approle/role/preserved-'+kind


class Trace(BaseTrace):
    def call(self, name, method, route, body=None, *, token=None, namespace='', status=200,
             source='127.0.0.1', spoof=False):
        if namespace: raise ValueError('unexpected_namespace')
        client = SourceClient(self.instance.address, self.instance.root/'ca.crt', self.instance.token)
        result = client.request(method, route, body, token=token, source=source, spoof=spoof)
        data, auth = result.body.get('data') or {}, result.body.get('auth') or {}
        self.sensitive.extend(value for value in (auth.get('client_token'), auth.get('accessor'),
            data.get('secret_id'), data.get('secret_id_accessor'), data.get('role_id'))
            if isinstance(value, str) and value)
        self.check(name+'_status', result.status == status, status=result.status)
        if status >= 400:
            self.check(name+'_no_credentials', not auth and not result.body.get('wrap_info') and not data)
        return result.body

    def bearer(self, prefix, auth):
        for label, source in (('one', '127.0.0.1'), ('two', '127.0.0.2')):
            body = self.call(prefix+'_'+label, 'GET', 'secret/data/upgrade', token=auth['client_token'], source=source)
            self.check(prefix+'_'+label+'_value', (body.get('data') or {}).get('data') == VALUE)


def sid(t, prefix, kind, role_id):
    data = t.call(prefix+'_mint', 'POST', role_path(kind)+'/secret-id', {})['data']
    return {'role_id': role_id, 'secret_id': data['secret_id']}


def remaining(t, prefix, kind, creds, expected):
    body = t.call(prefix+'_lookup', 'POST', role_path(kind)+'/secret-id/lookup',
                  {'secret_id': creds['secret_id']})
    t.check(prefix+'_remaining', (body.get('data') or {}).get('secret_id_num_uses') == expected)


def login(t, prefix, creds, kind, *, source='127.0.0.1'):
    return t.issued(prefix, t.call(prefix+'_request', 'POST', 'auth/approle/login', creds,
                    token='', source=source), kind)


def seed(instance, rows, mode):
    base, key = initialize(instance, rows, mode+'_legacy')
    t = Trace(instance, rows); t.sensitive = base.sensitive
    t.call(mode+'_policy', 'PUT', 'sys/policies/acl/'+POLICY,
           {'policy': 'path "secret/data/upgrade" { capabilities=["read"] }'}, status=204)
    t.call(mode+'_value', 'POST', 'secret/data/upgrade', {'data': VALUE})
    saved = {}
    for kind in KINDS:
        prefix = mode+'_'+kind
        t.call(prefix+'_role', 'POST', role_path(kind), {'token_type': kind, 'token_ttl': 900,
            'token_max_ttl': 1200, 'token_policies': [POLICY], 'secret_id_num_uses': 3,
            'secret_id_ttl': 1800}, status=204)
        role = t.call(prefix+'_old_role', 'GET', role_path(kind))['data']
        t.check(prefix+'_old_field_absent', FIELD not in role)
        rid = t.call(prefix+'_role_id', 'GET', role_path(kind)+'/role-id')['data']['role_id']
        creds = sid(t, prefix+'_old', kind, rid)
        auth = login(t, prefix+'_old', creds, kind, source='127.0.0.2')
        old_sid = t.call(prefix+'_old_sid', 'POST', role_path(kind)+'/secret-id/lookup',
                        {'secret_id': creds['secret_id']})['data']
        t.check(prefix+'_old_remaining', old_sid.get('secret_id_num_uses') == 2)
        saved[kind] = {'role': role, 'sid': old_sid, 'creds': creds, 'auth': auth}
    return t, key, saved


def downgrade(instance, candidate, legacy, t, key, mode):
    instance.stop(); before = durable_manifest(instance.root/'data', application_only=True)
    instance.binary = legacy; instance.start()
    t.call(mode+'_downgrade_unseal', 'POST', 'sys/unseal', {'key': key}, status=503)
    t.call(mode+'_downgrade_health', 'GET', 'sys/health', status=503)
    instance.stop()
    t.check(mode+'_downgrade_application_unchanged', durable_manifest(instance.root/'data', application_only=True) == before)
    restart(instance, candidate, t, key, mode+'_recover')


def storage_failure(t, instance, candidate, key, prefix, kind, rid):
    t.call(prefix+'_fault_role', 'POST', role_path(kind), {'secret_id_num_uses': 2}, status=204)
    creds = sid(t, prefix+'_fault', kind, rid)
    store = instance.root/'data'; before = durable_manifest(store)
    # FileBackend opens journal.hbj for append per publication. Verify a real
    # non-root permission failure before the request, and always restore mode.
    with denied_journal_append(store):
        denied = t.call(prefix+'_fault_denied', 'POST', 'auth/approle/login', creds,
                        token='', source='127.0.0.2', spoof=True, status=503)
        t.check(prefix+'_fault_unknown_reference', isinstance(denied.get('recovery_reference'), str)
                and bool(denied['recovery_reference']))
    t.check(prefix+'_fault_manifest_unchanged', durable_manifest(store) == before)
    t.call(prefix+'_fault_fenced', 'GET', 'sys/health', status=503)
    # Durable conservatively fences even an append-open error as unknown.
    # Do not retry the mutation; reopen and inspect the recovered credential.
    restart(instance, candidate, t, key, prefix+'_fault_reopen')
    remaining(t, prefix+'_fault_reopened', kind, creds, 2)
    login(t, prefix+'_fault_allowed', creds, kind)
    remaining(t, prefix+'_fault_after_allowed', kind, creds, 1)


def run_store(instance, candidate, legacy, rows, mode, sensitive):
    t, key, saved = seed(instance, rows, mode)
    sensitive.append(t.sensitive)
    store = instance.root/'data'; instance.stop()
    original = durable_manifest(store, application_only=True)
    for phase in ('pure', 'pure_restart'):
        restart(instance, candidate, t, key, mode+'_'+phase)
        t.check(mode+'_'+phase+'_application_unchanged', durable_manifest(store, application_only=True) == original)
        before = durable_manifest(store)
        for kind, old in saved.items():
            prefix = mode+'_'+phase+'_'+kind
            role = t.call(prefix+'_role', 'GET', role_path(kind))['data']
            t.check(prefix+'_role_preserved', retained_role(role, old['role']))
            data = t.call(prefix+'_field', 'GET', role_path(kind)+'/secret-id-bound-cidrs')['data']
            t.check(prefix+'_field_nil', FIELD in data and data[FIELD] is None)
            data = t.call(prefix+'_sid', 'POST', role_path(kind)+'/secret-id/lookup', {'secret_id': old['creds']['secret_id']})['data']
            t.check(prefix+'_sid_preserved', data == old['sid'])
            t.lookup(prefix+'_lookup', old['auth'], kind); t.bearer(prefix, old['auth'])
        t.check(mode+'_'+phase+'_reads_unchanged', durable_manifest(store) == before)
    restart(instance, legacy, t, key, mode+'_old_control')
    for kind, old in saved.items(): t.lookup(mode+'_control_'+kind, old['auth'], kind)
    t.check(mode+'_old_read_control', durable_manifest(store, application_only=True) == original)
    restart(instance, candidate, t, key, mode+'_current')
    value = [] if mode == 'empty' else BOUND
    # Dedicated POST empty is 400; the whole-role route owns Some([]).
    t.call(mode+'_first_mutation', 'POST', role_path('service'), {FIELD: value}, status=204)
    # No intervening token issue/renewal or other write can cause this fence.
    downgrade(instance, candidate, legacy, t, key, mode)
    data = t.call(mode+'_first_read', 'GET', role_path('service')+'/secret-id-bound-cidrs')['data']
    t.check(mode+'_first_shape', FIELD in data and data[FIELD] == value)
    for kind, old in saved.items():
        prefix = mode+'_'+kind; creds = old['creds']; rid = creds['role_id']
        t.call(prefix+'_bound', 'POST', role_path(kind)+'/secret-id-bound-cidrs', {FIELD: BOUND}, status=204)
        t.bearer(prefix+'_old', old['auth'])
        t.call(prefix+'_old_renew', 'POST', 'auth/token/renew-self', {'increment': 900},
               token=old['auth']['client_token'], source='127.0.0.2', status=200 if kind == 'service' else 400)
        t.call(prefix+'_denied', 'POST', 'auth/approle/login', creds, token='', source='127.0.0.2', spoof=True, status=400)
        remaining(t, prefix+'_after_denied', kind, creds, 1)
        restart(instance, candidate, t, key, prefix+'_reopen')
        remaining(t, prefix+'_reopened', kind, creds, 1)
        fresh = login(t, prefix+'_allowed', creds, kind)
        t.call(prefix+'_exhausted', 'POST', role_path(kind)+'/secret-id/lookup', {'secret_id': creds['secret_id']}, status=204)
        t.call(prefix+'_exhausted_login', 'POST', 'auth/approle/login', creds, token='', status=400)
        t.bearer(prefix+'_issued', fresh)
        for label, uses in (('one', 1), ('unlimited', 0)):
            t.call(prefix+'_'+label+'_role', 'POST', role_path(kind), {'secret_id_num_uses': uses}, status=204)
            current = sid(t, prefix+'_'+label, kind, rid)
            t.call(prefix+'_'+label+'_denied', 'POST', 'auth/approle/login', current,
                   token='', source='127.0.0.2', spoof=True, status=400)
            if uses:
                t.call(prefix+'_one_exhausted', 'POST', role_path(kind)+'/secret-id/lookup', {'secret_id': current['secret_id']}, status=204)
            else:
                remaining(t, prefix+'_unlimited', kind, current, 0)
                login(t, prefix+'_unlimited_allowed', current, kind)
        t.call(prefix+'_delete', 'DELETE', role_path(kind)+'/secret-id-bound-cidrs', status=204)
        data = t.call(prefix+'_deleted', 'GET', role_path(kind)+'/secret-id-bound-cidrs')['data']
        t.check(prefix+'_deleted_nil', FIELD in data and data[FIELD] is None)
        login(t, prefix+'_after_clear', current, kind, source='127.0.0.2')
        t.bearer(prefix+'_after_clear_old', old['auth'])
        t.call(prefix+'_restore', 'POST', role_path(kind), {FIELD: BOUND}, status=204)
        restart(instance, candidate, t, key, prefix+'_source_reopen')
        t.call(prefix+'_reopened_denied', 'POST', 'auth/approle/login', current,
               token='', source='127.0.0.2', spoof=True, status=400)
        login(t, prefix+'_reopened_allowed', current, kind)
        storage_failure(t, instance, candidate, key, prefix, kind, rid)
    instance.stop(); t.check(mode+'_secrets_absent', safe_files(instance.root, t.sensitive))


def helpers():
    names = ('approle_secret_cidrs_upgrade_contract', 'bao_http', 'heptabao.transport', 'core_isolation',
        'identity_upgrade', 'online_evidence', 'provider_renewal_upgrade', 'radius_cidrs_live',
        'userpass_password_live', 'userpass_batch_upgrade', 'remote_jwks_live', 'smoke',
        'jwt_batch_live', 'jwt_batch_probe')
    return {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}


def main():
    parser = SafeArgumentParser(description=__doc__)
    for name in ('binary', 'legacy-binary', 'legacy-receipt', 'work-parent', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ('build-source-commit', 'expected-binary-sha256', 'legacy-build-source-commit',
                 'legacy-binary-sha256', 'legacy-receipt-sha256'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.build_source_commit) or not re.fullmatch('[0-9a-f]{64}', args.expected_binary_sha256):
        parser.error('candidate_pins_required')
    candidate, legacy = args.binary.resolve(strict=True), args.legacy_binary.resolve(strict=True)
    actual, legacy_hash = validate_binary_pins(candidate, legacy, args.legacy_binary_sha256)
    if actual != args.expected_binary_sha256: parser.error('candidate_binary_mismatch')
    receipt = args.legacy_receipt.resolve(strict=True); receipt_hash = file_hash(receipt)
    expected = legacy_calibration()
    admit_legacy(json.loads(receipt.read_text()), receipt_hash, args.legacy_receipt_sha256,
                 args.legacy_build_source_commit, legacy_hash, expected, legacy_complete)
    output = args.output.absolute(); admitted = admit_output(output)
    before, runner, helper = source_identity(ROOT, candidate), file_hash(Path(__file__)), helpers()
    work = Path(tempfile.mkdtemp(prefix='approle-secret-source-upgrade-', dir=private_parent(args.work_parent)))
    rows, instances, sensitive, failure = [], [], [], None
    def interrupted(signum, frame): raise ScenarioFailure('fixture_interrupted')
    signals = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGTERM, signal.SIGINT)}
    try:
        for mode in MODES:
            instance = make_instance(legacy, work/mode); instances.append(instance)
            run_store(instance, candidate, legacy, rows, mode, sensitive)
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
    if not unchanged or not runner_ok or not helper_ok or file_hash(receipt) != receipt_hash:
        failure = 'source_binary_or_helpers_changed'
    if before['source_dirty'] or after['source_dirty']: failure = 'source_dirty'
    if not complete(rows): failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.approle-secret-cidrs-upgrade.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': rows, 'source_identity': before, 'source_identity_after': after,
        'source_and_binary_unchanged': unchanged, 'build_source_commit': args.build_source_commit,
        'runner_sha256': runner, 'runner_unchanged': runner_ok, 'helper_sha256': helper, 'helpers_unchanged': helper_ok,
        'legacy_source_commit': args.legacy_build_source_commit, 'legacy_binary_sha256': legacy_hash,
        'legacy_receipt_sha256': receipt_hash, 'from_schema': 44, 'minimum_to_schema': 45,
        'old_reader_actually_executed': old_reader_observed(rows), 'credential_storage_fabricated': False,
        'mutating_requests_retried': False, 'first_mutations': ['explicit_empty_source_cidrs', 'nonempty_source_cidrs'],
        'pure_read_profile': 'application bytes across two reopens; all durable artifacts across reads',
        'downgrade_ledger_exception': 'historical reopen may reseal ledger; application snapshot and journal must not change',
        'storage_failure_profile': 'nonroot journal append permission denied before write; mode restored in finally',
        'storage_failure_protocol': '503 outcome-unknown fence, explicit reopen, then inspect SID before any further login',
        'storage_failure_observed': any(row['case'].endswith('_fault_unknown_reference') and row['passed'] is True for row in rows),
        'all_crash_points_covered': False,
        'retained_failure_work_dir': str(work) if failure else None, 'synthetic_only': True,
        'HA_covered': False, 'openbao_state_interoperability': False, 'full_openbao_compatibility': False,
        'independent_qualification': False, 'production_authority': False}
    if any(secret in json.dumps(report) for group in sensitive for secret in group): raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    if failure is None: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return int(failure is not None)


if __name__ == '__main__': raise SystemExit(main())
