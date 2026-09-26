#!/usr/bin/env python3
"""Actual old45 creation, read-only upgrade and four independent SID option gates."""
from __future__ import annotations
import importlib
import json
from pathlib import Path
import re
import secrets
import shutil
import signal
import tempfile

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from userpass_password_live import private_parent, safe_files
from userpass_batch_upgrade import initialize, make_instance, restart
import approle_secret_cidrs_upgrade as previous
import approle_secret_cidrs_live as legacy_comparison
from approle_secretid_overrides_upgrade_contract import (
    PROFILES, LIFECYCLE, complete, old_reader_observed, old_secret_preserved, admit_legacy)

ROLE = 'auth/approle/role/preserved'
POLICY = 'secretid-overrides-upgrade'
BROAD = ['127.0.0.0/24']
ONE, TWO = ['127.0.0.1/32'], ['127.0.0.2/32']
Trace = previous.Trace


def issue(t, name, rid, mode, fields):
    body = dict(fields)
    if mode == 'custom':
        raw = 'synthetic-upgrade-'+secrets.token_urlsafe(24)
        body['secret_id'] = raw; t.sensitive.append(raw)
    data = t.call(name+'_mint', 'POST', ROLE+('/custom-secret-id' if mode == 'custom' else '/secret-id'), body)['data']
    return {'role_id': rid, 'secret_id': data['secret_id']}


def read_sid(t, name, creds, expected_uses=None):
    data = t.call(name+'_lookup', 'POST', ROLE+'/secret-id/lookup', {'secret_id': creds['secret_id']})['data']
    if expected_uses is not None: t.check(name+'_remaining', data.get('secret_id_num_uses') == expected_uses)
    return data


def login(t, name, creds, kind, source='127.0.0.1'):
    return t.issued(name, t.call(name+'_request', 'POST', 'auth/approle/login', creds, token='', source=source), kind)


def use(t, name, auth, one=200, two=200):
    for label, source, status in (('one', '127.0.0.1', one), ('two', '127.0.0.2', two)):
        body = t.call(name+'_'+label, 'GET', 'secret/data/upgrade', token=auth['client_token'], source=source,
                      spoof=source == '127.0.0.2', status=status)
        if status == 200: t.check(name+'_'+label+'_value', (body.get('data') or {}).get('data') == previous.VALUE)


def seed(instance, rows, profile):
    base, key = initialize(instance, rows, profile+'_legacy')
    t = Trace(instance, rows); t.sensitive = base.sensitive
    kind = PROFILES[profile][3]
    t.call(profile+'_policy', 'PUT', 'sys/policies/acl/'+POLICY,
           {'policy': 'path "secret/data/upgrade" { capabilities=["read"] }'}, status=204)
    t.call(profile+'_value', 'POST', 'secret/data/upgrade', {'data': previous.VALUE})
    t.call(profile+'_role', 'POST', ROLE, {'token_type': kind, 'token_ttl': 900, 'token_max_ttl': 1200,
        'token_policies': [POLICY], 'token_bound_cidrs': BROAD, 'secret_id_bound_cidrs': BROAD,
        'secret_id_num_uses': 6, 'secret_id_ttl': 1800}, status=204)
    role = t.call(profile+'_old_role', 'GET', ROLE)['data']
    rid = t.call(profile+'_role_id', 'GET', ROLE+'/role-id')['data']['role_id']
    creds = issue(t, profile+'_old', rid, 'random', {})
    auth = login(t, profile+'_old', creds, kind, '127.0.0.2')
    old = read_sid(t, profile+'_old', creds, 5)
    t.check(profile+'_old_no_overrides', old.get('cidr_list') == [] and old.get('token_bound_cidrs') == [])
    return t, key, {'role': role, 'sid': old, 'creds': creds, 'auth': auth, 'kind': kind, 'rid': rid}


def lifecycle(t, instance, candidate, key, profile, saved):
    kind, rid, mode = saved['kind'], saved['rid'], PROFILES[profile][2]
    t.call(profile+'_unlimited_role', 'POST', ROLE, {'secret_id_num_uses': 0}, status=204)
    source = issue(t, profile+'_source', rid, mode, {'cidr_list': ONE, 'num_uses': 2})
    subset = issue(t, profile+'_subset', rid, mode, {'cidr_list': ONE, 'num_uses': 2})
    override = issue(t, profile+'_override', rid, mode, {'cidr_list': ONE, 'token_bound_cidrs': TWO})
    t.call(profile+'_source_denied', 'POST', 'auth/approle/login', source,
           token='', source='127.0.0.2', spoof=True, status=400)
    read_sid(t, profile+'_source_after_denied', source, 1)
    restart(instance, candidate, t, key, profile+'_source_reopen')
    read_sid(t, profile+'_source_reopened', source, 1)
    source_auth = login(t, profile+'_source_allowed', source, kind)
    t.call(profile+'_source_exhausted', 'POST', ROLE+'/secret-id/lookup', {'secret_id': source['secret_id']}, status=204)
    use(t, profile+'_source_issued_unbound', source_auth)

    t.call(profile+'_role_source_moved', 'POST', ROLE, {'secret_id_bound_cidrs': TWO}, status=204)
    t.call(profile+'_subset_denied', 'POST', 'auth/approle/login', subset, token='', status=500)
    read_sid(t, profile+'_subset_after_denied', subset, 1)
    # Loading the now-incompatible subset must remain possible for an administrator to repair.
    restart(instance, candidate, t, key, profile+'_subset_reopen')
    read_sid(t, profile+'_subset_reopened', subset, 1)
    login(t, profile+'_old_sid_current_source', saved['creds'], kind, '127.0.0.2')
    t.call(profile+'_role_source_restored', 'POST', ROLE, {'secret_id_bound_cidrs': BROAD}, status=204)
    login(t, profile+'_subset_allowed', subset, kind)
    t.call(profile+'_subset_exhausted', 'POST', ROLE+'/secret-id/lookup', {'secret_id': subset['secret_id']}, status=204)

    original = login(t, profile+'_override_initial_login', override, kind)
    use(t, profile+'_override_initial', original, one=403)
    t.call(profile+'_role_token_moved', 'POST', ROLE,
           {'secret_id_bound_cidrs': [], 'token_bound_cidrs': ONE}, status=204)
    moved = login(t, profile+'_override_moved_login', override, kind)
    use(t, profile+'_override_moved', moved, one=403)
    inherited = login(t, profile+'_legacy_inherited_login', saved['creds'], kind, '127.0.0.2')
    use(t, profile+'_legacy_inherited', inherited, two=403)
    t.call(profile+'_role_token_cleared', 'POST', ROLE, {'token_bound_cidrs': []}, status=204)
    cleared = login(t, profile+'_override_cleared_login', override, kind)
    use(t, profile+'_override_cleared', cleared, one=403)
    unbound = login(t, profile+'_legacy_cleared_login', saved['creds'], kind, '127.0.0.2')
    use(t, profile+'_legacy_cleared', unbound)
    old = read_sid(t, profile+'_legacy_after_logins', saved['creds'], 2)
    t.check(profile+'_legacy_fields_still_empty', old.get('cidr_list') == [] and old.get('token_bound_cidrs') == [])
    t.call(profile+'_override_source_denied', 'POST', 'auth/approle/login', override,
           token='', source='127.0.0.2', spoof=True, status=400)
    read_sid(t, profile+'_override_unlimited', override, 0)
    restart(instance, candidate, t, key, profile+'_lifecycle_reopen')
    use(t, profile+'_override_reopened', original, one=403)
    use(t, profile+'_old_bearer_reopened', saved['auth'])
    again = login(t, profile+'_override_after_restart', override, kind)
    use(t, profile+'_override_fresh_after_restart', again, one=403)
    fields = read_sid(t, profile+'_override_readback', override, 0)
    t.check(profile+'_override_literal_fields', fields.get('cidr_list') == ONE and fields.get('token_bound_cidrs') == TWO)


def run_store(instance, candidate, legacy, rows, profile, sensitive):
    t, key, saved = seed(instance, rows, profile); sensitive.append(t.sensitive)
    store = instance.root/'data'; instance.stop()
    original = durable_manifest(store, application_only=True)
    for phase in ('pure', 'pure_restart'):
        name = profile+'_'+phase
        restart(instance, candidate, t, key, name)
        t.check(name+'_application_unchanged', durable_manifest(store, application_only=True) == original)
        before = durable_manifest(store)
        t.check(name+'_role_preserved', t.call(name+'_role', 'GET', ROLE)['data'] == saved['role'])
        t.check(name+'_sid_preserved', old_secret_preserved(read_sid(t, name+'_sid', saved['creds']), saved['sid']))
        t.lookup(name+'_token', saved['auth'], saved['kind']); use(t, name+'_bearer', saved['auth'])
        t.check(name+'_reads_unchanged', durable_manifest(store) == before)
    restart(instance, legacy, t, key, profile+'_old_control')
    t.lookup(profile+'_old_control_token', saved['auth'], saved['kind'])
    t.check(profile+'_old_read_control', durable_manifest(store, application_only=True) == original)
    restart(instance, candidate, t, key, profile+'_current')
    field, value, mode, _ = PROFILES[profile]
    # This is the first candidate mutation. No preliminary role update/login/renewal.
    first = issue(t, profile+'_first', saved['rid'], mode, {field: value})
    previous.downgrade(instance, candidate, legacy, t, key, profile)
    expected_fields = {'cidr_list': [], 'token_bound_cidrs': [], field: value}
    observed = read_sid(t, profile+'_first_read', first, 6)
    t.check(profile+'_first_shape', all(observed.get(k) == v for k,v in expected_fields.items()))
    t.check(profile+'_role_unmodified', t.call(profile+'_role_after_issue', 'GET', ROLE)['data'] == saved['role'])
    t.check(profile+'_old_sid_unmodified', old_secret_preserved(read_sid(t, profile+'_old_after_issue', saved['creds']), saved['sid']))
    if profile in LIFECYCLE: lifecycle(t, instance, candidate, key, profile, saved)
    restart(instance, candidate, t, key, profile+'_final_reopen')
    observed = read_sid(t, profile+'_first_final', first, 6)
    t.check(profile+'_final_first_shape', all(observed.get(k) == v for k,v in expected_fields.items()))
    old = read_sid(t, profile+'_old_final', saved['creds'], 2 if profile in LIFECYCLE else 5)
    t.check(profile+'_final_old_sid_empty', old.get('cidr_list') == [] and old.get('token_bound_cidrs') == [])
    instance.stop(); t.check(profile+'_secrets_absent', safe_files(instance.root, t.sensitive))


def helpers():
    names = ('approle_secretid_overrides_upgrade_contract', 'approle_secret_cidrs_upgrade')
    return {**previous.helpers(), **{'legacy_'+k:v for k,v in legacy_comparison.inputs().items()},
            **{name:file_hash(Path(importlib.import_module(name).__file__)) for name in names}}


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
    expected = legacy_comparison.calibrated_rows()
    admit_legacy(json.loads(receipt.read_text()), receipt_hash, args.legacy_receipt_sha256,
                 args.legacy_build_source_commit, legacy_hash, expected, legacy_comparison.complete)
    output = args.output.absolute(); admitted = admit_output(output)
    before, runner, helper = source_identity(ROOT, candidate), file_hash(Path(__file__)), helpers()
    work = Path(tempfile.mkdtemp(prefix='approle-secretid-overrides-upgrade-', dir=private_parent(args.work_parent)))
    rows, instances, sensitive, failure = [], [], [], None
    def interrupted(signum, frame): raise ScenarioFailure('fixture_interrupted')
    signals = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGTERM, signal.SIGINT)}
    try:
        for mode in PROFILES:
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
    if failure is None: Trace(instances[-1], rows).check('complete', True)
    after = source_identity(ROOT, candidate)
    unchanged = before == after and file_hash(legacy) == legacy_hash
    runner_ok, helper_ok = file_hash(Path(__file__)) == runner, helpers() == helper
    if not unchanged or not runner_ok or not helper_ok or file_hash(receipt) != receipt_hash:
        failure = 'source_binary_or_helpers_changed'
    if before['source_dirty'] or after['source_dirty']: failure = 'source_dirty'
    if not complete(rows): failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.approle-secretid-overrides-upgrade.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': rows, 'source_identity': before, 'source_identity_after': after,
        'source_and_binary_unchanged': unchanged, 'build_source_commit': args.build_source_commit,
        'runner_sha256': runner, 'runner_unchanged': runner_ok, 'helper_sha256': helper, 'helpers_unchanged': helper_ok,
        'legacy_source_commit': args.legacy_build_source_commit, 'legacy_binary_sha256': legacy_hash,
        'legacy_receipt_sha256': receipt_hash, 'from_schema': 45, 'minimum_to_schema': 46,
        'old_reader_actually_executed': old_reader_observed(rows), 'credential_storage_fabricated': False,
        'mutating_requests_retried': False, 'first_mutations': list(PROFILES), 'first_write_profile': {name: {'field': v[0], 'value': v[1], 'endpoint': v[2]} for name,v in PROFILES.items()},
        'pure_read_profile': 'application bytes across two reopens; all durable artifacts across reads',
        'downgrade_ledger_exception': 'historical reopen may reseal ledger; application snapshot and journal must not change',
        'storage_failure_covered': False,
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
