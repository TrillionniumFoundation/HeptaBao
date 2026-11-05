#!/usr/bin/env python3
"""Three actual schema46 stores: first API writes, upgrade and old-reader refusal."""
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
from online_evidence import admit_output, source_identity, complete_checks
from provider_renewal_upgrade import durable_manifest
from userpass_password_live import private_parent, safe_files
from userpass_batch_upgrade import initialize, make_instance, restart
import approle_secret_cidrs_upgrade as previous
import approle_secretid_overrides_live as legacy_comparison

ROLE = 'auth/approle/role/preserved'
POLICY = 'secretid-metadata-upgrade'
PROFILES = ('metadata_empty', 'metadata_nonempty', 'legacy_login')
RAW = {'role_name': 'spoofed', 'env': 'one'}
EFFECTIVE = {'role_name': 'preserved', 'env': 'one'}
SECOND = {'role_name': 'preserved', 'env': 'two'}
HISTORICAL = {'role_name': 'preserved'}
CUSTOM = {'owner': 'control'}
REQUIRED = frozenset({'processes_stopped', 'complete'}) | frozenset(
    p+'_'+case for p in PROFILES for case in (
        'pure_application_unchanged', 'pure_reads_unchanged', 'pure_sid_exact',
        'pure_restart_application_unchanged', 'pure_restart_reads_unchanged', 'pure_restart_sid_exact',
        'old_reader_control', 'downgrade_unseal_status', 'downgrade_health_status',
        'downgrade_application_unchanged', 'first_shape', 'old_sid_exact',
        'raw_role_name_preserved', 'same_entity', 'alias_backend_snapshot', 'alias_custom_preserved',
        'deleted_sid_status', 'old_sid_final_exact', 'restart_alias_backend_snapshot',
        'restart_alias_custom_preserved', 'secrets_absent')) | frozenset(
    p+'_'+phase+'_'+token+'_'+via+'_snapshot' for p in PROFILES
    for phase in ('after_delete', 'after_restart') for token in ('original', 'legacy')
    for via in ('self', 'token', 'accessor'))


class Trace(previous.Trace):
    def check(self, name, condition, **kwargs):
        if any(r['case'] == name for r in self.rows): raise ScenarioFailure('duplicate_observation')
        super().check(name, condition, **kwargs)


def complete(rows):
    if not isinstance(rows, list) or any(not isinstance(r, dict) or set(r)-{'case','passed','status'}
        or 'status' in r and (type(r['status']) is not int or not 100 <= r['status'] <= 599) for r in rows): return False
    return (complete_checks([{'case': r.get('case'), 'passed': r.get('passed')} for r in rows], required_cases=REQUIRED)
        and rows[-1]['case'] == 'complete')


def admit_legacy(receipt, actual_digest, expected_digest, source, binary_hash):
    if (not re.fullmatch('[0-9a-f]{40}', source) or not re.fullmatch('[0-9a-f]{64}', binary_hash)
        or not re.fullmatch('[0-9a-f]{64}', expected_digest) or actual_digest != expected_digest):
        raise ValueError('legacy_identity_pins_required')
    before = receipt.get('candidate_source') or {}; sides = receipt.get('cases') or {}
    phases = receipt.get('completed_scenarios') or {}; expected = legacy_comparison.calibrated_rows()
    if (receipt.get('schema') != 'heptabao.approle-secretid-overrides-comparison.v1'
        or receipt.get('status') != 'passed' or receipt.get('build_source_commit') != source
        or before.get('binary_sha256') != binary_hash or before.get('source_dirty') is not False
        or not re.fullmatch('[0-9a-f]{40}', before.get('source_commit', ''))
        or receipt.get('candidate_source_after') != before
        or receipt.get('oracle_only') is not False or receipt.get('target_version') != '2.6.2'
        or receipt.get('failures') or set(sides) != {'candidate', 'oracle'} or set(phases) != set(sides)
        or not all(legacy_comparison.complete(sides[s], phases[s], expected) for s in sides)
        or receipt.get('calibrated_cases_match') != {'candidate': True, 'oracle': True}
        or receipt.get('secrets_absent') != {'candidate': True, 'oracle': True}
        or any(receipt.get(k) is not True for k in ('processes_stopped', 'source_and_binary_unchanged',
            'cases_match', 'inputs_unchanged', 'oracle_binary_unchanged'))):
        raise ValueError('qualified_schema46_overrides_receipt_required')


def issue(t, name, rid, fields):
    data = t.call(name, 'POST', ROLE+'/secret-id', fields)['data']
    return {'role_id': rid, 'secret_id': data['secret_id']}


def sid(t, name, creds):
    return t.call(name, 'POST', ROLE+'/secret-id/lookup', {'secret_id': creds['secret_id']})['data']


def login(t, name, creds, metadata):
    auth = t.issued(name, t.call(name+'_request', 'POST', 'auth/approle/login', creds, token=''), 'service')
    t.check(name+'_metadata', auth.get('metadata') == metadata)
    return auth


def inspect_token(t, name, auth, metadata):
    data = t.lookup(name, auth, 'service')
    t.check(name+'_metadata', data.get('meta') == metadata)
    t.value(name+'_bearer', auth)


def read_alias(t, name, entity, rid):
    data = t.call(name+'_entity', 'GET', 'identity/entity/id/'+entity)['data']
    aliases = [a for a in data.get('aliases', []) if a.get('name') == rid]
    t.check(name+'_unique', len(aliases) == 1)
    alias = t.call(name+'_read', 'GET', 'identity/entity-alias/id/'+aliases[0]['id'])['data']
    t.sensitive.extend(v for v in (entity, alias.get('id')) if isinstance(v, str) and v)
    return alias


def renew(t, name, auth, expected):
    for via, path, body, actor in (
        ('self', 'auth/token/renew-self', {'increment': 900}, auth['client_token']),
        ('token', 'auth/token/renew', {'token': auth['client_token'], 'increment': 900}, None),
        ('accessor', 'auth/token/renew-accessor', {'accessor': auth['accessor'], 'increment': 900}, None)):
        response = t.call(name+'_'+via, 'POST', path, body, token=actor).get('auth') or {}
        t.check(name+'_'+via+'_snapshot', response.get('metadata') == expected
            and (response.get('client_token') in (None, '') if via == 'accessor' else response.get('client_token') == auth['client_token'])
            and type(response.get('lease_duration')) is int and response['lease_duration'] > 0)


def seed(instance, rows, profile):
    base, key = initialize(instance, rows, profile+'_legacy')
    t = Trace(instance, rows); t.sensitive = base.sensitive
    t.call(profile+'_policy', 'PUT', 'sys/policies/acl/'+POLICY,
        {'policy': 'path "secret/data/upgrade" { capabilities=["read"] }'}, status=204)
    t.call(profile+'_value', 'POST', 'secret/data/upgrade', {'data': previous.VALUE})
    t.call(profile+'_role', 'POST', ROLE, {'token_type': 'service', 'token_ttl': 900,
        'token_max_ttl': 1200, 'token_policies': [POLICY], 'secret_id_num_uses': 0,
        'secret_id_ttl': 1800}, status=204)
    rid = t.call(profile+'_roleid', 'GET', ROLE+'/role-id')['data']['role_id']
    old = issue(t, profile+'_old_sid', rid, {})
    auth = login(t, profile+'_old_login', old, HISTORICAL)
    raw = sid(t, profile+'_old_read', old)
    t.check(profile+'_old_metadata_empty', raw.get('metadata') == {})
    entity = auth.get('entity_id'); t.check(profile+'_old_entity', isinstance(entity, str) and bool(entity))
    alias = read_alias(t, profile+'_old_alias', entity, rid)
    t.call(profile+'_old_custom', 'POST', 'identity/entity-alias/id/'+alias['id'],
        {'name': rid, 'canonical_id': entity, 'mount_accessor': alias['mount_accessor'],
         'custom_metadata': CUSTOM}, status=200)
    alias = read_alias(t, profile+'_old_custom_read', entity, rid)
    return t, key, {'creds': old, 'auth': auth, 'sid': raw, 'rid': rid, 'entity': entity,
        'alias': alias, 'role': t.call(profile+'_old_role', 'GET', ROLE)['data']}


def first_write_and_downgrade(t, instance, candidate, legacy, key, profile, saved):
    # Deliberately no setup mutation between current reopen and this operation.
    if profile == 'legacy_login':
        first = login(t, profile+'_first_login', saved['creds'], HISTORICAL)
    elif profile in ('metadata_empty', 'metadata_nonempty'):
        first = issue(t, profile+'_first_issue', saved['rid'],
            {'metadata': json.dumps({} if profile == 'metadata_empty' else RAW)})
    else: raise ScenarioFailure('unknown_first_write_profile')
    # The very next state-changing interaction is the genuine old-reader open.
    previous.downgrade(instance, candidate, legacy, t, key, profile)
    return first


def run_store(instance, candidate, legacy, rows, profile, sensitive):
    t, key, saved = seed(instance, rows, profile); sensitive.append(t.sensitive)
    store = instance.root/'data'; instance.stop(); original = durable_manifest(store, application_only=True)
    for phase in ('pure', 'pure_restart'):
        name = profile+'_'+phase; restart(instance, candidate, t, key, name)
        t.check(name+'_application_unchanged', durable_manifest(store, application_only=True) == original)
        before = durable_manifest(store)
        t.check(name+'_role_exact', t.call(name+'_role', 'GET', ROLE)['data'] == saved['role'])
        t.check(name+'_sid_exact', sid(t, name+'_sid', saved['creds']) == saved['sid'])
        inspect_token(t, name+'_old_token', saved['auth'], HISTORICAL)
        t.check(name+'_alias_exact', read_alias(t, name+'_alias', saved['entity'], saved['rid']) == saved['alias'])
        t.check(name+'_reads_unchanged', durable_manifest(store) == before)
    restart(instance, legacy, t, key, profile+'_old_control')
    inspect_token(t, profile+'_control_token', saved['auth'], HISTORICAL)
    t.check(profile+'_old_reader_control', durable_manifest(store, application_only=True) == original)
    restart(instance, candidate, t, key, profile+'_current')
    first = first_write_and_downgrade(t, instance, candidate, legacy, key, profile, saved)
    if profile == 'legacy_login':
        data = t.lookup(profile+'_first_read', first, 'service')
        t.check(profile+'_first_shape', data.get('meta') == HISTORICAL)
    else:
        data = sid(t, profile+'_first_read', first)
        t.check(profile+'_first_shape', data.get('metadata') == ({} if profile == 'metadata_empty' else RAW))
    t.check(profile+'_old_sid_exact', sid(t, profile+'_old_sid_after', saved['creds']) == saved['sid'])
    primary = first if profile == 'metadata_nonempty' else issue(t, profile+'_primary_issue', saved['rid'], {'metadata': json.dumps(RAW)})
    original_auth = login(t, profile+'_primary_login', primary, EFFECTIVE)
    t.check(profile+'_raw_role_name_preserved', sid(t, profile+'_raw_read', primary).get('metadata') == RAW)
    replacement = issue(t, profile+'_replacement_issue', saved['rid'], {'metadata': '{"env":"two"}'})
    replacement_auth = login(t, profile+'_replacement_login', replacement, SECOND)
    t.check(profile+'_same_entity', original_auth.get('entity_id') == replacement_auth.get('entity_id') == saved['entity'])
    alias = read_alias(t, profile+'_updated_alias', saved['entity'], saved['rid'])
    t.check(profile+'_alias_backend_snapshot', alias.get('metadata') == SECOND)
    t.check(profile+'_alias_custom_preserved', alias.get('custom_metadata') == CUSTOM)
    t.call(profile+'_delete_sid', 'POST', ROLE+'/secret-id/destroy', {'secret_id': primary['secret_id']}, status=204)
    t.call(profile+'_deleted_sid', 'POST', ROLE+'/secret-id/lookup', {'secret_id': primary['secret_id']}, status=204)
    t.call(profile+'_role_changed', 'POST', ROLE, {'token_ttl': 800}, status=204)
    for label, auth, expected in (('original', original_auth, EFFECTIVE), ('legacy', saved['auth'], HISTORICAL)):
        inspect_token(t, profile+'_after_delete_'+label, auth, expected)
        renew(t, profile+'_after_delete_'+label, auth, expected)
    restart(instance, candidate, t, key, profile+'_final_reopen')
    for label, auth, expected in (('original', original_auth, EFFECTIVE), ('legacy', saved['auth'], HISTORICAL)):
        inspect_token(t, profile+'_after_restart_'+label, auth, expected)
        renew(t, profile+'_after_restart_'+label, auth, expected)
    alias = read_alias(t, profile+'_restart_alias', saved['entity'], saved['rid'])
    t.check(profile+'_restart_alias_backend_snapshot', alias.get('metadata') == SECOND)
    t.check(profile+'_restart_alias_custom_preserved', alias.get('custom_metadata') == CUSTOM)
    t.check(profile+'_old_sid_final_exact', sid(t, profile+'_final_old_sid', saved['creds']) == saved['sid'])
    instance.stop(); t.check(profile+'_secrets_absent', safe_files(instance.root, t.sensitive))


def helpers():
    names = ('approle_secret_cidrs_upgrade', 'approle_secretid_overrides_live')
    return {**previous.helpers(), **{'legacy_'+k:v for k,v in legacy_comparison.inputs().items()},
        **{name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}}


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
    admit_legacy(json.loads(receipt.read_text()), receipt_hash, args.legacy_receipt_sha256,
                 args.legacy_build_source_commit, legacy_hash)
    output = args.output.absolute(); admitted = admit_output(output)
    before, runner, helper = source_identity(ROOT, candidate), file_hash(Path(__file__)), helpers()
    if before['source_dirty']: parser.error('clean_harness_required')
    work = Path(tempfile.mkdtemp(prefix='approle-secretid-metadata-upgrade-', dir=private_parent(args.work_parent)))
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
    report = {'schema': 'heptabao.approle-secretid-metadata-upgrade.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': rows, 'source_identity': before, 'source_identity_after': after,
        'source_and_binary_unchanged': unchanged, 'build_source_commit': args.build_source_commit,
        'runner_sha256': runner, 'runner_unchanged': runner_ok, 'helper_sha256': helper, 'helpers_unchanged': helper_ok,
        'legacy_source_commit': args.legacy_build_source_commit, 'legacy_binary_sha256': legacy_hash,
        'legacy_receipt_sha256': receipt_hash, 'from_schema': 46, 'minimum_to_schema': 47,
        'old_reader_actually_executed': all(any(r['case'] == p+'_downgrade_unseal_status' and type(r.get('status')) is int for r in rows) for p in PROFILES), 'credential_storage_fabricated': False,
        'mutating_requests_retried': False, 'first_mutations': list(PROFILES), 'first_write_profile': {'metadata_empty': 'random SID explicit {} metadata',
            'metadata_nonempty': 'random SID env/role_name raw metadata', 'legacy_login': 'old None SID service login writes both issued_metadata and alias backend role_name'},
        'pure_read_profile': 'application bytes across two reopens; all durable artifacts across reads',
        'downgrade_ledger_exception': 'historical reopen may reseal ledger; application snapshot and journal must not change',
        'independent_issued_metadata_gate_covered': False,
        'legacy_login_first_write_is_composite': True,
        'alias_only_gate_covered': False, 'extended_alias_only_gate_covered': False, 'internal_None_after_renew_proven_by_this_fixture': False,
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
