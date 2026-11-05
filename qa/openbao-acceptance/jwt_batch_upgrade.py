#!/usr/bin/env python3
"""Real schema43 -> 44 ordinary JWT batch/alias upgrade, three private stores."""
from __future__ import annotations
import importlib
import json
from pathlib import Path
import re
import shutil
import signal
import tempfile
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from online_evidence import admit_output, complete_checks, source_identity
from provider_renewal_upgrade import durable_manifest
from remote_jwks_live import signing_key, token as sign_token
from userpass_password_live import private_parent, safe_files
from userpass_batch_upgrade import Trace, initialize, make_instance, restart
from approle_token_cidrs_live import complete as legacy_complete, calibrated_rows as legacy_calibration

LEGACY_SOURCE = '3588f54f038d2c35ac145d2410ae497777db2201'
LEGACY_SHA256 = '8f95452e7e06b0dc97de2b2f67deeac88a16a292e3255813c7de1eb947965147'
LEGACY_RECEIPT = ROOT/'qa/openbao-acceptance/evidence/approle-token-cidrs-live-3588f54.json'
LEGACY_RECEIPT_SHA256 = '8e3da4de8ae19888ffdf121ce3d20ae6de2cb4390dcf779e94cd84cc2caa6caf'
MODES = ('role', 'mount', 'alias')
MOUNT, ROLE, POLICY = 'jwt-upgrade', 'preserved', 'jwt-upgrade-read'
ISSUER, SUBJECT = 'https://jwt-upgrade.invalid', 'synthetic-upgrade-subject'
CUSTOM = {'qa': 'preserved-custom-metadata'}
ROLE_PATH = 'auth/'+MOUNT+'/role/'+ROLE
LOGIN_PATH = 'auth/'+MOUNT+'/login'
REQUIRED = frozenset({'complete', 'processes_stopped'}) | frozenset(
    mode+'_'+case for mode in MODES for case in (
        'legacy_role_type_absent', 'legacy_metadata_empty', 'legacy_service_shape',
        'pure_application_unchanged', 'pure_reads_unchanged',
        'pure_restart_application_unchanged', 'pure_restart_reads_unchanged',
        'old_read_control', 'first_mutation_status', 'first_downgrade_unseal_status',
        'first_downgrade_application_unchanged', 'secrets_absent')) | frozenset(
    mode+'_'+phase+'_'+case for mode in MODES for phase in ('pure', 'pure_restart')
    for case in ('role_preserved', 'alias_preserved', 'embedded_alias_preserved',
                 'service_preserved', 'read_value')) | frozenset(
    mode+'_'+case for mode in ('role', 'mount') for case in (
        'converted_role_shape', 'old_after_conversion_preserved', 'batch_shape', 'batch_metadata',
        'reused_shape', 'reused_same_identity_distinct_token', 'new_alias_custom_preserved',
        'self_renew_old_shape', 'token_renew_old_shape', 'accessor_renew_old_shape',
        'old_renewed_lifetime_bound', 'deleted_role_batch_value', 'disabled_mount_batch_value',
        'restart_batch_lookup_shape', 'restart_batch_metadata', 'restart_batch_value')) | frozenset((
        'alias_first_login_metadata', 'alias_untouched_role_type', 'alias_untouched_mount_type',
        'alias_deleted_mount_status', 'alias_retained_downgrade_unseal_status',
        'alias_retained_downgrade_application_unchanged', 'alias_retained_metadata',
        'alias_retained_custom_metadata', 'alias_recovered_metadata'))


def complete(rows):
    if not isinstance(rows, list) or any(not isinstance(row, dict)
        or set(row)-{'case', 'passed', 'status'}
        or 'status' in row and (type(row['status']) is not int or not 100 <= row['status'] <= 599)
        for row in rows): return False
    return (complete_checks([{'case': r.get('case'), 'passed': r.get('passed')} for r in rows],
                            required_cases=REQUIRED) and rows[-1]['case'] == 'complete')


def admit_legacy(receipt, digest):
    before, sides = receipt.get('candidate_source') or {}, receipt.get('cases') or {}
    finished = receipt.get('completed_scenarios') or {}
    expected = legacy_calibration()
    if (digest != LEGACY_RECEIPT_SHA256 or receipt.get('schema') != 'heptabao.approle-token-cidrs-comparison.v1'
        or receipt.get('status') != 'passed' or receipt.get('build_source_commit') != LEGACY_SOURCE
        or before.get('source_commit') != LEGACY_SOURCE or before.get('binary_sha256') != LEGACY_SHA256
        or before.get('source_dirty') is not False or receipt.get('candidate_source_after') != before
        or receipt.get('oracle_only') is not False or receipt.get('failures')
        or set(sides) != {'candidate', 'oracle'} or set(finished) != set(sides)
        or not all(legacy_complete(sides[s], finished[s], expected) for s in sides)
        or receipt.get('calibrated_cases_match') != {'candidate': True, 'oracle': True}
        or receipt.get('secrets_absent') != {'candidate': True, 'oracle': True}
        or any(receipt.get(k) is not True for k in ('source_and_binary_unchanged', 'cases_match',
            'inputs_unchanged', 'oracle_binary_unchanged'))):
        raise ValueError('qualified_schema43_binary_receipt_required')


def retained_role(current, previous):
    if not isinstance(current, dict) or not isinstance(previous, dict) or 'token_type' in previous: return False
    current = dict(current)
    return current.pop('token_type', None) == 'default' and current == previous


def retained_service(current, previous):
    if not isinstance(current, dict) or not isinstance(previous, dict) or 'meta' in previous: return False
    current, previous = dict(current), dict(previous)
    ttl, old_ttl = current.pop('ttl', None), previous.pop('ttl', None)
    return (type(ttl) is int and ttl > 0 and type(old_ttl) is int and old_ttl > 0
            and current.pop('meta', None) == {'role': ROLE} and current == previous)


def login(t, name, old, kind):
    return t.issued(name, t.call(name+'_request', 'POST', LOGIN_PATH,
        {'role': ROLE, 'jwt': old['assertion']}, token=''), kind)


def read_alias(t, name, old):
    return t.call(name, 'GET', 'identity/entity-alias/id/'+old['alias']['id'])['data']


def embedded_alias(t, name, old):
    entity = t.call(name, 'GET', 'identity/entity/id/'+old['auth']['entity_id'])['data']
    values = [a for a in entity.get('aliases', []) if a.get('id') == old['alias']['id']]
    t.check(name+'_one_alias', len(values) == 1)
    return values[0]


def seed(instance, rows, mode):
    t, key = initialize(instance, rows, mode+'_legacy')
    t.call(mode+'_policy', 'PUT', 'sys/policies/acl/'+POLICY, {'policy':
        'path "secret/data/upgrade" { capabilities=["read"] }'}, status=204)
    t.call(mode+'_value', 'POST', 'secret/data/upgrade', {'data': {'value': 'synthetic-upgrade-value'}})
    t.call(mode+'_mount', 'POST', 'sys/auth/'+MOUNT, {'type': 'jwt'}, status=204)
    t.call(mode+'_tune', 'POST', 'sys/auth/'+MOUNT+'/tune',
        {'default_lease_ttl': 900, 'max_lease_ttl': 1800}, status=204)
    private, jwk = signing_key('ES256', 'jwt-upgrade-key')
    t.call(mode+'_config', 'POST', 'auth/'+MOUNT+'/config',
        {'issuer': ISSUER, 'audiences': ['heptabao-test'], 'jwks': {'keys': [jwk]}}, status=204)
    t.call(mode+'_role', 'POST', ROLE_PATH, {'role_type': 'jwt', 'user_claim': 'sub',
        'bound_audiences': ['heptabao-test'], 'token_policies': [POLICY], 'token_ttl': 900,
        'token_max_ttl': 1800, 'token_explicit_max_ttl': 1200}, status=204)
    role = t.call(mode+'_legacy_role', 'GET', ROLE_PATH)['data']
    t.check(mode+'_legacy_role_type_absent', 'token_type' not in role)
    assertion = sign_token(private, jwk, ISSUER, sub=SUBJECT, exp=int(time.time())+1800)
    t.sensitive.append(assertion)
    old = {'assertion': assertion, 'role': role}
    auth = login(t, mode+'_legacy_service', old, 'service'); old['auth'] = auth
    old['token'] = t.lookup(mode+'_legacy_lookup', auth, 'service')
    t.check(mode+'_legacy_cap', old['token'].get('explicit_max_ttl') == 1200)
    t.check(mode+'_legacy_token_meta_absent', 'meta' not in old['token'])
    entity = t.call(mode+'_legacy_entity', 'GET', 'identity/entity/id/'+auth['entity_id'])['data']
    aliases = [a for a in entity.get('aliases', []) if a.get('name') == SUBJECT]
    t.check(mode+'_legacy_single_alias', len(aliases) == 1)
    alias = aliases[0]
    t.call(mode+'_legacy_custom', 'POST', 'identity/entity-alias/id/'+alias['id'],
        {'name': SUBJECT, 'canonical_id': auth['entity_id'], 'mount_accessor': alias['mount_accessor'],
         'custom_metadata': CUSTOM})
    old['alias'] = t.call(mode+'_legacy_alias', 'GET', 'identity/entity-alias/id/'+alias['id'])['data']
    t.check(mode+'_legacy_metadata_empty', old['alias'].get('metadata') == {} and old['alias'].get('custom_metadata') == CUSTOM)
    return t, key, old


def pure_reads(instance, candidate, legacy, t, key, old, mode):
    store = instance.root/'data'; instance.stop()
    original = durable_manifest(store, application_only=True)
    for phase in ('pure', 'pure_restart'):
        prefix = mode+'_'+phase
        restart(instance, candidate, t, key, prefix)
        t.check(prefix+'_application_unchanged', durable_manifest(store, application_only=True) == original)
        before = durable_manifest(store)
        t.check(prefix+'_role_preserved', retained_role(t.call(prefix+'_role', 'GET', ROLE_PATH)['data'], old['role']))
        t.check(prefix+'_alias_preserved', read_alias(t, prefix+'_alias', old) == old['alias'])
        t.check(prefix+'_embedded_alias_preserved', embedded_alias(t, prefix+'_entity', old) == old['alias'])
        t.check(prefix+'_service_preserved', retained_service(t.lookup(prefix+'_service', old['auth'], 'service'), old['token']))
        t.value(prefix+'_read', old['auth'])
        t.check(prefix+'_reads_unchanged', durable_manifest(store) == before)
    restart(instance, legacy, t, key, mode+'_old_control')
    t.lookup(mode+'_old_control_service', old['auth'], 'service')
    t.check(mode+'_old_read_control', durable_manifest(store, application_only=True) == original)
    restart(instance, candidate, t, key, mode+'_before_first_mutation')


def first_mutation(t, mode, old):
    """Exactly one candidate mutation; immediately followed by the old-reader test."""
    name = mode+'_first_mutation'
    if mode == 'role':
        t.call(name, 'POST', ROLE_PATH, {'role_type': 'jwt', 'token_type': 'batch'}, status=204)
    elif mode == 'mount':
        t.call(name, 'POST', 'sys/auth/'+MOUNT+'/tune', {'token_type': 'batch'}, status=204)
    elif mode == 'alias':
        body = t.call(name, 'POST', LOGIN_PATH, {'role': ROLE, 'jwt': old['assertion']}, token='')
        auth = t.issued('alias_first_login', body, 'service')
        t.check('alias_first_login_metadata', auth.get('metadata') == {'role': ROLE})
    else: raise ValueError('unknown_upgrade_mode')


def downgrade(instance, candidate, legacy, t, key, prefix):
    instance.stop(); before = durable_manifest(instance.root/'data', application_only=True)
    instance.binary = legacy; instance.start()
    t.call(prefix+'_downgrade_unseal', 'POST', 'sys/unseal', {'key': key}, status=503)
    t.call(prefix+'_downgrade_health', 'GET', 'sys/health', status=503)
    instance.stop()
    t.check(prefix+'_downgrade_application_unchanged', durable_manifest(instance.root/'data', application_only=True) == before)
    restart(instance, candidate, t, key, prefix+'_recover')


def renewable_old(t, old, mode):
    for via, body, actor, suffix in (
        ('self', {}, old['auth']['client_token'], 'renew-self'),
        ('token', {'token': old['auth']['client_token']}, None, 'renew'),
        ('accessor', {'accessor': old['auth']['accessor']}, None, 'renew-accessor')):
        result = t.call(mode+'_'+via+'_renew', 'POST', 'auth/token/'+suffix,
                        dict(body, increment=600), token=actor)
        auth = result.get('auth') or {}
        t.check(mode+'_'+via+'_renew_old_shape', auth.get('token_type') == 'service'
            and auth.get('renewable') is True and type(auth.get('lease_duration')) is int
            and auth.get('metadata') == {'role': ROLE} and auth.get('orphan') is True
            and 0 < auth['lease_duration'] <= 600
            and (auth.get('client_token') == old['auth']['client_token'] if via != 'accessor'
                 else auth.get('client_token') in ('', None)))
    current = t.lookup(mode+'_old_renewed', old['auth'], 'service')
    t.check(mode+'_old_renewed_lifetime_bound', current.get('creation_time') == old['token']['creation_time']
        and current.get('explicit_max_ttl') == 1200
        and current.get('display_name') == old['token']['display_name']
        and type(current.get('expire_time_unix')) is int
        and current['creation_time'] < current['expire_time_unix'] <= current['creation_time']+1200)


def retained_alias_only(instance, candidate, legacy, t, key, old):
    role = t.call('alias_unmodified_role', 'GET', ROLE_PATH)['data']
    t.check('alias_untouched_role_type', retained_role(role, old['role']))
    mount = t.call('alias_unmodified_mount', 'GET', 'sys/auth/'+MOUNT+'/tune')['data']
    t.check('alias_untouched_mount_type', mount.get('token_type') == 'default-service')
    # No explicit JWT role/mount type was ever written in this store. Deleting
    # the mount leaves its backend alias metadata as the independent new shape.
    t.call('alias_deleted_mount', 'DELETE', 'sys/auth/'+MOUNT, status=204)
    alias = read_alias(t, 'alias_retained_read', old)
    t.check('alias_retained_metadata', alias.get('metadata') == {'role': ROLE})
    t.check('alias_retained_custom_metadata', alias.get('custom_metadata') == CUSTOM)
    downgrade(instance, candidate, legacy, t, key, 'alias_retained')
    t.check('alias_recovered_metadata', read_alias(t, 'alias_recovered_read', old) == alias)


def run_store(instance, candidate, legacy, rows, mode):
    t, key, old = seed(instance, rows, mode)
    pure_reads(instance, candidate, legacy, t, key, old, mode)
    first_mutation(t, mode, old)
    downgrade(instance, candidate, legacy, t, key, mode+'_first')
    if mode == 'alias':
        retained_alias_only(instance, candidate, legacy, t, key, old)
    else:
        role = t.call(mode+'_converted_role', 'GET', ROLE_PATH)['data']
        wanted = dict(old['role'], token_type='batch' if mode == 'role' else 'default')
        t.check(mode+'_converted_role_shape', role == wanted)
        t.check(mode+'_old_after_conversion_preserved', retained_service(
            t.lookup(mode+'_old_after_conversion', old['auth'], 'service'), old['token']))
        renewable_old(t, old, mode)
        batch = login(t, mode+'_batch', old, 'batch')
        t.check(mode+'_batch_metadata', batch.get('metadata') == {'role': ROLE} and batch.get('orphan') is True)
        again = login(t, mode+'_reused', old, 'batch')
        t.check(mode+'_reused_same_identity_distinct_token', batch.get('entity_id') == old['auth']['entity_id']
            and again.get('entity_id') == batch.get('entity_id') and again['client_token'] != batch['client_token'])
        alias = read_alias(t, mode+'_new_alias', old)
        t.check(mode+'_new_alias_custom_preserved', alias.get('custom_metadata') == CUSTOM
                and alias.get('metadata') == {'role': ROLE})
        t.lookup(mode+'_batch_lookup', batch, 'batch'); t.value(mode+'_batch', batch)
        t.call(mode+'_batch_renew', 'POST', 'auth/token/renew-self', {}, token=batch['client_token'], status=400)
        t.call(mode+'_delete_role', 'DELETE', ROLE_PATH, status=204)
        t.value(mode+'_deleted_role_batch', batch)
        t.call(mode+'_disable_mount', 'DELETE', 'sys/auth/'+MOUNT, status=204)
        t.value(mode+'_disabled_mount_batch', batch)
        restart(instance, candidate, t, key, mode+'_restart')
        reopened = t.lookup(mode+'_restart_batch_lookup', batch, 'batch')
        t.check(mode+'_restart_batch_metadata', reopened.get('meta') == {'role': ROLE}
            and reopened.get('display_name') == MOUNT+'-'+SUBJECT
            and reopened.get('entity_id') == old['auth']['entity_id'])
        t.value(mode+'_restart_batch', batch)
    instance.stop()
    t.check(mode+'_secrets_absent', safe_files(instance.root, t.sensitive))


def helpers():
    names = ('bao_http', 'heptabao.transport', 'core_isolation', 'identity_upgrade', 'online_evidence',
        'provider_renewal_upgrade', 'remote_jwks_live', 'external_tls_fixtures', 'smoke',
        'userpass_password_live', 'userpass_batch_upgrade', 'approle_token_cidrs_live', 'approle_token_cidrs_probe')
    result = {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}
    result['legacy_calibration'] = file_hash(ROOT/'qa/openbao-acceptance/evidence/approle-token-cidrs-official-c2df6af.json')
    return result


def main():
    p = SafeArgumentParser(description=__doc__)
    for name in ('binary', 'legacy-binary', 'work-parent', 'output'): p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--build-source-commit', required=True); p.add_argument('--expected-binary-sha256', required=True)
    args = p.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.build_source_commit) or not re.fullmatch('[0-9a-f]{64}', args.expected_binary_sha256):
        p.error('candidate_pins_required')
    candidate, legacy = args.binary.resolve(strict=True), args.legacy_binary.resolve(strict=True)
    actual, legacy_hash = validate_binary_pins(candidate, legacy, LEGACY_SHA256)
    if actual != args.expected_binary_sha256: p.error('candidate_binary_mismatch')
    admit_legacy(json.loads(LEGACY_RECEIPT.read_text()), file_hash(LEGACY_RECEIPT))
    output = args.output.absolute(); admitted = admit_output(output)
    before, runner, helper = source_identity(ROOT, candidate), file_hash(Path(__file__)), helpers()
    work = Path(tempfile.mkdtemp(prefix='jwt-batch-upgrade-', dir=private_parent(args.work_parent)))
    rows, instances, failure = [], [], None
    def interrupted(signum, frame): raise ScenarioFailure('interrupted')
    signals = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for mode in MODES:
            instance = make_instance(legacy, work/mode); instances.append(instance)
            run_store(instance, candidate, legacy, rows, mode)
    except Exception as error:
        failure = next((r['case'] for r in reversed(rows) if r['passed'] is not True), 'fixture_'+type(error).__name__)
    finally:
        try:
            for instance in instances:
                try: instance.stop()
                except Exception: failure = failure or 'cleanup_failed'
        finally:
            for sig, handler in signals.items(): signal.signal(sig, handler)
    stopped = all(instance.process is None for instance in instances)
    rows.append({'case': 'processes_stopped', 'passed': stopped})
    if not stopped: failure = failure or 'cleanup_failed'
    if failure is None: Trace(instances[-1], rows).check('complete', True)
    after = source_identity(ROOT, candidate)
    unchanged = before == after and file_hash(legacy) == legacy_hash
    runner_ok, helper_ok = file_hash(Path(__file__)) == runner, helpers() == helper
    if not unchanged or not runner_ok or not helper_ok or file_hash(LEGACY_RECEIPT) != LEGACY_RECEIPT_SHA256:
        failure = 'source_binary_or_helpers_changed'
    if before['source_dirty'] or after['source_dirty']: failure = 'source_dirty'
    if not complete(rows): failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.jwt-batch-upgrade.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': rows, 'source_identity': before, 'source_identity_after': after,
        'source_and_binary_unchanged': unchanged, 'build_source_commit': args.build_source_commit,
        'runner_sha256': runner, 'runner_unchanged': runner_ok, 'helper_sha256': helper, 'helpers_unchanged': helper_ok,
        'legacy_source_commit': LEGACY_SOURCE, 'legacy_binary_sha256': legacy_hash,
        'legacy_receipt_sha256': LEGACY_RECEIPT_SHA256, 'from_schema': 43, 'minimum_to_schema': 44,
        'credential_storage_fabricated': False, 'mutating_requests_retried': False,
        'first_mutations': ['jwt_role_type', 'jwt_mount_type', 'jwt_login_alias_metadata_without_type_configuration'],
        'retained_alias_after_mount_deletion': True,
        'pure_read_profile': 'three actual old stores without dynamic leases; no maintenance clock ambiguity',
        'allowed_readback_additions': ['role.token_type=default', 'old_JWT_lookup.meta.role'],
        'downgrade_ledger_exception': 'historical reopen may reseal ledger; application artifacts must not change',
        'retained_failure_work_dir': str(work) if failure else None, 'synthetic_only': True,
        'HA_covered': False, 'remote_JWKS_covered': False, 'OIDC_covered': False,
        'openbao_state_interoperability': False, 'full_openbao_compatibility': False,
        'independent_qualification': False, 'production_authority': False}
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    if failure is None: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return int(failure is not None)


if __name__ == '__main__': raise SystemExit(main())
