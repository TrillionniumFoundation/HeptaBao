#!/usr/bin/env python3
"""Only synthetic values and pure source-bound selector/classifier branches."""
import copy
import hashlib
import json
from pathlib import Path
import struct

import mac_codex_backend_procargs_r1 as selectors
import mac_codex_candidate_backend_r1 as core

HERE = Path(__file__).resolve().parent
NAMES = ('mac_codex_backend_procargs_r1.py', 'mac_codex_candidate_backend_r1.py')
pins = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in NAMES}
cases = []
owners = [{'profileId': 'fixture-profile-' + str(i), 'credential': {
    'type': 'oauth', 'provider': 'openai', 'refresh': 'synthetic-refresh-' + str(i),
    'accountId': 'synthetic-account-' + str(i)}} for i in range(3)]


def need(value):
    if not value:
        raise AssertionError('synthetic_candidate_case_failed')


def refused(fn):
    try:
        fn()
    except (selectors.SelectorRefused, core.CandidateRefused):
        return
    raise AssertionError('expected_candidate_refusal')


def proc(args=(), env=(b'HOME=/Users/qianqi',)):
    argv = [b'/synthetic/codex', *args]
    raw = struct.pack('=i', len(argv)) + b'/synthetic/codex\0\0' + b'\0'.join(argv) + b'\0'
    raw += b'\0'.join(env) + b'\0\0'
    return selectors.parse_procargs(raw)


def test(name, fn):
    fn()
    cases.append({'name': name, 'passed': True})


def source_key():
    selected = proc((b'-c', b'cli_auth_credentials_store="file"'))
    need(selected['private']['storageModeOverride'] == 'file')
    need(selected['public']['otherConfigurationOverrides'] == 0)
    need(core.fixed_candidate_paths(selected) == (
        '/Users/qianqi/.codex/config.toml', '/Users/qianqi/.codex/auth.json'))


def wrong_key():
    selected = proc((b'-c', b'cli_auth_credentials_store_mode="file"'))
    need(selected['private']['storageModeOverride'] is None)
    need(selected['public']['otherConfigurationOverrides'] == 1)


def config_view():
    report = core.configuration_view(b'cli_auth_credentials_store = "auto"\n', proc())
    need(report['candidateModeIgnoringUnobservedLayers'] == 'auto')
    need(not report['effectiveBackendQualified'] and not report['systemManagedProjectAndRuntimeLayersBound'])
    default = core.configuration_view(None, proc())
    need(default['candidateModeIgnoringUnobservedLayers'] == 'file' and not default['effectiveBackendQualified'])


def nested_profile():
    selected = proc((b'--profile', b'fixture'))
    report = core.configuration_view(b'[profiles.fixture]\ncli_auth_credentials_store="keyring"\n', selected)
    need(report['unrecognizedNestedAuthStoreDeclaration'])
    need(report['candidateModeIgnoringUnobservedLayers'] == 'file' and not report['effectiveBackendQualified'])


def shared_candidate():
    report = core.compare_candidate_auth(json.dumps({'tokens': {'refresh_token': 'synthetic-refresh-1',
        'account_id': 'synthetic-account-1'}}).encode(), owners)
    need(report['private']['matchedOwnerOrdinals'] == [1])
    need(report['public']['candidateFileRelation'] == 'shared-candidate-refresh')
    need(report['public']['matchingSelectedOwnerCount'] == 1)
    public = json.dumps(report['public'])
    need('fixture-profile' not in public and 'synthetic-refresh' not in public and 'synthetic-account' not in public)
    need(not report['public']['productionRefreshAdmission'])


def different_candidate():
    report = core.compare_candidate_auth(b'{"tokens":{"refresh_token":"synthetic-other"}}', owners)['public']
    need(report['candidateFileRelation'] == 'different-candidate-refresh')
    need(report['runningCachedCredentialRelation'] == 'unknown')
    need(not report['effectiveBackendQualified'] and not report['productionRefreshAdmission'])


def absent_candidate():
    for raw in (None, b'{}', b'{"tokens":{"refresh_token":""}}'):
        report = core.compare_candidate_auth(raw, owners)['public']
        need(not report['storedRefreshFieldPresent'] and not report['allSelectedOwnerValuesCompared'])
        need(report['runningCachedCredentialRelation'] == 'unknown' and not report['productionRefreshAdmission'])


def duplicate_owner():
    values = copy.deepcopy(owners)
    values[2]['credential']['refresh'] = values[0]['credential']['refresh']
    refused(lambda: core.compare_candidate_auth(b'{}', values))


def empty_owner():
    values = copy.deepcopy(owners); values[1]['credential']['refresh'] = ''
    refused(lambda: core.compare_candidate_auth(b'{}', values))


test('C01_exact_actual_configuration_key', source_key)
test('C02_old_internal_field_spelling_remains_unknown', wrong_key)
test('C03_duplicate_storage_selector_refused', lambda: refused(lambda: proc((
    b'-c', b'cli_auth_credentials_store="file"', b'-c', b'cli_auth_credentials_store="auto"'))))
test('C04_profile_v2_does_not_open_default_configuration', lambda: refused(lambda:
    core.fixed_candidate_paths(proc((b'--profile-v2=fixture',)))))
test('C05_missing_environment_never_becomes_default_home', lambda: refused(lambda:
    core.fixed_candidate_paths(proc(env=()))))
test('C06_candidate_configuration_is_not_runtime_backend', config_view)
test('C07_invalid_storage_mode_type_refused', lambda: refused(lambda:
    core.configuration_view(b'cli_auth_credentials_store = true\n', proc())))
test('C08_legacy_profile_key_not_promoted_to_root_mode', nested_profile)
test('C09_private_exact_shared_refresh_relation', shared_candidate)
test('C10_file_inequality_does_not_exclude_cached_shared_auth', different_candidate)
test('C11_absence_and_empty_refresh_do_not_grant_admission', absent_candidate)
test('C12_duplicate_json_key_refused', lambda: refused(lambda:
    core.compare_candidate_auth(b'{"tokens":{},"tokens":{}}', owners)))
test('C13_duplicate_selected_refresh_object_refused', duplicate_owner)
test('C14_missing_selected_owner_refresh_refused', empty_owner)
test('C15_malformed_auth_tokens_shape_refused', lambda: refused(lambda:
    core.compare_candidate_auth(b'{"tokens":[]}', owners)))
test('C16_new_home_or_codex_override_outside_fixed_read_scope', lambda: refused(lambda:
    core.fixed_candidate_paths(proc(env=(b'HOME=/Users/qianqi', b'CODEX_HOME=/synthetic/other')))))
need(pins == {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in NAMES})
report = {'schema': 'heptabao.codex-candidate-backend-pure-qualification.r1', 'ok': True,
    'passed': len(cases), 'expected': 16, 'cases': cases, 'sourcePinsBeforeAndAfterExact': pins,
    'syntheticValuesOnly': True, 'actualAuthFilesRead': 0, 'actualProcessesObserved': 0,
    'actualProviderCalls': 0, 'effectiveRuntimeBackendQualified': False,
    'allFiniteConsumersQuiescenceQualified': False, 'productionRefreshAdmission': False}
(HERE / 'codex-candidate-backend-local-r1.result.public.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
