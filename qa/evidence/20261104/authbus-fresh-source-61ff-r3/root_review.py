#!/usr/bin/env python3
"""Verify two different provider-source outcomes; never turn evidence consistency into a provider pass."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
E = ROOT / 'evidence'
ORIGINAL = Path('/workspace/scratch/61ff8bef4cc9')
REMOTE = PurePosixPath('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-fresh-source-61ff8bef-r3')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def main():
    manifest_path = E / 'final-manifest.public.json'
    assert sha(manifest_path) == '64664718cbe70ca6d1c0f9edc91f287fa044d609c37ac1995d7957b73fe8f121'
    manifest = read(manifest_path)
    assert len(manifest['files']) == 27 and len(manifest['reviewerDependencies']) == 11
    for item in manifest['files']:
        path = ROOT / item['relative']
        assert path.stat().st_size == item['bytes'] and sha(path) == item['sha256']
    for item in manifest['reviewerDependencies']:
        relative = Path(item['path']).relative_to(ORIGINAL)
        path = ROOT.parent / relative
        assert path.stat().st_size == item['bytes'] and sha(path) == item['sha256']
    assert manifest['rawProviderBodiesIncluded'] is False and manifest['sourceCredentialValuesIncluded'] is False
    agent_path = E / 'agent-review.public.json'
    expected_agent = '20f8766308866064f7513b2187d2ec7702b6f9281ceefbeec63b7b59653d62fe'
    assert sha(agent_path) == expected_agent
    old_bytes = agent_path.read_bytes()
    execution = subprocess.run([sys.executable, str(ROOT / 'review_evidence.py')],
                               capture_output=True, text=True, check=True, timeout=30)
    assert not execution.stderr and agent_path.read_bytes() == old_bytes
    agent = read(agent_path)
    assert agent['checksPassed'] == agent['checksTotal'] == 98 and agent['evidenceConsistent']
    assert json.loads(execution.stdout)['sha256'] == expected_agent
    control_sdk = read(E / 'control-native-sdk-payload.public.json')
    assert control_sdk.get('isError') is not True
    native = json.loads(next(c['text'] for c in control_sdk['content'] if c['type'] == 'text'))
    assert native['truncated'] is False
    received = []
    for item in native['files']:
        relative = PurePosixPath(item['path']).relative_to(REMOTE)
        path = E / str(relative)
        raw = item['text'].encode()
        assert item['eof'] and len(raw) == item['size'] == path.stat().st_size
        assert hashlib.sha256(raw).hexdigest() == item['sha256'] == sha(path)
        assert raw == path.read_bytes()
        received.append(str(relative))
    assert set(received) == {'control/stage.public.json', 'control/managed1-r1.plan.json',
                             'control/native4-r1.plan.json', 'managed1-r1/intent.public.json',
                             'native4-r1/intent.public.json', 'import-probe-r1/result.public.json'}
    stage = read(E / 'control/stage.public.json')
    packet = read(ROOT / 'stage-input.json')
    pins = stage['pins']
    assert len(pins) == 15 and stage['providerCalled'] is False
    for name, source in packet['files'].items():
        assert source.encode() == (ROOT / name).read_bytes()
        assert hashlib.sha256(source.encode()).hexdigest() == packet['filePins'][name] == pins[str(REMOTE / 'control' / name)]
    for case in ('managed1-r1', 'native4-r1'):
        intent = read(E / case / 'intent.public.json')
        plan = read(E / 'control' / (case + '.plan.json'))
        assert intent['sourcePins'] == pins and intent['caseId'] == plan['caseId'] == case
        assert intent['sourceKind'] == plan['sourceKind']
        assert plan['work'] == str(REMOTE / case)
        assert pins[str(REMOTE / 'control' / (case + '.plan.json'))] == sha(E / 'control' / (case + '.plan.json'))
        assert plan['helperSha256'] == sha(ROOT / 'fresh_usage_read.mjs')
        assert intent['argv'][:4] == ['/usr/bin/bwrap', '--ro-bind', '/', '/']
        assert intent['argv'][4:7] == ['--bind', plan['work'], plan['work']]
        assert '--unshare-pid' in intent['argv'] and '--die-with-parent' in intent['argv']
        assert '--unshare-net' not in intent['argv']
        for key in ('onlyFreshWorkWritable', 'privatePidNamespace', 'originalHostNetworkPreserved', 'fixedSdkOneGetOnly'):
            assert intent[key] is True
        assert intent['httpTimeoutMs'] == 15000 and intent['sdkTimeoutMs'] == 18000 and intent['childTimeoutSeconds'] == 35
        assert intent['productionChanged'] is False and intent['automaticRetry'] is False
    helper = (ROOT / 'fresh_usage_read.mjs').read_text()
    launcher = (ROOT / 'launcher.py').read_text()
    assert "need(++calls === 1 && String(input) === ENDPOINT && init.method === 'GET'" in helper
    assert "headers.get('authorization') === 'Bearer ' + token" in helper
    assert "headers.get('chatgpt-account-id') === account" in helper
    assert "report.requestLedgerSha256 = save(work + '/request-started.public.json'" in helper
    assert 'agent:false, signal:init.signal' in helper
    assert "await sdk.a(token, account, 18000, fetchOne)" in helper
    assert helper.index("save(work + '/response.private', body)") < helper.index('resolve(new Response(body,')
    assert "'TMPDIR':str(WORK/'tmp')" in launcher and "(WORK/'tmp').mkdir(mode=0o700)" in launcher
    assert "tmpApi.n() === work + '/tmp/openclaw-' + process.getuid()" in helper
    managed = read(E / 'managed1-r1/result.public.json')
    unmanaged = read(E / 'native4-r1/result.public.json')
    managed_outer = read(E / 'managed1-r1/outer-result.public.json')
    native_outer = read(E / 'native4-r1/outer-result.public.json')
    assert managed['ok'] is False and managed['httpStatus'] == 401 and managed_outer['returnCode'] == 1
    assert unmanaged['ok'] is True and unmanaged['httpStatus'] == 200 and native_outer['returnCode'] == 0
    assert managed['sourceBindingBefore']['accountIdSha256'] != unmanaged['sourceBindingBefore']['accountIdSha256']
    assert managed['sourceBindingBefore']['nativeSourceGeneration'] == unmanaged['sourceBindingBefore']['nativeSourceGeneration']
    assert managed['sourceBindingBefore']['actualSdkRecoveredSelectionSha256'] == '8be2895e6a9c818b6c460f8a79e6b9e18602985b6c200514b65cf2a9f4e68252'
    assert unmanaged['sourceBindingBefore']['actualSdkRecoveredSelectionSha256'] is None
    classification = read(E / 'managed1-401-classification.public.json')
    assert classification['responseSha256'] == managed['responseSha256'] == '2dd8af6137cc2b1f408e76a00ccf6479db404b03f3d383befcb5bc67c3ba2cce'
    assert {v['path']: v['safeValue'] for v in classification['safeErrorFields']} == {
        'error.code': 'token_expired', 'error.type': 'invalid_request_error', 'detail.code': 'token_expired'}
    observations = {}
    for name, case, value, outer in [('managed1', 'managed1-r1', managed, managed_outer),
                                     ('native4', 'native4-r1', unmanaged, native_outer)]:
        ledger = read(E / case / 'request-started.public.json')
        assert value['sourceBindingBefore'] == value['sourceBindingAfter'] == ledger['sourceBinding']
        assert value['requestCount'] == outer['requestCount'] == 1
        assert value['tlsVerified'] and value['responseDurableBeforeSdkParse']
        assert outer['providerOutcomeUnknown'] is False and outer['ownedNamespaceProcessExited']
        assert outer['productionUnitBefore'] == outer['productionUnitAfter'] and outer['sourcePinsUnchanged']
        observations[name] = {
            'job': 'rog/' + agent['jobIds'][name], 'observed_at': ledger['startedAt'],
            'source_kind': value['sourceKind'], 'credential_sha256': value['sourceBindingBefore']['credentialSha256'],
            'http_status': value['httpStatus'], 'current_readonly_provider_validity': value['ok'],
            'known_request_outcomes': 1, 'unknown_outcomes': 0, 'retries': 0,
            'source_generation_unchanged': True, 'tls_verified': True,
            'raw_response_sha256': value['responseSha256'], 'raw_response_kept_host_private': True,
            'core_receipt_sha256': sha(E / case / 'result.public.json'),
            'outer_receipt_sha256': sha(E / case / 'outer-result.public.json'),
        }
    observations['managed1']['provider_error'] = 'token_expired'
    observations['native4']['remains_unmanaged'] = True
    report = {
        'schema': 'heptabao.root-review.distinct-current-provider-sources.v1',
        'evidence_consistent': True, 'all_provider_cases_passed': False,
        'reviewer_sha256': sha(Path(__file__)), 'source_manifest_sha256': sha(manifest_path),
        'agent_review_recomputed_exactly': True, 'agent_review_sha256': expected_agent,
        'public_file_pins_verified': 27, 'dependency_pins_verified': 11,
        'control_files_checked_against_original_sdk_bytes': len(received),
        'evidence_assertions_recomputed': 98, 'observations': observations,
        'pre_dispatch_r2_failure_retained': True,
        'actual_sdk_private_tmp_fallback_preserves_readonly_host_root': True,
        'production_gateway_pid_unchanged': 2436, 'all_owned_namespaces_exited': True,
        'source_pins_unchanged_both_requests': 15,
        'boundaries': {
            'managed2_qualified': False, 'all_accounts_qualified': False,
            'model_availability_qualified': False, 'native_factory_reopen_qualified': False,
            'oauth_refresh_attempted': False, 'new_login_attempted': False,
            'production_route_changed': False, 'native4_adopted_as_managed_source': False,
            'production_cutover': False, 'j3160_contacted': False,
            'full_openbao_271_replacement': False,
            'storage_sdk_rollback_236_remains_separate': True,
            'historical_managed1_200_is_not_current_validity': True,
        },
        'budgets': {'sdk_network_abort_ms': 18000, 'socket_inactivity_timeout_ms': 15000,
                    'outer_child_deadline_seconds': 35, 'whole_flow_18s_absolute_claim': False},
    }
    destination = ROOT / 'root-review.public.json'
    destination.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'evidence_consistent': True, 'all_provider_cases_passed': False,
                      'managed1_status': 401, 'native4_status': 200, 'sha256': sha(destination)}))


if __name__ == '__main__':
    main()
