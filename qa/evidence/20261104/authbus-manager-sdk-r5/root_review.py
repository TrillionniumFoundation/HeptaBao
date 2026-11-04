#!/usr/bin/env python3
"""Review original r5 receipts and pinned source; this script runs no remote work."""
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PINS = {
    'public-receipt.json': '527e025bd7376e46e469ff738fdbd1e5d440ca8ad5b43dce529a0b6851ad3d2e',
    'outer-result.public.json': 'f01a8ff4bf3720c8fddf9bc4ca31c4f8929ef7e2d6fa18d4459e155d4927543d',
    'stage.public.json': '31dec2588e9123a656196ba79971d666860819fce0b2f6931352f14ed4c359fe',
    'live-intent.public.json': 'fc605326451d97a93e217c8a5be16d809d4a0b2ca77b627df78b4ca636ef37de',
    'terminal-status.public.json': 'bf9b6b96ebc14b2c5fdc8a42c8c4a9ff11293a3972c3455e59084a059d09515f',
    'retained-r4/public-receipt.json': 'f45a728e8b5b1a82558edb4441a9520fc51d3829f5c3be7d29e19a5d3ca6030b',
    'retained-r4/token-metadata-diagnostic-r2.public.json': '8bdcde8af3c1c469a35344d5f278f7c0e0ed0dcd7bbf25a2ffadb968cd8d0b9a',
    '../authbus-manager-sdk-r3/baseline330.public.json': 'f153bfc82b65e5b96d09221eea43849d69a9fc84811fa29f6a9bf2a3fbccc1dc',
    '../authbus-manager-sdk-r3/retained-r2/public-receipt.json': 'c7ad8209728f442533aab453867e94fdd45204c89d56ecc70b06bf767ab9db1d',
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def read(name):
    b = (ROOT / name).read_bytes()
    if name in PINS:
        assert sha(b) == PINS[name], name
    return json.loads(b)


for name in PINS:
    read(name)
r, outer, staged = map(read, ['public-receipt.json', 'outer-result.public.json', 'stage.public.json'])
terminal, freeze = map(read, ['terminal-status.public.json', 'source-freeze.public.json'])
assert terminal['job_id'] == '1a1a6ca1093-fc05-28b5' and terminal['state'] == 'succeeded'
assert terminal['exit_code'] == 0 and terminal['timed_out'] is False
assert terminal['output_complete'] and terminal['output_durable'] and terminal['terminal_publication_confirmed']
assert not terminal['automatic_retry'] and not any(terminal['log_truncated'].values())
assert r['ok'] and outer['ok'] and outer['exit_code'] == 0
assert outer['result_sha256'] == PINS['public-receipt.json'] and outer['result_bytes'] == 505034
assert r['normal_storage_profile'] == 'native_v6_file' and not r['fixture_feature_used']
assert r['formal_activation_route'] == 'sys/storage/native-v6/activate'
assert outer['boundary_before'] == outer['boundary_after'] == staged['boundary']
b = outer['boundary_before']
assert b['commit'] == '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
assert b['tree'] == 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336' and b['source_clean']
assert b['binary_sha256'] == r['binary_sha256'] == '7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'
assert outer['protected_files_unchanged'] and outer['protected_metadata_before'] == outer['protected_metadata_after']
assert len(outer['protected_metadata_before']) == 3
assert freeze['inputs'] == staged['inputs'] and len(staged['inputs']) == 12
for name, expected in staged['inputs'].items():
    p = ROOT / name
    if not p.is_file():
        p = ROOT / 'candidate' / name
    assert sha(p.read_bytes()) == expected, name
assert len(staged['helpers']) == 7
for name, expected in staged['helpers'].items():
    assert sha((ROOT / 'pinned-helpers' / name).read_bytes()) == expected, name
original_plugin = b['plugin_sha256']
selected_plugin = outer['selected_plugin_source_sha256']
assert len(original_plugin) == 7 and set(original_plugin) == set(selected_plugin)
assert [n for n in original_plugin if original_plugin[n] != selected_plugin[n]] == ['runtime-refresh-policy.js']
assert selected_plugin == r['plugin_source_sha256'] and original_plugin == r['production_plugin_source_sha256']
assert original_plugin['runtime-refresh-policy.js'] == '8257a6d2ee04868f3a7de5ff8ffaa7fdd3b37bb12a07ac993a3e9c7480c83547'
assert selected_plugin['runtime-refresh-policy.js'] == '0881ce9500eff4686508cd5c6f5989d54faa6f832c4eefeb9ad38380692df72e'
assert outer['selected_plugin_unchanged'] and not r['production_plugin_modified']
assert (r['original_http_seconds'], r['original_readiness_seconds'], r['original_worker_seconds']) == (10, 12, 75)

checks = r['checks']
assert len(checks) == outer['checks'] == 1612 and all(c['passed'] is True for c in checks)
names = Counter(c['case'] for c in checks)
assert len(names) == 1611
by_name = {c['case']: c for c in checks}
baseline = read('../authbus-manager-sdk-r3/baseline330.public.json')
assert len(baseline['checks']) == 330 and all(c['passed'] is True for c in baseline['checks'])
renamed = {
    'manifest.exact_single_profile.72': 'manifest.exact_single_profile.73',
    'manifest.exact_single_profile.123': 'manifest.exact_single_profile.124',
    'manifest.exact_single_profile.132': 'manifest.exact_single_profile.133',
    'manifest.exact_single_profile.202': 'manifest.exact_single_profile.203',
}
baseline_names = Counter(c['case'] for c in baseline['checks'])
assert sum((baseline_names & names).values()) == 326
assert not (Counter(renamed.get(c['case'], c['case']) for c in baseline['checks']) - names)
m = r['manager_qualification']
assert len(m['checks']) == 1155 and all(c['passed'] is True for c in m['checks'])
for key in ['ok', 'sameFixture', 'sameBackendAndOwnerState', 'sameOriginalSdkStores',
            'realSystemManagerTested', 'actualManagerRestartTested', 'managerPendingRecoveryTested',
            'managerRevokedColdStartTested', 'ownedCleanupComplete', 'exactSecretIdDestroyedBeforeColdStart',
            'managerSessionTokenRevocationCoverage', 'operatorCliSessionTokenRevocationCoverage']:
    assert m[key] is True, key
assert m['requestedManagerScope'] == 'system' and not m['realUserManagerTested']
assert m['cleanupErrors'] == [] and not m['rootUnitReconciliationRequired']
assert m['installation']['sameOriginalBackendAndCredentials'] and m['installation']['sameOriginalOwnerAndLocks']
assert len(m['managerRestartHistory']) == 2
for restart in m['managerRestartHistory']:
    assert restart['oldPid'] != restart['newPid'] and restart['oldInvocationId'] != restart['newInvocationId']
    assert restart['oldIdentityAbsent'] and restart['exactOriginalUnitAndBinding']
assert m['managerRestartHistory'][0]['newInvocationId'] == m['managerRestartHistory'][1]['oldInvocationId']
for fence in m['runtimeFences']:
    for key in ['ok', 'argvExact', 'cgroupExact', 'executableExact', 'sameOriginalPid', 'noNewPrivileges']:
        assert fence[key] is True, key
    assert not fence['credentialsRead'] and not fence['targetEnvironmentRead']
    assert fence['paths']['code']['statvfsReadOnly'] and fence['paths']['config']['statvfsReadOnly']
    assert fence['paths']['state']['statvfsReadOnly'] is False
    assert fence['Uid'] == [1000] * 4 and fence['Gid'] == [1000] * 4
installed, removed = m['rootUnitFileReceipts']
assert installed['action'] == 'install' and removed['action'] == 'remove'
assert installed['identity'] == removed['removedIdentity'] == {'device': 28, 'gid': 0, 'inode': 252724, 'mode': 420, 'uid': 0}
assert installed['sha256'] == removed['sha256'] == m['installation']['unitSha256'] == '78d508f26948aa464a66299ed6afe9627d73e4ceaec38dd4f59b92788946cdf2'
assert outer['manager_cleanup_confirmed'] and outer['remaining_owned_processes'] == []
for unit in outer['manager_units_terminal']:
    assert unit['name'] == m['installation']['unitName'] and unit['runtime_file_absent']
    assert unit['fields'] == {'ActiveState': 'inactive', 'LoadState': 'not-found', 'MainPID': '0'}
cycles = {x['case']: x for x in m['managerCycleReceipts']}
assert cycles['same_fixture_publication_c']['committed'] == 1
assert cycles['same_fixture_pending_recovery']['recovered_pending'] and cycles['same_fixture_pending_recovery']['committed'] == 0
for case in ['ungranted_d_actual_manager_defers', 'ungranted_pending_after_restart', 'cold_ungranted_d_still_deferred']:
    assert cycles[case]['committed'] == 0 and cycles[case]['deferred'] >= 1
required_cases = [
    'system_manager.actual_manager_cleared_same_fixture_pending',
    'system_manager.actual_manager_same_fixture_manifest_not_replayed',
    'unacknowledged_rotation.producer_has_not_acked_c', 'unacknowledged_rotation.no_d_authority',
    'unacknowledged_rotation.d_survives_two_ticks', 'unacknowledged_rotation.c_unchanged_without_d_grant',
    'unacknowledged_rotation.d_survives_cold_sdk_and_manager_restart',
    'unacknowledged_rotation.exact_d_inbox_retained_without_authority',
    'unacknowledged_rotation.old_c_grant_did_not_authorize_d',
    'unacknowledged_rotation.producer_converges_to_exact_canonical_d',
    'backup.actual_sdk_old_snapshot_and_current_manifest', 'rollback.binding_bytes_restored',
]
assert all(name in names for name in required_cases)
assert r['same_fixture_generations'] == {'api': 2, 'after_actual_manager_and_recovery': 4}
assert len(r['server_cycles']) == 3 and all(c['method'] == 'SIGKILL' and c['exit_code'] == -9 for c in r['server_cycles'])
clients = r['clients']
positive, negative = [c for c in clients if c['ok']], [c for c in clients if not c['ok']]
assert len(clients) == 17 and len(positive) == 14 and len(negative) == 3
observations = [o for c in positive for o in c['observations']]
assert len(observations) == 89
for o in observations:
    assert o['tlsAuthorized'] is True and o['isSessionReused'] is False
    assert o['peerCertificateSha256'] == r['server_cert_der_sha256'] == 'c6c137931fa807ad8d9c0ea8b2f13cb46c17e59d134c26b5d0d229152a2ca761'
    assert o['socketId'] == o['requestSocketId']
assert all(c['sdkVersion'] == '2026.7.1-2' and c['defaultAgentScoped'] for c in clients)
assert all(not c['production_mutation'] and not c['provider_network_allowed'] for c in clients)
clients = {c['case']: c for c in clients}
assert 'same_fixture_original_producer_accept_c' not in clients
p = r['unacknowledged_rotation_proposal']
assert p == {
    'credentialDigest': '42bb02cdb39e56b50368e0a9247561d65cef38d824945df6f14392fcae2690d3',
    'eventIdSha256': '117f3805568d5bbe3ee568fc1586667a36e9531bb33143b7ab7e965150d38895',
    'identityDigest': '2130c128c1430bfc0273182701d49412c74585746250557ff3f930f5f63968f4',
    'immutableVersion': 1, 'locatedBeforeAnyDGrant': True, 'profileId': 'openai:authbus-central-a',
    'recordSha256': 'f366036e391009bdf51fc19c7b08b25af2754f590841bdcc2e3377273fc93980',
    'retainedAfterSdkAndManagerRestart': True, 'sourceHost': 'authbus-central-producer',
}
for case in ['same_fixture_original_producer_d', 'unacknowledged_rotation_sdk_cold_process_d']:
    for c in clients[case]['cycles']:
        assert c['before']['profiles'][p['profileId']] == c['after']['profiles'][p['profileId']] == p['credentialDigest']
        assert c['plugin']['pendingRuntimeRefreshes'] == 1 and c['plugin']['manifestGeneration'] == 3
assert clients['unacknowledged_rotation_sdk_cold_process_d']['initial']['profiles'][p['profileId']] == p['credentialDigest']
for case in ['same_fixture_original_follower_d', 'unacknowledged_rotation_producer_canonical_d_ack']:
    assert clients[case]['cycles'][-1]['after']['profiles'][p['profileId']] == p['credentialDigest']

a = m['accessorSessionQualification']
for key in ['ok', 'activeDaemonDeniedWithOldBearer', 'coldRevocationsPersisted', 'daemonAccessorsRevoked',
            'operatorAccessorsRevoked', 'onlyFixtureRootRemains']:
    assert a[key] is True, key
for key in ['bearersRead', 'processMemoryRead', 'processEnvironmentRead']:
    assert a[key] is False, key
assert a['namespaceScope'] == 'owned_root_endpoint_without_namespace_header'
assert a['namespaceProjectionEvidenceSha256'] == PINS['retained-r4/token-metadata-diagnostic-r2.public.json']
assert len(a['captures']) == len(a['revocations']) == 8
assert Counter(c['kind'] for c in a['captures']) == {'daemon': 4, 'operator': 4}
captures = {c['accessorSha256']: c for c in a['captures']}
assert len(captures) == 8
for c in a['captures']:
    assert c['policies'] == ['authbus-central-writer', 'default'] and c['roleName'] == 'authbus-central-writer'
    assert c['ttlAtCapture'] > 30 and c['exactDifferenceCardinality'] == (1 if c['kind'] == 'daemon' else 2)
assert len({c['invocationId'] for c in a['captures'] if c['kind'] == 'daemon'}) == 4
assert all(c['invocationId'] is None for c in a['captures'] if c['kind'] == 'operator')
for c in a['revocations']:
    assert c['revokeStatus'] == 204 and c['postLookupStatus'] == 400
    assert all(c[k] == captures[c['accessorSha256']][k] for k in ['case', 'kind'])
for i in range(8):
    for label in ['cold_revocation_' + str(i) + '.lookup_status']:
        c = by_name['system_manager.accessor_sessions.' + label]
        assert c['actual'] == c['expected'] == 400
for c in checks:
    if c['case'].endswith('.exact_writer_app_role'):
        assert all(c['predicates'].values()) and c['ttl'] > 30
assert len(a['inventories']) == 16
last = a['inventories'][-3:]
assert [x['case'] for x in last] == ['cold_revocations_inventory', 'before_revoked_sid_cold_start', 'after_revoked_sid_failed_start']
assert all(c['count'] == 1 for c in last) and len({c['sortedAccessorSetSha256'] for c in last}) == 1
for label in ['live_old_bearer_caused_exact_exit', 'live_revocation_no_automatic_retry',
              'actual_old_bearer_denial_receipt', 'live_revocation_left_manifest_exact',
              'failed_sid_cold_start_issued_no_accessor', 'remaining_token_is_exact_root_policy']:
    assert 'system_manager.accessor_sessions.' + label in names
failures = {f['case']: f for f in m['managerFailureReceipts']}
live = failures['actual_running_daemon_bearer_revoked']
assert live['error'] == 'bao_authentication_or_acl_denied' and not live['unknown_outcome']
assert live['invocationId'] == next(c['invocationId'] for c in a['captures'] if c['case'] == 'recovered_daemon')
assert not live['event_manifest_write_may_have_dispatched'] and not live['immutable_profile_write_may_have_dispatched']
cold = failures['revoked_writer_cold_start']
assert cold['error'] == 'mutation_outcome_unknown' and cold['unknown_outcome'] is True
assert 'system_manager.revoked_writer_cold_start.no_automatic_retry' in names
assert any(o['route'] == 'login' and o['status'] == 400 for o in clients['same_fixture_follower_revoked_after_cold_start']['observations'])
for i in range(28):
    assert all(prefix + str(i) in names for prefix in ['revoke.token_live_before.', 'revoke.token.', 'revoke.token_denied.', 'revoke.persisted_token.'])
    for prefix in ['revoke.token_denied.', 'revoke.persisted_token.']:
        assert by_name[prefix + str(i)]['status'] == by_name[prefix + str(i)]['expected'] == 403
assert sum(c['case'].startswith('revoke.persisted_token.') for c in checks) == 28
assert sum(c['case'].startswith('revoke.sid.') for c in checks) == 3
renewal = next(x for x in r['central_actions'] if x['case'] == 'central_actual_renewal_api')['result']
assert renewal == {'actualRenewSelfSameBearer': True, 'forcedLocalDueClock': True, 'realLeaseExpiryWaited': False}
assert r['rotation_protocol'] == 'unacknowledged_successive_local_rotation_with_exact_operator_grant'
assert r['unacknowledged_successive_rotation_qualified'] and r['manager_session_revocation_qualified']
assert not m['managerSessionBearersExposed']
failed2 = read('../authbus-manager-sdk-r3/retained-r2/public-receipt.json')
assert not failed2['ok'] and [c['case'] for c in failed2['checks'] if not c['passed']] == ['same_fixture.sdk_producer_d_actual_event']
failed_clients = {c['case']: c for c in failed2['clients']}
c, d = (failed_clients['same_fixture_original_producer_' + x]['cycles'][0] for x in ['c', 'd'])
assert d['before']['profiles'] != d['after']['profiles'] == c['after']['profiles']
assert d['plugin']['publishedEvents'] == 0 and d['plugin']['importedProfiles'] == 1
failed4 = read('retained-r4/public-receipt.json')
assert not failed4['ok'] and [c['case'] for c in failed4['checks'] if not c['passed']] == ['system_manager.accessor_sessions.initial_daemon.0.exact_writer_app_role']
red, green = map(read, ['selector-regression/evidence/selector-red.public.json', 'selector-regression/evidence/selector-green.public.json'])
assert red['moduleSha256'] == original_plugin['runtime-refresh-policy.js'] and not red['ok']
assert [c['case'] for c in red['checks'] if not c['passed']] == ['unacknowledged_c_must_not_overwrite_newer_managed_local_d']
assert green['moduleSha256'] == selected_plugin['runtime-refresh-policy.js'] and green['ok']
assert len(green['checks']) == 12 and all(c['passed'] for c in green['checks'])
for field in ['production_cutover', 'production_coordinator_replacement', 'j3160_contacted',
              'real_provider_credentials', 'provider_called', 'oauth_refreshed',
              'enforced_scheduler_qualified', 'oauth_refresh_ownership_qualified']:
    assert r[field] is False, field
assert m['formalNormalServerQualified'] is False and m['pairedOwnerKvRestoreQualified'] is False
report = {
    'schema': 'heptabao.root-review.actual-manager-and-sdk-r5.v1', 'ok': True,
    'source_commit': b['commit'], 'source_tree': b['tree'], 'binary_sha256': r['binary_sha256'],
    'live_job': terminal['job_id'], 'terminal_exit': 0, 'receipt_sha256': PINS['public-receipt.json'],
    'receipt_bytes': 505034, 'all_12_input_sources_and_7_original_helpers_verified': True,
    'dynamic_checks': 1612, 'unique_check_names': len(names), 'manager_dynamic_checks': 1155,
    'all_prior_330_assertions_retained': True, 'literal_prior_case_assertions_retained': 326,
    'counter_only_case_renames': renamed, 'sdk_positive_runs': 14, 'sdk_negative_runs': 3,
    'verified_fresh_tls_observations': 89, 'same_fixture_generations': 4,
    'actual_manager_restarts_verified': 2, 'server_sigkill_cold_restarts': 3,
    'unacknowledged_d_retained_across_two_ticks_cold_sdk_and_manager_restart': True,
    'canonical_c_unchanged_until_exact_d_grant': True, 'immutable_d_proposal': p,
    'manager_pending_recovery_without_replay_verified': True,
    'exact_daemon_sessions_revoked': 4, 'exact_operator_sessions_revoked': 4,
    'all_8_accessors_invalid_after_cold_restart': True, 'final_inventory_only_fixture_root': True,
    'live_daemon_known_auth_acl_denial_same_invocation_exit': 2, 'live_daemon_unknown_outcome': False,
    'live_daemon_wire_status_not_separately_recorded': True, 'known_denial_decoder_http_statuses': [401, 403],
    'revoked_sid_cold_manager_exit': 3, 'revoked_sid_cold_manager_unknown_outcome': True,
    'revoked_sid_cold_sdk_observed_login_status': 400, 'no_automatic_retry_observation_seconds': 6,
    'separate_captured_tokens_revoked_with_direct_live_and_cold_403': 28, 'secret_ids_destroyed': 3,
    'actual_renew_self_same_bearer': True, 'renewal_forced_local_due_clock': True, 'real_lease_expiry_waited': False,
    'actual_runtime_code_and_config_read_only': True, 'original_root_unit_identity_removed': True,
    'remaining_owned_processes': 0, 'observed_production_files_unchanged': 3,
    'original_7_plugin_sources_unchanged': True, 'candidate_selector_isolated': True,
    'retained_r2_actual_loss_receipt': PINS['../authbus-manager-sdk-r3/retained-r2/public-receipt.json'],
    'retained_r4_namespace_guard_failure': PINS['retained-r4/public-receipt.json'],
    'selector_component_checks': 12, 'synthetic_credentials': True, 'provider_called': False,
    'j3160_contacted': False, 'production_switched': False, 'enforced_scheduler_qualified': False,
    'oauth_refresh_ownership_qualified': False, 'paired_owner_kv_restore_qualified': False,
    'full_openbao_271_replacement_qualified': False,
}
(ROOT / 'root-review.public.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
