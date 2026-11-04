#!/usr/bin/env python3
"""Independently verify the complete manager/SDK fixture and retain its limits."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PINS = {
    'public-receipt.json': '223a2ba21c5cf448e3aa4479a11fe8daf86151fb93f536466b521176d541b68e',
    'outer-result.public.json': '247ebfc2ad290218024bb24a00c2727ca7989422f29b7bc21b2fa3d972699866',
    'stage.public.json': 'fb310ee1ea360a61d9a11775c7bc26505f43d750543967fe5dd4b6f666c6d2a0',
    'baseline330.public.json': 'f153bfc82b65e5b96d09221eea43849d69a9fc84811fa29f6a9bf2a3fbccc1dc',
    'retained-r1/public-receipt.json': 'ab260275950dc956ecdf69051b680f5f8a9a50ff47eb6c1e0d5b1059c35c60d3',
    'retained-r2/public-receipt.json': 'c7ad8209728f442533aab453867e94fdd45204c89d56ecc70b06bf767ab9db1d',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(name):
    raw = (ROOT / name).read_bytes()
    if name in PINS:
        assert sha(raw) == PINS[name], name
    return json.loads(raw)


r, outer, staged = map(read, ['public-receipt.json', 'outer-result.public.json', 'stage.public.json'])
baseline, failed1, failed2 = map(read, ['baseline330.public.json', 'retained-r1/public-receipt.json', 'retained-r2/public-receipt.json'])
terminal = read('terminal-status.public.json')
assert terminal['job_id'] == '1a1a68f04ec-fc05-26de' and terminal['state'] == 'succeeded'
assert terminal['exit_code'] == 0 and terminal['timed_out'] is False
assert terminal['output_complete'] and terminal['output_durable'] and terminal['terminal_publication_confirmed']
assert r['ok'] and outer['ok'] and outer['exit_code'] == 0
assert outer['result_sha256'] == PINS['public-receipt.json'] and outer['result_bytes'] == 335452
assert r['actual_manager_qualified_in_this_scope'] and r['installed_manager_sdk_same_fixture_qualified']
assert r['actual_sdk_qualified'] and r['actual_service_https_qualified']
assert r['normal_storage_profile'] == 'native_v6_file' and r['fixture_feature_used'] is False
assert r['formal_activation_route'] == 'sys/storage/native-v6/activate'
assert outer['boundary_before'] == outer['boundary_after'] == staged['boundary']
boundary = outer['boundary_before']
assert boundary['commit'] == '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
assert boundary['tree'] == 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336' and boundary['source_clean']
assert boundary['binary_sha256'] == r['binary_sha256'] == '7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'
assert outer['protected_files_unchanged'] and outer['protected_metadata_before'] == outer['protected_metadata_after']
assert len(outer['protected_metadata_before']) == 3
for name, expected in staged['inputs'].items():
    p = ROOT / name if name in ['controller.py', 'manager-system-plan.public.json'] else ROOT / 'candidate' / name
    assert sha(p.read_bytes()) == expected, name
checks = r['checks']
assert len(checks) == outer['checks'] == 1107 and all(c['passed'] is True for c in checks)
names = {c['case'] for c in checks}
assert len(baseline['checks']) == 330 and {c['case'] for c in baseline['checks']} <= names
assert all(c['passed'] is True for c in baseline['checks'])
m = r['manager_qualification']
assert len(m['checks']) == 689 and all(c['passed'] is True for c in m['checks'])
for k in ['ok', 'sameFixture', 'sameBackendAndOwnerState', 'sameOriginalSdkStores',
          'realSystemManagerTested', 'actualManagerRestartTested', 'managerPendingRecoveryTested',
          'managerRevokedColdStartTested', 'ownedCleanupComplete', 'exactSecretIdDestroyedBeforeColdStart']:
    assert m[k] is True, k
assert m['requestedManagerScope'] == 'system' and m['realUserManagerTested'] is False
assert m['cleanupErrors'] == [] and m['rootUnitReconciliationRequired'] is False
assert m['installation']['sameOriginalBackendAndCredentials'] and m['installation']['sameOriginalOwnerAndLocks']
restart = m['managerRestart']
assert restart['oldPid'] != restart['newPid'] and restart['oldInvocationId'] != restart['newInvocationId']
assert restart['oldIdentityAbsent'] and restart['exactOriginalUnitAndBinding']
for fence in m['runtimeFences']:
    for k in ['ok', 'argvExact', 'cgroupExact', 'executableExact', 'sameOriginalPid', 'noNewPrivileges']:
        assert fence[k] is True, k
    assert fence['credentialsRead'] is False and fence['targetEnvironmentRead'] is False
    assert fence['paths']['code']['statvfsReadOnly'] and fence['paths']['config']['statvfsReadOnly']
    assert fence['paths']['state']['statvfsReadOnly'] is False
    assert fence['Uid'] == [1000] * 4 and fence['Gid'] == [1000] * 4
installed, removed = m['rootUnitFileReceipts']
assert installed['action'] == 'install' and removed['action'] == 'remove'
assert installed['identity'] == removed['removedIdentity']
assert installed['sha256'] == removed['sha256'] == m['installation']['unitSha256']
assert installed['identity']['uid'] == 0 and installed['identity']['mode'] == 0o644
assert outer['manager_cleanup_confirmed'] and outer['remaining_owned_processes'] == []
for unit in outer['manager_units_terminal']:
    assert unit['name'] == m['installation']['unitName'] and unit['runtime_file_absent']
    assert unit['fields'] == {'ActiveState': 'inactive', 'LoadState': 'not-found', 'MainPID': '0'}
cycles = {x['case']: x for x in m['managerCycleReceipts']}
assert cycles['same_fixture_publication_c']['committed'] == 1
assert cycles['same_fixture_pending_recovery']['recovered_pending'] is True
assert cycles['same_fixture_pending_recovery']['committed'] == 0
for case in ['system_manager.actual_manager_cleared_same_fixture_pending',
             'system_manager.actual_manager_same_fixture_manifest_not_replayed',
             'same_fixture.sdk_follower_exact_c', 'same_fixture.sdk_follower_exact_d_after_manager_recovery',
             'backup.actual_sdk_old_snapshot_and_current_manifest', 'rollback.binding_bytes_restored']:
    assert case in names
assert r['same_fixture_generations'] == {'api': 2, 'after_actual_manager_and_recovery': 4}
assert len(r['server_cycles']) == 3
assert all(c['method'] == 'SIGKILL' and c['exit_code'] == -9 for c in r['server_cycles'])
clients = r['clients']
positive, negative = [c for c in clients if c['ok']], [c for c in clients if not c['ok']]
assert len(clients) == 16 and len(positive) == 13 and len(negative) == 3
observations = [o for c in positive for o in c['observations']]
assert len(observations) == 80
for o in observations:
    assert o['tlsAuthorized'] is True and o['isSessionReused'] is False
    assert o['peerCertificateSha256'] == r['server_cert_der_sha256']
    assert o['socketId'] == o['requestSocketId']
assert all(c['sdkVersion'] == '2026.7.1-2' and c['defaultAgentScoped'] for c in clients)
assert all(c['production_mutation'] is False and c['provider_network_allowed'] is False for c in clients)
for index in range(27):
    assert all(prefix + str(index) in names for prefix in ['revoke.token_live_before.', 'revoke.token.',
                                                         'revoke.token_denied.', 'revoke.persisted_token.'])
assert len([c for c in checks if c['case'].startswith('revoke.persisted_token.')]) == 27
assert len([c for c in checks if c['case'].startswith('revoke.sid.')]) == 3
renewal = next(x for x in r['central_actions'] if x['case'] == 'central_actual_renewal_api')['result']
assert renewal == {'actualRenewSelfSameBearer': True, 'forcedLocalDueClock': True, 'realLeaseExpiryWaited': False}
assert r['rotation_protocol'] == 'producer_canonical_ack_before_next_source_rotation'
assert r['unacknowledged_successive_rotation_qualified'] is False
assert m['managerSessionBearersExposed'] is False and m['managerSessionTokenRevocationCoverage'] is False
assert failed1['ok'] is False and failed2['ok'] is False
assert failed1['error'] == 'same_fixture_original_producer_c.exit'
assert [c['case'] for c in failed2['checks'] if not c['passed']] == ['same_fixture.sdk_producer_d_actual_event']
failed_clients = {c['case']: c for c in failed2['clients']}
c = failed_clients['same_fixture_original_producer_c']['cycles'][0]
d = failed_clients['same_fixture_original_producer_d']['cycles'][0]
assert d['before']['profiles'] != d['after']['profiles'] == c['after']['profiles']
assert d['plugin']['publishedEvents'] == 0 and d['plugin']['importedProfiles'] == 1
for field in ['production_cutover', 'production_coordinator_replacement', 'j3160_contacted',
              'real_provider_credentials', 'provider_called', 'oauth_refreshed',
              'enforced_scheduler_qualified', 'oauth_refresh_ownership_qualified']:
    assert r[field] is False, field
report = {
    'schema': 'heptabao.root-review.actual-manager-and-sdk-r3.v1', 'ok': True,
    'source_commit': boundary['commit'], 'source_tree': boundary['tree'], 'binary_sha256': r['binary_sha256'],
    'live_job': terminal['job_id'], 'terminal_exit': 0, 'receipt_sha256': PINS['public-receipt.json'],
    'actual_installed_system_manager_and_sdk_same_fixture': True,
    'dynamic_checks': 1107, 'unique_check_names': len(names), 'manager_dynamic_checks': 689,
    'all_prior_330_check_names_retained': True, 'sdk_positive_runs': 13, 'sdk_negative_runs': 3,
    'verified_fresh_tls_observations': 80, 'same_fixture_generations': 4,
    'actual_manager_restart_verified': True, 'manager_pending_recovery_without_replay_verified': True,
    'server_sigkill_cold_restarts': 3, 'captured_tokens_revoked_and_cold_denied': 27, 'secret_ids_destroyed': 3,
    'actual_renew_self_same_bearer': True, 'renewal_forced_local_due_clock': True, 'real_lease_expiry_waited': False,
    'actual_runtime_code_and_config_read_only': True, 'original_root_unit_identity_removed': True,
    'remaining_owned_processes': 0, 'observed_production_files_unchanged': 3,
    'normal_source_sdk_and_plugin_boundary_unchanged': True,
    'retained_failed_runs': {'r1': PINS['retained-r1/public-receipt.json'], 'r2': PINS['retained-r2/public-receipt.json']},
    'known_unacknowledged_rotation_loss_reproduced': True,
    'manager_daemon_bearer_revocation_qualified': False, 'unacknowledged_successive_rotation_qualified': False,
    'synthetic_credentials': True, 'provider_called': False, 'j3160_contacted': False,
    'production_switched': False, 'full_openbao_271_replacement_qualified': False,
}
(ROOT / 'root-review.public.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
