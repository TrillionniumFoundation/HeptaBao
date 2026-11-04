#!/usr/bin/env python3
"""Read-only verification of a preexisting exact-source installed-entry SDK run."""
import hashlib
import json
from pathlib import Path

R = Path(__file__).resolve().parent
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def read(name):
    return json.loads((R / name).read_text())

manifest = read('existing-r1-reconciliation-manifest.public.json')
assert sha(R / 'existing-r1-reconciliation-manifest.public.json') == '2b7cb57e1c630c68a1f0a69f5bc849f3d900915e97ba6149e7bec7c3bca5a6c0'
for entry in manifest['evidence']:
    p = R / entry['path']
    assert len(p.read_bytes()) == entry['bytes'] and sha(p) == entry['sha256']
d, o = read('existing-r1-full-result.public.json'), read('existing-r1-outer-result.public.json')
job = read('root-authoritative-job-status.public.json')
assert job == read('existing-r1-authoritative-terminal.public.json')
assert job['job_id'] == '1a1a67182ff-fc05-2559' and job['exit_code'] == 0 and job['state'] == 'succeeded'
assert job['output_complete'] and job['output_durable'] and not job['timed_out']
assert o['ok'] and o['exit_code'] == 0 and not o['remaining_owned_processes']
assert o['result_sha256'] == sha(R / 'existing-r1-full-result.public.json') and o['result_bytes'] == 72976
assert o['boundary_before'] == o['boundary_after'] and o['protected_metadata_before'] == o['protected_metadata_after']
assert d['ok'] and len(d['checks']) == 330 and all(x['passed'] for x in d['checks'])
assert d['normal_storage_profile'] == 'native_v6_file' and d['formal_activation_route'] == 'sys/storage/native-v6/activate'
assert d['binary_sha256'] == '7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'
assert (d['original_http_seconds'], d['original_readiness_seconds'], d['original_worker_seconds']) == (10, 12, 75)
assert d['coordinator_execution_scope'] == 'bound_installed_entry_api'
assert d['installed_entry_executed'] and d['installed_entry_sdk_same_fixture_qualified']
assert not any(d[k] for k in ['fixture_feature_used', 'actual_manager_qualified_in_this_scope', 'j3160_contacted', 'provider_called', 'oauth_refreshed', 'real_provider_credentials', 'production_cutover', 'production_coordinator_replacement', 'enforced_scheduler_qualified', 'oauth_refresh_ownership_qualified'])

pins = read('existing-r1-source-readback.public.json')['files']
for pin in pins:
    rel = pin['path'].split('/authbus-coordinator-installed-sdk-control-r1/', 1)[1]
    local = R / 'controller.py' if rel == 'controller.py' else R / 'candidate' / rel
    assert sha(local) == pin['sha256'] and local.stat().st_size == pin['bytes']
assert len(pins) == 5
assert d['driver_sha256'] == sha(R / 'candidate/qa/openbao-acceptance/native_v6_authbus_coordinator_live.py')
assert d['central_source_sha256'] == sha(R / 'candidate/tools/authbus/authbus_coordinator.py')
assert d['installed_entry_sha256'] == sha(R / 'candidate/tools/authbus/authbus_coordinator_installed.py')
assert d['consumer_sha256'] == sha(R / 'candidate/qa/openbao-acceptance/native_v6_authbus_coordinator_consumer.mjs')

checks = {x['case']: x for x in d['checks']}
critical = ['central.real_cas_rejection', 'central.current_or_historical_manifest_recovery',
    'central.recovery_did_not_replay_manifest', 'central.pending_cleared_after_receipt',
    'backup.actual_sdk_old_snapshot_and_current_manifest', 'rollback.binding_bytes_restored',
    'central.renew_self_same_bearer', 'acl.producer_canonical_write_denied',
    'acl.producer_other_inbox_denied', 'acl.writer_immutable_update_denied',
    'acl.writer_receipt_update_denied', 'acl.writer_inbox_injection_denied',
    'central.operator_grant_revoked', 'central.no_duplicate_credential_publication',
    'evidence.no_credential_values', 'source.original_plugin_unchanged',
    'source.independent_service_unchanged', 'source.installed_entry_unchanged',
    'installed_entry.actual_create_only_preparation']
assert all(checks[n]['passed'] for n in critical)

prep = d['installed_preparation']
assert not prep['serviceManagerRegistered'] and not prep['productionServiceChanged']
assert prep['binding']['bindingPrepared'] and prep['state']['statePrepared']
assert prep['state']['operationLock']['mode'] == prep['state']['serviceLock']['mode'] == 0o600
assert prep['state']['stateDirectory']['mode'] == 0o700
actions = {x['case']: x for x in d['central_actions']}
assert len(actions) == 12
for x in actions.values():
    assert x['installedEntryExecuted'] and x['installedEntrySha256'] == d['installed_entry_sha256']
    assert x['installationSha256'] == prep['binding']['bindingSha256']
    assert x['sourceSha256'] == d['central_source_sha256'] and x['syntheticCredentialFixture']
    assert not x['actualServiceManagerInThisScope'] and not x['productionMutation']
    assert x['entryApiCalls']
assert actions['actual_manifest_cas_race']['actualCompetingManifestCas']
crash = actions['actual_central_process_crash']
assert crash['injectedProcessExit'] == 73 and not crash['publicSuccessClaimed']
assert crash['lastObservedPhase'] == 'manifest_committed_before_journal_reply'
assert actions['central_cold_recover']['result']['recovered_pending']
assert actions['central_cold_recover']['entryApiCalls'] == ['service_cycle.recover']
renew = actions['central_actual_renewal_api']['result']
assert renew == {'actualRenewSelfSameBearer': True, 'forcedLocalDueClock': True, 'realLeaseExpiryWaited': False}
assert len(d['server_cycles']) == 2 and all(x['exit_code'] == -9 and x['method'] == 'SIGKILL' for x in d['server_cycles'])
clients = {x['case']: x for x in d['clients']}
assert len(clients) == 10
negative = {'follower_bad_binding', 'original_follower_sid_revoked'}
observations = 0
for name, x in clients.items():
    assert x['defaultAgentScoped'] and x['sdkVersion'] == '2026.7.1-2'
    assert not x['provider_network_allowed'] and not x['production_mutation']
    assert x['harnessTransport'] == {'isolatedBaoAgent': 'fresh_full_tls_handshake_per_request', 'keepAlive': False, 'maxCachedSessions': 0, 'productionPluginModified': False}
    assert x['authentications'] == (0 if name in negative else 1)
    assert x['ok'] is (name not in negative)
    if name not in negative:
        assert x['observations']
        for z in x['observations']:
            assert z['tlsAuthorized'] and z['peerCertificateSha256'] == d['server_cert_der_sha256']
            assert z['isSessionReused'] is False and z['socketId'] == z['requestSocketId']
        observations += len(x['observations'])
for name in negative:
    assert checks[name + '.exit']['actual'] == 3
assert observations == 50
for i in range(21):
    assert checks[f'revoke.token_live_before.{i}']['status'] == 200
    assert checks[f'revoke.token.{i}']['status'] == 204
    assert checks[f'revoke.token_denied.{i}']['status'] == checks[f'revoke.persisted_token.{i}']['status'] == 403
for host in ['producer', 'follower', 'writer']:
    assert checks['revoke.sid.authbus-central-' + host]['status'] == 204
provenance = read('existing-r1-job-provenance.public.json')
assert len(provenance['matching']) == 1 and provenance['matching'][0]['jobId'] == job['job_id']
assert provenance['matching'][0]['scriptIsExactController'] and provenance['matching'][0]['mode'] == 'live'
assert not provenance['stdinRead'] and not provenance['writes']
current = read('existing-r1-current-owned-process.public.json')
assert current['remainingOwnedProcesses'] == [] and not any(current['exactOriginalPidsPresent'].values())
assert current['readOnly'] and current['servicesStarted'] == current['signalsSent'] == 0
refusal = read('duplicate-stage-refusal.public.json')
assert refusal['rejectedBeforeBoundaryAndMkdir'] and refusal['existingControlAndWorkNotOverwritten']
assert not refusal['serverStartedByThisAttempt'] and not refusal['liveReplayed']

review = {'schema': 'heptabao.root-review.installed-entry-sdk-same-fixture.v1',
    'status': 'passed_with_explicit_scope', 'job': job['job_id'], 'host': 'rog', 'terminal_exit': 0,
    'preexisting_run_reconciled_without_replay': True,
    'launcher_agent_attribution': 'not recorded in observed durable metadata; no claim made',
    'full_result_sha256': sha(R / 'existing-r1-full-result.public.json'),
    'outer_result_sha256': sha(R / 'existing-r1-outer-result.public.json'),
    'reconciliation_manifest_sha256': sha(R / 'existing-r1-reconciliation-manifest.public.json'),
    'checks': {'passed': 330, 'observed': 330, 'dynamic_count': True},
    'elapsed_seconds': o['elapsed_seconds'], 'normal_binary_sha256': d['binary_sha256'],
    'normal_storage_profile': d['normal_storage_profile'], 'formal_activation_route': d['formal_activation_route'],
    'original_budget_seconds': {'http': 10, 'readiness': 12, 'worker': 75, 'outer': 900},
    'five_current_exact_source_pins_verified': True,
    'coordinator': {'installed_entry_executed': True, 'same_fixture_sdk_to_entry_to_sdk': True,
        'original_binding_locks_and_guarded_transport': True, 'actions': 12,
        'actual_competing_cas': True, 'actual_commit_before_exit_73': True,
        'pending_history_recovery_without_replay': True, 'exact_grant_revocation': True,
        'actual_manager_qualified_in_this_scope': False},
    'sdk': {'version': '2026.7.1-2', 'clients': 10, 'positive': 8, 'expected_negative': 2,
        'positive_full_tls_observations': observations, 'original_sdk_and_plugin': True,
        'actual_closed_database_backup_restore_and_bad_binding_rollback': True},
    'renewal': renew,
    'revocation': {'real_issued_tokens': 21, 'denied_after_cold_restart': 21, 'secret_ids_destroyed': 3},
    'normal_server_sigkill_cold_restarts': 2, 'all_current_owned_processes_stopped': True,
    'finite_production_hash_paths_unchanged': list(o['protected_metadata_before']),
    'scope': {'synthetic_provider_credentials': True, 'provider_called': False, 'j3160_contacted': False,
        'enforced_scheduler_qualified': False, 'oauth_refresh_ownership_qualified': False,
        'production_changed': False, 'full_replacement_qualified': False},
    'duplicate_stage_refusal_preserved': True,
    'root_review_script_sha256': sha(Path(__file__)), 'critical_checks': critical}
out = R / 'root-review.public.json'
out.write_text(json.dumps(review, indent=2, sort_keys=True) + '\n')
print(json.dumps({'path': str(out), 'bytes': out.stat().st_size, 'sha256': sha(out), 'checks': 330}))
