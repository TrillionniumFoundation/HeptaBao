from pathlib import Path
import ast,hashlib,json
r=Path('/workspace/scratch/f86faac821c4/rog-coordinator-normal-review-r1')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
d=json.loads((r/'result.public.json').read_bytes());o=json.loads((r/'outer-result.public.json').read_bytes())
assert sha(r/'result.public.json')=='c4105c0e933237058dd24aee70eabce2f2e244510c0a4deffa76e1c9e7eae185'
assert sha(r/'outer-result.public.json')=='f636852ca79a803c2756b6b7dcda61ab753b34fe8d7a78170d9fa5f0d71fc525'
assert o['ok'] and o['exit_code']==0 and not o['remaining_owned_processes']
assert o['boundary_before']==o['boundary_after'] and o['protected_metadata_before']==o['protected_metadata_after']
assert d['ok'] and len(d['checks'])==314 and all(x['passed'] for x in d['checks'])
assert d['normal_storage_profile']=='native_v6_file' and d['formal_activation_route']=='sys/storage/native-v6/activate'
assert (d['original_http_seconds'],d['original_readiness_seconds'],d['original_worker_seconds'])==(10,12,75)
assert not any(d[k] for k in ['fixture_feature_used','installed_entry_executed','j3160_contacted','provider_called','oauth_refreshed','real_provider_credentials','production_cutover','production_coordinator_replacement','enforced_scheduler_qualified','oauth_refresh_ownership_qualified'])
assert d['coordinator_execution_scope']=='direct_core_api'
assert len(d['clients'])==10 and len(d['central_actions'])==12
checks={x['case']:x for x in d['checks']}
required=['central.real_cas_rejection','central.current_or_historical_manifest_recovery','central.recovery_did_not_replay_manifest','central.pending_cleared_after_receipt','backup.actual_sdk_old_snapshot_and_current_manifest','rollback.binding_bytes_restored','central.renew_self_same_bearer','acl.producer_canonical_write_denied','acl.producer_other_inbox_denied','acl.writer_immutable_update_denied','acl.writer_receipt_update_denied','acl.writer_inbox_injection_denied','central.operator_grant_revoked','central.no_duplicate_credential_publication','evidence.no_credential_values','source.original_plugin_unchanged','source.independent_service_unchanged']
assert all(checks[n]['passed'] for n in required)
clients={x['case']:x for x in d['clients']};bad={'follower_bad_binding','original_follower_sid_revoked'};positive=clients.keys()-bad
observations=0
for n,x in clients.items():
 assert x['defaultAgentScoped'] and x['sdkVersion']=='2026.7.1-2' and not x['provider_network_allowed'] and not x['production_mutation']
 assert x['harnessTransport']=={'isolatedBaoAgent':'fresh_full_tls_handshake_per_request','keepAlive':False,'maxCachedSessions':0,'productionPluginModified':False}
 assert x['authentications']==(0 if n in bad else 1)
 assert x['ok'] is (n not in bad)
 if n not in bad:
  assert x['observations']
  for z in x['observations']:
   assert z['tlsAuthorized'] and z['peerCertificateSha256']==d['server_cert_der_sha256'] and z['isSessionReused'] is False
   assert z['socketId']==z['requestSocketId']
  observations+=len(x['observations'])
assert checks['follower_bad_binding.exit']['actual']==3 and checks['original_follower_sid_revoked.exit']['actual']==3
actions={x['case']:x for x in d['central_actions']}
assert actions['actual_manifest_cas_race']['actualCompetingManifestCas']
assert actions['actual_central_process_crash']['injectedProcessExit']==73 and actions['actual_central_process_crash']['publicSuccessClaimed'] is False
assert actions['central_cold_recover']['result']['recovered_pending']
renew=actions['central_actual_renewal_api']['result'];assert renew=={'actualRenewSelfSameBearer':True,'forcedLocalDueClock':True,'realLeaseExpiryWaited':False}
assert len(d['server_cycles'])==2 and all(x['exit_code']==-9 and x['method']=='SIGKILL' for x in d['server_cycles'])
for i in range(21):
 assert checks[f'revoke.token_live_before.{i}']['status']==200
 assert checks[f'revoke.token.{i}']['status']==204
 assert checks[f'revoke.token_denied.{i}']['status']==checks[f'revoke.persisted_token.{i}']['status']==403
for h in ['producer','follower','writer']:assert checks['revoke.sid.authbus-central-'+h]['status']==204
old=Path('/workspace/scratch/f86faac821c4/pocket-coordinator-review-20261104/native_v6_authbus_coordinator_live.py')
new=r/'candidate/qa/openbao-acceptance/native_v6_authbus_coordinator_live.py'
assert sha(old)=='61c7720591995c64ab4c8f1d4a78be10b9569430f6bb52b86d95ddf13a277cad'
a=ast.parse(old.read_text());b=ast.parse(new.read_text())
for name in ['run_worker','run']:
 x=next(n for n in a.body if isinstance(n,ast.FunctionDef) and n.name==name)
 y=next(n for n in b.body if isinstance(n,ast.FunctionDef) and n.name==name)
 if name=='run':
  for node in ast.walk(y):
   if isinstance(node,ast.Name) and node.id=='NormalInstance':node.id='NativeInstance'
   if isinstance(node,ast.Constant) and node.value=='sys/storage/native-v6/activate':node.value='sys/internal/native-v6/activate'
 assert ast.dump(x,include_attributes=False)==ast.dump(y,include_attributes=False),name
out={'schema':'heptabao.root-review.normal-sdk-coordinator-r1.v1','status':'passed_with_explicit_scope','result_sha256':sha(r/'result.public.json'),'outer_sha256':sha(r/'outer-result.public.json'),'job':'1a1a6603cd4-fc05-2472','terminal_exit':0,'elapsed_seconds':o['elapsed_seconds'],'checks':{'passed':314,'observed':314,'dynamic_credentials_and_metadata_count':True},'normal_binary_sha256':d['binary_sha256'],'source_profile':'native_v6_file','formal_activation_route':d['formal_activation_route'],'original_budget_seconds':{'http':10,'readiness':12,'worker':75},'all_original_worker_and_run_assertions_preserved':True,'sdk':{'version':'2026.7.1-2','clients':10,'positive_clients':8,'expected_negative_clients':2,'positive_tls_observations':observations,'new_full_tls_handshake_each_request':True,'exact_sqlite_and_default_agent_paths':True},'coordinator':{'independent_core_sha256':d['central_source_sha256'],'direct_core_api':True,'installed_entry_executed':False,'actual_competing_cas':True,'actual_commit_before_process_exit_73':True,'pending_history_recovery_without_manifest_replay':True,'seven_field_operator_grants_required':True},'revocation':{'real_issued_tokens':21,'denied_after_cold_restart':21,'secret_ids_destroyed':3},'renewal':renew,'server_sigkill_cold_restart_count':2,'all_owned_processes_stopped':True,'finite_production_hash_paths_unchanged':list(o['protected_metadata_before']),'scope':{'synthetic_oauth_only':True,'provider_called':False,'j3160_contacted':False,'enforced_scheduler_qualified':False,'oauth_refresh_ownership_qualified':False,'production_changed':False,'full_replacement_qualified':False},'critical_checks':required}
q=r/'root-review.public.json';q.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n')
print(json.dumps({'path':str(q),'sha256':sha(q),'bytes':q.stat().st_size,'positive_tls_observations':observations}))
s=Path('/workspace/scratch/f86faac821c4/root_continuation_state.json');state=json.loads(s.read_text());state['authbus_normal_sdk_coordinator_rog_r1']={**out,'local_root':str(r),'remote_control':'/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-coordinator-normal-sdk-control-r1','remote_work':'/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-coordinator-normal-sdk-live-r1','root_review_sha256':sha(q)};s.write_text(json.dumps(state,indent=2,ensure_ascii=False)+'\n')

