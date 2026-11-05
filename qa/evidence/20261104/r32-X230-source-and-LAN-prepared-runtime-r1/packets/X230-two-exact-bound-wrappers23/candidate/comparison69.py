from pathlib import Path
import hashlib,json,os,subprocess,time
os.umask(0o077)
BINDING_READY=True
NORMAL61_SHA='7830845172732432895c246d77c47266432a03c0788e15689ea74d15dff14475'
NORMAL_NATIVE_SHA='3bfc21f48ce6dd831c8bde094b2f24f53ed0266e57e5fd55839b0a5977f5db5a'
NORMAL_RELEASE_SHA='78d5eeb0235f62896ec57ca4d0243e31c56e861a4dde438ccd23eac3edafdd22'
TRANSFER_SHA='dd36121b4d65ced9ef686039f9c2869cc52c33adda58e5e185fcb32eceb4973f'
ROOT=Path('/home/qian/heptabao-same-root-publication-normal-20261105-r1')
SOURCE=ROOT/'source';OUT=ROOT/'evidence/comparison69-r1';ART=ROOT/'artifacts'
HEAD='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec';TREE='eba5e650bd080b8ad41ea52a2bc68867f541d255'
BINARY_SHA='cb840a0f275f5c56c5b60e774d613020160853495f821975df7a1451522e15f0'
DRIVER_SHA='fd88ed0b8f1c1010e79f9393dfbf6464cabcac48ece8c6e448a64b7ccc45272e'
MODULES=sorted('core,kv,token,transit,pki,totp,userpass,approle,identity,wrapping,edge_tls,system,operations'.split(','))
def need(x,label):
 if not x:raise RuntimeError(label)
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def save(path,value):
 raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 need(path.read_bytes()==raw,'receipt_readback')
 return hashlib.sha256(raw).hexdigest()
def git(*args):return subprocess.check_output(['/usr/bin/git','-C',str(SOURCE),*args],text=True,timeout=30).strip()
def source():
 return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'dirty_including_untracked':bool(git('status','--porcelain')),'binary_sha256':sha(ART/'heptabao-server')}
def normal61_admission():
 need(BINDING_READY is True,'normal61_and_transport_bindings_unresolved')
 need(all(isinstance(x,str) and len(x)==64 and all(c in '0123456789abcdef' for c in x)
          for x in (NORMAL61_SHA,NORMAL_NATIVE_SHA,NORMAL_RELEASE_SHA,TRANSFER_SHA)),
      'exact_actual_provenance_pins_required')
 actual=ROOT/'artifacts/normal61-result.public.json'
 need(sha(actual)==NORMAL61_SHA,'combined_normal61_whole_pin')
 n=json.loads(actual.read_bytes())
 need(n.get('schema')=='heptabao.linux-normal-same-root-publication-exact-tests.v1'
      and n.get('source_commit')==HEAD and n.get('source_tree')==TREE
      and n.get('controller_sha256')=='93dd6190c7f081305defdbc1c49600974bfa581d943736c77798d51a1c8f54be'
      and n.get('status')=='passed' and n.get('test_count')==44
      and n.get('selected_test_total')==61 and n.get('normal_default_features') is True
      and n.get('fixture_features')==[] and n.get('original_44_status')=='passed'
      and n.get('original_44_and_ingress_7_status')=='passed'
      and n.get('original_60_status')=='passed' and n.get('original_60_test_total')==60
      and n.get('additional_test_counts')=={'ingress_observer':7,'cold_h2':9,'same_root_publication':1}
      and n.get('source_unchanged') is True and n.get('binary_unchanged') is True
      and n.get('release_artifacts_unchanged') is True,'exact_normal61_qualification')
 for key,names in (
     ('ingress_observer_regression',["service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_permission_is_affine_and_resumed_binding_never_arms","service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_permission_rejects_actual_new_request_nonce_or_selected_root","service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_actual_failed_repair_closes_reselection_before_any_result","ha::native_v6_runtime::request_timing_tests::native_request_timing_failure_has_only_bounded_static_metadata","ha::native_v6_runtime::request_timing_tests::native_request_timing_sixty_four_buckets_preserve_existing_aggregates","ha::native_v6_runtime::request_timing_tests::native_request_timing_observes_deadlines_but_preserves_once_only_results","ha::native_v6_runtime::request_timing_tests::native_request_timing_phase_advance_is_distinct_from_operation_success"]),
     ('cold_h2_regression',["service::native_v6_ha_install::read::cold_timing_tests::cold_native_ha_timing_preserves_once_and_owned_result_identity","service::native_v6_ha_install::read::cold_timing_tests::cold_native_ha_timing_preserves_nested_source_and_inner_results","service::native_v6_ha_install::tests::native_ha_install_batches_actual_readindex_cold_missing_and_corrupt_file","http::h2_transport::sync_worker_tests::h2_sync_worker_is_unentered_and_retains_outer_context","http::h2_transport::sync_worker_tests::h2_sync_worker_expired_deadline_never_calls_work","http::h2_transport::sync_worker_tests::h2_sync_worker_preserves_inner_result","http::h2_transport::sync_worker_tests::h2_sync_worker_joins_panicked_work_and_drops_capture","http::h2_transport::sync_worker_tests::h2_sync_worker_does_not_authorize_nested_runtime_context","http::h2_transport::sync_worker_tests::h2_sync_worker_cancelled_waiter_retains_blocking_capacity"])):
  group=n.get(key,{})
  need(group.get('status')=='passed' and group.get('test_count')==len(names)
       and group.get('actual_test_names')==names and group.get('clamped_to_original_outer_deadline') is True,
       'exact_separate_normal_regression')
 same=n.get('same_root_publication_regression',{})
 need(same.get('schema')=='heptabao.normal-same-root-publication-regression.v1'
      and same.get('status')=='passed' and same.get('test_count')==1
      and same.get('actual_test_names')==['service::native_v6_ha_install::tests::same_root_republication_tests::native_ha_same_root_republication_advances_warm_and_cold_cursors']
      and same.get('original_44_7_9_denominators_unchanged') is True
      and same.get('clamped_to_original_outer_deadline') is True
      and same.get('new_total_group_cap_seconds')==600,
      'independent_same_root_publication_regression')
 cleanup=n.get('cleanup')
 need(isinstance(cleanup,list) and cleanup and all(
      row.get('exit_code')==0 and row.get('direct_child_reaped') is True
      and row.get('remaining')==[] and not row.get('cleanup_error_type') for row in cleanup),
      'normal_all_children_terminal')
 need(sha(ROOT/'artifacts/transfer.result.public.json')==TRANSFER_SHA,'new_exact_transfer_receipt_pin')
 return NORMAL61_SHA

def main():
 normal61_admission()
 OUT.parent.mkdir(mode=0o700,exist_ok=True);OUT.mkdir(mode=0o700);start=time.monotonic()
 report={'schema':'heptabao.4e808-x230-original-comparison69-assessment.v1','ok':False,'execution_host':'x230','full_openbao_compatibility':False,'production_qualified':False,'production_changed':False,'original_modules_unmodified':True,'original_driver_unmodified':True}
 try:
  before=source();need(before=={'commit':HEAD,'tree':TREE,'dirty_including_untracked':False,'binary_sha256':BINARY_SHA},'source_and_binary_pin')
  driver=ROOT/'native271_comparison_final_r1.py';need(sha(driver)==DRIVER_SHA,'original69_driver_pin')
  pins={'native-build.public.json':NORMAL_NATIVE_SHA,'result.public.json':NORMAL_RELEASE_SHA,'transfer.result.public.json':TRANSFER_SHA}
  for name,pin in pins.items():need(sha(ART/name)==pin,'artifact_provenance_pin')
  oracle=Path('/home/qian/heptabao-official-271-fresh-20261029-r1/bao');archive=oracle.with_name('official-openbao-2.7.1-linux-amd64.tar.gz')
  need(sha(oracle)=='535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea','official_binary_pin')
  need(sha(archive)=='0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243','official_archive_pin')
  need(sha(SOURCE/'qa/openbao-acceptance/acceptance.py')=='8312c400ec5f0946f8a87fb3241bf8db832ddd04763010af7245d6557f55f94d','unchanged_69_acceptance_contract')
  argv=['/usr/bin/python3','-I','-S','-B',str(driver),'--binary',str(ART/'heptabao-server'),'--expected-binary-sha256',BINARY_SHA,'--expected-source-commit',HEAD,'--candidate-source',str(SOURCE),'--work-dir',str(OUT/'private-run'),'--build-log',str(ART/'result.public.json'),'--oracle-version','2.7.1']
  env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C.UTF-8','TZ':'UTC','HB_ORACLE_BINARY':str(oracle),'HB_ORACLE_ARCHIVE':str(archive)}
  intent={'schema':'heptabao.4e808-x230-original-comparison69-intent.v1','argv':argv,'env':env,'source_before':before,'driver_sha256':DRIVER_SHA,'normal_receipt_pins':pins,'build_log_argument_is_immutable_normal_build_result_receipt':True,'modules_argument_omitted_to_preserve_original_13_module_default':True,'default_modules':MODULES,'controller_sha256':sha(Path(__file__)),'new_private_fixture_root':str(OUT/'private-run'),'network_scope':'X230 loopback only','full_openbao_compatibility':False,'production_qualified':False}
  report['intent_sha256']=save(OUT/'intent.public.json',intent)
  with (OUT/'run.stdout').open('xb') as so,(OUT/'run.stderr').open('xb') as se:
   p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=so,stderr=se,env=env)
   so.flush();se.flush();os.fsync(so.fileno());os.fsync(se.fileno())
  actual=OUT/'private-run/comparison-bound.json';raw=actual.read_bytes();summary=json.loads(raw)
  fd=os.open(OUT/'summary.public.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
  after=source()
  side_stats={}
  for side in ['candidate_results','oracle_results']:
   rows=summary[side]['cases'];side_stats[side]={'count':len(rows),'passed':sum(x.get('result')=='passed' for x in rows.values()),'not_run':sum(x.get('result')=='not_run' for x in rows.values()),'failed':sum(x.get('result')=='failed' for x in rows.values()),'cleanup':summary[side]['cleanup']['result']}
  report.update(child_exit_code=p.returncode,source_before=before,source_after=after,source_unchanged=before==after,side_stats=side_stats,status=summary.get('status'),cases_match=summary.get('cases_match'),mismatched_cases=summary.get('mismatched_cases'),scope=summary.get('scope'),uncovered=summary.get('uncovered'),owned_cleanup_completed=summary.get('owned_cleanup_completed'),cleanup_errors=summary.get('cleanup_errors'),summary_sha256=hashlib.sha256(raw).hexdigest(),summary_bytes=len(raw),summary_path=str(OUT/'summary.public.json'),elapsed_seconds=round(time.monotonic()-start,3))
  need(p.returncode==0 and summary['status']=='passed_scoped_cases' and summary['cases_match'] is True and summary['mismatched_cases']==[],'original69_scoped_cases_failed')
  need(all(s=={'count':69,'passed':69,'not_run':0,'failed':0,'cleanup':'passed'} for s in side_stats.values()),'original69_case_inventory_or_cleanup')
  need(sorted(summary['scope'])==MODULES and summary['owned_cleanup_completed'] is True and summary['cleanup_errors']==[],'original69_scope_or_owned_cleanup')
  need(before==after and summary['source_and_binary_unchanged'] is True,'source_or_binary_changed')
  need(summary['execution_binding']['runner_source_sha256']==DRIVER_SHA and summary['execution_binding']['candidate_source_sha']==HEAD and summary['execution_binding']['candidate_binary_sha256']==BINARY_SHA,'original69_execution_binding')
  need(summary['full_openbao_compatibility'] is False and summary['production_qualified'] is False,'bounded_scope_not_preserved')
  report['ok']=True
 except Exception as e:
  report['error']=str(e) if isinstance(e,RuntimeError) else type(e).__name__
 digest=save(OUT/'result.public.json',report)
 print(json.dumps({'ok':report['ok'],'error':report.get('error'),'side_stats':report.get('side_stats'),'owned_cleanup_completed':report.get('owned_cleanup_completed'),'receipt':str(OUT/'result.public.json'),'receipt_sha256':digest,'summary_sha256':report.get('summary_sha256')}))
 return 0 if report['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
