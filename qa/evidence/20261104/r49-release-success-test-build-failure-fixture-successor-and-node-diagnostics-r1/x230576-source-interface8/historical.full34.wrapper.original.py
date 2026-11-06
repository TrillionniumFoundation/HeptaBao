#!/usr/bin/env python3
"""Bind the unchanged 31-check full34 runner to the exact 4e808 normal61 build."""
import hashlib,json,os,stat,subprocess,time
from pathlib import Path
SOURCE_TEXT=Path(__file__).read_text()
BINDING_READY=True
NORMAL61_SHA='7830845172732432895c246d77c47266432a03c0788e15689ea74d15dff14475'
NORMAL_NATIVE_SHA='3bfc21f48ce6dd831c8bde094b2f24f53ed0266e57e5fd55839b0a5977f5db5a'
NORMAL_RELEASE_SHA='78d5eeb0235f62896ec57ca4d0243e31c56e861a4dde438ccd23eac3edafdd22'
TRANSFER_SHA='dd36121b4d65ced9ef686039f9c2869cc52c33adda58e5e185fcb32eceb4973f'
ROOT=Path('/home/qian/heptabao-same-root-publication-normal-20261105-r1');REPO=ROOT/'source';OUT=ROOT/'evidence/full34-r1'
HEAD='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec';TREE='eba5e650bd080b8ad41ea52a2bc68867f541d255'
PIN='cb840a0f275f5c56c5b60e774d613020160853495f821975df7a1451522e15f0';DRIVER='383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581'
def need(v,c):
 if not v:raise RuntimeError(c)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def save(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  v=memoryview(b)
  while v:
   n=os.write(fd,v);need(n>0,'short_write');v=v[n:]
  os.fsync(fd)
 finally:os.close(fd)
 need(p.read_bytes()==b,'save_readback');fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def enc(x):return (json.dumps(x,sort_keys=True,indent=2)+'\n').encode()
def git(*a):return subprocess.check_output(['/usr/bin/git','-C',str(REPO),*a],text=True).strip()
def source():return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'dirty':bool(git('status','--porcelain','--untracked-files=no')),'binary_sha256':sha(ROOT/'artifacts/heptabao-server')}
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
 os.umask(0o077);OUT.parent.mkdir(mode=0o700,exist_ok=True);OUT.mkdir(mode=0o700);(OUT/'tmp').mkdir(mode=0o700);start=time.monotonic()
 r={'schema':'heptabao.4e808-x230-original-full34-assessment.v1','ok':False,'full_replacement_qualified':False,'production_cutover':False,'production_changed':False,'original_http_seconds':15,'original_migration_seconds':360}
 try:
  before=source();need(before=={'commit':HEAD,'tree':TREE,'dirty':False,'binary_sha256':PIN},'normal_source_and_binary_pin')
  runner=REPO/'qa/openbao-acceptance/kv2_271_lossless_native_live.py';need(sha(runner)==DRIVER,'unchanged_runner_pin');need(sha(REPO/'qa/openbao-acceptance/official_openbao_launcher.py')=='5c11b432e1180fb40394fab382da774cf4171bf51431aab7e5823068cfba01d6','oracle_launcher_pin')
  normal=ROOT/'artifacts/native-build.public.json';build=ROOT/'artifacts/result.public.json'
  need(sha(normal)==NORMAL_NATIVE_SHA and sha(build)==NORMAL_RELEASE_SHA,'normal_build_receipt_pins')
  oracle=Path('/home/qian/heptabao-official-271-fresh-20261029-r1/bao');archive=oracle.with_name('official-openbao-2.7.1-linux-amd64.tar.gz')
  need(sha(oracle)=='535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea' and sha(archive)=='0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243','official271_pins')
  argv=['/usr/bin/python3','-I','-S','-B',str(runner),'--binary',str(ROOT/'artifacts/heptabao-server'),'--private-work-root',str(OUT/'private-run'),'--migration-lane','native-large','--profile','full34']
  env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C.UTF-8','TZ':'UTC','TMPDIR':str(OUT/'tmp'),'HB_ORACLE_BINARY':str(oracle),'HB_ORACLE_ARCHIVE':str(archive)}
  save(OUT/'controller.py',SOURCE_TEXT.encode());save(OUT/'intent.public.json',enc({'schema':'heptabao.4e808-x230-full34-intent.v1','argv':argv,'source_before':before,'driver_sha256':DRIVER,'original_http_seconds':15,'original_migration_seconds':360,'normal_default_build_verified':True,'default_build_receipt_sha256':sha(normal),'default_build_result_sha256':sha(build),'new_private_synthetic_target':True,'network_scope':'X230 loopback only','full_replacement_qualified':False,'production_cutover':False}))
  with (OUT/'run.stdout').open('xb') as stdout,(OUT/'run.stderr').open('xb') as stderr:
   p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env=env)
  raw=(OUT/'private-run/summary.json').read_bytes();summary=json.loads(raw);save(OUT/'summary.public.json',raw)
  after=source();checks=summary.get('checks',[]);passed=[x['case'] for x in checks if x.get('passed') is True]
  r.update(child_exit_code=p.returncode,source_before=before,source_after=after,source_unchanged=before==after,checks_total=len(checks),checks_passed=len(passed),full34_qualified=summary.get('full34_qualified') is True,owned_processes_stopped='owned_processes_stopped' in passed,summary_sha256=hashlib.sha256(raw).hexdigest(),summary_bytes=len(raw),reported_status=summary.get('status'),missing_checks=summary.get('missing_checks'),failure=summary.get('failure'),elapsed_seconds=round(time.monotonic()-start,3))
  need(p.returncode==0 and len(checks)==31 and len(passed)==31 and r['full34_qualified'] and r['owned_processes_stopped'] and before==after,'original_full34_not_qualified');r['ok']=True
 except Exception as e:r['error']=str(e) if isinstance(e,RuntimeError) else type(e).__name__
 raw=enc(r);save(OUT/'result.public.json',raw);print(json.dumps({'ok':r['ok'],'checks_passed':r.get('checks_passed'),'checks_total':r.get('checks_total'),'error':r.get('error'),'receipt':str(OUT/'result.public.json'),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}));return 0 if r['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
