#!/usr/bin/env python3
"""Current Mac single-node full34: readonly preparation, then one fresh run."""
import hashlib,json,os,stat,subprocess,time,sys
from pathlib import Path
SOURCE_TEXT=Path(__file__).read_text()
BINDING_READY=False
NORMAL61_SHA='02422f0070827e4940ae819d117b80ead30b993dba5ec9fe4a1aee21f286c113'
NORMAL_NATIVE_SHA='25c1ecc14b5b989d34227cef8d26964fdd0a6682fb3f8be754c2e1c501825f49'
NORMAL_RELEASE_SHA='2fdafe3670a0a7365245e509343ce1cf23ac28b071351d4f30ea12751d90a571'
# Filled only from root-reviewed actual fixed-path metadata; none are observations yet.
INPUT_METADATA={'oracle_binary': None, 'oracle_archive': None, 'server': None, 'python': None, 'git': None, 'openssl': None}
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-official271-full34-4e808-r1');REPO=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-same-root-publication-normal-r2/source');OUT=ROOT/'actual-r1'
PRODUCT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-same-root-publication-normal-r2/normal-release-tests-r1')
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
INPUT_PATHS={'oracle_binary': '/Volumes/T5/hepta-vnext-recovery-20261013/official-openbao-271-macos-20261016/bao', 'oracle_archive': '/Volumes/T5/hepta-vnext-recovery-20261013/official-openbao-271-macos-20261016/oracle-official.tar.gz', 'server': '/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-same-root-publication-normal-r2/normal-release-tests-r1/artifacts/heptabao-server', 'python': '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14', 'git': '/usr/bin/git', 'openssl': '/usr/bin/openssl'}
EXPECTED_SHA={'oracle_binary': '50c3588e64271171cc2147bddeace8ec2b6742f94fd3fe53baa60f6d938cda0c', 'oracle_archive': '15625b5f69aee5bb4578b4e76e856a2141647342b0f8e5969a8875b44e0fbf91', 'server': 'c1b005a9f73c3f28681613d6fa3a5703d74e4f30358da4b7d9fa1949eb25ae63', 'python': 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13', 'git': None, 'openssl': 'f81b4fcec5048ea1eceb40fc08f4e06f1668181f0b5bacfa8be27d0da181dcb7'}
EXPECTED_BYTES={'oracle_binary': None, 'oracle_archive': None, 'server': 92398928, 'python': 34640, 'git': None, 'openssl': 1130832}
NEW_PREPARE_SECONDS=60
ORIGINAL_RUNTIME_OUTER_SECONDS=1800
_PREPARE_UNTIL=None
HEAD='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec';TREE='eba5e650bd080b8ad41ea52a2bc68867f541d255'
PIN='c1b005a9f73c3f28681613d6fa3a5703d74e4f30358da4b7d9fa1949eb25ae63';DRIVER='383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581'
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
def git(*a):
 return subprocess.check_output(['/usr/bin/git','-c','core.hooksPath=/dev/null','-C',str(REPO),*a],text=True,timeout=min(30,prepare_remaining())).strip()
def source():return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'dirty':bool(git('status','--porcelain','--untracked-files=all')),'binary_sha256':sha(PRODUCT/'artifacts/heptabao-server')}
def normal61_admission():
 need(BINDING_READY is True,'normal61_and_local_prerequisite_bindings_unresolved')
 need(all(isinstance(x,str) and len(x)==64 and all(c in '0123456789abcdef' for c in x)
          for x in (NORMAL61_SHA,NORMAL_NATIVE_SHA,NORMAL_RELEASE_SHA)),
      'exact_actual_provenance_pins_required')
 actual=PRODUCT/'result.public.json'
 need(sha(actual)==NORMAL61_SHA,'combined_normal61_whole_pin')
 n=json.loads(actual.read_bytes())
 need(n.get('schema')=='heptabao.mac-normal-same-root-publication-exact-tests.v1'
      and n.get('source_commit')==HEAD and n.get('source_tree')==TREE
      and n.get('controller_sha256')=='3e013354f125cc4c282905beb6347d19f84448a14c304efd576b4d8705e0c2d8'
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
 return NORMAL61_SHA


def prepare_remaining():
 if _PREPARE_UNTIL is None:return 30.0
 left=_PREPARE_UNTIL-time.monotonic();need(left>0,'readonly_prepare_deadline');return left

def full9(s):
 return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def fixed_file(role):
 prepare_remaining();m=INPUT_METADATA[role];p=Path(INPUT_PATHS[role])
 need(isinstance(m,dict) and set(m)=={'path','bytes','sha256','identity','version'},'metadata_slot_unresolved')
 need(m['path']==str(p) and type(m['bytes']) is int and 0<m['bytes']<=512*1024*1024,'fixed_input_path_or_size')
 need(isinstance(m['sha256'],str) and len(m['sha256'])==64 and all(c in '0123456789abcdef' for c in m['sha256']),'fixed_input_sha256')
 need(isinstance(m['identity'],list) and len(m['identity'])==9 and all(type(x) is int for x in m['identity']),'fixed_input_full_identity')
 need(m['identity'][6]==m['bytes'] and m['identity'][5]==1,'fixed_input_identity_size_nlink')
 need(m['version']==':'.join(str(m['identity'][i]) for i in (0,1,6,7,8)),'fixed_input_version')
 if EXPECTED_SHA[role] is not None:need(m['sha256']==EXPECTED_SHA[role],'pinned_artifact_or_tool_digest')
 if EXPECTED_BYTES[role] is not None:need(m['bytes']==EXPECTED_BYTES[role],'pinned_artifact_or_tool_size')
 before=p.lstat();need(stat.S_ISREG(before.st_mode) and not p.is_symlink() and full9(before)==m['identity'],'input_metadata_changed')
 observed=0;digest=hashlib.sha256()
 with p.open('rb') as f:
  need(full9(os.fstat(f.fileno()))==m['identity'],'input_open_identity')
  while observed<m['bytes']:
   prepare_remaining();b=f.read(min(1024*1024,m['bytes']-observed));need(bool(b),'input_short_read');observed+=len(b);digest.update(b)
  prepare_remaining();need(f.read(1)==b'','input_eof');need(full9(os.fstat(f.fileno()))==m['identity'],'input_fd_changed')
 need(full9(p.lstat())==m['identity'] and observed==m['bytes'] and digest.hexdigest()==m['sha256'],'input_whole_bytes_or_name_changed')
 prepare_remaining();return m

def readonly_prepare():
 need(BINDING_READY is True,'normal61_and_local_prerequisite_bindings_unresolved')
 need(set(INPUT_METADATA)==set(INPUT_PATHS) and all(isinstance(v,dict) for v in INPUT_METADATA.values()),'all_six_prerequisites_required')
 need(sys.platform=='darwin','mac_native_host_required')
 inputs={name:fixed_file(name) for name in INPUT_PATHS}
 need(Path(sys.executable).samefile(PYTHON),'actual_python_executable_binding')
 need(ROOT.resolve(strict=True)==ROOT and ROOT.stat().st_uid==os.geteuid() and stat.S_IMODE(ROOT.stat().st_mode)==0o700,'fresh_control_root_custody')
 need(not os.path.lexists(OUT),'fresh_full34_work_root_required')
 normal61_admission()
 normal=PRODUCT/'native-build.public.json';release=PRODUCT/'normal-release-result.public.json'
 need(sha(normal)==NORMAL_NATIVE_SHA and sha(release)==NORMAL_RELEASE_SHA,'normal_build_receipt_pins')
 before=source();need(before=={'commit':HEAD,'tree':TREE,'dirty':False,'binary_sha256':PIN},'normal_source_and_binary_pin')
 need(sha(REPO/'qa/openbao-acceptance/kv2_271_lossless_native_live.py')==DRIVER,'unchanged_runner_pin')
 need(sha(REPO/'qa/openbao-acceptance/official_openbao_launcher.py')=='5c11b432e1180fb40394fab382da774cf4171bf51431aab7e5823068cfba01d6','oracle_launcher_pin')
 need(source()==before,'prepare_source_changed')
 for name,m in inputs.items():need(full9(Path(INPUT_PATHS[name]).lstat())==m['identity'],'prepare_input_final_identity')
 prepare_remaining()
 return {'schema':'heptabao.current-mac-full34-readonly-prepare.v1','candidate_commit':HEAD,'candidate_tree':TREE,'source':str(REPO),'source_before':before,'retained_server':str(PRODUCT/'artifacts/heptabao-server'),'normal61_sha256':NORMAL61_SHA,'native_build_sha256':NORMAL_NATIVE_SHA,'normal_release_sha256':NORMAL_RELEASE_SHA,'driver_sha256':DRIVER,'wrapper_sha256':hashlib.sha256(SOURCE_TEXT.encode()).hexdigest(),'fixed_inputs':inputs,'control_root':str(ROOT),'fresh_work_root':str(OUT),'original_checks':31,'original_http_seconds':15,'original_migration_seconds':360,'original_outer_seconds':ORIGINAL_RUNTIME_OUTER_SECONDS,'new_readonly_prepare_seconds':NEW_PREPARE_SECONDS,'private_fixture_created':False,'product_started':False,'official_cli_phaseb_qualified':False,'native_v6_ha_qualified':False,'full_replacement_qualified':False,'production_changed':False}

def main():
 global _PREPARE_UNTIL
 started=time.monotonic();_PREPARE_UNTIL=started+NEW_PREPARE_SECONDS
 need(sys.argv[1:]==['--prepare-only'] or (len(sys.argv)==3 and sys.argv[1]=='--run'),'exact_prepare_or_run_argv')
 prepared=readonly_prepare();prepared_raw=enc(prepared);prepared_sha=hashlib.sha256(prepared_raw).hexdigest()
 prepare_remaining()
 if sys.argv[1]=='--prepare-only':
  print(json.dumps({'schema':'heptabao.current-mac-full34-readonly-prepare-envelope.v1','prepared':prepared,'prepared_sha256':prepared_sha,'elapsed_seconds':time.monotonic()-started},sort_keys=True),flush=True)
  prepare_remaining();return 0
 need(sys.argv[2]==prepared_sha,'actual_prepare_binding_changed')
 _PREPARE_UNTIL=None
 os.umask(0o077);OUT.parent.mkdir(mode=0o700,exist_ok=True);OUT.mkdir(mode=0o700);(OUT/'tmp').mkdir(mode=0o700);start=time.monotonic()
 r={'schema':'heptabao.4e808-mac-original-full34-assessment.v1','ok':False,'full_replacement_qualified':False,'production_cutover':False,'production_changed':False,'original_http_seconds':15,'original_migration_seconds':360}
 try:
  before=source();need(before=={'commit':HEAD,'tree':TREE,'dirty':False,'binary_sha256':PIN},'normal_source_and_binary_pin')
  runner=REPO/'qa/openbao-acceptance/kv2_271_lossless_native_live.py';need(sha(runner)==DRIVER,'unchanged_runner_pin');need(sha(REPO/'qa/openbao-acceptance/official_openbao_launcher.py')=='5c11b432e1180fb40394fab382da774cf4171bf51431aab7e5823068cfba01d6','oracle_launcher_pin')
  normal=PRODUCT/'native-build.public.json';build=PRODUCT/'normal-release-result.public.json'
  need(sha(normal)==NORMAL_NATIVE_SHA and sha(build)==NORMAL_RELEASE_SHA,'normal_build_receipt_pins')
  oracle=Path(INPUT_PATHS['oracle_binary']);archive=Path(INPUT_PATHS['oracle_archive'])
  need(sha(oracle)==EXPECTED_SHA['oracle_binary'] and sha(archive)==EXPECTED_SHA['oracle_archive'],'official271_pins')
  argv=[PYTHON,'-I','-S','-B',str(runner),'--binary',str(PRODUCT/'artifacts/heptabao-server'),'--private-work-root',str(OUT/'private-run'),'--migration-lane','native-large','--profile','full34']
  env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C.UTF-8','TZ':'UTC','TMPDIR':str(OUT/'tmp'),'HB_ORACLE_BINARY':str(oracle),'HB_ORACLE_ARCHIVE':str(archive)}
  save(OUT/'controller.py',SOURCE_TEXT.encode());save(OUT/'intent.public.json',enc({'schema':'heptabao.4e808-mac-full34-intent.v1','argv':argv,'source_before':before,'driver_sha256':DRIVER,'original_http_seconds':15,'original_migration_seconds':360,'normal_default_build_verified':True,'default_build_receipt_sha256':sha(normal),'default_build_result_sha256':sha(build),'new_private_synthetic_target':True,'network_scope':'Mac loopback only','actual_prepared_sha256':prepared_sha,'full_replacement_qualified':False,'production_cutover':False}))
  with (OUT/'run.stdout').open('xb') as stdout,(OUT/'run.stderr').open('xb') as stderr:
   p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env=env)
  raw=(OUT/'private-run/summary.json').read_bytes();summary=json.loads(raw);save(OUT/'summary.public.json',raw)
  after=source();checks=summary.get('checks',[]);passed=[x['case'] for x in checks if x.get('passed') is True]
  r.update(child_exit_code=p.returncode,source_before=before,source_after=after,source_unchanged=before==after,checks_total=len(checks),checks_passed=len(passed),full34_qualified=summary.get('full34_qualified') is True,owned_processes_stopped='owned_processes_stopped' in passed,summary_sha256=hashlib.sha256(raw).hexdigest(),summary_bytes=len(raw),reported_status=summary.get('status'),missing_checks=summary.get('missing_checks'),failure=summary.get('failure'),elapsed_seconds=round(time.monotonic()-start,3))
  need(p.returncode==0 and len(checks)==31 and len(passed)==31 and r['full34_qualified'] and r['owned_processes_stopped'] and before==after,'original_full34_not_qualified');r['ok']=True
 except Exception as e:r['error']=str(e) if isinstance(e,RuntimeError) else type(e).__name__
 raw=enc(r);save(OUT/'result.public.json',raw);print(json.dumps({'ok':r['ok'],'checks_passed':r.get('checks_passed'),'checks_total':r.get('checks_total'),'error':r.get('error'),'receipt':str(OUT/'result.public.json'),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}));return 0 if r['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
