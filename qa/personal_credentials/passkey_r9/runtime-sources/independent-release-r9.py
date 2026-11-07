#!/usr/bin/env python3
"""Read-only independent absence recheck after complete-run r9 cleanup."""
import fcntl,hashlib,importlib.util,json,os,re,socket,time
from pathlib import Path

BASE=Path('/home/alex/HeptaBaoPasskey-20261106-r9');ROOT=BASE/'live-r9'
CORE='e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd'
BUILD='97a6daec5bb7276b935498fb3c8501df9ecc57a118641cffb9f2df3ae6edd009'
PROFILE='b6b7754bad0e34cf55b0c2635683b03093555fa5d3f096533ee36b3e02eec55b'
DIRECTORY='/sdcard/Download/HeptaBao-Passkey-QA-20261106-r9'
STAGES=('RP','SETUP','DOCUMENTS','M01','M02','M03','M04','M05_OBSERVE','M05_RESET','M05_RESTORE','M06','G11_RECOVERY_EXPORT','G11_OBSERVE','G11_RESET','G11_STALE','G02_G06','G07','SAF_GUARDS','M07_RESTORE','M07_CLEANUP')
def sha(b):return hashlib.sha256(b).hexdigest()
def native(v):
 if 'reply' in v:v=v['reply']
 if 'result' in v and isinstance(v['result'],dict) and 'value' in v['result']:v=v['result']['value']
 if 'content' in v:
  assert v.get('isError') is not True
  texts=[x['text'] for x in v['content'] if x.get('type')=='text'];assert len(texts)==1
  return json.loads(texts[0])
 return v
def main():
 os.umask(0o077);source=BASE/'passkey_live.r9.py';assert sha(source.read_bytes())==CORE
 spec=importlib.util.spec_from_file_location('live_r9_release',source);live=importlib.util.module_from_spec(spec);spec.loader.exec_module(live)
 for p in (BASE,ROOT,BASE/'artifacts'):live.private_directory(p)
 assert not (BASE/'release-r9.public.json').exists()
 lock=os.open(ROOT/'driver.lock',os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  buildraw=live.private_file(BASE/'artifacts/build.receipt.json',1048576);assert sha(buildraw)==BUILD
  profile_raw=live.private_file(ROOT/'profile.public.json',1048576);assert sha(profile_raw)==PROFILE
  journal=json.loads(live.private_file(ROOT/'journal.private.json',8*1048576));live.validate_journal(journal,json.loads(buildraw),BUILD)
  d=live.Device(Path('/home/alex/.local/bin/adb'))
  settings={k:d.setting(k) for k in live.SETTING_KEYS};assert settings==journal['original_settings']
  assert all(d.package_hash(x) is None for x in live.OWNED)
  reverse=d.adb_call('reverse','--list');assert reverse.returncode==0 and not reverse.stderr and not any('tcp:38491' in x for x in reverse.stdout.decode().splitlines())
  plan=json.loads(live.private_file(ROOT/'documents.private.json',65536))
  dirs={DIRECTORY,DIRECTORY+'/latest-recovery',DIRECTORY+'/G08-target',DIRECTORY+'/G10-target'}
  assert plan['cleanup_complete'] is True and plan['initial_directory_absent'] is True
  assert len(plan['files'])==8 and len(plan['directories'])==4 and {x['path'] for x in plan['directories']}==dirs
  assert {x['path'] for x in plan['files']}=={p+'/'+leaf for p in dirs for leaf in ('heptabao-passkey-qa-r9-seed.hbv','HeptaBao-passkey-backup.hbv')}
  paths=[x['path'] for x in plan['directories']]+[x['path'] for x in plan['files']];assert len(paths)==len(set(paths))==12
  for path in paths:
   assert path==DIRECTORY or path.startswith(DIRECTORY+'/')
   for alias in (path,path.replace('/sdcard/','/storage/emulated/0/',1)):
    q=d.adb_call('shell','if [ -e '+alias+' ] || [ -L '+alias+' ]; then printf EXISTS; else printf ABSENT; fi')
    assert q.returncode==0 and q.stdout==b'ABSENT' and not q.stderr
    assert d.shell('content','query','--uri','content://media/external/file','--projection','_id','--where',"_data='"+alias+"'")=='No result found.'
  for prefix in (DIRECTORY,DIRECTORY.replace('/sdcard/','/storage/emulated/0/',1)):
   assert d.shell('content','query','--uri','content://media/external/file','--projection','_id','--where',"_data LIKE '"+prefix+"/%'")=='No result found.'
  assert {p.name for p in (BASE/'stage-invocations').iterdir()}=={stage+'.intent.public.json' for stage in (*STAGES,'RELEASE')}
  terminal=[]
  for stage in STAGES:
   folder=BASE/'runtime-observations'/stage
   request_raw=live.private_file(folder/'request.public.json',1048576)
   launch_raw=live.private_file(folder/'launch.tool-original.json',1048576)
   status_raw=live.private_file(folder/'terminal.tool-original.json',1048576)
   request=json.loads(request_raw);launch=native(json.loads(launch_raw));status=native(json.loads(status_raw))
   assert request['host']=='pocket4' and request['executable']=='/usr/bin/python3'
   assert request['args'][:5]==['-I','-B',str(BASE/'execute-workflow.py'),'--stage',stage]
   assert launch['job']['host']=='pocket4' and launch['job']['id']==status['job_id'] and launch['job']['args']==request['args']
   assert status['state'] in ('succeeded','failed','cancelled','timed_out') and status['output_complete'] is True and status['output_durable'] is True
   out=live.private_file(folder/'stdout.original',1048576);err=live.private_file(folder/'stderr.original',1048576)
   assert len(out)==status['log_bytes']['stdout']['stored'] and len(err)==status['log_bytes']['stderr']['stored']
   if stage=='RP':
    assert status['state']=='cancelled' and status['exit_code']==0 and not err
    assert out==b'{"device_qualified":false,"port":38491,"status":"synthetic_rp_ready"}\n{"status":"synthetic_rp_stopped"}\n'
   terminal.append({'stage':stage,'job_id':status['job_id'],'state':status['state'],'exit_code':status['exit_code'],'output_durable':True,'output_complete':True,'launch_audit_recorded':launch.get('audit_recorded'),'request_sha256':sha(request_raw),'launch_sha256':sha(launch_raw),'terminal_sha256':sha(status_raw),'stdout_sha256':sha(out),'stderr_sha256':sha(err)})
  assert len({x['job_id'] for x in terminal})==len(STAGES)
  with socket.socket() as s:s.settimeout(3);assert s.connect_ex(('127.0.0.1',38491))!=0
  ledger_raw=live.private_file(BASE/'case-results.public.json',4*1048576);ledger=json.loads(ledger_raw)
  assert ledger['expected']==18 and [x['id'] for x in ledger['cases']]==[x['id'] for x in json.loads(profile_raw)['cases']]
  counts={k:sum(x['status']==k for x in ledger['cases']) for k in ('passed','failed','blocked','missing')}
  assert counts['missing']==0 and sum(counts.values())==18 and all(ledger[k]==v for k,v in counts.items())
  assert ledger['executed']==sum(bool(x['executed']) for x in ledger['cases']) and ledger['previous_run_results_inherited'] is False and ledger['supplemental_cases_merged']==0
  cleanup_raw=live.private_file(ROOT/'cleanup.result.public.json',1048576);cleanup=json.loads(cleanup_raw)
  assert cleanup['ok'] is True and cleanup['owned_document_count']==8 and cleanup['owned_directory_count']==4 and ledger['cleanup_sha256']==sha(cleanup_raw)
  assert next(x for x in ledger['cases'] if x['id']=='M07')['status']=='passed'
  value={'schema':1,'ok':True,'released':True,'candidate':'r9','scope':'independent_readonly_phone_absence_recheck_after_actual_cleanup',
   'device_sha256':live.DEVICE_SHA256,'settings_match_original':True,'settings_sha256':{k:sha(v.encode()) for k,v in settings.items()},
   'owned_packages_absent_including_retained':True,'owned_reverse_absent':True,'owned_documents_and_media_index_absent':True,
   'owned_files_count':8,'owned_directories_count':4,'rp_stop_observed_before_document_cleanup':True,'rp_port_closed':True,
   'all_prior_phone_jobs_terminal':terminal,'expected':18,'executed':ledger['executed'],**counts,
   'fixed_profile_all_passed':counts['passed']==18,'previous_run_results_inherited':False,'supplemental_cases_merged':0,
   'cleanup_sha256':sha(cleanup_raw),'case_ledger_sha256':sha(ledger_raw),'profile_sha256':PROFILE,
   'M05_actual_runtime_launch_audit_observations':[x for x in terminal if x['stage'] in ('M05_RESET','M05_RESTORE')],
   'same_physical_device_recovery_only':True,'credential_entry':'synthetic_only_adb_input_text_child_argv','p4_qualified':False,'production_qualified':False,'released_unix_ns':time.time_ns()}
  live.atomic(BASE/'release-r9.public.json',value)
  print(json.dumps({'ok':True,'release_path':str(BASE/'release-r9.public.json'),'release_sha256':sha((BASE/'release-r9.public.json').read_bytes()),'expected':18,'executed':ledger['executed'],**counts,'prior_jobs_terminal':len(terminal),'no_product_actions_in_this_recheck':True},sort_keys=True),flush=True)
 finally:os.close(lock)
if __name__=='__main__':main()
