#!/usr/bin/env python3
"""Complete-run cleanup of the exact r9 owned files after core restore and RP stop."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path,PurePosixPath
import re
import socket
import stat
import time

BASE=Path('/home/alex/HeptaBaoPasskey-20261106-r9');ROOT=BASE/'live-r9'
DRIVER='e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd'
BUILD='97a6daec5bb7276b935498fb3c8501df9ecc57a118641cffb9f2df3ae6edd009'
PROFILE='b6b7754bad0e34cf55b0c2635683b03093555fa5d3f096533ee36b3e02eec55b'
RP='386de84bb5335f21998a000b4a1267eaa17fadbde1e1753d5df1c30325709a63'
SEED='bb527d9aa00987a243b378ac31eb15d2caf203e106348a8e1ed60cff7f674917'
DIRECTORY='/sdcard/Download/HeptaBao-Passkey-QA-20261106-r9'
DIRS=[DIRECTORY,DIRECTORY+'/latest-recovery',DIRECTORY+'/G08-target',DIRECTORY+'/G10-target']
LEAF='HeptaBao-passkey-backup.hbv';SEED_LEAF='heptabao-passkey-qa-r9-seed.hbv'
def sha(b):return hashlib.sha256(b).hexdigest()
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def create(path,b):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def native(v):
 if 'reply' in v:v=v['reply']
 if 'result' in v and isinstance(v['result'],dict) and 'value' in v['result']:v=v['result']['value']
 if 'content' in v:
  assert v.get('isError') is not True
  texts=[x['text'] for x in v['content'] if x.get('type')=='text'];assert len(texts)==1
  return json.loads(texts[0])
 return v
def prior_job(live,stage):
 folder=BASE/'runtime-observations'/stage
 launch_raw=live.private_file(folder/'launch.tool-original.json',1048576)
 terminal_raw=live.private_file(folder/'terminal.tool-original.json',1048576)
 launch=native(json.loads(launch_raw));terminal=native(json.loads(terminal_raw))
 assert launch['job']['host']=='pocket4' and launch['job']['id']==terminal['job_id']
 assert terminal['state'] in ('succeeded','failed','cancelled','timed_out') and terminal['output_complete'] is True and terminal['output_durable'] is True
 return {'stage':stage,'job_id':terminal['job_id'],'state':terminal['state'],'exit_code':terminal['exit_code'],
         'launch_audit_recorded':launch.get('audit_recorded'),'launch_sha256':sha(launch_raw),'terminal_sha256':sha(terminal_raw)},terminal
def fixed_file(device,path,size,digest):
 fields=device.shell('stat','-c','%f %s',path).split()
 assert len(fields)==2 and stat.S_ISREG(int(fields[0],16)) and int(fields[1])==size
 assert device.shell('test','!','-L',path)=='' and device.shell('sha256sum',path).split()[0]==digest
 assert device.shell('readlink','-f',path)==path.replace('/sdcard/','/storage/emulated/0/',1)
def absent(device,path):
 q=device.adb_call('shell','if [ -e '+path+' ] || [ -L '+path+' ]; then printf EXISTS; else printf ABSENT; fi')
 assert q.returncode==0 and q.stdout==b'ABSENT' and not q.stderr
def media_absent(device,path):
 assert device.shell('content','query','--uri','content://media/external/file','--projection','_id','--where',"_data='"+path+"'")=='No result found.'
def backup_receipt(live,case,leaf):
 raw=live.private_file(ROOT/leaf,65536);receipt=json.loads(raw)
 result_raw=live.private_file(ROOT/(case+'-result.public.json'),1048576);result=json.loads(result_raw)
 assert result['status']=='passed' and result['backup_receipt_sha256']==sha(raw) and result['backup']==receipt['observed_backup']
 assert receipt['source_case_id']==case and receipt['ordinary_saf_export_observed'] is True and receipt['provider_write_readback_verified'] is True and receipt['build_receipt_sha256']==BUILD
 obj=receipt['observed_backup'];assert type(obj['bytes']) is int and 615<obj['bytes']<=8*1024*1024 and re.fullmatch(r'[0-9a-f]{64}',obj['sha256'])
 return obj,receipt
def main():
 os.umask(0o077);driver=BASE/'passkey_live.r9.py';assert sha(driver.read_bytes())==DRIVER
 spec=importlib.util.spec_from_file_location('live_r9_cleanup',driver);live=importlib.util.module_from_spec(spec);spec.loader.exec_module(live)
 for p in (BASE,ROOT,BASE/'artifacts'):live.private_directory(p)
 assert sha(live.private_file(ROOT/'profile.public.json',1048576))==PROFILE
 assert not (ROOT/'cleanup.result.public.json').exists() and not (ROOT/'documents.before-cleanup.private.json').exists()
 lock=os.open(ROOT/'driver.lock',os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  buildraw=live.private_file(BASE/'artifacts/build.receipt.json',1048576);assert sha(buildraw)==BUILD
  journal=json.loads(live.private_file(ROOT/'journal.private.json',8*1048576));live.validate_journal(journal,json.loads(buildraw),BUILD)
  device=live.Device(Path('/home/alex/.local/bin/adb'))
  assert all(v in ('restored_original','already_original') for v in journal['restoration'].values())
  settings={k:device.setting(k) for k in live.SETTING_KEYS};assert settings==journal['original_settings']
  assert all(device.package_hash(x) is None for x in live.OWNED)
  reverse=device.adb_call('reverse','--list');assert reverse.returncode==0 and not reverse.stderr and not any('tcp:38491' in x for x in reverse.stdout.decode().splitlines())
  rp_job,rp_terminal=prior_job(live,'RP')
  rp_stdout=live.private_file(BASE/'runtime-observations/RP/stdout.original',65536)
  rp_stderr=live.private_file(BASE/'runtime-observations/RP/stderr.original',65536)
  assert rp_terminal['state']=='cancelled' and rp_terminal['exit_code']==0 and rp_stderr==b''
  assert rp_stdout==b'{"device_qualified":false,"port":38491,"status":"synthetic_rp_ready"}\n{"status":"synthetic_rp_stopped"}\n'
  assert rp_terminal['log_bytes']['stdout']['stored']==len(rp_stdout) and rp_terminal['log_bytes']['stderr']['stored']==0
  with socket.socket() as s:s.settimeout(3);assert s.connect_ex(('127.0.0.1',38491))!=0
  old_ledger=live.private_file(BASE/'case-results.public.json',4*1048576);ledger=json.loads(old_ledger)
  profile=json.loads(live.private_file(ROOT/'profile.public.json',1048576))
  assert ledger['expected']==18 and [x['id'] for x in ledger['cases']]==[x['id'] for x in profile['cases']]
  for row in ledger['cases']:
   if row['id']=='M07':assert row['status']=='missing';continue
   assert row['status'] in ('passed','failed','blocked') and row['evidence']
   for e in row['evidence']:
    path=Path(e['path']);assert path.parent==ROOT and path.name==row['id']+'-result.public.json'
    raw=live.private_file(path,1048576);assert sha(raw)==e['sha256'] and json.loads(raw)['case']==row['id']
  m04,m04_receipt=backup_receipt(live,'M04','m04-backup-verified.private.json')
  latest,latest_receipt=backup_receipt(live,'G11_RECOVERY_EXPORT','g11-current-backup.private.json')
  assert m04['device_path']==DIRECTORY+'/'+LEAF and latest['device_path']==DIRECTORY+'/latest-recovery/'+LEAF
  assert m04['sha256']!=latest['sha256'] and m04_receipt['credential']['sign_count']<latest_receipt['credential']['sign_count']
  expected={p+'/'+SEED_LEAF:(615,SEED) for p in DIRS}
  for obj in (m04,latest):expected[obj['device_path']]=(obj['bytes'],obj['sha256'])
  for case in ('G08','G10'):
   baseline=json.loads(live.private_file(ROOT/(case+'-destination-baseline.public.json'),65536))
   path=DIRECTORY+'/'+case+'-target/'+LEAF
   assert baseline['file']=={'device_path':path,'bytes':615,'sha256':SEED}
   assert baseline['actual_ordinary_SAF_target_selection'] is True and baseline['product_Write_since_selection'] is False and baseline['QA_seeded_ciphertext_nonempty_baseline'] is True
   expected[path]=(615,SEED)
  assert len(expected)==8
  plan_raw=live.private_file(ROOT/'documents.private.json',65536);plan=json.loads(plan_raw)
  assert plan['device_sha256']==live.DEVICE_SHA256 and plan['directory']==DIRECTORY and plan['initial_directory_absent'] is True and plan['directory_created'] is True
  assert len(plan['directories'])==4 and {x['path'] for x in plan['directories']}==set(DIRS)
  assert all(x['initial_absent'] is True and x['mkdir_intent'] is True and x['created'] is True for x in plan['directories'])
  assert len(plan['files'])==8 and {x['path'] for x in plan['files']}==set(expected)
  for item in plan['files']:
   size,digest=expected[item['path']]
   assert item['initial_absent'] is True and item['write_intent'] is True and item['written'] is True and item['bytes']==size and item['sha256']==digest
   fixed_file(device,item['path'],size,digest)
  for path in DIRS:
   assert device.shell('test','-d',path)=='' and device.shell('test','!','-L',path)==''
   children={PurePosixPath(x).name for x in list(expected)+DIRS if x!=path and str(PurePosixPath(x).parent)==path}
   assert set(device.shell('ls','-A',path).splitlines())==children
  for name,obj in [('M04-phone-backup.hbv',m04),('G11_RECOVERY_EXPORT-phone-backup.hbv',latest)]:
   raw=live.private_file(BASE/'private'/name,8*1048576);assert len(raw)==obj['bytes'] and sha(raw)==obj['sha256']
  canonical=DIRECTORY.replace('/sdcard/','/storage/emulated/0/',1)
  for prefix in (DIRECTORY,canonical):
   allowed={x if prefix==DIRECTORY else x.replace('/sdcard/','/storage/emulated/0/',1) for x in list(expected)+DIRS if x!=DIRECTORY}
   value=device.shell('content','query','--uri','content://media/external/file','--projection','_id:_data','--where',"_data LIKE '"+prefix+"/%'")
   for line in ([] if value=='No result found.' else value.splitlines()):
    match=re.fullmatch(r'Row: \d+ _id=\d+, _data=(.+)',line);assert match and match.group(1) in allowed
  create(ROOT/'documents.before-cleanup.private.json',plan_raw)
  plan['cleanup_intent_unix_ns']=time.time_ns();plan['cleanup_exact_paths']=sorted(expected);plan['cleanup_exact_directories']=sorted(DIRS,key=len,reverse=True);live.atomic(ROOT/'documents.private.json',plan)
  for path in sorted(expected):
   size,digest=expected[path];fixed_file(device,path,size,digest);device.shell('rm','--',path)
   for alias in (path,path.replace('/sdcard/','/storage/emulated/0/',1)):
    absent(device,alias);device.shell('content','delete','--uri','content://media/external/file','--where',"_data='"+alias+"'");media_absent(device,alias)
  for path in sorted(DIRS,key=len,reverse=True):
   assert device.shell('test','-d',path)=='' and device.shell('test','!','-L',path)=='' and device.shell('readlink','-f',path)==path.replace('/sdcard/','/storage/emulated/0/',1) and device.shell('ls','-A',path)==''
   device.shell('rmdir',path)
   for alias in (path,path.replace('/sdcard/','/storage/emulated/0/',1)):
    absent(device,alias);device.shell('content','delete','--uri','content://media/external/file','--where',"_data='"+alias+"'");media_absent(device,alias)
  for prefix in (DIRECTORY,canonical):
   assert device.shell('content','query','--uri','content://media/external/file','--projection','_id','--where',"_data LIKE '"+prefix+"/%'")=='No result found.'
  assert {k:device.setting(k) for k in live.SETTING_KEYS}==journal['original_settings'] and all(device.package_hash(x) is None for x in live.OWNED)
  reverse=device.adb_call('reverse','--list');assert reverse.returncode==0 and not reverse.stderr and not any('tcp:38491' in x for x in reverse.stdout.decode().splitlines())
  rpraw=live.private_file(BASE/'rp-r9/result.manifest.json',1048576);rpmanifest=json.loads(rpraw);rp=rpmanifest['state'];state_raw=live.private_file(BASE/'rp-r9/state.public.json',8*1048576)
  assert rpmanifest['source_sha256']==RP and rpmanifest['state_sha256']==sha(state_raw)
  created=json.loads(live.private_file(ROOT/'M02-result.public.json',1048576))['rp_after']['credentials'][0]
  assert rp['credential_count']==1 and rp['counters']['registrations']==1 and rp['counters']['authentications']>=2
  assert all(rp['credentials'][0][k]==created[k] for k in ('credential_id','public_key_sha256'))
  audit=[]
  for stage in ('M05_RESET','M05_RESTORE'):
   observation,terminal=prior_job(live,stage);audit.append(observation)
  plan['cleanup_complete']=True;plan['cleaned_unix_ns']=time.time_ns();live.atomic(ROOT/'documents.private.json',plan)
  report={'schema':1,'ok':True,'scope':'r9_exact_synthetic_phone_cleanup','settings_match_original':True,
   'settings_sha256':{k:sha(v.encode()) for k,v in settings.items()},'packages_absent_including_retained':True,'owned_packages':sorted(live.OWNED),
   'reverse_absent':True,'owned_documents_absent':True,'owned_document_count':8,'owned_directory_count':4,'owned_media_index_absent':True,
   'media_alias_and_canonical_checked':True,'owned_directory_media_rows_checked':True,'M04_and_G11_current_ciphertext_private_captures_preserved':True,
   'credential_entry':'synthetic_only_adb_input_text_child_argv','rp':rp,'rp_last_manifest_sha256':sha(rpraw),
   'rp_port_closed':True,'rp_actual_stop_observed_before_cleanup':rp_job,'rp_stopped_stdout_sha256':sha(rp_stdout),
   'M05_actual_runtime_launch_audit_observations':audit,'production_qualified':False,'completed_unix_ns':time.time_ns()}
  create(ROOT/'cleanup.result.public.json',encoded(report));create(BASE/'case-results.before-cleanup.public.json',old_ledger)
  row=next(x for x in ledger['cases'] if x['id']=='M07');row.update(status='passed',executed=True,evidence=[{'path':str(ROOT/'cleanup.result.public.json'),'sha256':sha((ROOT/'cleanup.result.public.json').read_bytes())}])
  phases=[]
  for path in sorted((BASE/'attempts').glob('*.result.public.json')):
   raw=live.private_file(path,1048576);event=json.loads(raw);phases.append({'file':path.name,'sha256':sha(raw),'case':event['case'],'phase':event['phase'],'exit_code':event['exit_code'],'error':event.get('result',{}).get('error')})
  for k in ('passed','failed','blocked','missing'):ledger[k]=sum(x['status']==k for x in ledger['cases'])
  ledger['executed']=sum(bool(x['executed']) for x in ledger['cases'])
  def passed(case):return next(x for x in ledger['cases'] if x['id']==case)['status']=='passed'
  ledger.update(p4_qualified=False,production_qualified=False,fixed_profile_all_passed=ledger['passed']==18,
   credential_entry='synthetic_only_adb_input_text_child_argv',credential_manager_create_verified=passed('M02'),
   credential_manager_get_verified=passed('M03'),same_device_fresh_process_restore_verified=passed('M05') and passed('M06'),
   counter_rollback_rejection_verified=passed('G11'),phase_evidence=phases,failed_phase_attempts=[x for x in phases if x['exit_code']!=0],
   cleanup_sha256=sha((ROOT/'cleanup.result.public.json').read_bytes()),M05_actual_runtime_launch_audit_observations=audit,
   previous_run_results_inherited=False,supplemental_cases_merged=0,rp_final_public_state=rp)
  assert ledger['expected']==18 and sum(ledger[k] for k in ('passed','failed','blocked','missing'))==18 and ledger['missing']==0
  live.atomic(BASE/'case-results.public.json',ledger)
  print(json.dumps({'ok':True,'cleanup_path':str(ROOT/'cleanup.result.public.json'),'cleanup_sha256':sha((ROOT/'cleanup.result.public.json').read_bytes()),'ledger_path':str(BASE/'case-results.public.json'),'ledger_sha256':sha((BASE/'case-results.public.json').read_bytes()),'expected':18,'executed':ledger['executed'],'counts':{k:ledger[k] for k in ('passed','failed','blocked','missing')},'owned_files':8,'owned_directories':4,'M05_actual_runtime_launch_audit_observations':audit,'production_qualified':False},sort_keys=True))
 finally:os.close(lock)
if __name__=='__main__':main()
