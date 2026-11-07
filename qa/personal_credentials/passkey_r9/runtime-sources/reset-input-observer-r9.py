#!/usr/bin/env python3
"""Observe existing r9 backup inputs for a peer review; never clear application data."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import time
import urllib.request

BASE=Path('/home/alex/HeptaBaoPasskey-20261106-r9')
ROOT=BASE/'live-r9'
BUILD='97a6daec5bb7276b935498fb3c8501df9ecc57a118641cffb9f2df3ae6edd009'
DRIVER='e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd'
HELPER='c3d7da8f20fd03b7463eb59ad846718bcae5cad1668972eb626a7fd368aa4d30'
PROFILE_SOURCE='00e999af6c17c83fd81736fe8a8b5cda3553daaa6acf97fd652b7e6429751dd7'
PROFILE_PUBLIC='b6b7754bad0e34cf55b0c2635683b03093555fa5d3f096533ee36b3e02eec55b'
PROVIDER='b16e82916330fac6909f82696089798c3ec76d7b4058fe9290e7e841b9e00459'
RP='386de84bb5335f21998a000b4a1267eaa17fadbde1e1753d5df1c30325709a63'
EXPORTS={
 'M05':('M04','m04-backup-verified.private.json','m05-rp-before.private.json','M04-ordinary-saf-backup-r9.py','c49ec9c5473ce911c9df63066c6a49258f69b9bc9ca62846317765a88aa8d2c6',1),
 'G11':('G11_RECOVERY_EXPORT','g11-current-backup.private.json','g11-rp-before.private.json','G11-current-ordinary-saf-backup-r9.py','6572507dfb9bdbea1af5285e59fd4574d7c9a29a54b51ac79a6022d7468e7e47',2),
}
def sha(b):return hashlib.sha256(b).hexdigest()
def write(path,b):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def module(path,digest,name):
 assert sha(path.read_bytes())==digest
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def native(value):
 if 'reply' in value:value=value['reply']
 if 'result' in value and isinstance(value['result'],dict) and 'value' in value['result']:value=value['result']['value']
 if 'content' in value:
  assert value.get('isError') is not True
  texts=[x['text'] for x in value['content'] if x.get('type')=='text'];assert len(texts)==1
  return json.loads(texts[0])
 return value
def runtime_evidence(live,stage,source_file,source_hash,dispatcher_hash):
 assert re.fullmatch(r'[0-9a-f]{64}',dispatcher_hash)
 dispatcher=BASE/'execute-workflow.py';dispatcher_raw=live.private_file(dispatcher,131072);assert sha(dispatcher_raw)==dispatcher_hash
 intent_path=BASE/'stage-invocations'/(stage+'.intent.public.json')
 intent_raw=live.private_file(intent_path,65536);intent=json.loads(intent_raw)
 assert intent['schema']==1 and intent['stage']==stage and intent['source_sha256']==source_hash and intent['dispatcher_sha256']==dispatcher_hash
 assert intent['argv']==['/usr/bin/python3','-I','-B',str(source_file)] and intent['unknown_result_must_not_be_reissued'] is True and intent['case_passed_by_dispatch'] is False
 folder=BASE/'runtime-observations'/stage
 live.private_directory(folder)
 names=['request.public.json','launch.tool-original.json','terminal.tool-original.json','stdout.original','stderr.original']
 data={name:live.private_file(folder/name,1048576) for name in names}
 request=json.loads(data[names[0]]);launch=native(json.loads(data[names[1]]));terminal=native(json.loads(data[names[2]]))
 assert request['host']=='pocket4' and request['executable']=='/usr/bin/python3'
 assert request['args']==['-I','-B',str(BASE/'execute-workflow.py'),'--stage',stage]
 assert 'stdin' not in request and request['idempotency_key'].startswith('hb-passkey-r9-')
 assert launch['job']['host']=='pocket4' and launch['job']['execution_mode']=='operator' and launch['job']['args']==request['args']
 assert launch['job']['executable']==request['executable'] and launch['job']['idempotency_key']==request['idempotency_key']
 job=launch['job']['id'];assert re.fullmatch(r'[a-z0-9-]{8,96}',job) and terminal['job_id']==job
 assert terminal['state']=='succeeded' and terminal['exit_code']==0 and terminal['output_durable'] is True and terminal['output_complete'] is True
 assert terminal.get('timed_out',False) is False and terminal.get('cancelled',False) is False and terminal.get('automatic_retry',False) is False
 assert len(data['stdout.original'])==terminal['log_bytes']['stdout']['stored'] and terminal['log_bytes']['stderr']['stored']==len(data['stderr.original'])==0
 assert sha(live.private_file(source_file,131072))==source_hash
 return {'job_id':job,'launch_audit_recorded':launch.get('audit_recorded'),'request_digest':launch['job']['request_digest'],
         'source_sha256':source_hash,'dispatcher_sha256':dispatcher_hash,'dispatch_intent_sha256':sha(intent_raw),
         'files':[{'path':str(folder/name),'bytes':len(b),'sha256':sha(b)} for name,b in data.items()]+[{'path':str(p),'bytes':len(b),'sha256':sha(b)} for p,b in ((intent_path,intent_raw),(dispatcher,dispatcher_raw))]}
def main():
 os.umask(0o077);ap=argparse.ArgumentParser();ap.add_argument('--case-id',choices=('M05','G11'),required=True);ap.add_argument('--expected-dispatcher-sha256',required=True);args=ap.parse_args();case=args.case_id
 live=module(BASE/'passkey_live.r9.py',DRIVER,'live_r9_observer');helper=module(BASE/'passkey_reset_provider_r9.py',HELPER,'reset_r9_observer')
 for p in (BASE,ROOT,BASE/'artifacts'):live.private_directory(p)
 assert sha(live.private_file(ROOT/'profile.public.json',1048576))==PROFILE_PUBLIC
 assert sha(live.private_file(BASE/'passkey_phone_profile.r9.py',131072))==PROFILE_SOURCE
 stage,receipt_leaf,snapshot_leaf,source_leaf,source_hash,count=EXPORTS[case]
 source_file=BASE/'runtime-sources'/source_leaf
 runtime=runtime_evidence(live,stage,source_file,source_hash,args.expected_dispatcher_sha256)
 lock=os.open(ROOT/'driver.lock',os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  buildraw=live.private_file(BASE/'artifacts/build.receipt.json',1048576);assert sha(buildraw)==BUILD;build=json.loads(buildraw)
  journalraw=live.private_file(ROOT/'journal.private.json',8*1048576);journal=json.loads(journalraw);live.validate_journal(journal,build,BUILD)
  previous=helper.reset_history(live,ROOT,case,build,BUILD)
  checkpoint_path=ROOT/('provider-reset-'+case+'-checkpoint.private.json')
  assert not checkpoint_path.exists() and not (ROOT/snapshot_leaf).exists() and not (ROOT/(case+'-checkpoint-provenance.public.json')).exists()
  result_raw=live.private_file(ROOT/(stage+'-result.public.json'),1048576);result=json.loads(result_raw)
  assert result['status']=='passed' and result['ordinary_saf_export'] is True and result['provider_write_readback_verified'] is True
  receipt_raw=live.private_file(ROOT/receipt_leaf,65536);receipt=json.loads(receipt_raw)
  assert result['backup_receipt_sha256']==sha(receipt_raw) and result['backup']==receipt['observed_backup']
  before=live.private_file(ROOT/(stage+'-rp-before.public.json'),1048576);after=live.private_file(ROOT/(stage+'-rp-after.public.json'),1048576)
  assert before==after and sha(before)==receipt['rp_before_sha256']==receipt['rp_after_sha256']
  with urllib.request.urlopen('http://127.0.0.1:38491/state',timeout=5) as response:
   assert response.status==200;current=response.read(1048577)
  assert len(current)<=1048576 and current==before
  rp=json.loads(current);assert rp['credential_count']==1 and rp['credentials'][0]==receipt['credential'] and rp['credentials'][0]['sign_count']==count
  device=live.Device(Path('/home/alex/.local/bin/adb'))
  settings={k:device.setting(k) for k in live.SETTING_KEYS};assert settings==journal['owned_settings']
  assert device.package_hash(live.PROVIDER)==PROVIDER
  backup=receipt['observed_backup'];helper.validate_recovery_backup(backup,case)
  assert device.shell('test','!','-L',backup['device_path'])==''
  assert device.shell('readlink','-f',backup['device_path'])==backup['device_path'].replace('/sdcard/','/storage/emulated/0/',1)
  assert helper.backup_observation(device,backup)=={k:backup[k] for k in ('bytes','sha256')}
  stale=None;prior_sha=None;history_paths=[]
  if case=='G11':
   assert previous is not None
   oldcpraw=live.private_file(ROOT/'provider-reset-M05-checkpoint.private.json',65536);oldcp=json.loads(oldcpraw)
   assert sha(oldcpraw)==previous['intent']['input_sha256']['checkpoint']
   stale={'backup':oldcp['recovery_backup'],'credential':oldcp['credential'],'source_reset_result_sha256':previous['result_sha256']}
   helper.validate_stale_input(stale,backup,rp['credentials'][0],previous)
   assert device.shell('test','!','-L',stale['backup']['device_path'])==''
   assert device.shell('readlink','-f',stale['backup']['device_path'])==stale['backup']['device_path'].replace('/sdcard/','/storage/emulated/0/',1)
   assert helper.backup_observation(device,stale['backup'])=={k:stale['backup'][k] for k in ('bytes','sha256')}
   prior_sha=previous['result_sha256']
   history_paths=[ROOT/x for x in ('provider-reset-M05-checkpoint.private.json','provider-reset-M05-intent.private.json','provider-reset-M05-result.public.json','provider-reset-M05-completion.public.json','M05-result.public.json','M05-new-process.public.json','M06-result.public.json','M06-rp-before.public.json','M06-rp-after.public.json')]
  old_pid=helper.provider_pid(device);assert type(old_pid) is str and re.fullmatch(r'[1-9][0-9]{0,8}',old_pid)
  checkpoint={'schema':1,'scope':'same_device_synthetic_provider_reset','case_id':case,'reset_id':case+'-reset-1',
   'device_sha256':live.DEVICE_SHA256,'build_receipt_sha256':BUILD,'provider_apk_sha256':PROVIDER,
   'profile_source_sha256':PROFILE_SOURCE,'profile_public_sha256':PROFILE_PUBLIC,'rp_source_sha256':RP,
   'recovery_backup':backup,'backup_receipt_file':receipt_leaf,'backup_receipt_sha256':sha(receipt_raw),
   'rp_snapshot_file':snapshot_leaf,'rp_snapshot_sha256':sha(current),'credential':rp['credentials'][0],
   'prior_reset_result_sha256':prior_sha,'stale_input':stale,'created_unix_ns':time.time_ns()}
  helper.validate_inputs(live,build,BUILD,journal,checkpoint,receipt,rp,case)
  docsraw=live.private_file(ROOT/'documents.private.json',65536);docs=json.loads(docsraw)
  assert docs['initial_directory_absent'] is True and docs['directory']=='/sdcard/Download/HeptaBao-Passkey-QA-20261106-r9'
  entries=[x for x in docs['files'] if x['path']==backup['device_path']];assert len(entries)==1
  assert entries[0]['initial_absent'] is True and entries[0]['written'] is True and entries[0]['sha256']==backup['sha256'] and entries[0]['bytes']==backup['bytes']
  matches=[]
  for path in sorted((BASE/'attempts').glob('*.result.public.json')):
   raw=live.private_file(path,1048576);event=json.loads(raw)
   if event['case']==('M04' if case=='M05' else 'G11') and event['phase']=='inspect' and event['exit_code']==0:
    if any(n.get('text')=='Encrypted backup written and read-back verified' for n in event.get('result',{}).get('nodes',[])):
     if event['finished_unix_ns']<=receipt['completed_unix_ns'] and event['started_unix_ns']>=json.loads(live.private_file(ROOT/(stage+'-workflow.intent.public.json'),65536))['created_unix_ns']:
      matches.append((path,raw,event))
  assert len(matches)==1;event_path,event_raw,event=matches[0]
  write(ROOT/snapshot_leaf,current);write(checkpoint_path,encoded(checkpoint))
  proof={'schema':1,'scope':'actual_r9_case_inputs_for_independent_review_no_reset','case_id':case,'reset_executed':False,
   'helper_sha256':HELPER,'checkpoint_path':str(checkpoint_path),'checkpoint_sha256':sha(checkpoint_path.read_bytes()),
   'backup_receipt_sha256':sha(receipt_raw),'rp_snapshot_sha256':sha(current),'current_backup_rechecked':backup,
   'stale_input':stale,'old_provider_pid_observed_nonempty':True,'old_provider_pid_count':1,'old_provider_pid_sha256':sha(old_pid.encode()),
   'provider_apk_sha256':PROVIDER,'current_three_settings_match_owned_journal':True,'current_settings_sha256':{k:sha(v.encode()) for k,v in settings.items()},
   'private_run_journal_sha256':sha(journalraw),'documents_journal_sha256':sha(docsraw),'synthetic_directory_initial_absent':True,
   'actual_export_runtime':runtime,'actual_UI_event_path':str(event_path),'actual_UI_event_sha256':sha(event_raw),
   'actual_UI_event_started_unix_ns':event['started_unix_ns'],'actual_UI_event_finished_unix_ns':event['finished_unix_ns'],
   'observed_unix_ns':time.time_ns(),'requires_independent_case_go':True,'phone_case_passed':False}
  proof_path=ROOT/(case+'-checkpoint-provenance.public.json');write(proof_path,encoded(proof))
  leaves=[checkpoint_path,ROOT/receipt_leaf,ROOT/snapshot_leaf,ROOT/(stage+'-rp-before.public.json'),ROOT/(stage+'-rp-after.public.json'),ROOT/(stage+'-workflow.intent.public.json'),ROOT/(stage+'-picker-target.public.json'),ROOT/(stage+'-result.public.json'),ROOT/'documents-prepared.public.json',proof_path,source_file,event_path]+history_paths
  rows=[{'path':str(p),'bytes':len(live.private_file(p,1048576)),'sha256':sha(live.private_file(p,1048576))} for p in leaves]+runtime['files']
  assert len(rows)==len({x['path'] for x in rows})
  index={'schema':1,'scope':'explicit_reset_input_and_public_provenance_whitelist','files':rows,'does_not_include_password_private_key_backup_or_private_run_journal':True,'reset_executed':False}
  index_path=ROOT/(case+'-inputs-index.public.json');write(index_path,encoded(index))
  print(json.dumps({'case_id':case,'checkpoint_path':str(checkpoint_path),'checkpoint_sha256':sha(checkpoint_path.read_bytes()),'index_path':str(index_path),'index_sha256':sha(index_path.read_bytes()),'files':len(rows),'helper_sha256':HELPER,'reset_executed':False,'requires_independent_case_go':True},sort_keys=True))
 finally:os.close(lock)
if __name__=='__main__':main()
