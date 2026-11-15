#!/usr/bin/env python3
"""Persist original operator request/tool/stream bytes; no device or product calls."""
import argparse,base64,hashlib,json,os,re,stat,sys,time
from pathlib import Path
BASE=Path('/home/alex/HeptaBaoPasskey-20261106-r9')
NAMES=('request.public.json','launch.tool-original.json','terminal.tool-original.json','stdout.original','stderr.original')
STAGES=('RP','SETUP','DOCUMENTS','M01','M02','M03','M04','M05_OBSERVE','M05_RESET','M05_RESTORE','M06','G11_RECOVERY_EXPORT','G11_OBSERVE','G11_RESET','G11_STALE','G02_G06','G07','SAF_GUARDS','M07_RESTORE','M07_CLEANUP','RELEASE')
def sha(b):return hashlib.sha256(b).hexdigest()
def sync(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def private(path,directory=False):
 s=path.lstat();assert s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==(0o700 if directory else 0o600)
 assert stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink==1
def native(v):
 if 'reply' in v:v=v['reply']
 if 'result' in v and isinstance(v['result'],dict) and 'value' in v['result']:v=v['result']['value']
 if 'content' in v:
  assert v.get('isError') is not True
  texts=[x['text'] for x in v['content'] if x.get('type')=='text'];assert len(texts)==1
  return json.loads(texts[0])
 return v
def validate(stage,data):
 assert set(data)==set(NAMES)
 request=json.loads(data[NAMES[0]]);launch=native(json.loads(data[NAMES[1]]));terminal=native(json.loads(data[NAMES[2]]))
 assert request['host']=='pocket4' and request['executable']=='/usr/bin/python3' and 'stdin' not in request and not request.get('env')
 assert request['args'][:5]==['-I','-B',str(BASE/'execute-workflow.py'),'--stage',stage]
 assert request['idempotency_key'].startswith('hb-passkey-r9-') and launch['job']['idempotency_key']==request['idempotency_key']
 assert launch['job']['host']=='pocket4' and launch['job']['execution_mode']=='operator' and launch['job']['executable']==request['executable'] and launch['job']['args']==request['args']
 assert terminal['job_id']==launch['job']['id'] and re.fullmatch(r'[a-z0-9-]{8,96}',terminal['job_id'])
 assert terminal['state'] in ('succeeded','failed','cancelled','timed_out') and terminal['output_durable'] is True and terminal['output_complete'] is True
 assert len(data['stdout.original'])==terminal['log_bytes']['stdout']['stored'] and len(data['stderr.original'])==terminal['log_bytes']['stderr']['stored']
 return launch,terminal
def main():
 os.umask(0o077);ap=argparse.ArgumentParser();ap.add_argument('--stage',choices=STAGES,required=True);a=ap.parse_args()
 private(BASE,True);parent=BASE/'runtime-observations';private(parent,True)
 raw=sys.stdin.buffer.read(1048577);assert 0<len(raw)<=1048576
 payload=json.loads(raw);assert set(payload)=={'schema','files'} and payload['schema']==1 and set(payload['files'])==set(NAMES)
 data={name:base64.b64decode(payload['files'][name],validate=True) for name in NAMES};assert sum(map(len,data.values()))<=740000
 launch,terminal=validate(a.stage,data)
 target=parent/a.stage;target.mkdir(mode=0o700,exist_ok=False);sync(parent)
 rows=[]
 for name in NAMES:
  b=data[name];fd=os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
  rows.append({'path':name,'bytes':len(b),'sha256':sha(b)})
 sync(target)
 manifest={'schema':1,'scope':'original_runtime_records_host_only_capture','stage':a.stage,'job_id':terminal['job_id'],
  'launch_audit_recorded':launch.get('audit_recorded'),'actual_terminal_state':terminal['state'],'files':rows,'no_adb':True,'no_product_execution':True,'captured_unix_ns':time.time_ns()}
 b=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode();fd=os.open(target/'manifest.public.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 sync(target);print(json.dumps({'ok':True,'stage':a.stage,'job_id':terminal['job_id'],'manifest_path':str(target/'manifest.public.json'),'manifest_sha256':sha(b),'bytes':sum(map(len,data.values())),'no_adb':True},sort_keys=True))
if __name__=='__main__':main()
