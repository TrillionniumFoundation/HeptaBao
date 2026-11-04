import gzip,hashlib,io,json,os,shlex,stat,subprocess,tarfile
from pathlib import Path
root=Path('/Volumes/T5/hepta-vnext-recovery-20261013/authbus-current-source-61ff8bef-20261104-r1')
names=['result.public.json','stage.public.json','current-auth-rows-r1/result.public.json','current-auth-rows-r1/custody.public.json','native-profile2-selector-r1/result.public.json','current-auth-rows.intent.public.json','current-auth-rows-custody.intent.public.json','native-profile2-selector.intent.public.json','native-profile2-selector-r1/provider-read-intent.public.json','native-profile2-selector-r1/linked-prior-provider-read.public.json','native-profile2-selector-r1/consumer-initial/result.public.json','native-profile2-selector-r1/consumer-initial/rollback-result.public.json','native-profile2-selector-r1/consumer-cold-new-process/result.public.json','native-profile2-selector-r1/consumer-cold-new-process/rollback-result.public.json']
docs=json.loads((root/'current-auth-rows-r1/captured-auth-rows.private.json').read_bytes())
secrets=[]
for doc in docs:
 for pid,cred in json.loads(doc['rows']['store'][0][1])['profiles'].items():
  secrets.append(pid.encode())
  secrets.extend(v.encode() for k,v in cred.items() if k in ('key','token','access','refresh','idToken','accountId','email') and isinstance(v,str) and len(v)>=8)
native=json.loads(Path('/Users/qianqi/.codex/auth.json').read_bytes())
secrets.extend(v.encode() for v in native.get('tokens',{}).values() if isinstance(v,str) and len(v)>=8)
files={}
manifest={}
for name in names:
 p=root/name;i=p.lstat();assert stat.S_ISREG(i.st_mode) and i.st_uid==os.geteuid() and i.st_nlink==1 and not p.is_symlink()
 b=p.read_bytes();json.loads(b)
 assert all(s not in b for s in secrets if len(s)>=8)
 files[name]=b;manifest[name]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
configs={str(root/n/'server/server.json') for n in ('current-auth-rows-r1','native-profile2-selector-r1')}
remaining=[]
for line in subprocess.check_output(['/bin/ps','-axo','pid=,command='],text=True).splitlines():
 cols=line.strip().split(None,1)
 if len(cols)!=2:continue
 try:a=shlex.split(cols[1])
 except ValueError:continue
 if len(a)==3 and a[1]=='--config' and a[2] in configs:remaining.append(int(cols[0]))
assert not remaining
def enc(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def put(path,b):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
audit={'schema':'heptabao.normal33-current-source-public-export.v1','files':manifest,'sourceCredentialAndIdentityBytesAbsent':True,'ownedServersRemainingAtExport':remaining}
files['export-manifest.public.json']=enc(audit)
mem=io.BytesIO()
with gzip.GzipFile(fileobj=mem,mode='wb',mtime=0) as gz:
 with tarfile.open(fileobj=gz,mode='w') as tf:
  for n,b in files.items():
   t=tarfile.TarInfo(n);t.size=len(b);t.mode=0o600;t.mtime=0;tf.addfile(t,io.BytesIO(b))
data=mem.getvalue()
put(root/'complete-public-evidence-r1.tar.gz',data);put(root/'export-manifest.public.json',files['export-manifest.public.json'])
outer=json.loads(files['result.public.json']);rows=json.loads(files['current-auth-rows-r1/result.public.json']);custody=json.loads(files['current-auth-rows-r1/custody.public.json']);selector=json.loads(files['native-profile2-selector-r1/result.public.json'])
print(json.dumps({'ok':outer['ok'],'archiveBytes':len(data),'archiveSha256':hashlib.sha256(data).hexdigest(),'files':manifest,'outerChecks':len(outer['checks']),'rowsChecks':len(rows['checks']),'rowPhases':[{'phase':p['case'],'ok':p['ok'],'checks':len(p.get('checks',[]))} for p in rows['phases']],'selectorChecks':len(selector['checks']),'selectorPhases':[{'phase':p['phase'],'ok':p['ok'],'checks':len(p.get('checks',[]))} for p in selector['phases']],'allOwnedServersStopped':outer.get('allOwnedServersStopped'),'ownedServersRemainingAtExport':remaining,'frozenInputsUnchangedAtExit':outer.get('frozenInputsUnchangedAtExit'),'custody':custody,'providerReadPerformedThisRun':selector.get('providerReadPerformedThisRun'),'providerLink':selector.get('providerValidationLink')}))
