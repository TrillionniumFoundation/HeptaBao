import hashlib,json,os,stat,subprocess
from pathlib import Path
root=Path('/Volumes/T5/hepta-vnext-recovery-20261013/authbus-mac-current-stage-20261103-r1/validation-r1')
docs=json.loads((root/'captured-auth-rows.private.json').read_bytes())
secrets=[]
for doc in docs:
 for credential in json.loads(doc['rows']['store'][0][1])['profiles'].values():
  secrets.extend(v.encode() for k,v in credential.items() if k in ('key','token','access','refresh') and isinstance(v,str) and len(v)>=8)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
datafiles=[p for p in (root/'server/data').rglob('*') if p.is_file()]
diagnostics=[p for p in root.rglob('*') if p.is_file() and (p.name.endswith(('.stdout','.stderr','.public.json')) or p.name in ('audit.jsonl','server.log'))]
def clean(paths):
 return all(all(secret not in p.read_bytes() for secret in secrets) for p in paths)
processes=subprocess.run(['/bin/ps','-axo','pid=,args='],capture_output=True,text=True,check=True).stdout.splitlines()
config=str(root/'server/server.json')
pids=[int(line.strip().split(None,1)[0]) for line in processes if config in line and 'heptabao-server' in line]
sensitive=[p for p in root.rglob('*') if p.is_file() and (p.name.endswith('.private.json') or p.name in ('openclaw-agent.sqlite','role_id','secret_id','ca.key','tls.key'))]
result={'schema':'heptabao.current-private-stage-custody.v1','ok':False,'driverReceiptSha256':sha(root/'result.public.json'),'driverReceiptPassed':json.loads((root/'result.public.json').read_bytes()).get('ok') is True,'encryptedDataFiles':len(datafiles),'encryptedDataBytes':sum(p.stat().st_size for p in datafiles),'encryptedDataNoSourceCredentialPlaintext':clean(datafiles),'diagnosticFiles':len(diagnostics),'diagnosticsNoSourceCredentialPlaintext':clean(diagnostics),'sensitivePrivateFiles':len(sensitive),'sensitiveFilesOwnerPrivateSingleLink':all(p.lstat().st_uid==os.geteuid() and stat.S_IMODE(p.lstat().st_mode)==0o600 and p.lstat().st_nlink==1 and not p.is_symlink() for p in sensitive),'stagingServerRemainingPids':pids,'productionChanged':False,'providerCalled':False}
result['ok']=result['driverReceiptPassed'] and result['encryptedDataNoSourceCredentialPlaintext'] and result['diagnosticsNoSourceCredentialPlaintext'] and result['sensitiveFilesOwnerPrivateSingleLink'] and not pids
path=root/'custody.public.json'
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as f:
 f.write(json.dumps(result,sort_keys=True,separators=(',',':')).encode());f.flush();os.fsync(f.fileno())
print(json.dumps(result))
raise SystemExit(0 if result['ok'] else 1)
