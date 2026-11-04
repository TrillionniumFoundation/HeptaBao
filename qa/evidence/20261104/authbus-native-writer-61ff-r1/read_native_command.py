import os,pathlib,stat,hashlib,json,base64,zlib,platform
base=pathlib.Path('/home/qian-qi/.openclaw/runtime/openai-codex-0.159.2')
command=base/'node_modules/.bin/codex';launcher=command.resolve(strict=True);assert launcher.is_relative_to(base)
def sha_file(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode)and s.st_size<=536870912
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
  t=os.fstat(f.fileno());assert(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns,t.st_ctime_ns)
 return h.hexdigest(),s.st_size
public=[]
for p in [launcher,base/'node_modules/@openai/codex/package.json']:
 h,size=sha_file(p);assert size<262144;public.append({'path':str(p),'sha256':h,'bytes':size,'text':p.read_text()})
pkg=json.loads(public[1]['text']);assert pkg['version']=='0.159.2'
candidates=sorted(set(base.glob('node_modules/@openai/codex*/vendor/*/codex/codex')));assert 1<=len(candidates)<=8
bins=[]
for p in candidates:
 real=p.resolve(strict=True);assert real.is_relative_to(base)
 h,size=sha_file(real);bins.append({'path':str(p),'realpath':str(real),'sha256':h,'bytes':size})
r={'schema':'heptabao.rog-native-command-public-pin-readonly.v1','productionChanged':False,'providerCalled':False,'nativeStarted':False,'architecture':platform.machine(),'command':str(command),'launcher':str(launcher),'packageVersion':pkg['version'],'publicSources':public,'nativeBinaryCandidates':bins}
raw=json.dumps(r,sort_keys=True,separators=(',',':')).encode();z=zlib.compress(raw,9)
print(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'dataBase64':base64.b64encode(z).decode()},separators=(',',':')))
