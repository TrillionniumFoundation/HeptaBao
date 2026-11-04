import os,sys,pathlib,json,hashlib,stat
os.umask(0o077)
root=pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-native-writer-61ff8bef-baseline-r1')
raw=sys.stdin.buffer.read(1048577);assert len(raw)<=1048576
x=json.loads(raw);assert x['schema']=='heptabao.native-retirement-isolated-stage-input.v1' and x['candidateMode']=='baseline'
assert set(x['files'])=={'consumer.mjs','native_lifecycle.mjs','driver.py','launcher.py','provider-proof.public.json'}
sha=lambda b:hashlib.sha256(b).hexdigest()
EXPECTED_INPUT_SHA256='971052cef47d440f5a26bdf0d6c03d8d4b7e1d4c479db619c533ea30d57cb1f6'
assert sha(raw)==EXPECTED_INPUT_SHA256
assert not root.exists()
def file_sha(p):
 h=hashlib.sha256()
 with pathlib.Path(p).open('rb')as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode)and s.st_size<=536870912
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
  t=os.fstat(f.fileno());assert(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns,t.st_ctime_ns)
 return h.hexdigest()
for p,h in x['sourcePins'].items():assert file_sha(p)==h,p
for name,b in x['files'].items():assert sha(b.encode())==x['filePins'][name]
assert str(pathlib.Path('/usr/bin/node').resolve(strict=True))==x['native']['nodeRealpath']
root.mkdir(mode=0o700);control=root/'control';control.mkdir(mode=0o700)
def put(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(b);f.flush();os.fsync(f.fileno())
 d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(d)
 finally:os.close(d)
 return sha(b)
pins=dict(x['sourcePins'])
for name,b in x['files'].items():pins[str(control/name)]=put(control/name,b.encode())
stage={'schema':'heptabao.native-retirement-isolated-stage.v1','ok':True,'candidateMode':'baseline','native':x['native'],
 'knownConcurrentBuild':x['knownConcurrentBuild'],'pins':pins,'payloadSha256':sha(raw),'productionChanged':False,
 'providerCalled':False,'serverStarted':False,'nativeStarted':False,'productionPluginInstalled':False}
b=json.dumps(stage,sort_keys=True,separators=(',',':')).encode()
h=put(control/'stage.public.json',b)
print(json.dumps({'ok':True,'stage':str(control/'stage.public.json'),'sha256':h,'pins':len(pins),'nativeStarted':False,'serverStarted':False}))
