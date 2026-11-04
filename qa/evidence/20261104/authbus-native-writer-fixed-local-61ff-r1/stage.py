import os,sys,pathlib,json,hashlib,stat,subprocess
os.umask(0o077)
root=pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-native-writer-61ff8bef-fixed-r1')
raw=sys.stdin.buffer.read(1048577);assert len(raw)<=1048576
x=json.loads(raw);assert x['schema']=='heptabao.native-retirement-isolated-stage-input.v1' and x['candidateMode']=='fixed'
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(raw)=='e8ee94633c3d46912fcd7f9f4ebd8c229b0b24d78bfe3971b3a326b1c4b346d5'
assert not root.exists()
expected={'consumer.mjs','native_lifecycle.mjs','driver.py','launcher.py','provider-proof.public.json',
 'factory-overlay/dist/shared-client-4ICy3U6d.js','factory-overlay/dist/config-CYEDnLJ2.js','factory-overlay/dist/protocol-2POPqAY4.js','factory-overlay/dist/rolldown-runtime-8H4AJuhK.js','factory-overlay/package.json',
 'plugin-overlay/codex-client-recycler.js','plugin-overlay/runtime-refresh-policy.js','dependency-map.public.json','verify-dependencies.mjs'}
assert set(x['files'])==expected and set(x['filePins'])==expected
links=x['dependencyLinks'];assert set(links)=={'openclaw','ws','zod'}
assert links['openclaw']=='/home/qian-qi/.npm-global/lib/node_modules/openclaw'
original_plugin='/home/qian-qi/.openclaw/npm/projects/openclaw-codex-8902d781d4__openclaw-generation__g-49fd4dbfde2c5057/node_modules/@openclaw/codex'
assert links['ws']==original_plugin+'/node_modules/ws' and links['zod']==original_plugin+'/node_modules/zod'
control=root/'control'
assert x['native']['factoryEntry']==str(control/'factory-overlay/dist/shared-client-4ICy3U6d.js')
assert x['native']['configEntry']==str(control/'factory-overlay/dist/config-CYEDnLJ2.js')
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
root.mkdir(mode=0o700);control.mkdir(mode=0o700)
def put(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(b);f.flush();os.fsync(f.fileno())
 d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(d)
 finally:os.close(d)
 return sha(b)
pins=dict(x['sourcePins'])
for name,b in x['files'].items():
 p=control/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 pins[str(p)]=put(p,b.encode())
modules=control/'factory-overlay/node_modules';modules.mkdir(mode=0o700)
for name,target in links.items():(modules/name).symlink_to(target,target_is_directory=True)
d=os.open(modules,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(d)
finally:os.close(d)
verification=subprocess.run(['/usr/bin/node','--experimental-import-meta-resolve',str(control/'verify-dependencies.mjs'),str(control/'dependency-map.public.json')],
 stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10,env={'PATH':'/usr/bin:/bin','HOME':'/home/qian-qi'})
assert verification.returncode==0 and not verification.stderr,'dependency_verifier_failed'
resolved=json.loads(verification.stdout);assert resolved['ok']is True and resolved['moduleCount']==12 and resolved['packageCount']==2
assert all(file_sha(p)==h for p,h in pins.items())
stage={'schema':'heptabao.native-retirement-isolated-stage.v1','ok':True,'candidateMode':'fixed','native':x['native'],
 'knownConcurrentBuild':x['knownConcurrentBuild'],'pins':pins,'payloadSha256':sha(raw),'productionChanged':False,
 'dependencyLinks':links,'dependencyVerification':resolved,'providerCalled':False,'serverStarted':False,'nativeStarted':False,'productionPluginInstalled':False}
b=json.dumps(stage,sort_keys=True,separators=(',',':')).encode()
h=put(control/'stage.public.json',b)
print(json.dumps({'ok':True,'stage':str(control/'stage.public.json'),'sha256':h,'pins':len(pins),'dependencyVerificationPassed':True,'nativeStarted':False,'serverStarted':False}))
