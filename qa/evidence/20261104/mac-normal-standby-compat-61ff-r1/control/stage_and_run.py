import hashlib, json, os, platform, stat, sys
from pathlib import Path
os.umask(0o077)
root=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-unified-normal-61ff-r1')
control=root/'control'
source_path=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-unified-normal-61ff-r1/control/normal_unified_standby_compat_observer_r4.py')
live=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-unified-normal-61ff-r1/http-compat-standby-live-r1')
python=Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python')
assert platform.system()=='Darwin' and platform.machine()=='arm64' and os.getuid()==os.geteuid()==501
assert Path(sys.executable).resolve(strict=True)==python
assert hashlib.sha256(python.read_bytes()).hexdigest()=='7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211'
for directory in (root,control):
    info=directory.lstat()
    assert directory.resolve(strict=True)==directory and stat.S_ISDIR(info.st_mode) and info.st_uid==501 and info.st_dev==root.lstat().st_dev
assert stat.S_IMODE(control.lstat().st_mode)==0o700
assert not live.exists() and not live.is_symlink()
raw=sys.stdin.buffer.read(262145)
assert len(raw)==71182 and hashlib.sha256(raw).hexdigest()=='d1bf471e9cdae039750c20249313c372c7d95bdbb27c9e5c62a1425fe0f16096'
code=compile(raw,str(source_path),'exec')
fd=os.open(source_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o500)
with os.fdopen(fd,'wb') as stream:
    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
fd=os.open(source_path,os.O_RDONLY|os.O_NOFOLLOW)
try:
    before=os.fstat(fd)
    saved=b''
    while len(saved)<=len(raw):
        part=os.read(fd,len(raw)+1-len(saved))
        if not part: break
        saved+=part
    ident=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    assert ident(before)==ident(os.fstat(fd))==ident(source_path.lstat())
    assert stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and saved==raw
finally:
    os.close(fd)
for name in list(os.environ):
    if name.startswith(('GIT_','DYLD_')): os.environ.pop(name,None)
os.environ.update({'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0'})
argv=json.loads("[\"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-unified-normal-61ff-r1/control/normal_unified_standby_compat_observer_r4.py\",\"--binary\",\"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-unified-normal-61ff-r1/normal-default-r1/artifacts/heptabao-server\",\"--work-dir\",\"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-unified-normal-61ff-r1/http-compat-standby-live-r1\",\"--expected-binary-sha256\",\"976776d4183d76e6adf06dc0e765d30f59d0d433adea42aeed8a57a9877c1f26\",\"--expected-build-result-sha256\",\"1213701925f1be075e5d538104cbc25f8b132054f61602fcb27eebf4a820b763\",\"--expected-native-build-sha256\",\"22cfeed88871a0a5cb4fd7ffccce6e04a4ba5773c6d2d71cebbba0b8a2266444\",\"--expected-source-commit\",\"70714605c39014bea93545f7f6aa4217d2a23544\",\"--expected-source-tree\",\"ef0ae63704a06b7dda1038e02abcc3233a2a438f\"]")
receipt={'schema':'heptabao.mac-normal-compat-observer-stage.v1','source_path':str(source_path),'source_sha256':hashlib.sha256(raw).hexdigest(),'source_bytes':len(raw),'fresh_work_root':str(live),'syntax_compiled':True,'exact_source_readback':True,'argv':argv,'official_reference_commit':'df47f00f3289fe690f38a8fd433f11b6f530ecc9','reference_cases':34,'http_seconds':15,'readiness_seconds':45,'election_seconds':60,'stable_leader_seconds':2.2,'production_services_touched':False,'full_replacement_qualified':False}
with (control/'normal-observer-r4-stage.public.json').open('x') as stream:
    json.dump(receipt,stream,indent=2,sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
fd=os.open(control,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try: os.fsync(fd)
finally: os.close(fd)
print(json.dumps({'stage':'source_saved_and_pinned','source_sha256':receipt['source_sha256'],'fresh_work_root':str(live)},sort_keys=True),flush=True)
sys.argv=argv
namespace={'__name__':'__main__','__file__':str(source_path)}
exec(code,namespace,namespace)
