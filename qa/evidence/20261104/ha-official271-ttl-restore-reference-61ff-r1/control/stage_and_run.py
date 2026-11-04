import hashlib, json, os, stat, sys
from pathlib import Path
os.umask(0o077)
base=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
control=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/official271-standby-ttl-restore-oracle-control-61ff-r1')
live=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/official271-standby-ttl-restore-oracle-live-61ff-r1')
source_path=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/official271-standby-ttl-restore-oracle-control-61ff-r1/official_271_ttl_restore_reference_r1.py')
raw=sys.stdin.buffer.read(65537)
assert len(raw)==46195 and hashlib.sha256(raw).hexdigest()=='448cce0cedef1b2010beb789634d3b195750c25c8f96f7deb7b6919e9b2419fd'
assert base.resolve(strict=True)==base
st=base.lstat()
assert stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and os.geteuid()!=0
assert not control.exists() and not control.is_symlink() and not live.exists() and not live.is_symlink()
code=compile(raw,str(source_path),'exec')
control.mkdir(mode=0o700)
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
    after=os.fstat(fd)
    ident=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    assert ident(before)==ident(after)==ident(source_path.lstat())
    assert stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_nlink==1 and saved==raw
finally:
    os.close(fd)
receipt={'schema':'heptabao.official-ttl-reference-stage.v1','source_path':str(source_path),'source_sha256':hashlib.sha256(raw).hexdigest(),'source_bytes':len(raw),'prior_helper_sha256':'8fa4d740f3e0a7cddc3b27391ce2d46308c19e519f078fc9f3afb0e47039ccec','fresh_work_root':str(live),'syntax_compiled':True,'exact_source_readback':True,'http_seconds':15,'readiness_seconds':45,'expected_status_forced':False,'production_services_touched':False,'private_credentials_emitted':False}
with (control/'stage.public.json').open('x') as stream:
    json.dump(receipt,stream,indent=2,sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
fd=os.open(control,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try: os.fsync(fd)
finally: os.close(fd)
print(json.dumps({'stage':'source_saved_and_pinned','source_sha256':receipt['source_sha256'],'fresh_work_root':str(live)},sort_keys=True),flush=True)
sys.argv=[str(source_path),'--binary','/home/qian-qi/heptabao-ha-closure-20261103-r1/official271-standby-oracle-control-r1/artifacts/bao','--work-dir',str(live)]
namespace={'__name__':'__main__','__file__':str(source_path)}
exec(code,namespace,namespace)
