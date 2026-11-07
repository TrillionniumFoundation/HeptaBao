import base64,hashlib,json,os,stat,sys,time
from pathlib import Path
start=time.monotonic()
target=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/candidate-5ded-from-4bde9.bundle')
temporary=target.with_name(target.name+'.conditional-publication-r1.tmp')
expected='eef7fc4f17d9818ad53fda4cf57b1de2ca7a31661833fae61695d89ff5dfbab3'
def need(v,n):
 if not v:raise RuntimeError(n)
def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def verify(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and before.st_size==401428,'existing_public_bundle_identity')
  b=b''
  while len(b)<401429:
   part=os.read(fd,65536)
   if not part:break
   b+=part
  need(identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'bundle_stable_read')
  need(hashlib.sha256(b).hexdigest()==expected,'bundle_sha256')
  return {'bytes':len(b),'sha256':expected,'device':before.st_dev,'inode':before.st_ino,'mode':stat.S_IMODE(before.st_mode),'links':before.st_nlink}
 finally:os.close(fd)
need(sys.platform=='darwin' and os.geteuid()==501,'fixed_mac_owner')
os.umask(0o077)
parent=target.parent
s=parent.lstat()
need(parent.resolve(strict=True)==parent and stat.S_ISDIR(s.st_mode) and s.st_uid==501 and stat.S_IMODE(s.st_mode)==0o700 and s.st_dev==16777244,'fixed_owned_t5_parent')
text=sys.stdin.buffer.read(535241)
need(len(text)==535240,'bounded_base64_input')
raw=base64.b64decode(text,validate=True)
need(len(raw)==401428 and hashlib.sha256(raw).hexdigest()==expected,'exact_public_bundle_input')
published=False
if os.path.lexists(target):
 observation=verify(target)
else:
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  created=os.fstat(fd);offset=0
  while offset<len(raw):
   n=os.write(fd,raw[offset:]);need(n>0,'write_progress');offset+=n
  os.fsync(fd)
  need(os.fstat(fd).st_size==len(raw),'complete_private_stage')
 finally:os.close(fd)
 need(temporary.lstat().st_ino==created.st_ino and temporary.lstat().st_dev==created.st_dev,'same_owned_temporary')
 try:
  os.link(temporary,target,follow_symlinks=False);published=True
 except FileExistsError:
  verify(target)
 need(temporary.lstat().st_ino==created.st_ino and temporary.lstat().st_dev==created.st_dev,'same_owned_temporary_before_unlink')
 os.unlink(temporary)
 dirfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(dirfd)
 finally:os.close(dirfd)
 observation=verify(target)
need(time.monotonic()-start<45,'original_publication_budget')
print(json.dumps({'schema':'heptabao.exact-public-bundle-conditional-publication.v1','same_target_and_bytes_as_prior_unknown_rpc':True,'create_only':True,'existing_target_overwritten':False,'published_this_job':published,'bundle':observation,'elapsed_seconds':time.monotonic()-start,'product_or_source_execution_started':False},sort_keys=True))
