from pathlib import Path
import hashlib,json,os,stat,time
P=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-validation-source-controllers-r1')
files={
 '/home/qian-qi/.ssh/config':(None,'e7b887aad30f6642876c09744c317387b143e4a4b21ddc4879df2b558379ccf4'),
 '/home/qian-qi/.ssh/hepta-transport/known_hosts':(None,'1463442349bbb6b56e9ffbb66acce3c4abcceefe1c141c7b7f1ea9bb0dedf034'),
 str(P/'stage_desktop_r10.py'):(26983,'372a019ad50be02351fdba5de4837c52a7243290d7253fda8046c0eeafe02b30'),
 str(P/'source_sender_r10.py'):(10148,'410ff7b90622f0cdc36ba397e3e5c0a5674748b1356b9bd9d6b727d4dc9cd392'),
 str(P/'canonical-r10.bundle.base64'):(2033,'f25e8087a8c8444ab773efb566602feed63b5d51c59bb60e85e99b53eee29484')
}
def ident(s):
 return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
proof={}
started=time.monotonic()
for name,(size,digest) in files.items():
 p=Path(name);assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  assert stat.S_ISREG(before.st_mode) and before.st_uid==1000 and before.st_nlink==1
  assert before.st_mode&0o022==0 and 0<=before.st_size<=1048576
  if size is not None:assert before.st_size==size and stat.S_IMODE(before.st_mode)==0o600
  h=hashlib.sha256();count=0
  while True:
   assert time.monotonic()-started<15
   b=os.read(fd,65536)
   if not b:break
   count+=len(b);assert count<=1048576;h.update(b)
  assert count==before.st_size and h.hexdigest()==digest
  assert ident(before)==ident(os.fstat(fd))==ident(p.lstat())
  proof[name]={'bytes':count,'sha256':h.hexdigest(),'identity':ident(before)}
 finally:os.close(fd)
assert time.monotonic()-started<15
print(json.dumps({'schema':'heptabao.r10.desktop-source-launch-readonly-guards.v1',
 'status':'verified','actual_unix_ns':time.time_ns(),'files':proof,
 'git_operations':0,'network_operations':0,'file_writes':0,
 'elapsed_seconds':time.monotonic()-started},sort_keys=True),flush=True)
os.execve('/usr/bin/python3',['/usr/bin/python3','-I','-S','-B',str(P/'stage_desktop_r10.py')],dict(os.environ))
