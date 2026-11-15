import hashlib,json,os,stat,sys
from pathlib import Path
p=json.load(sys.stdin)
base=Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
assert base.resolve(strict=True)==base
fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 st=os.fstat(fd);assert st.st_uid==os.geteuid()
 os.mkdir('ha-native-build-projection-20261106-r1',0o700,dir_fd=fd)
 rootfd=os.open('ha-native-build-projection-20261106-r1',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
 try:
  rs=os.fstat(rootfd);assert rs.st_uid==os.geteuid() and stat.S_IMODE(rs.st_mode)==0o700
  for name,text in p['files'].items():
   assert '/' not in name and name in ('native_build_receipt_from_convergence.py','kv2_native_fresh_directory_dr_live.py','runtime-terminal.original.json')
   data=text.encode();assert hashlib.sha256(data).hexdigest()==p['pins'][name]
   n=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=rootfd)
   try:
    with os.fdopen(n,'wb',closefd=False) as f:f.write(data);f.flush();os.fsync(n)
   finally:os.close(n)
   n=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=rootfd)
   try:
    with os.fdopen(n,'rb',closefd=False) as f:check=f.read()
    assert check==data and os.fstat(n).st_nlink==1
   finally:os.close(n)
  os.fsync(rootfd)
 finally:os.close(rootfd)
 os.fsync(fd)
finally:os.close(fd)
root="/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/ha-native-build-projection-20261106-r1"
argv=[sys.executable,'-I','-B',root+'/native_build_receipt_from_convergence.py','--receipt',"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/build-test-4bde9-r1/result.public.json",'--receipt-sha256','90753d3b4f9b966c43d3e29919239f8d9aa879616c821a3d9ce0b6aa854054d6','--selection',"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/build-test-4bde9-r1/test-selection.public.json",'--selection-sha256','7da0b1e3efe257b66d31d50af7c1327a4d320c512c1c8f82df30020898c66595','--terminal',root+'/runtime-terminal.original.json','--terminal-sha256','76ec986884fc99d3bf96123ece9f361d21302a36af5b4ed2bd75f757a023c148','--job-id','1a1b116ba98-fc05-75a6','--source',"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/source-4bde9-r1",'--output',root+'/native-build.public.json']
os.execv(sys.executable,argv)
