import hashlib,json,os,platform,stat,time
from pathlib import Path
os.umask(0o077);END=time.monotonic()+15
ROOT=Path('/home/qian/heptabao-current-pocket4-4bde9-qualification-20261106-r1');CONTROL=ROOT/'control'
def need(v,s):
 if not v:raise RuntimeError(s)
def ident(s):return(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
need(platform.node()=='qian-ThinkPad-X230' and platform.system()=='Linux' and os.geteuid()==1000,'observed_x230')
for path in [ROOT,CONTROL]:
 s=path.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==1000 and stat.S_IMODE(s.st_mode)==0o700 and path.resolve(strict=True)==path,'owned_delivered_private_control')
fd=os.open(CONTROL,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 before=os.fstat(fd);need({r['name'] for r in ROWS}=={'owned_process.py','prepare_current_source_x230.py'} and len(ROWS)==2,'two_frozen_source_inputs')
 for r in ROWS:
  need(time.monotonic()<END,'source_stage_deadline');b=r['text'].encode();need(len(b)==r['bytes'] and hashlib.sha256(b).hexdigest()==r['sha256'],'frozen_source_pin')
  f=os.open(r['name'],os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
  try:
   with os.fdopen(f,'wb',closefd=False) as stream:stream.write(b);stream.flush();os.fsync(f)
   s=os.fstat(f);os.lseek(f,0,os.SEEK_SET);observed=os.read(f,len(b)+1)
   need(observed==b and s.st_nlink==1 and s.st_uid==1000 and stat.S_IMODE(s.st_mode)==0o600 and ident(s)==ident(os.fstat(f))==ident(os.stat(r['name'],dir_fd=fd,follow_symlinks=False)),'whole_source_readback')
  finally:os.close(f)
 os.fsync(fd);need(ident(before)[:5]==ident(os.fstat(fd))[:5]==ident(CONTROL.lstat())[:5],'held_control_unchanged')
finally:os.close(fd)
need(time.monotonic()<END,'source_stage_deadline')
os.execve('/usr/bin/python3',['/usr/bin/python3','-I','-S','-B',str(CONTROL/'prepare_current_source_x230.py')],{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'})
