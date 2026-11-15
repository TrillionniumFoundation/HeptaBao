import hashlib,json,os,platform,stat,time
from pathlib import Path
END=time.monotonic()+20
os.umask(0o077)
def need(v,s):
 if not v: raise RuntimeError(s)
def ident(s): return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
need(platform.system()=='Linux' and platform.machine()=='x86_64' and platform.node()==PACKET['hostname'] and os.geteuid()==1000,'exact approved host')
root=Path(PACKET['root']);out=Path(PACKET['out'])
need(root.is_absolute() and root.resolve(strict=True)==root and out.parent==root,'canonical explicit parent')
parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 ps=os.fstat(parent);need(ps.st_uid==1000 and stat.S_IMODE(ps.st_mode)==0o700 and ident(ps)[:5]==ident(root.lstat())[:5],'held private parent')
 os.mkdir(out.name,0o700,dir_fd=parent)
 child=os.open(out.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
 try:
  cs=os.fstat(child);need(cs.st_uid==1000 and stat.S_IMODE(cs.st_mode)==0o700 and ident(cs)[:5]==ident(out.lstat())[:5],'held new directory')
  names=[x['name'] for x in PACKET['files']];need(len(names)==len(set(names)) and sorted(names)==PACKET['names'],'closed source input set')
  for row in PACKET['files']:
   need(time.monotonic()<END and '/' not in row['name'] and row['name'] not in ('','.','..'),'bounded literal child')
   data=row['text'].encode();need(0<len(data)<=512*1024 and len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],'exact frozen source bytes')
   fd=os.open(row['name'],os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=child)
   try:
    with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(data);stream.flush();os.fsync(fd)
    before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==1000 and stat.S_IMODE(before.st_mode)==0o600 and before.st_size==len(data),'new private input')
    os.lseek(fd,0,os.SEEK_SET);chunks=[];total=0
    while True:
     need(time.monotonic()<END,'staging deadline')
     block=os.read(fd,65536)
     if not block:break
     total+=len(block);need(total<=len(data),'readback cap');chunks.append(block)
    need(b''.join(chunks)==data and ident(before)==ident(os.fstat(fd))==ident(os.stat(row['name'],dir_fd=child,follow_symlinks=False)),'full stable input readback')
   finally:os.close(fd)
  os.fsync(child);need(ident(cs)[:5]==ident(os.fstat(child))[:5]==ident(out.lstat())[:5],'held stage remains named')
 finally:os.close(child)
 os.fsync(parent);need(ident(ps)[:5]==ident(os.fstat(parent))[:5]==ident(root.lstat())[:5],'parent remains named')
finally:os.close(parent)
need(time.monotonic()<END,'fixed staging cap')
os.execve('/usr/bin/python3',PACKET['argv'],{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'})
