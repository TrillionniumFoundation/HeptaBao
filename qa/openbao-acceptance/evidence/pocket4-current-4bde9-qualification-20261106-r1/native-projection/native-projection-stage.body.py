import hashlib,json,os,platform,stat,time
from pathlib import Path
START=time.monotonic(); DEADLINE=START+20
os.umask(0o077)
def need(v,msg):
 if not v: raise RuntimeError(msg)
def ident(s): return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read_pin(path,maximum,private=False):
 need(time.monotonic()<DEADLINE,'staging deadline')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=maximum and not s.st_mode&0o022,'stable bounded regular file')
  need((s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o600) if private else s.st_uid==0,'expected file custody')
  h=hashlib.sha256();n=0;header=b''
  while True:
   need(time.monotonic()<DEADLINE,'staging deadline')
   b=os.read(fd,1024*1024)
   if not b: break
   n+=len(b);need(n<=s.st_size and n<=maximum,'bounded whole file');h.update(b);header=(header+b)[:64]
  need(n==s.st_size and ident(s)==ident(os.fstat(fd))==ident(os.lstat(path)),'stable file identity')
  return {'path':str(path),'bytes':n,'sha256':h.hexdigest(),'identity':list(ident(s)),'header_hex':header.hex()}
 finally: os.close(fd)
need(platform.system()=='Linux' and platform.machine()=='x86_64' and platform.node()=='alex-G1628-04' and os.geteuid()==1000,'exact producer host')
root=Path(PACKET['root']);out=Path(PACKET['out'])
need(root.is_absolute() and root.resolve(strict=True)==root,'canonical original owned root')
parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 ps=os.fstat(parent);need(ps.st_uid==1000 and stat.S_IMODE(ps.st_mode)==0o700 and ident(ps)[:5]==ident(root.lstat())[:5],'held private original root')
 os.mkdir(out.name,0o700,dir_fd=parent)
 child=os.open(out.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
 try:
  ci=os.fstat(child)
  need(ci.st_uid==1000 and stat.S_IMODE(ci.st_mode)==0o700 and ident(ci)[:5]==ident(out.lstat())[:5],'held new private output')
  def write_new(name,data):
   need('/' not in name and name not in ('','.','..') and time.monotonic()<DEADLINE,'closed new child name')
   f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=child)
   try:
    with os.fdopen(f,'wb',closefd=False) as stream: stream.write(data);stream.flush();os.fsync(f)
   finally: os.close(f)
  need({r['name'] for r in PACKET['files']}=={'native_build_receipt_from_convergence.py','kv2_native_fresh_directory_dr_live.py','normal107.terminal.exact-tool-text.json'} and len(PACKET['files'])==3,'exact source closure')
  for row in PACKET['files']:
   b=row['text'].encode();need(len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256'],'exact reviewed source bytes')
   write_new(row['name'],b);pin=read_pin(out/row['name'],128*1024,True)
   need(pin['bytes']==row['bytes'] and pin['sha256']==row['sha256'],'whole staged readback')
  tool=Path('/usr/bin/readelf').resolve(strict=True);pin=read_pin(tool,2*1024*1024)
  need(bytes.fromhex(pin['header_hex'])[:6]==b'\x7fELF\x02\x01','actual system ELF tool')
  obs={'schema':'heptabao.current-producer-readelf-observation.v1','host':'pocket4','hostname':platform.node(),'logical_path':'/usr/bin/readelf','tool':pin,'product_executions':0,'compiler_invocations':0}
  write_new('host-readelf.public.json',(json.dumps(obs,sort_keys=True,indent=2)+'\n').encode())
  os.fsync(child);need(ident(ci)[:5]==ident(os.fstat(child))[:5]==ident(out.lstat())[:5],'held stage remains named')
 finally: os.close(child)
 os.fsync(parent);need(ident(ps)[:5]==ident(os.fstat(parent))[:5]==ident(root.lstat())[:5],'parent remains named')
finally: os.close(parent)
need(time.monotonic()<DEADLINE,'staging complete within fixed cap')
os.execve('/usr/bin/python3',PACKET['argv'],{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'})
