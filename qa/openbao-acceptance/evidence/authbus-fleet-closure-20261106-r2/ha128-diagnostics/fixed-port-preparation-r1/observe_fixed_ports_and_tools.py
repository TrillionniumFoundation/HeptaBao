import hashlib,json,os,platform,shutil,stat,sys
from pathlib import Path
assert (sys.platform=='linux' and os.getuid()==1000 and platform.node() in ('qian-ThinkPad-X230','ai395')) or (sys.platform=='darwin' and os.getuid()==501 and platform.machine()=='arm64')
def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
report={'schema':'heptabao.fixed-ha-port-tool-observation.r1','hostRole':platform.node() if sys.platform=='linux' else 'mac','childCount':0,'networkCalls':0,'rulesChanged':False,'ports':[31040,31041],'tools':[]}
names=('nft','iptables-save') if sys.platform=='linux' else ('pfctl','netstat','socketfilterfw')
for name in names:
 value=('/usr/libexec/ApplicationFirewall/socketfilterfw' if name=='socketfilterfw' else shutil.which(name,path='/usr/sbin:/usr/bin:/sbin:/bin'))
 if value is None or not Path(value).exists():report['tools'].append({'name':name,'present':False});continue
 alias=Path(value);path=alias.resolve(strict=True);s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and s.st_size<=4194304
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);raw=bytearray()
 try:
  assert ident(os.fstat(fd))==ident(s)
  while True:
   block=os.read(fd,65536)
   if not block:break
   raw.extend(block);assert len(raw)<=s.st_size
  assert len(raw)==s.st_size and ident(os.fstat(fd))==ident(path.lstat())==ident(s) and alias.resolve(strict=True)==path
 finally:os.close(fd)
 report['tools'].append({'name':name,'present':True,'lookupPath':str(alias),'resolvedPath':str(path),'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
if sys.platform=='linux':
 matched=[]
 for family,name in (('ipv4','tcp'),('ipv6','tcp6')):
  with Path('/proc/net',name).open('rb') as f:raw=f.read(1048577)
  assert len(raw)<=1048576
  lines=raw.decode('ascii').splitlines();assert lines and 'local_address' in lines[0]
  for line in lines[1:]:
   fields=line.split();assert len(fields)>=10
   local,port=fields[1].split(':');port=int(port,16)
   if fields[3]=='0A' and port in (31040,31041):
    assert all(c in '0123456789ABCDEF' for c in local) and len(local) in (8,32)
    matched.append({'family':family,'port':port,'bindKind':'wildcard' if int(local,16)==0 else 'specific_local_address'})
 report['candidatePortListeners']=matched
 report['bothCandidateTcpPortsUnoccupiedInObservedKernelTables']=not matched
 report['readOnlySnapshotDoesNotReservePorts']=True
print(json.dumps(report,sort_keys=True))
