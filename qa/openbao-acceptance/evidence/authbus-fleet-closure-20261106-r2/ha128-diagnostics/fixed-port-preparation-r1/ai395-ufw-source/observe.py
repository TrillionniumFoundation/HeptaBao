import ast,fcntl,hashlib,json,os,platform,shutil,socket,stat,struct
from pathlib import Path
assert platform.node()=='ai395' and os.getuid()==1000
def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,maximum):
 s=path.lstat();assert path.resolve(strict=True)==path and stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and s.st_size<=maximum
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);raw=bytearray()
 try:
  assert ident(os.fstat(fd))==ident(s)
  while True:
   block=os.read(fd,65536)
   if not block:break
   raw.extend(block);assert len(raw)<=s.st_size
  assert len(raw)==s.st_size and ident(os.fstat(fd))==ident(path.lstat())==ident(s)
 finally:os.close(fd)
 return bytes(raw)
report={'schema':'heptabao.ai395-existing-ufw-source-observation.r1','childCount':0,'networkPacketsSent':0,'rulesChanged':False,'files':[],'originalPtyPidObservations':[{'pid':pid,'procEntryAbsent':not Path('/proc/'+str(pid)).exists()} for pid in (1765362,1765363,1766076,1766077)]}
found=shutil.which('ufw',path='/usr/sbin:/usr/bin:/sbin:/bin');assert found
entry=Path(found).resolve(strict=True);raw=read(entry,65536);report['entry']={'path':str(entry),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'source':raw.decode()}
for name in ('frontend','backend','backend_iptables','parser','common','util'):
 path=Path('/usr/lib/python3/dist-packages/ufw')/(name+'.py')
 raw=read(path,300000);tree=ast.parse(raw.decode())
 methods=[]
 for node in ast.walk(tree):
  if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and any(term in node.name for term in ('add','delete','remove','save','reload','commit','update','parse','equal','action')):
   methods.append(node.name)
 report['files'].append({'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'relevantMethodNames':methods})
for name,expected in (('nft','7b3efd79bd3a70d72275b7bbfe19f2234a837968a3c0ad5528126a396a00d42f'),('iptables-save','603f55a8877a2db138615f961901ef23ba77451ac0a53233bd01f1c9b216636a')):
 path=Path(shutil.which(name,path='/usr/sbin:/usr/bin:/sbin:/bin')).resolve(strict=True);assert hashlib.sha256(read(path,1048576)).hexdigest()==expected
report['priorNftAndIptablesToolsUnchanged']=True
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as control:
 address=socket.inet_ntoa(fcntl.ioctl(control.fileno(),0x8915,struct.pack('256s',b'br0'))[20:24])
report['declaredLanAddressAttachment']={'interface':'br0','ipv4':address,'isBridge':Path('/sys/class/net/br0/bridge').is_dir(),'scope':'kernel interface-address metadata; no packet capture'}
assert address=='192.168.0.11' and report['declaredLanAddressAttachment']['isBridge']
print(json.dumps(report,sort_keys=True))
