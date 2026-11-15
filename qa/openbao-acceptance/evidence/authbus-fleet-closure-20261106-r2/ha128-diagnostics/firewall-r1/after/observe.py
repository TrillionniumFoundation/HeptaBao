import hashlib,json,os,shutil,stat,sys
from pathlib import Path
assert sys.platform=='linux' and os.getuid()==1000
names=('nft','iptables','iptables-save')
def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
report={'schema':'heptabao.fixed-firewall-after-observation.r1','childCount':0,'networkCalls':0,'rulesChanged':False,'tools':[]}
for name in names:
 value=shutil.which(name,path='/usr/sbin:/usr/bin:/sbin:/bin')
 if value is None:report['tools'].append({'name':name,'present':False});continue
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
expected={'nft':'3f1c21553e62716ef1abfcf31f51ff94eb73ff4234a6653bac754a42f936d1c7','iptables':'a1610dd70bb5ab04180671280df65b0077b680b627c0b6c51480b327732a762d','iptables-save':'a1610dd70bb5ab04180671280df65b0077b680b627c0b6c51480b327732a762d'}
assert all(t['present'] and t['sha256']==expected[t['name']] for t in report['tools'])
report['originalPtyPidObservations']=[{'pid':pid,'procEntryAbsent':not Path('/proc/'+str(pid)).exists()} for pid in (331386,331387,332563,332565)]
report['allOriginalPtyPidsAbsent']=all(x['procEntryAbsent'] for x in report['originalPtyPidObservations'])
report['toolBytesUnchanged']=True
print(json.dumps(report,sort_keys=True))
