import hashlib,json,os,platform,signal,stat
from pathlib import Path
P=Path('/home/qq/heptabao-ha-ufw-peer-ports-20261106-r2/after-add-mac/etc-ufw-user.rules')
EXPECTED={"bytes":5612,"sha256":"dadf2a867a6b42b31619c95dbfbb6a989be8dc6f0224cb5d5a81c3ea0e82dd51","rootIdentity":["66306","48246769","0","0","16832"],"phaseIdentity":["66306","48246784","0","0","16832"]}
def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def need(v,c):
 if not v:raise RuntimeError(c)
def deadline(s,f):raise RuntimeError('five_second_deadline')
signal.signal(signal.SIGALRM,deadline);signal.alarm(5)
fd=None;report={'schema':'heptabao.ai395-ufw-exact-owned-persistent-tuple.r1','ok':False,'childCount':0,'networkPacketsSent':0,'firewallWrites':0}
try:
 need(os.getuid()==0 and platform.node()=='ai395','fixed_host')
 for path,key in ((P.parent.parent,'rootIdentity'),(P.parent,'phaseIdentity')):
  st=path.lstat();need(path.resolve(strict=True)==path and stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700 and [str(x) for x in ident(st)[:5]]==EXPECTED[key],'exact_private_directory')
 st=P.lstat();need(P.resolve(strict=True)==P and stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and st.st_size==EXPECTED['bytes']<=1048576,'exact_private_file')
 fd=os.open(P,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);raw=bytearray()
 while True:
  block=os.read(fd,min(65536,st.st_size+1-len(raw)))
  if not block:break
  raw.extend(block);need(len(raw)<=st.st_size,'bounded_read')
 need(len(raw)==st.st_size and hashlib.sha256(raw).hexdigest()==EXPECTED['sha256'] and ident(os.fstat(fd))==ident(P.lstat())==ident(st),'exact_stable_capture')
 lines=raw.decode().splitlines();tag='comment='+b'heptabao-ha4bde9-20261106-r2-mac'.hex();matches=[i for i,x in enumerate(lines) if x.startswith('### tuple ### ') and tag in x.split()]
 need(len(matches)==1 and matches[0]+1<len(lines),'exact_unique_comment')
 i=matches[0];report.update(ok=True,sourcePin={'bytes':len(raw),'sha256':EXPECTED['sha256']},tuple=lines[i],body=lines[i+1],tupleOrdinal=sum(x.startswith('### tuple ### ') for x in lines[:i]),totalTuples=sum(x.startswith('### tuple ### ') for x in lines))
except BaseException as e:
 report['errorType']=type(e).__name__
 if type(e) is RuntimeError:report['errorCode']=str(e)
 if isinstance(e,OSError):report['errno']=e.errno
finally:
 signal.alarm(0);facts={'opened':int(fd is not None),'attemptedOnce':0,'knownClosed':0}
 if fd is not None:
  facts['attemptedOnce']=1
  try:os.close(fd);facts['knownClosed']=1
  except BaseException as e:report['ok']=False;report['closeErrorType']=type(e).__name__
 report['fdCloseFacts']=facts
 print(json.dumps(report,sort_keys=True,separators=(',',':')))
raise SystemExit(0 if report['ok'] else 1)
