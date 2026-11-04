from pathlib import Path
import hashlib,json,os,signal,stat,subprocess,sys,time
START=time.monotonic();UNTIL=START+30
TRUST={'/home/qian-qi/.ssh/config':'e7b887aad30f6642876c09744c317387b143e4a4b21ddc4879df2b558379ccf4',
'/home/qian-qi/.ssh/hepta-transport/known_hosts':'1463442349bbb6b56e9ffbb66acce3c4abcceefe1c141c7b7f1ea9bb0dedf034'}
PFX=['/usr/bin/ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ConnectTimeout=8','-o','ConnectionAttempts=1']
child=None;protected=False;pending=False
result={'schema':'heptabao.r10.pocket-artifact-route-readonly.v1','ok':False,'alias':'pocket4-ts','writes':0,'remoteSessionStarted':False,'productStarted':False,'sshGSeconds':15,'overallSeconds':30}
def stop(sig,frame):
 global pending
 pending=True
 if not protected:raise RuntimeError('interrupted')
for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,stop)
def identity(s):return [str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def read(path):
 p=Path(path);assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_uid==1000 and a.st_nlink==1 and a.st_size<=262144 and a.st_mode&0o022==0
  raw=os.read(fd,262145);assert len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(p.lstat())
  return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':identity(a)}
 finally:os.close(fd)
try:
 assert os.getuid()==1000
 assert hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()=='d90fa41f7e59edf2f2a732ea082cac83085a2a3695a503cd82b6b4eef9cab9f3'
 before={p:read(p) for p in TRUST}
 assert all(before[p]['sha256']==h for p,h in TRUST.items())
 result['trustBefore']=before
 protected=True
 try:
  child=subprocess.Popen(PFX+['-G','pocket4-ts'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 finally:protected=False
 if pending:raise RuntimeError('interrupted')
 out,err=child.communicate(timeout=min(15,max(0,UNTIL-time.monotonic())))
 assert child.returncode==0 and len(out)<=65536 and len(err)<=4096
 parsed={}
 for line in out.decode('utf-8').splitlines():
  k,sep,v=line.partition(' ');assert sep
  parsed.setdefault(k,[]).append(v)
 selected=('hostname','user','port','hostkeyalias','proxyjump','identityfile','identitiesonly','identityagent','userknownhostsfile','globalknownhostsfile','stricthostkeychecking','updatehostkeys','batchmode','connecttimeout','connectionattempts','controlmaster','controlpath','controlpersist','forwardagent','clearallforwardings')
 result.update(effectiveConfigSha256=hashlib.sha256(out).hexdigest(),effectiveConfigBytes=len(out),selected={k:parsed[k] for k in selected if k in parsed},proxyCommandSha256=[hashlib.sha256(x.encode()).hexdigest() for x in parsed.get('proxycommand',[])],stderrSha256=hashlib.sha256(err).hexdigest(),stderrBytes=len(err))
 after={p:read(p) for p in TRUST};assert after==before
 result['trustAfter']=after
 result['ok']=time.monotonic()<UNTIL
except BaseException as error:
 result['errorClass']=type(error).__name__
finally:
 signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
 if child is not None and child.poll() is None:
  try:
   os.killpg(child.pid,signal.SIGTERM)
   try:child.wait(timeout=5)
   except subprocess.TimeoutExpired:
    os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
  except BaseException as error:result['cleanupErrorClass']=type(error).__name__
 remaining=None
 try:
  snap=subprocess.run(['/usr/bin/ps','-eo','pid=,pgid='],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=2,check=True)
  rows=[list(map(int,line.split())) for line in snap.stdout.decode('ascii').splitlines()]
  assert all(len(row)==2 for row in rows)
  remaining=[] if child is None else [pid for pid,pgid in rows if pgid==child.pid]
 except BaseException as error:result['groupObservationErrorClass']=type(error).__name__
 result['cleanup']={'pid':child.pid if child else None,'returncode':child.returncode if child else None,'directChildReaped':child is None or child.returncode is not None,'remaining':remaining}
 result['elapsedSeconds']=time.monotonic()-START
 result['ok']=result['ok'] and not pending and result['cleanup']['directChildReaped'] and remaining==[] and 'cleanupErrorClass' not in result and time.monotonic()<UNTIL
 print(json.dumps(result,sort_keys=True),flush=True)
sys.exit(0 if result['ok'] and time.monotonic()<UNTIL else 1)
