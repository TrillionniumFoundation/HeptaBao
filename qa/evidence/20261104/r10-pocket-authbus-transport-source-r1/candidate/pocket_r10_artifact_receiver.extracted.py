
from pathlib import Path
import hashlib,json,os,signal,stat,sys,time
P=Path('/home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1')
ROOT=P/'shared-first-cycle-r10-artifacts-r1'
MACHINE='83cf23c61610cc1595d7323f6ae2f1af29b364a4676cbee1385ba6d478ad853c'
HEAD='49503322c7f446e5eb41e7744f1fdbd7f1192ecc'
TREE='1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
EXPECTED=[('heptabao-server',109091112,'67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113',0o500),
 ('native-build.public.json',801,'0e3d1ae800820d33f0d5369968cbccbab8fa62b077b142f87c9f52b31cd09c77',0o600),
 ('normal-build.result.public.json',3227,'75f858b280249dcc981eee3e4340982a58027e8ca40217244ae029bb8e9011ee',0o600)]
def ident(s):return [str(getattr(s,k))for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def sync_dir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def put(p,v):
 raw=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 sync_dir(p.parent)
 return {'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def expired(*_):raise TimeoutError('fixed_artifact_receiver_deadline')
os.umask(0o077);created=False;rows=[];failure=None;started=time.time_ns()
signal.signal(signal.SIGALRM,expired);signal.alarm(180)
try:
 s=P.lstat();assert os.getuid()==1000 and P.resolve(strict=True)==P and stat.S_ISDIR(s.st_mode)and s.st_uid==1000 and stat.S_IMODE(s.st_mode)==0o700
 assert hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()==MACHINE
 ROOT.mkdir(mode=0o700);created=True;sync_dir(P)
 line=sys.stdin.buffer.readline(16385);assert len(line)<=16384 and line.endswith(b'\n')
 manifest=json.loads(line)
 assert manifest['schema']=='heptabao.pocket-r10-public-artifact-transfer.v1'
 assert manifest['sourceCommit']==HEAD and manifest['sourceTree']==TREE and manifest['nativeBuildHost']=='rog'
 assert [(x['name'],x['bytes'],x['sha256'],x['mode'])for x in manifest['files']]==EXPECTED
 put(ROOT/'receive-intent.public.json',manifest)
 for name,size,expected,mode in EXPECTED:
  p=ROOT/name;fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
  h=hashlib.sha256();left=size
  with os.fdopen(fd,'wb')as f:
   while left:
    chunk=sys.stdin.buffer.read(min(left,1048576))
    if not chunk:raise EOFError('artifact_body_truncated')
    f.write(chunk);h.update(chunk);left-=len(chunk)
   f.flush();os.fsync(f.fileno());written=os.fstat(f.fileno())
  assert h.hexdigest()==expected and stat.S_ISREG(written.st_mode)and written.st_uid==1000 and written.st_nlink==1 and written.st_size==size and stat.S_IMODE(written.st_mode)==mode
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
  with os.fdopen(fd,'rb')as f:
   first=os.fstat(f.fileno());assert ident(first)==ident(written)==ident(p.lstat())
   readback=hashlib.file_digest(f,'sha256').hexdigest()
   assert ident(first)==ident(os.fstat(f.fileno()))==ident(p.lstat())
  assert readback==expected;sync_dir(ROOT)
  rows.append({'name':name,'path':str(p),'bytes':size,'mode':mode,'sha256':readback,'identity':ident(written),'createOnly':True})
 assert sys.stdin.buffer.read(1)==b''
except BaseException as e:failure=type(e).__name__
finally:
 signal.alarm(0)
 if created:
  result={'schema':'heptabao.pocket-r10-public-artifact-receive-result.v1','ok':failure is None and len(rows)==3,'errorClass':failure,'files':rows,'sourceCommit':HEAD,'sourceTree':TREE,'nativeBuildHost':'rog','machineIdSha256':MACHINE,'createdRoot':str(ROOT),'createOnly':True,'partialRootPreservedOnFailure':failure is not None,'serverOrConsumerStarted':False,'privateInputsTransferred':False,'productionChanged':False,'startedUnixNs':started,'finishedUnixNs':time.time_ns()}
  record=put(ROOT/'receive-result.public.json',result);sync_dir(P)
  print(json.dumps({'ok':result['ok'],'receipt':record,'filesReceived':len(rows),'errorClass':failure},sort_keys=True))
 else:print(json.dumps({'ok':False,'createdRoot':False,'errorClass':failure},sort_keys=True))
sys.exit(0 if failure is None and len(rows)==3 else 1)
