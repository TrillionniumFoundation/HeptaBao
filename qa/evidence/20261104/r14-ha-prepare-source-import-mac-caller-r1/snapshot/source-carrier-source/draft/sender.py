from pathlib import Path
import hashlib,json,os,platform,select,signal,stat,subprocess,sys,time
os.umask(0o077)
START=time.monotonic()
UNTIL=START+90
HEAD='3cb873919170cc77101b27f6a3ab9e98f41f8d93'
TREE='7f4d48a647a81ca96e8a24a0a057c2c829459060'
FILES=[
 {
  "bytes": 23335023,
  "name": "canonical-3cb-full.bundle",
  "path": "/home/qian-qi/heptabao-phaseb-ingress-observer-source-export-20261104-r1/canonical-3cb-full.bundle",
  "sha256": "25020ee42fe92f95c9408cb937dc507430f18b84fdaef7ec438a0a233de1438b",
  "source_mode": 384,
  "target_mode": 256,
  "version": "66306:28324895:23335023:1793839385060504547:1793839385063504533"
 },
 {
  "bytes": 39965,
  "name": "source-export.result.public.json",
  "path": "/home/qian-qi/heptabao-phaseb-ingress-observer-source-export-20261104-r1/result.public.json",
  "sha256": "3619fafe30f3a025b193139e55800d19cc5d4e8772c6388cbd3f3c170d4bf448",
  "source_mode": 384,
  "target_mode": 256,
  "version": "66306:28324969:39965:1793839385327147652:1793839385327147652"
 }
]
protected=0
pending_signal=None
children=[]
result={'schema':'heptabao.phaseb3cb.fixed-public-source-endpoint.v1','status':'failed',
        'request_seconds':90,'git_operations':0,'server_started':False,'compiler_started':False}
class Cancelled(BaseException):pass
def handler(sig,_frame):
 global pending_signal
 pending_signal=sig
 if not protected:raise Cancelled()
for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,handler)
def remaining():
 value=UNTIL-time.monotonic()
 assert value>0,'original endpoint deadline exhausted'
 return value
def identity(s):
 return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def stop_active(p):
 if p.poll() is None:
  try:os.killpg(p.pid,signal.SIGTERM)
  except ProcessLookupError:pass
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   p.wait(timeout=5)
def snapshot():
 q=subprocess.run(['/bin/ps','-axo','pid=,ppid=,pgid=,stat='],stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=True)
 rows=[]
 for line in q.stdout.decode('ascii').splitlines():
  v=line.split()
  if len(v)>=4:rows.append({'pid':int(v[0]),'ppid':int(v[1]),'pgid':int(v[2]),'state':v[3]})
 return rows
def read_file(fd,size,expected,retain=False):
 os.lseek(fd,0,os.SEEK_SET)
 h=hashlib.sha256();n=0;parts=[]
 while True:
  remaining();b=os.read(fd,65536)
  if not b:break
  n+=len(b);assert n<=size;h.update(b)
  if retain:parts.append(b)
 assert n==size and h.hexdigest()==expected
 return {'bytes':n,'sha256':h.hexdigest()},b''.join(parts) if retain else None
def dir_fsync(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def run_and_report(operation):
 try:
  operation()
  remaining()
  result['status']='complete'
 except BaseException as e:
  result['status']='failed';result['error_type']=type(e).__name__
  frames=[];tb=e.__traceback__
  while tb is not None:
   frames.append({'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno});tb=tb.tb_next
  result['failure_frames']=frames
 finally:
  for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
  errors=[]
  for p in reversed(children):
   try:stop_active(p)
   except BaseException as e:errors.append(type(e).__name__)
  rows=None
  try:rows=snapshot() if children else []
  except BaseException as e:errors.append(type(e).__name__)
  result['cleanup']=[{'pid':p.pid,'direct_child_reaped':p.returncode is not None,
       'exit_code':p.returncode,'remaining':None if rows is None else [r for r in rows if r['pgid']==p.pid]}
       for p in children]
  result['cleanup_errors']=errors
  result['all_owned_stopped']=not errors and all(r['direct_child_reaped'] and r['remaining']==[] for r in result['cleanup'])
  result['elapsed_seconds']=time.monotonic()-START
  result['within_original_deadline']=time.monotonic()<UNTIL
  if pending_signal is not None or not result['all_owned_stopped'] or not result['within_original_deadline']:result['status']='failed'
  sys.stderr.write(json.dumps(result,sort_keys=True)+'\n');sys.stderr.flush()
 sys.exit(0 if result['status']=='complete' and time.monotonic()<UNTIL else 1)

def send():
 assert (platform.system(),platform.machine(),os.getuid())==('Linux','x86_64',1000)
 handles=[];fences=[]
 try:
  for item in FILES:
   path=Path(item['path']);assert path.resolve(strict=True)==path
   fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   handles.append(fd);before=os.fstat(fd)
   assert stat.S_ISREG(before.st_mode) and before.st_uid==1000 and before.st_nlink==1
   assert stat.S_IMODE(before.st_mode)==item['source_mode'] and before.st_size==item['bytes']
   version=':'.join(map(str,(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)))
   assert version==item['version']
   initial,_=read_file(fd,item['bytes'],item['sha256'])
   assert identity(before)==identity(os.fstat(fd))==identity(path.lstat())
   fences.append((item,path,fd,before,initial))
  os.set_blocking(1,False);sent=[]
  for item,path,fd,before,initial in fences:
   os.lseek(fd,0,os.SEEK_SET);h=hashlib.sha256();count=0
   while True:
    remaining();block=os.read(fd,65536)
    if not block:break
    count+=len(block);assert count<=item['bytes'];h.update(block)
    view=memoryview(block)
    while view:
     assert select.select([], [1], [], remaining())[1]
     try:n=os.write(1,view)
     except (BlockingIOError,InterruptedError):continue
     assert n>0;view=view[n:]
   assert count==item['bytes'] and h.hexdigest()==item['sha256']
   assert identity(before)==identity(os.fstat(fd))==identity(path.lstat())
   sent.append({'name':item['name'],'source':str(path),'source_version':item['version'],
      'source_identity_before':identity(before),'source_identity_after':identity(os.fstat(fd)),
      'initial_file':initial,'stream':{'bytes':count,'sha256':h.hexdigest()}})
  for item,path,fd,before,_ in fences:
   assert identity(before)==identity(os.fstat(fd))==identity(path.lstat())
  result.update(role='sender',source_commit=HEAD,source_tree=TREE,files=sent)
 finally:
  for fd in reversed(handles):os.close(fd)
run_and_report(send)
