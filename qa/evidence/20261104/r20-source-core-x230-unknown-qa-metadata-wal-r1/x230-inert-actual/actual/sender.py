from pathlib import Path
import hashlib,json,os,platform,select,signal,stat,subprocess,sys,time
os.umask(0o077)
START=time.monotonic()
UNTIL=START+90
HEAD='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c'
TREE='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825'
BINDING_READY=True
FILES=[
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-cold-h2-shared-artifacts-r1/incoming/heptabao-server",
    "name": "heptabao-server",
    "bytes": 110339520,
    "sha256": "7540cfb7e691fe5bea2515df3c35d8f31cdc42f05d5c9f2199c8464182de40b2",
    "source_mode": 320,
    "target_mode": 320,
    "version": "2050:5019547:110339520:1793857530819632046:1793857530819632046"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-cold-h2-shared-artifacts-r1/incoming/native-build.public.json",
    "name": "native-build.public.json",
    "bytes": 772,
    "sha256": "ebef4cd1143ea4d6cc197916072de4978520a0f67d1a175adc7bb2faae7fd69e",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:5019549:772:1793857533118564089:1793857533118564089"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-cold-h2-shared-artifacts-r1/incoming/normal-release-result.public.json",
    "name": "result.public.json",
    "bytes": 3137,
    "sha256": "6691ddb0f927a068bd3b7b4da1f190399bf58558ab1efb754fa57b4233597f1d",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:5019550:3137:1793857533123563941:1793857533123563941"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-cold-h2-source-carrier-r1/incoming/canonical-df026-full.bundle",
    "name": "canonical-df026-full.bundle",
    "bytes": 23429893,
    "sha256": "2f25963c59ecfd0918f786c98e6babcd7ba35daec02f00d899e987f19c28ad71",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:5019525:23429893:1793856420289823382:1793856420289823382"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-cold-h2-source-carrier-r1/incoming/source-export.result.public.json",
    "name": "source-export.result.public.json",
    "bytes": 38783,
    "sha256": "34816ca251e2cf420ed63db97bd56c10e0c1a725e16470f28f9eedf70dd21bb4",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:5019527:38783:1793856420629814207:1793856420629814207"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-cold-h2-shared-artifacts-r1/incoming/normal-release-tests-result.public.json",
    "name": "normal60-result.public.json",
    "bytes": 48188,
    "sha256": "84d763e6ff948df27964f373e834f869d7b22eeb0d7efb929fbd5c299c528f1b",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:5019551:48188:1793857533128563794:1793857533128563794"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-cold-h2-shared-artifacts-r1/incoming/groups.json",
    "name": "groups.json",
    "bytes": 6249,
    "sha256": "0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:5019552:6249:1793857533133563646:1793857533133563646"
  }
]
protected=0
pending_signal=None
children=[]
result={'schema':'heptabao.df026.x230-public-artifacts-sender.v1','status':'failed',
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

def binding_ready():
 assert BINDING_READY is True,'actual_normal60_export_and_transport_file_bindings_unresolved'
 assert len(FILES)==7 and len({x['name'] for x in FILES})==7
 for item in FILES:
  assert type(item['bytes']) is int and item['bytes']>0
  assert isinstance(item['sha256'],str) and len(item['sha256'])==64
  assert all(c in '0123456789abcdef' for c in item['sha256'])
  assert isinstance(item['version'],str) and len(item['version'].split(':'))==5

def send():
 binding_ready()
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
