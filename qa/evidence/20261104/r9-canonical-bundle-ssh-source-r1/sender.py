from pathlib import Path
import hashlib,json,os,platform,plistlib,select,signal,stat,subprocess,sys,time
os.umask(0o077)
START=time.monotonic()
UNTIL=START+90
EXPECTED_BYTES=1886365
EXPECTED_SHA='49060b399899b9904aded82973589837062dace090fcb43102fa862a5ff7fb06'
SOURCE_VERSION='66306:28228563:1886365:1793814029233278292:1793814029235278291'
UUID='FB804D1B-24CB-4D6E-AEA7-A9E180807758'
protected=0
pending_signal=None
children=[]
result={'schema':'heptabao.r9.fixed-public-bundle-endpoint.v1','status':'failed',
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
def original_volume():
 global protected
 remaining();protected+=1
 try:
  p=subprocess.Popen(['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
       stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  children.append(p)
 finally:protected-=1
 if pending_signal is not None:raise Cancelled()
 try:out,err=p.communicate(timeout=min(30,remaining()))
 finally:
  if p.poll() is None:stop_active(p)
 assert p.returncode==0 and len(out)<=262144 and len(err)<=262144
 info=plistlib.loads(out)
 assert info.get('VolumeUUID')==UUID
 result['volume']={'uuid':info['VolumeUUID'],'stdout_sha256':hashlib.sha256(out).hexdigest(),
                  'stderr_sha256':hashlib.sha256(err).hexdigest(),'exit_code':p.returncode}
def read_file(fd):
 os.lseek(fd,0,os.SEEK_SET)
 h=hashlib.sha256();n=0
 while True:
  remaining();b=os.read(fd,65536)
  if not b:break
  n+=len(b);assert n<=EXPECTED_BYTES;h.update(b)
 assert n==EXPECTED_BYTES and h.hexdigest()==EXPECTED_SHA
 return {'bytes':n,'sha256':h.hexdigest()}
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

SOURCE=Path('/home/qian-qi/heptabao-native-ssh-owner-20261104-r1/r9-http-routing-r1/control/canonical-export-r2/canonical-from-7a552330-r2.bundle')
def send():
 assert (platform.system(),platform.machine(),os.getuid())==('Linux','x86_64',1000)
 assert SOURCE.resolve(strict=True)==SOURCE
 fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  assert stat.S_ISREG(before.st_mode) and before.st_uid==1000 and before.st_nlink==1
  assert stat.S_IMODE(before.st_mode)==0o600
  version=':'.join(map(str,(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)))
  assert version==SOURCE_VERSION
  initial=read_file(fd)
  assert identity(before)==identity(os.fstat(fd))==identity(SOURCE.lstat())
  os.lseek(fd,0,os.SEEK_SET);os.set_blocking(1,False)
  h=hashlib.sha256();count=0
  while True:
   remaining();block=os.read(fd,65536)
   if not block:break
   count+=len(block);assert count<=EXPECTED_BYTES;h.update(block)
   view=memoryview(block)
   while view:
    assert select.select([], [1], [], remaining())[1]
    try:n=os.write(1,view)
    except (BlockingIOError,InterruptedError):continue
    assert n>0;view=view[n:]
  assert count==EXPECTED_BYTES and h.hexdigest()==EXPECTED_SHA
  assert identity(before)==identity(os.fstat(fd))==identity(SOURCE.lstat())
  result.update({'role':'sender','source':str(SOURCE),'source_version':version,
        'source_identity_before':identity(before),'source_identity_after':identity(os.fstat(fd)),
        'initial_file':initial,'stream':{'bytes':count,'sha256':h.hexdigest()}})
 finally:os.close(fd)
run_and_report(send)
