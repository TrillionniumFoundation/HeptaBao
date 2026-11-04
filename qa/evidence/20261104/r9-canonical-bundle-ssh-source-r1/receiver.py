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

DEST=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-native-http-r9/control/canonical-from-7a552330-r2.bundle')
def receive():
 assert (platform.system(),platform.machine(),os.getuid())==('Darwin','arm64',501)
 original_volume()
 assert DEST.parent.resolve(strict=True)==DEST.parent and DEST.parent.is_dir()
 parentfd=os.open(DEST.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  parent_before=os.fstat(parentfd)
  assert identity(parent_before)==identity(DEST.parent.lstat())
  assert parent_before.st_uid==501 and stat.S_IMODE(parent_before.st_mode)&0o022==0
  remaining()
  fd=os.open(DEST.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parentfd)
  result['destination_created_exclusive']=True
  try:
   start=os.fstat(fd)
   assert stat.S_ISREG(start.st_mode) and start.st_uid==501 and start.st_nlink==1 and start.st_size==0
   os.set_blocking(0,False);count=0;h=hashlib.sha256()
   while True:
    assert select.select([0], [], [], remaining())[0]
    try:block=os.read(0,min(65536,EXPECTED_BYTES+1-count))
    except (BlockingIOError,InterruptedError):continue
    if not block:break
    count+=len(block);assert count<=EXPECTED_BYTES;h.update(block)
    view=memoryview(block)
    while view:
     remaining()
     try:n=os.write(fd,view)
     except InterruptedError:continue
     assert n>0;view=view[n:]
   assert count==EXPECTED_BYTES and h.hexdigest()==EXPECTED_SHA
   os.fchmod(fd,0o600);os.fsync(fd);remaining()
   after=os.fstat(fd)
   assert after.st_dev==start.st_dev and after.st_ino==start.st_ino and after.st_uid==501 and after.st_nlink==1
   assert after.st_size==EXPECTED_BYTES and stat.S_IMODE(after.st_mode)==0o600
   assert identity(after)==identity(os.stat(DEST.name,dir_fd=parentfd,follow_symlinks=False))==identity(DEST.lstat())
   verified=read_file(fd)
   assert identity(after)==identity(os.fstat(fd))==identity(DEST.lstat())
   parent_after=os.fstat(parentfd)
   assert identity(parent_after)==identity(DEST.parent.lstat())
   assert (parent_before.st_dev,parent_before.st_ino,parent_before.st_uid,parent_before.st_gid,parent_before.st_mode)==(parent_after.st_dev,parent_after.st_ino,parent_after.st_uid,parent_after.st_gid,parent_after.st_mode)
   os.fsync(parentfd);remaining()
   result.update({'role':'receiver','destination':str(DEST),'received':{'bytes':count,'sha256':h.hexdigest()},
        'same_fd_readback':verified,'destination_identity':identity(after),'destination_fsynced':True,
        'parent_descriptor_identity':identity(parent_after)})
  finally:os.close(fd)
 finally:os.close(parentfd)
run_and_report(receive)
