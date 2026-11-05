from pathlib import Path
import hashlib,json,os,platform,select,signal,stat,subprocess,sys,time
ACTUAL_INPUTS_READY=True
if not ACTUAL_INPUTS_READY:
 raise RuntimeError('unresolved exact normal artifact transport input metadata')
os.umask(0o077)
START=time.monotonic()
UNTIL=START+90
HEAD='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c'
TREE='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825'
FILES=[
 {
  "path": "/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/normal-release-tests-r3/artifacts/heptabao-server",
  "name": "heptabao-server",
  "bytes": 110339520,
  "sha256": "7540cfb7e691fe5bea2515df3c35d8f31cdc42f05d5c9f2199c8464182de40b2",
  "source_mode": 320,
  "target_mode": 320,
  "version": "66306:31618600:110339520:1793854196517721681:1793854196660721163"
 },
 {
  "path": "/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/normal-release-tests-r3/native-build.public.json",
  "name": "native-build.public.json",
  "bytes": 772,
  "sha256": "ebef4cd1143ea4d6cc197916072de4978520a0f67d1a175adc7bb2faae7fd69e",
  "source_mode": 384,
  "target_mode": 256,
  "version": "66306:31618604:772:1793854197085814600:1793854197085814600"
 },
 {
  "path": "/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/normal-release-tests-r3/normal-release-result.public.json",
  "name": "normal-release-result.public.json",
  "bytes": 3137,
  "sha256": "6691ddb0f927a068bd3b7b4da1f190399bf58558ab1efb754fa57b4233597f1d",
  "source_mode": 384,
  "target_mode": 256,
  "version": "66306:31618602:3137:1793854197085005556:1793854197085005556"
 },
 {
  "path": "/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/normal-release-tests-r3/result.public.json",
  "name": "normal-release-tests-result.public.json",
  "bytes": 48188,
  "sha256": "84d763e6ff948df27964f373e834f869d7b22eeb0d7efb929fbd5c299c528f1b",
  "source_mode": 384,
  "target_mode": 256,
  "version": "66306:31618802:48188:1793855417596045434:1793855417596045434"
 },
 {
  "path": "/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/control/normal-test-groups.public.json",
  "name": "groups.json",
  "bytes": 6249,
  "sha256": "0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1",
  "source_mode": 384,
  "target_mode": 256,
  "version": "66306:27299399:6249:1793850441629209928:1793850441629209928"
 }
]
protected=0
pending_signal=None
children=[]
result={'schema':'heptabao.df026.fixed-public-normal-endpoint.v1','status':'failed',
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

ROOT=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-cold-h2-shared-artifacts-r1')
DESTINATION=ROOT/'incoming'
def receive():
 assert (platform.system(),platform.machine(),os.getuid())==('Linux','x86_64',1000)
 assert ROOT.resolve(strict=True)==ROOT and ROOT.is_dir() and ROOT.stat().st_uid==1000
 assert stat.S_IMODE(ROOT.stat().st_mode)==0o700
 assert not DESTINATION.exists() and not DESTINATION.is_symlink()
 DESTINATION.mkdir(mode=0o700);dir_fsync(ROOT)
 result['partial_directory_retained_on_failure']=True
 results=[];json_bytes={}
 for item in FILES:
  remaining();path=DESTINATION/item['name']
  fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   count=0;h=hashlib.sha256()
   while count<item['bytes']:
    assert select.select([0],[],[],remaining())[0]
    try:block=os.read(0,min(65536,item['bytes']-count))
    except (BlockingIOError,InterruptedError):continue
    assert block,'truncated artifact stream'
    count+=len(block);h.update(block);view=memoryview(block)
    while view:
     remaining();n=os.write(fd,view);assert n>0;view=view[n:]
   assert count==item['bytes'] and h.hexdigest()==item['sha256']
   os.fchmod(fd,item['target_mode']);os.fsync(fd)
   before=os.fstat(fd)
   assert stat.S_ISREG(before.st_mode) and before.st_uid==1000 and before.st_nlink==1
   assert before.st_size==item['bytes'] and stat.S_IMODE(before.st_mode)==item['target_mode']
   same_fd,raw=read_file(fd,item['bytes'],item['sha256'],item['name'].endswith('.json'))
   assert identity(before)==identity(os.fstat(fd))==identity(path.lstat())
   if raw is not None:json_bytes[item['name']]=raw
   results.append({'name':item['name'],'path':str(path),'bytes':count,'sha256':h.hexdigest(),
        'mode':item['target_mode'],'create_only':True,'fsynced':True,
        'identity':identity(before),'same_fd_readback':same_fd})
  finally:os.close(fd)
 assert select.select([0],[],[],remaining())[0]
 assert os.read(0,1)==b'','unexpected artifact stream trailer'
 native=json.loads(json_bytes['native-build.public.json'])
 build=json.loads(json_bytes['normal-release-result.public.json'])
 assert native['source_commit']==build['source_commit']==HEAD
 assert native['source_tree']==build['source_tree']==TREE
 assert native['binary_sha256']==build['artifacts']['heptabao-server']['sha256']==FILES[0]['sha256']
 assert build['artifacts']['heptabao-server']['bytes']==FILES[0]['bytes']
 assert native['provenance']['result_sha256']==FILES[2]['sha256']
 assert native['build_exit_code']==build['build_exit_code']==0
 assert native['features']==build['artifacts']['heptabao-server']['features']==['default','native-v6-ha','native-v6-storage']
 assert native['native_abi']==build['native_abi']=='x86_64-unknown-linux-gnu'
 assert native['source_freeze_verified'] and build['source_freeze_verified']
 assert build['normal_default_candidate'] and build['build_finished_success']
 assert not build['timed_out'] and not build['owned_group_survivors_after_wait']
 assert sorted(os.listdir(DESTINATION))==sorted(x['name'] for x in FILES)
 dirfd=os.open(DESTINATION,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fchmod(dirfd,0o500);os.fsync(dirfd)
 finally:os.close(dirfd)
 dir_fsync(ROOT);remaining()
 result.update(role='receiver',source_commit=HEAD,source_tree=TREE,files=results,
      destination_created_exclusive=True,destination_directory_mode=0o500,
      destination_fsynced=True,raw_receipts_preserved=True,normal_release_provenance_verified=True)
run_and_report(receive)
