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

ROOT=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-phaseb-ingress-observer-source-carrier-r1')
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
 exported=json.loads(json_bytes['source-export.result.public.json'])
 assert exported['schema']=="heptabao.phaseb.rog-3cb-standalone-source-export.v1"
 assert exported['status']=='exported' and exported['all_owned_stopped']
 assert exported['canonical_commit']==HEAD and exported['canonical_tree']==TREE
 assert exported['canonical_proof']=={'commit':HEAD,'tree':TREE,
      'parents':['bf0aaec1dcafbf476c0ab3a75544bb0eafaeff24'],
      'root':'67d79b3b5442ed033d38929eab2010403463e56d','commit_count':3755,'full_fsck_passed':True}
 assert exported['expected_prerequisites']==[] and exported['expected_full_commit_count']==3755
 assert exported['source_before']==exported['source_after']
 assert exported['source_before']['head']==HEAD and exported['source_before']['tree']==TREE
 assert exported['source_before']['clean'] and exported['source_before']['independent_git_directory']
 assert exported['controller']['bytes']==15352
 assert exported['controller']['sha256']=='7c8912c99b86742a072329d883d4c28c5f36a6581114197bfd5638b06076a72a'
 assert exported['bundle']['path']==FILES[0]['path']
 assert exported['bundle']['bytes']==FILES[0]['bytes'] and exported['bundle']['sha256']==FILES[0]['sha256']
 assert exported['bundle']['header']['prerequisites']==[]
 assert exported['bundle']['header']['heads']==[[HEAD,'HEAD']]
 assert exported['deadline_before_receipt_passed'] and exported['overall_seconds']==300
 assert exported['git_command_seconds']==90 and exported['elapsed_seconds']<300
 assert len(exported['cleanup'])==27 and all(row['direct_child_reaped'] and row['remaining']==[] for row in exported['cleanup'])
 assert not exported['network_git_protocols_enabled'] and not exported['server_started'] and not exported['compiler_started']
 assert not exported['source_imported'] and not exported['runtime_qualification'] and exported['product_tests_executed']==0
 assert sorted(os.listdir(DESTINATION))==sorted(x['name'] for x in FILES)
 dirfd=os.open(DESTINATION,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fchmod(dirfd,0o500);os.fsync(dirfd)
 finally:os.close(dirfd)
 dir_fsync(ROOT);remaining()
 result.update(role='receiver',source_commit=HEAD,source_tree=TREE,files=results,
      destination_created_exclusive=True,destination_directory_mode=0o500,
      destination_fsynced=True,raw_receipts_preserved=True,source_export_provenance_verified=True)
run_and_report(receive)
