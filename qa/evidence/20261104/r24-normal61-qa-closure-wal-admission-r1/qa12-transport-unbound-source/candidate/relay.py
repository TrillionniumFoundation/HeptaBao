#!/usr/bin/env python3
"""Create-only desktop copy of twelve fixed public df026 H2 QA instrument artifacts.
Uses the prior reviewed rog-ts transport. No Git, compiler, server or HTTP starts.
"""
from pathlib import Path
import hashlib,json,os,shlex,signal,stat,subprocess,sys,time
ACTUAL_INPUTS_READY=False
if not ACTUAL_INPUTS_READY:
 raise RuntimeError('unresolved exact H2 QA artifact transport input metadata')
os.umask(0o077)
BASE=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
SOURCES=BASE/'normal-native-h2-qa-shared-artifact-controls-r1'
ROOT=BASE/'normal-native-h2-qa-shared-artifacts-r1'
CONTROL=ROOT/'control'
ORIGINAL=BASE/'normal-33cafa-full128-control-r2/launch_normal_33cafa_full128_r2.py'
ORIGINAL_SHA='c70892cb19601fa9769ae3f36810bb123f756f335654f284a4001bf2d69c796e'
HEAD='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c'
TREE='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825'
FILES=[
 {
  "role": "executable",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/artifacts/heptabao-native-h2-qa",
  "name": "heptabao-native-h2-qa",
  "bytes": None,
  "sha256": None,
  "source_mode": 320,
  "target_mode": 320,
  "version": None
 },
 {
  "role": "rust_source",
  "path": "/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3/inputs/native_h2_client.rs",
  "name": "native_h2_client.rs",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "test_source",
  "path": "/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3/inputs/native_h2_client_tests.rs",
  "name": "native_h2_client_tests.rs",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "cargo_manifest",
  "path": "/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3/inputs/Cargo.toml",
  "name": "Cargo.toml",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "cargo_lock",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/artifacts/Cargo.lock",
  "name": "Cargo.lock",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "canonical_lock",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/artifacts/canonical.Cargo.lock",
  "name": "canonical.Cargo.lock",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "build_receipt",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/result.public.json",
  "name": "build-result.public.json",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "build_controller",
  "path": "/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3/build_native_h2_client_r1.py",
  "name": "build_native_h2_client_r1.py",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "build_binding",
  "path": "/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3/build-binding.private.json",
  "name": "build-binding.private.json",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "component_stdout",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/components.stdout",
  "name": "components.stdout",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "component_record",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/components.public.json",
  "name": "components.public.json",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "component_list_stdout",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/components-list.stdout",
  "name": "components-list.stdout",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 }
]
HELPERS={"sender.py":"62f3f3d69ebeb2ef902225069155f336923247948fc3b58ed3107af92454dbd1","receiver.py":"771215df75bd1016601649b55ef8f8fb2208c46f80e4326768b640c646a32feb"}
SSH=['/usr/bin/ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
     '-o','ConnectTimeout=10','-o','ConnectionAttempts=1',
     '-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','UpdateHostKeys=no',
     '-o','ControlMaster=no','-o','ControlPath=none']
START=time.monotonic();UNTIL=START+300
children=[];commands=[];handles=[];protected=0;pending_signal=None;created=False;remote_endpoints_verified=False
result={'schema':'heptabao.df026.shared-public-h2-qa-artifacts-relay.v1','status':'failed',
 'overall_seconds':300,'ssh_child_seconds':90,'endpoint_seconds':90,
 'source_alias':'rog-ts','destination_host':'desktop',
 'destination_root':str(ROOT),'source_commit':HEAD,'source_tree':TREE,'files':FILES,
 'git_operations':0,'compiler_started':False,'server_started':False,'runtime_qualification':False,
 'automatic_retry':False,'production_changed':False}
TRUST={
 '/home/qian-qi/.ssh/config':'e7b887aad30f6642876c09744c317387b143e4a4b21ddc4879df2b558379ccf4',
 '/home/qian-qi/.ssh/hepta-transport/known_hosts':'1463442349bbb6b56e9ffbb66acce3c4abcceefe1c141c7b7f1ea9bb0dedf034'}

class Cancelled(BaseException):pass
def signal_handler(sig,_frame):
 global pending_signal
 pending_signal=sig
 if not protected:raise Cancelled()
for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,signal_handler)
def remaining(until=UNTIL):
 r=until-time.monotonic()
 assert r>0,'original relay deadline exhausted'
 return r
def identity(s):
 return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def stable(path,cap=262144,owner=1000):
 assert path.resolve(strict=True)==path
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  assert stat.S_ISREG(before.st_mode) and before.st_uid==owner and before.st_nlink==1
  assert before.st_size<=cap and before.st_mode&0o022==0
  chunks=[];count=0
  while True:
   remaining();b=os.read(fd,min(65536,cap+1-count))
   if not b:break
   chunks.append(b);count+=len(b);assert count<=cap
  raw=b''.join(chunks)
  assert count==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat())
  return raw,{'bytes':count,'sha256':hashlib.sha256(raw).hexdigest(),'identity':identity(before)}
 finally:os.close(fd)
def fsync_dir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def create(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def public(path,value):
 create(path,(json.dumps(value,indent=2,sort_keys=True)+'\n').encode());fsync_dir(path.parent)
def snapshot():
 p=subprocess.run(['/bin/ps','-axo','pid=,ppid=,pgid=,stat='],stdin=subprocess.DEVNULL,
   stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=True)
 rows=[]
 for line in p.stdout.decode('ascii').splitlines():
  v=line.split()
  if len(v)>=4:rows.append({'pid':int(v[0]),'ppid':int(v[1]),'pgid':int(v[2]),'state':v[3]})
 return rows
def stop_active(p):
 if p.poll() is None:
  try:os.killpg(p.pid,signal.SIGTERM)
  except ProcessLookupError:pass
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   p.wait(timeout=5)
def log_file(label,suffix):
 p=CONTROL/(label+'.'+suffix)
 f=os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')
 handles.append(f)
 return p,f
def start_child(label,argv,*,stdin=subprocess.DEVNULL,stdout=None):
 global protected
 remaining()
 errpath,err=log_file(label,'stderr')
 outpath=None
 if stdout is None:outpath,stdout=log_file(label,'stdout')
 started=time.monotonic();deadline=min(UNTIL,started+90)
 protected+=1
 try:
  remaining(deadline)
  p=subprocess.Popen(argv,stdin=stdin,stdout=stdout,stderr=err,start_new_session=True)
  row={'label':label,'process':p,'started':started,'deadline':deadline,
       'stdout_path':outpath,'stderr_path':errpath,'argv':argv}
  children.append(row)
 finally:protected-=1
 if pending_signal is not None:raise Cancelled()
 return row
def wait_child(row):
 p=row['process'];timedout=False
 try:p.wait(timeout=remaining(row['deadline']))
 except subprocess.TimeoutExpired:
  timedout=True;stop_active(p)
 rem=[r for r in snapshot() if r['pgid']==p.pid]
 record={'label':row['label'],'pid':p.pid,'exit_code':p.returncode,'timed_out':timedout,
  'elapsed_seconds':time.monotonic()-row['started'],'limit_seconds':90,
  'direct_child_reaped':p.returncode is not None,'remaining':rem}
 commands.append(record);public(CONTROL/(row['label']+'.public.json'),record)
 assert not timedout and p.returncode==0 and not rem
 return record
def read_log(row,which):
 return stable(row[which+'_path'])[0]
def known_hosts_state(config):
 paths=shlex.split(config.get('userknownhostsfile',''))
 assert paths
 records={}
 for raw in paths:
  path=Path(raw)
  assert path.is_absolute() and path.is_relative_to(Path('/home/qian-qi/.ssh'))
  if path.exists():
   _bytes,pin=stable(path,1048576);records[str(path)]=pin
  else:
   assert not path.is_symlink();records[str(path)]={'absent':True}
 assert any('sha256' in value for value in records.values())
 return records
def inspect_config(alias):
 row=start_child(alias+'-effective-config',[*SSH,'-G',alias])
 wait_child(row)
 raw=read_log(row,'stdout');assert not read_log(row,'stderr')
 config={}
 for line in raw.decode('utf-8').splitlines():
  key,sep,value=line.partition(' ')
  assert sep
  if key not in config:config[key]=value
 assert alias=='rog-ts' and config.get('hostname')=='192.168.0.10'
 assert config.get('user')=='qian-qi' and config.get('port')=='22'
 assert config.get('hostkeyalias')=='hepta-node-rog' and config.get('identitiesonly')=='yes'
 assert config.get('userknownhostsfile')=='/home/qian-qi/.ssh/hepta-transport/known_hosts'
 assert config.get('stricthostkeychecking') in ('true','yes')
 assert config.get('batchmode')=='yes' and config.get('connectionattempts')=='1'
 assert config.get('connecttimeout')=='10' and config.get('forwardagent')=='no'
 assert config.get('updatehostkeys')=='false' or config.get('updatehostkeys')=='no'
 assert config.get('clearallforwardings')=='yes' and config.get('controlmaster') in ('false','no')
 keys=('host','hostname','user','port','hostkeyalias','stricthostkeychecking','batchmode',
       'connecttimeout','connectionattempts','forwardagent','updatehostkeys',
       'clearallforwardings','controlmaster','controlpath')
 projection={k:config.get(k) for k in keys}
 return config,{'projection':projection,'effective_config_sha256':hashlib.sha256(raw).hexdigest(),
                'known_hosts_before':known_hosts_state(config)}
def remote_command(python,source):
 return python+' -I -S -B -c '+shlex.quote(source)
try:
 assert os.getuid()==1000
 assert BASE.resolve(strict=True)==BASE and BASE.stat().st_uid==1000
 assert SOURCES.resolve(strict=True)==SOURCES and SOURCES.stat().st_uid==1000
 assert Path(__file__).resolve(strict=True)==SOURCES/'relay.py'
 assert not ROOT.exists() and not ROOT.is_symlink()
 assert not CONTROL.exists() and not CONTROL.is_symlink()
 original_raw,original_pin=stable(ORIGINAL)
 assert len(original_raw)==12409 and original_pin['sha256']==ORIGINAL_SHA
 controller_raw,controller_pin=stable(Path(__file__))
 helper_source={};helper_pins={}
 for name,digest in HELPERS.items():
  raw,pin=stable(SOURCES/name);assert pin['sha256']==digest
  compile(raw,str(SOURCES/name),'exec')
  helper_source[name]=raw.decode('ascii');helper_pins[name]=pin
 trust_before={}
 for path,expected in TRUST.items():
  _,pin=stable(Path(path),1048576);assert pin['sha256']==expected
  trust_before[path]=pin
 ROOT.mkdir(mode=0o700);fsync_dir(BASE)
 CONTROL.mkdir(mode=0o700);created=True;fsync_dir(ROOT)
 public(CONTROL/'intent.public.json',{**result,'controller':controller_pin,
        'helpers':helper_pins,'original_ha_controller':original_pin,'ssh_argv_prefix':SSH,
        'destination_create_only':True,'trust_before':trust_before})
 configs={};preflights={}
 for alias in ('rog-ts',):
  configs[alias],preflights[alias]=inspect_config(alias)
 public(CONTROL/'ssh-preflight.public.json',preflights)
 receiver=start_child('receive-desktop',['/usr/bin/python3','-I','-S','-B','-c',helper_source['receiver.py']],
                      stdin=subprocess.PIPE)
 try:
  sender=start_child('send-rog',[*SSH,'rog-ts',remote_command('/usr/bin/python3',helper_source['sender.py'])],
                     stdout=receiver['process'].stdin)
 finally:
  receiver['process'].stdin.close()
 wait_child(sender)
 wait_child(receiver)
 for h in handles:h.flush();os.fsync(h.fileno())
 sender_result=json.loads(read_log(sender,'stderr'));receiver_result=json.loads(read_log(receiver,'stderr'))
 assert read_log(receiver,'stdout')==b''
 for endpoint in (sender_result,receiver_result):
  assert endpoint['status']=='complete' and endpoint['all_owned_stopped']
  assert endpoint['within_original_deadline'] and endpoint['request_seconds']==90
  assert endpoint['git_operations']==0 and not endpoint['server_started'] and not endpoint['compiler_started']
  assert endpoint['source_commit']==HEAD and endpoint['source_tree']==TREE
 assert sender_result['role']=='sender' and receiver_result['role']=='receiver'
 assert len(sender_result['files'])==len(receiver_result['files'])==len(FILES)
 for item,sent,received in zip(FILES,sender_result['files'],receiver_result['files']):
  assert sent['name']==received['name']==item['name']
  assert sent['source']==item['path'] and sent['source_version']==item['version']
  assert sent['source_identity_before']==sent['source_identity_after']
  expected={'bytes':item['bytes'],'sha256':item['sha256']}
  assert sent['initial_file']==sent['stream']==received['same_fd_readback']==expected
  assert received['bytes']==item['bytes'] and received['sha256']==item['sha256']
  assert received['path']==str(ROOT/'incoming'/item['name'])
  assert received['mode']==item['target_mode'] and received['create_only'] and received['fsynced']
 assert receiver_result['destination_created_exclusive'] and receiver_result['destination_directory_mode']==0o500
 assert receiver_result['destination_fsynced'] and receiver_result['raw_receipts_preserved']
 assert receiver_result['qa_build_provenance_verified']
 remote_endpoints_verified=True
 for alias in ('rog-ts',):
  assert known_hosts_state(configs[alias])==preflights[alias]['known_hosts_before']
 for path,pin in trust_before.items():assert stable(Path(path),1048576)[1]==pin
 result['trust_before']=trust_before;result['trust_after']=trust_before
 assert stable(ORIGINAL)[1]==original_pin and stable(Path(__file__))[1]==controller_pin
 for name,pin in helper_pins.items():assert stable(SOURCES/name)[1]==pin
 result.update({'status':'transferred','sender':sender_result,'receiver':receiver_result,
                'controller':controller_pin,'helpers':helper_pins,'ssh_preflight':preflights,
                'original_ha_controller_before':original_pin,'original_ha_controller_after':stable(ORIGINAL)[1]})
except BaseException as e:
 result['status']='failed';result['error_type']=type(e).__name__
 frames=[];tb=e.__traceback__
 while tb is not None:
  frames.append({'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno});tb=tb.tb_next
 result['failure_frames']=frames
finally:
 for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)
 errors=[]
 for row in reversed(children):
  try:
   if row['process'].stdin is not None and not row['process'].stdin.closed:row['process'].stdin.close()
   stop_active(row['process'])
  except BaseException as e:errors.append({'label':row['label'],'error_type':type(e).__name__})
 for h in handles:
  try:h.flush();os.fsync(h.fileno());h.close()
  except BaseException as e:errors.append({'label':'capture-close','error_type':type(e).__name__})
 rows=None
 try:rows=snapshot()
 except BaseException as e:errors.append({'label':'snapshot','error_type':type(e).__name__})
 cleanup=[{'label':row['label'],'pid':row['process'].pid,'exit_code':row['process'].returncode,
  'direct_child_reaped':row['process'].returncode is not None,
  'remaining':None if rows is None else [p for p in rows if p['pgid']==row['process'].pid]}
  for row in children]
 result['commands']=commands;result['cleanup']=cleanup;result['cleanup_errors']=errors
 result['all_local_owned_stopped']=bool(cleanup) and not errors and all(r['direct_child_reaped'] and r['remaining']==[] for r in cleanup)
 endpoint_launched=any(row['label'] in ('send-rog','receive-desktop') for row in children)
 result['remote_endpoint_completion_verified']=remote_endpoints_verified
 result['remote_cleanup_unknown']=endpoint_launched and not remote_endpoints_verified
 result['all_owned_stopped']=result['all_local_owned_stopped'] and not result['remote_cleanup_unknown']
 if pending_signal is not None or not result['all_owned_stopped'] or time.monotonic()>=UNTIL:result['status']='failed'
 result['elapsed_seconds']=time.monotonic()-START;result['terminal_unix_ns']=time.time_ns()
 if created:public(CONTROL/'result.public.json',result)
 terminal={'status':result['status'] if time.monotonic()<UNTIL else 'failed',
  'receipt':str(CONTROL/'result.public.json') if created else None,
  'all_owned_stopped':result['all_owned_stopped'],'publication_within_original_deadline':time.monotonic()<UNTIL,
  'elapsed_after_publication_seconds':time.monotonic()-START,'git_operations':0,'server_started':False,'compiler_started':False}
 if not created:terminal['unpublished_failed_result']=result
 print(json.dumps(terminal,sort_keys=True),flush=True)
sys.exit(0 if terminal['status']=='transferred' and time.monotonic()<UNTIL else 1)
