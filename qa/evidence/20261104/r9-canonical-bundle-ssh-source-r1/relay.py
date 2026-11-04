#!/usr/bin/env python3
"""Fixed public Git-bundle relay over the prior successful HA SSH aliases.
No Git, compiler, server, HTTP, key generation, credential read or production change.
"""
from pathlib import Path
import hashlib,json,os,shlex,signal,stat,subprocess,sys,time
os.umask(0o077)
BASE=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
SOURCES=BASE/'r9-canonical-bundle-ssh-source-r1'
CONTROL=BASE/'r9-canonical-bundle-ssh-relay-r1'
ORIGINAL=BASE/'normal-33cafa-full128-control-r2/launch_normal_33cafa_full128_r2.py'
ORIGINAL_SHA='c70892cb19601fa9769ae3f36810bb123f756f335654f284a4001bf2d69c796e'
EXPECTED_BYTES=1886365
EXPECTED_SHA='49060b399899b9904aded82973589837062dace090fcb43102fa862a5ff7fb06'
SOURCE_VERSION='66306:28228563:1886365:1793814029233278292:1793814029235278291'
HELPERS={'sender.py':'e855a5deefe27ef4cbccc28e7e654c6c23d7ce0b86c3d8c5e5284c5228f2488b','receiver.py':'28b594cd10f9a15633ce54eaf8ab66d8d789f55543e47bb3b5e842bc1fb46e99'}
SSH=['/usr/bin/ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
     '-o','ConnectTimeout=10','-o','ConnectionAttempts=1',
     '-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','UpdateHostKeys=no',
     '-o','ControlMaster=no','-o','ControlPath=none']
START=time.monotonic();UNTIL=START+300
children=[];commands=[];handles=[];protected=0;pending_signal=None;created=False;remote_endpoints_verified=False
result={'schema':'heptabao.r9.fixed-public-bundle-relay.v1','status':'failed',
 'overall_seconds':300,'ssh_child_seconds':90,'endpoint_seconds':90,'diskutil_seconds':30,
 'source_alias':'rog-ts','destination_alias':'mac-ts','expected_bytes':EXPECTED_BYTES,
 'expected_sha256':EXPECTED_SHA,'source_version':SOURCE_VERSION,
 'git_operations':0,'compiler_started':False,'server_started':False,'runtime_qualification':False}
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
 return python+' -B -c '+shlex.quote(source)
try:
 assert os.getuid()==1000
 assert BASE.resolve(strict=True)==BASE and BASE.stat().st_uid==1000
 assert SOURCES.resolve(strict=True)==SOURCES and SOURCES.stat().st_uid==1000
 assert Path(__file__).resolve(strict=True)==SOURCES/'relay.py'
 assert not CONTROL.exists() and not CONTROL.is_symlink()
 original_raw,original_pin=stable(ORIGINAL)
 assert len(original_raw)==12409 and original_pin['sha256']==ORIGINAL_SHA
 controller_raw,controller_pin=stable(Path(__file__))
 helper_source={};helper_pins={}
 for name,digest in HELPERS.items():
  raw,pin=stable(SOURCES/name);assert pin['sha256']==digest
  compile(raw,str(SOURCES/name),'exec')
  helper_source[name]=raw.decode('ascii');helper_pins[name]=pin
 CONTROL.mkdir(mode=0o700);created=True
 public(CONTROL/'intent.public.json',{**result,'controller':controller_pin,
        'helpers':helper_pins,'original_ha_controller':original_pin,'ssh_argv_prefix':SSH,
        'destination_create_only':True,'t5_uuid':'FB804D1B-24CB-4D6E-AEA7-A9E180807758'})
 configs={};preflights={}
 for alias in ('rog-ts','mac-ts'):
  configs[alias],preflights[alias]=inspect_config(alias)
 public(CONTROL/'ssh-preflight.public.json',preflights)
 receiver=start_child('receive-mac',[*SSH,'mac-ts',remote_command('/opt/homebrew/bin/python3',helper_source['receiver.py'])],
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
 assert sender_result['role']=='sender' and sender_result['source_version']==SOURCE_VERSION
 assert sender_result['source_identity_before']==sender_result['source_identity_after']
 assert sender_result['stream']=={'bytes':EXPECTED_BYTES,'sha256':EXPECTED_SHA}
 assert receiver_result['role']=='receiver' and receiver_result['destination_created_exclusive']
 assert receiver_result['volume']['uuid']=='FB804D1B-24CB-4D6E-AEA7-A9E180807758'
 assert receiver_result['received']==receiver_result['same_fd_readback']=={'bytes':EXPECTED_BYTES,'sha256':EXPECTED_SHA}
 assert receiver_result['destination_fsynced']
 remote_endpoints_verified=True
 for alias in ('rog-ts','mac-ts'):
  assert known_hosts_state(configs[alias])==preflights[alias]['known_hosts_before']
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
 endpoint_launched=any(row['label'] in ('send-rog','receive-mac') for row in children)
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
