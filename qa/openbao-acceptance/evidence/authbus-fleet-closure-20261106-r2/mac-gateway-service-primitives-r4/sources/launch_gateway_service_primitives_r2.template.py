#!/usr/bin/env python3
"""Single credential-free qualification of one new launchd QA label.

The original command helper owns each helper child. Launchd owns the two finite
sleep services. No production service, configuration or credential is read.
Failure never dispatches a compensating service mutation or replays an intent.
"""
import ast,hashlib,json,os,re,stat,sys,time,types
from pathlib import Path

START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Users/qianqi/heptabao-authbus-gateway-service-primitives-20261106-r2')
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
# PAYLOAD_PLACEHOLDER
RUNTIME_PINS={
 PYTHON:(34640,'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13',0o755),
 '/bin/sleep':(100976,'c30e72b2e2d6a4eb32b6f38f07815346bc734d031d3c712d9123f28d8b237051',0o755),
 '/bin/launchctl':(363488,'b4dbf509754d8e1117f7851baa93ede75bc75218c48d6ddf19fbb1505d261be7',0o755),
 '/bin/ps':(170432,'3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c',0o4755)}
SOURCE_NAMES=('mac_owned_unreaped_r1.py','mac_owned_commands_r1.py',
 'mac_native_process_observer_r1.py','mac_owned_launchd_r3.py',
 'mac_gateway_service_primitives_r2.py')
report={'schema':'heptabao.actual-mac-gateway-service-primitives-launcher.r2','ok':False,
 'sharedSeconds':45,'supervisorSeconds':70,'automaticRetry':False,
 'actualProductionGatewayChanged':False,'credentialOrConfigurationReads':0,
 'providerCalls':0,'originalMutationsExpected':6,'sleepServiceGenerationsExpected':2,
 'productionKeepAliveRollbackQualified':False,'originalDisabledMapPublished':False,
 'sourcePins':{},'runtimePins':{},'recordedFileDescriptors':[]}
codes=set();anchors=[];runtime_bindings={};source_bindings={};created=False;commands=None;qualification=None
root_fd=None;modules=[];signals=None
def need(value,code):
 if not value:codes.add(code);raise RuntimeError(code)
def remaining():
 need(time.monotonic()<UNTIL,'original_service_qualification_deadline')
 if signals is not None:need(signals.pending is None,'original_service_qualification_cancelled')
def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def sha(raw):return hashlib.sha256(raw).hexdigest()
def open_fd(path,flags,mode=None,dir_fd=None,role='public-source'):
 fd=os.open(path,flags,mode if mode is not None else 0o777,dir_fd=dir_fd)
 row={'ordinal':len(report['recordedFileDescriptors']),'role':role,'closeAttempts':0,'closed':False}
 report['recordedFileDescriptors'].append(row)
 return fd,row
def close_fd(item):
 fd,row=item;need(row['closeAttempts']==0,'recorded_fd_close_once');row['closeAttempts']=1
 try:os.close(fd);row['closed']=True
 except BaseException:row['closeUnknown']=True;raise
def read(path,cap=1048576,*,expected=None):
 remaining();item=open_fd(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  fd,_=item;s=os.fstat(fd)
  need(stat.S_ISREG(s.st_mode) and s.st_uid in (0,501) and s.st_nlink==1
   and not stat.S_IMODE(s.st_mode)&0o022 and 0<s.st_size<=cap,'bounded_service_public_file')
  if expected is not None:need(ident(s)==expected,'same_service_public_file_generation')
  raw=bytearray()
  while len(raw)<=s.st_size:
   remaining();part=os.read(fd,min(65536,s.st_size+1-len(raw)))
   if not part:break
   raw.extend(part)
  need(len(raw)==s.st_size and ident(s)==ident(os.fstat(fd))==ident(Path(path).lstat()),'complete_stable_service_public_file')
  return bytes(raw),ident(s)
 finally:close_fd(item)
def private(name,raw,*,publication=False):
 need(isinstance(name,str) and '/' not in name and name not in ('','.','..'),'fixed_service_file_name')
 need(root_fd is not None and isinstance(raw,bytes) and len(raw)<=1048576,'bounded_service_publication')
 if not publication:remaining()
 item=open_fd(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=root_fd[0],role='owned-file')
 try:
  view=memoryview(raw)
  while view:
   if not publication:remaining()
   n=os.write(item[0],view);need(n>0,'service_owned_write_progress');view=view[n:]
  os.fsync(item[0])
 finally:close_fd(item)
 os.fsync(root_fd[0])
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def verify_anchors():
 for path,item,original in anchors:
  need(ident(os.fstat(item[0]))[:6]==original[:6]==ident(path.lstat())[:6],'same_service_parent_components')
 if root_fd is not None:
  need(ident(os.fstat(root_fd[0]))[:6]==root_identity[:6]==ident(ROOT.lstat())[:6],'same_service_created_root')
def parent_after_owned_mkdir(before,after):
 # Only the immediately containing, retained directory is rebased once after
 # this launcher's own known mkdir. Other anchors remain exact. Neither inode,
 # owner, group nor mode may change. APFS may report unchanged nlink; filesystems
 # that count child directories report exactly one additional link.
 need(len(before)==len(after)==9 and before[:5]==after[:5]
  and stat.S_ISDIR(after[4]) and after[5] in (before[5],before[5]+1),
  'only_owned_mkdir_parent_link_generation')
 return after
def runtime_fence():
 remaining();verify_anchors()
 for path,(size,pin,mode) in RUNTIME_PINS.items():
  raw,identity=read(path,2097152,expected=runtime_bindings.get(path))
  need(len(raw)==size and sha(raw)==pin and stat.S_IMODE(identity[4])==mode,'same_service_runtime_size_hash_mode')
  runtime_bindings.setdefault(path,identity)
 for name in SOURCE_NAMES:
  value=PAYLOAD['sources'][name];raw,identity=read(ROOT/name,expected=source_bindings.get(name))
  need(len(raw)==value['bytes'] and sha(raw)==value['sha256'] and raw==value['text'].encode(),'same_service_helper_source_bytes')
  source_bindings.setdefault(name,identity)
def import_exact(name):
 filename=name+'.py';need(name not in sys.modules,'no_prior_qa_helper_module')
 raw,identity=read(ROOT/filename,expected=source_bindings[filename])
 need(sha(raw)==PAYLOAD['sources'][filename]['sha256'],'exact_helper_before_exec')
 module=types.ModuleType(name);module.__file__=str(ROOT/filename);module.__package__=''
 sys.modules[name]=module;modules.append((name,module))
 exec(compile(raw,str(ROOT/filename),'exec',dont_inherit=True),module.__dict__)
 return module
try:
 need(sys.platform=='darwin' and os.getuid()==501 and os.geteuid()==501
  and str(Path(sys.executable).resolve())==PYTHON,'exact_service_qualification_host_and_interpreter')
 os.umask(0o077);sys.dont_write_bytecode=True
 need(set(PAYLOAD)=={'schema','sources','parserNames'} and PAYLOAD['schema']=='heptabao.gateway-service-primitives.payload.r2'
  and set(PAYLOAD['sources'])==set(SOURCE_NAMES)
  and PAYLOAD['parserNames']==['ManagerRefused','need','parse_print','missing_service'],'fixed_embedded_service_source_scope')
 for name,value in PAYLOAD['sources'].items():
  raw=value['text'].encode();need(set(value)=={'text','bytes','sha256'} and len(raw)==value['bytes']
   and sha(raw)==value['sha256'] and len(raw)<=262144,'embedded_service_source_exact')
  report['sourcePins'][name]={'bytes':len(raw),'sha256':sha(raw)}
 for path in (Path('/'),Path('/Users'),ROOT.parent):
  s=path.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,501)
   and not stat.S_IMODE(s.st_mode)&0o022,'safe_service_root_parent')
  item=open_fd(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,role='parent-directory')
  need(ident(os.fstat(item[0]))==ident(s),'opened_service_parent_identity');anchors.append((path,item,ident(s)))
 verify_anchors()
 parent_path,parent_item,parent_before=anchors[-1]
 need(parent_path==ROOT.parent and ident(os.fstat(parent_item[0]))[:6]==parent_before[:6],
  'exact_immediate_parent_before_owned_mkdir')
 os.mkdir(ROOT.name,0o700,dir_fd=parent_item[0]);created=True
 parent_after=ident(os.fstat(parent_item[0]))
 need(parent_after==ident(parent_path.lstat()),'same_named_parent_after_owned_mkdir')
 anchors[-1]=(parent_path,parent_item,parent_after_owned_mkdir(parent_before,parent_after))
 report['ownedMkdirParentGeneration']={'onlyImmediateParentRebased':True,
  'originalDeviceInodeOwnerGroupModeExact':True,
  'linkCountUnchangedOrExactlyOneHigher':True,
  'linkCountChanged':parent_after[5]!=parent_before[5]}
 root_fd=open_fd(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,role='owned-root')
 root_identity=ident(os.fstat(root_fd[0]));need(stat.S_IMODE(root_identity[4])==0o700 and root_identity[2]==501,'new_private_service_root')
 for name,value in PAYLOAD['sources'].items():private(name,value['text'].encode())
 runtime_fence()
 for path,(size,pin,mode) in RUNTIME_PINS.items():report['runtimePins'][path]={'bytes':size,'sha256':pin,'mode':oct(mode)}
 unreaped=import_exact('mac_owned_unreaped_r1');unreaped.require_waitid()
 command_module=import_exact('mac_owned_commands_r1')
 observer=import_exact('mac_native_process_observer_r1')
 core=import_exact('mac_gateway_service_primitives_r2')
 manager_raw,_=read(ROOT/'mac_owned_launchd_r3.py',expected=source_bindings['mac_owned_launchd_r3.py'])
 parsed=ast.parse(manager_raw);selected=[n for n in parsed.body if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name in PAYLOAD['parserNames']]
 need([n.name for n in selected]==PAYLOAD['parserNames'],'exact_qualified_parser_excerpt_nodes')
 parser_namespace={'__builtins__':__builtins__,'re':__import__('re')}
 exec(compile(ast.Module(body=selected,type_ignores=[]),str(ROOT/'mac_owned_launchd_r3.py')+':four-pure-definitions','exec'),parser_namespace)
 signals=command_module.Signals();signals.install();commands=command_module.Commands(signals)
 qualification=core.Qualification(commands=commands,reader=observer.ProcessReader(),bsd_info=observer.BsdInfo,
  parse_print=parser_namespace['parse_print'],missing_service=parser_namespace['missing_service'],until=UNTIL,runtime_fence=runtime_fence)
 qualification.run();remaining();runtime_fence()
 report['ok']=True
except BaseException as error:
 report['errorType']=type(error).__name__
 # Exception messages from original SDK/OS are never copied to public evidence.
 safe_original=type(error).__name__ in ('Refused','CommandRefused','Refusal','ObservationRefused','ManagerRefused') and re.fullmatch(r'[a-z0-9_]{1,120}',str(error)) is not None
 report['errorCode']=str(error) if (isinstance(error,RuntimeError) and str(error) in codes) or safe_original else 'service_primitives_refused_or_unknown'
 report['ok']=False
finally:
 if qualification is not None:report['qualification']=qualification.public()
 if commands is not None:
  state=commands.public()
  safe_rows=[None if row is None else core.safe_command_public(row) for row in state['commands']]
  report['originalCommandHelpers']={**state,'commands':safe_rows}
  if not state['allOwnedCommandsStopped'] or state['unknownCommandCount']!=0:report['ok']=False
 report['automaticFailureServiceMutationAttempted']=False
 report['createdPrivateRoot']=created
 report['elapsedSeconds']=time.monotonic()-START
 report['businessCompletedWithinOriginal45Seconds']=report['ok'] and report['elapsedSeconds']<45
 if not report['businessCompletedWithinOriginal45Seconds']:report['ok']=False
 # Publication is allowed after the business deadline; it never dispatches a
 # command, signal, service mutation or retry. Core failure roots stay intact.
 try:
  if created:
   private('result-pre-close.public.json',encoded(report),publication=True)
 except BaseException:report['publicationFailed']=True;report['ok']=False
 if root_fd is not None:
  try:close_fd(root_fd)
  except BaseException:report['ok']=False
 for _path,item,_identity in reversed(anchors):
  try:close_fd(item)
  except BaseException:report['ok']=False
 report['allLauncherRecordedFileDescriptorsClosedOnce']=all(x['closeAttempts']==1 and x['closed'] for x in report['recordedFileDescriptors'])
 if not report['allLauncherRecordedFileDescriptorsClosedOnce']:report['ok']=False
 report['elapsedSecondsIncludingPublication']=time.monotonic()-START
 print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
sys.exit(0 if report['ok'] else 1)
