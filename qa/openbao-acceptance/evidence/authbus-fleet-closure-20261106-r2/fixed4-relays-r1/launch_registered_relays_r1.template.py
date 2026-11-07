#!/usr/bin/env python3
"""Read the four already registered relay services in one original parent.

Ten bounded launchctl commands with the original retained-child helper and
its original ps metadata children. Raw registration/plist/environment and
executable pins stay in the new private directory. No database, SDK, provider,
signal to an application, service action, or inference of consumer quiescence.
"""
import ast
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Users/qianqi/heptabao-authbus-four-relay-registration-20261106-r1')
HOME=Path('/Users/qianqi')
QUAL=HOME/'heptabao-authbus-auth-wal-qualification-20261106-r2'
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
RUNTIME_PINS={
 PYTHON:(34640,'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13',0o755),
 '/bin/launchctl':(363488,'b4dbf509754d8e1117f7851baa93ede75bc75218c48d6ddf19fbb1505d261be7',0o755),
 '/bin/ps':(170432,'3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c',0o4755)}
SOURCE_NAMES=('mac_owned_unreaped_r1.py','mac_owned_commands_r1.py',
 'mac_native_process_observer_r1.py','mac_owned_launchd_r3.py',
 'mac_gateway_service_primitives_r4.py','mac_current_gateway_observation_r2.py',
 'mac_registered_relays_r1.py')
FIELDS=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
# PAYLOAD_PLACEHOLDER

report={'schema':'heptabao.mac-fixed-four-relay-observation-launch.public.r1','ok':False,
 'sharedSeconds':45,'supervisorSeconds':70,'automaticRetry':False,
 'selectedRegisteredServiceCount':4,'originalLaunchctlCommandsExpected':10,
 'originalRetainedCustodyIncludesItsOwnPsMetadataChildren':True,
 'totalOperatingSystemChildCountClaimed':False,
 'databaseReads':0,'credentialReads':0,'providerCalls':0,'serviceMutations':0,
 'applicationSignals':0,'sdkImported':False,'fullConsumerCoverageProven':False,
 'productionQuiescenceProven':False,'productionRestartOrRollbackQualified':False,
 'privateArgumentsEnvironmentPlistOrDigestPublished':False,
 'observationsAreDiscreteNotAContinuousLock':True,
 'sourcePins':{},'runtimePins':{},'recordedFileDescriptors':[]}
codes=set();anchors=[];runtime_bindings={};source_bindings={};created=False
root_fd=None;root_identity=None;commands=None;observer=None;signals=None;modules=[]

def need(value,code):
 if not value:codes.add(code);raise RuntimeError(code)
def remaining():
 need(time.monotonic()<UNTIL,'relay_parent_original_absolute_deadline')
 if signals is not None:need(signals.pending is None,'relay_parent_cancelled')
def ident(value):return tuple(getattr(value,key) for key in FIELDS)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def open_fd(path,flags,mode=None,dir_fd=None,role='public-source'):
 fd=os.open(path,flags,mode if mode is not None else 0o777,dir_fd=dir_fd)
 row={'ordinal':len(report['recordedFileDescriptors']),'role':role,'closeAttempts':0,'closed':False}
 report['recordedFileDescriptors'].append(row)
 return fd,row
def close_fd(item):
 fd,row=item;need(row['closeAttempts']==0,'relay_parent_descriptor_close_once');row['closeAttempts']=1
 try:os.close(fd);row['closed']=True
 except BaseException:row['closeUnknown']=True;raise
def read(path,cap=1048576,*,expected=None):
 remaining();item=open_fd(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  fd,_=item;value=os.fstat(fd)
  need(stat.S_ISREG(value.st_mode) and value.st_uid in (0,501) and value.st_nlink==1
   and not stat.S_IMODE(value.st_mode)&0o022 and 0<value.st_size<=cap,'relay_bounded_public_source_file')
  if expected is not None:need(ident(value)==expected,'relay_original_public_source_generation')
  raw=bytearray()
  while len(raw)<=value.st_size:
   remaining();part=os.read(fd,min(65536,value.st_size+1-len(raw)))
   if not part:break
   raw.extend(part)
  need(len(raw)==value.st_size and ident(value)==ident(os.fstat(fd))==ident(Path(path).lstat()),
   'relay_complete_stable_public_source_file')
  return bytes(raw),ident(value)
 finally:close_fd(item)
def private(name,value,*,publication=False):
 need(type(name) is str and re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,127}',name) is not None
  and name not in ('.','..'),'relay_exact_private_output_name')
 raw=value if isinstance(value,bytes) else encoded(value)
 need(root_fd is not None and isinstance(raw,bytes) and len(raw)<=2*1048576,'relay_bounded_private_output')
 if not publication:remaining()
 item=open_fd(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,
  dir_fd=root_fd[0],role='owned-private-file')
 try:
  view=memoryview(raw)
  while view:
   if not publication:remaining()
   count=os.write(item[0],view);need(count>0,'relay_private_write_progress');view=view[count:]
  os.fsync(item[0])
 finally:close_fd(item)
 os.fsync(root_fd[0])
def verify_anchors():
 for path,item,original in anchors:
  need(ident(os.fstat(item[0]))[:5]==original[:5]==ident(path.lstat())[:5],
   'relay_same_parent_directory_identity')
 if root_fd is not None:
  need(ident(os.fstat(root_fd[0]))[:5]==root_identity[:5]==ident(ROOT.lstat())[:5],
   'relay_same_created_private_root')
def runtime_fence():
 remaining();verify_anchors()
 for path,(size,pin,mode) in RUNTIME_PINS.items():
  raw,full=read(path,2097152,expected=runtime_bindings.get(path))
  need(len(raw)==size and sha(raw)==pin and stat.S_IMODE(full[4])==mode,
   'relay_exact_native_runtime_size_hash_mode')
  runtime_bindings.setdefault(path,full)
 if created:
  for name in SOURCE_NAMES:
   value=PAYLOAD['sources'][name];raw,full=read(ROOT/name,expected=source_bindings.get(name))
   need(len(raw)==value['bytes'] and sha(raw)==value['sha256'] and raw==value['text'].encode(),
    'relay_exact_whole_helper_source')
   source_bindings.setdefault(name,full)
def import_exact(name):
 filename=name+'.py';need(name not in sys.modules,'relay_no_prior_helper_module')
 raw,_=read(ROOT/filename,expected=source_bindings[filename])
 need(sha(raw)==PAYLOAD['sources'][filename]['sha256'],'relay_exact_helper_before_exec')
 module=types.ModuleType(name);module.__file__=str(ROOT/filename);module.__package__=''
 sys.modules[name]=module;modules.append((name,module))
 exec(compile(raw,str(ROOT/filename),'exec',dont_inherit=True),module.__dict__)
 return module
def pure(name,names,namespace):
 raw,_=read(ROOT/name,expected=source_bindings[name])
 need(sha(raw)==PAYLOAD['sources'][name]['sha256'],'relay_exact_whole_pure_definition_source')
 parsed=ast.parse(raw)
 selected=[node for node in parsed.body if isinstance(node,(ast.ClassDef,ast.FunctionDef)) and node.name in names]
 need([node.name for node in selected]==list(names),'relay_ordered_exact_pure_definition_set')
 # Whole original bytes and exact definition order are bound. No version-
 # dependent ast.dump serialization is substituted for that byte authority.
 exec(compile(ast.Module(body=selected,type_ignores=[]),str(ROOT/name)+':fixed-pure-excerpt','exec'),namespace)
 return namespace
def safe_commands():
 if commands is None:return {'commands':[],'allOwnedCommandsStopped':True,'unknownCommandCount':0}
 value=commands.public()
 rows=[]
 for row in value['commands']:
  rows.append(None if row is None else {key:item for key,item in row.items()
   if key not in ('stdoutSha256','stderrSha256')})
 return {**value,'commands':rows}

try:
 need(sys.platform=='darwin' and os.getuid()==501 and os.geteuid()==501
  and str(Path(sys.executable).resolve())==PYTHON,'relay_actual_host_and_exact_interpreter')
 os.umask(0o077);sys.dont_write_bytecode=True
 need(set(PAYLOAD)=={'schema','sources','custodyQualificationAuthority'}
  and PAYLOAD['schema']=='heptabao.fixed-four-relay-observation.payload.r1'
  and set(PAYLOAD['sources'])==set(SOURCE_NAMES),'relay_fixed_embedded_source_scope')
 authority=PAYLOAD['custodyQualificationAuthority']
 need(authority['job_id']=='1a1b141ef40-fc05-7750' and authority['state']=='succeeded'
  and type(authority['exit_code']) is int and authority['exit_code']==0
  and all(authority[k] is True for k in ('output_complete','output_durable','terminal_publication_confirmed'))
  and all(authority[k] is False for k in ('timed_out','cancelled','automatic_retry')),
  'relay_original_custody_qualification_authority')
 proof,_=read(QUAL/'result.public.json',65536)
 need(len(proof)==58701 and sha(proof)=='67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e',
  'relay_original_custody18_bytes')
 previous=json.loads(proof)
 need(previous['ok'] and previous['allCasesMatched'] and previous['allOwnedClosed']
  and previous['custody']['passed_process_custody'] and previous['custody']['original_count']==18,
  'relay_original_custody18_not_this_attempt_count')
 for name,value in PAYLOAD['sources'].items():
  raw=value['text'].encode()
  need(set(value)=={'text','bytes','sha256'} and len(raw)==value['bytes']
   and sha(raw)==value['sha256'] and len(raw)<=262144,'relay_exact_embedded_public_source')
  compile(raw,name,'exec');report['sourcePins'][name]={'bytes':len(raw),'sha256':sha(raw)}
 for path in (Path('/'),Path('/Users'),HOME):
  value=path.lstat()
  need(stat.S_ISDIR(value.st_mode) and value.st_uid==(501 if path==HOME else 0)
   and not stat.S_IMODE(value.st_mode)&0o022,'relay_private_root_parent_custody')
  item=open_fd(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,role='parent-directory')
  need(ident(os.fstat(item[0]))==ident(value),'relay_opened_parent_identity');anchors.append((path,item,ident(value)))
 verify_anchors()
 parent_path,parent_item,parent_before=anchors[-1]
 os.mkdir(ROOT.name,0o700,dir_fd=parent_item[0]);created=True
 parent_after=ident(os.fstat(parent_item[0]))
 need(parent_after==ident(parent_path.lstat()) and parent_before[:5]==parent_after[:5]
  and parent_after[5] in (parent_before[5],parent_before[5]+1),'relay_only_owned_mkdir_parent_rebase')
 anchors[-1]=(parent_path,parent_item,parent_after)
 root_fd=open_fd(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,role='owned-root')
 root_identity=ident(os.fstat(root_fd[0]))
 need(root_identity==ident(ROOT.lstat()) and root_identity[2:5]==(501,20,stat.S_IFDIR|0o700),
  'relay_new_private_root_identity')
 for name,value in PAYLOAD['sources'].items():private(name,value['text'].encode())
 runtime_fence()
 for path,(size,pin,mode) in RUNTIME_PINS.items():report['runtimePins'][path]={'bytes':size,'sha256':pin,'mode':oct(mode)}
 import_exact('mac_owned_unreaped_r1').require_waitid()
 command_module=import_exact('mac_owned_commands_r1')
 core=import_exact('mac_registered_relays_r1')
 parser=pure('mac_owned_launchd_r3.py',('ManagerRefused','need','parse_print','missing_service'),{'re':re})
 native=pure('mac_native_process_observer_r1.py',('ObservationRefused','require','BsdInfo','ProcessReader'),
  {'ctypes':ctypes,'sys':sys,'Path':Path})
 disabled={};plists={}
 for label in core.LABELS:
  disabled[label]=pure('mac_gateway_service_primitives_r4.py',('Refused','need','parse_disabled'),
   {'re':re,'DOMAIN':'gui/501','LABEL':label})['parse_disabled']
  plists[label]=pure('mac_current_gateway_observation_r2.py',('ObservationRefused','need','identity','FixedPlist'),
   {'os':os,'stat':stat,'Path':Path,'FIELDS':FIELDS,'HOME':HOME,
    'PLIST':HOME/'Library/LaunchAgents'/(label+'.plist')})['FixedPlist']
 def parse_selected_disabled(raw,label):
  need(label in disabled,'relay_only_fixed_disabled_label');return disabled[label](raw)
 def fixed_plist(label,callback):
  need(label in plists,'relay_only_fixed_plist_label');return plists[label](callback)
 signals=command_module.Signals();signals.install();commands=command_module.Commands(signals)
 # All new directories and public source files exist before any current HOME
 # or source/plist descriptor is held by the observation phase.
 observer=core.RegisteredRelayInputs(commands=commands,reader=native['ProcessReader'](),
  parse_print=parser['parse_print'],parse_disabled=parse_selected_disabled,plist_factory=fixed_plist,
  parent_until=UNTIL,source_fence=runtime_fence,private_write=private)
 observer.capture();observer.verify();runtime_fence();remaining()
 need(len(commands.rows)==10,'relay_exact_ten_original_readonly_helpers')
 report['ok']=True
except BaseException as error:
 report['errorType']=type(error).__name__
 safe=type(error).__name__ in ('RelayRefused','ObservationRefused','ManagerRefused','CommandRefused','Refused','Refusal')
 safe=safe and re.fullmatch(r'[a-z0-9_]{1,120}',str(error)) is not None
 report['errorCode']=str(error) if str(error) in codes or safe else 'fixed_relay_observation_refused_or_unknown'
 report['ok']=False
finally:
 if observer is not None:
  try:report['relayObservation']=observer.close()
  except BaseException:report['observationCloseUnknown']=True;report['ok']=False
  if not report.get('relayObservation',{}).get('allPlistSourceDescriptorsClosedOnce') or not report.get('relayObservation',{}).get('allBinaryDescriptorsClosedOnce'):
   report['ok']=False
 state=safe_commands();report['originalCommandHelpers']=state
 if not state['allOwnedCommandsStopped'] or state['unknownCommandCount']!=0:report['ok']=False
 report['applicationOrServiceCleanupAttempted']=False
 report['createdPrivateRoot']=created
 report['elapsedSeconds']=time.monotonic()-START
 report['readonlyCompletedWithinOriginal45Seconds']=report['ok'] and report['elapsedSeconds']<45
 if not report['readonlyCompletedWithinOriginal45Seconds']:report['ok']=False
 # Publication does not extend the command or source-observation budget.
 try:
  if root_fd is not None:private('result-pre-close.public.json',report,publication=True)
 except BaseException:report['publicationFailed']=True;report['ok']=False
 if root_fd is not None:
  try:close_fd(root_fd)
  except BaseException:report['ok']=False
 for _path,item,_identity in reversed(anchors):
  try:close_fd(item)
  except BaseException:report['ok']=False
 report['allLauncherRecordedDescriptorsClosedOnce']=all(row['closeAttempts']==1 and row['closed'] for row in report['recordedFileDescriptors'])
 if not report['allLauncherRecordedDescriptorsClosedOnce']:report['ok']=False
 report['elapsedSecondsIncludingPublication']=time.monotonic()-START
 print(json.dumps(report,sort_keys=True,separators=(',',':'),allow_nan=False),flush=True)
raise SystemExit(0 if report['ok'] else 1)
