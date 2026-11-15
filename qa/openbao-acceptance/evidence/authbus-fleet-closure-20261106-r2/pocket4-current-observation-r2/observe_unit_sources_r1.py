#!/usr/bin/env python3
"""Read the five systemd source files selected by one completed path query.

Original unit bytes and all configuration-derived digests stay in a new private
host directory. This observes syntax; it does not claim systemd expansion or
execute a service, SDK, shell, provider, or network operation.
"""
import hashlib,json,os,shlex,stat,sys,time
from pathlib import Path

HOME=Path('/home/alex')
ROOT=HOME/'heptabao-pocket4-unit-source-observation-20261106-r1'
BASE=HOME/'.config/systemd/user'
RELATIVE=(
 'openclaw-gateway.service',
 'openclaw-gateway.service.d/30-telegram-spooled-handler-timeout.conf',
 'openclaw-gateway.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf',
 'openclaw-authbus-restart-when-idle.service',
 'openclaw-authbus-restart-when-idle.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf')
START=time.monotonic();UNTIL=START+15
report={'schema':'heptabao.pocket4.selected-unit-source-observation.r1','ok':False,
 'selectedByJob':'1a1b2d7d5f2-fc05-7ffd','sourceFileCount':5,
 'productionMutations':0,'serviceActions':0,'childrenStarted':0,
 'credentialDatabaseContentsRead':False,'providerCalled':False,'networkOpened':False,
 'sdkImported':False,'rawUnitContentsOrDigestsPublished':False,
 'unitExpansionQualified':False,'existingHoldsChanged':False,'fileDescriptors':[]}
anchors={};fdrecords=[];codes=set();created=False;originals=[]
def need(x,code):
 if not x:codes.add(code);raise RuntimeError(code)
def remaining():need(time.monotonic()<UNTIL,'bounded_unit_observation_deadline')
def ident(s):return [str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def track(fd,role):
 row={'ordinal':len(fdrecords),'role':role,'closeAttempts':0,'closed':False};fdrecords.append(row);return fd,row
def close(item):
 fd,row=item;need(row['closeAttempts']==0,'unit_fd_close_once');row['closeAttempts']=1
 os.close(fd);row['closed']=True
def read(path):
 remaining();need(path.is_absolute() and '..' not in path.parts,'fixed_absolute_unit_path')
 held=[]
 try:
  item=track(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC),'unit-parent');held.append(item);current=Path('/')
  for name in path.parts[1:-1]:
   current/=name
   item=track(os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=item[0]),'unit-parent');held.append(item)
   s=os.fstat(item[0]);need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.getuid()) and not s.st_mode&0o022,'owned_unit_parent')
   v=ident(s)[:5];need(v==ident(current.lstat())[:5],'same_named_unit_parent')
   if str(current) in anchors:need(anchors[str(current)]==v,'unchanged_unit_parent')
   else:anchors[str(current)]=v
  item=track(os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=item[0]),'unit-source');held.append(item)
  s=os.fstat(item[0]);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid in (0,os.getuid()) and not s.st_mode&0o022 and 0<s.st_size<=65536,'bounded_owned_unit_source')
  raw=bytearray()
  while len(raw)<=s.st_size:
   remaining();part=os.read(item[0],min(16384,s.st_size+1-len(raw)))
   if not part:break
   raw.extend(part)
  need(len(raw)==s.st_size and ident(s)==ident(os.fstat(item[0]))==ident(path.lstat()),'stable_complete_unit_source')
  return bytes(raw),ident(s)
 finally:
  for item in reversed(held):close(item)
def save(name,raw):
 need(created and '/' not in name and len(raw)<=1048576,'bounded_private_unit_copy')
 item=track(os.open(ROOT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600),'private-output')
 try:
  buf=memoryview(raw)
  while buf:
   remaining();n=os.write(item[0],buf);need(n>0,'private_unit_write_progress');buf=buf[n:]
  os.fsync(item[0])
 finally:close(item)
def projection(raw):
 text=raw.decode('utf-8');need('\x00' not in text,'unit_text_no_nul')
 sections={'Unit','Service','Install'}
 keys={'Description','Documentation','After','Before','Wants','Requires','PartOf','BindsTo',
  'Type','ExecStart','ExecStartPre','ExecStartPost','ExecCondition','ExecStop','ExecStopPost',
  'Environment','EnvironmentFile','WorkingDirectory','RootDirectory','User','Group',
  'Restart','RestartSec','TimeoutStartSec','TimeoutStopSec','KillMode','KillSignal','SendSIGKILL',
  'LimitNOFILE','Nice','CPUQuota','MemoryMax','UMask','StandardOutput','StandardError','SyslogIdentifier',
  'WantedBy','RequiredBy','Alias','ConditionPathExists','ConditionPathIsDirectory','ConditionEnvironment',
  'AssertPathExists','AssertPathIsDirectory','StartLimitIntervalSec','StartLimitBurst'}
 executable_paths={'/usr/bin/node','/usr/bin/env','/usr/bin/bash','/bin/bash','/bin/sh',
  '/usr/bin/python3','/bin/false','/bin/true',
  '/home/alex/.local/bin/openclaw-gateway',
  '/home/alex/.local/bin/openclaw-gateway-launch',
  '/home/alex/.local/bin/openclaw-authbus-restart-when-idle'}
 section=None;rows=[];continued=False;skip_continuation=False
 for line in text.splitlines():
  clean=line.strip()
  if not clean or clean.startswith(('#',';')):continue
  if skip_continuation:
   skip_continuation=clean.endswith('\\');continue
  if clean.endswith('\\'):continued=True;skip_continuation=True;continue
  if clean.startswith('[') and clean.endswith(']'):
   section=clean[1:-1] if clean[1:-1] in sections else 'unsupported-section';continue
  if '=' not in line:rows.append({'section':section,'unsupportedLine':True});continue
  key,value=line.split('=',1);key=key.strip();value=value.strip()
  if key not in keys:
   rows.append({'section':section,'unsupportedDirective':True});continue
  row={'section':section,'key':key,'empty':not value}
  if key in ('ExecStart','ExecStartPre','ExecCondition','ExecStop','ExecStopPost'):
   try:parts=shlex.split(value,posix=True)
   except ValueError:parts=[];row['shellTokenizationFailed']=True
   row['tokenCount']=len(parts)
   if parts:
    first=parts[0];prefix=first.lstrip('-@:+!')
    if prefix in executable_paths:
     row['executablePath']=prefix;row['execPrefixPresent']=prefix!=first
    else:row['executablePathKeptPrivate']=True
    row['argumentValuesKeptPrivate']=True
  elif key=='Environment':
   try:parts=shlex.split(value,posix=True)
   except ValueError:parts=[];row['shellTokenizationFailed']=True
   need(all('=' in p for p in parts),'complete_environment_assignments_only')
   keys=[p.partition('=')[0] for p in parts]
   need(all(k.replace('_','').isalnum() and len(k)<100 for k in keys),'safe_environment_key_projection')
   row['keys']=keys
  elif key in ('EnvironmentFile','WorkingDirectory','RootDirectory','User','Group'):
   row['valueKeptPrivate']=True
  elif key.startswith(('Condition','Assert')):row['valueKeptPrivate']=True
  rows.append(row)
 return {'directives':rows,'lineContinuationsPresent':continued}
try:
 need(sys.platform=='linux' and Path.home()==HOME,'selected_pocket4_account')
 os.umask(0o077);sys.dont_write_bytecode=True
 home=HOME.lstat();need(stat.S_ISDIR(home.st_mode) and home.st_uid==os.getuid() and not home.st_mode&0o022,'owned_pocket4_home')
 for rel in RELATIVE:
  raw,identity=read(BASE/rel);originals.append((rel,raw,identity))
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 projections=[];private_manifest=[]
 for ordinal,(rel,raw,identity) in enumerate(originals):
  filename=f'unit-{ordinal:02d}.original.private';save(filename,raw)
  private_manifest.append({'sourcePath':str(BASE/rel),'file':filename,'identity':identity,'sha256':hashlib.sha256(raw).hexdigest()})
  projections.append({'sourcePath':str(BASE/rel),'bytes':len(raw),**projection(raw)})
 save('bindings.private.json',(json.dumps(private_manifest,separators=(',',':'))+'\n').encode())
 for rel,raw,identity in originals:
  again,after=read(BASE/rel);need(raw==again and identity==after,'all_original_unit_generations_unchanged')
 for name,value in anchors.items():need(ident(Path(name).lstat())[:5]==value,'all_unit_parent_anchors_unchanged')
 item=track(os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC),'private-output-directory')
 try:os.fsync(item[0])
 finally:close(item)
 report.update(ok=True,units=projections,allOriginalsUnchanged=True)
except BaseException as error:
 report['errorType']=type(error).__name__;report['errorCode']=str(error) if str(error) in codes else 'selected_unit_source_unavailable'
finally:
 report['fileDescriptors']=fdrecords;report['allRecordedFileDescriptorsClosedOnce']=all(r['closeAttempts']==1 and r['closed'] for r in fdrecords)
 if not report['allRecordedFileDescriptorsClosedOnce']:report['ok']=False
 report['createdPrivateObservationRoot']=created;report['elapsedSeconds']=time.monotonic()-START
 print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
sys.exit(0 if report['ok'] else 1)
