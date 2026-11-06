#!/usr/bin/env python3
"""Project literal non-secret entry paths from the retained complete unit bytes.

This does not expand or execute systemd directives. Unknown syntax is refused;
it never exposes environment values, raw unit content, or unit-content hashes.
"""
import hashlib,json,os,re,shlex,stat,sys,time
from pathlib import Path
HOME=Path('/home/alex')
ROOT=HOME/'heptabao-pocket4-unit-source-observation-20261106-r1'
BASE=HOME/'.config/systemd/user'
RELATIVE=('openclaw-gateway.service','openclaw-gateway.service.d/30-telegram-spooled-handler-timeout.conf',
 'openclaw-gateway.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf',
 'openclaw-authbus-restart-when-idle.service','openclaw-authbus-restart-when-idle.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf')
START=time.monotonic();UNTIL=START+10;records=[];codes=set();anchors={}
report={'schema':'heptabao.pocket4.retained-unit-literal-entry-projection.r1','ok':False,
 'sourceJob':'1a1b2dcf741-fc05-800c','productionWrites':0,'serviceActions':0,'childProcesses':0,
 'networkOpened':False,'sdkImported':False,'databaseOpened':False,'environmentValuesPublished':False,
 'unitContentOrDigestsPublished':False,'systemdExpansionQualified':False,'holdsReleased':False}
def need(x,code):
 if not x:codes.add(code);raise RuntimeError(code)
def ident(s):return [str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def read(path):
 need(time.monotonic()<UNTIL,'original_projection_deadline');held=[]
 def opened(name,flags,dir_fd=None):
  fd=os.open(name,flags,dir_fd=dir_fd);r={'closeAttempts':0,'closed':False};records.append(r);held.append((fd,r));return fd
 try:
  fd=opened('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);cur=Path('/')
  for name in path.parts[1:-1]:
   fd=opened(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);cur/=name;s=os.fstat(fd)
   need(s.st_uid in (0,os.getuid()) and not s.st_mode&0o022 and ident(s)[:5]==ident(cur.lstat())[:5],'owned_bound_unit_path')
   value=ident(s)[:5]
   if str(cur) in anchors:need(anchors[str(cur)]==value,'unchanged_unit_path')
   else:anchors[str(cur)]=value
  fd=opened(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd);s=os.fstat(fd)
  need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid() and not s.st_mode&0o022 and 0<s.st_size<=65536,'owned_bounded_unit_file')
  data=bytearray()
  while len(data)<=s.st_size:
   need(time.monotonic()<UNTIL,'original_projection_deadline');part=os.read(fd,min(16384,s.st_size+1-len(data)))
   if not part:break
   data.extend(part)
  need(len(data)==s.st_size and ident(s)==ident(os.fstat(fd))==ident(path.lstat()),'complete_stable_unit_file')
  return bytes(data),ident(s)
 finally:
  for fd,r in reversed(held):
   r['closeAttempts']+=1
   try:os.close(fd);r['closed']=True
   except OSError:report['closeUnknown']=True
def directives(raw):
 values=[];section=None
 for line in raw.decode('utf-8').splitlines():
  text=line.strip()
  if not text or text.startswith(('#',';')):continue
  need(not text.endswith('\\') and '\x00' not in text,'literal_unit_no_continuation_or_nul')
  if text.startswith('[') and text.endswith(']'):section=text[1:-1];continue
  need('=' in line,'complete_unit_directive');key,value=line.split('=',1);values.append((section,key.strip(),value.strip()))
 return values
try:
 need(sys.platform=='linux' and Path.home()==HOME,'selected_pocket4_account')
 raw,_=read(ROOT/'bindings.private.json');bindings=json.loads(raw)
 need(isinstance(bindings,list) and len(bindings)==len(RELATIVE),'exact_original_unit_binding_count')
 units=[];source_rows=[]
 for i,(rel,binding) in enumerate(zip(RELATIVE,bindings)):
  need(binding['sourcePath']==str(BASE/rel) and binding['file']==f'unit-{i:02d}.original.private','fixed_original_unit_binding')
  content,_=read(ROOT/binding['file']);need(hashlib.sha256(content).hexdigest()==binding['sha256'],'exact_retained_unit_bytes')
  current,identity=read(BASE/rel);need(current==content and identity==binding['identity'],'current_unit_is_same_original_generation')
  units.append(directives(content));source_rows.append((BASE/rel,identity,content))
 gateway=[row for u in units[:3] for row in u]
 starts=[]
 for section,key,value in gateway:
  if section=='Service' and key=='ExecStart':
   if not value:starts=[]
   else:starts.append(shlex.split(value,posix=True))
 need(len(starts)==1,'one_selected_gateway_execstart');argv=starts[0]
 need(len(argv)==5 and argv[0]=='/usr/bin/node' and argv[2:4]==['gateway','--port'] and argv[4].isdigit() and 1<=int(argv[4])<=65535,'fixed_node_gateway_argument_shape')
 entry=Path(argv[1]);need(entry.is_absolute() and '..' not in entry.parts,'literal_gateway_entry_path')
 need(re.fullmatch(r'/home/alex/(?:\.[A-Za-z0-9_-]+/)*[A-Za-z0-9_./-]+/node_modules/openclaw/dist/index\.js',str(entry)) is not None,'bounded_openclaw_entry_path_shape')
 environment_files=[]
 for section,key,value in gateway:
  if section=='Service' and key=='EnvironmentFile':
   if not value:environment_files=[];continue
   optional=value.startswith('-');selected=value[1:] if optional else value
   need(re.fullmatch(r'/home/alex/(?:\.[A-Za-z0-9_-]+/)*[A-Za-z0-9_./-]+',selected) is not None and '..' not in Path(selected).parts,'literal_environment_file_path')
   environment_files.append({'path':selected,'optional':optional})
 for path,identity,content in source_rows:
  current,after=read(path);need(after==identity and current==content,'original_unit_generation_still_current')
 for path,value in anchors.items():need(ident(Path(path).lstat())[:5]==value,'all_unit_anchors_still_current')
 report.update(ok=True,gatewayNodePath=argv[0],gatewayEntryPath=str(entry),sdkRoot=str(entry.parent.parent),
  gatewayPort=int(argv[4]),environmentFiles=environment_files,currentUnitGenerationMatchesPrivateOriginal=True,
  existingHoldDropinsObserved=True)
except BaseException as error:
 report['errorType']=type(error).__name__;report['errorCode']=str(error) if str(error) in codes else 'retained_literal_unit_projection_unavailable'
finally:
 report['descriptors']=records;report['allDescriptorsClosedOnce']=all(r['closeAttempts']==1 and r['closed'] for r in records)
 if not report['allDescriptorsClosedOnce']:report['ok']=False
 report['elapsedSeconds']=time.monotonic()-START
 print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
sys.exit(0 if report['ok'] else 1)
