import os,stat,json,hashlib,shlex,re,time,plistlib
from pathlib import Path
START=time.monotonic();UNTIL=START+15
OUTPUT=Path('/Users/qianqi/heptabao-current-r3-wrapper-source-20261106-r1')
rows=[];codes=set()
report={'schema':'heptabao.current-r3-gateway-wrapper-env.public.r1','ok':False,'originalInventoryJob':'1a1b3333a55-fc05-8103','originalWrapperProjectionJob':'1a1b337c5dc-fc05-8123','childCount':0,'sqlConnections':0,'networkCalls':0,'providerCalls':0,'serviceActions':0,'productionWrites':0,'privateArgumentsOrEnvironmentPublished':False,'configurationOrCredentialDigestsPublished':False,'selectedEnvironmentFileReads':0,'privateEnvironmentCopyCreated':False}
def need(v,c):
 if not v:codes.add(c);raise RuntimeError(c)
def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(p,private=True):
 need(time.monotonic()<UNTIL,'original_projection_deadline')
 held=[];parent=None;fd=None
 try:
  chain=[Path('/'),*list(reversed(p.parent.parents))[1:],p.parent]
  for q in chain:
   f=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW) if parent is None else os.open(q.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
   s=os.fstat(f);r={'fd':f,'path':q,'identity':ident(s),'closed':False,'attempts':0};rows.append(r);held.append(r);parent=f
   need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,501) and not stat.S_IMODE(s.st_mode)&0o022,'private_parent_custody')
   need(ident(s)==ident(q.lstat()),'same_opened_private_parent')
  f=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);s=os.fstat(f)
  r={'fd':f,'path':p,'identity':ident(s),'closed':False,'attempts':0};rows.append(r);held.append(r)
  need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=(1048576 if private else 65536) and ((s.st_uid==501 and s.st_gid==20 and stat.S_IMODE(s.st_mode)==0o600) if private else (s.st_uid in (0,501) and not stat.S_IMODE(s.st_mode)&0o022)),'private_original_file_custody')
  b=b''
  while len(b)<=s.st_size:
   need(time.monotonic()<UNTIL,'original_projection_deadline')
   q=os.read(f,min(65536,s.st_size+1-len(b)))
   if not q:break
   b+=q
  need(len(b)==s.st_size,'complete_original_private_bytes')
  for r in held:need(ident(os.fstat(r['fd']))==r['identity']==ident(r['path'].lstat()),'private_original_full9_unchanged')
  return b
 finally:
  for r in reversed(held):
   r['attempts']+=1
   try:os.close(r['fd']);r['closed']=True
   except BaseException:codes.add('original_descriptor_close_unknown')
def write(name,raw):
 p=OUTPUT/name;f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 r={'fd':f,'closed':False,'attempts':0};rows.append(r)
 try:
  v=memoryview(raw)
  while v:
   need(time.monotonic()<UNTIL,'original_projection_deadline')
   n=os.write(f,v);need(n>0,'private_output_progress');v=v[n:]
  os.fsync(f)
 finally:r['attempts']+=1;os.close(f);r['closed']=True
 f=os.open(OUTPUT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 r={'fd':f,'closed':False,'attempts':0};rows.append(r)
 try:os.fsync(f)
 finally:r['attempts']+=1;os.close(f);r['closed']=True
try:
 packet=json.loads(read(OUTPUT/'binding.private.json'));script=read(OUTPUT/'registered-script.original.private')
 need(hashlib.sha256(script).hexdigest()==packet['scriptSha256'],'same_original_private_wrapper_bytes')
 args=packet['arguments'];need(len(args)==8 and args[0]=='/bin/sh' and args[3:]==['/opt/homebrew/opt/node/bin/node','/opt/homebrew/lib/node_modules/openclaw/dist/index.js','gateway','--port','18789'],'same_fixed_original_entry_arguments')
 lines=[line.strip() for line in script.decode('utf-8','strict').splitlines()]
 need(len(lines)==8 and lines[0]=='#!/bin/sh' and lines[1]=='set -eu' and lines[3]=='shift' and lines[6]=='fi' and lines[7]=='exec "$@"','exact_eight_line_parameter_wrapper')
 match=re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)="\$1"',lines[2])
 need(match is not None,'quoted_first_argument_assignment')
 var=match.group(1);condition=re.fullmatch(r'if \[ -(f|r) "\$'+re.escape(var)+r'" \]; then',lines[4])
 need(condition is not None and lines[5]=='. "$'+var+'"','same_single_quoted_environment_source_condition')
 report.update(exactParameterFileThenShiftAndExecShape=True,sourceConditionRegularFile=condition.group(1)=='f',sourceConditionReadable=condition.group(1)=='r',sourcePathIsOriginalSecondArgument=True)
 env_path=Path(args[2]);need(env_path.is_absolute() and str(env_path)==os.path.normpath(str(env_path)) and str(env_path).startswith('/Users/qianqi/') and len(str(env_path))<=4096,'fixed_registered_home_environment_path')
 knownpaths={'currentStateDotenv':'/Users/qianqi/.openclaw/.env','defaultGatewayDotenv':'/Users/qianqi/.config/openclaw/gateway.env'}
 report.update(environmentPathMatchesKnownSelectors={k:str(env_path)==v for k,v in knownpaths.items()})
 try:raw=read(env_path)
 except FileNotFoundError:raw=None
 report['environmentFilePresent']=raw is not None
 private={'originalInventoryJob':'1a1b3333a55-fc05-8103','originalWrapperProjectionJob':'1a1b337c5dc-fc05-8123','environmentPath':str(env_path),'present':raw is not None}
 if raw is not None:
  report['selectedEnvironmentFileReads']=1
  text=raw.decode('utf-8','strict');entries={};unknown=0;dynamic=0;duplicates=0;autoexport=False
  for line in text.splitlines():
   line=line.strip()
   if not line or line.startswith('#'):continue
   if line=='set -a':autoexport=True;continue
   if line=='set +a':autoexport=False;continue
   if '$' in line or chr(96) in line:dynamic+=1;continue
   try:tokens=shlex.split(line,comments=True,posix=True)
   except ValueError:unknown+=1;continue
   exported=autoexport
   if tokens and tokens[0]=='export':exported=True;tokens=tokens[1:]
   if len(tokens)!=1 or '=' not in tokens[0]:unknown+=1;continue
   key,value=tokens[0].split('=',1)
   if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,255}',key):unknown+=1;continue
   if key in entries:duplicates+=1
   entries[key]={'value':value,'exported':exported}
  keys=('HOME','OPENCLAW_HOME','OPENCLAW_STATE_DIR','OPENCLAW_CONFIG_PATH','OPENCLAW_PROFILE','OPENCLAW_AGENT_DIR','OPENCLAW_WORKSPACE_DIR','OPENCLAW_INCLUDE_ROOTS','OPENCLAW_PACKAGE_DIR','OPENCLAW_TEST_FAST','OPENCLAW_LOAD_SHELL_ENV','OPENCLAW_DEFER_SHELL_ENV_FALLBACK','OPENCLAW_AUTH_STORE_READONLY','NODE_OPTIONS','NODE_PATH')
  report.update(literalAssignmentCount=len(entries),unrecognizedExecutableLineCount=unknown,dynamicExpansionLineCount=dynamic,duplicateAssignmentCount=duplicates,sourceSelectorPresence={key:key in entries for key in keys},literalAssignmentOnly=unknown==0 and dynamic==0)
  write('environment.original.private',raw)
  private.update(environmentFull9=ident(env_path.lstat()),environmentSha256=hashlib.sha256(raw).hexdigest(),literalEntries=entries,literalAssignmentOnly=unknown==0 and dynamic==0)
  report['privateEnvironmentCopyCreated']=True
 write('environment-binding.private.json',(json.dumps(private,sort_keys=True)+'\n').encode())
 report.update(ok=True,productionFallbackQualified=False,privateSourceBindingDurable=True)
except BaseException as error:
 report.update(ok=False,errorType=type(error).__name__,codes=sorted(codes))
finally:
 report.update(descriptorsOpened=len(rows),descriptorsClosed=sum(r['closed'] for r in rows),allDescriptorsClosedOnce=all(r['closed'] and r['attempts']==1 for r in rows),elapsedSeconds=time.monotonic()-START)
 if not report['allDescriptorsClosedOnce'] or time.monotonic()>=UNTIL:report['ok']=False
print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['ok'] else 1)
