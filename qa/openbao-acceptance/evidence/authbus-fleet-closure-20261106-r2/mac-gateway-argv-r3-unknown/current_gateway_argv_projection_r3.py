#!/usr/bin/env python3
"""Read the already captured gateway restore record; publish safe syntax only.
No child, gateway API, provider, service mutation, auth DB, or profile inventory.
"""
import hashlib,json,os,re,shlex,stat,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+30
ROOT=Path('/Users/qianqi/heptabao-authbus-current-gateway-argv-20261106-r3')
PRIOR=Path('/Users/qianqi/heptabao-authbus-current-gateway-lineage-20261106-r1')
SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
LIVE=Path('/Users/qianqi/.openclaw')
codes=set();fd_rows=[];created=False
report={'schema':'heptabao.current-gateway-argv-safe-projection.r3','ok':False,'serviceMutations':0,'providerCalls':0,
 'credentialStoresRead':0,'registryOpened':False,'childProcesses':0,'rawArgumentsOrDigestsPublished':False,
 'rawConfigOrHashPublished':False,'runningPluginMemoryFlagsProven':False,'sameCurrentProcessReobserved':False,
 'sourceObservationJob':'1a1b2348f45-fc05-7cf1','originalSeconds':30,'supervisorSeconds':45}
def need(v,c):
 if not v:codes.add(c);raise RuntimeError(c)
def remaining():need(time.monotonic()<UNTIL,'argv_original_deadline')
def identity(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(p,cap,private=False):
 remaining();fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);row={'fd':fd,'attempted':False,'closed':False};fd_rows.append(row)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid in (0,501) and not stat.S_IMODE(s.st_mode)&0o022 and 0<=s.st_size<=cap,'argv_bounded_owned_or_public_file')
  if private:need(s.st_uid==501 and stat.S_IMODE(s.st_mode)==0o600,'argv_private_input_custody')
  raw=bytearray()
  while len(raw)<=cap:
   remaining();part=os.read(fd,min(65536,cap+1-len(raw)))
   if not part:break
   raw.extend(part)
  need(len(raw)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(Path(p).lstat()),'argv_whole_full9_read')
  return bytes(raw),identity(s)
 finally:row['attempted']=True;os.close(fd);row['closed']=True
def new(name,raw):
 fd=os.open(ROOT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);row={'fd':fd,'attempted':False,'closed':False};fd_rows.append(row)
 try:
  view=memoryview(raw)
  while view:
   remaining();n=os.write(fd,view);need(n>0,'argv_owned_write_progress');view=view[n:]
  os.fsync(fd)
 finally:row['attempted']=True;os.close(fd);row['closed']=True
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);row={'fd':fd,'attempted':False,'closed':False};fd_rows.append(row)
 try:os.fsync(fd)
 finally:row['attempted']=True;os.close(fd);row['closed']=True
def shell_switch(value):
 # Only a closed set of documented short shell switches is classified. Unknown
 # text is not published and does not authorize interpretation as shell code.
 if not isinstance(value,str) or not 2<=len(value)<=8 or not value.startswith('-'):return None
 letters=value[1:]
 if 'c' not in letters or any(x not in 'cefluvx' for x in letters):return None
 return {'commandString':True,'errexit':'e' in letters,'noglob':'f' in letters,
  'login':'l' in letters,'nounset':'u' in letters,'verbose':'v' in letters,'xtrace':'x' in letters,
  'duplicateFlagCount':len(letters)-len(set(letters))}
try:
 os.umask(0o077);need(sys.platform=='darwin' and os.getuid()==501,'argv_actual_mac_owner')
 original=read(PRIOR/'result.public.json',16384)[0]
 need(len(original)==3950 and hashlib.sha256(original).hexdigest()=='03ac0574dc762c9e4853a71571aa38e5f15e7de94947243163bf48cce180456c','argv_original_public_projection_binding')
 prior=json.loads(original);need(prior['ok'] and prior['privateRestoreInputsCaptured'] and prior['custody']['passed_process_custody'],'argv_original_lineage_closed')
 raw,ident=read(PRIOR/'restore-inputs.private.json',1048576,True);value=json.loads(raw)
 need(value['schema']=='heptabao.current-gateway-private-restore-inputs.r1' and value['target']=='gui/501/ai.openclaw.gateway' and value['arguments']==value['loadedFirst']['arguments']==value['loadedSecond']['arguments'],'argv_exact_prior_private_binding')
 config=read(LIVE/'openclaw.json',1048576,True)
 need(list(config[1])==value['configFull9'] and hashlib.sha256(config[0]).hexdigest()==value['configSha256'],'argv_same_current_config_generation')
 args=value['arguments'];need(isinstance(args,list) and len(args)==8 and all(isinstance(x,str) for x in args),'argv_exact_original_eight_arguments')
 switches=[i for i,x in enumerate(args[:2]) if shell_switch(x) is not None]
 need(len(switches)<=1,'argv_unambiguous_known_shell_switch')
 script_index=switches[0]+1 if switches and switches[0]+1<len(args) else None
 if script_index is not None:
  lex=shlex.shlex(args[script_index],posix=True,punctuation_chars=';&|()<>');lex.whitespace_split=True;lex.commenters='';tokens=list(lex)
 else:tokens=[]
 safe={'ulimit','-n','65536','8192','4096',';','&&','exec','$0','$@','--','2','>','/dev/null',':'}
 safe_tokens=[x if x in safe else '<private-or-unrecognized>' for x in tokens]
 patterns=[['ulimit','-n','65536',';','exec','$0','$@'],['ulimit','-n','65536','&&','exec','$0','$@'],['exec','$0','$@']]
 transparent=script_index is not None and tokens in patterns
 atom_allow={'/bin/sh','sh','-c','-l','-lc','-cl','--login','--','gateway','--port','--bind','loopback','--config'}
 projected=[];entry_paths=[]
 for i,arg in enumerate(args):
  item={'position':i}
  if i==script_index:item.update(kind='shell-code',recognizedTokens=safe_tokens,unknownTokenCount=sum(x not in safe for x in tokens))
  elif i in switches:item.update(kind='known-shell-switches',flags=shell_switch(arg))
  elif arg in atom_allow:item.update(kind='known-public-atom',value=arg)
  elif i>0 and args[i-1]=='--port' and arg.isdecimal() and 1<=int(arg)<=65535:item.update(kind='explicit-listen-port',value=int(arg))
  elif arg.startswith(str(SDK)+'/dist/') and Path(arg).suffix in ('.js','.mjs') and str(Path(arg))==arg and '..' not in Path(arg).parts:
   item.update(kind='public-sdk-entry',path=arg);entry_paths.append(Path(arg))
  elif arg.startswith('/opt/homebrew/') and Path(arg).name=='node' and '..' not in Path(arg).parts:item.update(kind='public-node-path',path=arg)
  elif arg==str(LIVE/'openclaw.json'):item.update(kind='registered-config-path',sameRegisteredPath=True)
  else:item.update(kind='private-or-unrecognized')
  projected.append(item)
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 entries=[];source_total=0;first_hop=[]
 need(entry_paths==[SDK/'dist/index.js'],'exact_current_registered_public_entry')
 for p in entry_paths:
  b,ident_entry=read(p,1048576);text=b.decode('utf-8','strict');source_total+=len(b)
  need(len(b)==3293 and hashlib.sha256(b).hexdigest()=='9832720dcaf85519d315dda624497e352588f0d65c5607390df0501cc2358985','same_current_entry_public_pin')
  name=p.name;new('public-entry-'+name,b)
  imports=re.findall(r"from\s+['\"]\./([A-Za-z0-9_.-]+\.js)['\"]",text)
  need(len(imports)<=8 and len(set(imports))==len(imports),'finite_public_entry_first_hop')
  entries.append({'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
   'staticRelativeImportCount':len(imports),'sourceCopiedToOwnedPublicCodeFile':True})
  for leaf in imports:
   remaining();need(leaf not in ('.','..') and '..' not in Path(leaf).parts,'public_entry_import_leaf')
   target=SDK/'dist'/leaf;raw_source,source_identity=read(target,1048576);source_total+=len(raw_source)
   need(source_total<=2*1048576,'bounded_public_entry_first_hop_total')
   source_text=raw_source.decode('utf-8','strict');new('public-import-'+leaf,raw_source)
   first_hop.append({'path':str(target),'bytes':len(raw_source),'sha256':hashlib.sha256(raw_source).hexdigest(),
    'mentionsConfigEnvironment':('OPENCLAW_CONFIG_PATH' in source_text),'mentionsStateEnvironment':('OPENCLAW_STATE_DIR' in source_text),
    'sourceCopiedToOwnedPublicCodeFile':True})
  need(read(p,1048576)==(b,ident_entry),'entry_public_source_unchanged_after_first_hop')
 # These four exact public paths are named by the already captured installed
 # state-db/plugin-registry/plugin-metadata sources; no directory search occurs.
 support=[]
 for leaf in ('paths-BMBAvkNf.js','config-state-CtMlHVRM.js','config-normalization-shared-w2iz0aeC.js','installed-plugin-index-N4jxqS0-.js'):
  target=SDK/'dist'/leaf;code,code_identity=read(target,1048576);source_total+=len(code)
  need(source_total<=2*1048576,'bounded_public_entry_first_hop_total');code.decode('utf-8','strict')
  new('public-support-'+leaf,code)
  support.append({'path':str(target),'bytes':len(code),'sha256':hashlib.sha256(code).hexdigest(),'sourceCopiedToOwnedPublicCodeFile':True})
 report['publicConfigAndPluginSupport']=support
 need(read(PRIOR/'restore-inputs.private.json',1048576,True)==(raw,ident),'argv_original_private_record_unchanged')
 need(read(LIVE/'openclaw.json',1048576,True)==config,'argv_config_after_public_source_read')
 report.update(ok=True,argumentProjection=projected,shellScriptPosition=script_index,shellTransparentExecPatternMatched=transparent,
  loginShellStartupFilesNotBound=(shell_switch(args[switches[0]])['login'] if switches else None),
  shellSwitchClassified=bool(switches),publicEntryFirstHop=first_hop,publicCodeBytes=source_total,
  recognizedShellOnly=script_index is not None and all(x in safe for x in tokens),publicEntries=entries,currentConfigFull9AndBytesStillExact=True,
  originalRestoreRecordFull9AndBytesExact=True,publicEntrypointQualificationStillRequired=True)
except BaseException as e:
 report['errorType']=type(e).__name__;report['errorCode']=str(e) if str(e) in codes else 'gateway_argv_readonly_refused'
finally:
 report['allOwnedFileDescriptorsClosedOnce']=all(x['attempted'] and x['closed'] for x in fd_rows)
 report['elapsedSeconds']=round(time.monotonic()-START,6)
 if not report['allOwnedFileDescriptorsClosedOnce']:report['ok']=False
 if created:
  try:new('result.public.json',json.dumps(report,sort_keys=True).encode()+b'\n')
  except BaseException:report['ok']=False;report['resultPublicationFailed']=True
 print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['ok'] else 1)
