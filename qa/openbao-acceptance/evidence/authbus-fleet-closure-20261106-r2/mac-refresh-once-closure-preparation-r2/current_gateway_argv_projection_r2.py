#!/usr/bin/env python3
"""Read the already captured gateway restore record; publish safe syntax only.
No child, gateway API, provider, service mutation, auth DB, or profile inventory.
"""
import hashlib,json,os,shlex,stat,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+30
ROOT=Path('/Users/qianqi/heptabao-authbus-current-gateway-argv-20261106-r2')
PRIOR=Path('/Users/qianqi/heptabao-authbus-current-gateway-lineage-20261106-r1')
SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
LIVE=Path('/Users/qianqi/.openclaw')
codes=set();fd_rows=[];created=False
report={'schema':'heptabao.current-gateway-argv-safe-projection.r2','ok':False,'serviceMutations':0,'providerCalls':0,
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
 switches=[i for i,x in enumerate(args) if x in ('-c','-lc','-cl')]
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
  elif arg in atom_allow:item.update(kind='known-public-atom',value=arg)
  elif i>0 and args[i-1]=='--port' and arg.isdecimal() and 1<=int(arg)<=65535:item.update(kind='explicit-listen-port',value=int(arg))
  elif arg.startswith(str(SDK)+'/dist/') and Path(arg).suffix in ('.js','.mjs') and str(Path(arg))==arg and '..' not in Path(arg).parts:
   item.update(kind='public-sdk-entry',path=arg);entry_paths.append(Path(arg))
  elif arg.startswith('/opt/homebrew/') and Path(arg).name=='node' and '..' not in Path(arg).parts:item.update(kind='public-node-path',path=arg)
  elif arg==str(LIVE/'openclaw.json'):item.update(kind='registered-config-path',sameRegisteredPath=True)
  else:item.update(kind='private-or-unrecognized')
  projected.append(item)
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 entries=[]
 for p in entry_paths:
  b,s=read(p,1048576);text=b.decode('utf-8','strict')
  # Public source only, saved with a code digest; never hash original argv.
  name=p.name;need(name not in ('.','..') and '/' not in name,'argv_public_code_leaf')
  new('public-entry-'+name,b)
  entries.append({'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
   'staticRelativeImportCount':text.count('from "./')+text.count("from './"),'sourceCopiedToOwnedPublicCodeFile':True})
 need(read(PRIOR/'restore-inputs.private.json',1048576,True)==(raw,ident),'argv_original_private_record_unchanged')
 need(read(LIVE/'openclaw.json',1048576,True)==config,'argv_config_after_public_source_read')
 report.update(ok=True,argumentProjection=projected,shellScriptPosition=script_index,shellTransparentExecPatternMatched=transparent,
  loginShellStartupFilesNotBound=any(x in ('-l','-lc','-cl','--login') for x in args[:script_index] if script_index is not None),
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
