import os,stat,json,hashlib,shlex,re,time,plistlib
from pathlib import Path
START=time.monotonic();UNTIL=START+15
BASE=Path('/Users/qianqi/heptabao-authbus-production-source-inventory-20261106-r3/output')
PATHS=[BASE/'gateway-restore-inputs.private.json',BASE/'gateway-original.plist.private']
rows=[];codes=set()
report={'schema':'heptabao.current-r3-gateway-shell-shape.public.r1','ok':False,'originalInventoryJob':'1a1b3333a55-fc05-8103','childCount':0,'sqlConnections':0,'networkCalls':0,'providerCalls':0,'serviceActions':0,'productionWrites':0,'privateArgumentsOrEnvironmentPublished':False,'configurationOrCredentialDigestsPublished':False,'historicalUnknownAttemptReplayed':False}
def need(v,c):
 if not v:codes.add(c);raise RuntimeError(c)
def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(p):
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
  need(stat.S_ISREG(s.st_mode) and s.st_uid==501 and s.st_gid==20 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=1048576,'private_original_file_custody')
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
try:
 binding=json.loads(read(PATHS[0]));raw=read(PATHS[1]);plist=plistlib.loads(raw)
 need(binding.get('schema')=='heptabao.current-gateway-private-restore-inputs.r1' and binding.get('observationSchema')=='heptabao.current-gateway-observation.private.r2' and binding.get('configSource')=='same_parent_original_inventory_capture','exact_r3_original_source_binding')
 need(hashlib.sha256(raw).hexdigest()==binding.get('plistSha256'),'same_private_original_plist')
 args=plist.get('ProgramArguments')
 need(isinstance(args,list) and all(isinstance(x,str) for x in args) and args==binding.get('arguments')==binding.get('loadedFirst',{}).get('arguments')==binding.get('loadedSecond',{}).get('arguments'),'same_original_loaded_eight_arguments')
 need(len(args)==8 and args[0]=='/bin/sh' and plist.get('Label')=='ai.openclaw.gateway','exact_registered_original_shape')
 flags=args[1];need(0<len(flags)<=256 and len(args[2])<=16384,'bounded_private_shell_fields')
 chars=flags[1:] if flags.startswith('-') and not flags.startswith('--') else ''
 lexer=shlex.shlex(args[2],posix=True,punctuation_chars=';&|()<>');lexer.whitespace_split=True;lexer.commenters=''
 tokens=list(lexer)
 transparent=tokens in (['ulimit','-n','65536',';','exec','$0','$@'],['ulimit','-n','65536','&&','exec','$0','$@'],['exec','$0','$@'])
 quoted=re.fullmatch(r'\s*(?:ulimit\s+-n\s+65536\s*(?:;|&&)\s*)?exec\s+"\$0"\s+"\$@"\s*',args[2]) is not None
 report.update(shortSwitchesShape=bool(chars),uniqueShortSwitches=len(set(chars))==len(chars),knownFiniteSwitchAlphabet=bool(chars) and set(chars)<=set('cefluvx'),containsLoginSwitch='l' in chars,containsCommandSwitch='c' in chars,containsExecSwitch='e' in chars,containsUnsetVariableSwitch='u' in chars,containsVerboseSwitch='v' in chars,containsTraceSwitch='x' in chars,nonLoginCurrentFallbackSwitchesAccepted=2<=len(flags)<=8 and flags.startswith('-') and 'c' in chars and set(chars)<=set('cef') and len(set(chars))==len(chars),transparentScriptTokenShape=transparent,exactDoubleQuotedForwarding=quoted,tokenCount=len(tokens),containsSubstitutionSyntax='$(' in args[2] or chr(96) in args[2],fixedNodeSdkAndGatewayPortTail=args[3:]==['/opt/homebrew/opt/node/bin/node','/opt/homebrew/lib/node_modules/openclaw/dist/index.js','gateway','--port','18789'],currentOriginalPlistAndTwoLoadedRecordsAgree=True,currentProcessPid=binding['process']['pid'],descendantCount=len(binding.get('descendants',[])),productionFallbackQualified=False,ok=True)
except BaseException as error:
 report.update(ok=False,errorType=type(error).__name__,codes=sorted(codes))
finally:
 report.update(descriptorsOpened=len(rows),descriptorsClosed=sum(r['closed'] for r in rows),allDescriptorsClosedOnce=all(r['closed'] and r['attempts']==1 for r in rows),elapsedSeconds=time.monotonic()-START)
 if not report['allDescriptorsClosedOnce'] or time.monotonic()>=UNTIL:report['ok']=False
print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['ok'] else 1)
