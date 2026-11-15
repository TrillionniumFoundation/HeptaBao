import os,stat,json,hashlib,shlex,re,time,plistlib
from pathlib import Path
START=time.monotonic();UNTIL=START+15
BASE=Path('/Users/qianqi/heptabao-authbus-production-source-inventory-20261106-r3/output')
OUTPUT=Path('/Users/qianqi/heptabao-current-r3-wrapper-source-20261106-r1')
rows=[];codes=set()
report={'schema':'heptabao.current-r3-gateway-wrapper-source.public.r1','ok':False,'originalInventoryJob':'1a1b3333a55-fc05-8103','childCount':0,'sqlConnections':0,'networkCalls':0,'providerCalls':0,'serviceActions':0,'productionWrites':0,'privateArgumentsOrEnvironmentPublished':False,'configurationOrCredentialDigestsPublished':False,'historicalUnknownAttemptReplayed':False,'registeredScriptReadCount':0,'privateScriptCopyCreated':False}
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
 binding=json.loads(read(BASE/'gateway-restore-inputs.private.json'));raw=read(BASE/'gateway-original.plist.private');plist=plistlib.loads(raw);args=plist.get('ProgramArguments')
 need(hashlib.sha256(raw).hexdigest()==binding.get('plistSha256') and isinstance(args,list) and len(args)==8 and args==binding.get('arguments')==binding.get('loadedFirst',{}).get('arguments')==binding.get('loadedSecond',{}).get('arguments'),'exact_original_loaded_argv_binding')
 first=args[1];second=args[2]
 report.update(firstArgumentAbsolutePath=first.startswith('/'),firstArgumentStartsDash=first.startswith('-'),secondArgumentDoubleDash=second=='--',secondArgumentCommandFlag=second=='-c',firstArgumentWithinRegisteredHome=first.startswith('/Users/qianqi/'),firstArgumentWithinInstalledSdk=first.startswith('/opt/homebrew/lib/node_modules/openclaw/'),firstArgumentEndsShellExtension=first.endswith('.sh'))
 if first.startswith('/'):
  need(os.path.normpath(first)==first and (first.startswith('/Users/qianqi/') or first.startswith('/opt/homebrew/lib/node_modules/openclaw/')) and len(first)<=4096,'one_registered_script_path_scope')
  script_path=Path(first);script=read(script_path,False);report['registeredScriptReadCount']=1
  text=script.decode('utf-8','strict');lines=text.splitlines()
  patterns=[('shebang-posix-sh',r'#!/bin/sh'),('set-e',r'set -e'),('set-eu',r'set -eu'),('set-u',r'set -u'),('set-ef',r'set -ef'),('shift-one',r'shift'),('ulimit-65536',r'ulimit -n 65536'),('exec-all-quoted',r'exec "\$@"'),('exec-zero-all-quoted',r'exec "\$0" "\$@"'),('skip-double-dash-one-line',r'if \[ "\$1" = "--" \]; then shift; fi'),('skip-double-dash-open',r'if \[ "\$1" = "--" \]; then'),('if-close',r'fi')]
  recognized=[];unknown=0;comments=0;first_tokens={}
  for number,line in enumerate(lines,1):
   value=line.strip()
   if not value:continue
   matched=[name for name,pattern in patterns if re.fullmatch(pattern,value)]
   if matched:recognized.append({'line':number,'pattern':matched[0]});continue
   if value.startswith('#'):comments+=1;continue
   unknown+=1
   try:tokens=shlex.split(value,posix=True)
   except ValueError:tokens=[]
   if tokens and tokens[0] in ('set','shift','exec','ulimit','if','then','fi','case','esac','.','source','eval','env','export','trap','exit','umask','read','cat','sleep'):
    first_tokens[tokens[0]]=first_tokens.get(tokens[0],0)+1
  need(not OUTPUT.exists(),'new_private_wrapper_artifact_root')
  os.mkdir(OUTPUT,0o700)
  write('registered-script.original.private',script)
  write('binding.private.json',(json.dumps({'originalInventoryJob':'1a1b3333a55-fc05-8103','scriptPath':str(script_path),'scriptFull9':ident(script_path.lstat()),'scriptSha256':hashlib.sha256(script).hexdigest(),'arguments':args},sort_keys=True)+'\n').encode())
  report.update(privateScriptCopyCreated=True,scriptLineCount=len(lines),recognizedPatterns=recognized,unrecognizedExecutableLineCount=unknown,commentLineCount=comments,closedKnownFirstTokenCounts=first_tokens,fullScriptOrDigestPublished=False)
 report.update(ok=True,productionFallbackQualified=False)
except BaseException as error:
 report.update(ok=False,errorType=type(error).__name__,codes=sorted(codes))
finally:
 report.update(descriptorsOpened=len(rows),descriptorsClosed=sum(r['closed'] for r in rows),allDescriptorsClosedOnce=all(r['closed'] and r['attempts']==1 for r in rows),elapsedSeconds=time.monotonic()-START)
 if not report['allDescriptorsClosedOnce'] or time.monotonic()>=UNTIL:report['ok']=False
print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['ok'] else 1)
