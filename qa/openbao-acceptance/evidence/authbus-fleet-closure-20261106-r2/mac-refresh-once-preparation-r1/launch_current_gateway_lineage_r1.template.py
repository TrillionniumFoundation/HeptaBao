#!/usr/bin/env python3
"""One exact registered gateway label; read-only lineage and private restore inputs.

No credential store, registry, provider, RPC to gateway, or service mutation.
Two launchctl-print children use the previously qualified owned-child tracker.
Full loaded arguments, plist/config bytes and their hashes remain private.
"""
import ast,ctypes,hashlib,json,os,plistlib,re,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+30.0
ROOT=Path('/Users/qianqi/heptabao-authbus-current-gateway-lineage-20261106-r1')
LIVE=Path('/Users/qianqi/.openclaw')
CONFIG=LIVE/'openclaw.json'
TARGET='gui/501/ai.openclaw.gateway'
PLIST=Path('/Users/qianqi/Library/LaunchAgents/ai.openclaw.gateway.plist')
QUAL=Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2')
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
# PAYLOAD_PLACEHOLDER
PINS={'kv2_dr_process_custody.py':'669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008',
 'owned_process.py':'0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'}
report={'schema':'heptabao.current-gateway-lineage-readonly.r1','ok':False,'exactRegisteredLabel':'ai.openclaw.gateway',
 'sharedSeconds':30,'supervisorSeconds':50,'serviceMutations':0,'providerCalls':0,'credentialStoresRead':0,
 'registryOpened':False,'gatewayRpcCalls':0,'credentialsOrDigestsPublished':False,'rawConfigurationOrHashPublished':False,
 'runningPluginMemoryFlagsProven':False,'quiescencePerformed':False,'privateRestoreInputsCaptured':False}
codes=set();rows=[];created=False;owner=None;children=[]
def need(v,c):
 if not v:codes.add(c);raise RuntimeError(c)
def remaining(cap=30):
 v=UNTIL-time.monotonic();need(v>0,'gateway_original_readonly_deadline');return min(v,cap)
def identity(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(p,cap=1048576,private=False):
 remaining();fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 row={'fd':fd,'attempted':False,'closed':False};rows.append(row)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid in (0,501) and not stat.S_IMODE(s.st_mode)&0o022 and 0<=s.st_size<=cap,'gateway_regular_bounded_input')
  if private:need(s.st_uid==501 and stat.S_IMODE(s.st_mode)==0o600,'gateway_private_config_custody')
  parts=bytearray()
  while len(parts)<=cap:
   remaining();pbytes=os.read(fd,min(65536,cap+1-len(parts)))
   if not pbytes:break
   parts.extend(pbytes)
  need(len(parts)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(Path(p).lstat()),'gateway_stable_whole_read')
  return bytes(parts),identity(s)
 finally:row['attempted']=True;os.close(fd);row['closed']=True
def new(name,bytes):
 p=ROOT/name;need(len(bytes)<=1048576,'gateway_bounded_owned_file')
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);row={'fd':fd,'attempted':False,'closed':False};rows.append(row)
 try:
  view=memoryview(bytes)
  while view:
   remaining();n=os.write(fd,view);need(n>0,'gateway_owned_write_progress');view=view[n:]
  os.fsync(fd)
 finally:row['attempted']=True;os.close(fd);row['closed']=True
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);row={'fd':fd,'attempted':False,'closed':False};rows.append(row)
 try:os.fsync(fd)
 finally:row['attempted']=True;os.close(fd);row['closed']=True
def pins():
 for name,pin in PINS.items():need(hashlib.sha256(read(QUAL/'qa'/name)[0]).hexdigest()==pin,'gateway_qualified_custody_source')
def stable_read(p,previous,cap=1048576,private=False):
 v=read(p,cap,private);need(v==previous,'gateway_input_generation_exact');return v
def derive_source(text,names,pin):
 need(hashlib.sha256(text.encode()).hexdigest()==pin,'gateway_public_helper_whole_pin')
 nodes=[n for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
 need({n.name for n in nodes}==set(names),'gateway_public_helper_exact_ast_nodes')
 return compile(ast.Module(body=nodes,type_ignores=[]),'<source-bound-readonly-excerpt>','exec')
def safe_process(row):
 out={k:v for k,v in row.items() if k!='executable'}
 out['executablePublicPath']=row['executable'] if row['executable'].startswith(('/opt/homebrew/','/usr/bin/','/bin/','/System/')) else None
 out['executableKeptPrivate']=out['executablePublicPath'] is None
 return out
def scoped_environments(raw):
 # Keep only config-scope names in private memory. No arbitrary environment
 # value is projected. Conflicting layers remain an explicit refusal.
 wanted={'HOME','OPENCLAW_STATE_DIR','OPENCLAW_CONFIG_PATH','OPENCLAW_HOME','OPENCLAW_PROFILE'}
 found={};depth=1;block=None
 for line in raw.decode('utf-8','strict').splitlines()[1:]:
  text=line.strip()
  if depth==1 and text in ('environment = {','default environment = {','inherited environment = {'):
   block=text.split(' = ',1)[0]
  elif block is not None and depth==2:
   if text=='}':block=None
   elif ' => ' in text:
    key,value=text.split(' => ',1)
    if key in wanted:found.setdefault(key,[]).append(value)
  depth+=text.count('{')-text.count('}')
 return found
def label_query(ordinal):
 remaining();argv=['/bin/launchctl','print',TARGET]
 child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/Users/qianqi'})
 children.append(child)
 try:out,err=child.communicate(timeout=remaining(8))
 finally:
  for stream in (child.stdin,child.stdout,child.stderr):
   if stream is not None and not stream.closed:stream.close()
 need(len(out)<=262144 and len(err)<=16384,'gateway_bounded_exact_label_output')
 new(f'launchctl-{ordinal}.stdout.private',out);new(f'launchctl-{ordinal}.stderr.private',err)
 need(child.returncode==0 and not err,'gateway_known_exact_label_print')
 parsed=parse_print(out,TARGET);parsed['observedEnvironmentScope']=scoped_environments(out);return parsed
try:
 os.umask(0o077);need(sys.platform=='darwin' and os.getuid()==501 and os.path.realpath(sys.executable)==PYTHON,'gateway_actual_mac_owner')
 authority=PAYLOAD['custodyAuthority'];need(authority['job_id']=='1a1b141ef40-fc05-7750' and authority['state']=='succeeded' and authority['exit_code']==0 and authority['output_complete'] and authority['output_durable'] and not authority['timed_out'],'gateway_original_custody_authority')
 proof=read(QUAL/'result.public.json',65536)[0];need(len(proof)==58701 and hashlib.sha256(proof).hexdigest()=='67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e','gateway_qualified_original_proof')
 pins();sys.path.insert(0,str(QUAL/'qa'));import kv2_dr_process_custody as custody
 exec(derive_source(PAYLOAD['observerSource'],('ObservationRefused','require','BsdInfo','ProcessReader'),PAYLOAD['observerPin']),globals())
 exec(derive_source(PAYLOAD['managerSource'],('ManagerRefused','need','parse_print'),PAYLOAD['managerPin']),globals())
 # Restore this launcher's closed-code need after importing only pure parser.
 parser_need=need
 def need(v,c):
  if not v:codes.add(c);raise RuntimeError(c)
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 config=read(CONFIG,1048576,True);value=json.loads(config[0]);need(isinstance(value,dict),'gateway_current_config_object')
 original_popen=subprocess.Popen;original_killpg=os.killpg
 with custody.activated() as owner:
  first=label_query(1);need(first.get('path')==str(PLIST) and first.get('state')=='running' and isinstance(first.get('pid'),int),'gateway_exact_plist_running_pid')
  plist=read(PLIST,262144);loaded=plistlib.loads(plist[0]);need(isinstance(loaded,dict) and loaded.get('Label')=='ai.openclaw.gateway','gateway_plist_exact_label')
  args=loaded.get('ProgramArguments');program=loaded.get('Program',args[0] if isinstance(args,list) and args else None)
  need(isinstance(args,list) and 1<=len(args)<=32 and all(isinstance(x,str) and len(x)<=16384 for x in args) and first['arguments']==args and first.get('program')==program,'gateway_loaded_args_match_current_plist')
  env=loaded.get('EnvironmentVariables',{});need(isinstance(env,dict) and all(isinstance(k,str) and isinstance(v,str) for k,v in env.items()),'gateway_plist_environment_shape')
  config_path=env.get('OPENCLAW_CONFIG_PATH',str(CONFIG));state_path=env.get('OPENCLAW_STATE_DIR',str(LIVE));home=env.get('HOME','/Users/qianqi')
  need(config_path==str(CONFIG) and state_path==str(LIVE) and home=='/Users/qianqi','gateway_current_registered_config_scope')
  expected_env={'HOME':'/Users/qianqi','OPENCLAW_STATE_DIR':str(LIVE),'OPENCLAW_CONFIG_PATH':str(CONFIG),'OPENCLAW_HOME':'/Users/qianqi'}
  loaded_scope=first['observedEnvironmentScope']
  need(all(all(v==expected_env[k] for v in values) for k,values in loaded_scope.items() if k in expected_env),'gateway_loaded_config_environment_scope')
  reader=ProcessReader();process=reader.read(first['pid']);need(process['uid']==501,'gateway_same_user_process')
  direct=[reader.read(pid) for pid in reader.children(process['pid'])];need(all(x['ppid']==process['pid'] for x in direct),'gateway_direct_child_lineage')
  ancestors=[];parent=process['ppid']
  for _ in range(4):
   if parent==1:break
   row=reader.read(parent);ancestors.append(row);parent=row['ppid']
  need(parent==1,'gateway_bounded_lineage_to_launchd')
  second=label_query(2)
  need(all(second.get(k)==first.get(k) for k in ('path','program','pid','runs','state','arguments','observedEnvironmentScope')),'gateway_same_loaded_registration')
  need(reader.read(process['pid'])==process,'gateway_same_original_birth_executable')
  need(sorted(reader.children(process['pid']))==sorted(x['pid'] for x in direct),'gateway_same_direct_child_set')
  need(all(reader.read(x['pid'])==x for x in direct+ancestors),'gateway_entire_observed_lineage_unchanged')
  stable_read(CONFIG,config,1048576,True);stable_read(PLIST,plist,262144)
  owner.assert_retired()
 report['custody']=owner.receipt();need(report['custody']['passed_process_custody'] and report['custody']['original_count']==2 and subprocess.Popen is original_popen and os.killpg is original_killpg,'gateway_original_helpers_closed')
 pins();remaining()
 born=process['birthSec']*1000000000+process['birthUsec']*1000
 # Merely a time/path observation. Current in-memory plugin flags remain unproven.
 report.update(ok=True,process=safe_process(process),directChildren=[safe_process(x) for x in direct],ancestors=[safe_process(x) for x in ancestors],
  loadedArgumentsEqualCurrentPlist=True,currentPlistConfigurationPathMatchesRegisteredCurrent=True,configurationPathExplicitInPlist='OPENCLAW_CONFIG_PATH' in env,
  loadedConfigEnvironmentConsistentWithCurrent=True,loadedConfigPathExplicit='OPENCLAW_CONFIG_PATH' in loaded_scope,
  loadedProfileEnvironmentPresent='OPENCLAW_PROFILE' in loaded_scope,
  stateRootExplicitInPlist='OPENCLAW_STATE_DIR' in env,currentConfigGenerationPredatesProcessBirth=max(int(config[1][7]),int(config[1][8]))<=born,
  currentConfigAndPlistWholeBytesFull9Stable=True,launchdRunCount=first['runs'],keepAliveConfigured=bool(loaded.get('KeepAlive')),
  programPath=program if isinstance(program,str) and program.startswith(('/opt/homebrew/','/usr/bin/','/bin/')) else None,
  argumentCount=len(args),directChildCount=len(direct),restoreArgsAndEnvironmentKeptPrivate=True)
 private={'schema':'heptabao.current-gateway-private-restore-inputs.r1','target':TARGET,'process':process,'children':direct,'ancestors':ancestors,
  'loadedFirst':first,'loadedSecond':second,'plistPath':str(PLIST),'plistFull9':plist[1],'plistSha256':hashlib.sha256(plist[0]).hexdigest(),
  'configPath':str(CONFIG),'configFull9':config[1],'configSha256':hashlib.sha256(config[0]).hexdigest(),'environment':env,'arguments':args}
 new('restore-inputs.private.json',json.dumps(private,sort_keys=True).encode()+b'\n');new('gateway-original.plist.private',plist[0]);report['privateRestoreInputsCaptured']=True
except BaseException as e:
 report['errorType']=type(e).__name__;report['errorCode']=str(e) if str(e) in codes else 'gateway_lineage_readonly_refused'
finally:
 for child in children:
  for stream in (child.stdin,child.stdout,child.stderr):
   if stream is not None and not stream.closed:stream.close()
 if owner is not None:report['custody']=owner.receipt()
 report['elapsedSeconds']=round(time.monotonic()-START,6)
 report['allOwnedFileDescriptorsClosedOnce']=all(r['attempted'] and r['closed'] for r in rows)
 if not report['allOwnedFileDescriptorsClosedOnce']:report['ok']=False
 if created:
  try:new('result.public.json',json.dumps(report,sort_keys=True).encode()+b'\n')
  except BaseException:report['ok']=False;report['resultPublicationFailed']=True
 print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['ok'] else 1)
