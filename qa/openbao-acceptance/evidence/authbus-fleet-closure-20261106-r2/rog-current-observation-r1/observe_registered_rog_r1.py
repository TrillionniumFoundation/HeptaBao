#!/usr/bin/env python3
"""Bounded read-only observation of the one registered ROG gateway.

Only the new private observation directory is written. No SDK, credential
database, service command, network operation or provider is invoked.
"""
import hashlib,json,os,stat,sys,time
from pathlib import Path
from urllib.parse import urlsplit

CALLER_HOME=Path('/home/qian-qi')
LIVE=CALLER_HOME/'.openclaw'
ROOT=CALLER_HOME/'heptabao-rog-current-client-observation-20261106-r1'
PID=599954
INVOCATION='7564ce91c7d4453ab7e0fdadc42e0166'
UNIT='openclaw-gateway.service'
SDK=CALLER_HOME/'.npm-global/lib/node_modules/openclaw'
PLUGIN=LIVE/'extensions/openclaw-authbus'
START=time.monotonic();UNTIL=START+25
report={'schema':'heptabao.rog-current-registered-client-observation.r1','ok':False,
 'selectedClient':UNIT,'productionMutations':0,'credentialDatabaseContentsRead':False,
 'credentialValuesOrDigestsPublished':False,'rawConfigurationDigestPublished':False,
 'sdkImported':False,'providerCalled':False,'networkOpened':False,'childrenStarted':0,
 'serviceActions':0,'runningPluginMemoryFlagsProven':False,'writerExclusionProven':False,
 'oldUnknownSourcePreparationResolved':False}
fds=[];codes=set();created=False;anchors={}
def need(value,code):
 if not value:codes.add(code);raise RuntimeError(code)
def remaining():need(time.monotonic()<UNTIL,'original_observation_deadline')
def identity(s):return [str(x) for x in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)]
def track_fd(fd,kind):
 row={'kind':kind,'closed':False};fds.append(row);return row
def anchor(path,allow_public_symlinks=False):
 path=Path(path);need(path.is_absolute() and '..' not in path.parts,'absolute_bounded_source_path')
 need(not stat.S_ISLNK(path.lstat().st_mode),'source_leaf_alias_not_admitted')
 for parent in reversed(path.parents):
  s=parent.lstat();symbolic=stat.S_ISLNK(s.st_mode)
  need(stat.S_ISDIR(s.st_mode) or symbolic and allow_public_symlinks,'source_parent_directory_or_bound_public_alias')
  need(s.st_uid in (0,os.getuid()) and (symbolic or not s.st_mode&0o022),'source_parent_ownership')
  row={'identity':identity(s) if symbolic else identity(s)[:5],
       'symlink':symbolic,'target':os.readlink(parent) if symbolic else None}
  if str(parent) in anchors:need(anchors[str(parent)]==row,'unchanged_bound_source_parent')
  else:anchors[str(parent)]=row
 canonical=path.resolve(strict=True)
 if not allow_public_symlinks:need(canonical==path,'private_source_has_no_alias')
 if canonical!=path:anchor(canonical,False)
 return canonical
def open_regular_parent(path):
 opened=[];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);opened.append((fd,track_fd(fd,'source-parent')))
 try:
  current=Path('/')
  need(identity(os.fstat(fd))[:5]==anchors['/']['identity'],'same_held_root_parent')
  for name in path.parent.parts[1:]:
   fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
   opened.append((fd,track_fd(fd,'source-parent')));current=current/name
   need(identity(os.fstat(fd))[:5]==anchors[str(current)]['identity'],'same_held_source_parent')
  return fd,opened
 except BaseException:
  for held,row in reversed(opened):os.close(held);row['closed']=True
  raise
def verify_anchors():
 for path,expected in anchors.items():
  s=Path(path).lstat();symbolic=stat.S_ISLNK(s.st_mode)
  row={'identity':identity(s) if symbolic else identity(s)[:5],
       'symlink':symbolic,'target':os.readlink(path) if symbolic else None}
  need(row==expected,'bound_source_parent_changed')
def read_regular(path,maximum,private=False):
 remaining();path=anchor(path,allow_public_symlinks=not private);parent,held=open_regular_parent(path)
 fd=None;row=None
 try:
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);row=track_fd(fd,'regular')
  before=os.fstat(fd)
  need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid in (0,os.getuid())
   and not stat.S_IMODE(before.st_mode)&0o022 and 0<=before.st_size<=maximum,'bounded_owned_source_file')
  if private:need(before.st_uid==os.getuid() and stat.S_IMODE(before.st_mode)==0o600,'private_current_configuration')
  out=bytearray()
  while len(out)<=maximum:
   remaining();part=os.read(fd,min(65536,maximum+1-len(out)))
   if not part:break
   out.extend(part)
  need(len(out)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'stable_source_file')
  return bytes(out),identity(before)
 finally:
  if fd is not None:os.close(fd);row['closed']=True
  for parent,entry in reversed(held):os.close(parent);entry['closed']=True
def proc_read(name,maximum=131072):
 remaining();fd=os.open('/proc/'+str(PID)+'/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);row={'kind':'proc','closed':False};fds.append(row)
 try:
  need(os.fstat(fd).st_uid==os.getuid(),'owned_registered_gateway_proc')
  out=bytearray()
  while len(out)<=maximum:
   remaining();part=os.read(fd,min(16384,maximum+1-len(out)))
   if not part:break
   out.extend(part)
  need(len(out)<=maximum,'bounded_registered_gateway_proc');return bytes(out)
 finally:os.close(fd);row['closed']=True
def lifetime():
 raw=proc_read('stat',8192).decode();end=raw.rfind(')');need(end>0,'complete_gateway_stat')
 fields=raw[end+2:].split();need(len(fields)>=20 and int(raw.split('(',1)[0])==PID,'complete_gateway_stat_fields')
 need(fields[0] not in ('Z','X'),'gateway_live_at_observation')
 return {'pid':PID,'ppid':int(fields[1]),'pgid':int(fields[2]),'session':int(fields[3]),'startTicks':fields[19]}
def metadata(path):
 path=Path(path)
 try:s=path.lstat()
 except FileNotFoundError:return {'exists':False}
 anchor(path,False)
 need(not stat.S_ISLNK(s.st_mode),'no_credential_store_metadata_symlink')
 return {'exists':True,'regular':stat.S_ISREG(s.st_mode),'directory':stat.S_ISDIR(s.st_mode),
  'identity':identity(s),'owned':s.st_uid==os.getuid()}
def new_private(name,raw):
 need(created and '/' not in name and isinstance(raw,bytes) and len(raw)<=4*1048576,'bounded_private_observation_output')
 fd=os.open(ROOT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);row={'kind':'private-output','closed':False};fds.append(row)
 try:
  view=memoryview(raw)
  while view:
   remaining();n=os.write(fd,view);need(n>0,'observation_output_progress');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd);row['closed']=True
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);directory_row=track_fd(fd,'private-output-directory')
 try:os.fsync(fd)
 finally:os.close(fd);directory_row['closed']=True
def public_code(path,maximum=1048576):
 raw,ident=read_regular(path,maximum)
 return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':ident},raw
def configured_path(value,default):
 if value is None:return default
 need(isinstance(value,str) and value.startswith('/') and '..' not in Path(value).parts,'absolute_selected_runtime_path')
 p=Path(value);need(p.is_relative_to(CALLER_HOME),'selected_runtime_path_within_account');return p
try:
 need(sys.platform=='linux' and os.getuid()==1000 and Path.home()==CALLER_HOME,'expected_rog_account')
 home=CALLER_HOME.lstat();need(stat.S_ISDIR(home.st_mode) and home.st_uid==os.getuid() and not home.st_mode&0o022,'owned_account_home')
 original=lifetime();environment_raw=proc_read('environ');args_raw=proc_read('cmdline');cgroup_raw=proc_read('cgroup',16384)
 environment={}
 for item in environment_raw.split(b'\0'):
  if not item:continue
  key,separator,value=item.partition(b'=');need(bool(separator),'complete_gateway_environment')
  decoded=key.decode('ascii');need(decoded not in environment,'unique_gateway_environment_key');environment[decoded]=value.decode('utf-8')
 need(environment.get('INVOCATION_ID')==INVOCATION,'same_observed_systemd_invocation')
 need(any(line.rsplit('/',1)[-1]==UNIT for line in cgroup_raw.decode().splitlines()),'same_registered_gateway_cgroup')
 state=configured_path(environment.get('OPENCLAW_STATE_DIR'),LIVE)
 config_path=configured_path(environment.get('OPENCLAW_CONFIG_PATH'),state/'openclaw.json')
 need(state==LIVE and config_path==LIVE/'openclaw.json','current_registered_default_state_binding')
 raw,config_identity=read_regular(config_path,4*1048576,private=True);config=json.loads(raw)
 need(isinstance(config,dict),'current_configuration_object')
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 new_private('configuration.original.private.json',raw)
 new_private('gateway.environment.original.private.bin',environment_raw)
 new_private('gateway.cmdline.original.private.bin',args_raw)
 new_private('gateway.cgroup.original.private.txt',cgroup_raw)
 entry=config.get('plugins',{}).get('entries',{}).get('openclaw-authbus',{})
 need(isinstance(entry,dict) and isinstance(entry.get('config'),dict),'registered_authbus_configuration')
 ac=entry['config'];address=urlsplit(ac.get('address',''))
 need(address.scheme in ('http','https') and address.hostname and not address.username and not address.password,'safe_configured_authbus_address')
 flags={k:ac.get(k) for k in ('leader','publishNew','manageOrder','enforceRefreshLeases','schedulerMode')}
 need(all(v is None or type(v) is bool or k=='schedulerMode' and v in ('shadow','strict') for k,v in flags.items()),'fixed_flag_projection')
 report['configuredAuthBus']={'entryEnabled':entry.get('enabled') is True,'scheme':address.scheme,
  'addressReferencesJ3160':address.hostname.lower() in ('j3160','100.66.117.33'),
  'port':address.port,'hasPath':address.path not in ('','/'),'hasQuery':bool(address.query),
  'hostIdIsRegisteredRog':ac.get('hostId')=='rog','flags':flags}
 report['connectionFiles']={}
 for key in ('caFile','roleIdFile','secretIdFile'):
  value=ac.get(key);need(isinstance(value,str),'registered_authbus_connection_path')
  path=Path(value);need(path.is_absolute() and path.is_relative_to(LIVE) and '..' not in path.parts,'registered_connection_path_within_state')
  report['connectionFiles'][key]=metadata(path)
 agents=config.get('agents',{}).get('list',[])
 need(isinstance(agents,list) and 0<len(agents)<=32,'finite_current_registered_agents')
 report['agentCount']=len(agents);report['credentialStoreMetadata']=[]
 dirs=[]
 for i,agent in enumerate(agents):
  need(isinstance(agent,dict) and isinstance(agent.get('id'),str) and '/' not in agent['id'] and agent['id'] not in ('','.','..'),'registered_agent_id_shape')
  directory=configured_path(agent.get('agentDir'),LIVE/'agents'/agent['id']/'agent')
  need(directory.is_relative_to(LIVE/'agents') and directory not in dirs,'finite_unique_agent_state_paths');dirs.append(directory)
  files={name:metadata(directory/name) for name in ('openclaw-agent.sqlite','openclaw-agent.sqlite-wal','openclaw-agent.sqlite-shm','auth-profiles.json','auth-state.json')}
  report['credentialStoreMetadata'].append({'agentOrdinal':i+1,'files':files})
 registry=config.get('auth',{}).get('profiles',{})
 need(isinstance(registry,dict),'configured_profile_registry_shape');report['configuredProfileCount']=len(registry)
 report['configuredOAuthProfileCount']=sum(isinstance(v,dict) and v.get('mode')=='oauth' for v in registry.values())
 report['publicPluginPins']={}
 for name in ('index.js','package.json','order-policy.js','runtime-refresh-policy.js','codex-client-recycler.js','provider-error-classifier.js','bad-refresh-quarantine.js','lease-assignments.js'):
  pin,_=public_code(PLUGIN/name);report['publicPluginPins'][name]=pin
 report['expectedSdkPath']=str(SDK)
 if (SDK/'package.json').exists():
  sdk_pin,sdk_raw=public_code(SDK/'package.json');package=json.loads(sdk_raw)
  need(package.get('name')=='openclaw' and isinstance(package.get('version'),str) and len(package['version'])<80,'actual_installed_sdk_package')
  report['publicSdkPackage']={**sdk_pin,'version':package['version']}
 else:report['publicSdkPackage']={'exists':False}
 exe=os.readlink('/proc/'+str(PID)+'/exe');need(exe.startswith('/') and not exe.endswith(' (deleted)'),'current_gateway_executable')
 exe_pin,_=public_code(Path(exe),256*1048576);report['publicRuntimeExecutable']=exe_pin
 for name in ('openclaw-authbus-accept-after-restart','openclaw-authbus-restart-when-idle'):
  path=CALLER_HOME/'.local/bin'/name
  if path.exists():
   script,ident=read_regular(path,65536)
   report.setdefault('heldHelperSourceMetadata',{})[name]={'identity':ident,'sourceAndDigestPrivateOnly':True}
   new_private(name+'.source.private',script)
 current_raw,current_identity=read_regular(config_path,4*1048576,private=True)
 need(current_raw==raw and current_identity==config_identity,'current_configuration_unchanged')
 need(original==lifetime() and os.readlink('/proc/'+str(PID)+'/exe')==exe,'same_original_gateway_lifetime')
 need(proc_read('environ')==environment_raw and proc_read('cgroup',16384)==cgroup_raw
  and proc_read('cmdline')==args_raw,'same_current_runtime_binding')
 verify_anchors()
 new_private('source-parent-bindings.private.json',(json.dumps(anchors,sort_keys=True)+'\n').encode())
 report.update(ok=True,originalGateway=original,systemdInvocationMatches=True,cgroupMatches=True,
  defaultStateAndConfigSelectedByObservedEnvironment=True,configurationUnchanged=True,
  configurationIdentity=config_identity,privateOriginalsSaved=True,currentCmdlineUnchanged=True,
  boundParentCount=len(anchors),boundParentsUnchanged=True,
  currentCmdlineIsNotAssumedToBeOriginalStartupArgv=True)
except BaseException as error:
 report['errorCode']=str(error) if str(error) in codes else 'registered_rog_observation_refused'
 report['errorType']=type(error).__name__
finally:
 report['allReturnedDescriptorsClosed']=all(row['closed'] for row in fds)
 report['returnedDescriptorCount']=len(fds);report['elapsedSeconds']=time.monotonic()-START
 report['descriptorScope']='all returned observation handles before final result publication'
 report['ok']=report['ok'] and report['allReturnedDescriptorsClosed']
 encoded=(json.dumps(report,sort_keys=True,separators=(',',':'))+'\n').encode()
 if created:
  try:new_private('result.public.json',encoded)
  except BaseException:report['ok']=False;report['resultPublicationFailed']=True
 print(json.dumps(report,sort_keys=True,separators=(',',':')))
raise SystemExit(0 if report['ok'] else 1)
