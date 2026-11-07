#!/usr/bin/env python3
"""Observe selected Pocket4 inputs; never import its SDK or read auth DB values.

One original systemctl read obtains the manager environment into a private file.
Unit and environment values remain private. Literal default selectors are checked
before observing the default configuration. Pre-bootstrap selection and runtime
memory remain unqualified, so this report cannot authorize a service cutover.
"""
import hashlib,importlib.util,json,os,re,shlex,stat,sys,time
from pathlib import Path
from urllib.parse import urlsplit

HOME=Path('/home/alex');LIVE=HOME/'.openclaw'
ROOT=HOME/'heptabao-pocket4-current-input-observation-20261106-r1'
OLD=HOME/'heptabao-pocket4-unit-source-observation-20261106-r1'
BASE=HOME/'.config/systemd/user'
SDK=HOME/'.npm-global/lib/node_modules/openclaw'
ENVFILE=LIVE/'gateway.systemd.env'
RELATIVE=('openclaw-gateway.service','openclaw-gateway.service.d/30-telegram-spooled-handler-timeout.conf',
 'openclaw-gateway.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf',
 'openclaw-authbus-restart-when-idle.service','openclaw-authbus-restart-when-idle.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf')
PUBLIC_PLUGIN_NAMES=('index.js','package.json','order-policy.js','runtime-refresh-policy.js',
 'codex-client-recycler.js','provider-error-classifier.js','bad-refresh-quarantine.js','lease-assignments.js')
# PAYLOAD_PLACEHOLDER
START=time.monotonic();UNTIL=START+30;fds=[];codes=set();anchors={};bindings=[];owner=None;created=False
report={'schema':'heptabao.pocket4.current-input-observation.r1','ok':False,
 'productionMutations':0,'serviceActions':0,'providerCalls':0,'sdkImported':False,
 'credentialDatabaseContentsRead':False,'credentialValuesOrDigestsPublished':False,
 'configurationOrEnvironmentDigestsPublished':False,'sdkSourceExecutionQualified':False,
 'preBootstrapSelectorsQualified':False,'runningPluginMemoryQualified':False,'holdsReleased':False}
def need(v,code):
 if not v:codes.add(code);raise RuntimeError(code)
def remaining():need(time.monotonic()<UNTIL,'original_input_observation_deadline')
def identity(s):return [str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def opened(path,flags,mode=0o777,dir_fd=None,role='input'):
 fd=os.open(path,flags,mode,dir_fd=dir_fd);row={'role':role,'closeAttempts':0,'closed':False};fds.append(row);return fd,row
def close(item):
 fd,row=item;need(row['closeAttempts']==0,'input_descriptor_close_once');row['closeAttempts']=1;os.close(fd);row['closed']=True
def read(path,cap=1048576,*,private=False,public=False,bind=True):
 remaining();held=[];path=Path(path)
 need(path.is_absolute() and '..' not in path.parts,'absolute_selected_input_path')
 try:
  item=opened('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,role='parent');held.append(item);cur=Path('/')
  for name in path.parts[1:-1]:
   item=opened(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=item[0],role='parent');held.append(item);cur/=name;s=os.fstat(item[0])
   need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.getuid()) and (public or not s.st_mode&0o022),'bounded_input_parent_ownership')
   v=identity(s)[:5];need(v==identity(cur.lstat())[:5],'named_input_parent_same')
   if str(cur) in anchors:need(anchors[str(cur)]==v,'bound_input_parent_same')
   else:anchors[str(cur)]=v
  item=opened(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=item[0]);held.append(item);s=os.fstat(item[0])
  need(stat.S_ISREG(s.st_mode) and s.st_uid in (0,os.getuid()) and s.st_nlink==1 and 0<=s.st_size<=cap and (public or not s.st_mode&0o022),'bounded_regular_input')
  if private:need(s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600,'private_input_mode600')
  raw=bytearray()
  while len(raw)<=s.st_size:
   remaining();part=os.read(item[0],min(65536,s.st_size+1-len(raw)))
   if not part:break
   raw.extend(part)
  need(len(raw)==s.st_size and identity(s)==identity(os.fstat(item[0]))==identity(path.lstat()),'complete_stable_input')
  if bind:bindings.append((path,identity(s),hashlib.sha256(raw).digest(),private,public,cap))
  return bytes(raw),s
 finally:
  for item in reversed(held):
   try:close(item)
   except OSError:report['closeUnknown']=True
def save(name,raw):
 need(created and '/' not in name and len(raw)<=4*1048576,'new_private_output_scope')
 item=opened(ROOT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,role='private-output')
 try:
  view=memoryview(raw)
  while view:
   remaining();n=os.write(item[0],view);need(n>0,'private_output_progress');view=view[n:]
  os.fsync(item[0])
 finally:close(item)
def assignment(token):
 key,sep,value=token.partition('=');need(sep and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,99}',key),'literal_environment_assignment')
 need('\x00' not in value,'environment_value_no_nul');return key,value
def assignment_lines(raw):
 result={}
 for line in raw.decode('utf-8').splitlines():
  text=line.strip()
  if not text or text.startswith(('#',';')):continue
  need(not text.endswith('\\'),'environment_continuations_not_admitted')
  parts=shlex.split(text,posix=True);need(len(parts)==1,'one_literal_environment_assignment')
  key,value=assignment(parts[0]);need(key not in result,'unique_literal_environment_assignment');result[key]=value
 return result
def unit_directives(raw):
 section=None;rows=[]
 for line in raw.decode('utf-8').splitlines():
  text=line.strip()
  if not text or text.startswith(('#',';')):continue
  need(not text.endswith('\\'),'unit_continuations_not_admitted')
  if text.startswith('[') and text.endswith(']'):section=text[1:-1];continue
  need('=' in line,'complete_unit_directive');key,value=line.split('=',1);rows.append((section,key.strip(),value.strip()))
 return rows
def metadata(path):
 for parent in reversed(path.parents):
  try:ps=parent.lstat()
  except FileNotFoundError:return {'exists':False,'parentMissing':True}
  need(stat.S_ISDIR(ps.st_mode) and ps.st_uid in (0,os.getuid()) and not ps.st_mode&0o022,'store_metadata_parent_custody')
 try:s=path.lstat()
 except FileNotFoundError:return {'exists':False}
 need(not stat.S_ISLNK(s.st_mode),'no_store_leaf_symlink')
 return {'exists':True,'regular':stat.S_ISREG(s.st_mode),'directory':stat.S_ISDIR(s.st_mode),
  'ownerMatches':s.st_uid==os.getuid(),'mode':oct(stat.S_IMODE(s.st_mode)),'identity':identity(s)}
try:
 need(sys.platform=='linux' and Path.home()==HOME and os.getuid()==1000,'expected_pocket4_account')
 os.umask(0o077);sys.dont_write_bytecode=True
 hs=HOME.lstat();need(stat.S_ISDIR(hs.st_mode) and hs.st_uid==1000 and not hs.st_mode&0o022,'owned_pocket4_home')
 raw,_=read(OLD/'bindings.private.json',private=True);oldbindings=json.loads(raw)
 need(len(oldbindings)==5,'five_original_unit_bindings');units=[]
 for i,(relative,binding) in enumerate(zip(RELATIVE,oldbindings)):
  need(binding['sourcePath']==str(BASE/relative) and binding['file']==f'unit-{i:02d}.original.private','exact_original_unit_paths')
  raw,s=read(BASE/relative);need(identity(s)==binding['identity'] and hashlib.sha256(raw).hexdigest()==binding['sha256'],'current_same_original_unit_generation');units.append(unit_directives(raw))
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 source=OWNED_SOURCE.encode();need(hashlib.sha256(source).hexdigest()==OWNED_SHA,'qualified_owned_process_source')
 save('owned_process.py',source)
 spec=importlib.util.spec_from_file_location('pocket4_observation_owned_process',ROOT/'owned_process.py');owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
 owner=owned.Owner(ROOT,deadline_ns=time.monotonic_ns()+int((UNTIL-time.monotonic())*1e9),profile='pocket4_current_input_readonly')
 output=opened(ROOT/'manager-environment.original.private',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,role='private-child-stdout')
 errors=opened(ROOT/'manager-environment.stderr.private',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,role='private-child-stderr')
 try:
  with owned.activated(owner):
   result=owned.run(['/usr/bin/systemctl','--user','show-environment'],label='pocket4-manager-environment-read',timeout=5,stdout=output[0],stderr=errors[0],stdin=owned.subprocess.DEVNULL)
   need(result.returncode==0,'known_original_manager_environment_read')
  os.fsync(output[0]);os.fsync(errors[0])
 finally:close(errors);close(output)
 need(owner.receipt['passed_process_method'] and owner.receipt['same_originals_closed'],'original_readonly_child_closed')
 raw,_=read(ROOT/'manager-environment.original.private',131072,private=True);manager=assignment_lines(raw)
 errorraw,_=read(ROOT/'manager-environment.stderr.private',131072,private=True);need(not errorraw,'manager_read_no_stderr')
 explicit={};files=[];unset=[]
 for section,key,value in [r for unit in units[:3] for r in unit]:
  if section!='Service':continue
  if key=='Environment':
   if not value:explicit={}
   else:
    for token in shlex.split(value,posix=True):
     name,selected=assignment(token);explicit[name]=selected
  elif key=='EnvironmentFile':
   if not value:files=[]
   else:files.append(value)
  elif key=='UnsetEnvironment':
   if not value:unset=[]
   else:unset.extend(shlex.split(value,posix=True))
  elif key in ('PAMName','RootDirectory','RootImage','ExecSearchPath','PassEnvironment'):
   need(not value,'no_unhandled_service_environment_selector')
 need(files==['-'+str(ENVFILE)],'one_observed_optional_environment_file')
 effective={**manager,**explicit};need(not ENVFILE.is_symlink(),'environment_file_not_symlink');env_present=ENVFILE.exists()
 if env_present:
  raw,_=read(ENVFILE,131072,private=True);save('gateway-environment.original.private',raw);effective.update(assignment_lines(raw))
 for item in unset:
  if '=' in item:
   key,value=assignment(item)
   if effective.get(key)==value:effective.pop(key)
  else:
   need(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,99}',item),'literal_unset_environment_key');effective.pop(item,None)
 need(effective.get('HOME')==str(HOME),'effective_service_home_literal')
 need(not effective.get('OPENCLAW_HOME') and not effective.get('OPENCLAW_PROFILE'),'no_additional_literal_root_or_profile_selector')
 need(effective.get('OPENCLAW_STATE_DIR',str(LIVE))==str(LIVE) and effective.get('OPENCLAW_CONFIG_PATH',str(LIVE/'openclaw.json'))==str(LIVE/'openclaw.json'),'literal_default_state_and_config')
 raw,s=read(LIVE/'openclaw.json',4*1048576,private=True);save('default-configuration.original.private.json',raw);cfg=json.loads(raw);need(isinstance(cfg,dict),'configuration_object')
 entry=cfg.get('plugins',{}).get('entries',{}).get('openclaw-authbus',{});need(isinstance(entry,dict) and isinstance(entry.get('config'),dict),'registered_authbus_entry');ac=entry['config'];address=urlsplit(ac.get('address',''))
 report['configuredAuthBus']={'entryEnabled':entry.get('enabled') is True,'addressReferencesJ3160':(address.hostname or '').lower() in ('j3160','100.66.117.33'),
  'usesHttps':address.scheme=='https','leader':ac.get('leader') is True,'publishNew':ac.get('publishNew') is True,'manageOrder':ac.get('manageOrder') is True}
 agents=cfg.get('agents',{}).get('list',[]);need(isinstance(agents,list) and 0<len(agents)<=32,'bounded_configured_agent_list');dirs=[];stores=[]
 for ordinal,agent in enumerate(agents):
  need(isinstance(agent,dict) and isinstance(agent.get('id'),str) and re.fullmatch(r'[A-Za-z0-9_-]{1,100}',agent['id']),'configured_agent_id_shape')
  directory=Path(agent.get('agentDir',str(LIVE/'agents'/agent['id']/'agent')))
  need(directory.is_relative_to(LIVE/'agents') and '..' not in directory.parts and directory not in dirs,'bounded_unique_configured_agent_path');dirs.append(directory)
  stores.append({'agentOrdinal':ordinal+1,'files':{name:metadata(directory/name) for name in ('openclaw-agent.sqlite','openclaw-agent.sqlite-wal','openclaw-agent.sqlite-shm','auth-profiles.json','auth-state.json')}})
 report['agentCount']=len(agents);report['credentialStoreMetadata']=stores
 report['publicCodeObservations']={}
 for path in (SDK/'package.json',SDK/'dist/index.js',*(LIVE/'extensions/openclaw-authbus'/name for name in PUBLIC_PLUGIN_NAMES)):
  raw,s=read(path,1048576,public=True)
  report['publicCodeObservations'][str(path)]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':oct(stat.S_IMODE(s.st_mode)),
   'groupOrWorldWritable':bool(s.st_mode&0o022),'observationOnly':True,'trustedForExecution':False}
  if path==SDK/'package.json':
   package=json.loads(raw);need(package.get('name')=='openclaw' and re.fullmatch(r'[0-9A-Za-z.+-]{1,80}',package.get('version','')),'sdk_package_metadata');report['observedSdkVersion']=package['version']
  elif path==LIVE/'extensions/openclaw-authbus/package.json':
   package=json.loads(raw);need(re.fullmatch(r'[0-9A-Za-z.+-]{1,80}',package.get('version','')),'plugin_package_metadata');report['observedPluginVersion']=package['version']
 for path,ident,pin,private,public,cap in list(bindings):
  raw,s=read(path,cap,private=private,public=public,bind=False);need(identity(s)==ident and hashlib.sha256(raw).digest()==pin,'all_input_generations_unchanged')
 for path,v in anchors.items():need(identity(Path(path).lstat())[:5]==v,'all_input_parent_anchors_unchanged')
 need(ENVFILE.exists()==env_present,'optional_environment_file_existence_unchanged')
 report.update(ok=True,allInputGenerationsUnchanged=True,managerEnvironmentObserved=True,literalDefaultStateAndConfig=True,
  environmentFilePresent=env_present,hasNodeOptions=bool(effective.get('NODE_OPTIONS')),hasNodePath=bool(effective.get('NODE_PATH')))
except BaseException as error:
 report['errorType']=type(error).__name__;report['errorCode']=str(error) if str(error) in codes else 'current_input_observation_unavailable'
finally:
 if owner is not None:
  try:owner.finish();report['originalProcessCustody']=owner.receipt
  except BaseException:report['originalProcessCustodyUnknown']=True;report['ok']=False
  if not getattr(owner,'receipt',{}).get('passed_process_method',False):report['ok']=False
 report['fileDescriptors']=fds;report['allDescriptorsClosedOnce']=all(r['closeAttempts']==1 and r['closed'] for r in fds)
 if not report['allDescriptorsClosedOnce']:report['ok']=False
 report['createdPrivateRoot']=created;report['elapsedSeconds']=time.monotonic()-START
 print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
sys.exit(0 if report['ok'] else 1)
