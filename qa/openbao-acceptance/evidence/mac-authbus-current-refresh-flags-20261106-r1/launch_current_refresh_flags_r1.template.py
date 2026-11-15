#!/usr/bin/env python3
"""Bounded current main3 refresh concurrency facts; no refresh or source write."""
import contextlib,hashlib,json,os,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Users/qianqi/heptabao-authbus-current-refresh-flags-20261106-r1')
LIVE=Path('/Users/qianqi/.openclaw');SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
PLUGIN=LIVE/'extensions/openclaw-authbus'
QUAL=Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2')
CONFIG_ROOT=Path('/Users/qianqi/heptabao-authbus-current-source-20261106-r1')
ORDER_ROOT=Path('/Users/qianqi/heptabao-authbus-current-sdk-order-20261106-r1')
BINDING=CONFIG_ROOT/'output/current-source-binding.private.json'
MAPPING=ORDER_ROOT/'output/owner-mapping.private.json'
STATES=('bad-refresh-quarantine.json','refresh-backoff.json')
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
NODE='/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
# PAYLOAD_PLACEHOLDER
PINS={
 'authbus_current_auth_wal.py':'ad443869e259da06de2be71131e5d1854680477d1cf77248e05a3c1704160f8c',
 'mac_guarded_current_capture_r3.py':'606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693',
 'mac_registry_readonly_wal_r1.py':'60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed',
 'kv2_dr_process_custody.py':'669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008',
 'owned_process.py':'0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'}
report={'schema':'heptabao.current-main3-refresh-flags-owned.r1','ok':False,
 'providerCalled':False,'refreshDispatched':False,'productionWrites':0,'productionMutexAcquired':False,
 'j3160Contacted':False,'serviceActions':0,'credentialValuesOrDigestsPublished':False,
 'profileIdsPublished':False,'rawConfigurationHashPublished':False,'wholeCacheFileCopied':False,
 'registryDatabaseOpened':False,'selectionOrderReexecuted':False,
 'sharedSeconds':45,'supervisorSeconds':70,'automaticRetry':False,
 'configuredFlagsDoNotProveRunningServiceConfiguration':True}
errors=set();created=False;owner=None;source=None;bundle=None;state_guard=None;children=[]
def need(value,code):
 if not value:errors.add(code);raise RuntimeError(code)
def remaining(cap=45):
 left=UNTIL-time.monotonic();need(left>0,'original_refresh_flags_deadline');return min(left,cap)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def ident(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,cap=1048576,private=False):
 remaining();fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid in (0,501) and before.st_nlink==1
    and not stat.S_IMODE(before.st_mode)&0o022 and 0<=before.st_size<=cap,'bounded_public_or_owned_input')
  if private:need(before.st_uid==501 and stat.S_IMODE(before.st_mode)==0o600,'private_scope_input_custody')
  out=bytearray()
  while len(out)<=cap:
   remaining();part=os.read(fd,min(65536,cap+1-len(out)))
   if not part:break
   out.extend(part)
  need(len(out)==before.st_size and ident(before)==ident(os.fstat(fd))==ident(Path(path).lstat()),'stable_whole_input')
  return bytes(out)
 finally:os.close(fd)
def new(path,data):
 raw=data if isinstance(data,bytes) else data.encode();need(len(raw)<=1048576,'bounded_owned_projection')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:
   remaining();n=os.write(fd,view);need(n>0,'owned_projection_write_progress');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def validate_authority(value,job):
 need(value['job_id']==job and value['state']=='succeeded' and value['exit_code']==0
   and all(value[k] is True for k in ('output_complete','output_durable','terminal_publication_confirmed'))
   and all(value[k] is False for k in ('timed_out','cancelled','automatic_retry')),'original_known_public_authority')
class StateInputs:
 """Only two named state files; held no-follow parents and whole-file full9."""
 def __init__(self):self.rows=[];self.absent=set();self.opened=0;self.closed=0;self.finished=False;self.close_errors=[]
 def hold_parent(self,name,parent=None):
  remaining();fd=os.open(name if parent is None else Path(name).name,
   os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,**({} if parent is None else {'dir_fd':parent}))
  self.opened+=1
  try:
   s=os.fstat(fd);need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,501) and not stat.S_IMODE(s.st_mode)&0o022,'state_parent_custody')
  except BaseException:os.close(fd);self.closed+=1;raise
  self.rows.append({'path':str(name),'fd':fd,'expected':ident(s)});return fd
 def get(self,name):
  need(name in STATES,'only_two_known_state_paths');pathname=LIVE/'authbus'/name
  parent=self.hold_parent(Path('/'))
  for part in (Path('/Users'),Path('/Users/qianqi'),LIVE,LIVE/'authbus'):
   try:parent=self.hold_parent(part,parent)
   except FileNotFoundError:
    need(part==LIVE/'authbus','only_known_optional_state_directory');self.absent.update((str(part),str(pathname)));return None
  try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
  except FileNotFoundError:self.absent.add(str(pathname));return None
  self.opened+=1;s=os.fstat(fd)
  self.rows.append({'path':str(pathname),'fd':fd,'expected':ident(s)})
  need(stat.S_ISREG(s.st_mode) and s.st_uid==501 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
    and 0<s.st_size<=1048576,'selected_state_file_custody')
  data=bytearray()
  while len(data)<=1048576:
   remaining();part=os.read(fd,min(65536,1048577-len(data)))
   if not part:break
   data.extend(part)
  need(len(data)==s.st_size and ident(s)==ident(os.fstat(fd))==ident(pathname.lstat()),'state_full_file_unchanged')
  return bytes(data)
 def verify(self):
  for row in self.rows:
   remaining();need(ident(Path(row['path']).lstat())==row['expected'],'state_full9_name_unchanged')
   if not self.finished:need(ident(os.fstat(row['fd']))==row['expected'],'state_original_descriptor_unchanged')
  for name in self.absent:
   remaining()
   try:Path(name).lstat()
   except FileNotFoundError:continue
   raise RuntimeError('state_original_absence_changed')
 def close(self):
  if self.finished:return
  self.finished=True
  for row in reversed(self.rows):
   try:os.close(row['fd']);self.closed+=1
   except OSError:self.close_errors.append('original_descriptor_close_unknown')
 def public(self):return {'openedDescriptors':self.opened,'closedDescriptors':self.closed,
   'allOwnedDescriptorsClosed':self.finished and self.opened==self.closed and not self.close_errors,
   'closeErrors':list(self.close_errors),'full9ComparisonWeakened':False}
def fence():
 remaining();source.verify();auth.verify_auth_bundle(source,bundle,until=UNTIL);state_guard.verify()
def code_fence():
 for name,pin in PINS.items():need(sha(read(QUAL/'qa'/name))==pin,'qualified_capture_source_pin')
 for relative,pin in {**PAYLOAD['sdkPins'],**PAYLOAD['additionalSdkPins']}.items():need(sha(read(SDK/relative))==pin,'current_sdk_public_source_pin')
 for name,pin in PAYLOAD['pluginPins'].items():need(sha(read(PLUGIN/name))==pin,'current_plugin_public_source_pin')
 need(sha(read(Path(NODE),2097152))=='a46ed02589ca3af795237111ff854262064f8ff5c5b58d75c1509f37311eb15e','exact_node_runtime')
 need(sha(read(Path(PYTHON),2097152))=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13','exact_python_runtime')
def close_streams(child):
 for stream in (child.stdin,child.stdout,child.stderr):
  if stream is not None and not stream.closed:stream.close()
try:
 os.umask(0o077)
 need(sys.platform=='darwin' and os.getuid()==501 and os.path.realpath(sys.executable)==PYTHON,'actual_mac_refresh_flags_owner')
 validate_authority(PAYLOAD['custodyAuthority'],'1a1b141ef40-fc05-7750')
 proof=read(QUAL/'result.public.json',65536)
 need(len(proof)==58701 and sha(proof)=='67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e','original_18_case_qualification')
 q=json.loads(proof);need(q['ok'] and q['allCasesMatched'] and q['allOwnedClosed'] and q['custody']['passed_process_custody'],'original_qualified_readonly_capture')
 validate_authority(PAYLOAD['configAuthority'],'1a1b137a21d-fc05-76f8')
 validate_authority(PAYLOAD['orderAuthority'],'1a1b197fa0e-fc05-79c0')
 for path,pin in [(CONFIG_ROOT/'result.public.json',PAYLOAD['configResult']),(ORDER_ROOT/'result.public.json',PAYLOAD['orderResult'])]:
  raw=read(path,65536);need(len(raw)==pin['bytes'] and sha(raw)==pin['sha256'],'original_scope_public_receipt_exact')
 code_fence();sys.path.insert(0,str(QUAL/'qa'))
 import authbus_current_auth_wal as auth
 import kv2_dr_process_custody as custody
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 for name in ('code','output','output/tmp','output/tmp/openclaw-501'):(ROOT/name).mkdir(mode=0o700,exist_ok=False)
 new(ROOT/'protected-read',b'owned synthetic protected read probe\n');new(ROOT/'protected-write',b'owned synthetic protected write probe\n')
 for name,raw in PAYLOAD['sources'].items():
  need(name in ('mac_current_refresh_flags_r1.mjs','authbus_sdk_read_guard.mjs') and sha(raw.encode())==PAYLOAD['sourcePins'][name],'prepared_readonly_worker_source')
  new(ROOT/'code'/name,raw)
 binding=auth.strict_json(read(BINDING,262144,True));mapping=auth.strict_json(read(MAPPING,1048576,True))
 need(binding['schema']=='heptabao.authbus-current-source-allowlist.private.r1' and binding['sourceRoot']==str(LIVE)
   and mapping['schema']=='heptabao.actual-sdk-owned-profile-mapping.private.r1' and mapping['host']=='mac'
   and mapping['configurationSha256']==binding['configurationSha256'] and mapping['configurationIdentity']==binding['configurationIdentity']
   and mapping['sdkSourcePins']==PAYLOAD['sdkPins'] and mapping['constraints']['selectionOrderExecuted'] is True,'original_selected_owner_scope')
 selected=mapping['selectedOwners'];need(isinstance(selected,list) and len(selected)==3
   and len({r['profileId'] for r in selected})==3 and all(r['ownerAgent']=='main' and r['ownerAgentDir']==str(LIVE/'agents/main/agent')
     and r['actualProvider']=='openai' and isinstance(r['profileId'],str) and 0<len(r['profileId'])<=256 for r in selected),'exact_three_selected_main_owners')
 source=auth.AuthInputs(until=UNTIL,critical=contextlib.nullcontext,cancelled=lambda:False)
 raw=source.read(LIVE/'openclaw.json');cfg=auth.strict_json(raw)
 need(sha(raw)==binding['configurationSha256'] and list(source.files[str(LIVE/'openclaw.json')]['expected'])==binding['configurationIdentity'],
   'original_configuration_still_current_full9')
 need(set(cfg.get('auth',{}).get('profiles',{}))=={row['profileId'] for row in binding['registeredProfiles']},'same_current_registered_configuration')
 entry=cfg.get('plugins',{}).get('entries',{}).get('openclaw-authbus')
 need(isinstance(entry,dict) and isinstance(entry.get('config'),dict),'current_authbus_config_entry')
 bundle=auth.auth_wal_database(source,'main');state_guard=StateInputs();states={}
 selected_ids={r['profileId'] for r in selected}
 for name in STATES:
  raw_state=state_guard.get(name)
  if raw_state is None:states[name]={'present':False,'profiles':{}};continue
  value=auth.strict_json(raw_state)
  need(isinstance(value,dict) and isinstance(value.get('profiles'),dict),'known_state_file_structure_not_silently_ignored')
  states[name]={'present':True,'profiles':{key:item for key,item in value['profiles'].items() if key in selected_ids}}
 input={'schema':'heptabao.current-main3-refresh-flags-input.private.r1','host':'mac',
  'selectionAuthorityJob':'1a1b197fa0e-fc05-79c0','currentConfigurationSameAsOriginal':True,
  'configurationSha256':binding['configurationSha256'],'selectedOwners':selected,
  'pluginRawConfig':entry['config'],'pluginEntryEnabled':entry.get('enabled'),
  'states':states,'sdkPins':{**PAYLOAD['sdkPins'],**PAYLOAD['additionalSdkPins']},'pluginPins':PAYLOAD['pluginPins']}
 new(ROOT/'input.private.json',json.dumps(input,sort_keys=True).encode()+b'\n')
 paths={ROOT,ROOT/'input.private.json',LIVE/'openclaw.json',PLUGIN/'index.js',PLUGIN/'bad-refresh-quarantine.js'}
 for pathname in tuple(paths):paths.update(pathname.parents)
 database=LIVE/'agents/main/agent/openclaw-agent.sqlite'
 for suffix in ('','-wal','-shm','-journal'):
  pathname=Path(str(database)+suffix);paths.add(pathname);paths.update(pathname.parents)
 lines=['(version 1)','(deny default)','(allow process*)','(allow signal (target children))',
  '(allow sysctl-read)','(allow mach-lookup)','(allow file-read-metadata)']
 for name in ('/System','/usr','/bin','/sbin','/Library','/private/etc','/opt/homebrew','/dev/fd'):
  lines.append('(allow file-read* (subpath '+json.dumps(name)+'))')
 for name in (ROOT/'code',ROOT/'output'):lines.append('(allow file-read* (subpath '+json.dumps(str(name))+'))')
 for name in sorted(paths,key=str):lines.append('(allow file-read* (literal '+json.dumps(str(name))+'))')
 for name in ('/dev/null','/dev/urandom','/dev/random'):lines.append('(allow file-read* (literal '+json.dumps(name)+'))')
 lines.extend(['(allow file-write* (subpath '+json.dumps(str(ROOT/'output'))+'))','(allow file-write* (literal "/dev/null"))'])
 policy='\n'.join(lines)+'\n';new(ROOT/'reader.sb',policy)
 env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/Users/qianqi','NODE_NO_WARNINGS':'1',
  'TMPDIR':str(ROOT/'output/tmp'),'OPENCLAW_STATE_DIR':str(LIVE),
  'OPENCLAW_CONFIG_PATH':str(LIVE/'openclaw.json'),'OPENCLAW_AUTH_STORE_READONLY':'1'}
 original_popen=subprocess.Popen;original_killpg=os.killpg;fence()
 with custody.activated() as owner:
  child=subprocess.Popen([NODE,'--check',str(ROOT/'code/mac_current_refresh_flags_r1.mjs')],
   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=env)
  children.append(child);out,err=child.communicate(timeout=remaining(5));close_streams(child)
  need(child.returncode==0 and not out and not err,'actual_readonly_worker_syntax')
  fence()
  child=subprocess.Popen(['/usr/bin/sandbox-exec','-f',str(ROOT/'reader.sb'),NODE,'--no-warnings',
    str(ROOT/'code/mac_current_refresh_flags_r1.mjs'),str(int(remaining(30)*1000))],stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=env)
  children.append(child);out,err=child.communicate(timeout=remaining(30));close_streams(child)
  need(len(out)<=65536 and len(err)<=16384,'bounded_readonly_worker_output')
  new(ROOT/'output/child.stdout.public.json',out);new(ROOT/'output/child.stderr.private',err)
  value=json.loads(out);report['observation']=value;report['stderrBytes']=len(err);report['childExitCode']=child.returncode
  need(child.returncode==0 and not err and value.get('ok') is True,'actual_current_refresh_flags_complete')
  owner.assert_retired()
 report['custody']=owner.receipt()
 need(report['custody']['passed_process_custody'] and report['custody']['original_count']==2
   and subprocess.Popen is original_popen and os.killpg is original_killpg,'all_original_flags_children_closed')
 fence();closed_names=[(name,tuple(item['expected'])) for name,item in source.files.items()];closed_absences=list(source.absent)
 source.close();state_guard.close();state_guard.verify()
 need(source.public()['allOwnedDescriptorsClosed'] and state_guard.public()['allOwnedDescriptorsClosed'],'all_source_state_descriptors_closed')
 for name,expected in closed_names:remaining();need(ident(Path(name).lstat())==expected,'closed_current_auth_full9_unchanged')
 for name in closed_absences:
  remaining()
  try:Path(name).lstat()
  except FileNotFoundError:continue
  raise RuntimeError('closed_current_auth_absence_changed')
 code_fence()
 for name,pin in PAYLOAD['sourcePins'].items():need(sha(read(ROOT/'code'/name))==pin,'owned_worker_source_after')
 remaining();report.update(ok=True,currentConfigurationWholeBytesAndFull9Exact=True,
   currentMainAuthFull9Exact=True,currentTwoKnownStateFilesFull9OrAbsenceExact=True,
   allSourceDescriptorsClosed=True,sourcePins=PAYLOAD['sourcePins'],sdkSourcePins={**PAYLOAD['sdkPins'],**PAYLOAD['additionalSdkPins']},
   pluginSourcePins=PAYLOAD['pluginPins'],sandboxProfileSha256=sha(policy.encode()),
   actualCurrentMainCredentialLookupCount=3,providerValidityQualified=False)
except BaseException as error:
 report['errorCode']=str(error) if str(error) in errors else 'current_refresh_flags_refused'
 report['errorType']=type(error).__name__
finally:
 for child in children:close_streams(child)
 if owner is not None:report['custody']=owner.receipt()
 if source is not None:source.close();report['sourceGuardClosure']=source.public()
 if state_guard is not None:state_guard.close();report['stateGuardClosure']=state_guard.public()
 report['elapsedSeconds']=round(time.monotonic()-START,6)
 if created:
  try:new(ROOT/'result.public.json',json.dumps(report,sort_keys=True).encode()+b'\n')
  except BaseException:report['ok']=False;report['resultPublicationFailed']=True
 print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['ok'] else 1)
