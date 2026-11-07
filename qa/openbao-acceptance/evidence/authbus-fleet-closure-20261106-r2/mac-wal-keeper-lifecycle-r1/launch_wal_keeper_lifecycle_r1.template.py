#!/usr/bin/env python3
"""One bounded synthetic Mac WAL lifecycle; no live config, credentials, or service."""
import hashlib,json,os,sqlite3,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Users/qianqi/heptabao-authbus-wal-keeper-lifecycle-20261106-r1')
QUAL=Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2')
SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
NODE='/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
# PAYLOAD_PLACEHOLDER
CUSTODY_PINS={
 'kv2_dr_process_custody.py':'669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008',
 'owned_process.py':'0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'}
RUNTIME_PINS={
 PYTHON:'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13',
 NODE:'a46ed02589ca3af795237111ff854262064f8ff5c5b58d75c1509f37311eb15e',
 '/usr/bin/sandbox-exec':'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a'}
PHASES=('read-cold','read-held','write-held','read-committed','read-after-close')
SOURCE_NAMES=('mac_sdk_raw_owner_cas_r1.mjs','mac_wal_keeper_sdk_worker_r1.mjs')
FIELDS=('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns')
SUFFIXES=('','-wal','-shm','-journal')
IDS=['synthetic-main-one','synthetic-main-two','synthetic-main-three']
report={'schema':'heptabao.actual-mac-synthetic-wal-keeper-lifecycle.r1','ok':False,
 'sharedSeconds':45,'supervisorSeconds':70,'automaticRetry':False,'providerCalls':0,
 'productionCredentialReads':0,'productionWrites':0,'productionMutexAcquired':False,
 'nativeServiceStarted':False,'syntheticStateOnly':True,'originalChildrenExpected':7,
 'keeperUsedAsLatestSource':False,'productionKeeperOrRefreshControllerQualified':False,
 'children':[],'namespaceObservations':[],'phases':[],
 'candidateCommit':'4bde9aee03fcd27c59e13607e529b1cee594b249'}
owner=None;created=False;children=[];connections=[];namespace_records=[];error_codes=set()
def need(value,code):
 if not value:error_codes.add(code);raise RuntimeError(code)
def remaining(cap=45):
 value=UNTIL-time.monotonic();need(value>0,'original_wal_lifecycle_deadline');return min(cap,value)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def ident(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,cap=1048576):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid in (0,501)
    and not stat.S_IMODE(s.st_mode)&0o022 and 0<=s.st_size<=cap,'bounded_public_wal_source')
  out=bytearray()
  while len(out)<=cap:
   remaining();part=os.read(fd,min(65536,cap+1-len(out)))
   if not part:break
   out.extend(part)
  need(len(out)==s.st_size and ident(s)==ident(os.fstat(fd))==ident(Path(path).lstat()),'stable_public_wal_source')
  return bytes(out)
 finally:os.close(fd)
def private(path,data):
 raw=data if isinstance(data,bytes) else data.encode();need(len(raw)<=262144,'bounded_owned_wal_artifact')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:
   remaining();n=os.write(fd,view);need(n>0,'owned_wal_write_progress');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def fence():
 for name,pin in CUSTODY_PINS.items():need(sha(read(QUAL/'qa'/name))==pin,'qualified_custody_source_unchanged')
 for path,pin in RUNTIME_PINS.items():need(sha(read(Path(path),2*1048576))==pin,'qualified_wal_runtime_unchanged')
 for name,pin in PAYLOAD['sdkPins'].items():need(sha(read(SDK/name))==pin,'qualified_raw_sdk_source_unchanged')
def database(which):
 need(which in ('cold','held'),'fixed_synthetic_database_slot')
 return ROOT/'output/fixtures'/which/'agents/main/agent/openclaw-agent.sqlite'
def namespace(which,label,prior=None):
 found={};changes={}
 for suffix in SUFFIXES:
  key='db' if not suffix else suffix[1:]
  try:s=Path(str(database(which))+suffix).lstat()
  except FileNotFoundError:found[key]=None
  else:
   need(stat.S_ISREG(s.st_mode) and s.st_uid==501 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,
    'owned_synthetic_sqlite_namespace')
   found[key]=ident(s)
  if prior is not None:
   a,b=prior[key],found[key]
   changes[key]=['presence'] if (a is None)!=(b is None) else [] if a is None else [FIELDS[i] for i in range(9) if a[i]!=b[i]]
 need(found['db'] is not None and found['journal'] is None,'fixed_synthetic_wal_database')
 namespace_records.append({'phase':label,'slot':which,'full9':found})
 report['namespaceObservations'].append({'phase':label,'slot':which,
  'present':{k:v is not None for k,v in found.items()},'changedFields':changes})
 return found
def open_sql(which,role,readonly=False,immutable=False):
 remaining();need(not immutable or readonly,'synthetic_immutable_read_only')
 p=database(which);target=p.as_uri()+'?mode=ro'+('&immutable=1' if immutable else '') if readonly else str(p)
 db=sqlite3.connect(target,uri=readonly,timeout=0,isolation_level=None)
 row={'role':role,'readOnly':readonly,'immutableControlOnly':immutable,'closeAttempts':0,'closed':False,
  'cursorOpened':0,'cursorClosed':0,'beginDispatches':0,'rollbackDispatches':0,'transactionActive':False,'unknown':False}
 item={'db':db,'row':row};connections.append(item);return item
def query(item,sql,parameters=(),fetch='none'):
 row=item['row'];need(not row['closeAttempts'],'live_original_parent_sqlite_handle')
 cursor=item['db'].execute(sql,parameters);row['cursorOpened']+=1
 try:
  if fetch=='one':return cursor.fetchone()
  if fetch=='all':return cursor.fetchall()
  need(fetch=='none','fixed_parent_query_mode')
 finally:cursor.close();row['cursorClosed']+=1
def begin_keeper(item):
 row=item['row'];need(row['readOnly'] and not row['immutableControlOnly'] and not row['beginDispatches'],'single_actual_keeper_begin')
 query(item,'PRAGMA query_only=ON');need(query(item,'PRAGMA query_only',fetch='one')==(1,),'keeper_query_only_enabled')
 row['beginDispatches']+=1;query(item,'BEGIN');row['transactionActive']=True
 value=query(item,'SELECT store_json FROM auth_profile_store WHERE store_key = ?',('primary',),'one')
 need(value is not None and json.loads(value[0])==store(),'keeper_established_actual_read_snapshot')
 report['keeperReadTransactionEstablished']=True
 return value[0]
def close_sql(item):
 row=item['row']
 if row['closeAttempts']:return
 try:
  if row['transactionActive']:
   need(row['rollbackDispatches']==0,'keeper_rollback_not_replayed');row['rollbackDispatches']+=1
   try:query(item,'ROLLBACK');row['transactionActive']=False
   except BaseException:row['unknown']=True;raise
 finally:
  row['closeAttempts']+=1
  try:item['db'].close();row['closed']=True
  except BaseException:row['unknown']=True;raise
def credential(n):
 return {'type':'oauth','provider':'openai','access':'synthetic-access-'+n,'refresh':'synthetic-refresh-'+n,
  'expires':1,'accountId':'synthetic-account-'+n,'email':'synthetic-'+n+'@invalid.example',
  'retainedExtension':{'purpose':'wal-lifecycle-only','value':7}}
def store():
 value={'version':1,'profiles':{key:credential(str(i+1)) for i,key in enumerate(IDS)},
  'preservedUnknown':{'nested':[1,'unchanged',{'flag':True}]},'order':{'openai':[IDS[2],IDS[0],IDS[1]]},
  'usageStats':{IDS[0]:{'lastUsed':123,'errorCount':2}},'lastGood':{'openai':IDS[1]}}
 value['profiles']['synthetic-other-provider']={'type':'api_key','provider':'anthropic','key':'synthetic-other-key'}
 return value
STATE={'version':1,'order':{'openai':[IDS[2],IDS[0],IDS[1]]},'usageStats':{IDS[1]:{'lastUsed':27}},'lastGood':{'openai':IDS[2]}}
def setup(which,checkpoint_control=False):
 item=open_sql(which,which+'-original-rw')
 need(query(item,'PRAGMA journal_mode=WAL',fetch='one')==('wal',),'actual_synthetic_wal_mode')
 query(item,'PRAGMA wal_autocheckpoint=0')
 query(item,'CREATE TABLE auth_profile_store(store_key TEXT PRIMARY KEY, store_json TEXT NOT NULL, updated_at INTEGER NOT NULL)')
 query(item,'CREATE TABLE auth_profile_state(state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at INTEGER NOT NULL)')
 value=store()
 if checkpoint_control:value['profiles'][IDS[0]]['access']='synthetic-access-checkpointed'
 query(item,'INSERT INTO auth_profile_store VALUES (?,?,?)',('primary',json.dumps(value,separators=(',',':')),1700000000001))
 query(item,'INSERT INTO auth_profile_state VALUES (?,?,?)',('primary',json.dumps(STATE,separators=(',',':')),1700000000002))
 if checkpoint_control:
  need(query(item,'PRAGMA wal_checkpoint(TRUNCATE)',fetch='one')==(0,0,0),'synthetic_checkpoint_control_completed')
  query(item,'UPDATE auth_profile_store SET store_json=? WHERE store_key=?',(json.dumps(store(),separators=(',',':')),'primary'))
 return item
def close_streams(child):
 for stream in (child.stdin,child.stdout,child.stderr):
  if stream is not None and not stream.closed:stream.close()
def record(label,child,out,err):
 close_streams(child);need(len(out)<=65536 and len(err)<=65536,'bounded_wal_worker_output')
 private(ROOT/'output'/(label+'.stdout.public.json'),out);private(ROOT/'output'/(label+'.stderr.private'),err)
 report['children'].append({'label':label,'exitCode':child.returncode,'stdoutBytes':len(out),
  'stderrBytes':len(err),'stdoutSha256':sha(out),'streamsClosed':True})
 need(child.returncode==0 and not err,'actual_wal_child_complete_zero')
def run_phase(mode,environment):
 need(mode in PHASES and mode not in [x['mode'] for x in report['phases']],'one_original_wal_phase')
 policy=ROOT/('write.sb' if mode=='write-held' else 'read.sb')
 child=subprocess.Popen(['/usr/bin/sandbox-exec','-f',str(policy),NODE,'--no-warnings',
   str(ROOT/'code/mac_wal_keeper_sdk_worker_r1.mjs'),mode,str(int(remaining(8)*1000))],
   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=environment)
 children.append(child);out,err=child.communicate(timeout=remaining(8));record(mode,child,out,err)
 value=json.loads(out);report['phases'].append(value)
 need(value.get('ok') is True and value.get('mode')==mode and value.get('actualInstalledSdk') is True
  and value.get('syntheticCredentialsOnly') is True and value.get('kernelProtectedFileAndNetworkRefusalsObserved') is True
  and value.get('installedGuardsRestored') is True
  and value.get('sqliteScope',{}).get('allReturnedOriginalHandlesClosedOnce') is True
  and value.get('recordedSourceAndResponseFds',{}).get('allReturnedDescriptorsClosedOnce') is True
  and all(value.get(k)==0 for k in ('productionReads','productionWrites','providerCalls','serviceMutations','childAttempts','networkAttempts')),
  'actual_original_sdk_wal_phase_complete')
 if mode in ('read-held','write-held','read-committed'):need(value.get('readOutcome')=='complete','held_keeper_permits_actual_sdk_read')
 else:need(value.get('readOutcome') in ('complete','known-readonly-refusal'),'bounded_cold_or_retired_keeper_observation')
 if mode=='write-held':need(value.get('actualRawCasCommitted') is True and value.get('syntheticResponseFsyncedBeforeCas') is True,'single_original_raw_cas_known')
 return value
try:
 os.umask(0o077)
 need(sys.platform=='darwin' and os.getuid()==501 and os.path.realpath(sys.executable)==PYTHON,'exact_mac_wal_lifecycle_runtime')
 authority=PAYLOAD['custodyQualificationAuthority']
 need(authority['job_id']=='1a1b141ef40-fc05-7750' and authority['state']=='succeeded' and authority['exit_code']==0
   and all(authority[k] is True for k in ('output_complete','output_durable','terminal_publication_confirmed'))
   and all(authority[k] is False for k in ('timed_out','cancelled','automatic_retry')),'original_custody_qualification_authority')
 q=read(QUAL/'result.public.json',65536)
 need(len(q)==58701 and sha(q)=='67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e','same_original_custody_qualification')
 proof=json.loads(q)
 need(proof['ok'] and proof['allCasesMatched'] and proof['allOwnedClosed']
   and proof['custody']['passed_process_custody'] and proof['custody']['original_count']==18,'complete_original_18_custody_cases')
 need(tuple(PAYLOAD['sources'])==SOURCE_NAMES and set(PAYLOAD['sourcePins'])==set(SOURCE_NAMES),'exact_two_prepared_wal_sources')
 fence();home=ROOT.parent.lstat()
 need(stat.S_ISDIR(home.st_mode) and home.st_uid==501 and not stat.S_IMODE(home.st_mode)&0o022,'owned_mac_home_parent')
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 for name in ('code','output','output/tmp','output/tmp/openclaw-501','output/state','output/state/initial','output/responses','output/fixtures'):
  (ROOT/name).mkdir(mode=0o700,exist_ok=False)
 for which in ('cold','held'):
  for tail in ('','/agents','/agents/main','/agents/main/agent'):(ROOT/('output/fixtures/'+which+tail)).mkdir(mode=0o700,exist_ok=False)
 private(ROOT/'protected-read',b'synthetic kernel read refusal probe\n');private(ROOT/'protected-write',b'synthetic kernel write refusal probe\n')
 private(ROOT/'output/config.json',b'{"synthetic":"wal-lifecycle-only"}\n')
 for name,raw in PAYLOAD['sources'].items():
  need(sha(raw.encode())==PAYLOAD['sourcePins'][name],'prepared_wal_source_pin');private(ROOT/'code'/name,raw)
 private(ROOT/'plan.public.json',json.dumps({'schema':'heptabao.synthetic-wal-keeper-plan.r1','sharedSeconds':45,
  'supervisorSeconds':70,'originalChildren':7,'originalPythonSqliteConnections':4,'phases':PHASES,
  'sourcePins':PAYLOAD['sourcePins'],'sdkPins':PAYLOAD['sdkPins'],'onlySyntheticPaths':True,
  'productionReadAuthorized':False,'productionMutationAuthorized':False,'providerCallAuthorized':False},sort_keys=True).encode()+b'\n')
 lines=['(version 1)','(deny default)','(allow process*)','(allow signal (target children))',
   '(allow sysctl-read)','(allow mach-lookup)','(allow file-read-metadata)']
 for name in ('/System','/usr','/bin','/sbin','/Library','/private/etc','/opt/homebrew','/dev/fd'):
  lines.append('(allow file-read* (subpath '+json.dumps(name)+'))')
 for name in (ROOT/'code',ROOT/'output'):lines.append('(allow file-read* (subpath '+json.dumps(str(name))+'))')
 for name in [ROOT,*ROOT.parents]:lines.append('(allow file-read* (literal '+json.dumps(str(name))+'))')
 for name in ('/dev/null','/dev/urandom','/dev/random'):lines.append('(allow file-read* (literal '+json.dumps(name)+'))')
 lines.extend(['(allow file-write* (subpath '+json.dumps(str(ROOT/'output/tmp'))+'))','(allow file-write* (literal "/dev/null"))'])
 read_policy='\n'.join(lines)+'\n';private(ROOT/'read.sb',read_policy)
 write_policy=read_policy+'(allow file-write* (subpath '+json.dumps(str(database('held').parent))+'))\n'+\
  '(allow file-write* (subpath '+json.dumps(str(ROOT/'output/responses'))+'))\n';private(ROOT/'write.sb',write_policy)
 environment={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/Users/qianqi','NODE_NO_WARNINGS':'1',
  'TMPDIR':str(ROOT/'output/tmp'),'OPENCLAW_STATE_DIR':str(ROOT/'output/state/initial'),
  'OPENCLAW_CONFIG_PATH':str(ROOT/'output/config.json'),'OPENCLAW_AUTH_STORE_READONLY':'1'}
 sys.path.insert(0,str(QUAL/'qa'));import kv2_dr_process_custody as custody
 original_popen=subprocess.Popen;original_killpg=os.killpg
 with custody.activated() as owner:
  for number,name in enumerate(SOURCE_NAMES):
   child=subprocess.Popen([NODE,'--check',str(ROOT/'code'/name)],stdin=subprocess.DEVNULL,
     stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=environment)
   children.append(child);out,err=child.communicate(timeout=remaining(4));record('syntax-'+str(number),child,out,err)
  cold=setup('cold');close_sql(cold)
  cold_before=namespace('cold','cold-original-rw-closed')
  need(cold_before['wal'] is None and cold_before['shm'] is None,'actual_cold_fixture_has_no_sidecars')
  cold_result=run_phase('read-cold',environment)
  need(namespace('cold','cold-read-complete',cold_before)==cold_before,'cold_read_did_not_mutate_namespace')
  original=setup('held',True)
  first=namespace('held','original-rw-and-committed-wal')
  need(first['wal'] is not None and first['wal'][6]>32 and first['shm'] is not None,'actual_committed_wal_and_shm_exist')
  control=open_sql('held','checkpointed-main-control',True,True)
  try:
   value=query(control,'SELECT store_json FROM auth_profile_store WHERE store_key = ?',('primary',),'one')
   need(value is not None and json.loads(value[0])['profiles'][IDS[0]]['access']=='synthetic-access-checkpointed',
    'main_control_excludes_uncheckpointed_wal_commit')
  finally:close_sql(control)
  keeper=open_sql('held','readonly-keeper',True)
  original_snapshot=begin_keeper(keeper);before_close=namespace('held','keeper-transaction-established',first)
  close_sql(original);held=namespace('held','original-rw-closed-keeper-held',before_close)
  need(held['wal'] is not None and held['shm'] is not None and all(held[k][:6]==before_close[k][:6] for k in ('db','wal','shm')),
   'keeper_retains_exact_existing_sqlite_names')
  run_phase('read-held',environment)
  need(namespace('held','independent-sdk-read-before-cas',held)==held,'held_independent_read_preserved_full9')
  run_phase('write-held',environment);committed=namespace('held','original-sdk-cas-closed',held)
  need(all(committed[k] is not None and committed[k][:6]==held[k][:6] for k in ('db','wal','shm')),
   'original_cas_preserves_keeper_held_names')
  need(query(keeper,'SELECT store_json FROM auth_profile_store WHERE store_key = ?',('primary',),'one')==(original_snapshot,),
   'keeper_remains_old_snapshot_not_latest_source')
  report['keeperSnapshotStayedOldAfterKnownCommit']=True
  run_phase('read-committed',environment)
  need(namespace('held','independent-sdk-read-new-commit',committed)==committed,'new_commit_read_preserved_full9')
  close_sql(keeper);after_close=namespace('held','keeper-finally-closed-new-observation',committed)
  report['freshNamespaceAfterKeeperCloseObserved']=True
  retired=run_phase('read-after-close',environment)
  need(namespace('held','post-keeper-read-complete',after_close)==after_close,'post_keeper_read_preserved_full9')
 report['custody']=owner.receipt()
 need(report['custody']['passed_process_custody'] and report['custody']['original_count']==7
   and subprocess.Popen is original_popen and os.killpg is original_killpg,'seven_original_wal_children_closed')
 need(len(connections)==4 and all(x['row']['closed'] and x['row']['closeAttempts']==1 and not x['row']['transactionActive']
   and not x['row']['unknown'] and x['row']['cursorOpened']==x['row']['cursorClosed'] for x in connections),
   'four_original_parent_sqlite_connections_and_cursors_closed')
 for name,pin in PAYLOAD['sourcePins'].items():need(sha(read(ROOT/'code'/name))==pin,'owned_wal_source_unchanged')
 fence();remaining()
 report.update(ok=True,actualKeeperLifecycleObserved=True,heldKeeperAllowsIndependentActualSdkReadAndCas=True,
  coldReadonlyOutcome=cold_result['readOutcome'],afterKeeperCloseReadonlyOutcome=retired['readOutcome'],
  allOriginalConnectionsAndChildrenClosed=True,sourcePins=PAYLOAD['sourcePins'],sdkSourcePins=PAYLOAD['sdkPins'],
  runtimePins=RUNTIME_PINS,pythonSqliteVersion=sqlite3.sqlite_version,
  sandboxProfileSha256={'read':sha(read_policy.encode()),'write':sha(write_policy.encode())},
  nextProductionCaptureStillRequiresFreshGeneration=True,dynamicLibraryDependencyClosureClaimed=False)
except BaseException as error:
 report['errorCode']=str(error) if str(error) in error_codes else 'wal_lifecycle_qualification_refused'
 report['errorType']=type(error).__name__
finally:
 for item in reversed(connections):
  if not item['row']['closeAttempts']:
   try:close_sql(item)
   except BaseException:report['ok']=False;report['parentSqliteCleanupUnknown']=True
 for child in children:close_streams(child)
 if owner is not None:report['custody']=owner.receipt()
 report['parentSqliteConnections']=[x['row'] for x in connections]
 report['allOriginalParentSqliteConnectionsClosed']=all(x['row']['closed'] and x['row']['closeAttempts']==1
  and not x['row']['transactionActive'] and not x['row']['unknown'] and x['row']['cursorOpened']==x['row']['cursorClosed'] for x in connections)
 if not report['allOriginalParentSqliteConnectionsClosed']:report['ok']=False
 report['elapsedSeconds']=round(time.monotonic()-START,6)
 if created:
  try:
   private(ROOT/'output/namespace-generations.private.json',json.dumps(namespace_records,sort_keys=True).encode()+b'\n')
   private(ROOT/'result.public.json',json.dumps(report,sort_keys=True).encode()+b'\n')
  except BaseException:report['ok']=False;report['resultPublicationFailed']=True
 print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['ok'] else 1)
