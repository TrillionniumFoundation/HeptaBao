#!/usr/bin/env python3
"""One actual Mac pre-bootstrap/registration qualification; no server or provider."""
import hashlib,json,os,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Users/qianqi/heptabao-authbus-gateway-registration-qualification-20261106-r2')
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
report={'schema':'heptabao.actual-sdk-gateway-selectors-registration-owned.r2','ok':False,
 'sharedSeconds':45,'supervisorSeconds':70,'automaticRetry':False,'providerCalls':0,
 'productionCredentialReads':0,'productionWrites':0,'productionMutexAcquired':False,
 'nativeServiceStarted':False,'syntheticStateOnly':True,'actualOriginalSelectorAndRegistrationFunctions':True,'productionGatewayMemoryQualified':False,
 'originalOuterChildrenExpected':3,'children':[],
 'candidateCommit':'4bde9aee03fcd27c59e13607e529b1cee594b249'}
owner=None;created=False;children=[];error_codes=set()
def need(value,code):
 if not value:error_codes.add(code);raise RuntimeError(code)
def remaining(cap=45):
 value=UNTIL-time.monotonic();need(value>0,'original_fallback_sdk_qualification_deadline');return min(cap,value)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def ident(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,cap=1048576):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid in (0,501)
    and not stat.S_IMODE(s.st_mode)&0o022 and 0<=s.st_size<=cap,'bounded_public_fallback_sdk_source')
  out=bytearray()
  while len(out)<=cap:
   remaining();part=os.read(fd,min(65536,cap+1-len(out)))
   if not part:break
   out.extend(part)
  need(len(out)==s.st_size and ident(s)==ident(os.fstat(fd))==ident(Path(path).lstat()),'stable_public_fallback_sdk_source')
  return bytes(out)
 finally:os.close(fd)
def private(path,data):
 raw=data if isinstance(data,bytes) else data.encode();need(len(raw)<=262144,'bounded_owned_fallback_sdk_artifact')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:
   remaining();n=os.write(fd,view);need(n>0,'owned_fallback_sdk_write_progress');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def fence():
 for name,pin in CUSTODY_PINS.items():need(sha(read(QUAL/'qa'/name))==pin,'qualified_custody_source_unchanged')
 for path,pin in RUNTIME_PINS.items():need(sha(read(Path(path),2*1048576))==pin,'qualified_fallback_sdk_runtime_unchanged')
 for name,pin in PAYLOAD['sdkPins'].items():need(sha(read(SDK/name))==pin,'qualified_registration_sdk_source_unchanged')
 for name,pin in PAYLOAD['publicPluginPins'].items():need(sha(read(Path('/Users/qianqi/.openclaw/extensions/openclaw-authbus')/name))==pin,'qualified_public_authbus_source_unchanged')
def close_streams(child):
 for stream in (child.stdin,child.stdout,child.stderr):
  if stream is not None and not stream.closed:stream.close()
def record(label,child,out,err):
 close_streams(child)
 need(len(out)<=65536 and len(err)<=65536,'bounded_fallback_sdk_worker_output')
 private(ROOT/'output'/(label+'.stdout.public.json'),out)
 private(ROOT/'output'/(label+'.stderr.private'),err)
 report['children'].append({'label':label,'exitCode':child.returncode,'stdoutBytes':len(out),
   'stderrBytes':len(err),'stdoutSha256':sha(out),'streamsClosed':True})
 need(child.returncode==0 and not err,'actual_fallback_sdk_child_complete_zero')
try:
 os.umask(0o077)
 need(sys.platform=='darwin' and os.getuid()==501 and os.path.realpath(sys.executable)==PYTHON,'exact_mac_fallback_sdk_runtime')
 authority=PAYLOAD['custodyQualificationAuthority']
 need(authority['job_id']=='1a1b141ef40-fc05-7750' and authority['state']=='succeeded' and authority['exit_code']==0
   and all(authority[k] is True for k in ('output_complete','output_durable','terminal_publication_confirmed'))
   and all(authority[k] is False for k in ('timed_out','cancelled','automatic_retry')),'original_custody_qualification_authority')
 q=read(QUAL/'result.public.json',65536)
 need(len(q)==58701 and sha(q)=='67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e','same_original_custody_qualification')
 proof=json.loads(q)
 need(proof['ok'] and proof['allCasesMatched'] and proof['allOwnedClosed']
   and proof['custody']['passed_process_custody'] and proof['custody']['original_count']==18,'complete_original_18_custody_cases')
 fence();home=ROOT.parent.lstat()
 need(stat.S_ISDIR(home.st_mode) and home.st_uid==501 and not stat.S_IMODE(home.st_mode)&0o022,'owned_mac_home_parent')
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 for name in ('code','code/disabled-authbus','code/control','output','output/tmp','output/tmp/openclaw-501',
   'output/home','output/home/.openclaw','output/home/.openclaw/state','output/home/.openclaw/oauth','output/home/.config','output/home/.config/openclaw',
   'output/maintenance','output/workspace','output/logs','output/decoy-state'):
  (ROOT/name).mkdir(mode=0o700,exist_ok=False)
 private(ROOT/'protected-read',b'synthetic kernel read refusal probe\n')
 private(ROOT/'protected-write',b'synthetic kernel write refusal probe\n')
 need(set(PAYLOAD['sources'])=={'mac_gateway_registration_cases_r2.mjs','mac_gateway_registration_qualification_r2.mjs'},'exact_two_registration_sources')
 fixture_pins={}
 for name,raw in PAYLOAD['sources'].items():
  need(sha(raw.encode())==PAYLOAD['sourcePins'][name],'prepared_gateway_registration_source_pin')
  private(ROOT/'code'/name,raw);fixture_pins['code/'+name]=sha(raw.encode())
 for name,raw in PAYLOAD['authbusPublicFiles'].items():
  need(name in ('index.js','package.json','openclaw.plugin.json') and sha(raw.encode())==PAYLOAD['publicPluginPins'][name],
   'exact_public_disabled_authbus_copy')
  private(ROOT/'code/disabled-authbus'/name,raw);fixture_pins['code/disabled-authbus/'+name]=sha(raw.encode())
 for name,raw in PAYLOAD['controlFiles'].items():
  need(name in ('index.cjs','package.json','openclaw.plugin.json'),'fixed_positive_control_file')
  private(ROOT/'code/control'/name,raw);fixture_pins['code/control/'+name]=sha(raw.encode())
 for name,raw in PAYLOAD['syntheticInputs'].items():
  need(name in ('output/maintenance/fallback.json','output/home/.openclaw/openclaw.json','output/decoy-state/openclaw.json',
    'output/home/.openclaw/.env','output/home/.config/openclaw/gateway.env'),'fixed_synthetic_selector_inputs')
  private(ROOT/name,raw);fixture_pins[name]=sha(raw.encode())
 plan={'schema':'heptabao.gateway-selectors-registration.synthetic-plan.r2','sharedSeconds':45,'supervisorSeconds':70,
  'originalOuterChildren':3,'expectedCases':15,'sourcePins':PAYLOAD['sourcePins'],'sdkPins':PAYLOAD['sdkPins'],
  'fixturePins':fixture_pins,'productionReadAuthorized':False,'productionMutationAuthorized':False,
  'providerCallAuthorized':False,'productionMutexAcquisitionAuthorized':False,
  'fixedReadonlyMountMaximum':8,'fixedReadonlyMountSeconds':3,'fixedReadonlyMountOutputBytes':262144}
 private(ROOT/'code/plan.public.json',json.dumps(plan,sort_keys=True).encode()+b'\n')
 lines=['(version 1)','(deny default)','(allow process*)','(allow signal (target children))',
   '(allow sysctl-read)','(allow mach-lookup)','(allow file-read-metadata)']
 for name in ('/System','/usr','/bin','/sbin','/Library','/private/etc','/opt/homebrew','/dev/fd'):
  lines.append('(allow file-read* (subpath '+json.dumps(name)+'))')
 for name in (ROOT/'code',ROOT/'output'):lines.append('(allow file-read* (subpath '+json.dumps(str(name))+'))')
 for name in [ROOT,*ROOT.parents]:lines.append('(allow file-read* (literal '+json.dumps(str(name))+'))')
 for name in ('/dev/null','/dev/urandom','/dev/random'):lines.append('(allow file-read* (literal '+json.dumps(name)+'))')
 lines.extend(['(allow file-write* (subpath '+json.dumps(str(ROOT/'output'))+'))','(allow file-write* (literal "/dev/null"))'])
 policy='\n'.join(lines)+'\n';private(ROOT/'fixture.sb',policy)
 environment={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(ROOT/'output/home'),'NODE_NO_WARNINGS':'1',
  'TMPDIR':str(ROOT/'output/tmp'),'OPENCLAW_STATE_DIR':str(ROOT/'output/home/.openclaw'),
  'OPENCLAW_CONFIG_PATH':str(ROOT/'output/maintenance/fallback.json'),'OPENCLAW_OAUTH_DIR':str(ROOT/'output/home/.openclaw/oauth'),
  'OPENCLAW_AUTH_STORE_READONLY':'1','OPENCLAW_SERVICE_MARKER':'heptabao-isolated-qualification'}
 sys.path.insert(0,str(QUAL/'qa'));import kv2_dr_process_custody as custody
 original_popen=subprocess.Popen;original_killpg=os.killpg
 with custody.activated() as owner:
  for number,name in enumerate(PAYLOAD['sources']):
   child=subprocess.Popen([NODE,'--check',str(ROOT/'code'/name)],stdin=subprocess.DEVNULL,
     stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=environment)
   children.append(child);out,err=child.communicate(timeout=remaining(5));record('syntax-'+str(number),child,out,err)
  child=subprocess.Popen(['/usr/bin/sandbox-exec','-f',str(ROOT/'fixture.sb'),NODE,'--no-warnings',
    str(ROOT/'code/mac_gateway_registration_qualification_r2.mjs'),str(int(remaining(30)*1000))],
    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=environment)
  children.append(child);out,err=child.communicate(timeout=remaining(30))
  value=json.loads(out);report['unitResult']=value;record('unit',child,out,err)
  need(value.get('ok') is True and value.get('actualInstalledSdk') is True
    and value.get('executed')==15 and value.get('passed')==15 and len(value.get('cases',[]))==15
    and all(row.get('passed') is True for row in value['cases'])
    and value.get('kernelReadWriteAndBothNetworkRefusalsObserved') is True
    and value.get('allRecordedFileDescriptorsClosedOnce') is True
    and value.get('allInstalledGuardsRestored') is True and value.get('originalModuleHookDeregistered') is True
    and value.get('actualStateAndGatewayDotenvReadsObserved') is True
    and value.get('previousEmptyDisabledConfigRejectedByOriginalValidator') is True
    and value.get('actualPreBootstrapFinalFallbackSelected') is True
    and value.get('actualNormalGatewayRegistrationFunctionQualified') is True
    and value.get('actualIsolatedActiveRegistryQualified') is True
    and value.get('actualProductionGatewayMemoryQualified') is False
    and value.get('productionFallbackConfigurationQualified') is False
    and value.get('fullGatewayServerStarted') is False
    and value.get('allowedReadonlyMountCalls')==value.get('completedReadonlyMountCalls')
    and 0<=value.get('allowedReadonlyMountCalls',-1)<=8
    and value.get('sqlite',{}).get('allOriginalHandlesClosedOnce') is True
    and value.get('sqlite',{}).get('denials')==0
    and all(value.get(key)==0 for key in ('providerCalls','productionWrites','productionCredentialReads',
      'forbiddenChildAttempts','forbiddenNetworkAttempts','forbiddenProductionReadAttempts',
      'forbiddenWriteAttempts','authbusModuleLoadAttempts','serviceMutations')),
    'actual_original_selector_and_registration_fifteen_cases_passed')
 report['custody']=owner.receipt()
 need(report['custody']['passed_process_custody'] and report['custody']['original_count']==3
   and subprocess.Popen is original_popen and os.killpg is original_killpg,'three_original_registration_outer_children_closed')
 for name,pin in PAYLOAD['sourcePins'].items():need(sha(read(ROOT/'code'/name))==pin,'owned_fallback_sdk_source_unchanged')
 fence();remaining()
 report.update(ok=True,caseCount=15,allOriginalChildrenClosed=True,sourcePins=PAYLOAD['sourcePins'],
   sdkSourcePins=PAYLOAD['sdkPins'],runtimePins=RUNTIME_PINS,sandboxProfileSha256=sha(policy.encode()),
   actualOriginalPreBootstrapAndRegistrationQualified=True,fullProductionGatewayQualified=False,
   runningProductionGatewayMemoryFlagsProven=False,productionRefreshControllerQualified=False,dynamicLibraryDependencyClosureClaimed=False)
except BaseException as error:
 report['errorCode']=str(error) if str(error) in error_codes else 'fallback_sdk_qualification_refused'
 report['errorType']=type(error).__name__
finally:
 for child in children:close_streams(child)
 if owner is not None:report['custody']=owner.receipt()
 report['elapsedSeconds']=round(time.monotonic()-START,6)
 if created:
  try:private(ROOT/'result.public.json',json.dumps(report,sort_keys=True).encode()+b'\n')
  except BaseException:report['ok']=False;report['resultPublicationFailed']=True
 print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['ok'] else 1)
