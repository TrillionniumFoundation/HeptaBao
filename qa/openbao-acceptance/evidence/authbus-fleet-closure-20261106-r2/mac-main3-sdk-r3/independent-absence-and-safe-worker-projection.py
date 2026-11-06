#!/usr/bin/env python3
"""Independent read-only absence proof after the failed SDK r3 owned cleanup."""
import ast,ctypes,errno,hashlib,json,os,re,stat,subprocess,sys,time
from pathlib import Path
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r3')
LABEL='org.heptabao.qa.mac-authbus-main3-sdk-20261106-r3.server'
TARGET='gui/501/'+LABEL
FINAL=Path('/Users/qianqi/heptabao-mac-authbus-main3-sdk-journal-20261106-r3/057-final-result.public.json')
FINAL_SHA='5c25c6404f636fde10d26cbb64671c96b25a5d865ab7d063e8f592782af2a773'
OBSERVER_SHA='cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b'
EXPECTED=[{"birthSec":1793996777,"birthUsec":671639,"executable":"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r3/bin/heptabao-server","pgid":70272,"pid":70272,"ppid":1,"uid":501}]
START=time.monotonic();UNTIL=START+15
class Refused(RuntimeError):pass
def need(v,c):
 if not v:raise Refused(c)
def identity(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,sha,maximum):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd)
  need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
   and stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=maximum,'input_custody')
  raw=os.read(fd,maximum+1)
  need(len(raw)==before.st_size and not os.read(fd,1)
   and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'stable_complete_input')
  need(hashlib.sha256(raw).hexdigest()==sha,'pinned_complete_input')
  return raw
 finally:os.close(fd)
def call(argv):
 left=UNTIL-time.monotonic();need(left>0,'original_observation_deadline')
 p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
  timeout=min(4,left),check=False,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
 need(len(p.stdout)<=262144 and len(p.stderr)<=4096,'bounded_metadata_output')
 return p
report={'schema':'heptabao.mac-main3-sdk-r3-independent-absence.r1','ok':False,
 'target':TARGET,'expectedFailedCampaignRetiredLifetimes':EXPECTED,'finalResultSha256':FINAL_SHA,'rounds':[],
 'serviceMutationDispatched':False,'processArgumentsRead':False,'credentialValuesOrDigestsIncluded':False,
 'genericSystemScopeServiceStatusUsedAsGuiProof':False,'hostileEscapedDescendantContainmentClaimed':False}
try:
 need(sys.platform=='darwin' and os.geteuid()==501,'exact_mac_owner')
 final=json.loads(read(FINAL,FINAL_SHA,65536))['value']
 need(final['ok'] is False and final['errorCode']=='sdk_original_owned_child_known_zero'
  and final['closuresKnown'] and final['manager']['allRegistrationsClosed']
  and final['manager']['allKnownLineagesClosed'] and final['manager']['failureCleanupAttempted']
  and final['commands']['unknownCommandCount']==0 and len(final['manager']['registrations'])==1,
  'original_failed_campaign_owned_cleanup_known_closed')
 entry=final['manager']['registrations'][0]
 need(set(entry['attempts'])=={'bootstrap','kill','bootout'} and all(
  x['attempted'] is True and x['complete'] is True and x['exitCode']==0
  and x['command']['outcomeUnknown'] is False for x in entry['attempts'].values()),
  'original_once_bootstrap_kill_bootout_known_zero')
 need([e['execIdentity'] for e in final['manager']['registrations']]==EXPECTED,'exact_completed_lifetimes')
 raw=read(ROOT/'qa/mac_native_process_observer_r1.py',OBSERVER_SHA,65536)
 names={'ObservationRefused','require','BsdInfo','ProcessReader'}
 nodes=[n for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
 need(len(nodes)==4 and {n.name for n in nodes}==names,'exact_pinned_observer_definitions')
 ns={'ctypes':ctypes,'Path':Path,'sys':sys}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pinned-absence-observer>','exec'),ns)
 reader=ns['ProcessReader']();Bsd=ns['BsdInfo'];pids={r['pid'] for r in EXPECTED}
 for index in range(2):
  query=call(['/bin/launchctl','print',TARGET])
  expected='Could not find service "'+LABEL+'" in domain for user gui: 501'
  need(query.returncode in (3,113) and not query.stdout and query.stderr.decode().splitlines()
   in ([expected],['Bad request.',expected]),'exact_gui_label_absent')
  ps=call(['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat='])
  need(ps.returncode==0 and not ps.stderr,'complete_fixed_ps_metadata')
  related=[];count=0
  for line in ps.stdout.decode('ascii','strict').splitlines():
   fields=line.split();count+=1
   if not(len(fields)>=3 and all(v.isdecimal() and len(v)<=10 for v in fields[:3])):
    report['rejectedProcessMetadataRow']={'fields':[v[:64] for v in fields[:5]],'fieldCount':len(fields)}
    raise Refused('strict_process_selectors')
   if any(int(v) in pids for v in fields[:3]):related.append(fields[:5])
  native=[]
  for pid in sorted(pids):
   info=Bsd();ctypes.set_errno(0)
   size=reader.lib.proc_pidinfo(pid,3,0,ctypes.byref(info),ctypes.sizeof(info));error=ctypes.get_errno()
   native.append({'pid':pid,'returnedBytes':size,'errno':error})
  record={'index':index,'guiLabelAbsent':True,'guiQueryExitCode':query.returncode,
   'guiQueryExactStderr':query.stderr.decode(),'processMetadataRowsExamined':count,
   'relatedPidGroupOrDirectChildRows':related,'nativePidAbsence':native}
  report['rounds'].append(record)
  need(not related and all(r['returnedBytes']==0 and r['errno']==errno.ESRCH for r in native),
   'failed_lifetime_pid_group_direct_children_absent')

 original_worker=json.loads(read(Path('/Users/qianqi/heptabao-mac-authbus-main3-sdk-journal-20261106-r3/045-sdk-child-result.public.json'),'e0a625049461c1ae77b3d8b09925110b2811e5b9c71722b1ddce9e42da6352d8',65536))['value']['command']
 need(original_worker['pid']==70395 and original_worker['exitCode']==1 and original_worker['completeBeforeDeadline'] is True and original_worker['outcomeUnknown'] is False and original_worker['streamsClosed'] is True and original_worker['stdoutBytes']==3696 and original_worker['stderrBytes']==0,'original_worker_known_exit_and_exact_stream_counts')
 need(original_worker['cleanup']['ok'] and original_worker['cleanup']['directChildReaped'] and original_worker['cleanup']['allGroupRowsEmptyAfterReap'] and not original_worker['cleanup']['signals'],'original_worker_wait_group_and_signal_closure')
 worker_source=read(ROOT/'qa/main3_sdk_cycle_r2.mjs','be755ff0dfb7a833bf1c40a75f9c7dc68bc4c38ea12339b4af707f065e1abbe0',65536).decode('utf-8')
 wire_source=read(ROOT/'qa/main3_sdk_wire_r2.mjs','2b06342e30703611729788a522ba764ae30adfe1e47c4f4673b7aa8f647170e2',65536).decode('utf-8')
 public_codes=set(re.findall(r"""['"]([a-z][a-z0-9_.-]{1,120})['"]""",worker_source+'\n'+wire_source))
 streams={}
 for leaf,expected_size in [('sdk-initial.stdout.private.json',3696),('sdk-initial.stderr.private',0)]:
  path=ROOT/'initial'/leaf
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   before=os.fstat(fd)
   need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and before.st_size==expected_size,'retained_private_stream_custody')
   data=os.read(fd,65537)
   need(len(data)==expected_size and not os.read(fd,1) and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'complete_unchanged_retained_private_stream')
   streams[leaf]=data
  finally:os.close(fd)
 value=json.loads(streams['sdk-initial.stdout.private.json'])
 need(type(value) is dict and value.get('schema')=='heptabao.mac-main3-sdk-private-cycle.r2' and value.get('ok') is False,'original_worker_failed_result_shape')
 need(not streams['sdk-initial.stderr.private'],'original_worker_stderr_empty')
 projected={'originalChildPid':70395,'originalExitCode':1,'originalProcessOutcomeKnown':True,
  'originalStdoutBytes':3696,'originalStderrBytes':0,'retainedPrivateStreamsIndependentlyMatchedSizes':True,
  'rawPrivateBytesOrDigestsPublished':False,'actualSdkBusinessOutcomeQualified':False,
  'workerSourceSha256':'be755ff0dfb7a833bf1c40a75f9c7dc68bc4c38ea12339b4af707f065e1abbe0',
  'wireSourceSha256':'2b06342e30703611729788a522ba764ae30adfe1e47c4f4673b7aa8f647170e2'}
 for key in ('ok','outcomeUnknown','serviceStopAttempted','serviceStopped','candidateSaved','inverseMutationAttempted',
  'inverseCompleted','inverseRetried','privateTokenCustodyRecorded','networkHooksRestored',
  'connectionClosureFailed','originalAgentCacheClosureFailed','originalStateCacheClosureFailed',
  'actualGatewayRestarted','providerCalled','providerRefreshAttempted','providerValid','j3160Contacted',
  'productionChanged','productionTrafficCutover','credentialValuesOrDigestsPublished','profileIdsPublished'):
  if key in value:need(type(value[key]) is bool,'fixed_boolean_projection');projected[key]=value[key]
 for key in ('exactOwnedMountProbeCount','forbiddenChildAttemptCount','unexpectedDiagnosticBytes',
  'workerReadDescriptorsOpened','workerReadDescriptorsClosed','elapsedMs','originalStateCacheCloseInvocations'):
  if key in value:need(type(value[key]) is int and 0<=value[key]<=10000000,'fixed_count_projection');projected[key]=value[key]
 code=value.get('errorCode')
 projected['errorCodeIsPinnedSourceLiteral']=type(code) is str and code in public_codes
 projected['fixedErrorCode']=code if projected['errorCodeIsPinnedSourceLiteral'] else 'unprojected_error_code'
 projected['fixedErrorType']=value.get('errorType') if value.get('errorType') in ('Error','TypeError','RangeError','SyntaxError') else 'unprojected_error_type'
 projected['checks']=[]
 for item in value.get('checks',[]):
  need(type(item) is dict and type(item.get('passed')) is bool,'check_projection_shape')
  case=item.get('case');known=type(case) is str and case in public_codes
  projected['checks'].append({'case':case if known else 'unprojected_case','caseIsPinnedSourceLiteral':known,'passed':item['passed']})
 for key,allowed in {
  'sqlite':('attempts','opened','readOnly','writable','memory','denials','closed','allOriginalHandlesClosedOnce'),
  'connections':('ownedHttpsAgentClosed','remainingRequestCount','remainingSocketCount','otherNetworkDenials','allDispatchedResponsesComplete','unknownOutcomeCount','allObservedSocketsClosed'),
  'sdkCacheClose':('registered','invoked','closed','listenerRestored','originalCloseInvocations','observerRestored')
 }.items():
  if key not in value:continue
  item=value[key];need(type(item) is dict,'fixed_closure_projection_shape');projected[key]={}
  for name in allowed:
   if name not in item:continue
   data=item[name];need(type(data) is bool or type(data) is int and 0<=data<=10000000,'fixed_closure_scalar')
   projected[key][name]=data
 wire=value.get('wire',[])
 need(type(wire) is list and len(wire)<=192,'bounded_wire_row_count')
 projected['workerWireRowCount']=len(wire)
 projected['workerWireDispatchedCount']=sum(row.get('dispatched') is True for row in wire if type(row) is dict)
 projected['workerWireCompleteResponseCount']=sum(row.get('responseComplete') is True for row in wire if type(row) is dict)
 projected['workerWireUnknownCount']=sum(row.get('outcomeUnknown') is True for row in wire if type(row) is dict)
 report['workerFailureProjection']=projected
 need(time.monotonic()<UNTIL,'original_observation_deadline')
 report['ok']=True
except Refused as error:report['errorCode']=str(error)
except BaseException as error:report['errorType']=type(error).__name__
report['elapsedSeconds']=time.monotonic()-START
print(json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report['ok'] else 1)
