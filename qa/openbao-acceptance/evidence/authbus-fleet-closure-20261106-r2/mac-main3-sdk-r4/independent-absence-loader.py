#!/usr/bin/env python3
"""Independent read-only absence proof after both successful SDK r4 owned lifetimes retired."""
import ast,ctypes,errno,hashlib,json,os,re,stat,subprocess,sys,time
from pathlib import Path
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r4')
LABEL='org.heptabao.qa.mac-authbus-main3-sdk-20261106-r4.server'
TARGET='gui/501/'+LABEL
FINAL=Path('/Users/qianqi/heptabao-mac-authbus-main3-sdk-journal-20261106-r4/103-final-result.public.json')
FINAL_SHA='e3473d2a1bde64a2ce2a92dc53b1da11905772e0925af1a71f3602165993f2bc'
OBSERVER_SHA='cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b'
EXPECTED=[{"birthSec":1793999946,"birthUsec":587861,"executable":"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r4/bin/heptabao-server","pgid":92011,"pid":92011,"ppid":1,"uid":501},{"birthSec":1793999956,"birthUsec":270309,"executable":"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r4/bin/heptabao-server","pgid":92351,"pid":92351,"ppid":1,"uid":501}]
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
report={'schema':'heptabao.mac-main3-sdk-r4-independent-absence.r1','ok':False,
 'target':TARGET,'expectedSuccessfulCampaignRetiredLifetimes':EXPECTED,'finalResultSha256':FINAL_SHA,'rounds':[],
 'serviceMutationDispatched':False,'processArgumentsRead':False,'credentialValuesOrDigestsIncluded':False,
 'genericSystemScopeServiceStatusUsedAsGuiProof':False,'hostileEscapedDescendantContainmentClaimed':False}
try:
 need(sys.platform=='darwin' and os.geteuid()==501,'exact_mac_owner')
 final=json.loads(read(FINAL,FINAL_SHA,131072))['value']
 need(final['ok'] is True and final['actualPluginSdkQualified'] is True and final['actualPluginSdkPhaseExecuted'] is True
  and final['closuresKnown'] and final['manager']['allRegistrationsClosed']
  and final['manager']['allKnownLineagesClosed'] and final['manager']['failureCleanupAttempted'] is False
  and final['commands']['completeCommandCount']==67 and final['commands']['unknownCommandCount']==0
  and len(final['manager']['registrations'])==2,'original_successful_campaign_owned_cleanup_known_closed')
 need([e['execIdentity'] for e in final['manager']['registrations']]==EXPECTED,'exact_completed_lifetimes')
 for entry in final['manager']['registrations']:
  need(set(entry['attempts'])=={'bootstrap','kill','bootout'} and all(
   x['attempted'] is True and x['complete'] is True and x['exitCode']==0
   and x['command']['outcomeUnknown'] is False for x in entry['attempts'].values()),
   'original_once_bootstrap_kill_bootout_known_zero')
 need([p['phase'] for p in final['phases']]==['initial','cold-new-process']
  and [len(p['checks']) for p in final['phases']]==[32,20]
  and all(c['passed'] is True for p in final['phases'] for c in p['checks']),
  'original_two_api_phases_checks_passed')
 need([len(p['sdkChildren']) for p in final['phases']]==[1,1]
  and [len(p['sdkChildren'][0]['checks']) for p in final['phases']]==[56,109]
  and all(c['passed'] is True for p in final['phases'] for c in p['sdkChildren'][0]['checks']),
  'original_two_actual_sdk_phases_checks_passed')
 need(final['phases'][1]['sdkChildren'][0]['inverseCompleted'] is True
  and final['phases'][1]['sdkChildren'][0]['inverseRetried'] is False
  and all(final[k] is False for k in ('providerValid','providerCalled','providerRefreshAttempted',
   'productionChanged','productionClientRollbackQualified','productionTrafficCutover','wholeProductionDatabaseRollback')),
  'original_isolated_inverse_and_claim_boundaries')
 CHILD_RESULT_PINS=[{"path":"/Users/qianqi/heptabao-mac-authbus-main3-sdk-journal-20261106-r4/009-sdk-child-result.public.json","sha256":"3bfa517083a7c2d90905529e98844e90a48c6cb2a064d51edebfdb5965c93835"},{"path":"/Users/qianqi/heptabao-mac-authbus-main3-sdk-journal-20261106-r4/045-sdk-child-result.public.json","sha256":"ea98ffe15edfa3619e0051b1094665b11f7d95202833e55867d7c8f2ff6b2489"},{"path":"/Users/qianqi/heptabao-mac-authbus-main3-sdk-journal-20261106-r4/075-sdk-child-result.public.json","sha256":"f8221587a2d121766a9d31588d67246eae1f65e5bbbdc30c7532c503d521b881"}]
 child_pids=[];child_rows=[]
 for pin in CHILD_RESULT_PINS:
  command=json.loads(read(Path(pin['path']),pin['sha256'],65536))['value']['command']
  need(type(command['pid']) is int and command['pid']>1 and command['exitCode']==0
   and command['completeBeforeDeadline'] is True and command['outcomeUnknown'] is False
   and command['streamsClosed'] is True,'original_node_child_known_zero_closed')
  need(command['cleanup']['ok'] and command['cleanup']['directChildReaped']
   and command['cleanup']['allGroupRowsEmptyAfterReap'] and not command['cleanup']['signals'],
   'original_node_child_wait_group_and_no_signal_closure')
  child_pids.append(command['pid'])
  child_rows.append({'pid':command['pid'],'originalExitCode':0,'originalWaitAndGroupClosureKnown':True,
   'originalResultPublicSha256':pin['sha256']})
 need(len(set(child_pids))==3 and not(set(child_pids)&{e['pid'] for e in EXPECTED}),'distinct_completed_node_children')
 report['originalNodeChildren']=child_rows
 report['originalObservedApiChecks']=52;report['originalObservedSdkChecks']=165
 report['originalObservedApiHttpResponses']=34;report['originalObservedSdkHttpResponses']=21
 report['providerValid']=False;report['productionClientRollbackQualified']=False
 raw=read(ROOT/'qa/mac_native_process_observer_r1.py',OBSERVER_SHA,65536)
 names={'ObservationRefused','require','BsdInfo','ProcessReader'}
 nodes=[n for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
 need(len(nodes)==4 and {n.name for n in nodes}==names,'exact_pinned_observer_definitions')
 ns={'ctypes':ctypes,'Path':Path,'sys':sys}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pinned-absence-observer>','exec'),ns)
 reader=ns['ProcessReader']();Bsd=ns['BsdInfo'];pids={r['pid'] for r in EXPECTED}|set(child_pids)
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
   'completed_lifetimes_pid_group_direct_children_absent')

 need(time.monotonic()<UNTIL,'original_observation_deadline')
 report['ok']=True
except Refused as error:report['errorCode']=str(error)
except BaseException as error:report['errorType']=type(error).__name__
report['elapsedSeconds']=time.monotonic()-START
print(json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report['ok'] else 1)
