#!/usr/bin/env python3
"""Independent read-only absence proof after the failed SDK r2 owned cleanup."""
import ast,ctypes,errno,hashlib,json,os,re,stat,subprocess,sys,time
from pathlib import Path
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r2')
LABEL='org.heptabao.qa.mac-authbus-main3-sdk-20261106-r2.server'
TARGET='gui/501/'+LABEL
FINAL=Path('/Users/qianqi/heptabao-mac-authbus-main3-sdk-journal-20261106-r2/057-final-result.public.json')
FINAL_SHA='0fc7095c486f05f7dfafb058234f4483f2e0b126e13e91c9231b904216a15f08'
OBSERVER_SHA='cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b'
EXPECTED=[{"birthSec":1793994246,"birthUsec":257828,"executable":"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r2/bin/heptabao-server","pgid":54169,"pid":54169,"ppid":1,"uid":501}]
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
report={'schema':'heptabao.mac-main3-sdk-r2-independent-absence.r1','ok':False,
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

 original_worker=json.loads(read(Path("/Users/qianqi/heptabao-mac-authbus-main3-sdk-journal-20261106-r2/045-sdk-child-result.public.json"),"d551a258b168a17521c646512deb031633c377f9c45a36d85cbd4a2d404703d3",65536))['value']['command']
 need(original_worker['pid']==54346 and original_worker['exitCode']==65 and original_worker['completeBeforeDeadline'] is True and original_worker['outcomeUnknown'] is False and original_worker['streamsClosed'] is True and original_worker['stdoutBytes']==0 and original_worker['stderrBytes']==207,'original_worker_known_exit_and_exact_stream_counts')
 phase_raw=read(ROOT/'qa/main3_sdk_phase.py','2ae860ba7fbfef5c48254cd74f0800fcd5ddc341653a7965c1d31c889397a910',65536)
 profile_nodes=[n for n in ast.parse(phase_raw).body if isinstance(n,ast.FunctionDef) and n.name=='sandbox_profile']
 need(len(profile_nodes)==1,'one_source_bound_public_sandbox_function')
 profile_scope={'ROOT':ROOT,'STATE':ROOT/'state','LIVE':Path('/Users/qianqi/.openclaw'),'Path':Path,'json':json,'need':need}
 exec(compile(ast.Module(body=profile_nodes,type_ignores=[]),'<pinned-sdk-r2-profile>','exec'),profile_scope)
 profile=profile_scope['sandbox_profile'](63907)
 sb_path=ROOT/'initial/worker.sb'
 need(read(sb_path,hashlib.sha256(profile).hexdigest(),65536)==profile,'exact_original_worker_profile')
 streams={}
 for leaf,expected_size in [('sdk-initial.stdout.private.json',0),('sdk-initial.stderr.private',207)]:
  path=ROOT/'initial'/leaf
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   before=os.fstat(fd)
   need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and before.st_size==expected_size,'retained_private_stream_custody')
   data=os.read(fd,4097)
   need(len(data)==expected_size and not os.read(fd,1) and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'complete_unchanged_retained_private_stream')
   streams[leaf]=data
  finally:os.close(fd)
 stderr=streams['sdk-initial.stderr.private'].decode('utf-8','strict')
 public_lines=profile.decode().splitlines()
 mentioned=[]
 for ordinal,line in enumerate(public_lines,1):
  if line.strip() and any(line.strip()==candidate.strip() for candidate in stderr.splitlines()):
   mentioned.append(ordinal)
 coordinates=[]
 for match in re.finditer(re.escape(str(sb_path))+r':([0-9]{1,3})(?::([0-9]{1,3}))?',stderr):
  line=int(match.group(1));column=int(match.group(2)) if match.group(2) else None
  if 1<=line<=len(public_lines):coordinates.append({'line':line,'column':column})
 vocabulary={'sandbox','exec','error','failed','policy','compile','compilation','unbound','variable','remote','ip','unsupported','syntax','network-outbound','invalid','argument','type','unexpected','token','undefined','not','permitted','operation','host','port','literal','filter','element','denied','parameter','parse','format','address','regex','at','line','allow','value','version','expecting','expected','number','string','symbol'}
 words=[w.lower() for w in re.findall(r'[A-Za-z][A-Za-z-]*',stderr) if w.lower() in vocabulary]
 markers=('policy compilation failed','unbound variable','invalid argument','invalid network address','invalid IP address','syntax error','unexpected token','unknown filter','Operation not permitted','Permission denied')
 network_ordinals=[i for i,line in enumerate(public_lines,1) if 'network-outbound' in line]
 report['workerFailureProjection']={'originalChildPid':54346,'originalExitCode':65,'originalProcessOutcomeKnown':True,'originalStdoutBytes':0,'originalStderrBytes':207,'retainedPrivateStreamsIndependentlyMatchedSizes':True,'rawPrivateBytesOrDigestsPublished':False,'actualSdkBusinessOutcomeQualified':False,'profileSha256':hashlib.sha256(profile).hexdigest(),'profileLineCount':len(public_lines),'publicProfileLineOrdinalsMentionedVerbatim':mentioned,'publicProfileCoordinates':coordinates,'networkRulePublicLineOrdinals':network_ordinals,'fixedPublicWordsInOriginalOrder':words[:64],'fixedErrorMarkers':[m for m in markers if m.lower() in stderr.lower()],'sandboxExecPrefix':stderr.startswith('sandbox-exec:'),'kernelPermissionOrTccChanged':False}
 need(time.monotonic()<UNTIL,'original_observation_deadline')
 report['ok']=True
except Refused as error:report['errorCode']=str(error)
except BaseException as error:report['errorType']=type(error).__name__
report['elapsedSeconds']=time.monotonic()-START
print(json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report['ok'] else 1)
