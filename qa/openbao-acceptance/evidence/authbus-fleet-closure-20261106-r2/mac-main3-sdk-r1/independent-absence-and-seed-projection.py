#!/usr/bin/env python3
"""Independent read-only absence proof after the failed SDK r1 owned cleanup."""
import ast,ctypes,errno,hashlib,json,os,re,stat,subprocess,sys,time
from pathlib import Path
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r1')
LABEL='org.heptabao.qa.mac-authbus-main3-sdk-20261106-r1.server'
TARGET='gui/501/'+LABEL
FINAL=Path('/Users/qianqi/heptabao-mac-authbus-main3-sdk-journal-20261106-r1/021-final-result.public.json')
FINAL_SHA='31d9e3e2766dc26d31e9162ab58e85e62c8b7aec84acaa8e30708aac185942d6'
OBSERVER_SHA='cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b'
EXPECTED=[{"birthSec":1793991840,"birthUsec":435599,"executable":"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r1/bin/heptabao-server","pgid":38306,"pid":38306,"ppid":1,"uid":501}]
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
report={'schema':'heptabao.mac-main3-sdk-r1-independent-absence.r1','ok':False,
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
 original_seed=json.loads(read(Path("/Users/qianqi/heptabao-mac-authbus-main3-sdk-journal-20261106-r1/009-sdk-child-result.public.json"),"7f838c8a1405fe0a4992ac3da06851bb1a3737b58c442f74fee3ed9b536e3495",65536))['value']['command']
 need(original_seed['exitCode']==-6 and original_seed['completeBeforeDeadline'] is True and original_seed['outcomeUnknown'] is False and original_seed['streamsClosed'] is True and original_seed['stdoutBytes']==0 and original_seed['stderrBytes']==0,'original_seed_known_abort_and_zero_streams')
 for leaf in ('sdk-private-seed.stdout.private.json','sdk-private-seed.stderr.private'):
  path=ROOT/'initial'/leaf
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   before=os.fstat(fd)
   need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and before.st_size==0,'retained_zero_byte_private_stream')
   need(os.read(fd,1)==b'' and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'unchanged_empty_retained_private_stream')
  finally:os.close(fd)
 report['seedFailureProjection']={'originalChildPid':original_seed['pid'],'originalExitCode':-6,'originalOutcomeKnown':True,'originalStdoutBytes':0,'originalStderrBytes':0,'retainedPrivateFilesIndependentlyEmpty':True,'faultCauseIdentified':False,'privateBytesOrDigestsPublished':False}
 need(time.monotonic()<UNTIL,'original_observation_deadline')
 report['ok']=True
except Refused as error:report['errorCode']=str(error)
except BaseException as error:report['errorType']=type(error).__name__
report['elapsedSeconds']=time.monotonic()-START
print(json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report['ok'] else 1)
