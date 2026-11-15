#!/usr/bin/env python3
"""Independent read-only absence proof after the completed API r5 owned retirement."""
import ast,ctypes,errno,hashlib,json,os,re,stat,subprocess,sys,time
from pathlib import Path
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-api-20261106-r5')
LABEL='org.heptabao.qa.mac-authbus-main3-api-20261106-r5.server'
TARGET='gui/501/'+LABEL
FINAL=Path('/Users/qianqi/heptabao-mac-authbus-main3-api-journal-20261106-r5/210-final-result.public.json')
FINAL_SHA='4fa236165be77911efa02d998db32b55f5d593dfc65f52940feeaacaa32d3d30'
OBSERVER_SHA='cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b'
EXPECTED=[{"birthSec":1793990786,"birthUsec":686367,"executable":"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-api-20261106-r5/bin/heptabao-server","pgid":30336,"pid":30336,"ppid":1,"uid":501},{"birthSec":1793990794,"birthUsec":798133,"executable":"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-api-20261106-r5/bin/heptabao-server","pgid":30658,"pid":30658,"ppid":1,"uid":501}]
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
report={'schema':'heptabao.mac-main3-api-r5-independent-absence.r1','ok':False,
 'target':TARGET,'expectedCompletedCampaignRetiredLifetimes':EXPECTED,'finalResultSha256':FINAL_SHA,'rounds':[],
 'serviceMutationDispatched':False,'processArgumentsRead':False,'credentialValuesOrDigestsIncluded':False,
 'genericSystemScopeServiceStatusUsedAsGuiProof':False,'hostileEscapedDescendantContainmentClaimed':False}
try:
 need(sys.platform=='darwin' and os.geteuid()==501,'exact_mac_owner')
 final=json.loads(read(FINAL,FINAL_SHA,131072))['value']
 need(final['ok'] is True and final['closuresKnown'] and final['manager']['allRegistrationsClosed']
  and final['manager']['allKnownLineagesClosed'] and final['manager']['failureCleanupAttempted'] is False
  and final['commands']['unknownCommandCount']==0 and len(final['manager']['registrations'])==2
  and final['providerValid'] is False and final['productionTrafficCutover'] is False,
  'original_completed_campaign_owned_retirement_known_closed')
 for entry in final['manager']['registrations']:
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
   'completed_lifetimes_pid_group_direct_children_absent')
 need(time.monotonic()<UNTIL,'original_observation_deadline')
 report['ok']=True
except Refused as error:report['errorCode']=str(error)
except BaseException as error:report['errorType']=type(error).__name__
report['elapsedSeconds']=time.monotonic()-START
print(json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report['ok'] else 1)
