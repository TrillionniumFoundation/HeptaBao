#!/usr/bin/env python3
"""Read only fixed fields of the original failed SDK r3 private wire record."""
import hashlib,json,os,re,stat,sys,time
from pathlib import Path
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r3')
JOURNAL=Path('/Users/qianqi/heptabao-mac-authbus-main3-sdk-journal-20261106-r3')
FINAL_SHA='5c25c6404f636fde10d26cbb64671c96b25a5d865ab7d063e8f592782af2a773'
CHILD_SHA='e0a625049461c1ae77b3d8b09925110b2811e5b9c71722b1ddce9e42da6352d8'
WORKER_SHA='be755ff0dfb7a833bf1c40a75f9c7dc68bc4c38ea12339b4af707f065e1abbe0'
WIRE_SHA='2b06342e30703611729788a522ba764ae30adfe1e47c4f4673b7aa8f647170e2'
START=time.monotonic();UNTIL=START+15
COUNTS={'opened':0,'closed':0}
class Refused(RuntimeError):pass
def need(value,code):
 if not value:raise Refused(code)
def identity(s):
 return(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read_exact(path,maximum,sha=None,expected_size=None):
 need(time.monotonic()<UNTIL,'original_observation_deadline')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);COUNTS['opened']+=1
 try:
  before=os.fstat(fd)
  need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
   and stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=maximum,'input_file_custody')
  if expected_size is not None:need(before.st_size==expected_size,'original_exact_stream_size')
  raw=os.read(fd,maximum+1)
  need(len(raw)==before.st_size and not os.read(fd,1)
   and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'complete_stable_fd_and_name')
  if sha is not None:need(hashlib.sha256(raw).hexdigest()==sha,'pinned_public_source_or_receipt')
  return raw
 finally:
  os.close(fd);COUNTS['closed']+=1
def safe_count(value,maximum=10000000):
 need(type(value) is int and 0<=value<=maximum,'fixed_count_projection')
 return value
report={'schema':'heptabao.mac-main3-sdk-r3-original-wire-projection.r1','ok':False,
 'originalJobId':'1a1b28a4d4c-fc05-7e81','originalChildPid':70395,
 'originalStdoutBytes':3696,'originalStderrBytes':0,
 'finalResultSha256':FINAL_SHA,'childResultSha256':CHILD_SHA,
 'workerSourceSha256':WORKER_SHA,'wireSourceSha256':WIRE_SHA,
 'rawPrivateBytesOrDigestsPublished':False,'pathsOrIdsProjected':False,
 'httpRequestsDispatched':0,'childProcessesStarted':0,'serviceMutationsDispatched':0,
 'productionChanged':False,'originalFailedBusinessResultReplaced':False}
try:
 need(sys.platform=='darwin' and os.getuid()==501 and os.geteuid()==501,'exact_mac_owner')
 final=json.loads(read_exact(JOURNAL/'057-final-result.public.json',65536,FINAL_SHA))['value']
 need(final['ok'] is False and final['errorCode']=='sdk_original_owned_child_known_zero'
  and final['closuresKnown'] and final['manager']['allRegistrationsClosed']
  and final['manager']['allKnownLineagesClosed'] and final['commands']['unknownCommandCount']==0,
  'original_failed_cleanup_known_closed')
 command=json.loads(read_exact(JOURNAL/'045-sdk-child-result.public.json',65536,CHILD_SHA))['value']['command']
 need(command['pid']==70395 and command['exitCode']==1 and command['completeBeforeDeadline'] is True
  and command['outcomeUnknown'] is False and command['streamsClosed'] is True
  and command['stdoutBytes']==3696 and command['stderrBytes']==0,'original_worker_known_exit_stream_sizes')
 need(command['cleanup']['ok'] and command['cleanup']['directChildReaped']
  and command['cleanup']['allGroupRowsEmptyAfterReap'] and not command['cleanup']['signals'],
  'original_worker_wait_group_no_signals')
 worker=read_exact(ROOT/'qa/main3_sdk_cycle_r2.mjs',65536,WORKER_SHA).decode('utf-8')
 wire_source=read_exact(ROOT/'qa/main3_sdk_wire_r2.mjs',65536,WIRE_SHA).decode('utf-8')
 public_codes=set(re.findall(r"""['"]([a-z][a-z0-9_.-]{1,120})['"]""",worker+'\n'+wire_source))
 value=json.loads(read_exact(ROOT/'initial/sdk-initial.stdout.private.json',65536,expected_size=3696))
 need(not read_exact(ROOT/'initial/sdk-initial.stderr.private',4096,expected_size=0),'original_empty_stderr')
 need(type(value) is dict and value.get('schema')=='heptabao.mac-main3-sdk-private-cycle.r2'
  and value.get('ok') is False and value.get('errorCode')=='actual_complete_plugin_cycle',
  'original_worker_failed_result')
 rows=value.get('wire')
 need(type(rows) is list and len(rows)==2 and all(type(row) is dict for row in rows)
  and sum(row.get('dispatched') is True for row in rows)==2
  and sum(row.get('responseComplete') is True for row in rows)==1
  and sum(row.get('outcomeUnknown') is True for row in rows)==1,
  'original_two_wire_rows_one_complete_one_unknown')
 projected=[]
 for index,row in enumerate(rows,1):
  need(row.get('ordinal')==index,'original_sequential_wire_ordinals')
  output={'ordinal':index}
  for key,choices in {
   'routeCategory':('approle-login','manifest-read','order-policy-read','scheduler-assignments-read','profile-read','inbox-write'),
   'method':('GET','POST'),'responseFraming':('no-body','chunked','content-length'),
   'tlsVersion':('TLSv1.2','TLSv1.3')
  }.items():
   if key in row:
    need(row[key] in choices,'fixed_enum_projection')
    output[key]=row[key]
  for key in ('dispatched','responseComplete','requestClosed','socketObserved','socketClosed','tlsVerified',
   'outcomeUnknown','requestError','responseError','responseAborted','closedRequestResponseFailureForwarded','privateTokenCaptured'):
   if key in row:
    need(type(row[key]) is bool,'fixed_boolean_projection');output[key]=row[key]
  for key in ('slotOrdinal','requestCount','requestBytes','responseBytes','originalHttpMaximumMs','allocatedHttpMs'):
   if key in row:output[key]=safe_count(row[key])
  if 'status' in row:
   need(type(row['status']) is int and 100<=row['status']<=599,'fixed_http_status')
   output['status']=row['status']
  if 'errorCode' in row:
   code=row['errorCode'];known=type(code) is str and code in public_codes
   output['errorCodeIsPinnedSourceLiteral']=known
   output['fixedErrorCode']=code if known else 'unprojected_error_code'
  projected.append(output)
 report['originalWireRows']=projected
 report['originalWorkerFixedErrorCode']='actual_complete_plugin_cycle'
 plugin=value.get('plugin')
 need(type(plugin) is dict,'original_plugin_status_shape')
 result={}
 for key in ('ok',):
  if key in plugin and plugin[key] is not None:
   need(type(plugin[key]) is bool,'plugin_fixed_bool');result[key]=plugin[key]
 for key in ('manifestProfiles','importedProfiles','agentStores','verifiedStores','effectiveMissing',
  'effectiveMismatched','changedOrders','verifiedOrderBindings','schedulerReports','pendingRuntimeRefreshes','publishedEvents'):
  if key in plugin:
   result[key]=None if plugin[key] is None else safe_count(plugin[key])
 logs=plugin.get('logCounts')
 if logs is not None:
  need(type(logs) is dict,'plugin_fixed_logs')
  result['logCounts']={k:safe_count(logs[k]) for k in ('info','warn','error','debug') if k in logs}
 report['originalPluginStatusProjection']=result
 need(COUNTS['opened']==COUNTS['closed'] and time.monotonic()<UNTIL,'all_readonly_descriptors_closed_before_deadline')
 report['ok']=True
except Refused as error:report['errorCode']=str(error)
except BaseException as error:report['errorType']=type(error).__name__
report['readDescriptors']=COUNTS
report['elapsedSeconds']=time.monotonic()-START
print(json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report['ok'] else 1)
