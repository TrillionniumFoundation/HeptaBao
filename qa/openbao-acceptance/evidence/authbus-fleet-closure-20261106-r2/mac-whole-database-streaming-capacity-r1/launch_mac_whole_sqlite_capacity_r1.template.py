#!/usr/bin/env python3
"""One new Mac synthetic whole-database fixture; no production source read."""
import hashlib,json,os,re,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+600
ROOT=Path('/Users/qianqi/heptabao-authbus-whole-database-streaming-capacity-20261106-r1')
QUAL=Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2')
SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
CUSTODY_PINS={'kv2_dr_process_custody.py':'669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008',
 'owned_process.py':'0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'}
RUNTIME_PINS={PYTHON:'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13',
 '/usr/bin/sandbox-exec':'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a',
 '/usr/bin/vm_stat':'0127fec1de1d99c7f0b0cf185fec048c7fe92d1f1b2ad380882c583f0c921df7',
 '/bin/ps':'3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'}
VM_STAT='/usr/bin/vm_stat'
MINIMUM_PRIMARY_BYTES=2469126144
MAXIMUM_PRIMARY_BYTES=2502680576
MINIMUM_FREE_DISK_BYTES=26463895552
MINIMUM_FREE_MEMORY_BYTES=1073741824
# PAYLOAD_PLACEHOLDER
codes=set();fds=[];owner=None;child=None;commands=None;created=False
report={'schema':'heptabao.actual-mac-whole-database-qualification-launch.capacity.r1','ok':False,
 'productionSourceReads':0,'productionWrites':0,'providerCalls':0,'serviceActions':0,
 'sdkImported':False,'productionRollbackQualified':False,'sharedSeconds':600,'workerSeconds':540,
 'supervisorSeconds':630,'automaticRetry':False,'maximumDatabaseBytes':4294967296,
 'largeDatabaseCapacityQualified':False,
 'candidateCommit':'4bde9aee03fcd27c59e13607e529b1cee594b249'}
def need(v,code):
 if not v:codes.add(code);raise RuntimeError(code)
def remaining(cap=600):
 value=UNTIL-time.monotonic();need(value>0,'whole_parent_absolute_deadline');return min(value,cap)
def ident(s):return [str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def opened(path,flags,mode=0o600):
 fd=os.open(path,flags|os.O_NOFOLLOW|os.O_CLOEXEC,mode);row={'fd':fd,'closeAttempts':0,'closed':False};fds.append(row);return row
def close(row):
 if row['closeAttempts']:return
 row['closeAttempts']=1;os.close(row['fd']);row['closed']=True
def read(path,cap=131072):
 remaining();row=opened(path,os.O_RDONLY|os.O_NONBLOCK)
 try:
  before=os.fstat(row['fd']);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid in (0,501)
   and not stat.S_IMODE(before.st_mode)&0o022 and 0<before.st_size<=cap,'whole_parent_bounded_public_input')
  out=bytearray()
  while len(out)<=before.st_size:
   remaining();part=os.read(row['fd'],min(65536,before.st_size+1-len(out)))
   if not part:break
   out.extend(part)
  need(len(out)==before.st_size and ident(before)==ident(os.fstat(row['fd']))==ident(Path(path).lstat()),'whole_parent_complete_stable_input')
  return bytes(out)
 finally:close(row)
def private(path,data):
 raw=data if isinstance(data,bytes) else data.encode();need(len(raw)<=262144,'whole_parent_private_write_bound')
 row=opened(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
 try:
  view=memoryview(raw)
  while view:
   remaining();n=os.write(row['fd'],view);need(n>0,'whole_parent_private_write_progress');view=view[n:]
  os.fsync(row['fd'])
 finally:close(row)
 row=opened(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(row['fd'])
 finally:close(row)
def public_fence():
 for name,pin in CUSTODY_PINS.items():need(sha(read(QUAL/'qa'/name))==pin,'same_qualified_original_custody_source')
 for path,pin in RUNTIME_PINS.items():need(sha(read(Path(path),2*1048576))==pin,'same_actual_whole_runtime')
 for relative,pin in PAYLOAD['installedSchemaSourcePins'].items():need(sha(read(SDK/relative))==pin,'same_installed_whole_schema_sources')
def own_fence():
 for name,pin in PAYLOAD['sourcePins'].items():need(sha(read(ROOT/'code'/name))==pin,'same_staged_whole_source')
 for name,pin in PAYLOAD['schemaPins'].items():need(sha(read(ROOT/'code'/(name+'-schema.sql')))==pin,'same_staged_whole_schema')
def disk_observation():
 remaining();s=ROOT.lstat();home=ROOT.parent.lstat();fs=os.statvfs(ROOT)
 need(stat.S_ISDIR(s.st_mode) and s.st_uid==501 and stat.S_IMODE(s.st_mode)==0o700
  and s.st_dev==home.st_dev,'capacity_owned_same_home_filesystem')
 need(all(type(value) is int and value>0 for value in (fs.f_frsize,fs.f_blocks))
  and type(fs.f_bavail) is int and 0<=fs.f_bavail<=fs.f_blocks,'capacity_statvfs_numeric_bounds')
 return {'method':'fresh_statvfs_owned_home_fixture','availableBytes':fs.f_bavail*fs.f_frsize,
  'fragmentBytes':fs.f_frsize,'device':s.st_dev,'observationIsDiscreteNotAReservation':True}
def resource_admission():
 disk=disk_observation()
 need(disk['availableBytes']>=MINIMUM_FREE_DISK_BYTES,'capacity_synthetic_disk_headroom')
 row,out,err=commands.run('capacity-memory-vm-stat',[VM_STAT],until=min(UNTIL,time.monotonic()+3),maximum=32768)
 private(ROOT/'output/memory-observation.stdout.private',out);private(ROOT/'output/memory-observation.stderr.private',err)
 need(row.get('outcomeUnknown') is False and type(row.get('exitCode')) is int
  and row['exitCode']==0 and not err,'capacity_original_memory_command_known_closed_zero')
 lines=out.decode('ascii','strict').splitlines()
 header=re.fullmatch(r'Mach Virtual Memory Statistics: \(page size of ([0-9]{1,6}) bytes\)',lines[0] if lines else '')
 need(header is not None,'capacity_actual_vm_page_size_header')
 page_size=int(header.group(1));need(page_size in (4096,16384,65536),'capacity_actual_vm_page_size')
 names={'Pages free':'free','Pages active':'active','Pages inactive':'inactive',
  'Pages speculative':'speculative','Pages wired down':'wired','Pages occupied by compressor':'compressor'}
 pages={}
 for line in lines[1:]:
  match=re.fullmatch(r'([^:]{1,64}):\s+([0-9]{1,20})\.',line.strip())
  need(match is not None,'capacity_complete_numeric_vm_stat_line')
  if match.group(1) in names:
   key=names[match.group(1)];need(key not in pages,'capacity_unique_vm_stat_field');pages[key]=int(match.group(2))
 need(set(pages)==set(names.values()) and all(0<=v*page_size<=34359738368 for v in pages.values()),
  'capacity_bounded_observed_memory_pages')
 need(pages['free']*page_size>=MINIMUM_FREE_MEMORY_BYTES,'capacity_actual_current_free_memory_headroom')
 need(commands.public()['allOwnedCommandsStopped'] and commands.public()['unknownCommandCount']==0,
  'capacity_original_admission_helpers_closed_before_large_child')
 # Reobserve disk after the memory command; neither observation reserves resources.
 disk=disk_observation();need(disk['availableBytes']>=MINIMUM_FREE_DISK_BYTES,'capacity_fresh_disk_before_large_child')
 return {'disk':disk,'memory':{'method':'one_pinned_original_vm_stat','pageSize':page_size,
  'observedPages':pages,'currentlyFreeBytes':pages['free']*page_size,
  'inactivePagesCountedAsGuaranteedAvailable':False,'totalPhysicalMemoryCountedAsAvailable':False,
  'observationIsDiscreteNotAReservation':True},'minimumFreeDiskBytes':MINIMUM_FREE_DISK_BYTES,
  'minimumFreeMemoryBytes':MINIMUM_FREE_MEMORY_BYTES,'budgetScope':'new_synthetic_largest_database_fixture_only',
  'productionWholeSixDatabaseDiskBudgetAdmitted':False}
def safe_command_rows():
 if commands is None:return []
 return [{key:row['public'][key] for key in ('label','pid','exitCode','completeBeforeDeadline',
  'cleanup','stdoutBytes','stderrBytes','streamsClosed','outcomeUnknown')}
  if row.get('public') is not None else {'label':row['label'],'outcomeUnknown':True} for row in commands.rows]
def close_streams():
 if child is not None:
  for stream in (child.stdin,child.stdout,child.stderr):
   if stream is not None and not stream.closed:stream.close()
try:
 os.umask(0o077);sys.dont_write_bytecode=True
 need(sys.platform=='darwin' and os.getuid()==501 and os.path.realpath(sys.executable)==PYTHON,'actual_whole_mac_runtime')
 a=PAYLOAD['custodyQualificationAuthority']
 need(a['job_id']=='1a1b141ef40-fc05-7750' and a['state']=='succeeded' and a['exit_code']==0
  and all(a[k] is True for k in ('output_complete','output_durable','terminal_publication_confirmed'))
  and all(a[k] is False for k in ('timed_out','cancelled','automatic_retry')),'original_whole_custody_qualification_authority')
 proof=read(QUAL/'result.public.json',65536)
 need(len(proof)==58701 and sha(proof)=='67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e','whole_original_custody_proof_exact')
 q=json.loads(proof);need(q['ok'] and q['allCasesMatched'] and q['allOwnedClosed']
  and q['custody']['passed_process_custody'] and q['custody']['original_count']==18,'whole_complete_original_custody_cases')
 public_fence()
 need(set(PAYLOAD['sources'])=={'whole_sqlite_streaming_r1.py','qualify_whole_sqlite_capacity_r1.py','mac_whole_sqlite_capacity_worker_r1.py',
  'mac_owned_commands_r1.py','mac_owned_unreaped_r1.py','mac_native_process_observer_r1.py'},'six_exact_whole_and_command_modules')
 for kind,relative,constant in [('agent','dist/openclaw-agent-db-DKpxi-Ll.js','OPENCLAW_AGENT_SCHEMA_SQL'),
  ('state','dist/openclaw-state-db-DzSsA9Ji.js','OPENCLAW_STATE_SCHEMA_SQL')]:
  raw=read(SDK/relative).decode();parts=re.findall(r'const '+constant+r' = `([\s\S]*?)`;',raw)
  need(len(parts)==1 and '${' not in parts[0] and '\\' not in parts[0].replace('\\n',''),'literal_original_generated_whole_schema')
  need(parts[0].replace('\\n','\n')==PAYLOAD['schemas'][kind],'whole_generated_schema_exact_extraction')
 home=ROOT.parent.lstat();need(stat.S_ISDIR(home.st_mode) and home.st_uid==501 and not stat.S_IMODE(home.st_mode)&0o022,'owned_whole_mac_home')
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 for name in ('code','output'):(ROOT/name).mkdir(mode=0o700,exist_ok=False)
 for name,source in PAYLOAD['sources'].items():
  need(sha(source.encode())==PAYLOAD['sourcePins'][name],'whole_prepared_source_hash');compile(source,name,'exec');private(ROOT/'code'/name,source)
 for kind,sql in PAYLOAD['schemas'].items():private(ROOT/'code'/(kind+'-schema.sql'),sql)
 plan={'schema':'heptabao.synthetic-whole-sqlite-plan.capacity.r1','sourceVfs':'unix-posix','maximumDatabaseBytes':4294967296,
 'largeDatabaseCapacityQualified':False,
  'sourcePins':PAYLOAD['workerSourcePins'],'helperSourcePins':PAYLOAD['helperSourcePins'],
  'schemaPins':PAYLOAD['schemaPins'],'installedSchemaSourcePins':PAYLOAD['installedSchemaSourcePins'],
  'minimumPrimaryBytes':MINIMUM_PRIMARY_BYTES,'maximumPrimaryBytes':MAXIMUM_PRIMARY_BYTES,
  'minimumFreeDiskBytes':MINIMUM_FREE_DISK_BYTES,'minimumFreeMemoryBytes':MINIMUM_FREE_MEMORY_BYTES,
  'originalChildren':1,'sharedSeconds':600,'workerSeconds':540,'productionReadAuthorized':False,'productionWriteAuthorized':False}
 private(ROOT/'code/plan.public.json',json.dumps(plan,sort_keys=True)+'\n')
 private(ROOT/'protected-read',b'synthetic protected read probe\n');private(ROOT/'protected-write',b'synthetic protected write probe\n')
 lines=['(version 1)','(deny default)','(allow process*)','(allow signal (target children))',
  '(allow sysctl-read)','(allow mach-lookup)','(allow file-read-metadata)']
 for name in ('/System','/usr','/bin','/sbin','/Library','/private/etc','/opt/homebrew','/dev/fd'):
  lines.append('(allow file-read* (subpath '+json.dumps(name)+'))')
 for name in (ROOT/'code',ROOT/'output'):lines.append('(allow file-read* (subpath '+json.dumps(str(name))+'))')
 for name in (ROOT,*ROOT.parents):lines.append('(allow file-read* (literal '+json.dumps(str(name))+'))')
 for name in ('/dev/null','/dev/random','/dev/urandom'):lines.append('(allow file-read* (literal '+json.dumps(name)+'))')
 lines.extend(['(allow file-write* (subpath '+json.dumps(str(ROOT/'output'))+'))','(allow file-write* (literal "/dev/null"))'])
 private(ROOT/'qualification.sb','\n'.join(lines)+'\n');own_fence()
 sys.path[:0]=[str(ROOT/'code'),str(QUAL/'qa')]
 from mac_owned_commands_r1 import Commands,Signals
 import mac_owned_commands_r1,mac_owned_unreaped_r1,mac_native_process_observer_r1
 for module in (mac_owned_commands_r1,mac_owned_unreaped_r1,mac_native_process_observer_r1):
  need(Path(module.__file__).resolve()==ROOT/'code'/(module.__name__+'.py'),'exact_staged_command_module_import')
 signals=Signals();signals.install();commands=Commands(signals)
 report['resourceAdmission']=resource_admission()
 public_fence();own_fence();remaining()
 import kv2_dr_process_custody as custody
 with custody.activated() as owner:
  deadline=time.monotonic()+remaining(540)
  child=subprocess.Popen(['/usr/bin/sandbox-exec','-f',str(ROOT/'qualification.sb'),PYTHON,'-I','-S','-B',
    str(ROOT/'code/mac_whole_sqlite_capacity_worker_r1.py'),repr(deadline)],stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),
    env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/Users/qianqi','LANG':'C','LC_ALL':'C'})
  out,err=child.communicate(timeout=remaining(540));close_streams()
  need(len(out)<=65536 and len(err)<=65536,'whole_bounded_original_worker_streams')
  private(ROOT/'output/worker.stdout.public.json',out);private(ROOT/'output/worker.stderr.private',err)
  report['originalChild']={'exitCode':child.returncode,'stdoutBytes':len(out),'stderrBytes':len(err),
   'stdoutSha256':sha(out),'streamsClosed':True}
  need(child.returncode==0 and not err,'whole_original_worker_known_zero')
  value=json.loads(out);report['worker']=value
  need(value['ok'] and value['kernelReadWriteNetworkRefusalsObserved'] and value['originalProbeSocketClosed']
   and value['allExplicitInputDescriptorsClosedOnce'] and value['sqliteVersion']=='3.53.4','whole_actual_worker_qualified')
  qualified=value['qualification'];need(qualified['ok'] and len(qualified['cases'])==17
   and qualified['closedRestoredDatabases']==6 and qualified['retainedOriginalNamespaceFiles']==18
   and qualified['resources']['restoreOperationCount']==48
   and qualified['resources']['darwinXattrQueryCount']>0
   and qualified['resources']['allDarwinXattrQueriesClosedAndAbsent']
   and qualified['resources']['allStreamOperationsCompleteAndClosed']
   and qualified['resources']['allOriginalBackupsCompleted']
   and qualified['resources']['databaseSerializeCalls']==0
   and qualified['resources']['backupCalls']==24
   and all(item['passed'] is True for item in qualified['cases'])
   and MINIMUM_PRIMARY_BYTES<=qualified['capacity']['logicalBytes']<=MAXIMUM_PRIMARY_BYTES
   and qualified['capacity']['minimumRequiredBytes']==MINIMUM_PRIMARY_BYTES
   and qualified['capacity']['allRestoredPayloadRowsComparedToOriginalSyntheticInput'] is True
   and 0<value['processMaximumRssBytes']<=value['memoryBudgetBytes']==536870912
   and all(qualified['resources'][k] for k in ('allFileDescriptorsClosedOnce','allSqliteHandlesClosedOnce',
    'allExplicitCursorsClosed','allRestoreOperationsCompleted')),'whole_complete_six_database_original_results')
 public_fence();own_fence();remaining()
 report['custody']=owner.receipt();need(report['custody']['passed_process_custody']
  and report['custody']['original_count']==1,'whole_original_child_custody_closed')
 report.update(ok=True,allOriginalSourcePinsUnchanged=True,createdOnlyNewSyntheticRoot=True,
  largeDatabaseCapacityQualified=True,capacityScope='largest_current_database_plus_six_database_lifecycle',
  allCurrentSixDatabaseSizesReproduced=False,productionDiskBudgetAdmitted=False,
  rssThresholdIsPostRunAcceptanceNotOsEnforcedLimit=True)
 report['diskAfterQualification']=disk_observation()
except BaseException as error:
 report['errorType']=type(error).__name__;report['errorCode']=str(error) if str(error) in codes else 'whole_database_qualification_launch_refused'
finally:
 close_streams()
 if owner is not None:report['custody']=owner.receipt()
 report['originalAdmissionCommands']=safe_command_rows()
 report['allOriginalAdmissionCommandsClosed']=commands is None or commands.public()['allOwnedCommandsStopped']
 report['unknownAdmissionCommandCount']=0 if commands is None else commands.public()['unknownCommandCount']
 report['fileDescriptors']=[{k:r[k] for k in ('closeAttempts','closed')} for r in fds]
 report['allParentFileDescriptorsClosedOnce']=all(r['closeAttempts']==1 and r['closed'] for r in fds)
 report['createdPrivateRoot']=created;report['elapsedSeconds']=time.monotonic()-START
 if (not report['allParentFileDescriptorsClosedOnce'] or not report['allOriginalAdmissionCommandsClosed']
  or report['unknownAdmissionCommandCount'] or time.monotonic()>=UNTIL):report['ok']=False
 if not report['ok']:report['largeDatabaseCapacityQualified']=False
 print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if report['ok'] else 1)
