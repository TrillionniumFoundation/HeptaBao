#!/usr/bin/env python3
"""One new Mac synthetic whole-database fixture; no production source read."""
import hashlib,json,os,re,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+45
ROOT=Path('/Users/qianqi/heptabao-authbus-whole-database-qualification-20261106-r1')
QUAL=Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2')
SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
CUSTODY_PINS={'kv2_dr_process_custody.py':'669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008',
 'owned_process.py':'0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'}
RUNTIME_PINS={PYTHON:'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13',
 '/usr/bin/sandbox-exec':'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a'}
# PAYLOAD_PLACEHOLDER
codes=set();fds=[];owner=None;child=None;created=False
report={'schema':'heptabao.actual-mac-whole-database-qualification-launch.r1','ok':False,
 'productionSourceReads':0,'productionWrites':0,'providerCalls':0,'serviceActions':0,
 'sdkImported':False,'productionRollbackQualified':False,'sharedSeconds':45,'workerSeconds':30,
 'supervisorSeconds':70,'automaticRetry':False,'maximumDatabaseBytes':67108864,
 'candidateCommit':'4bde9aee03fcd27c59e13607e529b1cee594b249'}
def need(v,code):
 if not v:codes.add(code);raise RuntimeError(code)
def remaining(cap=45):
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
 need(set(PAYLOAD['sources'])=={'whole_sqlite_bundle_r1.py','qualify_whole_sqlite_bundle_r1.py','mac_whole_sqlite_worker_r1.py'},'three_exact_whole_modules')
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
 plan={'schema':'heptabao.synthetic-whole-sqlite-plan.r1','sourceVfs':'unix-posix','maximumDatabaseBytes':67108864,
  'sourcePins':PAYLOAD['sourcePins'],'schemaPins':PAYLOAD['schemaPins'],'installedSchemaSourcePins':PAYLOAD['installedSchemaSourcePins'],
  'originalChildren':1,'sharedSeconds':45,'workerSeconds':30,'productionReadAuthorized':False,'productionWriteAuthorized':False}
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
 sys.path.insert(0,str(QUAL/'qa'));import kv2_dr_process_custody as custody
 with custody.activated() as owner:
  deadline=time.monotonic()+remaining(30)
  child=subprocess.Popen(['/usr/bin/sandbox-exec','-f',str(ROOT/'qualification.sb'),PYTHON,'-I','-S','-B',
    str(ROOT/'code/mac_whole_sqlite_worker_r1.py'),repr(deadline)],stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),
    env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/Users/qianqi','LANG':'C','LC_ALL':'C'})
  out,err=child.communicate(timeout=remaining(30));close_streams()
  need(len(out)<=65536 and len(err)<=65536,'whole_bounded_original_worker_streams')
  private(ROOT/'output/worker.stdout.public.json',out);private(ROOT/'output/worker.stderr.private',err)
  report['originalChild']={'exitCode':child.returncode,'stdoutBytes':len(out),'stderrBytes':len(err),
   'stdoutSha256':sha(out),'streamsClosed':True}
  need(child.returncode==0 and not err,'whole_original_worker_known_zero')
  value=json.loads(out);report['worker']=value
  need(value['ok'] and value['kernelReadWriteNetworkRefusalsObserved'] and value['originalProbeSocketClosed']
   and value['allExplicitInputDescriptorsClosedOnce'] and value['sqliteVersion']=='3.53.4','whole_actual_worker_qualified')
  qualified=value['qualification'];need(qualified['ok'] and len(qualified['cases'])==13
   and qualified['closedRestoredDatabases']==6 and qualified['retainedOriginalNamespaceFiles']==18
   and qualified['resources']['restoreOperationCount']==48
   and all(qualified['resources'][k] for k in ('allFileDescriptorsClosedOnce','allSqliteHandlesClosedOnce',
    'allExplicitCursorsClosed','allRestoreOperationsCompleted')),'whole_complete_six_database_original_results')
 public_fence();own_fence();remaining()
 report['custody']=owner.receipt();need(report['custody']['passed_process_custody']
  and report['custody']['original_count']==1,'whole_original_child_custody_closed')
 report.update(ok=True,allOriginalSourcePinsUnchanged=True,createdOnlyNewSyntheticRoot=True)
except BaseException as error:
 report['errorType']=type(error).__name__;report['errorCode']=str(error) if str(error) in codes else 'whole_database_qualification_launch_refused'
finally:
 close_streams()
 if owner is not None:report['custody']=owner.receipt()
 report['fileDescriptors']=[{k:r[k] for k in ('closeAttempts','closed')} for r in fds]
 report['allParentFileDescriptorsClosedOnce']=all(r['closeAttempts']==1 and r['closed'] for r in fds)
 report['createdPrivateRoot']=created;report['elapsedSeconds']=time.monotonic()-START
 if not report['allParentFileDescriptorsClosedOnce'] or time.monotonic()>=UNTIL:report['ok']=False
 print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if report['ok'] else 1)
