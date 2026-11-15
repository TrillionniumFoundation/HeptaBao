#!/usr/bin/env python3
"""One bounded actual Mac SDK mutex qualification in new synthetic private state."""
import hashlib,json,os,select,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path("/Users/qianqi/heptabao-authbus-sdk-mutex-qualification-20261106-r2")
QUAL=Path("/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2")
SDK=Path("/opt/homebrew/lib/node_modules/openclaw")
PYTHON="/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
NODE="/opt/homebrew/Cellar/node/25.9.0_1/bin/node"
# PAYLOAD_PLACEHOLDER
CUSTODY_PINS={
 "kv2_dr_process_custody.py":"669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008",
 "owned_process.py":"0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0"}
RUNTIME_PINS={
 PYTHON:"cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13",
 NODE:"a46ed02589ca3af795237111ff854262064f8ff5c5b58d75c1509f37311eb15e",
 "/usr/bin/sandbox-exec":"abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a"}
report={"schema":"heptabao.actual-sdk-mutex-owned-qualification.r2","ok":False,
 "sharedSeconds":45,"supervisorSeconds":70,"automaticRetry":False,"providerCalls":0,
 "productionCredentialReads":0,"productionWrites":0,"productionMutexAcquired":False,
 "nativeServiceStarted":False,"authDatabaseOpened":False,"syntheticStateOnly":True,
 "allProviderRegistrationsQualified":False,"asyncUnlinkIsAtomicCompareAndDeleteClaimed":False,
 "originalChildrenExpected":7,"children":[],"interprocess":[],"candidateCommit":"4bde9aee03fcd27c59e13607e529b1cee594b249"}
owner=None;created=False;children=[];error_codes=set()
def need(value,code):
 if not value:error_codes.add(code);raise RuntimeError(code)
def remaining(cap=45):
 value=UNTIL-time.monotonic();need(value>0,"original_mutex_qualification_deadline");return min(cap,value)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def ident(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,cap=1048576):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid in (0,501)
    and not stat.S_IMODE(s.st_mode)&0o022 and 0<=s.st_size<=cap,"bounded_public_mutex_source")
  out=bytearray()
  while len(out)<=cap:
   remaining();part=os.read(fd,min(65536,cap+1-len(out)))
   if not part:break
   out.extend(part)
  need(len(out)==s.st_size and ident(s)==ident(os.fstat(fd))==ident(Path(path).lstat()),"stable_public_mutex_source")
  return bytes(out)
 finally:os.close(fd)
def private(path,data):
 raw=data if isinstance(data,bytes) else data.encode()
 need(len(raw)<=262144,"bounded_owned_mutex_artifact")
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:
   remaining();n=os.write(fd,view);need(n>0,"owned_mutex_write_progress");view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def fence():
 for name,pin in CUSTODY_PINS.items():need(sha(read(QUAL/"qa"/name))==pin,"qualified_custody_source_unchanged")
 for path,pin in RUNTIME_PINS.items():need(sha(read(Path(path),2*1048576))==pin,"qualified_mutex_runtime_unchanged")
 for name,pin in PAYLOAD["sdkPins"].items():need(sha(read(SDK/name))==pin,"qualified_mutex_sdk_source_unchanged")
def close_streams(child):
 for stream in (child.stdin,child.stdout,child.stderr):
  if stream is not None and not stream.closed:stream.close()
def parse_output(raw):
 need(len(raw)<=65536 and raw.endswith(b"\n"),"bounded_complete_mutex_worker_stdout")
 rows=[json.loads(line) for line in raw.splitlines()]
 need(rows and isinstance(rows[-1],dict),"structured_mutex_worker_result")
 return rows
def record(label,child,out,err,*,ready=None):
 close_streams(child)
 private(ROOT/"output"/(label+".stdout.public.json"),out)
 private(ROOT/"output"/(label+".stderr.private"),err)
 need(len(err)<=65536,"bounded_mutex_worker_stderr")
 row={"label":label,"exitCode":child.returncode,"stdoutBytes":len(out),"stderrBytes":len(err),
      "stdoutSha256":sha(out),"streamsClosed":True}
 if ready is not None:row["ready"]=ready
 report["children"].append(row)
 need(child.returncode==0 and not err,"actual_mutex_child_complete_zero")
 return row
def child_args(mode):
 return ["/usr/bin/sandbox-exec","-f",str(ROOT/"mutex-fixture.sb"),NODE,
         str(ROOT/"code/mac_sdk_refresh_mutex_qualification_r2.mjs"),mode,str(int(remaining()*1000))]
def spawn(mode,*,control=False):
 child=subprocess.Popen(child_args(mode),stdin=subprocess.PIPE if control else subprocess.DEVNULL,
   stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,cwd=str(ROOT),env=environment)
 children.append(child);return child
def read_ready(child,mode):
 out=bytearray();deadline=min(UNTIL,time.monotonic()+5.0)
 while b"\n" not in out:
  left=deadline-time.monotonic();need(left>0,"mutex_holder_original_ready_deadline")
  ready,_,_=select.select([child.stdout],[],[],left);need(bool(ready),"mutex_holder_ready_timeout")
  part=os.read(child.stdout.fileno(),1);need(bool(part),"mutex_holder_eof_before_ready")
  out.extend(part);need(len(out)<=4096,"mutex_holder_ready_bound")
 row=json.loads(out);need(row=={"event":"ready","mode":mode,"syntheticStateOnly":True},"exact_mutex_holder_ready")
 return bytes(out),row
try:
 os.umask(0o077)
 need(sys.platform=="darwin" and os.getuid()==501 and os.path.realpath(sys.executable)==PYTHON,"exact_mac_mutex_qualification_runtime")
 authority=PAYLOAD["custodyQualificationAuthority"]
 need(authority["job_id"]=="1a1b141ef40-fc05-7750" and authority["state"]=="succeeded" and authority["exit_code"]==0
      and all(authority[k] is True for k in ("output_complete","output_durable","terminal_publication_confirmed"))
      and all(authority[k] is False for k in ("timed_out","cancelled","automatic_retry")),"original_custody_qualification_authority")
 q=read(QUAL/"result.public.json",65536)
 need(len(q)==58701 and sha(q)=="67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e",
      "same_actual_18_case_custody_qualification")
 prior=json.loads(q)
 need(prior["ok"] and prior["allCasesMatched"] and prior["allOwnedClosed"]
      and prior["custody"]["passed_process_custody"] and prior["custody"]["original_count"]==18,
      "qualified_original_mac_custody")
 fence()
 home=ROOT.parent.lstat();need(stat.S_ISDIR(home.st_mode) and home.st_uid==501 and not stat.S_IMODE(home.st_mode)&0o022,
      "owned_mac_home_parent")
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 for d in ("code","output","output/tmp","output/tmp/openclaw-501","output/state"): (ROOT/d).mkdir(mode=0o700,exist_ok=False)
 private(ROOT/"protected-write",b"synthetic-write-must-be-denied\n")
 private(ROOT/"output/config.json",b"{}\n")
 for name,raw in PAYLOAD["sources"].items():
  need(name in ("mac_sdk_refresh_mutex_r3.mjs","mac_sdk_refresh_mutex_qualification_r2.mjs"),"fixed_mutex_code_name")
  need(sha(raw.encode())==PAYLOAD["sourcePins"][name],"prepared_mutex_source_pin")
  private(ROOT/"code"/name,raw)
 private(ROOT/"plan.public.json",json.dumps({"schema":"heptabao.actual-sdk-mutex-synthetic-plan.r2",
   "sharedSeconds":45,"supervisorSeconds":70,"originalChildren":7,"unitCases":23,"interprocessDirections":2,
   "sourcePins":PAYLOAD["sourcePins"],"sdkPins":PAYLOAD["sdkPins"],"productionMutationAuthorized":False,
   "productionReadAuthorized":False,"providerCallAuthorized":False,"existingLockTakeoverAuthorized":False},
   sort_keys=True).encode()+b"\n")
 lines=["(version 1)","(deny default)","(allow process*)","(allow signal (target children))",
        "(allow sysctl-read)","(allow mach-lookup)","(allow file-read-metadata)"]
 for pathname in ("/System","/usr","/bin","/sbin","/Library","/private/etc","/opt/homebrew","/dev/fd"):
  lines.append("(allow file-read* (subpath "+json.dumps(pathname)+"))")
 for pathname in (ROOT/"code",ROOT/"output"):
  lines.append("(allow file-read* (subpath "+json.dumps(str(pathname))+"))")
 for pathname in [ROOT,*ROOT.parents,ROOT/"protected-write"]:
  lines.append("(allow file-read* (literal "+json.dumps(str(pathname))+"))")
 for pathname in ("/dev/null","/dev/urandom","/dev/random"):
  lines.append("(allow file-read* (literal "+json.dumps(pathname)+"))")
 lines.extend(["(allow file-write* (subpath "+json.dumps(str(ROOT/"output"))+"))",'(allow file-write* (literal "/dev/null"))'])
 policy="\n".join(lines)+"\n";private(ROOT/"mutex-fixture.sb",policy)
 environment={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":"/Users/qianqi","NODE_NO_WARNINGS":"1",
   "TMPDIR":str(ROOT/"output/tmp"),"OPENCLAW_STATE_DIR":str(ROOT/"output/state/initial"),
   "OPENCLAW_CONFIG_PATH":str(ROOT/"output/config.json"),"OPENCLAW_AUTH_STORE_READONLY":"1"}
 sys.path.insert(0,str(QUAL/"qa"));import kv2_dr_process_custody as custody
 original_popen=subprocess.Popen;original_killpg=os.killpg
 with custody.activated() as owner:
  for number,name in enumerate(PAYLOAD["sources"]):
   child=subprocess.Popen([NODE,"--check",str(ROOT/"code"/name)],stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(ROOT),env=environment)
   children.append(child);out,err=child.communicate(timeout=remaining(5))
   record("syntax-%d"%number,child,out,err)
  child=spawn("unit");out,err=child.communicate(timeout=remaining(15));row=record("unit",child,out,err)
  rows=parse_output(out);need(len(rows)==1 and rows[0].get("ok") is True
      and len(rows[0].get("cases",[]))==23 and all(x.get("passed") is True for x in rows[0]["cases"]),
      "actual_mutex_23_unit_cases_passed")
  report["unitResult"]=rows[0]
  for holder_mode,contender_mode in (("hold-standard","contend-adapter"),("hold-adapter","contend-standard")):
   holder=spawn(holder_mode,control=True);ready_raw,ready=read_ready(holder,holder_mode)
   contender=spawn(contender_mode);out,err=contender.communicate(timeout=remaining(5))
   record(contender_mode,contender,out,err)
   result=parse_output(out);need(len(result)==1 and result[0].get("ok") is True,"actual_mutex_contender_refused_as_expected")
   out,err=holder.communicate(input=b"release\n",timeout=remaining(5))
   record(holder_mode,holder,ready_raw+out,err,ready=ready)
   holder_result=parse_output(ready_raw+out);need(len(holder_result)==2 and holder_result[-1].get("ok") is True,
      "actual_mutex_original_holder_released")
   report["interprocess"].append({"holderMode":holder_mode,"contenderMode":contender_mode,
      "contender":result[0],"holder":holder_result[-1],"bothOriginalProcessesClosed":True})
 report["custody"]=owner.receipt()
 need(report["custody"]["passed_process_custody"] and report["custody"]["original_count"]==7
      and subprocess.Popen is original_popen and os.killpg is original_killpg,"seven_original_mutex_children_closed")
 for name,pin in PAYLOAD["sourcePins"].items():need(sha(read(ROOT/"code"/name))==pin,"owned_mutex_code_unchanged")
 leftovers=list((ROOT/"output/state").rglob("lock-*"))
 need(not leftovers,"all_synthetic_mutex_names_retired")
 fence();remaining()
 report.update(ok=True,unitCasesPassed=23,interprocessDirectionsPassed=2,allOriginalChildrenClosed=True,
   remainingSyntheticLockNameCount=0,sourcePins=PAYLOAD["sourcePins"],sdkSourcePins=PAYLOAD["sdkPins"],
   sandboxProfileSha256=sha(policy.encode()),runtimePins=RUNTIME_PINS,
   dynamicLibraryDependencyClosureClaimed=False,providerRefreshQualified=False)
except BaseException as error:
 code=str(error)
 report["errorCode"]=code if code in error_codes else "mutex_qualification_refused"
 report["errorType"]=type(error).__name__
finally:
 for child in children:close_streams(child)
 if owner is not None:report["custody"]=owner.receipt()
 report["elapsedSeconds"]=round(time.monotonic()-START,6)
 if created:
  try:private(ROOT/"result.public.json",json.dumps(report,sort_keys=True).encode()+b"\n")
  except BaseException:report["ok"]=False;report["resultPublicationFailed"]=True
 print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report["ok"] else 1)
