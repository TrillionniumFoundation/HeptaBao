import time
START=time.monotonic()
import hashlib,json,os,signal,stat,sys
from pathlib import Path
OUT=Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-env-inputs-r2")
DEST=OUT.parent/"formal-kv2-python-env-50-0-2-r2"
EXPECTED={"fixed-wheel-plan.json":(11294,"7639a1521c7f8551ea7cd603c2efc11b359b04149b1191c50ffeaa1fc59bf044"),"mac_fixed_capture_environment.py":(29364,"4ec4f525c3a926573b98ea42d36b85fbdbc9a0e4f535d8f5d48283c514e01cd0"),"mac_capture_controls18.py":(17877,"693d9420e0a13b8852418ee76a87afc6b4ed07e46a38c29bc293f6524169908f"),"mac_current_sqlite_capture.py":(57280,"9e27369657667dc3360ae276bb62e2d1ad0c6f55f07290d91304d7d396d72972"),"test_mac_current_sqlite_capture.py":(23809,"0b93d597b9fd525470951cb7b49cdb6707c11fc38b5e42f0d06bcedc7e0395f6"),"rog-download.result.public.json":(4005,"77ac4489798f4186faa63d54901b9c9adc3f4a9535db85590a717ece2a4d52cf"),"rog-download.runtime-terminal.original.json":(731,"3634d8688e9251c3b0a145a214ca6f32f3245f1ff7b78efcb5da0407fc1affed")}
REPORT={"schema":"heptabao.mac-fixed-capture-environment-input-stage.v1","status":"failed","work_budget_seconds":52,"runtime_budget_seconds":60,"environment_installed":False,"business_source_opened":False,"provider_called":False,"service_modified":False,"files":[]}
def need(x,label):
 if not x: raise RuntimeError(label)
def check():
 need(time.monotonic()<START+52,"original_stage_deadline")
def alarm(_s,_f): raise TimeoutError("original_stage_deadline")
def sync(path):
 f=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try: os.fsync(f)
 finally: os.close(f)
os.umask(0o077)
try:
 need(sys.platform=="darwin" and os.geteuid()==501 and sys.version_info[:3]==(3,14,3),"fixed_python")
 need(hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()=="cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13","fixed_python_pin")
 need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0) and signal.getsignal(signal.SIGALRM)==signal.SIG_DFL,"foreign_timer")
 signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,max(.001,START+52-time.monotonic()))
 raw=sys.stdin.buffer.read(200001);need(len(raw)<=200000,"input_bound")
 items=json.loads(raw);need(len(items)==7 and {x["name"] for x in items}==set(EXPECTED),"exact_inputs")
 parent=OUT.parent.lstat();need(OUT.parent.resolve()==OUT.parent and stat.S_ISDIR(parent.st_mode) and parent.st_uid==501 and not parent.st_mode&0o022,"owned_parent")
 need(not os.path.lexists(OUT) and not os.path.lexists(DEST),"fresh_input_and_environment_roots")
 for item in items:
  b=item["text"].encode();need((len(b),hashlib.sha256(b).hexdigest())==EXPECTED[item["name"]],"fixed_input_bytes")
 OUT.mkdir(mode=0o700);sync(OUT.parent)
 for item in items:
  check();b=item["text"].encode();p=OUT/item["name"]
  fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   with os.fdopen(fd,"wb",closefd=False) as stream:stream.write(b);stream.flush();os.fsync(fd)
  finally:os.close(fd)
  st=p.lstat();need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==501 and stat.S_IMODE(st.st_mode)==0o600 and p.read_bytes()==b,"stage_readback")
  REPORT["files"].append({"name":item["name"],"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()})
 sync(OUT);check()
 after=OUT.parent.lstat();need((after.st_dev,after.st_ino,after.st_uid)==(parent.st_dev,parent.st_ino,parent.st_uid) and not os.path.lexists(DEST),"parent_or_output_changed")
 REPORT["status"]="passed"
except BaseException as error:
 REPORT["error_type"]=type(error).__name__
finally:
 signal.setitimer(signal.ITIMER_REAL,0)
 REPORT["elapsed_seconds_before_receipt"]=time.monotonic()-START
 print(json.dumps(REPORT,sort_keys=True),flush=True)
raise SystemExit(0 if REPORT["status"]=="passed" else 1)
