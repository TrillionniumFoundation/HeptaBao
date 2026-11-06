import time
START=time.monotonic()
import hashlib,io,json,os,signal,stat,sys,zipfile
from pathlib import Path
ITEMS=json.loads("[{\"project\":\"pip\",\"wheel\":{\"actual_interpreter_tag_compatible\":true,\"bytes\":1950951,\"filename\":\"pip-26.3-py3-none-any.whl\",\"requires_python\":\">=3.10\",\"sha256\":\"f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13\",\"url\":\"https://files.pythonhosted.org/packages/07/25/ee8c38ae72d66b844ce8eb9711ba905dba21ca1a8a0c960057c41cd23337/pip-26.3-py3-none-any.whl\",\"yanked\":false}},{\"project\":\"cryptography\",\"wheel\":{\"actual_interpreter_tag_compatible\":true,\"bytes\":3914904,\"filename\":\"cryptography-50.0.2-cp311-abi3-macosx_11_0_arm64.whl\",\"requires_python\":\"!=3.9.0,!=3.9.1,>=3.9\",\"sha256\":\"fa8f5efb344d6908a1ce62f4a24e2e5780f825d6f53f5f50ec5ffacac72936cb\",\"url\":\"https://files.pythonhosted.org/packages/e5/56/d194340cc4a57535e82e1bee9e89667ac4b7c13b5d3f59686deae3094dd5/cryptography-50.0.2-cp311-abi3-macosx_11_0_arm64.whl\",\"yanked\":false}},{\"project\":\"cffi\",\"wheel\":{\"actual_interpreter_tag_compatible\":true,\"bytes\":181487,\"filename\":\"cffi-2.0.0-cp314-cp314-macosx_11_0_arm64.whl\",\"requires_python\":\">=3.9\",\"sha256\":\"c654de545946e0db659b3400168c9ad31b5d29593291482c43e3564effbcee13\",\"url\":\"https://files.pythonhosted.org/packages/59/dd/27e9fa567a23931c838c6b02d0764611c62290062a6d4e8ff7863daf9730/cffi-2.0.0-cp314-cp314-macosx_11_0_arm64.whl\",\"yanked\":false}},{\"project\":\"pycparser\",\"wheel\":{\"actual_interpreter_tag_compatible\":true,\"bytes\":118140,\"filename\":\"pycparser-2.23-py3-none-any.whl\",\"requires_python\":\">=3.8\",\"sha256\":\"e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934\",\"url\":\"https://files.pythonhosted.org/packages/a0/e3/59cd50310fc9b59512193629e1984c1f95e5c8ae6e5d8c69532ccc65a7fe/pycparser-2.23-py3-none-any.whl\",\"yanked\":false}}]")
BASE=Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control")
SOURCE=BASE/"formal-kv2-public-wheels-from-rog-r1"
OUT=BASE/"formal-kv2-wheel-core-metadata-originals-r1"
REPORT={"schema":"heptabao.fixed-wheel-original-core-metadata-preservation.v1","status":"failed","work_seconds":52,"runtime_seconds":60,"business_source_opened":False,"network_called":False,"packages_installed":False,"files":[]}
def check():
 if time.monotonic()>=START+52:raise TimeoutError("original_deadline")
def alarm(_s,_f):raise TimeoutError("original_deadline")
def identity(s):return(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read_wheel(path,pin):
 check();assert path.resolve(strict=True)==path
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);assert stat.S_ISREG(st.st_mode) and st.st_uid==501 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and st.st_size==pin["bytes"]
  raw=b""
  while True:
   check();b=os.read(fd,65536)
   if not b:break
   raw+=b;assert len(raw)<=pin["bytes"]
  assert len(raw)==pin["bytes"] and hashlib.sha256(raw).hexdigest()==pin["sha256"]
  assert identity(st)==identity(os.fstat(fd))==identity(path.lstat())
  return raw
 finally:os.close(fd)
def write(name,raw):
 p=OUT/name;assert p.parent==OUT
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,"wb",closefd=False) as f:f.write(raw);f.flush();os.fsync(fd)
 finally:os.close(fd)
 assert p.read_bytes()==raw
 return {"name":name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def sync(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
os.umask(0o077)
try:
 assert sys.platform=="darwin" and os.geteuid()==501
 assert signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0) and signal.getsignal(signal.SIGALRM)==signal.SIG_DFL
 signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,max(.001,START+52-time.monotonic()))
 st=BASE.lstat();assert BASE.resolve(strict=True)==BASE and stat.S_ISDIR(st.st_mode) and st.st_uid==501 and not st.st_mode&0o022
 assert not os.path.lexists(OUT)
 records=[]
 for item in ITEMS:
  pin=item["wheel"];raw=read_wheel(SOURCE/pin["filename"],pin)
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   members=[x for x in z.infolist() if x.filename.endswith(".dist-info/METADATA")]
   assert len(members)==1 and members[0].file_size<=131072
   content=z.read(members[0]);assert len(content)==members[0].file_size
  records.append((item["project"]+".METADATA.original",content,pin["sha256"]))
 assert len(records)==4
 OUT.mkdir(mode=0o700);sync(BASE)
 for name,raw,source_sha in records:
  check();row=write(name,raw);row["wheel_sha256"]=source_sha;REPORT["files"].append(row)
 sync(OUT);check();REPORT["status"]="passed"
except BaseException as error:REPORT["error_type"]=type(error).__name__
finally:
 signal.setitimer(signal.ITIMER_REAL,0);REPORT["elapsed_seconds"]=time.monotonic()-START
 if OUT.is_dir():write("result.public.json",(json.dumps(REPORT,sort_keys=True,indent=2)+"\n").encode());sync(OUT)
 print(json.dumps(REPORT,sort_keys=True),flush=True)
raise SystemExit(0 if REPORT["status"]=="passed" else 1)
