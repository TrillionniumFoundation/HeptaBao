import time
START=time.monotonic()
import email.parser,hashlib,io,json,os,signal,stat,sys,zipfile
from pathlib import Path
SPEC=json.loads("[{\"project\":\"pip\",\"metadata\":{\"bytes\":6671,\"path\":\"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-dependency-plan-r2/pip-26.3.pypi.original.json\",\"sha256\":\"9cee103938ec9d9fb6201ecd0eb8a51b1893e01358f75c162d7c7cf6a9d8fa20\"},\"wheel\":{\"actual_interpreter_tag_compatible\":true,\"bytes\":1950951,\"filename\":\"pip-26.3-py3-none-any.whl\",\"requires_python\":\">=3.10\",\"sha256\":\"f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13\",\"url\":\"https://files.pythonhosted.org/packages/07/25/ee8c38ae72d66b844ce8eb9711ba905dba21ca1a8a0c960057c41cd23337/pip-26.3-py3-none-any.whl\",\"yanked\":false}},{\"project\":\"cryptography\",\"metadata\":{\"bytes\":57201,\"path\":\"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-dependency-plan-r2/cryptography-50.0.2.pypi.original.json\",\"sha256\":\"7423990cc0948676ef47a71ea62a476ece4c76245e6bebd1c3a71f03c4ffc0f4\"},\"wheel\":{\"actual_interpreter_tag_compatible\":true,\"bytes\":3914904,\"filename\":\"cryptography-50.0.2-cp311-abi3-macosx_11_0_arm64.whl\",\"requires_python\":\"!=3.9.0,!=3.9.1,>=3.9\",\"sha256\":\"fa8f5efb344d6908a1ce62f4a24e2e5780f825d6f53f5f50ec5ffacac72936cb\",\"url\":\"https://files.pythonhosted.org/packages/e5/56/d194340cc4a57535e82e1bee9e89667ac4b7c13b5d3f59686deae3094dd5/cryptography-50.0.2-cp311-abi3-macosx_11_0_arm64.whl\",\"yanked\":false}},{\"project\":\"cffi\",\"metadata\":{\"bytes\":75565,\"path\":\"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-dependency-plan-r1/cffi-2.0.0.pypi.original.json\",\"sha256\":\"176060f17977cb6a9df47b3ee7f97ee40d688832f30593649b465e8d064f4530\"},\"wheel\":{\"actual_interpreter_tag_compatible\":true,\"bytes\":181487,\"filename\":\"cffi-2.0.0-cp314-cp314-macosx_11_0_arm64.whl\",\"requires_python\":\">=3.9\",\"sha256\":\"c654de545946e0db659b3400168c9ad31b5d29593291482c43e3564effbcee13\",\"url\":\"https://files.pythonhosted.org/packages/59/dd/27e9fa567a23931c838c6b02d0764611c62290062a6d4e8ff7863daf9730/cffi-2.0.0-cp314-cp314-macosx_11_0_arm64.whl\",\"yanked\":false}},{\"project\":\"pycparser\",\"metadata\":{\"bytes\":3154,\"path\":\"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-dependency-plan-r1/pycparser-2.23.pypi.original.json\",\"sha256\":\"2f8b35ee20ccc932a73315a4fea04b3b88a17a66b23c5305af534a9a6d1f20a2\"},\"wheel\":{\"actual_interpreter_tag_compatible\":true,\"bytes\":118140,\"filename\":\"pycparser-2.23-py3-none-any.whl\",\"requires_python\":\">=3.8\",\"sha256\":\"e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934\",\"url\":\"https://files.pythonhosted.org/packages/a0/e3/59cd50310fc9b59512193629e1984c1f95e5c8ae6e5d8c69532ccc65a7fe/pycparser-2.23-py3-none-any.whl\",\"yanked\":false}}]")
ROOT=Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-public-wheels-from-rog-r1")
OLD=ROOT.parent/"formal-kv2-python-env-50-0-2-r2"/"wheels"
REPORT={"schema":"heptabao.fixed-public-wheel-core-metadata-diagnostic.v1","status":"failed","work_seconds":52,"runtime_seconds":60,"packages_installed":False,"business_source_opened":False,"network_called":False,"rows":[]}
def check():
 if time.monotonic()>=START+52:raise TimeoutError("original_deadline")
def alarm(_s,_f):raise TimeoutError("original_deadline")
def ident(s):return(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,size,digest):
 check();assert path.resolve(strict=True)==path
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==size
  data=b""
  while True:
   check();block=os.read(fd,65536)
   if not block:break
   data+=block;assert len(data)<=size
  assert len(data)==size and hashlib.sha256(data).hexdigest()==digest
  assert ident(st)==ident(os.fstat(fd))==ident(path.lstat())
  return data
 finally:os.close(fd)
try:
 assert sys.platform=="darwin" and os.geteuid()==501
 assert signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0) and signal.getsignal(signal.SIGALRM)==signal.SIG_DFL
 signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,max(.001,START+52-time.monotonic()))
 assert len(SPEC)==4
 for package in SPEC:
  wheel=package["wheel"];pin=package["metadata"]
  raw=read(ROOT/wheel["filename"],wheel["bytes"],wheel["sha256"])
  metadata=json.loads(read(Path(pin["path"]),pin["bytes"],pin["sha256"]))["info"]
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   names=[x for x in z.infolist() if x.filename.endswith(".dist-info/METADATA")]
   assert len(names)==1 and names[0].file_size<=131072
   m=email.parser.BytesParser().parsebytes(z.read(names[0]))
  actual={"name":m["Name"].lower().replace("_","-"),"version":m["Version"],"requires_python":m["Requires-Python"],"requires_dist":sorted(m.get_all("Requires-Dist",[]))}
  expected={"name":metadata["name"].lower().replace("_","-"),"version":metadata["version"],"requires_python":metadata["requires_python"],"requires_dist":sorted(metadata.get("requires_dist") or [])}
  REPORT["rows"].append({"project":package["project"],"wheel":wheel["filename"],"wheel_sha256":wheel["sha256"],"metadata_pin_verified":True,"wheel_pin_verified":True,"already_copied_in_failed_r2":os.path.lexists(OLD/wheel["filename"]),"equal_fields":{k:actual[k]==expected[k] for k in expected},"wheel_core":actual,"pypi_core":expected})
 check();REPORT["status"]="passed"
except BaseException as error:REPORT["error_type"]=type(error).__name__
finally:
 signal.setitimer(signal.ITIMER_REAL,0)
 REPORT["elapsed_seconds"]=time.monotonic()-START
 print(json.dumps(REPORT,sort_keys=True),flush=True)
raise SystemExit(0 if REPORT["status"]=="passed" else 1)
