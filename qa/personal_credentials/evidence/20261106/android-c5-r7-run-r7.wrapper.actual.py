#!/usr/bin/env python3
import hashlib,json,os,subprocess,sys,time
from pathlib import Path
os.umask(0o077)
base=Path("/home/alex/heptabao-android-autofill-20261106-r1")
qa=base/"android_live.revision9.py"
build=base/"candidate5/build-receipt.json"
release=Path("/home/alex/HeptaBaoPasskey-20261106-r5/release-r5b.public.json")
output=base/"run-r7"
expected={
 str(qa):"4d20ac12535e592da591b5c63cf7971ef2443c6b219f36e250aac2074fd3ce1e",
 str(build):"e9fa9d9d12ad9e02433799528d8ffeb0165d5db5ddb0545ede4b3f67e2fe7047",
 str(release):"89d8cdd189a7da58fcf251d8688202b8a9fb9fd82faa99421f478904b6044a71",
 str(base/"candidate5/apks/provider.apk"):"5c643afa5a08c6e8dd0baf751fe56dadf0f66947284d119d2da7051f4ab88ff8",
 str(base/"candidate5/apks/fixture-good.apk"):"ddead923325a10232749b76bee39e469eda8e7dce51b58b2d3cd47bce2f1076c",
 str(base/"candidate5/apks/fixture-wrong-certificate.apk"):"05c382bd166ba8ac69077f0bd0d57ee383967f71f2c2ac5c48e4390e7959cd45",
 str(base/"candidate5/apks/fixture-wrong-package.apk"):"a9f5c47b15cfaac2c2ad579de218641ce9ada1da050bd7be83f860fb52f35b36"}
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write_once(path,obj):
 data=(json.dumps(obj,sort_keys=True,indent=2)+"\n").encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,"wb") as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
 finally: pass
 parent=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY)
 try: os.fsync(parent)
 finally: os.close(parent)
 return hashlib.sha256(data).hexdigest()
try:
 if output.exists() or output.is_symlink(): raise ValueError()
 before={path:digest(path) for path in expected}
 if before!=expected: raise ValueError()
 argv=["/usr/bin/python3","-u",str(qa),"--adb","/home/alex/.local/bin/adb","--apks",str(base/"candidate5/apks"),"--build-receipt",str(build),"--master-file",str(base/"master.private"),"--output",str(output)]
 binding={"schema":1,"candidate":"android-autofill-candidate5","run":"r7","qa_revision":9,"expected_case_count":12,"synthetic_only":True,"production_qualified":False,"device_exclusive_handoff":"passkey-r5b-release-sha256-bound","argv":argv,"input_sha256":before,"wrapper_sha256":digest(__file__),"created_unix_ns":time.time_ns()}
 binding_sha=write_once(base/"run-r7.launch.public.json",binding)
 print(json.dumps({"phase":"launch_bound","run":"r7","qa_sha256":expected[str(qa)],"binding_sha256":binding_sha}),flush=True)
 started=time.time_ns()
 result=subprocess.run(argv,check=False)
 after={path:digest(path) for path in expected}
 execution={"schema":1,"run":"r7","launch_binding_sha256":binding_sha,"started_unix_ns":started,"finished_unix_ns":time.time_ns(),"exit_code":result.returncode,"input_sha256_before":before,"input_sha256_after":after,"inputs_unchanged":before==after,"wrapper_sha256":digest(__file__)}
 if (output/"report.json").is_file(): execution["phone_report_sha256"]=digest(output/"report.json")
 execution_sha=write_once(base/"run-r7.execution.public.json",execution)
 print(json.dumps({"phase":"execution_finished","run":"r7","exit_code":result.returncode,"inputs_unchanged":before==after,"execution_sha256":execution_sha}),flush=True)
 sys.exit(result.returncode if before==after else 1)
except Exception:
 print(json.dumps({"ok":False,"error":"launch_or_execution_binding_failed","run":"r7"}),flush=True)
 sys.exit(1)
