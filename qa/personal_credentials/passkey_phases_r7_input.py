#!/usr/bin/env python3
"""Record each approved driver phase, including failures; never pass a case."""
import argparse,hashlib,json,os,re,secrets,stat,subprocess,time
from pathlib import Path
BASE=Path("/home/alex/HeptaBaoPasskey-20261106-r7")
DRIVER=BASE/"passkey_live.r7.py"
DRIVER_SHA="e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd"
INPUT_HELPER=BASE/"passkey_input_r7.py"
INPUT_HELPER_SHA="0ba29978acd83d7cccad6ff4d25d4ee32304c2c2584a02b74fee28be8db87f56"
PROFILE_SHA="a568f1e51f4d4e6c096b0b871bb7a9be5f7da88cf3aef39fca17e59bf8564706"
BUILD_SHA="e12bd68de3c606e03ce22a7a688ebb90c7b6ec4a951d15e5be233339e698042b"
PHASES={"preflight","install","inspect","launch-provider","launch-fixture","launch-decoy","tap","input-master","back","hide-keyboard","settings-arm-primary-system-bridge","settings-selected","kill-provider","kill-fixture","reverse","rp-state","wrong-certificate","good-certificate","restore"}
def sha(x):return hashlib.sha256(x).hexdigest()
def write(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,"wb",closefd=False) as f:f.write(data);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
 d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
def binding():
 for p,h in ((DRIVER,DRIVER_SHA),(INPUT_HELPER,INPUT_HELPER_SHA),(BASE/"passkey_phone_profile.r7.py",PROFILE_SHA),(BASE/"artifacts/build.receipt.json",BUILD_SHA)):
  s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and sha(p.read_bytes())==h
def main():
 os.umask(0o077);ap=argparse.ArgumentParser();ap.add_argument("--case",required=True);ap.add_argument("--steps",required=True);a=ap.parse_args()
 assert re.fullmatch(r"(?:M0[1-7]|G(?:0[1-9]|1[01])|SETUP|CLEANUP|OBSERVE)",a.case) and len(a.steps)<=16000
 steps=json.loads(a.steps);assert type(steps)is list and 0<len(steps)<=12
 for x in steps:
  assert type(x)is dict and "phase"in x and x["phase"]in PHASES and set(x)<={"phase","selector","selector_kind","wrong"}
  if x["phase"]=="tap":assert type(x.get("selector"))is str and len(x["selector"])<=256 and x.get("selector_kind","text")in("text","description","id")
  else:assert "selector"not in x and "selector_kind"not in x
  assert "wrong"not in x or x["phase"]=="input-master" and type(x["wrong"])is bool
 binding();attempts=BASE/"attempts"
 s=attempts.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700
 run=str(time.time_ns())+"-"+secrets.token_hex(4);source_sha=sha(Path(__file__).read_bytes())
 write(attempts/(run+".intent.public.json"),(json.dumps({"schema":1,"case":a.case,"steps":steps,"runner_sha256":source_sha,"driver_sha256":DRIVER_SHA,"profile_sha256":PROFILE_SHA,"build_sha256":BUILD_SHA,"input_helper_sha256":INPUT_HELPER_SHA,"started_unix_ns":time.time_ns()},sort_keys=True,indent=2)+"\n").encode())
 for i,step in enumerate(steps):
  binding();phase=step["phase"];argv=["/usr/bin/python3",str(DRIVER),"--adb","/home/alex/.local/bin/adb","--root",str(BASE/"live-r7"),"--artifacts",str(BASE/"artifacts"),"--expected-build-sha256",BUILD_SHA,"--phase",phase]
  if phase=="tap":argv+=["--selector-kind",step.get("selector_kind","text"),"--selector",step["selector"]]
  if phase=="input-master":
   argv[1]=str(INPUT_HELPER);argv+=["--driver",str(DRIVER)]
   argv+=["--master-file",str(BASE/"private/master.private")]
   if step.get("wrong"):argv+=["--wrong"]
  prefix=attempts/(run+"-"+str(i));start=time.time_ns();mono=time.monotonic_ns()
  write(Path(str(prefix)+".dispatch.public.json"),(json.dumps({"case":a.case,"step":i,"phase":phase,"argv":argv,"started_unix_ns":start},sort_keys=True,indent=2)+"\n").encode())
  try:r=subprocess.run(argv,capture_output=True,timeout=240);code=r.returncode;out,err=r.stdout,r.stderr
  except subprocess.TimeoutExpired as e:code=124;out=e.stdout or b"";err=e.stderr or b""
  assert len(out)<=1048576 and len(err)<=1048576
  write(Path(str(prefix)+".stdout.private"),out);write(Path(str(prefix)+".stderr.private"),err)
  try:result=json.loads(out)
  except (ValueError,UnicodeError):result={"ok":False,"error":"driver_output_not_json"}
  event={"schema":1,"case":a.case,"step":i,"phase":phase,"started_unix_ns":start,"finished_unix_ns":time.time_ns(),"duration_ns":time.monotonic_ns()-mono,"exit_code":code,"stdout_sha256":sha(out),"stderr_sha256":sha(err),"stdout_bytes":len(out),"stderr_bytes":len(err),"runner_sha256":source_sha,"driver_sha256":DRIVER_SHA,"input_helper_sha256":INPUT_HELPER_SHA,"result":result,"case_passed_by_phase":False}
  raw=(json.dumps(event,sort_keys=True,indent=2)+"\n").encode();write(Path(str(prefix)+".result.public.json"),raw)
  print(json.dumps(event,sort_keys=True),flush=True)
  if code!=0:raise SystemExit(code if code>0 else 1)
 binding()
if __name__=="__main__":main()
