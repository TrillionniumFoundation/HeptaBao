import pathlib,os,json,re,hashlib,runpy,time,subprocess,xml.etree.ElementTree as ET,urllib.request
os.umask(0o077);b=pathlib.Path("/home/alex/HeptaBaoPasskey-20261106-r9");root=b/"live-r9";driver=b/"passkey_live.r9.py";runner=b/"run_phases.input-r9.public.py"
assert hashlib.sha256(driver.read_bytes()).hexdigest()=="e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd" and hashlib.sha256(runner.read_bytes()).hexdigest()=="38793057a126e755fd965a218aa5c4f7d078dd78a3af4386a7cb6accfe679e60"
m=runpy.run_path(str(driver));d=m["Device"](pathlib.Path("/home/alex/.local/bin/adb"))
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(p,raw):
 with p.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def rp(leaf=None):
 with urllib.request.urlopen("http://127.0.0.1:38491/state",timeout=5) as r:assert r.status==200;raw=r.read(1048577)
 assert len(raw)<=1048576
 if leaf:save(root/leaf,raw)
 return json.loads(raw),raw
def ready():
 d.shell("input","-d","0","keyevent","KEYCODE_WAKEUP");time.sleep(1)
 pol=d.shell("dumpsys","window","policy");assert re.findall(r"^\s*secure=(true|false)\s*$",pol,re.M)==["false"]
 showing=re.findall(r"^\s*showing=(true|false)\s*$",pol,re.M);assert showing in (["true"],["false"])
 if showing==["false"]:return False
 def gate():
  w=d.shell("dumpsys","window");p=d.shell("dumpsys","window","policy");f=[x for x in w.splitlines() if "mCurrentFocus=Window{" in x]
  assert re.findall(r"mTopFocusedDisplayId=(\d+)",w)==["0"] and len(f)==1 and re.search(r"mCurrentFocus=Window\{[0-9a-f]+ u0 NotificationShade\}",f[0])
  assert re.findall(r"^\s*secure=(true|false)\s*$",p,re.M)==["false"] and re.findall(r"^\s*showing=(true|false)\s*$",p,re.M)==["true"]
 gate();r=d.adb_call("exec-out","uiautomator","dump","--compressed","/dev/tty",timeout=25);start=r.stdout.find(b"<hierarchy");end=r.stdout.find(b"</hierarchy>");assert r.returncode==0 and start>=0 and end>start
 nodes=list(ET.fromstring(r.stdout[start:end+len(b"</hierarchy>")]).iter("node"));assert nodes and all(n.get("package")=="com.android.systemui" for n in nodes)
 ids={"com.android.systemui:id/keyguard_root_view","com.android.systemui:id/device_entry_icon_view","com.android.systemui:id/keyguard_indication_text_bottom"};assert all(sum(n.get("resource-id")==key for n in nodes)==1 for key in ids)
 roots=[n for n in nodes if n.get("resource-id")=="com.android.systemui:id/keyguard_root_view"];q=re.fullmatch(r"\[0,0\]\[(\d+),(\d+)\]",roots[0].get("bounds",""));assert q;w,h=map(int,q.groups());assert 400<=w<=4000 and 700<=h<=5000
 gate();d.shell("input","-d","0","swipe",w//2,h*4//5,w//2,h//5,350);time.sleep(1)
 p=d.shell("dumpsys","window","policy");assert re.findall(r"^\s*showing=(true|false)\s*$",p,re.M)==["false"]
 return True

events=[];case=None
def phase(step,allow_observation_refusal=False):
 r=subprocess.run(["/usr/bin/python3","-B",str(runner),"--case",case,"--steps",json.dumps([step])],capture_output=True,timeout=260);assert len(r.stdout)<262144 and not r.stderr
 parsed=[json.loads(line) for line in r.stdout.splitlines()];assert len(parsed)==1;e=parsed[0];events.append(e)
 print(json.dumps({"case":case,"phase":e["phase"],"exit_code":e["exit_code"],"started_unix_ns":e["started_unix_ns"],"finished_unix_ns":e["finished_unix_ns"],"stdout_sha256":e["stdout_sha256"],"error":e["result"].get("error"),"foreground":e["result"].get("foreground"),"texts":[n.get("text") for n in e["result"].get("nodes",[]) if n.get("text")]},sort_keys=True),flush=True)
 if r.returncode and not (allow_observation_refusal and e["result"].get("error") in ("focused_window_unavailable","foreground_changed_during_ui_read")):raise RuntimeError("phase_refused")
 time.sleep(0.65);return e["result"]
def inspect():
 deadline=time.monotonic()+8
 while True:
  result=phase({"phase":"inspect"},True)
  assert time.monotonic()<deadline
  if result.get("ok"):return result
def unlock():
 phase({"phase":"launch-provider"});phase({"phase":"input-master"});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"UNLOCK PUBLIC CREDENTIAL LIST"})
 deadline=time.monotonic()+20
 while True:
  r=inspect();texts=[n.get("text") for n in r.get("nodes",[])]
  assert time.monotonic()<deadline
  if "Unlocked public list: 1 passkeys; five minute limit" in texts:return time.monotonic_ns()
  assert "Verifying vault password" in texts
def complete_real_good_get(label):
 old,oldraw=rp(label+"-rp-before.public.json");start=time.monotonic_ns()
 phase({"phase":"launch-fixture"});phase({"phase":"tap","selector":"AUTHENTICATE WITH PASSKEY"})
 s=inspect();assert s["foreground"][0]=="com.android.credentialmanager" and any(n.get("text")=="继续" for n in s.get("nodes",[]))
 phase({"phase":"tap","selector":"继续"});phase({"phase":"input-master"});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"APPROVE PASSKEY OPERATION"})
 deadline=time.monotonic()+20
 while True:
  out=inspect();state,raw=rp()
  if out["foreground"][0]=="org.heptabao.passkey.fixture" and any(n.get("text")=="PASS: RP verified authentication" for n in out.get("nodes",[])) and state["counters"]["authentications"]==old["counters"]["authentications"]+1:break
  assert time.monotonic()<deadline
 assert state["credential_count"]==1 and state["credentials"][0]["credential_id"]==old["credentials"][0]["credential_id"] and state["credentials"][0]["public_key_sha256"]==old["credentials"][0]["public_key_sha256"]
 assert state["credentials"][0]["sign_count"]>old["credentials"][0]["sign_count"] and state["credentials"][0]["flags"]==29
 assert state["counters"]["rejected"]==old["counters"]["rejected"] and state["counters"]["registrations"]==old["counters"]["registrations"] and state["counters"]["options"]==old["counters"]["options"]+1 and time.monotonic_ns()-start<180_000_000_000
 save(root/(label+"-rp-after.public.json"),raw)
 proof={"schema":1,"scope":"actual_same_run_good_CM_RP_positive_control","before_sha256":sha(oldraw),"after_sha256":sha(raw),"before_credential":old["credentials"][0],"after_credential":state["credentials"][0],"cm_begin_to_observation_ns":time.monotonic_ns()-start,"finished_unix_ns":time.time_ns(),"is_additional_denominator_case":False}
 m["atomic"](root/(label+"-positive-control.public.json"),proof);return state,raw,proof
def finish(case,status,executed,before,braw,control,unlocked_ns,negative_started,error=None,platform_error=None):
 after,raw=rp();observed_ns=time.monotonic_ns()
 if status=="passed":
  assert 0<=observed_ns-negative_started<180_000_000_000 and 0<=observed_ns-unlocked_ns<300_000_000_000
  assert after["credentials"]==before["credentials"] and after["counters"]["options"]==before["counters"]["options"]+1 and all(after["counters"][k]==before["counters"][k] for k in ("authentications","registrations","verification_attempts","rejected"))
 save(root/(case+"-rp-after.public.json"),raw)
 ev={"schema":1,"case":case,"status":status,"executed":executed,"same_run_actual_positive_control":control,"rp_before_sha256":sha(braw) if braw else None,"rp_after_sha256":sha(raw),"rp_before":before,"rp_after":after,"platform_error":platform_error,"negative_begin_to_observation_ns":None if negative_started is None else observed_ns-negative_started,"unlock_to_observation_ns":None if unlocked_ns is None else observed_ns-unlocked_ns,"selection_limit_seconds":180,"public_index_limit_seconds":300,"counter_mutations_by_wrapper":0,"rp_submissions_by_wrapper":0,"events":[{"phase":e["phase"],"started_unix_ns":e["started_unix_ns"],"finished_unix_ns":e["finished_unix_ns"],"exit_code":e["exit_code"],"stdout_sha256":e["stdout_sha256"]} for e in events],"error":error,"finished_unix_ns":time.time_ns(),"production_qualified":False}
 p=root/(case+"-result.public.json");m["atomic"](p,ev);led=json.loads(m["private_file"](b/"case-results.public.json",1048576));row=next(x for x in led["cases"] if x["id"]==case);assert row["status"]=="missing";row.update({"status":status if executed else "blocked","executed":executed,"evidence":[{"path":str(p),"sha256":sha(p.read_bytes())}]})
 for k in ("passed","failed","blocked","missing"):led[k]=sum(x["status"]==k for x in led["cases"])
 led["executed"]=sum(x["executed"] for x in led["cases"]);m["atomic"](b/"case-results.public.json",led)
 print(json.dumps({"case":case,"status":status,"result_sha256":sha(p.read_bytes()),"platform_error":platform_error,"rp_accepted_sign_count":after["credentials"][0]["sign_count"],"counts":{k:led[k] for k in ("passed","failed","blocked","missing","executed")}},sort_keys=True),flush=True)
for case in ["G02","G03","G04","G05","G06"]:
 events=[];before=None;braw=None;control=None;unlocked_ns=None;negative_started=None;executed=False;platform_error=None
 assert not (root/(case+"-workflow.intent.public.json")).exists() and not (root/(case+"-result.public.json")).exists()
 m["atomic"](root/(case+"-workflow.intent.public.json"),{"schema":1,"case":case,"scope":"frozen_CM_guard_with_current_real_positive_control","created_unix_ns":time.time_ns()})
 try:
  ready();unlocked_ns=time.monotonic_ns();unlock();before,braw,control=complete_real_good_get(case+"-control")
  if case=="G05":
   result=phase({"phase":"wrong-certificate"});assert result["installed_sha256"]=="7182763885b80e8d54a5c40c3e3ff5439d85a3bc125b80b59937442c011e8e90"
  if case=="G03":
   phase({"phase":"launch-provider"});phase({"phase":"tap","selector":"LOCK NOW"});locked=inspect();assert locked["foreground"][0]=="org.heptabao.passkey.preview" and any(n.get("text")=="Locked" for n in locked.get("nodes",[]))
  # The eligibility control and negative request stay inside the same fresh index interval.
  phase({"phase":"launch-decoy" if case=="G06" else "launch-fixture"})
  before,braw=rp(case+"-negative-rp-before.public.json")
  negative_started=time.monotonic_ns();phase({"phase":"tap","selector":"REJECT A WRONG RP TARGET" if case=="G04" else "AUTHENTICATE WITH PASSKEY"});executed=True
  if case in ("G02","G07"):
   s=inspect();assert s["foreground"][0]=="com.android.credentialmanager" and any(n.get("text")=="继续" for n in s.get("nodes",[]))
   phase({"phase":"tap","selector":"继续"});op=inspect();assert op["foreground"]==["org.heptabao.passkey.preview","org.heptabao.passkey.preview.OperationActivity"]
   if case=="G02":phase({"phase":"input-master","wrong":True});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"APPROVE PASSKEY OPERATION"})
   else:phase({"phase":"back"})
  deadline=time.monotonic()+25
  while True:
   out=inspect();texts=[n.get("text") for n in out.get("nodes",[])]
   platform=[t for t in texts if isinstance(t,str) and t.startswith("platform_rejected\n")]
   if out["foreground"][0]==("org.heptabao.passkey.decoy" if case=="G06" else "org.heptabao.passkey.fixture") and len(platform)==1:platform_error=platform[0];break
   assert time.monotonic()<deadline
  after,raw=rp();assert after["revision"]>before["revision"] and after["counters"]["options"]==before["counters"]["options"]+1
  assert after["credentials"]==before["credentials"] and all(after["counters"][k]==before["counters"][k] for k in ("authentications","registrations","verification_attempts","rejected"))
  assert time.monotonic_ns()-negative_started<180_000_000_000 and time.monotonic_ns()-unlocked_ns<300_000_000_000
  # Concrete platform callback type must match the expected refusal family.
  expected="android.credentials.GetCredentialException.TYPE_USER_CANCELED" if case in ("G02","G07") else "android.credentials.GetCredentialException.TYPE_NO_CREDENTIAL"
  assert platform_error=="platform_rejected\n"+expected
  if case=="G05":
   restored=phase({"phase":"good-certificate"});assert restored["installed_sha256"]=="b0d266ce40939a74822a3bd285895063fb938b93fd1c007c31b2a309abd52f7f"
  finish(case,"passed",executed,before,braw,control,unlocked_ns,negative_started,platform_error=platform_error)
 except Exception as error:
  finish(case,"failed",executed,before,braw,control,unlocked_ns,negative_started,type(error).__name__ if type(error).__name__ in ("AssertionError","RuntimeError","TimeoutExpired") else "closed_error",platform_error);raise SystemExit(1)
