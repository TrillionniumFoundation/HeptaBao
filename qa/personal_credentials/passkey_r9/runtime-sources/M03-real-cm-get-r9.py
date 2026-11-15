import pathlib,os,json,re,hashlib,runpy,time,subprocess,xml.etree.ElementTree as ET,urllib.request
os.umask(0o077);b=pathlib.Path("/home/alex/HeptaBaoPasskey-20261106-r9");root=b/"live-r9";driver=b/"passkey_live.r9.py";runner=b/"run_phases.input-r9.public.py"
assert hashlib.sha256(driver.read_bytes()).hexdigest()=="e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd" and hashlib.sha256(runner.read_bytes()).hexdigest()=="38793057a126e755fd965a218aa5c4f7d078dd78a3af4386a7cb6accfe679e60"
m=runpy.run_path(str(driver));assert not (root/"M03-result.public.json").exists() and not (root/"M03-workflow.intent.public.json").exists();d=m["Device"](pathlib.Path("/home/alex/.local/bin/adb"));events=[];case_started=False;cm_started=None
ledger=json.loads(m["private_file"](b/"case-results.public.json",1048576));assert next(x for x in ledger["cases"] if x["id"]=="M02")["status"]=="passed"
m["atomic"](root/"M03-workflow.intent.public.json",{"schema":1,"case":"M03","scope":"real_platform_cm_get_independent_rp","created_unix_ns":time.time_ns()})
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

def rp_snapshot(name):
 with urllib.request.urlopen("http://127.0.0.1:38491/state",timeout=5) as r:
  assert r.status==200;raw=r.read(1048577)
 assert len(raw)<=1048576;state=json.loads(raw)
 if name:
  p=root/name
  with p.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
  fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 return state,raw
before,before_raw=rp_snapshot("M03-rp-before.public.json");assert before["credential_count"]==1 and before["credentials"][0]["sign_count"]==0 and before["counters"]["authentications"]==0
def phase(step,allow_observation_refusal=False):
 global case_started,cm_started
 if step.get("selector")=="AUTHENTICATE WITH PASSKEY":cm_started=time.monotonic_ns()
 r=subprocess.run(["/usr/bin/python3","-B",str(runner),"--case","M03","--steps",json.dumps([step])],capture_output=True,timeout=260);assert len(r.stdout)<262144 and not r.stderr
 parsed=[json.loads(line) for line in r.stdout.splitlines()];assert len(parsed)==1;e=parsed[0];events.append(e);print(json.dumps(e,sort_keys=True),flush=True)
 if step.get("selector")=="AUTHENTICATE WITH PASSKEY" and r.returncode==0:case_started=True
 if r.returncode and not (allow_observation_refusal and e["result"].get("error") in ("focused_window_unavailable","foreground_changed_during_ui_read")):raise RuntimeError("phase_refused")
 time.sleep(0.7);return e["result"]
def inspect():
 deadline=time.monotonic()+8
 while True:
  result=phase({"phase":"inspect"},True)
  if result.get("ok"):return result
  assert time.monotonic()<deadline
def record(status,error=None):
 after,raw=rp_snapshot("M03-rp-after.public.json")
 elapsed=None if cm_started is None else time.monotonic_ns()-cm_started
 ev={"schema":1,"case":"M03","status":status,"executed":case_started or after["revision"]>before["revision"],"frozen_rp_sha256":"386de84bb5335f21998a000b4a1267eaa17fadbde1e1753d5df1c30325709a63","rp_before_sha256":hashlib.sha256(before_raw).hexdigest(),"rp_after_sha256":hashlib.sha256(raw).hexdigest(),"rp_after":after,"cm_begin_to_observation_ns":elapsed,"challenge_and_ticket_limit_seconds":180,"independent_rp_submissions_by_wrapper":0,"events":[{"phase":e["phase"],"started_unix_ns":e["started_unix_ns"],"finished_unix_ns":e["finished_unix_ns"],"exit_code":e["exit_code"],"stdout_sha256":e["stdout_sha256"]} for e in events],"error":error,"finished_unix_ns":time.time_ns(),"production_qualified":False}
 p=root/"M03-result.public.json";m["atomic"](p,ev)
 led=json.loads(m["private_file"](b/"case-results.public.json",1048576));row=next(x for x in led["cases"] if x["id"]=="M03");assert row["status"]=="missing";row.update({"status":status if ev["executed"] else "missing","executed":ev["executed"],"evidence":[{"path":str(p),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}]});led["credential_manager_exercised"]=ev["executed"]
 for state in ("passed","failed","blocked","missing"):led[state]=sum(x["status"]==state for x in led["cases"])
 led["executed"]=sum(x["executed"] for x in led["cases"]);m["atomic"](b/"case-results.public.json",led)
 print(json.dumps({"case":"M03","status":status,"result_sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"rp_after":after,"elapsed_seconds":None if elapsed is None else elapsed/1e9,"counts":{k:led[k] for k in ("passed","failed","blocked","missing","executed")}},sort_keys=True),flush=True)
try:
 ready();phase({"phase":"launch-provider"});phase({"phase":"input-master"});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"UNLOCK PUBLIC CREDENTIAL LIST"})
 opened=inspect();assert any(n.get("text")=="Unlocked public list: 1 passkeys; five minute limit" for n in opened.get("nodes",[]))
 phase({"phase":"launch-fixture"});phase({"phase":"tap","selector":"AUTHENTICATE WITH PASSKEY"})
 selector=inspect();assert selector["foreground"][0]=="com.android.credentialmanager" and any(n.get("text")=="继续" for n in selector.get("nodes",[]))
 phase({"phase":"tap","selector":"继续"});phase({"phase":"input-master"});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"APPROVE PASSKEY OPERATION"})
 deadline=time.monotonic()+20
 while True:
  returned=inspect();after,raw=rp_snapshot(None)
  if returned["foreground"][0]=="org.heptabao.passkey.fixture" and after["credential_count"]==1 and after["counters"]["authentications"]==1:break
  assert time.monotonic()<deadline
 assert after["revision"]>before["revision"] and after["credentials"][0]["sign_count"]==1 and after["credentials"][0]["credential_id"]==before["credentials"][0]["credential_id"] and after["credentials"][0]["public_key_sha256"]==before["credentials"][0]["public_key_sha256"]
 assert after["counters"]["authentications"]==before["counters"]["authentications"]+1 and after["counters"]["registrations"]==1 and after["counters"]["rejected"]==before["counters"]["rejected"] and after["counters"]["options"]==before["counters"]["options"]+1
 assert after["credentials"][0]["flags"] & 13 == 13
 assert time.monotonic_ns()-cm_started<180_000_000_000
 record("passed")
except Exception as error:
 record("failed",type(error).__name__ if type(error).__name__ in ("AssertionError","RuntimeError","TimeoutExpired") else "closed_error");raise SystemExit(1)
