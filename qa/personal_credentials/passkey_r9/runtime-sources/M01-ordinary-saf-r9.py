import pathlib,os,json,re,hashlib,runpy,time,subprocess,xml.etree.ElementTree as ET
os.umask(0o077);b=pathlib.Path("/home/alex/HeptaBaoPasskey-20261106-r9");root=b/"live-r9";driver=b/"passkey_live.r9.py";runner=b/"run_phases.input-r9.public.py"
assert hashlib.sha256(driver.read_bytes()).hexdigest()=="e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd" and hashlib.sha256(runner.read_bytes()).hexdigest()=="38793057a126e755fd965a218aa5c4f7d078dd78a3af4386a7cb6accfe679e60"
m=runpy.run_path(str(driver));assert not (root/"M01-result.public.json").exists() and not (root/"M01-workflow.intent.public.json").exists();d=m["Device"](pathlib.Path("/home/alex/.local/bin/adb"));events=[];master_entered=False;case_started=False
m["atomic"](root/"M01-workflow.intent.public.json",{"schema":1,"case":"M01","scope":"ordinary_saf_and_real_password_ui","profile_sha256":"b6b7754bad0e34cf55b0c2635683b03093555fa5d3f096533ee36b3e02eec55b","seed_sha256":"bb527d9aa00987a243b378ac31eb15d2caf203e106348a8e1ed60cff7f674917","created_unix_ns":time.time_ns()})
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
def phase(step):
 global master_entered,case_started
 r=subprocess.run(["/usr/bin/python3","-B",str(runner),"--case","M01","--steps",json.dumps([step])],capture_output=True,timeout=260);assert len(r.stdout)<262144 and not r.stderr
 parsed=[json.loads(line) for line in r.stdout.splitlines()];assert len(parsed)==1;e=parsed[0];events.append(e);print(json.dumps(e,sort_keys=True),flush=True)
 if step.get("selector")=="CHOOSE ENCRYPTED VAULT FILE" and r.returncode==0:case_started=True
 if step["phase"]=="input-master" and r.returncode==0:master_entered=True
 if r.returncode:raise RuntimeError("phase_refused")
 time.sleep(0.8);return e["result"]
def record(status,error=None):
 evidence={"schema":1,"case":"M01","status":status,"executed":case_started,"ordinary_saf":True,"master_entered":master_entered,"input_boundary":"synthetic_only_adb_input_text_child_argv","events":[{"phase":e["phase"],"started_unix_ns":e["started_unix_ns"],"finished_unix_ns":e["finished_unix_ns"],"exit_code":e["exit_code"],"stdout_sha256":e["stdout_sha256"]} for e in events],"final_error":error,"observed_unlocked_public_count":0 if status=="passed" else None,"finished_unix_ns":time.time_ns(),"phone_qualified":False,"production_qualified":False}
 path=root/"M01-result.public.json";m["atomic"](path,evidence)
 ledger=json.loads(m["private_file"](b/"case-results.public.json",1048576));row=next(x for x in ledger["cases"] if x["id"]=="M01");assert row["status"]=="missing";row.update({"status":status if case_started else "missing","executed":case_started,"evidence":[{"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}]});ledger["master_entered"]=master_entered
 for state in ("passed","failed","blocked","missing"):ledger[state]=sum(x["status"]==state for x in ledger["cases"])
 ledger["executed"]=sum(x["executed"] for x in ledger["cases"]);m["atomic"](b/"case-results.public.json",ledger);print(json.dumps({"case":"M01","status":status,"executed":case_started,"result_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"counts":{k:ledger[k] for k in ("passed","failed","blocked","missing","executed")}},sort_keys=True),flush=True)
try:
 swiped=ready();m["atomic"](root/"M01-screen-ready.public.json",{"schema":1,"ordinary_nonsecure_swipe_used":swiped,"no_setting_changed":True})
 phase({"phase":"launch-provider"})
 for step in [{"phase":"tap","selector":"CHOOSE ENCRYPTED VAULT FILE"},{"phase":"tap","selector_kind":"description","selector":"显示根目录"},{"phase":"tap","selector":"下载"},{"phase":"tap","selector":"HeptaBao-Passkey-QA-20261106-r9"},{"phase":"tap","selector":"heptabao-passkey-qa-r9-seed.hbv"}]:phase(step)
 staged=phase({"phase":"inspect"});assert staged["foreground"]==["org.heptabao.passkey.preview","org.heptabao.passkey.preview.HomeActivity"]
 phase({"phase":"input-master"});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"IMPORT ENCRYPTED VAULT INTO A FRESH STORE"})
 deadline=time.monotonic()+20
 while True:
  final=phase({"phase":"inspect"});texts=[n.get("text") for n in final.get("nodes",[])];assert final["foreground"]==["org.heptabao.passkey.preview","org.heptabao.passkey.preview.HomeActivity"]
  if "Unlocked public list: 0 passkeys; five minute limit" in texts:break
  assert "Verifying vault password" in texts and time.monotonic()<deadline
 record("passed")
except Exception as error:
 record("failed",type(error).__name__ if type(error).__name__ in ("AssertionError","RuntimeError","TimeoutExpired") else "closed_error")
 raise SystemExit(1)
