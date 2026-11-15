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
  assert time.monotonic()<deadline
  if out["foreground"][0]=="org.heptabao.passkey.fixture" and any(n.get("text")=="PASS: RP verified authentication" for n in out.get("nodes",[])) and state["counters"]["authentications"]==old["counters"]["authentications"]+1:break
 assert state["credential_count"]==1 and state["credentials"][0]["credential_id"]==old["credentials"][0]["credential_id"] and state["credentials"][0]["public_key_sha256"]==old["credentials"][0]["public_key_sha256"]
 assert state["credentials"][0]["sign_count"]>old["credentials"][0]["sign_count"] and state["credentials"][0]["flags"]==29
 assert state["counters"]["rejected"]==old["counters"]["rejected"] and state["counters"]["registrations"]==old["counters"]["registrations"] and state["counters"]["options"]==old["counters"]["options"]+1 and time.monotonic_ns()-start<180_000_000_000
 save(root/(label+"-rp-after.public.json"),raw)
 proof={"schema":1,"scope":"actual_same_run_good_CM_RP_positive_control","before_sha256":sha(oldraw),"after_sha256":sha(raw),"before_credential":old["credentials"][0],"after_credential":state["credentials"][0],"cm_begin_to_observation_ns":time.monotonic_ns()-start,"finished_unix_ns":time.time_ns(),"is_additional_denominator_case":False}
 m["atomic"](root/(label+"-positive-control.public.json"),proof);return state,raw,proof

case="G07";LABEL="G07";events=[];negative_started=None;index_started=None;executed=False;control=None;before=None;braw=None
ledger=json.loads(m["private_file"](b/"case-results.public.json",1048576));assert len(ledger["cases"])==18
assert next(x for x in ledger["cases"] if x["id"]==case)["status"]=="missing"
assert not (root/"G07-workflow.intent.public.json").exists() and not (root/"G07-result.public.json").exists()
declaration={"schema":1,"case":case,"scope":"fresh_full_eighteen_same_request_double_Back_cancellation","profile_public_sha256":"b6b7754bad0e34cf55b0c2635683b03093555fa5d3f096533ee36b3e02eec55b","selection_limit_seconds":180,"index_limit_seconds":300,"maximum_provider_Back_inputs":1,"maximum_same_system_chooser_Back_inputs":1,"unknown_input_result_is_never_retried":True,"created_unix_ns":time.time_ns()}
m["atomic"](root/"G07-workflow.intent.public.json",declaration)
def wait_screen(target,required_text):
 deadline=time.monotonic()+8
 while True:
  result=inspect()
  assert time.monotonic()<deadline
  if result["foreground"]==target and any(n.get("text")==required_text for n in result.get("nodes",[])):return result
def record(status,error=None,final_observation=None):
 if final_observation is None:
  after,raw=rp();observed_monotonic_ns=time.monotonic_ns()
 else:after,raw,observed_monotonic_ns=final_observation
 elapsed=None if negative_started is None else observed_monotonic_ns-negative_started;index_elapsed=None if index_started is None else observed_monotonic_ns-index_started
 if status=="passed":
  assert elapsed is not None and 0<=elapsed<180_000_000_000 and index_elapsed is not None and 0<=index_elapsed<300_000_000_000
  assert after["credentials"]==before["credentials"] and after["counters"]["options"]==before["counters"]["options"]+1 and after["revision"]==before["revision"]+1
  assert all(after["counters"][k]==before["counters"][k] for k in ("verification_attempts","authentications","registrations","rejected")) and provider_backs==chooser_backs==1
 save(root/(LABEL+"-rp-after.public.json"),raw)
 result={"schema":1,"case":case,"scope":"fresh_full_eighteen_G07_cancellation","status":status,"executed":executed,"fresh_real_positive_control":control,"negative_before_sha256":sha(braw) if braw else None,"negative_after_sha256":sha(raw),"rp_before":before,"rp_after":after,"negative_begin_to_final_observation_ns":elapsed,"index_start_before_unlock_to_final_observation_ns":index_elapsed,"selection_limit_seconds":180,"index_limit_seconds":300,"same_ceremony_options_sha256":ceremony,"provider_Back_inputs":provider_backs,"system_chooser_Back_inputs":chooser_backs,"no_task_clear_between_negative_start_and_callback":True,"unknown_input_retry_count":0,"error":error,"events":[{"phase":e["phase"],"started_unix_ns":e["started_unix_ns"],"finished_unix_ns":e["finished_unix_ns"],"exit_code":e["exit_code"],"stdout_sha256":e["stdout_sha256"]} for e in events],"finished_unix_ns":time.time_ns(),"production_qualified":False}
 p=root/"G07-result.public.json";assert not p.exists();m["atomic"](p,result)
 led=json.loads(m["private_file"](b/"case-results.public.json",1048576));row=next(x for x in led["cases"] if x["id"]==case);assert row["status"]=="missing";row.update({"status":status if executed else "blocked","executed":executed,"evidence":[{"path":str(p),"sha256":sha(p.read_bytes())}]})
 for key in ("passed","failed","blocked","missing"):led[key]=sum(x["status"]==key for x in led["cases"])
 led["executed"]=sum(x["executed"] for x in led["cases"]);m["atomic"](b/"case-results.public.json",led)
 print(json.dumps({"case":case,"status":status,"result_sha256":sha(p.read_bytes()),"negative_elapsed_seconds":None if elapsed is None else elapsed/1e9,"index_elapsed_seconds":None if index_elapsed is None else index_elapsed/1e9,"counts":{k:led[k] for k in ("passed","failed","blocked","missing","executed")}},sort_keys=True),flush=True)
provider_backs=0;chooser_backs=0;ceremony=None
try:
 ready();prior_screen=inspect();assert prior_screen["foreground"] in (["org.heptabao.passkey.preview","org.heptabao.passkey.preview.HomeActivity"],["org.heptabao.passkey.fixture","org.heptabao.passkey.fixture.FixtureActivity"])
 assert d.package_hash(m["PROVIDER"])=="b16e82916330fac6909f82696089798c3ec76d7b4058fe9290e7e841b9e00459" and d.package_hash(m["FIXTURE"])=="b0d266ce40939a74822a3bd285895063fb938b93fd1c007c31b2a309abd52f7f"
 index_started=time.monotonic_ns();unlock();before,braw,control=complete_real_good_get(LABEL+"-control")
 phase({"phase":"launch-fixture"});before,braw=rp(LABEL+"-negative-rp-before.public.json")
 negative_started=time.monotonic_ns();phase({"phase":"tap","selector":"AUTHENTICATE WITH PASSKEY"});executed=True
 wait_screen(["com.android.credentialmanager","com.android.credentialmanager.CredentialSelectorActivity"],"继续")
 phase({"phase":"tap","selector":"继续"});wait_screen(["org.heptabao.passkey.preview","org.heptabao.passkey.preview.OperationActivity"],"APPROVE PASSKEY OPERATION")
 state,rstate=rp();assert state["counters"]["options"]==before["counters"]["options"]+1 and state["credentials"]==before["credentials"] and all(state["counters"][k]==before["counters"][k] for k in ("verification_attempts","authentications","registrations","rejected"))
 raw_state=m["private_file"](b/"rp-r9/state.public.json",8*1024*1024);parsed=json.loads(raw_state);added=[e for e in parsed["events"] if e["sequence"]>before["revision"]];assert len(added)==1 and added[0]["kind"]=="options_issued" and re.fullmatch(r"[0-9a-f]{64}",added[0]["ceremony_sha256"]);ceremony=added[0]["ceremony_sha256"]
 m["atomic"](root/(LABEL+"-ceremony-binding.public.json"),{"schema":1,"source_sha256":"386de84bb5335f21998a000b4a1267eaa17fadbde1e1753d5df1c30325709a63","actual_new_options_event":added[0],"state_sha256":sha(raw_state),"observed_unix_ns":time.time_ns()})
 foreground,nodes=d.ui();assert foreground==("org.heptabao.passkey.preview","org.heptabao.passkey.preview.OperationActivity") and any(n.get("text")=="APPROVE PASSKEY OPERATION" for n in nodes)
 provider_backs+=1;phase({"phase":"back"})
 wait_screen(["com.android.credentialmanager","com.android.credentialmanager.CredentialSelectorActivity"],"继续")
 _,same=rp();assert same==rstate
 foreground,nodes=d.ui();assert foreground==("com.android.credentialmanager","com.android.credentialmanager.CredentialSelectorActivity") and any(n.get("text")=="继续" for n in nodes)
 chooser_backs+=1;phase({"phase":"back"})
 wait_screen(["org.heptabao.passkey.fixture","org.heptabao.passkey.fixture.FixtureActivity"],"platform_rejected\nandroid.credentials.GetCredentialException.TYPE_USER_CANCELED")
 after,raw=rp();assert after["credentials"]==before["credentials"] and after["counters"]["options"]==before["counters"]["options"]+1 and after["revision"]==before["revision"]+1
 assert all(after["counters"][k]==before["counters"][k] for k in ("verification_attempts","authentications","registrations","rejected"))
 assert time.monotonic_ns()-negative_started<180_000_000_000 and time.monotonic_ns()-index_started<300_000_000_000 and provider_backs==chooser_backs==1
 record("passed",final_observation=(after,raw,time.monotonic_ns()))
except Exception as error:
 record("failed",type(error).__name__ if type(error).__name__ in ("AssertionError","RuntimeError","TimeoutExpired") else "closed_error");raise SystemExit(1)
