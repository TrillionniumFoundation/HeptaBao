import pathlib,os,json,re,hashlib,runpy,time,subprocess,xml.etree.ElementTree as ET,urllib.request
os.umask(0o077);b=pathlib.Path("/home/alex/HeptaBaoPasskey-20261106-r9");root=b/"live-r9";driver=b/"passkey_live.r9.py";runner=b/"run_phases.input-r9.public.py"
assert hashlib.sha256(driver.read_bytes()).hexdigest()=="e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd" and hashlib.sha256(runner.read_bytes()).hexdigest()=="38793057a126e755fd965a218aa5c4f7d078dd78a3af4386a7cb6accfe679e60"
import argparse
parser=argparse.ArgumentParser();parser.add_argument("--checkpoint-sha256",required=True);parser.add_argument("--reset-result-sha256",required=True);parser.add_argument("--completion-sha256",required=True);args=parser.parse_args()
assert all(re.fullmatch(r"[0-9a-f]{64}",x) for x in (args.checkpoint_sha256,args.reset_result_sha256,args.completion_sha256))
m=runpy.run_path(str(driver));assert not (root/"G11-result.public.json").exists() and not (root/"G11-workflow.intent.public.json").exists();d=m["Device"](pathlib.Path("/home/alex/.local/bin/adb"));events=[];case_started=False;cm_started=None;rejection=None
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(p,raw):
 with p.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def rp(leaf=None):
 with urllib.request.urlopen("http://127.0.0.1:38491/state",timeout=5) as r:assert r.status==200;raw=r.read(1048577)
 assert len(raw)<=1048576
 if leaf:save(root/leaf,raw)
 return json.loads(raw),raw
resetraw=m["private_file"](root/"provider-reset-G11-result.public.json",65536);wraw=m["private_file"](root/"provider-reset-G11-completion.public.json",65536);iraw=m["private_file"](root/"provider-reset-G11-intent.private.json",1048576)
assert sha(resetraw)==args.reset_result_sha256 and sha(wraw)==args.completion_sha256
reset=json.loads(resetraw);witness=json.loads(wraw)
assert reset["ok"] is True and reset["reset_completed"] is True and reset["pm_clear_exact_success_observed"] is True and reset["old_provider_process_absence_observed"] is True and reset["all_three_settings_unchanged"] is True and reset["apk_unchanged"] is True
assert witness["case_id"]=="G11" and witness["reset_id"]=="G11-reset-1" and witness["result_persisted_before_witness"] is True and witness["result_sha256"]==sha(resetraw) and witness["intent_sha256"]==sha(iraw)==reset["intent_sha256"]
cpraw=m["private_file"](root/"provider-reset-G11-checkpoint.private.json",65536);assert sha(cpraw)==args.checkpoint_sha256;cp=json.loads(cpraw)
assert reset["case_id"]==cp["case_id"]=="G11" and reset["input_sha256"]["checkpoint"]==args.checkpoint_sha256
assert reset["input_sha256"]["helper"]=="c3d7da8f20fd03b7463eb59ad846718bcae5cad1668972eb626a7fd368aa4d30" and reset["input_sha256"]["driver"]=="e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd"
assert reset["input_sha256"]["profile_source"]==cp["profile_source_sha256"]=="00e999af6c17c83fd81736fe8a8b5cda3553daaa6acf97fd652b7e6429751dd7"
assert reset["input_sha256"]["profile_public"]==cp["profile_public_sha256"]=="b6b7754bad0e34cf55b0c2635683b03093555fa5d3f096533ee36b3e02eec55b"
assert reset["input_sha256"]["build"]==cp["build_receipt_sha256"]=="97a6daec5bb7276b935498fb3c8501df9ecc57a118641cffb9f2df3ae6edd009"
assert reset["provider_apk_sha256"]==cp["provider_apk_sha256"]=="b16e82916330fac6909f82696089798c3ec76d7b4058fe9290e7e841b9e00459"
assert reset["device_sha256"]==cp["device_sha256"]==m["DEVICE_SHA256"] and reset["credential"]==cp["credential"]
assert reset["external_recovery_backup"]=={k:cp["recovery_backup"][k] for k in ("bytes","sha256")}
assert reset["rp_snapshot_sha256"]==reset["input_sha256"]["rp_snapshot"]==cp["rp_snapshot_sha256"]

for obj in (cp["recovery_backup"],cp["stale_input"]["backup"]):
 path=obj["device_path"];assert d.shell("test","-f",path)=="" and d.shell("test","!","-L",path)=="" and int(d.shell("stat","-c","%s",path))==obj["bytes"] and d.shell("sha256sum",path).split()[0]==obj["sha256"]
before,before_raw=rp("G11-rp-before.public.json");assert before_raw==m["private_file"](root/"g11-rp-before.private.json",1048576) and before["credentials"][0]["sign_count"]==2 and before["counters"]["authentications"]==2
state_before_raw=m["private_file"](b/"rp-r9/state.public.json",8*1024*1024);state_before=json.loads(state_before_raw)
assert state_before["revision"]==before["revision"] and state_before["events"][-1]["sequence"]==before["revision"]
m["atomic"](root/"G11-workflow.intent.public.json",{"schema":1,"case":"G11","scope":"actual_stale_SAF_restore_then_real_CM_get_no_counter_editing","checkpoint_sha256":sha(cpraw),"reset_result_sha256":sha(resetraw),"completion_sha256":sha(wraw),"stale_backup":cp["stale_input"]["backup"],"current_recovery_backup":cp["recovery_backup"],"rp_before_sha256":sha(before_raw),"rp_state_before_sha256":sha(state_before_raw),"rp_before_revision":before["revision"],"created_unix_ns":time.time_ns()})
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

def phase(step,allow_observation_refusal=False):
 global case_started,cm_started
 if step.get("selector")=="AUTHENTICATE WITH PASSKEY":cm_started=time.monotonic_ns()
 r=subprocess.run(["/usr/bin/python3","-B",str(runner),"--case","G11","--steps",json.dumps([step])],capture_output=True,timeout=260);assert len(r.stdout)<262144 and not r.stderr
 parsed=[json.loads(line) for line in r.stdout.splitlines()];assert len(parsed)==1;e=parsed[0];events.append(e)
 print(json.dumps({"phase":e["phase"],"exit_code":e["exit_code"],"started_unix_ns":e["started_unix_ns"],"finished_unix_ns":e["finished_unix_ns"],"stdout_sha256":e["stdout_sha256"],"error":e["result"].get("error"),"foreground":e["result"].get("foreground"),"texts":[n.get("text") for n in e["result"].get("nodes",[]) if n.get("text")]},sort_keys=True),flush=True)
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
 after,raw=rp("G11-rp-after.public.json");elapsed=None if cm_started is None else time.monotonic_ns()-cm_started
 ev={"schema":1,"case":"G11","status":status,"executed":case_started or after["revision"]>before["revision"],"checkpoint_sha256":sha(cpraw),"reset_result_sha256":sha(resetraw),"completion_sha256":sha(wraw),"stale_backup_sha256":cp["stale_input"]["backup"]["sha256"],"latest_recovery_backup_sha256":cp["recovery_backup"]["sha256"],"rp_before_sha256":sha(before_raw),"rp_after_sha256":sha(raw),"rp_before":before,"rp_after":after,"actual_rp_rejection":rejection,"cm_begin_to_observation_ns":elapsed,"challenge_and_ticket_limit_seconds":180,"counter_mutations_by_wrapper":0,"rp_submissions_by_wrapper":0,"events":[{"phase":e["phase"],"started_unix_ns":e["started_unix_ns"],"finished_unix_ns":e["finished_unix_ns"],"exit_code":e["exit_code"],"stdout_sha256":e["stdout_sha256"]} for e in events],"error":error,"finished_unix_ns":time.time_ns(),"production_qualified":False}
 p=root/"G11-result.public.json";m["atomic"](p,ev);led=json.loads(m["private_file"](b/"case-results.public.json",1048576));row=next(x for x in led["cases"] if x["id"]=="G11");assert row["status"]=="missing";row.update({"status":status if ev["executed"] else "blocked","executed":ev["executed"],"evidence":[{"path":str(p),"sha256":sha(p.read_bytes())}]})
 for state in ("passed","failed","blocked","missing"):led[state]=sum(x["status"]==state for x in led["cases"])
 led["executed"]=sum(x["executed"] for x in led["cases"]);m["atomic"](b/"case-results.public.json",led)
 print(json.dumps({"case":"G11","status":status,"result_sha256":sha(p.read_bytes()),"rp_after":after,"rejection":rejection,"elapsed_seconds":None if elapsed is None else elapsed/1e9,"counts":{k:led[k] for k in ("passed","failed","blocked","missing","executed")}},sort_keys=True),flush=True)
try:
 ready();phase({"phase":"launch-provider"})
 ps=d.adb_call("shell","pidof",m["PROVIDER"],allow_failure=True);assert ps.returncode==0 and ps.stderr==b"" and re.fullmatch(rb"[1-9][0-9]*(?: [1-9][0-9]*)*\n?",ps.stdout)
 m["atomic"](root/"G11-new-process.public.json",{"provider_pid_count":len(ps.stdout.split()),"pidof_stdout_sha256":sha(ps.stdout),"observed_after_verified_old_process_absence":True,"reset_completed_unix_ns":reset["completed_unix_ns"],"observed_unix_ns":time.time_ns()})
 for step in [{"phase":"tap","selector":"CHOOSE ENCRYPTED VAULT FILE"},{"phase":"tap","selector_kind":"description","selector":"显示根目录"},{"phase":"tap","selector":"下载"},{"phase":"tap","selector":"HeptaBao-Passkey-QA-20261106-r9"},{"phase":"tap","selector":"HeptaBao-passkey-backup.hbv"}]:phase(step)
 staged=inspect();assert any(n.get("text")=="Ciphertext staged; enter password and import into a fresh store" for n in staged.get("nodes",[]))
 phase({"phase":"input-master"});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"IMPORT ENCRYPTED VAULT INTO A FRESH STORE"})
 deadline=time.monotonic()+20
 while True:
  final=inspect();assert final["foreground"]==["org.heptabao.passkey.preview","org.heptabao.passkey.preview.HomeActivity"];texts=[n.get("text") for n in final.get("nodes",[])]
  if "Unlocked public list: 1 passkeys; five minute limit" in texts:break
  assert "Verifying vault password" in texts and time.monotonic()<deadline
 _,unchanged=rp();assert unchanged==before_raw
 m["atomic"](root/"G11-stale-restored.public.json",{"schema":1,"ordinary_saf_stale_restore_observed":True,"stale_backup_sha256":cp["stale_input"]["backup"]["sha256"],"rp_unchanged_before_real_get":True,"case_passed":False,"observed_unix_ns":time.time_ns()})
 phase({"phase":"launch-fixture"});phase({"phase":"tap","selector":"AUTHENTICATE WITH PASSKEY"})
 selector=inspect();assert selector["foreground"][0]=="com.android.credentialmanager" and any(n.get("text")=="继续" for n in selector.get("nodes",[]))
 phase({"phase":"tap","selector":"继续"});phase({"phase":"input-master"});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"APPROVE PASSKEY OPERATION"})
 deadline=time.monotonic()+20
 while True:
  returned=inspect();after,raw=rp()
  if returned["foreground"][0]=="org.heptabao.passkey.fixture" and any(n.get("text")=="rp_verification_failed" for n in returned.get("nodes",[])) and after["counters"]["rejected"]==before["counters"]["rejected"]+1:break
  assert time.monotonic()<deadline
 assert after["credentials"]==before["credentials"] and after["counters"]["authentications"]==before["counters"]["authentications"] and after["counters"]["registrations"]==1
 assert after["counters"]["options"]==before["counters"]["options"]+1 and after["counters"]["verification_attempts"]==before["counters"]["verification_attempts"]+1
 state_after_raw=m["private_file"](b/"rp-r9/state.public.json",8*1024*1024);state_after=json.loads(state_after_raw);assert state_after["revision"]==after["revision"] and state_after["last_run_id"]==state_before["last_run_id"]
 added=[e for e in state_after["events"] if e["sequence"]>before["revision"]];rejects=[e for e in added if e["kind"]=="verification_rejected"]
 assert len(rejects)==1 and rejects[0]["code"]=="counter_rollback_or_replay" and re.fullmatch(r"[0-9a-f]{64}",rejects[0]["ceremony_sha256"]) and rejects[0]["source_sha256"]=="386de84bb5335f21998a000b4a1267eaa17fadbde1e1753d5df1c30325709a63"
 rejection=rejects[0];m["atomic"](root/"G11-rp-rejection-projection.public.json",{"schema":1,"scope":"closed_public_RP_event_projection_from_real_own_state","state_file_sha256":sha(state_after_raw),"rp_state_revision":state_after["revision"],"rp_source_sha256":"386de84bb5335f21998a000b4a1267eaa17fadbde1e1753d5df1c30325709a63","new_events":added,"accepted_credential_before":before["credentials"][0],"accepted_credential_after":after["credentials"][0],"counter_not_manually_modified":True})
 assert time.monotonic_ns()-cm_started<180_000_000_000
 record("passed")
except Exception as error:
 record("failed",type(error).__name__ if type(error).__name__ in ("AssertionError","RuntimeError","TimeoutExpired") else "closed_error");raise SystemExit(1)
