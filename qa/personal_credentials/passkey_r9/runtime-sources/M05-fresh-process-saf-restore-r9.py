import pathlib,os,json,re,hashlib,runpy,time,subprocess,xml.etree.ElementTree as ET,urllib.request
os.umask(0o077);b=pathlib.Path("/home/alex/HeptaBaoPasskey-20261106-r9");root=b/"live-r9";driver=b/"passkey_live.r9.py";runner=b/"run_phases.input-r9.public.py"
assert hashlib.sha256(driver.read_bytes()).hexdigest()=="e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd" and hashlib.sha256(runner.read_bytes()).hexdigest()=="38793057a126e755fd965a218aa5c4f7d078dd78a3af4386a7cb6accfe679e60"
import argparse
parser=argparse.ArgumentParser();parser.add_argument("--checkpoint-sha256",required=True);parser.add_argument("--reset-result-sha256",required=True);parser.add_argument("--completion-sha256",required=True);args=parser.parse_args()
assert all(re.fullmatch(r"[0-9a-f]{64}",x) for x in (args.checkpoint_sha256,args.reset_result_sha256,args.completion_sha256))
m=runpy.run_path(str(driver));assert not (root/"M05-result.public.json").exists() and not (root/"M05-workflow.intent.public.json").exists();d=m["Device"](pathlib.Path("/home/alex/.local/bin/adb"));events=[];master_entered=False;case_started=True;new_process=None;rp_after_sha=None
resetraw=m["private_file"](root/"provider-reset-M05-result.public.json",65536);wraw=m["private_file"](root/"provider-reset-M05-completion.public.json",65536);iraw=m["private_file"](root/"provider-reset-M05-intent.private.json",1048576)
assert hashlib.sha256(resetraw).hexdigest()==args.reset_result_sha256 and hashlib.sha256(wraw).hexdigest()==args.completion_sha256
reset=json.loads(resetraw);witness=json.loads(wraw)
assert reset["ok"] is True and reset["reset_completed"] is True and reset["pm_clear_exact_success_observed"] is True and reset["old_provider_process_absence_observed"] is True and reset["all_three_settings_unchanged"] is True and reset["apk_unchanged"] is True
assert witness["case_id"]=="M05" and witness["reset_id"]=="M05-reset-1" and witness["result_persisted_before_witness"] is True and witness["result_sha256"]==hashlib.sha256(resetraw).hexdigest() and witness["intent_sha256"]==hashlib.sha256(iraw).hexdigest()==reset["intent_sha256"]
cpraw=m["private_file"](root/"provider-reset-M05-checkpoint.private.json",65536);assert hashlib.sha256(cpraw).hexdigest()==args.checkpoint_sha256;cp=json.loads(cpraw)
backup="/sdcard/Download/HeptaBao-Passkey-QA-20261106-r9/HeptaBao-passkey-backup.hbv"
assert cp["recovery_backup"]["device_path"]==backup
assert reset["case_id"]==cp["case_id"]=="M05" and reset["input_sha256"]["checkpoint"]==args.checkpoint_sha256
assert reset["input_sha256"]["helper"]=="c3d7da8f20fd03b7463eb59ad846718bcae5cad1668972eb626a7fd368aa4d30" and reset["input_sha256"]["driver"]=="e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd"
assert reset["input_sha256"]["profile_source"]==cp["profile_source_sha256"]=="00e999af6c17c83fd81736fe8a8b5cda3553daaa6acf97fd652b7e6429751dd7"
assert reset["input_sha256"]["profile_public"]==cp["profile_public_sha256"]=="b6b7754bad0e34cf55b0c2635683b03093555fa5d3f096533ee36b3e02eec55b"
assert reset["input_sha256"]["build"]==cp["build_receipt_sha256"]=="97a6daec5bb7276b935498fb3c8501df9ecc57a118641cffb9f2df3ae6edd009"
assert reset["provider_apk_sha256"]==cp["provider_apk_sha256"]=="b16e82916330fac6909f82696089798c3ec76d7b4058fe9290e7e841b9e00459"
assert reset["device_sha256"]==cp["device_sha256"]==m["DEVICE_SHA256"] and reset["credential"]==cp["credential"]
assert reset["external_recovery_backup"]=={k:cp["recovery_backup"][k] for k in ("bytes","sha256")}
assert reset["rp_snapshot_sha256"]==reset["input_sha256"]["rp_snapshot"]==cp["rp_snapshot_sha256"]

assert d.shell("test","-f",backup)=="" and d.shell("test","!","-L",backup)=="" and int(d.shell("stat","-c","%s",backup))==cp["recovery_backup"]["bytes"] and d.shell("sha256sum",backup).split()[0]==cp["recovery_backup"]["sha256"]
m["atomic"](root/"M05-workflow.intent.public.json",{"schema":1,"case":"M05","scope":"ordinary_saf_restore_after_verified_os_app_data_reset","profile_sha256":"b6b7754bad0e34cf55b0c2635683b03093555fa5d3f096533ee36b3e02eec55b","backup_sha256":cp["recovery_backup"]["sha256"],"created_unix_ns":time.time_ns()})
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
 r=subprocess.run(["/usr/bin/python3","-B",str(runner),"--case","M05","--steps",json.dumps([step])],capture_output=True,timeout=260);assert len(r.stdout)<262144 and not r.stderr
 parsed=[json.loads(line) for line in r.stdout.splitlines()];assert len(parsed)==1;e=parsed[0];events.append(e);print(json.dumps(e,sort_keys=True),flush=True)
 if step.get("selector")=="CHOOSE ENCRYPTED VAULT FILE" and r.returncode==0:case_started=True
 if step["phase"]=="input-master" and r.returncode==0:master_entered=True
 if r.returncode:raise RuntimeError("phase_refused")
 time.sleep(0.8);return e["result"]
def record(status,error=None):
 evidence={"schema":1,"case":"M05","status":status,"executed":case_started,"ordinary_saf":True,"master_entered":master_entered,"input_boundary":"synthetic_only_adb_input_text_child_argv","events":[{"phase":e["phase"],"started_unix_ns":e["started_unix_ns"],"finished_unix_ns":e["finished_unix_ns"],"exit_code":e["exit_code"],"stdout_sha256":e["stdout_sha256"]} for e in events],"final_error":error,"observed_unlocked_public_count":1 if status=="passed" else None,"reset_result_sha256":args.reset_result_sha256,"completion_witness_sha256":args.completion_sha256,"new_process_observation":new_process,"rp_after_sha256":rp_after_sha,"private_inode_observed":False,"same_physical_device":True,"physical_device_migration":False,"finished_unix_ns":time.time_ns(),"phone_qualified":False,"production_qualified":False}
 path=root/"M05-result.public.json";m["atomic"](path,evidence)
 ledger=json.loads(m["private_file"](b/"case-results.public.json",1048576));row=next(x for x in ledger["cases"] if x["id"]=="M05");assert row["status"]=="missing";row.update({"status":status if case_started else "missing","executed":case_started,"evidence":[{"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}]});ledger["master_entered"]=master_entered;ledger["reset_executed"]=True
 for state in ("passed","failed","blocked","missing"):ledger[state]=sum(x["status"]==state for x in ledger["cases"])
 ledger["executed"]=sum(x["executed"] for x in ledger["cases"]);m["atomic"](b/"case-results.public.json",ledger);print(json.dumps({"case":"M05","status":status,"executed":case_started,"result_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"counts":{k:ledger[k] for k in ("passed","failed","blocked","missing","executed")}},sort_keys=True),flush=True)
try:
 swiped=ready();m["atomic"](root/"M05-screen-ready.public.json",{"schema":1,"ordinary_nonsecure_swipe_used":swiped,"no_setting_changed":True})
 phase({"phase":"launch-provider"})
 ps=d.adb_call("shell","pidof",m["PROVIDER"],allow_failure=True);assert ps.returncode==0 and ps.stderr==b"" and re.fullmatch(rb"[1-9][0-9]*(?: [1-9][0-9]*)*\n?",ps.stdout)
 new_process={"provider_pid_count":len(ps.stdout.split()),"pidof_stdout_sha256":hashlib.sha256(ps.stdout).hexdigest(),"observed_after_verified_old_process_absence":True,"reset_completed_unix_ns":reset["completed_unix_ns"],"observed_unix_ns":time.time_ns()}
 m["atomic"](root/"M05-new-process.public.json",new_process)
 for step in [{"phase":"tap","selector":"CHOOSE ENCRYPTED VAULT FILE"},{"phase":"tap","selector_kind":"description","selector":"显示根目录"},{"phase":"tap","selector":"下载"},{"phase":"tap","selector":"HeptaBao-Passkey-QA-20261106-r9"},{"phase":"tap","selector":"HeptaBao-passkey-backup.hbv"}]:phase(step)
 staged=phase({"phase":"inspect"});assert staged["foreground"]==["org.heptabao.passkey.preview","org.heptabao.passkey.preview.HomeActivity"]
 phase({"phase":"input-master"});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"IMPORT ENCRYPTED VAULT INTO A FRESH STORE"})
 deadline=time.monotonic()+20
 while True:
  final=phase({"phase":"inspect"});texts=[n.get("text") for n in final.get("nodes",[])];assert final["foreground"]==["org.heptabao.passkey.preview","org.heptabao.passkey.preview.HomeActivity"]
  if "Unlocked public list: 1 passkeys; five minute limit" in texts:break
  assert "Verifying vault password" in texts and time.monotonic()<deadline
 with urllib.request.urlopen("http://127.0.0.1:38491/state",timeout=5) as r:assert r.status==200;rpraw=r.read(1048577)
 assert rpraw==m["private_file"](root/"m05-rp-before.private.json",1048576);rp_after_sha=hashlib.sha256(rpraw).hexdigest()
 m["atomic"](root/"M05-rp-after.public.json",json.loads(rpraw))
 assert d.package_hash(m["PROVIDER"])=="b16e82916330fac6909f82696089798c3ec76d7b4058fe9290e7e841b9e00459"
 journal=json.loads(m["private_file"](root/"journal.private.json",8*1024*1024));assert {k:d.setting(k) for k in m["SETTING_KEYS"]}==journal["owned_settings"]
 record("passed")
except Exception as error:
 record("failed",type(error).__name__ if type(error).__name__ in ("AssertionError","RuntimeError","TimeoutExpired") else "closed_error")
 raise SystemExit(1)
