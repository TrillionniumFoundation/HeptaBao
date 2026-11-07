import pathlib,os,json,re,hashlib,runpy,time,subprocess,xml.etree.ElementTree as ET,urllib.request,fcntl
os.umask(0o077);b=pathlib.Path("/home/alex/HeptaBaoPasskey-20261106-r9");root=b/"live-r9";driver=b/"passkey_live.r9.py";runner=b/"run_phases.input-r9.public.py"
assert hashlib.sha256(driver.read_bytes()).hexdigest()=="e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd" and hashlib.sha256(runner.read_bytes()).hexdigest()=="38793057a126e755fd965a218aa5c4f7d078dd78a3af4386a7cb6accfe679e60"
m=runpy.run_path(str(driver));assert not (root/"G11_RECOVERY_EXPORT-result.public.json").exists() and not (root/"G11_RECOVERY_EXPORT-workflow.intent.public.json").exists();d=m["Device"](pathlib.Path("/home/alex/.local/bin/adb"));events=[];case_started=False;destination="/sdcard/Download/HeptaBao-Passkey-QA-20261106-r9/latest-recovery/HeptaBao-passkey-backup.hbv"
ledger=json.loads(m["private_file"](b/"case-results.public.json",1048576));assert next(x for x in ledger["cases"] if x["id"]=="M06")["status"]=="passed"
def save_raw(p,raw):
 with p.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def rp():
 with urllib.request.urlopen("http://127.0.0.1:38491/state",timeout=5) as r:assert r.status==200;raw=r.read(1048577)
 assert len(raw)<=1048576;return json.loads(raw),raw
before,before_raw=rp();assert before["credential_count"]==1 and before["credentials"][0]["sign_count"]==2 and before["counters"]["authentications"]==2 and before["credentials"][0]["flags"]==29 and before["counters"]["rejected"]==0
save_raw(root/"G11_RECOVERY_EXPORT-rp-before.public.json",before_raw)
lock=os.open(root/"driver.lock",os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
try:
 j=json.loads(m["private_file"](root/"journal.private.json",8*1024*1024));buildraw=m["private_file"](b/"artifacts/build.receipt.json",1048576);assert hashlib.sha256(buildraw).hexdigest()=="97a6daec5bb7276b935498fb3c8501df9ecc57a118641cffb9f2df3ae6edd009";m["validate_journal"](j,json.loads(buildraw),"97a6daec5bb7276b935498fb3c8501df9ecc57a118641cffb9f2df3ae6edd009");assert {k:d.setting(k) for k in m["SETTING_KEYS"]}==j["owned_settings"]
 assert d.package_hash(m["PROVIDER"])=="b16e82916330fac6909f82696089798c3ec76d7b4058fe9290e7e841b9e00459"
 side=root/"documents.private.json";plan=json.loads(m["private_file"](side,65536));assert plan["directory"]=="/sdcard/Download/HeptaBao-Passkey-QA-20261106-r9" and any(x["path"]==destination.rsplit("/",1)[0] and x["initial_absent"] is True and x["created"] is True for x in plan["directories"]) and plan["initial_directory_absent"] is True and plan["directory_created"] is True and all(x["path"]!=destination for x in plan["files"])
 q=d.adb_call("shell","if [ -e "+destination+" ] || [ -L "+destination+" ]; then printf EXISTS; else printf ABSENT; fi");assert q.returncode==0 and q.stdout==b"ABSENT" and q.stderr==b""
 plan["files"].append({"path":destination,"initial_absent":True,"write_intent":True,"written":False,"source_case":"G11_RECOVERY_EXPORT","sha256":None,"bytes":None});m["atomic"](side,plan)
 intent={"schema":1,"case":"G11_RECOVERY_EXPORT","scope":"ordinary_saf_latest_backup","destination":destination,"initial_absent":True,"rp_snapshot_sha256":hashlib.sha256(before_raw).hexdigest(),"credential":before["credentials"][0],"documents_journal_sha256":hashlib.sha256(side.read_bytes()).hexdigest(),"created_unix_ns":time.time_ns(),"reset_authorized":False}
 m["atomic"](root/"G11_RECOVERY_EXPORT-workflow.intent.public.json",intent);print(json.dumps(intent,sort_keys=True),flush=True)
finally:os.close(lock)
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
 global case_started
 r=subprocess.run(["/usr/bin/python3","-B",str(runner),"--case","G11","--steps",json.dumps([step])],capture_output=True,timeout=260);assert len(r.stdout)<262144 and not r.stderr
 parsed=[json.loads(line) for line in r.stdout.splitlines()];assert len(parsed)==1;e=parsed[0];events.append(e);print(json.dumps({"phase":e["phase"],"exit_code":e["exit_code"],"started_unix_ns":e["started_unix_ns"],"finished_unix_ns":e["finished_unix_ns"],"stdout_sha256":e["stdout_sha256"],"error":e["result"].get("error"),"foreground":e["result"].get("foreground"),"texts":[n.get("text") for n in e["result"].get("nodes",[]) if n.get("text")]},sort_keys=True),flush=True)
 if step.get("selector")=="CHOOSE ENCRYPTED BACKUP DESTINATION" and r.returncode==0:case_started=True
 if r.returncode:raise RuntimeError("phase_refused")
 time.sleep(0.8);return e["result"]
def record(status,detail):
 p=root/"G11_RECOVERY_EXPORT-result.public.json";detail.update({"schema":1,"case":"G11","auxiliary_operation":"G11_RECOVERY_EXPORT","status":status,"ordinary_export_executed":case_started,"case_passed":False,"events":[{"phase":e["phase"],"started_unix_ns":e["started_unix_ns"],"finished_unix_ns":e["finished_unix_ns"],"exit_code":e["exit_code"],"stdout_sha256":e["stdout_sha256"]} for e in events],"finished_unix_ns":time.time_ns(),"reset_authorized":False,"production_qualified":False});m["atomic"](p,detail)
 led=json.loads(m["private_file"](b/"case-results.public.json",1048576));assert next(x for x in led["cases"] if x["id"]=="G11")["status"]=="missing"
 print(json.dumps({"case":"G11","auxiliary_operation":"G11_RECOVERY_EXPORT","status":status,"case_passed":False,"result_sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"evidence":detail},sort_keys=True),flush=True)

try:
 ready();phase({"phase":"launch-provider"});phase({"phase":"input-master"});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"UNLOCK PUBLIC CREDENTIAL LIST"})
 opened=phase({"phase":"inspect"});assert any(n.get("text")=="Unlocked public list: 1 passkeys; five minute limit" for n in opened.get("nodes",[]))
 for step in [{"phase":"tap","selector":"CHOOSE ENCRYPTED BACKUP DESTINATION"},{"phase":"tap","selector_kind":"description","selector":"显示根目录"},{"phase":"tap","selector":"下载"},{"phase":"tap","selector":"HeptaBao-Passkey-QA-20261106-r9"},{"phase":"tap","selector":"latest-recovery"}]:phase(step)
 foreground,nodes=d.ui();assert foreground==("com.google.android.documentsui","com.android.documentsui.picker.PickActivity")
 names=[n for n in nodes if n.get("package")=="com.google.android.documentsui" and n.get("class")=="android.widget.EditText" and n.get("resource-id")=="android:id/title"];assert len(names)==1 and names[0].get("text")=="HeptaBao-passkey-backup.hbv"
 assert any(n.get("resource-id")=="com.google.android.documentsui:id/breadcrumb_text" and n.get("text")=="latest-recovery" for n in nodes)
 m["atomic"](root/"G11_RECOVERY_EXPORT-picker-target.public.json",{"schema":1,"case":"G11_RECOVERY_EXPORT","ordinary_picker_target_verified":True,"fixed_leaf":"HeptaBao-passkey-backup.hbv","fixed_owned_directory":"HeptaBao-Passkey-QA-20261106-r9/latest-recovery","arbitrary_picker_text_output":False,"observed_unix_ns":time.time_ns()})
 phase({"phase":"tap","selector":"保存"});phase({"phase":"input-master"});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"WRITE ENCRYPTED BACKUP TO CHOSEN FILE"})
 deadline=time.monotonic()+20
 while True:
  final=phase({"phase":"inspect"});assert final["foreground"]==["org.heptabao.passkey.preview","org.heptabao.passkey.preview.HomeActivity"];texts=[n.get("text") for n in final.get("nodes",[])]
  if "Encrypted backup written and read-back verified" in texts:break
  assert "Verifying vault password" in texts and time.monotonic()<deadline
 assert d.shell("test","-f",destination)=="" and d.shell("test","!","-L",destination)==""
 size=int(d.shell("stat","-c","%s",destination));assert 615<size<=8*1024*1024
 digest=d.shell("sha256sum",destination).split()[0];assert re.fullmatch(r"[0-9a-f]{64}",digest)
 got=d.adb_call("exec-out","cat",destination,timeout=30);assert got.returncode==0 and not got.stderr and len(got.stdout)==size and hashlib.sha256(got.stdout).hexdigest()==digest
 save_raw(b/"private/G11_RECOVERY_EXPORT-phone-backup.hbv",got.stdout);assert hashlib.sha256(m["private_file"](b/"private/G11_RECOVERY_EXPORT-phone-backup.hbv",8*1024*1024)).hexdigest()==digest
 after,after_raw=rp();assert after_raw==before_raw;save_raw(root/"G11_RECOVERY_EXPORT-rp-after.public.json",after_raw)
 backup={"device_path":destination,"bytes":size,"sha256":digest}
 receipt={"schema":1,"scope":"observed_ordinary_saf_backup_for_reset","source_case_id":"G11_RECOVERY_EXPORT","device_sha256":m["DEVICE_SHA256"],"build_receipt_sha256":"97a6daec5bb7276b935498fb3c8501df9ecc57a118641cffb9f2df3ae6edd009","provider_apk_sha256":"b16e82916330fac6909f82696089798c3ec76d7b4058fe9290e7e841b9e00459","observed_backup":backup,"ordinary_saf_export_observed":True,"provider_write_readback_verified":True,"synthetic_directory_initial_absent":True,"rp_before_sha256":hashlib.sha256(before_raw).hexdigest(),"rp_after_sha256":hashlib.sha256(after_raw).hexdigest(),"credential":after["credentials"][0],"completed_unix_ns":time.time_ns()}
 m["atomic"](root/"g11-current-backup.private.json",receipt)
 lock=os.open(root/"driver.lock",os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  plan=json.loads(m["private_file"](root/"documents.private.json",65536));matches=[x for x in plan["files"] if x["path"]==destination];assert len(matches)==1 and matches[0]["written"] is False;matches[0].update({"written":True,"sha256":digest,"bytes":size,"canonical_path":destination.replace("/sdcard/","/storage/emulated/0/",1),"ciphertext_captured_private":True});m["atomic"](root/"documents.private.json",plan)
 finally:os.close(lock)
 record("passed",{"ordinary_saf_export":True,"provider_write_readback_verified":True,"backup":backup,"private_ciphertext_capture_verified":True,"rp_raw_before_after_identical":True,"rp_snapshot_sha256":hashlib.sha256(after_raw).hexdigest(),"credential":after["credentials"][0],"backup_receipt_sha256":hashlib.sha256((root/"g11-current-backup.private.json").read_bytes()).hexdigest()})
except Exception as error:
 record("failed",{"error":type(error).__name__ if type(error).__name__ in ("AssertionError","RuntimeError","TimeoutExpired") else "closed_error"});raise SystemExit(1)
