import pathlib,os,json,re,hashlib,runpy,time,subprocess,xml.etree.ElementTree as ET,urllib.request,fcntl
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

events=[];case=None;product_write_count=0
def phase(step,allow_observation_refusal=False):
 global product_write_count
 if step.get("selector")=="WRITE ENCRYPTED BACKUP TO CHOSEN FILE":product_write_count+=1
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
  if "Unlocked public list: 1 passkeys; five minute limit" in texts:return time.monotonic_ns()
  assert "Verifying vault password" in texts and time.monotonic()<deadline

def current_file(path):
 assert d.shell("test","-f",path)=="" and d.shell("test","!","-L",path)==""
 size=int(d.shell("stat","-c","%s",path));digest=d.shell("sha256sum",path).split()[0];assert 0<=size<=8*1024*1024 and re.fullmatch(r"[0-9a-f]{64}",digest)
 return {"device_path":path,"bytes":size,"sha256":digest}
def output_intent(path,label):
 lock=os.open(root/"driver.lock",os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  plan=json.loads(m["private_file"](root/"documents.private.json",65536));directory=path.rsplit("/",1)[0]
  assert plan["initial_directory_absent"] is True and any(x["path"]==directory and x["created"] is True and x["initial_absent"] is True for x in plan["directories"]) and not any(x["path"]==path for x in plan["files"])
  q=d.adb_call("shell","if [ -e "+path+" ] || [ -L "+path+" ]; then printf EXISTS; else printf ABSENT; fi");assert q.returncode==0 and q.stdout==b"ABSENT" and q.stderr==b""
  plan["files"].append({"path":path,"initial_absent":True,"write_intent":True,"written":False,"source_case":label,"sha256":None,"bytes":None});m["atomic"](root/"documents.private.json",plan)
 finally:os.close(lock)
def output_confirm(obj):
 lock=os.open(root/"driver.lock",os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  plan=json.loads(m["private_file"](root/"documents.private.json",65536));matches=[x for x in plan["files"] if x["path"]==obj["device_path"]];assert len(matches)==1 and matches[0]["initial_absent"] is True
  matches[0].update({"written":True,"sha256":obj["sha256"],"bytes":obj["bytes"],"canonical_path":obj["device_path"].replace("/sdcard/","/storage/emulated/0/",1)});m["atomic"](root/"documents.private.json",plan)
 finally:os.close(lock)
def choose_backup(subdir):
 for step in [{"phase":"tap","selector":"CHOOSE ENCRYPTED BACKUP DESTINATION"},{"phase":"tap","selector_kind":"description","selector":"显示根目录"},{"phase":"tap","selector":"下载"},{"phase":"tap","selector":"HeptaBao-Passkey-QA-20261106-r9"},{"phase":"tap","selector":subdir}]:phase(step)
 foreground,nodes=d.ui();assert foreground==("com.google.android.documentsui","com.android.documentsui.picker.PickActivity")
 names=[n for n in nodes if n.get("package")=="com.google.android.documentsui" and n.get("class")=="android.widget.EditText" and n.get("resource-id")=="android:id/title"];assert len(names)==1 and names[0].get("text")=="HeptaBao-passkey-backup.hbv"
 assert any(n.get("resource-id")=="com.google.android.documentsui:id/breadcrumb_text" and n.get("text")==subdir for n in nodes)
 phase({"phase":"tap","selector":"保存"});out=inspect();assert any(n.get("text")=="Destination chosen; enter password and write encrypted backup" for n in out.get("nodes",[]))
def choose_seed():
 for step in [{"phase":"tap","selector":"CHOOSE ENCRYPTED VAULT FILE"},{"phase":"tap","selector_kind":"description","selector":"显示根目录"},{"phase":"tap","selector":"下载"},{"phase":"tap","selector":"HeptaBao-Passkey-QA-20261106-r9"},{"phase":"tap","selector":"heptabao-passkey-qa-r9-seed.hbv"}]:phase(step)
 out=inspect();assert any(n.get("text")=="Ciphertext staged; enter password and import into a fresh store" for n in out.get("nodes",[]))
def cancel_picker():
 for _ in range(10):
  foreground,_=d.ui()
  if foreground==("org.heptabao.passkey.preview","org.heptabao.passkey.preview.HomeActivity"):
   result=inspect();assert any(n.get("text")=="Document selection cancelled" for n in result.get("nodes",[]));return
  assert foreground==("com.google.android.documentsui","com.android.documentsui.picker.PickActivity")
  phase({"phase":"back"})
 raise RuntimeError("picker_cancel_not_returned")
def wait_status(expected):
 deadline=time.monotonic()+20
 while True:
  result=inspect();assert result["foreground"]==["org.heptabao.passkey.preview","org.heptabao.passkey.preview.HomeActivity"]
  texts=[n.get("text") for n in result.get("nodes",[])]
  assert time.monotonic()<deadline
  if expected in texts:return result
  assert "Verifying vault password" in texts
SEED_SHA="bb527d9aa00987a243b378ac31eb15d2caf203e106348a8e1ed60cff7f674917"
seed=b/"artifacts/seed.hbv";seed_raw=m["private_file"](seed,1048576);assert sha(seed_raw)==SEED_SHA and len(seed_raw)==615
def require_unconsumed_selection(screen,baseline,path):
 assert product_write_count==0
 assert screen["foreground"]==["org.heptabao.passkey.preview","org.heptabao.passkey.preview.HomeActivity"]
 assert any(n.get("text")=="Destination chosen; enter password and write encrypted backup" for n in screen.get("nodes",[]))
 assert baseline=={"device_path":path,"bytes":615,"sha256":SEED_SHA}

def seed_selected_destination(path,label):
 # QA fills only this newly created synthetic target; no product Write occurs.
 empty=current_file(path);assert empty["bytes"]==0 and empty["sha256"]==sha(b"")
 lock=os.open(root/"driver.lock",os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  plan=json.loads(m["private_file"](root/"documents.private.json",65536));entries=[x for x in plan["files"] if x["path"]==path];assert len(entries)==1
  e=entries[0];assert e["initial_absent"] is True and e["written"] is True and e["bytes"]==0 and e["sha256"]==sha(b"")
  m["atomic"](root/(label+"-nonempty-fixture.intent.public.json"),{"schema":1,"path":path,"expected_before":empty,"intended_bytes":615,"intended_sha256":SEED_SHA,"source":"fixed empty-vault ciphertext used only as QA target content","not_a_product_backup_export":True,"created_unix_ns":time.time_ns()})
  e["qa_nonempty_fixture_write_intent"]=True;m["atomic"](root/"documents.private.json",plan)
  assert current_file(path)==empty
  q=d.adb_call("push",seed,path,timeout=30);assert q.returncode==0 and len(q.stdout)<65536 and len(q.stderr)<65536
  baseline=current_file(path);assert baseline["bytes"]==615 and baseline["sha256"]==SEED_SHA
  e.update({"written":True,"bytes":615,"sha256":SEED_SHA,"canonical_path":path.replace("/sdcard/","/storage/emulated/0/",1),"qa_nonempty_fixture_written":True});m["atomic"](root/"documents.private.json",plan)
  return baseline
 finally:os.close(lock)
def record(status,detail,error=None):
 after,raw=rp(case+"-rp-after.public.json")
 if status=="passed":assert raw==before_raw
 ev={"schema":1,"case":case,"status":status,"executed":executed,"rp_before_sha256":sha(before_raw),"rp_after_sha256":sha(raw),"rp_raw_unchanged":raw==before_raw,"detail":detail,"error":error,"events":[{"phase":e["phase"],"started_unix_ns":e["started_unix_ns"],"finished_unix_ns":e["finished_unix_ns"],"exit_code":e["exit_code"],"stdout_sha256":e["stdout_sha256"]} for e in events],"finished_unix_ns":time.time_ns(),"production_qualified":False}
 p=root/(case+"-result.public.json");m["atomic"](p,ev);led=json.loads(m["private_file"](b/"case-results.public.json",1048576));row=next(x for x in led["cases"] if x["id"]==case);assert row["status"]=="missing";row.update({"status":status if executed else "blocked","executed":executed,"evidence":[{"path":str(p),"sha256":sha(p.read_bytes())}]})
 for k in ("passed","failed","blocked","missing"):led[k]=sum(x["status"]==k for x in led["cases"])
 led["executed"]=sum(x["executed"] for x in led["cases"]);m["atomic"](b/"case-results.public.json",led)
 print(json.dumps({"case":case,"status":status,"result_sha256":sha(p.read_bytes()),"detail":detail,"counts":{k:led[k] for k in ("passed","failed","blocked","missing","executed")}},sort_keys=True),flush=True)

for case in ["G01","G08","G09","G10"]:
 events=[];executed=False;detail={};product_write_count=0
 assert not (root/(case+"-workflow.intent.public.json")).exists() and not (root/(case+"-result.public.json")).exists()
 before,before_raw=rp(case+"-rp-before.public.json")
 m["atomic"](root/(case+"-workflow.intent.public.json"),{"schema":1,"case":case,"scope":"ordinary_SAF_negative_control","created_unix_ns":time.time_ns()})
 try:
  ready();unlock()
  if case=="G01":
   choose_seed();phase({"phase":"input-master","wrong":True});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"IMPORT ENCRYPTED VAULT INTO A FRESH STORE"});executed=True
   wait_status("wrong_key_or_corrupt");unlock();detail={"wrong_master_rejected_with":"wrong_key_or_corrupt","previous_active_store_public_count_still_one":True,"selected_ciphertext_sha256":"bb527d9aa00987a243b378ac31eb15d2caf203e106348a8e1ed60cff7f674917"}
  elif case=="G09":
   choose_seed();phase({"phase":"tap","selector":"CHOOSE ENCRYPTED VAULT FILE"});executed=True;cancel_picker()
   phase({"phase":"input-master"});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"IMPORT ENCRYPTED VAULT INTO A FRESH STORE"});wait_status("choose_encrypted_vault_first");unlock()
   detail={"old_staged_seed_before_new_picker":True,"new_picker_cancel_observed":True,"explicit_refusal":"choose_encrypted_vault_first","previous_active_store_public_count_still_one":True,"no_old_staged_import":True}
  elif case in ("G08","G10"):
   directory=case+"-target";path="/sdcard/Download/HeptaBao-Passkey-QA-20261106-r9/"+directory+"/HeptaBao-passkey-backup.hbv"
   output_intent(path,case);choose_backup(directory);created=current_file(path);output_confirm(created)
   baseline=seed_selected_destination(path,case);screen=inspect();require_unconsumed_selection(screen,baseline,path)
   m["atomic"](root/(case+"-destination-baseline.public.json"),{"schema":1,"scope":"ordinary_SAF_selection_then_explicit_QA_nonempty_baseline_before_any_product_Write","file":baseline,"actual_ordinary_SAF_target_selection":True,"product_Write_since_selection":False,"QA_seeded_ciphertext_nonempty_baseline":True,"unconsumed_is_precondition_only":True,"observed_unix_ns":time.time_ns()})
   if case=="G08":
    phase({"phase":"tap","selector":"CHOOSE ENCRYPTED BACKUP DESTINATION"});executed=True;cancel_picker();phase({"phase":"input-master"});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"WRITE ENCRYPTED BACKUP TO CHOSEN FILE"});wait_status("choose_backup_destination_first")
    after=current_file(path);assert after==baseline;detail={"old_selected_destination":baseline,"new_picker_cancel_observed":True,"explicit_refusal":"choose_backup_destination_first","old_destination_unchanged":True,"selection_unconsumed_before_new_picker":True,"baseline_is_QA_ciphertext_not_product_export":True}
   else:
    phase({"phase":"input-master","wrong":True});phase({"phase":"hide-keyboard"});phase({"phase":"tap","selector":"WRITE ENCRYPTED BACKUP TO CHOSEN FILE"});executed=True;wait_status("wrong_key_or_corrupt")
    after=current_file(path);assert after==baseline;detail={"nonempty_destination_baseline_after_selection":baseline,"wrong_master_rejected_with":"wrong_key_or_corrupt","nonempty_file_unchanged":True,"selection_unconsumed_before_negative_Write":True,"negative_Write_consumes_selection":True,"baseline_is_QA_ciphertext_not_product_export":True}
  else:raise RuntimeError("unknown_case")
  _,raw=rp();assert raw==before_raw;record("passed",detail)
 except Exception as error:
  record("failed",detail,type(error).__name__ if type(error).__name__ in ("AssertionError","RuntimeError","TimeoutExpired") else "closed_error");raise SystemExit(1)
