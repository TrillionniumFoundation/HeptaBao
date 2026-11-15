import pathlib,hashlib,os,json,runpy,fcntl,time,tarfile
os.umask(0o077);b=pathlib.Path("/home/alex/HeptaBaoPasskey-20261106-r9");driver=b/"passkey_live.r9.py"
assert hashlib.sha256(driver.read_bytes()).hexdigest()=="e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd"
m=runpy.run_path(str(driver));root=b/"live-r9";m["private_directory"](b);m["private_directory"](root);d=m["Device"](pathlib.Path("/home/alex/.local/bin/adb"))
lock=os.open(root/"driver.lock",os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
try:
 j=json.loads(m["private_file"](root/"journal.private.json",8*1024*1024));buildraw=m["private_file"](b/"artifacts/build.receipt.json",1024*1024);assert hashlib.sha256(buildraw).hexdigest()=="97a6daec5bb7276b935498fb3c8501df9ecc57a118641cffb9f2df3ae6edd009";m["validate_journal"](j,json.loads(buildraw),"97a6daec5bb7276b935498fb3c8501df9ecc57a118641cffb9f2df3ae6edd009")
 assert {k:d.setting(k) for k in m["SETTING_KEYS"]}==j["owned_settings"]
 profile=m["private_file"](b/"profile.public.json",65536);assert hashlib.sha256(profile).hexdigest()=="b6b7754bad0e34cf55b0c2635683b03093555fa5d3f096533ee36b3e02eec55b"
 with (root/"profile.public.json").open("xb") as f:f.write(profile);f.flush();os.fsync(f.fileno())
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 directory="/sdcard/Download/HeptaBao-Passkey-QA-20261106-r9"
 directories=[directory,directory+"/latest-recovery",directory+"/G08-target",directory+"/G10-target"]
 source=b/"artifacts/seed.hbv";raw=m["private_file"](source,1048576);digest=hashlib.sha256(raw).hexdigest();assert digest=="bb527d9aa00987a243b378ac31eb15d2caf203e106348a8e1ed60cff7f674917" and len(raw)==615
 assert d.shell("test","-d","/sdcard/Download")==""
 q=d.adb_call("shell","if [ -e "+directory+" ] || [ -L "+directory+" ]; then printf EXISTS; else printf ABSENT; fi")
 assert q.returncode==0 and q.stdout==b"ABSENT" and q.stderr==b""
 side=root/"documents.private.json";assert not side.exists()
 plan={"schema":1,"device_sha256":m["DEVICE_SHA256"],"directory":directory,"initial_directory_absent":True,"mkdir_intent":True,"directory_created":False,"directories":[{"path":p,"initial_absent":True,"mkdir_intent":True,"created":False} for p in directories],"files":[{"path":p+"/heptabao-passkey-qa-r9-seed.hbv","sha256":digest,"bytes":len(raw),"initial_absent":True,"write_intent":True,"written":False,"role":"synthetic_seed_or_media_index_marker"} for p in directories],"started_unix_ns":time.time_ns()}
 m["atomic"](side,plan)
 for entry in plan["directories"]:
  assert d.shell("mkdir",entry["path"])==""
  assert d.shell("test","-d",entry["path"])==""
  entry["created"]=True
  if entry["path"]==directory:plan["directory_created"]=True
  m["atomic"](side,plan)
 for entry in plan["files"]:
  destination=entry["path"];pushed=d.adb_call("push",source,destination,timeout=30);assert pushed.returncode==0 and len(pushed.stdout)<=65536 and len(pushed.stderr)<=65536
  entry["push_ack"]={"returncode":pushed.returncode,"stdout_sha256":hashlib.sha256(pushed.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(pushed.stderr).hexdigest(),"stdout_bytes":len(pushed.stdout),"stderr_bytes":len(pushed.stderr)}
  assert d.shell("sha256sum",destination).split()[0]==digest and int(d.shell("stat","-c","%s",destination))==len(raw)
  canonical=d.shell("readlink","-f",destination);assert canonical==destination.replace("/sdcard/","/storage/emulated/0/",1)
  entry["written"]=True;entry["canonical_path"]=canonical;m["atomic"](side,plan)
  d.shell("am","broadcast","--user","0","-a","android.intent.action.MEDIA_SCANNER_SCAN_FILE","-d","file://"+destination)
  deadline=time.monotonic()+10
  while True:
   index=d.shell("content","query","--uri","content://media/external/file","--projection","_id:_data","--where","_data='"+canonical+"'")
   assert time.monotonic()<deadline
   if "_data="+canonical in index and len(index.splitlines())==1:break
   time.sleep(0.25)
  entry["media_index_confirmed"]=True;m["atomic"](side,plan)
 public={"schema":1,"ok":True,"scope":"synthetic_ciphertext_document_staging_only","directory_initial_absent":True,"directory":directory,"owned_directories":directories,"seed_sha256":digest,"seed_bytes":len(raw),"four_files_media_index_confirmed":True,"documents_journal_sha256":hashlib.sha256(side.read_bytes()).hexdigest(),"profile_public_sha256":hashlib.sha256(profile).hexdigest(),"master_read":False,"case_passed":False}
 m["atomic"](root/"documents-prepared.public.json",public);print(json.dumps(public,sort_keys=True),flush=True)
finally:os.close(lock)
archive=b/"artifacts/source-r8-fixture-permission.tar.gz";assert hashlib.sha256(archive.read_bytes()).hexdigest()=="93ae4e2bb76d9e761bb088d86a7c69326fca469bbb3ba610eab1c4b8565ab77d"
with tarfile.open(archive,"r:gz") as t:
 members=[x for x in t.getmembers() if x.isfile() and x.name.endswith("/HomeActivity.java")];assert len(members)==1
 code=t.extractfile(members[0]).read();assert hashlib.sha256(code).hexdigest()=="90e3ea0753c5edb28db406f5b1c0845a8dec17e4d778651c62b17814869b3657"
 lines=code.decode().splitlines()
 print(json.dumps({"frozen_source":"HomeActivity","source_sha256":hashlib.sha256(code).hexdigest(),"status_source_lines":[[i+1,x.strip()] for i,x in enumerate(lines) if "setText(" in x or "complete(" in x or "Public list" in x]},sort_keys=True),flush=True)
