#!/usr/bin/env python3
import hashlib,importlib.util,json,os,sys,time
from pathlib import Path
os.umask(0o077)
base=Path("/home/alex/heptabao-android-autofill-20261106-r1")
qa=base/"android_live.revision9.py"
expected_qa="4d20ac12535e592da591b5c63cf7971ef2443c6b219f36e250aac2074fd3ce1e"
expected_report="be859adb806b91a57f8cf206e5880e5b995e596641b3caca8a321bd29b2af251"
sha=lambda data:hashlib.sha256(data).hexdigest()
try:
 if sha(qa.read_bytes())!=expected_qa: raise ValueError()
 raw=(base/"run-r7/report.json").read_bytes()
 if sha(raw)!=expected_report: raise ValueError()
 report=json.loads(raw)
 if report["restoration"]!="restored_original" or set(report["package_cleanup"].values())!={"removed_owned_package"}: raise ValueError()
 spec=importlib.util.spec_from_file_location("android_qa9_readonly",qa); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
 device=module.Device(Path("/home/alex/.local/bin/adb"))
 if device.shell("am","get-current-user")!="0" or device.shell("getprop","ro.build.version.sdk")!="36": raise ValueError()
 current=sha(device.setting().encode())
 if current!=report["previous_setting_sha256"]: raise ValueError()
 absence={}
 for package in sorted(module.PACKAGES):
  active=device.package_present(package)
  retained=device.package_present(package,True)
  if active or retained: raise ValueError()
  absence[package]={"installed_absent":True,"retained_record_absent":True,"query_succeeded":True}
 result={"schema":1,"run":"r7","scope":"readonly_post_cleanup_verification","device_serial_sha256":module.DEVICE_SHA256,"qa_script_sha256":expected_qa,"report_sha256":expected_report,"restoration":"restored_original","original_setting_sha256":report["previous_setting_sha256"],"current_setting_sha256":current,"packages":absence,"device_mutations":False,"phone_driver_job":"1a1b065558e-fc05-7038","phone_driver_terminal_exit_code":1,"created_unix_ns":time.time_ns()}
 data=(json.dumps(result,sort_keys=True,indent=2)+"\n").encode()
 fd=os.open(base/"release-r7.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as f:f.write(data);f.flush();os.fsync(f.fileno())
 directory=os.open(base,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(directory)
 finally:os.close(directory)
 print(json.dumps({"ok":True,"release_sha256":sha(data),"restoration":"restored_original","packages_absent":len(absence),"run":"r7"}),flush=True)
except Exception:
 print(json.dumps({"ok":False,"error":"readonly_release_verification_failed","run":"r7"}),flush=True)
 sys.exit(1)
