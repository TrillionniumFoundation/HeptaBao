#!/usr/bin/env python3
"""Fresh run setup: owned preflight, installation, exact intent, ordinary system UI."""
import pathlib,os,json,re,hashlib,runpy,time,subprocess,xml.etree.ElementTree as ET
os.umask(0o077);b=pathlib.Path('/home/alex/HeptaBaoPasskey-20261106-r9');driver=b/'passkey_live.r9.py';runner=b/'run_phases.input-r9.public.py'
assert hashlib.sha256(driver.read_bytes()).hexdigest()=='e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd'
assert hashlib.sha256(runner.read_bytes()).hexdigest()=='38793057a126e755fd965a218aa5c4f7d078dd78a3af4386a7cb6accfe679e60'
m=runpy.run_path(str(driver));d=m['Device'](pathlib.Path('/home/alex/.local/bin/adb'))
def phase(step):
 r=subprocess.run(['/usr/bin/python3','-B',str(runner),'--case','SETUP','--steps',json.dumps([step])],capture_output=True,timeout=260)
 assert len(r.stdout)<262144 and not r.stderr
 events=[json.loads(x) for x in r.stdout.splitlines()];assert len(events)==1
 print(json.dumps(events[0],sort_keys=True),flush=True)
 if r.returncode:raise SystemExit(r.returncode)
 time.sleep(1);return events[0]['result']
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

for step in [{'phase':'preflight'},{'phase':'install'},{'phase':'reverse'},{'phase':'settings-arm-primary-system-bridge'}]:phase(step)
swiped=ready();m['atomic'](b/'setup-screen-ready.public.json',{'schema':1,'ordinary_nonsecure_swipe_used':swiped,'no_lock_screen_setting_changed':True,'master_read':False})
for step in [
 {'phase':'launch-provider'},{'phase':'inspect'},
 {'phase':'tap','selector':'OPEN PROVIDER SETTINGS'},
 {'phase':'tap','selector_kind':'id','selector':'com.android.settings:id/change_button'},
 {'phase':'tap','selector':'HeptaBao synthetic passkeys'},
 {'phase':'tap','selector_kind':'id','selector':'android:id/button1'},
 {'phase':'settings-selected'},{'phase':'launch-provider'},{'phase':'inspect'}]:phase(step)
print(json.dumps({'schema':1,'setup_complete':True,'ordinary_system_settings':True,'master_entered':False,'case_passed':False},sort_keys=True),flush=True)
