import hashlib,json,os,stat,sys,time,types,unittest
from pathlib import Path
QA=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-api-20261106-r5/qa')
path=QA/'main3_api_controller.py'
def identity(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
 before=os.fstat(fd)
 assert stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
 raw=os.read(fd,1048576)
 assert len(raw)==32986 and hashlib.sha256(raw).hexdigest()=='d2a9b7575e1be7d2a591660d89df3659fed39c1bbdf54ab49c3be57c0eb27c9f'
 assert os.read(fd,1)==b'' and identity(before)==identity(os.fstat(fd))==identity(path.lstat())
finally:os.close(fd)
module=types.ModuleType('main3_api_controller');module.__file__=str(path)
sys.modules[module.__name__]=module
exec(compile(raw,str(path),'exec'),module.__dict__)
plan,pin=module.load_inputs()
assert pin=='e4e8315fc348cdbbfb9f8df001e952a940357a5d8fa9fcf43cb15c339c092ebb'
sys.path.insert(0,str(QA))
names=['test_main3_api_controller','test_suid_ps_tls_r2','test_main3_api_guards','test_main3_inline_capture','test_main3_http_complete']
suite=unittest.defaultTestLoader.loadTestsFromNames(names)
assert suite.countTestCases()==173
started=time.monotonic()
r=unittest.TextTestRunner(verbosity=2).run(suite)
passed=r.wasSuccessful() and r.testsRun==173 and not r.skipped
print(json.dumps({'schema':'heptabao.main3-mac-qa-guards.r5','ok':passed,'testCount':r.testsRun,'skipCount':len(r.skipped),'sourcePins':plan['sourcePins'],'serviceActions':[],'providerCalled':False,'productionChanged':False,'elapsedSeconds':time.monotonic()-started},sort_keys=True),flush=True)
if not passed:raise SystemExit(1)
from qualify_main3_http_tls import run as qualify_tls
report=qualify_tls(QA.parent/'server/tls/server.crt',QA.parent/'server/tls/server.key')
assert report['ok'] and report['checkCount']==15 and report['allPeerThreadsJoined'] and report['allPeerSocketsClosed']
print(json.dumps(report,sort_keys=True),flush=True)
import contextlib
from mac_public_code_pin_excerpt_r1 import public_code_pin
pin_until=time.monotonic()+3.0
def pin_remaining():
 remaining=pin_until-time.monotonic();assert remaining>0;return remaining
public_pins=[]
for nominal in ('/sbin/mount','/opt/homebrew/lib/node_modules/openclaw/package.json'):
 before=identity(Path(nominal).lstat())
 value=public_code_pin(nominal,remaining=pin_remaining,critical=contextlib.nullcontext)
 assert before==identity(Path(nominal).lstat())
 value.update(nominal=nominal,nominalIdentity=list(before),resolvedIdentity=list(identity(Path(value['path']).lstat())))
 public_pins.append(value)
print(json.dumps({'schema':'heptabao.main3-sdk-required-public-runtime-pins.r1','ok':True,'publicCodePins':public_pins,'serviceActions':[],'credentialInputsRead':False},sort_keys=True),flush=True)
sys.argv=[str(path),'--mode','preflight']
raise SystemExit(module.main())
