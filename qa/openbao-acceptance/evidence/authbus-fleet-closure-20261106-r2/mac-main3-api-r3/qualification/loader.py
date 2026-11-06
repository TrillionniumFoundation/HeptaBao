import hashlib,json,os,stat,sys,time,types,unittest
from pathlib import Path
QA=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-api-20261106-r3/qa')
path=QA/'main3_api_controller.py'
def identity(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
 before=os.fstat(fd)
 assert stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
 raw=os.read(fd,1048576)
 assert len(raw)==32340 and hashlib.sha256(raw).hexdigest()=='74daa03bfc8edcb4d577c47dc4d664cbd5fc065adc4c79a46d2d9f822eae483f'
 assert os.read(fd,1)==b'' and identity(before)==identity(os.fstat(fd))==identity(path.lstat())
finally:os.close(fd)
module=types.ModuleType('main3_api_controller');module.__file__=str(path)
sys.modules[module.__name__]=module
exec(compile(raw,str(path),'exec'),module.__dict__)
plan,pin=module.load_inputs()
assert pin=='18798417435d55eea5c48823162e079bfdf910d1f36dcbd91f61993106353216'
sys.path.insert(0,str(QA))
names=['test_main3_api_controller','test_suid_ps_tls_r2','test_main3_api_guards']
suite=unittest.defaultTestLoader.loadTestsFromNames(names)
assert suite.countTestCases()==108
started=time.monotonic()
r=unittest.TextTestRunner(verbosity=2).run(suite)
passed=r.wasSuccessful() and r.testsRun==108 and not r.skipped
print(json.dumps({'schema':'heptabao.main3-mac-qa-guards.r3','ok':passed,'testCount':r.testsRun,
 'skipCount':len(r.skipped),'sourcePins':plan['sourcePins'],'normalStorageConfigAlreadyVerified':True,
 'serviceActions':[],'providerCalled':False,'productionChanged':False,
 'elapsedSeconds':time.monotonic()-started},sort_keys=True),flush=True)
if not passed:raise SystemExit(1)
sys.argv=[str(path),'--mode','preflight']
raise SystemExit(module.main())
