import hashlib,json,os,stat,sys,time,types,unittest
from pathlib import Path
QA=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-api-20261106-r2/qa')
path=QA/'main3_api_controller.py'
def identity(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
 before=os.fstat(fd)
 assert stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
 raw=os.read(fd,1048576)
 assert len(raw)==32340 and hashlib.sha256(raw).hexdigest()=='6bf27db160301108340d371e32c0b5384205fe26db27aea878abf493f680a722'
 assert os.read(fd,1)==b'' and identity(before)==identity(os.fstat(fd))==identity(path.lstat())
finally:os.close(fd)
module=types.ModuleType('main3_api_controller');module.__file__=str(path)
sys.modules[module.__name__]=module
exec(compile(raw,str(path),'exec'),module.__dict__)
plan,pin=module.load_inputs()
assert pin=='e655fb1c5780ed7d1ee3fb7b5febb299f0ff7c4849ab0537dc17426cf68f2378'
sys.path.insert(0,str(QA))
sys.argv=[str(path),'--mode','run']
raise SystemExit(module.main())
