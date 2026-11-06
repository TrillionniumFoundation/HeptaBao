import hashlib,os,stat,sys,types
from pathlib import Path
QA=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r2/qa')
path=QA/'fresh_synthetic_controller_r1.py'
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 before=os.fstat(fd)
 assert stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
 raw=os.read(fd,1048576)
 assert len(raw)==29955 and hashlib.sha256(raw).hexdigest()=='4697eb12c7af0b88fc8faec697518e0397cc8f620cf2581f301b18206f54f42c'
 assert os.read(fd,1)==b''
 assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(os.fstat(fd).st_dev,os.fstat(fd).st_ino,os.fstat(fd).st_size,os.fstat(fd).st_mtime_ns,os.fstat(fd).st_ctime_ns)
finally:os.close(fd)
module=types.ModuleType('fresh_synthetic_controller_r1');module.__file__=str(path)
sys.modules[module.__name__]=module
exec(compile(raw,str(path),'exec'),module.__dict__)
plan,pin=module.load_inputs()
assert pin=='6928becb06ea989734983c31bdd0de73cea245852f6c564a5660ff947010066c'
sys.path.insert(0,str(QA))
sys.argv=[str(path),'--mode','run']
raise SystemExit(module.main())
