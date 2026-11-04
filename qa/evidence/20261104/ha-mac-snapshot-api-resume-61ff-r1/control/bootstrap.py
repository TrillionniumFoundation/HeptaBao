import hashlib,json,os,stat,sys
from pathlib import Path
expected_python="/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python"
if len(sys.argv)!=4 or sys.argv[3] not in ("compile","execute") or str(Path(sys.executable).resolve(strict=True))!=expected_python or os.getuid()!=501 or os.geteuid()!=501:
    raise SystemExit("new_attempt_bootstrap_identity")
fd=os.open(expected_python,os.O_RDONLY|os.O_NOFOLLOW)
try:
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=501 or info.st_nlink!=1 or info.st_size>64*1024*1024:
        raise SystemExit("python_custody")
    py=os.read(fd,64*1024*1024+1)
    if len(py)!=info.st_size or info!=os.fstat(fd) or hashlib.sha256(py).hexdigest()!="7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211":
        raise SystemExit("python_pin")
finally:
    os.close(fd)
raw=sys.stdin.buffer.read(262145)
if len(raw)>262144 or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:
    raise SystemExit("new_attempt_packet_pin")
payload=json.loads(raw)
source=payload["driver"].encode()
if hashlib.sha256(source).hexdigest()!=sys.argv[1]:
    raise SystemExit("new_attempt_driver_pin")
path="/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-snapshot-acl-denial-61ff-r1/control/normal-resume-r4/run_normal_resume_r4.py"
code=compile(source,path,"exec")
if sys.argv[3]=="compile":
    print(json.dumps({"compiled":True,"executed":False,"driver_sha256":sys.argv[1],"packet_sha256":sys.argv[2],"source_bytes":len(source)},sort_keys=True),flush=True)
else:
    sys.argv=[path,sys.argv[1],sys.argv[2]]
    exec(code,{"__name__":"__main__","__file__":path,"__source_raw__":source,"__packet_raw__":raw,"__payload__":payload})
