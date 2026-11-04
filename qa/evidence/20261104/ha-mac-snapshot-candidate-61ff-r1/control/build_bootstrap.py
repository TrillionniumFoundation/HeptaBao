import hashlib,os,stat,sys
path="/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-snapshot-acl-denial-61ff-r1/control/run_candidate_normal_r1.py"
if len(sys.argv)!=3:
    raise SystemExit("build_input_pins")
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
try:
    before=os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid!=501 or before.st_nlink!=1 or before.st_size>128*1024:
        raise SystemExit("build_source_custody")
    raw=b""
    while len(raw)<=128*1024:
        data=os.read(fd,65536)
        if not data: break
        raw+=data
    after=os.fstat(fd)
finally:
    os.close(fd)
if len(raw)!=before.st_size or before!=after or hashlib.sha256(raw).hexdigest()!=sys.argv[1]:
    raise SystemExit("build_source_pin")
sys.argv=[path,sys.argv[1],sys.argv[2]]
exec(compile(raw,path,"exec"),{"__name__":"__main__","__file__":path})
