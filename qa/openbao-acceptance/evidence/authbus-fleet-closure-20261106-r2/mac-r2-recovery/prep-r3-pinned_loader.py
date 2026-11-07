import hashlib,os,stat
from pathlib import Path
p=Path('/Users/qianqi/heptabao-mac-authbus-r2-recovery-preparation-20261106-r3/recover_r2_qa_once.py')
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    s=os.fstat(fd)
    assert stat.S_ISREG(s.st_mode) and s.st_uid==501 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
    assert 0<s.st_size<=65536
    raw=os.read(fd,65537)
    ident=lambda x:(x.st_dev,x.st_ino,x.st_uid,x.st_gid,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    assert len(raw)==s.st_size and not os.read(fd,1) and ident(s)==ident(os.fstat(fd))==ident(p.lstat())
finally:os.close(fd)
assert hashlib.sha256(raw).hexdigest()=='a54a12b1b7efd12c16f6720b6fe6a63fd197016b675068fb4d95da8ea891fde9'
exec(compile(raw,str(p),'exec'),{'__name__':'__main__','__source_sha256__':'a54a12b1b7efd12c16f6720b6fe6a63fd197016b675068fb4d95da8ea891fde9'})
