#!/usr/bin/env python3
"""Public-code pin excerpt only; no current config or credential capture code.

Bodies are byte-identical to the original guarded capture source. This excerpt
has not independently qualified a fresh manager; its caller must bind and test
its actual use. The original full source SHA is recorded in provenance.
"""
import hashlib, os, stat
from pathlib import Path

MIB=1024*1024

class CaptureRefused(RuntimeError):pass
def need(value,code):
    if not value:raise CaptureRefused(code)

def identity(s):
    return tuple(str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
                                 s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))

def public_code_pin(path,*,remaining,critical):
    # Public interpreter/extension/source hashes have their own fixed 64MiB
    # per-file bound. They do not pretend to be measured SQLite page I/O.
    remaining();path=Path(path).resolve(strict=True)
    with critical():
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0<before.st_size<=64*MIB
             and not stat.S_IMODE(before.st_mode)&0o022,'public_runtime_code_custody')
        digest=hashlib.sha256();count=0
        while count<=before.st_size:
            remaining()
            raw=os.read(fd,min(MIB,before.st_size+1-count))
            if not raw:break
            count+=len(raw);digest.update(raw)
        need(count==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),
             'public_runtime_code_changed')
        remaining()
        result={'path':str(path),'bytes':count,'sha256':digest.hexdigest()}
    finally:
        with critical():os.close(fd)
    remaining()
    return result

