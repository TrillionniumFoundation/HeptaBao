import hashlib, os, stat, sys
from pathlib import Path
p = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-unified-normal-61ff-r1/control/launch_mac_normal_build_r3.py')
fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
try:
    before = os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_nlink == 1 and before.st_size == 22417
    raw = b''
    while len(raw) <= 22417:
        part = os.read(fd, 22418 - len(raw))
        if not part:
            break
        raw += part
    after = os.fstat(fd)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert identity(before) == identity(after) == identity(p.lstat())
finally:
    os.close(fd)
assert len(raw) == 22417 and hashlib.sha256(raw).hexdigest() == 'aa09d9bb4c72c374430dc83fdd592b08b36a6d8fa1865c9580c168ac774c3043'
sys.argv = [str(p)]
namespace = {'__name__': '__main__', '__file__': str(p)}
exec(compile(raw, str(p), 'exec'), namespace, namespace)
