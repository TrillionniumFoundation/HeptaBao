import hashlib,os,stat
from pathlib import Path
p=Path('/Users/qianqi/heptabao-mac-fresh-synthetic-recovery-preparation-20261106-r1/recover_fresh_synthetic_once.r1.py')
f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 s=os.fstat(f)
 assert stat.S_ISREG(s.st_mode) and s.st_uid==501 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
 raw=os.read(f,65537)
 assert len(raw)==40821 and hashlib.sha256(raw).hexdigest()=='74c1c25ea9a747946b18b4a4e70e2a48037e3ca8892af63230e1e1980fcfad8a' and os.read(f,1)==b''
finally:os.close(f)
exec(compile(raw,str(p),'exec'),{'__name__':'__main__','__file__':str(p),'__source_sha256__':'74c1c25ea9a747946b18b4a4e70e2a48037e3ca8892af63230e1e1980fcfad8a'})
