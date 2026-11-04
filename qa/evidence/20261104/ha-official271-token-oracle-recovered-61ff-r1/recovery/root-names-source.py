import json, os, stat
from pathlib import Path
p=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
assert p.resolve(strict=True)==p
s=p.lstat()
assert stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid()
rows=[]
with os.scandir(p) as entries:
    for count,e in enumerate(entries,1):
        assert count<=2048
        if 'official271' in e.name or 'wire' in e.name or 'oracle' in e.name:
            info=e.stat(follow_symlinks=False)
            rows.append({'name':e.name,'directory':stat.S_ISDIR(info.st_mode),'symlink':stat.S_ISLNK(info.st_mode),'owned':info.st_uid==os.geteuid()})
print(json.dumps({'schema':'owned-oracle-root-names.v1','root':str(p),'matches':sorted(rows,key=lambda x:x['name']),'contents_read':False,'mutations':False},sort_keys=True),flush=True)
