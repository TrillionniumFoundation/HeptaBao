import errno,json,os,stat,struct,time
from pathlib import Path
H=Path('/home/qian-qi'); S=H/'.npm-global/lib/node_modules/openclaw'
paths=list(dict.fromkeys([*S.parents,*(H/'.openclaw/extensions/openclaw-authbus/package.json').parents]))
rows=[];opened=closed=0;ok=False;error=None
def ident(s):return [str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
try:
 assert os.getuid()==1000 and Path.home()==H and len(paths)<=16
 for p in paths:
  s=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid in (0,1000) and p.resolve(strict=True)==p
  f=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);opened+=1
  try:
   assert ident(os.fstat(f))==ident(s)
   a=[]
   for name in ('system.posix_acl_access','system.posix_acl_default'):
    try:raw=os.getxattr(f,name)
    except OSError as e:
     assert e.errno in (errno.ENODATA,errno.ENOTSUP);continue
    assert 4<=len(raw)<=4096 and struct.unpack_from('<I',raw)[0]==2 and (len(raw)-4)%8==0
    entries=[struct.unpack_from('<HHI',raw,i) for i in range(4,len(raw),8)]
    assert all(t in (1,2,4,8,16,32) and perm<=7 for t,perm,u in entries)
    assert len({(t,u) for t,perm,u in entries})==len(entries)
    mask=next((perm for t,perm,u in entries if t==16),7)
    a.append({'kind':name.removeprefix('system.posix_acl_'),'entries':[{'tag':t,'permission':perm,'principalClass':'unspecified' if u==4294967295 else 'owner-or-root' if u in (0,1000) else 'other-principal','effectiveWrite':bool((perm if t in (1,32) else perm&mask)&2)} for t,perm,u in entries]})
   assert ident(os.fstat(f))==ident(p.lstat())==ident(s)
   rows.append({'path':str(p),'mode':oct(stat.S_IMODE(s.st_mode)),'acl':a})
  finally:os.close(f);closed+=1
 ok=True
except BaseException as e:error=type(e).__name__
print(json.dumps({'schema':'heptabao.rog-fixed-code-ancestor-acl-observation.r1','ok':ok,'errorType':error,'rows':rows,'opened':opened,'closed':closed,'allOriginalFdsClosed':opened==closed,'permissionWrites':0,'credentialReads':0,'children':0,'providerCalls':0},sort_keys=True,separators=(',',':')))
raise SystemExit(0 if ok and opened==closed else 1)
