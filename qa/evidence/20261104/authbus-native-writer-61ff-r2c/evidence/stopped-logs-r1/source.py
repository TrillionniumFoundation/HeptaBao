import os,json,pathlib,hashlib,sqlite3,stat,re
root=pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-native-writer-61ff8bef-baseline-r2c')
home=root/'run-r1/live/consumer-active-lease/state/home/.codex'
out=root/'stopped-log-diag-r1'
out.mkdir(mode=0o700,exist_ok=False)
sha=lambda b:hashlib.sha256(b).hexdigest()
def read(p,limit=2097152):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode)and a.st_uid==os.getuid()and a.st_nlink==1 and a.st_size<=limit
  b=os.read(fd,a.st_size+1);z=os.fstat(fd);assert len(b)==a.st_size and(a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
  return b
 finally:os.close(fd)
pins={}
for name in ('logs_2.sqlite','logs_2.sqlite-wal','logs_2.sqlite-shm'):
 p=home/name
 if not p.exists():continue
 b=read(p);pins[name]={'bytes':len(b),'sha256':sha(b)}
 fd=os.open(out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb',closefd=False)as f:f.write(b);f.flush();os.fsync(fd)
 finally:os.close(fd)
assert all(sha(read(home/n))==v['sha256']for n,v in pins.items())
r={'schema':'heptabao.native-r2c-private-log-projection.v1','sourcePins':pins,'sourceReadOnly':True,'newSnapshotOnly':True,'nativeStarted':False,'providerCalled':False,'maxRowsPerTable':64}
db=sqlite3.connect((out/'logs_2.sqlite').as_uri()+'?mode=ro',uri=True);db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON')
try:
 tables=[x[0]for x in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
 assert len(tables)<=24 and all(re.fullmatch('[A-Za-z0-9_]+',t)for t in tables)
 result=[]
 patterns={'accountsCheck':r'accounts/check','workspaceRouting':r'workspace.{0,12}rout','timeout':r'timed out|timeout','dns':r'dns|resolve.{0,12}host|name resolution','networkUnreachable':r'network is unreachable|no route to host','connectionRefused':r'connection refused','connectError':r'error.{0,10}connect|tcp connect|failed to connect','cloudConfig':r'cloud.{0,12}config|requirements','keyring':r'keyring|secret service|dbus','permission':r'permission denied|read-only file system','accountRead':r'account/read|get_account','initialized':r'initializ','refresh':r'refresh','httpUnauthorized':r'401|unauthorized','requestFailed':r'error sending request|request failed'}
 for t in tables:
  columns=[x[1]for x in db.execute('PRAGMA table_info("'+t+'")')]
  assert len(columns)<=64 and all(re.fullmatch('[A-Za-z0-9_]+',c)for c in columns)
  entry={'table':t,'columns':columns,'rowCount':db.execute('SELECT count(*) FROM "'+t+'"').fetchone()[0]}
  message=next((x for x in ('message','body','msg')if x in columns),None)
  if message:
   rows=db.execute('SELECT * FROM "'+t+'" ORDER BY rowid DESC LIMIT 64').fetchall();classified=[]
   for row in rows:
    value=row[message]
    if not isinstance(value,str):continue
    targets=[str(row[c])for c in ('target','module','module_path')if c in columns and row[c]is not None]
    target=next((p for p in ('codex_app_server','codex_login','codex_core','codex_backend_client','reqwest','hyper','h2')if any(v.startswith(p)for v in targets)),'other')
    levels=[str(row[c]).upper()for c in ('level','severity')if c in columns]
    level=next((v for v in levels if v in ('TRACE','DEBUG','INFO','WARN','WARNING','ERROR')),'other')
    classified.append({'messageBytes':len(value.encode()),'messageSha256':sha(value.encode()),'targetCategory':target,'level':level,'classes':{k:bool(re.search(v,value,re.I))for k,v in patterns.items()}})
   entry['selectedRecentRows']=len(classified);entry['classifications']=classified
  result.append(entry)
 r['tables']=result
finally:db.close()
r['sourcePinsUnchangedAfter']=all(sha(read(home/n))==v['sha256']for n,v in pins.items())
assert r['sourcePinsUnchangedAfter']
text=json.dumps(r,sort_keys=True)+'\n';fd=os.open(out/'result.public.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:os.write(fd,text.encode());os.fsync(fd)
finally:os.close(fd)
print(text,end='')
