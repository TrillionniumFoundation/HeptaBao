import os,json,pathlib,hashlib,sqlite3,stat
root=pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-native-writer-61ff8bef-baseline-r1/run-r1/live')
work=root/'consumer-active-lease'
sha=lambda b:hashlib.sha256(b).hexdigest()
def read(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and a.st_nlink==1 and a.st_size<=2097152
  b=os.read(fd,a.st_size+1);z=os.fstat(fd);assert len(b)==a.st_size and(a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
  return b
 finally:os.close(fd)
r={'schema':'heptabao.native-baseline-failure-readonly-projection.v1','readOnly':True,'nativeStarted':False,'providerCalled':False,'files':{}}
for name in ('stdout.private','stderr.private','baseline-store.private.json','runtime-selection.private.json','auth.private.json','state/authbus/status.json'):
 p=work/name
 if not p.exists():r['files'][name]={'exists':False};continue
 b=read(p);r['files'][name]={'exists':True,'bytes':len(b),'sha256':sha(b)}
 if name=='stderr.private':r['stderrClassifiers']={x:x.encode() in b for x in ('SyntaxError','TypeError','ReferenceError','EACCES','EROFS','Error','Warning')}
r['nativeOutput']=[{'name':p.name,'bytes':p.stat().st_size,'sha256':sha(read(p))}for p in sorted((work/'native').iterdir()) if p.is_file()]
r['nativeCloneExact']={n:sha(read(work/'state/home/.codex'/n))==h for n,h in [('auth.json','f4aee2935351eaa6d56ce99166a0123c3c9e3260ae8737e6d7ad8ce2c8c12b78'),('config.toml','57c13259d009c266c37d1c4578596c0a6236dae3862eccedb3eb74a99084c350')]}
p=work/'state/agents/main/agent/openclaw-agent.sqlite'
db=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True);db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
try:
 source=json.loads(read(root/'source-auth-tables.private.json'))
 tables={'store':('openclaw_auth_profile_store','store_key','value_json'),'state':('openclaw_auth_profile_state','state_key','value_json')}
 # Use the exactly pinned original driver's declared table mapping, never infer schema.
 import ast
 tree=ast.parse(pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-native-writer-61ff8bef-baseline-r1/control/driver.py').read_text())
 assignments=[n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='TABLES' for t in n.targets)]
 assert len(assignments)==1;tables=ast.literal_eval(assignments[0].value)
 now={}
 for k,(table,key,column) in tables.items():
  assert all(v.replace('_','').isalnum() for v in (table,key,column))
  now[k]=[list(t)for t in db.execute('SELECT '+key+','+column+',updated_at FROM '+table+' ORDER BY '+key)]
 db.rollback()
 enc=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
 r['rawAuthRows']={k:{'exactOriginalRows':now[k]==source['rows'][k],'sourceSha256':sha(enc(source['rows'][k])),'currentSha256':sha(enc(now[k]))}for k in tables}
 r['wholeRawAuthRowsExact']=now==source['rows']
finally:db.close()
print(json.dumps(r,sort_keys=True))
