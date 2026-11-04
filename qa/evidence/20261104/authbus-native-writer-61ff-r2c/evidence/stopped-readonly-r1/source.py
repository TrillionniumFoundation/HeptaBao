import os,json,pathlib,hashlib,sqlite3,stat,ast,tomllib,urllib.parse,re
root=pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-native-writer-61ff8bef-baseline-r2c/run-r1/live');work=root/'consumer-active-lease';home=work/'state/home/.codex'
sha=lambda b:hashlib.sha256(b).hexdigest()
def read(p,limit=2097152):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode)and a.st_uid==os.getuid()and a.st_nlink==1 and a.st_size<=limit
  b=os.read(fd,a.st_size+1);z=os.fstat(fd);assert len(b)==a.st_size and(a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
  return b
 finally:os.close(fd)
r={'schema':'heptabao.native-r2c-stopped-readonly-diagnostic.v1','readOnly':True,'diagnosticNativeStarted':False,'diagnosticProviderCalled':False}
raw=read(work/'native/consumer-initial-error.private.json');assert sha(raw)=='e2761351d3454ae51cc2df391f3148c7aea5a719145f49a5352cd2b403e10bdf';error=json.loads(raw)
r['originalError']={'sha256':sha(raw),'class':error.get('name') if error.get('name')in('Error','TypeError','RangeError','SyntaxError')else'unknown','messageExactAccountReadTimeout':error.get('message')=='account/read timed out','frames':[{'file':m.group(1),'line':int(m.group(2))}for m in re.finditer(r'([A-Za-z0-9_.-]+\.(?:mjs|js)):(\d+):\d+',error.get('stack',''))][:8]}
nativeAuth=read(home/'auth.json');tokens=json.loads(nativeAuth).get('tokens',{});secret=[v for v in tokens.values() if isinstance(v,str)and len(v)>=8]
configRaw=read(home/'config.toml');config=tomllib.loads(configRaw.decode())
r['nativeClone']={'authSha256':sha(nativeAuth),'configSha256':sha(configRaw)}
def publicString(v,allowed):
 return v if isinstance(v,str)and v in allowed else None
r['nativeConfiguration']={'topLevelKeys':sorted(config),'credentialStoreKeyPresent':'cli_auth_credentials_store'in config,
 'credentialStore':publicString(config.get('cli_auth_credentials_store'),{'file','keyring','auto','ephemeral'}),
 'credentialStoreValueSha256':sha(json.dumps(config.get('cli_auth_credentials_store'),sort_keys=True).encode()),
 'modelKeyPresent':'model'in config,'modelProviderKeyPresent':'model_provider'in config,
 'modelValueSha256':sha(json.dumps(config.get('model'),sort_keys=True).encode()),
 'modelProviderValueSha256':sha(json.dumps(config.get('model_provider'),sort_keys=True).encode())}
def urlProjection(value):
 if not isinstance(value,str):return {'present':False}
 u=urllib.parse.urlsplit(value);return {'present':True,'scheme':u.scheme,'hostSha256':sha((u.hostname or '').encode()),'port':u.port,'hasUserinfo':bool(u.username or u.password),'hasQuery':bool(u.query)}
r['nativeConfiguration']['chatgptBaseUrl']=urlProjection(config.get('chatgpt_base_url'))
r['nativeConfiguration']['modelProviders']=[{'nameSha256':sha(str(k).encode()),'baseUrl':urlProjection(v.get('base_url')),'hasEnvKey':'env_key'in v}for k,v in config.get('model_providers',{}).items()if isinstance(v,dict)]
for key in r['nativeConfiguration']['topLevelKeys']:assert not any(s in key for s in secret)
files=[];logs=[];directories=0
for directory,dirnames,filenames in os.walk(home,followlinks=False):
 directories+=1;assert directories<=24;dirnames[:]=[n for n in dirnames if not(pathlib.Path(directory)/n).is_symlink()]
 for name in filenames:
  p=pathlib.Path(directory)/name;s=p.lstat()
  if not stat.S_ISREG(s.st_mode):continue
  assert len(files)<96;rel=str(p.relative_to(home))
  safeRel=rel if not any(x in rel for x in secret)else'sha256:'+sha(rel.encode())
  item={'relativePath':safeRel,'bytes':s.st_size};files.append(item)
  if name.endswith('.log')and s.st_size<=65536:
   b=read(p,65536);classes={k:bool(re.search(v,b,re.I))for k,v in {'permission':b'permission denied|read-only file system','network':b'network is unreachable|connection refused|dns|timed out','keyring':b'keyring|secret service|dbus','sqlite':b'sqlite|database is locked','auth':b'authentication|unauthorized|token expired','modelCache':b'model.*cache|cache.*model','initialize':b'initializ'}.items()}
   logs.append({'relativePath':safeRel,'bytes':len(b),'sha256':sha(b),'classifiers':classes})
r['nativeGeneratedFiles']=files;r['nativeLogClassifiers']=logs
for n in ('stdout.private','stderr.private','runtime-selection.private.json','state/authbus/status.json'):
 p=work/n;r.setdefault('consumerFiles',{})[n]={'exists':p.exists()}
 if p.exists():
  b=read(p);r['consumerFiles'][n].update(bytes=len(b),sha256=sha(b))
source=json.loads(read(root/'source-auth-tables.private.json'));tree=ast.parse(pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-native-writer-61ff8bef-baseline-r2c/control/driver.py').read_text())
assignments=[n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='TABLES'for t in n.targets)];assert len(assignments)==1;tables=ast.literal_eval(assignments[0].value)
db=sqlite3.connect((work/'state/agents/main/agent/openclaw-agent.sqlite').as_uri()+'?mode=ro',uri=True);db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
try:
 now={}
 for k,(table,key,column)in tables.items():
  assert all(v.replace('_','').isalnum()for v in(table,key,column))
  now[k]=[list(t)for t in db.execute('SELECT '+key+','+column+',updated_at FROM '+table+' ORDER BY '+key)]
 db.rollback();enc=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
 r['rawAuthRows']={k:{'exactOriginalRows':now[k]==source['rows'][k],'sourceSha256':sha(enc(source['rows'][k])),'currentSha256':sha(enc(now[k]))}for k in tables};r['wholeRawAuthRowsExact']=now==source['rows']
finally:db.close()
out=json.dumps(r,sort_keys=True);assert not any(x in out for x in secret);print(out)
