import pathlib,json,hashlib,os,stat,sqlite3,re,shlex,zlib,base64
HOME=pathlib.Path('/home/qian-qi');LIVE=HOME/'.openclaw'
sha=lambda b:hashlib.sha256(b).hexdigest()
canon=lambda o:json.dumps(o,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def read(p,want=None):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb')as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=1048576;b=f.read();t=os.fstat(f.fileno())
  assert (s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(t.st_size,t.st_mtime_ns,t.st_ctime_ns)
 if want:assert sha(b)==want
 return b
r={'schema':'heptabao.desktop-source-ownership-supplement.v1','providerCalled':False,'productionChanged':False,'serviceActions':[],'credentialValuesPublished':False,'kernelRootReadOnly':bool(os.statvfs('/').f_flag&os.ST_RDONLY),'heldGuards':[],'runtimeOverrides':[],'authState':[]}
assert r['kernelRootReadOnly']
prefix=HOME/'.config/systemd/user'
for rel,want in [('openclaw-gateway.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf','d5dfba6bd4f9b3198b582084f755bdca4116866fde6cc1aa864b64a02a84de26'),('openclaw-authbus-accept-after-restart.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf','1f5435149ad6bccd48ee9bb6a6a26f1dbe8652d6634fa3da8b2494839257e8f9'),('openclaw-authbus-restart-when-idle.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf','13b0f19464a97726db94b95a8ec48b1465d972f958b21f87b77a185c0b5d088f')]:
 p=prefix/rel;b=read(p,want);o={'path':str(p),'sha256':sha(b),'conditions':[]}
 for line in b.decode().splitlines():
  if '='not in line or line.strip().startswith(('#',';')):continue
  k,v=line.strip().split('=',1)
  if k.startswith(('Condition','Assert')):
   item={'name':k,'valueSha256':sha(v.encode())}
   value=v.lstrip('!|')
   if value.startswith('/home/qian-qi/')and re.fullmatch(r'[/A-Za-z0-9_.-]+',value):
    item.update({'path':value,'negated':'!'in v[:2],'trigger':'|'in v[:2],'pathExists':pathlib.Path(value).exists()})
   o['conditions'].append(item)
  elif k.startswith('Exec'):
   o['conditions'].append({'name':k,'commandSha256':sha(v.encode()),'execPresent':bool(v)})
 r['heldGuards'].append(o)
for name in ['openclaw-gateway.service.d/40-ai-max-codex-harness.conf','ai-max-codex-responses.service.d/50-openresponses-native-cutover.conf']:
 p=prefix/name;b=read(p);o={'path':str(p),'sha256':sha(b),'fields':[]}
 for line in b.decode().splitlines():
  if '='not in line or line.strip().startswith(('#',';')):continue
  k,v=line.strip().split('=',1)
  if k=='Environment':
   for t in shlex.split(v):
    if '='not in t:continue
    name,value=t.split('=',1);d={'name':name,'valueSha256':sha(value.encode())}
    if name in ['OPENCLAW_AI_MAX_CODEX_BIN','OPENCLAW_AI_MAX_CODEX_RESPONSES_BASE_URL','OPEN_RESPONSES_PORT']:d['value']=value
    o['fields'].append(d)
  elif k=='ExecStart'and v:
   args=shlex.split(v);o['fields'].append({'key':k,'scriptPaths':[x for x in args if x.startswith('/home/qian-qi/')and pathlib.Path(x).suffix in ['.js','.mjs','.py']],'argumentCount':len(args),'sha256':sha(v.encode())})
 r['runtimeOverrides'].append(o)
for agent in ['main','resident-helper','independent-helper','telegram-bot-8681289317','telegram-bot-8449317572','hepta-paper-worker']:
 p=LIVE/'agents'/agent/'agent/openclaw-agent.sqlite';db=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True,timeout=3)
 try:
  db.execute('PRAGMA query_only=ON');db.execute('PRAGMA temp_store=MEMORY');db.execute('BEGIN');rows=db.execute("SELECT state_json,updated_at FROM auth_profile_state WHERE state_key='primary'").fetchall();assert len(rows)<=1
  item={'agentId':agent,'primaryStatePresent':bool(rows)}
  if rows:
   raw,at=rows[0];state=json.loads(raw);item.update({'rawStateSha256':sha(raw.encode()),'canonicalStateSha256':sha(canon(state)),'updatedAtUnixMs':at,'hasOrder':isinstance(state.get('order'),dict),'order':{provider:[sha(x.encode())for x in values]for provider,values in state.get('order',{}).items()if isinstance(values,list)},'usageStatsSha256':sha(canon(state.get('usageStats'))),'usageProfileIdsSha256':[sha(x.encode())for x in state.get('usageStats',{})]})
  r['authState'].append(item);db.rollback()
 finally:db.close()
p=LIVE/'npm/projects/openclaw-codex-8902d781d4__openclaw-generation__g-49fd4dbfde2c5057/node_modules/@openclaw/codex/dist/shared-client-4ICy3U6d.js'
b=read(p,'08769a5a75dfd8f426e8e6f70bc1201e90027c273f8fa247ef3b6549a617de7c');r['fixedPublicSources']=[{'name':'desktop-shared-client-4ICy3U6d.js','path':str(p),'sha256':sha(b),'bytes':len(b),'text':b.decode()}]
raw=canon(r);z=zlib.compress(raw,9)
print(json.dumps({'bytes':len(raw),'sha256':sha(raw),'zlibSha256':sha(z),'dataBase64':base64.b64encode(z).decode()},separators=(',',':')))
