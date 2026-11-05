import ast,json,sys,hashlib
x=json.loads(sys.argv[1]);s=x['source'];req=x['request'];t=ast.parse(s);compile(t,'metadata-source','exec');checks=[]
def ck(v,n):
 if not v:raise AssertionError(n)
 checks.append(n)
assign={q.targets[0].id:q.value for q in t.body if isinstance(q,ast.Assign) and len(q.targets)==1 and isinstance(q.targets[0],ast.Name)}
targets=ast.literal_eval(assign['TARGETS']);parents=ast.literal_eval(assign['PARENTS'])
live='/Users/qianqi/.openclaw';agents=['main','trnm','hepta-ui','hepta','hepta-backend'];expected=[]
def add(label,path,role,maximum,optional,private):
 expected.append(dict(label=label,path=path,role=role,maximum=maximum,optional=optional,privateMode=private))
def db(label,path):
 add(label,path,'database_main',None,False,True)
 for name,maximum in [('wal',0),('shm',8388608),('journal',0)]:add(label+'_'+name,path+'-'+name,'database_'+name,maximum,True,True)
add('config',live+'/openclaw.json','small_read',1048576,False,True)
for a in agents:db('auth_'+a,live+'/agents/'+a+'/agent/openclaw-agent.sqlite')
for f in ['applied-profiles.json','publish-baseline.json','bad-refresh-quarantine.json','refresh-backoff.json','lease-epochs.json','status.json']:add('cache_'+f,live+'/authbus/'+f,'small_read',1048576,True,True)
for a in agents:
 for f in ['config.toml','requirements.toml','auth.json']:add('native_'+a+'_'+f,live+'/agents/'+a+'/agent/codex-home/'+f,'small_read',1048576,True,f=='auth.json')
db('installed_registry',live+'/state/openclaw.sqlite')
ck(targets==expected and len(targets)==46,'exact_46_capture_leaf_order_and_original_caps')
wanted={'/'}
for q in targets:
 path=q['path'].rsplit('/',1)[0]
 while path!='/':
  wanted.add(path);path=path.rsplit('/',1)[0] or '/'
ck(set(parents)==wanted and len(parents)==22,'exact_22_ancestor_set')
seen=set()
for path in parents:
 ck(path=='/' or (path.rsplit('/',1)[0] or '/') in seen,'parent_precedes_'+path)
 seen.add(path)
imports=[]
for n in t.body:
 if isinstance(n,ast.Import):imports.extend(v.name for v in n.names)
 if isinstance(n,ast.ImportFrom):imports.append(n.module)
ck(sorted(imports)==sorted(['json','os','signal','stat','sys','time','contextlib','pathlib']),'fixed_imports')
os_calls=sorted({n.func.attr for n in ast.walk(t) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='os'})
ck(os_calls==['close','fstat','getgid','getuid','lstat','open','stat'],'only_allowed_os_calls')
names={n.id for n in ast.walk(t) if isinstance(n,ast.Name)};attrs={n.attr for n in ast.walk(t) if isinstance(n,ast.Attribute)}
ck(not names.intersection({'eval','exec','__import__','open','hashlib','sqlite3','subprocess','socket','ctypes'}),'no_dynamic_private_body_or_child_access')
ck(not attrs.intersection({'read','read_bytes','read_text','readinto','listdir','scandir','glob','rglob','iterdir','walk','write_text','write_bytes','unlink','mkdir','rename','replace','O_WRONLY','O_RDWR','O_CREAT','O_TRUNC','O_APPEND'}),'no_body_read_directory_enumeration_or_mutation')
ck(req['host']=='mac' and req['executable']=='/opt/homebrew/bin/python3' and req['cwd']=='/Users/qianqi','exact_host_python_cwd')
ck(req['args']==['-I','-S','-B','-c',s] and req['stdin']=='' and req['timeout_seconds']==60,'request_source_whole')
ck(req['idempotency_key']=='heptabao-mac-current-capture-size-metadata-3ba165eb-20261105-r1','exact_unique_key')
ck(hashlib.sha256(s.encode()).hexdigest()=='3ba165eb8073c87217d2e5f076fb8dcb65c2ccec4f2fb7637926d36960295fd4' and len(s.encode())==22077,'whole_source')
out={'status':'source_only_passed','executed_candidate':False,'checks':checks,'checks_passed':len(checks),'targets':46,'parents':22,'os_calls':os_calls,'source_sha256':hashlib.sha256(s.encode()).hexdigest()}
print(json.dumps(out,sort_keys=True))
