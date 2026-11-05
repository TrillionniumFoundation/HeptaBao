import ast, base64, hashlib, json, pathlib
ROOT=pathlib.Path("/tmp/heptabao_qa12_transport_bound_r1")
data=json.loads((ROOT/'input.json').read_text())
checks=[]
def check(name, value):
    checks.append({'name':name,'passed':bool(value)})
    if not value: raise AssertionError(name)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def assignments(tree, name):
    found=[n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
    check('unique assignment '+name,len(found)==1)
    return ast.literal_eval(found[0])
def definitions(src,tree):
    return [(type(n).__name__,getattr(n,'name',''),ast.get_source_segment(src,n))
            for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
for name, src in data['after'].items():
    old=data['before'][name]; a=ast.parse(src,name); b=ast.parse(old,name)
    compile(a,name,'exec',dont_inherit=True)
    check(name+' definitions whole identical',definitions(src,a)==definitions(old,b))
    check(name+' exact original None table',assignments(b,'FILES')==data['table_before'])
    check(name+' exact bound table',assignments(a,'FILES')==data['table_after'])
    check(name+' ready literal',assignments(a,'ACTUAL_INPUTS_READY') is True and assignments(b,'ACTUAL_INPUTS_READY') is False)
    check(name+' no sys.argv extra argument contract',not any(isinstance(n,ast.Attribute) and isinstance(n.value,ast.Name) and n.value.id=='sys' and n.attr=='argv' for n in ast.walk(a)))
    check(name+' exact instrument commit',assignments(a,'HEAD')=='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c')
    check(name+' exact instrument tree',assignments(a,'TREE')=='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825')
    check(name+' no current product substitution','4e808d0ecb1bcded22870a7ec960dfb2491cf6ec' not in src)
for old,new in zip(data['table_before'],data['table_after']):
    info=json.loads(data['actual_info'][new['role']])
    check(new['role']+' only three slots changed',{k:v for k,v in old.items() if k not in ('bytes','sha256','version')}=={k:v for k,v in new.items() if k not in ('bytes','sha256','version')})
    check(new['role']+' exact actual whole/version',(new['path'],new['bytes'],new['sha256'],new['version'])==(info['path'],info['size'],info['sha256'],info['version']))
    check(new['role']+' actual metadata',(info['metadata']['uid'],info['metadata']['gid'],info['metadata']['mode'],info['metadata']['link_count'])==(1000,1000,new['source_mode'],1))
check('12 roles remain ordered',[r['role'] for r in data['table_before']]==[r['role'] for r in data['table_after']] and len(data['table_after'])==12)
relay=ast.parse(data['after']['relay.py'])
check('exact new helpers',assignments(relay,'HELPERS')=={n:sha(data['after'][n].encode()) for n in ('sender.py','receiver.py')})
ca=ast.parse(data['carrier_after']); cb=ast.parse(data['carrier_before'])
compile(ca,'inert_carrier.py','exec',dont_inherit=True)
check('all inert definitions byte equal',definitions(data['carrier_after'],ca)==definitions(data['carrier_before'],cb))
pins=assignments(ca,'PINS')
check('three exact pins',pins=={n:[len(s.encode()),sha(s.encode())] for n,s in data['after'].items()})
payload=json.loads(data['payload'])
check('payload exact schema and keys',set(payload)=={'schema','files'} and payload['schema']=='heptabao.df026-shared-h2qa12-inputs.v1' and set(payload['files'])==set(pins))
for n,s in data['after'].items():
    check(n+' payload exact bytes',base64.b64decode(payload['files'][n],validate=True)==s.encode())
check('original payload cap',0<len(data['payload'].encode())<=262144 and "read(262145)" in data['carrier_after'])
req=data['inert_request']; rr=data['relay_request']
check('exact inert seven keys',set(req)=={'host','executable','args','cwd','stdin','timeout_seconds','idempotency_key'})
check('inert original invocation',req['host']=='desktop' and req['executable']=='/usr/bin/python3' and req['args']==['-I','-S','-B','-c',data['carrier_after']] and req['stdin']==data['payload'] and req['timeout_seconds']==60)
check('relay invocation from source contract',rr['host']=='desktop' and rr['executable']=='/usr/bin/python3' and rr['args']==['-I','-S','-B','/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-native-h2-qa-shared-artifact-controls-r1/relay.py'] and rr['timeout_seconds']==360 and 'stdin' not in rr)
check('relay precise self filename guard',"assert Path(__file__).resolve(strict=True)==SOURCES/'relay.py'" in data['after']['relay.py'])
check('shared original cwd',req['cwd']==rr['cwd']=='/home/qian-qi/heptabao-ha-closure-20261103-r1')
check('endpoints original 90s','UNTIL=START+90' in data['after']['sender.py'] and 'UNTIL=START+90' in data['after']['receiver.py'])
check('relay original 300s','UNTIL=START+300' in data['after']['relay.py'])
result={'schema':'heptabao.qa12-literal-binding-offline-verification.v1','status':'passed','checks':checks,'compiled_modules':4,'modules_executed':0,'host_requests':0,'child_product_or_runtime_requests':0,'exact_original_limits':True}
text=json.dumps(result,indent=2)+'\n'
(ROOT/'result.public.json').write_text(text)
print(text,end='')
