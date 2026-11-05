import ast,base64,hashlib,json
from pathlib import Path
p=Path('/tmp/heptabao_qa12_transport_unbound_r1')
d=json.loads((p/'carrier-input.json').read_text())
compile(d['after'],'inert_carrier.py','exec')
def blocks(s):
    ls=s.splitlines(keepends=True)
    return {n.name:''.join(ls[n.lineno-1:n.end_lineno]) for n in ast.parse(s).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
assert blocks(d['before'])==blocks(d['after'])
v=json.loads(d['payload'])
assert set(v)=={'schema','files'} and v['schema']=='heptabao.df026-shared-h2qa12-inputs.v1'
assert set(v['files'])==set(d['sources']) and len(d['payload'].encode())<=262144
for n,s in d['sources'].items():
    assert base64.b64decode(v['files'][n],validate=True)==s.encode()
pins=next(ast.literal_eval(n.value) for n in ast.parse(d['after']).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PINS' for t in n.targets))
assert pins=={n:[len(s.encode()),hashlib.sha256(s.encode()).hexdigest()] for n,s in d['sources'].items()}
print(json.dumps({'status':'passed','whole_compile_only':1,'unchanged_carrier_definitions':list(blocks(d['after'])),'decoded_sources':3,'stdin_cap':262144,'stdin_actual':len(d['payload'].encode()),'module_execution':False,'host_actions':0,'transport_execution':False},sort_keys=True))
