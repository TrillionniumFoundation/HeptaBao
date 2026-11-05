import ast,base64,hashlib,json
from pathlib import Path
root=Path('/tmp/heptabao_4e808_lan_bound_r1')
d=json.loads((root/'input.json').read_text())
checks=[]
def need(name,value):
    checks.append({'name':name,'passed':bool(value)})
    if not value: raise AssertionError(name)
def val(tree,name):
    found=[n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
    need('single assignment '+name,len(found)==1)
    return ast.literal_eval(found[0])
def defs(s):
    tree=ast.parse(s)
    return [(n.name,ast.get_source_segment(s,n)) for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
payload=json.loads(d['payload'])
need('fixed payload schema',payload['schema']=='heptabao.same-root-publication-validation-control-inert-inputs.v1' and set(payload)=={'schema','files'})
need('same nine source names',list(payload['files'])==d['publish_order'] and len(payload['files'])==9)
sources={name:base64.b64decode(encoded,validate=True).decode() for name,encoded in payload['files'].items()}
count=0
for name,s in sources.items():
    tree=ast.parse(s,filename=name)
    compile(tree,name,'exec')
    count+=len(defs(s))
    need(name+' exact payload pin',[len(s.encode()),hashlib.sha256(s.encode()).hexdigest()]==d['pins'][name])
    if name!=d['launcher_name']: need(name+' complete unchanged',hashlib.sha256(s.encode()).hexdigest()==d['unbound_source_sha256'][name])
new=sources[d['launcher_name']]
a,b=ast.parse(d['launcher_before']),ast.parse(new)
need('all launcher definitions unchanged',defs(d['launcher_before'])==defs(new))
need('actual ten builds exact',val(b,'BUILDS')==d['binding']['all10_actual_artifact_pins'])
need('ten complete SHA256 bindings',len([pin for x in val(b,'BUILDS').values() for pin in x['files'].values()])==10 and all(isinstance(pin,str) and len(pin)==64 and set(pin)<=set('0123456789abcdef') for x in val(b,'BUILDS').values() for pin in x['files'].values()))
for n in ['COMPARISON_PINS','POSTCOLD_CHECKS','QA_PINS','DEADLINE_QA_PINS','COMMIT','TREE','RUNNER_SHA256','NUMERIC_HELPER_SHA256','CIPHER_HELPER_SHA256']:
    need(n+' unchanged',val(a,n)==val(b,n))
need('36 old fences unchanged',len(val(b,'COMPARISON_PINS'))==36)
need('12 postcold names unchanged',len(val(b,'POSTCOLD_CHECKS'))==12)
need('runner exact SHA',val(b,'RUNNER_SHA256')==hashlib.sha256(sources[d['runner_name']].encode()).hexdigest())
need('entry self filename present',("CONTROL / '"+d['launcher_name']+"'") in new)
ca,cb=ast.parse(d['carrier_before']),ast.parse(d['carrier'])
compile(cb,'inert-carrier.py','exec')
need('all inert definitions unchanged',defs(d['carrier_before'])==defs(d['carrier']))
need('nine carrier pins exact',val(cb,'PINS')==d['pins'])
need('unchanged 1MiB stdin cap',len(d['payload'].encode())<=1048576 and 'read(1048577)' in d['carrier'] and 'len(incoming) <= 1048576' in d['carrier'])
need('inert argv exact',d['inert_without_stdin']['args']==['-I','-S','-B','-c',d['carrier']])
need('prepare argv exact',d['prepare']['args']==['-I','-S','-B',d['control']+'/'+d['launcher_name'],'--prepare-only'])
need('original outer stages',d['inert_without_stdin']['timeout_seconds']==60 and d['prepare']['timeout_seconds']==360)
need('two normal61 exact independent counts',d['binding']['qualified_normal61_both_platforms'] and d['binding']['each_platform_original60']==60 and d['binding']['each_platform_additional_same_root_regression']==1)
need('no host or runtime admission',d['binding']['dispatch_authorized'] is False and d['binding']['actual_stage_or_runtime_submitted'] is False)
need('desktop canonical still explicitly unobserved',d['binding']['desktop_source']['exists_claimed'] is False and d['binding']['desktop_source']['actual_complete_import_sha256'] is None)
report={'schema':'heptabao.4e808-lan-actual-binding-source-checks.v1','status':'passed','checks':checks,'candidate_function_class_definitions':count,'inert_definitions':len(defs(d['carrier'])),'compiled_only_sources':10,'candidate_modules_executed':0,'host_requests':0,'products_started':0}
text=json.dumps(report,indent=2)+'\n'
(root/'result.public.json').write_text(text)
print(text,end='')
