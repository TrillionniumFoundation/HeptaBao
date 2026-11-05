import ast,json,hashlib,base64
from pathlib import Path
root=Path('/tmp/heptabao_4e808_normal5_source_r1')
data=json.loads((root/'input.json').read_text())
checks=[]
def need(name,value):
    checks.append({'name':name,'passed':bool(value)})
    if not value: raise AssertionError(name)
def assignment(tree,name):
    values=[n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
    need('one assignment '+name,len(values)==1)
    return ast.literal_eval(values[0])
definitions={}
for name,before in data['before'].items():
    after=data['after'][name]
    trees=[ast.parse(s,filename=name) for s in (before,after)]
    for tree in trees: compile(tree,name,'exec')
    funcs=[]
    for text,tree in zip((before,after),trees):
        funcs.append([(n.name,ast.get_source_segment(text,n)) for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))])
    need(name+' all ordered definitions byte identical',funcs[0]==funcs[1])
    definitions[name]=len(funcs[0])
    if name!='inert-carrier.py':
        need(name+' ready actual',assignment(trees[1],'ACTUAL_INPUTS_READY') is True)
        need(name+' actual table exact',assignment(trees[1],'FILES')==data['table'])
        need(name+' current commit',assignment(trees[1],'HEAD')==data['head'])
        need(name+' current tree',assignment(trees[1],'TREE')==data['tree'])
        need(name+' no None binding',all(x['bytes']>0 and len(x['sha256'])==64 and x['version'] for x in data['table']))
need('fixed five names', [x['name'] for x in data['table']]==['heptabao-server','native-build.public.json','normal-release-result.public.json','normal-release-tests-result.public.json','groups.json'])
need('exact source and destination permissions',[(x['source_mode'],x['target_mode']) for x in data['table']]==[(0o500,0o500)]+[(0o600,0o400)]*4)
for row in data['table']:
    actual=data['metadata'][row['name']]
    need(row['name']+' actual whole/version',all(row[k]==actual[j] for k,j in [('path','path'),('bytes','size'),('sha256','sha256'),('version','version')]))
    need(row['name']+' actual uid/gid/nlink',actual['metadata']['uid']==1000 and actual['metadata']['gid']==1000 and actual['metadata']['link_count']==1)
payload=json.loads(data['inert']['stdin'])
need('inert exact schema and file set',set(payload)=={'schema','files'} and payload['schema']=='heptabao.4e808-shared-normal5-inputs.v1' and set(payload['files'])=={'sender.py','receiver.py','relay.py'})
pins=assignment(ast.parse(data['after']['inert-carrier.py']),'PINS')
for name,encoded in payload['files'].items():
    raw=base64.b64decode(encoded,validate=True)
    need(name+' payload exact',raw==data['after'][name].encode() and pins[name]==[len(raw),hashlib.sha256(raw).hexdigest()])
need('inert raw stdin cap',0<len(data['inert']['stdin'].encode())<=262144)
need('inert exact argv',data['inert']['args']==['-I','-S','-B','-c',data['after']['inert-carrier.py']])
need('inert and relay budgets',data['inert']['timeout_seconds']==60 and data['relay']['timeout_seconds']==360)
need('relay invocation from actual source',data['relay']['args']==['-I','-S','-B','/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-shared-artifact-controls-r1/relay.py'])
need('both desktop and fixed cwd',all(x['host']=='desktop' and x['executable']=='/usr/bin/python3' and x['cwd']=='/home/qian-qi/heptabao-ha-closure-20261103-r1' for x in [data['inert'],data['relay']]))
report={'schema':'heptabao.4e808-normal5-selected-source-checks.v1','status':'passed','checks':checks,'ordered_definition_counts':definitions,'total_definitions_unchanged':sum(definitions.values()),'compiled_only':4,'candidate_modules_executed':0,'remote_requests':0,'cargo':0,'service_requests':0}
text=json.dumps(report,indent=2)+'\n'
(root/'result.public.json').write_text(text)
print(text,end='')
