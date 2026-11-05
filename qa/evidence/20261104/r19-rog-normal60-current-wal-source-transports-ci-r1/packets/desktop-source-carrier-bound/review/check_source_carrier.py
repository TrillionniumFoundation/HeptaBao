#!/usr/bin/env python3
"""Offline source/delivery binding check. No target module, process or network."""
import ast, base64, difflib, hashlib, json, pathlib, sys
x=json.loads(pathlib.Path(sys.argv[1]).read_text())
out=pathlib.Path(sys.argv[2]);out.mkdir(exist_ok=True)
def sha(s):return hashlib.sha256(s.encode()).hexdigest()
rows=[]
trees={}
for name,source in x['candidate'].items():
 before=x['reference'][name]
 current=before
 for a,b in x['edits'][name]:
  assert current.count(a)==1,(name,'forward',a[:40])
  current=current.replace(a,b,1)
 assert current==source,(name,'forward whole')
 # Independently reverse by retaining exact full intermediate strings.
 intermediates=[before]
 for a,b in x['edits'][name]:intermediates.append(intermediates[-1].replace(a,b,1))
 reverse=source
 for index in range(len(x['edits'][name])-1,-1,-1):
  a,b=x['edits'][name][index];prior=intermediates[index]
  assert prior.count(a)==1 and prior.replace(a,b,1)==reverse
  reverse=prior
 assert reverse==before
 bt=ast.parse(before);at=ast.parse(source);compile(at,name,'exec');trees[name]=at
 def defs(text,tree):
  return {n.name:ast.get_source_segment(text,n) for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
 old,new=defs(before,bt),defs(source,at)
 assert old.keys()==new.keys()
 changed=[k for k in old if old[k]!=new[k]]
 expected={'sender':[],'receiver':['receive'],'relay':[],'inert':[],'importer':['verify_receipts']}[name]
 assert changed==expected,(name,changed)
 diff=''.join(difflib.unified_diff(before.splitlines(True),source.splitlines(True),fromfile='reference/'+name+'.py',tofile='candidate/'+name+'.py'))
 (out/(name+'.review.diff')).write_text(diff)
 (out/(name+'.py')).write_text(source)
 rows.append({'name':name,'before_bytes':len(before.encode()),'after_bytes':len(source.encode()),'before_sha256':sha(before),'after_sha256':sha(source),'literal_edits':len(x['edits'][name]),'reverse_whole_equal':True,'definitions':len(old),'unchanged_definitions':len(old)-len(changed),'changed_definitions':changed,'parsed_and_compiled_not_executed':True})
def value(tree,name):
 nodes=[n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
 assert len(nodes)==1,name
 return ast.literal_eval(nodes[0].value)
for name in ('sender','receiver','relay'):
 assert value(trees[name],'FILES')==x['expected_files']
 assert value(trees[name],'HEAD')=='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c'
 assert value(trees[name],'TREE')=='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825'
helper=value(trees['relay'],'HELPERS')
assert helper=={n+'.py':sha(x['candidate'][n]) for n in ('sender','receiver')}
pins=value(trees['inert'],'PINS')
assert pins=={n+'.py':[len(x['candidate'][n].encode()),sha(x['candidate'][n])] for n in ('sender','receiver','relay')}
request=x['inert_request'];carrier=json.loads(x['carrier_text'])
assert request['stdin']==x['carrier_text'] and request['args']==['-I','-S','-B','-c',x['candidate']['inert']]
assert request['timeout_seconds']==60 and request['host']=='desktop' and request['executable']=='/usr/bin/python3'
assert carrier['schema']=='heptabao.df026-source-carrier-inputs.v1'
assert set(carrier['files'])==set(pins)
for name,encoded in carrier['files'].items():
 assert base64.b64decode(encoded,validate=True).decode()==x['candidate'][name[:-3]]
transfer=x['transfer_request']
assert transfer['host']=='desktop' and transfer['timeout_seconds']==360
assert transfer['args']==['-I','-S','-B','/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-cold-h2-source-carrier-controls-r1/relay.py']
for item,raw in zip(x['expected_files'],x['actual_file_infos'],strict=True):
 info=json.loads(raw)
 assert (item['path'],item['bytes'],item['sha256'],item['version'])==(info['path'],info['size'],info['sha256'],info['version'])
 assert item['source_mode']==info['mode']==384 and item['target_mode']==256
 assert info['metadata']['uid']==1000 and info['metadata']['link_count']==1
# Execute only the finite consecutive pure receipt assertions, no receive I/O.
func=next(n for n in trees['receiver'].body if isinstance(n,ast.FunctionDef) and n.name=='receive')
begin=next(i for i,n in enumerate(func.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='exported' for t in n.targets))+1
nodes=[]
for node in func.body[begin:]:
 if not isinstance(node,ast.Assert):break
 if any(isinstance(n,ast.Name) and n.id in {'os','DESTINATION'} for n in ast.walk(node)):break
 nodes.append(node)
assert len(nodes)>=18
ns={'exported':json.loads(x['actual_export_raw']),'FILES':x['expected_files'],'HEAD':value(trees['receiver'],'HEAD'),'TREE':value(trees['receiver'],'TREE')}
exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),'<selected-public-receipt-assertions>','exec'),ns)
assert value(trees['importer'],'ACTUAL_INPUTS_READY') is False
assert value(trees['importer'],'SOURCE_FILES')==x['expected_files']
dest=value(trees['importer'],'FILES');tr=value(trees['importer'],'TRANSFER')
assert all(v['version'] is None and v['bytes']==s['bytes'] and v['sha256']==s['sha256'] for v,s in zip(dest,x['expected_files'],strict=True))
assert [tr[k] for k in ('bytes','sha256','version')]==[None,None,None]
assert 'TRANSPORT_PROGRAM_PINS' not in x['candidate']['importer']
report={'schema':'heptabao.df026-source-carrier.source-review.v1','status':'passed_source_only','source_rows':rows,'carrier_and_all_derived_pins_exact':True,'exact_actual_export_versions':True,'selected_pure_receiver_receipt_assertions':len(nodes),'target_modules_executed':False,'host_operations':0,'carrier_readiness':'concrete source for root admission; not dispatched','importer_readiness':False,'remaining_importer_slots':['received_bundle_version','received_export_receipt_version','transfer_receipt_bytes','transfer_receipt_sha256','transfer_receipt_version'],'original_deadlines_preserved':{'relay':300,'endpoints':90,'ssh_connect':10,'cleanup_each':5,'transfer_outer':360,'import':300,'import_git':60,'import_clone':90,'import_outer':330},'scope':'No runtime or new import/transfer qualification'}
(out/'source-review.public.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({'status':report['status'],'definitions':sum(r['definitions'] for r in rows),'actual_receipt_assertions':len(nodes),'rows':rows},sort_keys=True))
