import ast,difflib,hashlib,json,pathlib,sys
x=json.loads(pathlib.Path(sys.argv[1]).read_text());out=pathlib.Path(sys.argv[2]);out.mkdir(exist_ok=True)
a=x['before'];b=x['after'];v=a
for old,new in x['edits']:
 assert v.count(old)==1
 v=v.replace(old,new,1)
assert v==b
for old,new in reversed(x['edits']):
 assert v.count(new)==1
 v=v.replace(new,old,1)
assert v==a
at,bt=ast.parse(a),ast.parse(b);compile(bt,'bound_importer.py','exec')
def defs(src,t):return {n.name:ast.get_source_segment(src,n) for n in t.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
ad,bd=defs(a,at),defs(b,bt);assert ad==bd
def literal(t,name):
 n=next(n for n in t.body if isinstance(n,ast.Assign) and any(isinstance(v,ast.Name) and v.id==name for v in n.targets))
 return ast.literal_eval(n.value)
assert literal(at,'ACTUAL_INPUTS_READY') is False and literal(bt,'ACTUAL_INPUTS_READY') is True
old_files=literal(at,'FILES');new_files=literal(bt,'FILES')
old_tr=literal(at,'TRANSFER');new_tr=literal(bt,'TRANSFER')
for old,new,info in zip(old_files,new_files,x['infos'][:2],strict=True):
 assert old['version'] is None and new=={**old,'version':info['version']}
 assert new['path']==info['path'] and new['sha256']==info['sha256'] and new['bytes']==info['size'] and new['mode']==info['mode']==256
info=x['infos'][2];assert new_tr=={**old_tr,'bytes':info['size'],'sha256':info['sha256'],'version':info['version']}
assert new_tr['path']==info['path'] and new_tr['mode']==info['mode']==384
for k in ('bytes','sha256','version'):assert old_tr[k] is None
q=x['request']
assert q['host']=='desktop' and q['executable']=='/usr/bin/python3'
assert q['args']==['-I','-S','-B','-c',b] and q['timeout_seconds']==330
sha=lambda s:hashlib.sha256(s.encode()).hexdigest()
assert q['idempotency_key']=='heptabao-df026-standalone-import-'+sha(b)[:8]+'-20261105-r1'
diff=''.join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile='reference/importer.unresolved.py',tofile='candidate/importer.bound.py'))
(out/'importer-five-slots.review.diff').write_text(diff)
report={'schema':'heptabao.df026.standalone-importer.actual-binding-review.v1','status':'passed_source_only','before_bytes':len(a.encode()),'before_sha256':sha(a),'after_bytes':len(b.encode()),'after_sha256':sha(b),'exact_field_changes':['FILES[0].version','FILES[1].version','TRANSFER.bytes','TRANSFER.sha256','TRANSFER.version','ACTUAL_INPUTS_READY'],'all_definitions_byte_identical':len(ad),'all_definition_names':list(ad),'whole_inverse_equal':True,'parsed_compiled_not_executed':True,'dispatch_bound_exact':True,'host_operation':False,'source_imported':False,'original_caps':{'total':300,'git':60,'clone':90,'term':5,'kill':5,'outer':330}}
(out/'binding-review.public.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps(report,sort_keys=True))
