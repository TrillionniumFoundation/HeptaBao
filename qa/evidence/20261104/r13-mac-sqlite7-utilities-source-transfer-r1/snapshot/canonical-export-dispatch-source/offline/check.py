import ast,base64,difflib,hashlib,json,sys
x=json.loads(sys.argv[1]);old=x['old'];new=x['new'];bt=ast.parse(old);at=ast.parse(new);compile(new,'stage_source_export.py','exec')
b=[n for n in bt.body if isinstance(n,ast.FunctionDef)];a=[n for n in at.body if isinstance(n,ast.FunctionDef)]
assert [n.name for n in a]==[n.name for n in b] and len(a)==5
assert all(ast.get_source_segment(old,bb)==ast.get_source_segment(new,aa) for aa,bb in zip(a,b))
inverse=new
for e in reversed(x['edits']):
 assert inverse.count(e['after'])==1
 inverse=inverse.replace(e['after'],e['before'],1)
assert inverse==old
payload=json.loads(x['carrier'])
assert set(payload)=={'schema','files'} and payload['schema']=='heptabao.phaseb3cb-source-export-inputs.v1'
assert list(payload['files'])==['source_export_phaseb_3cb_r1.py']
raw=base64.b64decode(payload['files']['source_export_phaseb_3cb_r1.py'],validate=True)
assert len(raw)==15352 and hashlib.sha256(raw).hexdigest()=='7c8912c99b86742a072329d883d4c28c5f36a6581114197bfd5638b06076a72a'
compile(raw,'source_export_phaseb_3cb_r1.py','exec')
print(json.dumps({'status':'passed_source_only','functions_preserved':5,'inverse_whole_equal':True,'decoded_exporter_sha256':hashlib.sha256(raw).hexdigest(),'candidate_modules_executed':False,'host_access':False,'diff':''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='reference/stage_shared_controls.py',tofile='source/stage_source_export.py'))},sort_keys=True))
