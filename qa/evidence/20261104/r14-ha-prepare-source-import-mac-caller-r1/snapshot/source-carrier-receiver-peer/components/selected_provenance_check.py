import ast,hashlib,json,sys
before,after,raw=json.loads(sys.argv[1])
def blocked(event,args):
 if event=='open' or event.startswith(('socket.','subprocess.')) or event in {'os.system','os.fork','os.exec','os.posix_spawn','os.mkdir','os.rename','os.unlink','os.remove'}:raise RuntimeError('offline_source_review_io_refused')
sys.addaudithook(blocked)
b=ast.parse(before);a=ast.parse(after)
def defs(m,s):return {n.name:ast.get_source_segment(s,n) for n in m.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
bd,ad=defs(b,before),defs(a,after)
unchanged=sorted(set(bd)&set(ad)-{'receive'})
assert len(unchanged)==9 and all(bd[n]==ad[n] for n in unchanged)
values={n.targets[0].id:ast.literal_eval(n.value) for n in a.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in {'HEAD','TREE','FILES'}}
f=next(n for n in a.body if isinstance(n,ast.FunctionDef) and n.name=='receive')
start=next(i for i,n in enumerate(f.body) if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='exported' for x in n.targets))
end=next(i for i,n in enumerate(f.body[start:],start) if isinstance(n,ast.Assert) and 'os.listdir' in ast.get_source_segment(after,n))
block=f.body[start:end]
env={'json':json,**values,'json_bytes':{'source-export.result.public.json':raw.encode()}}
exec(compile(ast.Module(body=block,type_ignores=[]),'<actual-receiver-export-provenance>','exec'),env)
item=values['FILES'][0];exported=env['exported'];identity=exported['bundle']['identity']
assert item['version']==':'.join(str(identity[i]) for i in (0,1,6,7,8))
assert values['FILES'][1]['bytes']==len(raw.encode()) and values['FILES'][1]['sha256']==hashlib.sha256(raw.encode()).hexdigest()
print(json.dumps({'schema':'heptabao.phaseb3cb.source-receiver-peer-pure-check.v1','status':'passed','identical_definitions':unchanged,'identical_definitions_count':len(unchanged),'actual_provenance_assertions':sum(isinstance(n,ast.Assert) for n in block),'actual_raw_export_receipt_accepted':True,'bundle_metadata_version_exact_raw_ns':True,'receipt_original_sha256':hashlib.sha256(raw.encode()).hexdigest(),'complete_modules_executed':False,'host_calls':0,'network_calls':0,'child_processes':0,'python_version':sys.version},sort_keys=True,indent=2))
