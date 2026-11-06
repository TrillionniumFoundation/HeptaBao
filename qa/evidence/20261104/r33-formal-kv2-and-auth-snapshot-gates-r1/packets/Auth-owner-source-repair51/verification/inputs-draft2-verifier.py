import ast,difflib,hashlib,json,pathlib
p=pathlib.Path('authbus_registration_body4_recovery_r1/owner-repair/exact')
b=(p/'inputs.before.py').read_text();r1=(p/'inputs.after.draft1.py').read_text();r2=(p/'inputs.after.draft2.py').read_text()
compile(ast.parse(r2),'candidate','exec')
def method(s):return next(x for x in ast.walk(ast.parse(s)) if isinstance(x,ast.FunctionDef) and x.name=='admit_actual_harnesses')
def npmloop(s):return next(x for x in ast.walk(method(s)) if isinstance(x,ast.For) and isinstance(x.target,ast.Name) and x.target.id=='name')
oldnpm=npmloop(b);newnpm=next(x for x in ast.walk(method(r2)) if isinstance(x,ast.For) and isinstance(x.target,ast.Name) and x.target.id=='name' and isinstance(x.iter,ast.Tuple) and len(x.iter.elts)==3 and all(isinstance(n,ast.Constant) for n in x.iter.elts) and x.iter.elts[0].value=='openclaw.plugin.json')
assert ast.dump(oldnpm,include_attributes=False)==ast.dump(newnpm,include_attributes=False)
def definitions(s):return {x.name:ast.get_source_segment(s,x) for x in ast.walk(ast.parse(s)) if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef))}
x,y=definitions(r1),definitions(r2)
assert all(y[k]==v for k,v in x.items() if k!='admit_actual_harnesses')
assert 'OWNER_PUBLIC_BINDING_READY=False' in r2
full=''.join(difflib.unified_diff(b.splitlines(True),r2.splitlines(True),fromfile='inputs.before.py',tofile='inputs.after.draft2.py'))
delta=''.join(difflib.unified_diff(r1.splitlines(True),r2.splitlines(True),fromfile='inputs.after.draft1.py',tofile='inputs.after.draft2.py'))
(p/'inputs.draft2.review.diff').write_text(full);(p/'inputs.draft1-to-draft2.diff').write_text(delta)
print(json.dumps({'schema':'heptabao.owner-inputs-npm-preservation.delta.v1','compileOnly':True,'originalNpmReadLoopAstExact':True,'otherDraft1DefinitionsByteExact':True,'publicBindingReady':False,'afterBytes':len(r2.encode()),'afterSha256':hashlib.sha256(r2.encode()).hexdigest(),'fullDiff':full,'delta':delta,'hostCalls':0,'candidateModulesExecuted':False},indent=2))
