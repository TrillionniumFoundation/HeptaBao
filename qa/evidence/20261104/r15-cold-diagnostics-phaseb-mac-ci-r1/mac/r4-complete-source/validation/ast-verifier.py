import ast, hashlib, json
from pathlib import Path
root=Path('/tmp/mac-public-parent-guard-r1-bf4B0d')
expected={
 'after.py':'c160d3593bd6ddce8e9eaea2acd96991af29b43c55713056ff996e9ffa2d2603',
 'outer_r3.py':'5ecc57805f1fb2b162c38d28d28debe5e035ca3135db6b1b7df55daa6227df50',
 'outer_r4.py':'6da29c3dab80e3373638621026f293ddd050a2e4e99f3bc3314ca42bc0005b4f',
 'inert_r3.py':'7e830ba2a0e85c6ba5e2ff7fdf398d18ef7f8964d2aaf706fac57dd9a7487e0c',
 'inert_r4.py':'aece8bec79b525bfb1e0331fdfa8016d9d0ff58380df97161f1ccecb3f42f894',
}
# This verifier never executes any candidate module.
raws={name:(root/name).read_text() for name in list(expected)}
trees={}
for name,raw in raws.items():
    if name in expected:
        assert hashlib.sha256(raw.encode()).hexdigest()==expected[name],name
    trees[name]=ast.parse(raw,filename=name)
    compile(trees[name],name,'exec')
def defs(name):
    return {node.name:node for node in trees[name].body if isinstance(node,ast.FunctionDef)}
def source(name,node):
    return ''.join(raws[name].splitlines(keepends=True)[node.lineno-1:node.end_lineno])
old,new=defs('inert_r3.py'),defs('inert_r4.py')
unchanged=[]
for name in sorted(set(old)&set(new)-{'main'}):
    assert source('inert_r3.py',old[name])==source('inert_r4.py',new[name]),name
    unchanged.append(name)
def assignment(name,key):
    found=[n.value for n in trees[name].body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id==key for t in n.targets)]
    assert len(found)==1,key
    return ast.dump(found[0],include_attributes=False)
for key in ['NEW_OUTER_SECONDS','NEW_OUTER_FAILURE_CLEANUP_SECONDS',
            'NEW_LISTENER_READY_SECONDS','HTTP_SECONDS','CAPTURE_SECONDS',
            'MAX_HTTP_BODY','MAX_PUBLIC_REPORT','ROOT','QA','COMMIT','TREE',
            'BINARY','BINARY_SHA','BINARY_BYTES','ENTRY_NAMES','SYNTHETIC',
            'AGENTS','FIXED_UTILITIES']:
    assert assignment('outer_r3.py',key)==assignment('outer_r4.py',key),key
print(json.dumps({
 'schema':'heptabao.mac-input-successor-r4.source-ast-review.r1',
 'status':'passed','full_python_ast_compiled':list(raws),
 'candidate_modules_executed':False,'candidate_host_calls':0,
 'candidate_sqlite_calls':0,'candidate_children':0,
 'inert_shared_top_level_functions_byte_identical':unchanged,
 'outer_original_source_artifacts_anchor_profile_caps_and_deadlines_unchanged':True
},indent=2,sort_keys=True))
