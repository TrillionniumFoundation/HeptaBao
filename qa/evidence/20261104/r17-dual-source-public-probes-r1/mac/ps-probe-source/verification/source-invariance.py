import ast, hashlib, json, pathlib
from pathlib import Path
base=pathlib.Path(__file__).parent
old=(base/'previous_probe.py').read_text()
new=(base/'probe.py').read_text()
a,b=ast.parse(old),ast.parse(new)
def fns(text,tree):
    return {n.name:ast.get_source_segment(text,n) for n in tree.body if isinstance(n,ast.FunctionDef)}
oa,nb=fns(old,a),fns(new,b)
unchanged=['need','sha','encoded','ident','critical','interrupted','remaining','close_fd',
           'source_snapshot','utility_snapshot','safe_error','absence_twice',
           'capture_profile','profiles','kernel_refusals','null_read_case']
assert all(oa[n]==nb[n] for n in unchanged)
g={'Path':Path,'json':json,'hashlib':hashlib}
constants={'SOURCE_ROOT','ROOT','PROBE_STAGE','PROBE_ROOT','QA','BASE','LIVE','AGENTS','CACHE_NAMES',
           'READ_NULL_RULE','PROBE_CONTENT'}
nodes=[n for n in b.body if isinstance(n,ast.Assign) and all(isinstance(t,ast.Name) and t.id in constants for t in n.targets)]
nodes += [n for n in b.body if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name in {'Refused','need','sha','capture_profile','profiles'}]
exec(compile(ast.Module(nodes,type_ignores=[]),'<selected-pure-profile>', 'exec'),g)
profiles=g['profiles']()
assert len(profiles['patched'])-len(profiles['original'])==41
assert profiles['patched'].replace(g['READ_NULL_RULE'],b'',1)==profiles['original']
assert b'no-sandbox' not in profiles['patched']
assert b'ps-sandbox-probe-r1' in profiles['patched']
assert b'devnull-sandbox-probe-r1' not in profiles['patched']
assert b'captures/before' not in profiles['patched']
for name,raw in profiles.items():(base/(name+'.sb')).write_bytes(raw)
rows=[{'name':n,'bytes':len(nb[n].encode()),'sha256':hashlib.sha256(nb[n].encode()).hexdigest()} for n in unchanged]
print(json.dumps({'schema':'heptabao.ps-probe-source-invariance.r1',
  'candidate_source_sha256':hashlib.sha256(new.encode()).hexdigest(),
  'source_functions_byte_equal':rows,'pure_profile_only_executed':True,
  'profile_pins':{n:{'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for n,v in profiles.items()},
  'patched_delta_bytes':41,'full_candidate_main_executed':False,'host_actions':0},sort_keys=True))

