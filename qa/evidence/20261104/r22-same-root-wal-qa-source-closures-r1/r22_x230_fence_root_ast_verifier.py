import ast,difflib,json,sys
base_s,cand_s,raw=sys.argv[1:4]
b,c=ast.parse(base_s),ast.parse(cand_s)
def defs(t,s):return [(x.name,ast.get_source_segment(s,x)) for x in t.body if isinstance(x,(ast.FunctionDef,ast.ClassDef))]
assert defs(b,base_s)==defs(c,cand_s)
def literals(t):
 out={}
 for x in t.body:
  if isinstance(x,ast.Assign) and len(x.targets)==1 and isinstance(x.targets[0],ast.Name):
   try:out[x.targets[0].id]=ast.literal_eval(x.value)
   except(ValueError,TypeError):pass
 return out
old,new=literals(b),literals(c)
changed=[k for k in new if old.get(k)!=new[k]]
assert sorted(changed)==['EXPECTED_DIRECTORIES','METADATA_EVIDENCE_SHA256']
obs=json.loads(raw)
assert new['EXPECTED_DIRECTORIES']=={n['path']:n['identity_before'] for n in obs['nodes'] if n['directory']}
assert all(n['identity_before']==n['identity_after'] for n in obs['nodes'])
assert new['EXPECTED_CONTROLS']==old['EXPECTED_CONTROLS']
for name,row in new['EXPECTED_CONTROLS'].items():assert row['identity']==next(n['identity_before'] for n in obs['nodes'] if not n['directory'] and n['name']==name)
assert new['SOFT_SECONDS']==15 and new['READ_CAP']==131072 and new['TOMBSTONE_CAP']==8192 and new['OUTPUT_CAP']==32768 and new['BINDING_READY'] is True
print(json.dumps({'all_definitions_byte_identical':len(defs(b,base_s)),'changed_assignments':changed,'new_directories_match_actual_full9':True,'unchanged_control_sources_match_actual_full9':True,'bounds_unchanged':True,'module_executed':False}))
print(''.join(difflib.unified_diff(base_s.splitlines(True),cand_s.splitlines(True),fromfile='r1-failed-before-mutation.py',tofile='r2-fresh-metadata-bound.py')))
