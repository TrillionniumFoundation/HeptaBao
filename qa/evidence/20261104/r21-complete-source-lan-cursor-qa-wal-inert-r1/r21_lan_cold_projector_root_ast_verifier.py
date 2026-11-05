import ast,json,sys
base,cand=map(ast.parse,sys.argv[1:3])
def defs(t): return {x.name:ast.get_source_segment(sys.argv[1] if t is base else sys.argv[2],x) for x in t.body if isinstance(x,(ast.FunctionDef,ast.ClassDef)) and x.name!='main'}
assert defs(base)==defs(cand)
def val(n):
 if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='frozenset': return frozenset(ast.literal_eval(n.args[0]))
 if isinstance(n,ast.BinOp):
  if isinstance(n.op,ast.Mult): return val(n.left)*val(n.right)
  if isinstance(n.op,ast.Sub): return val(n.left)-val(n.right)
  if isinstance(n.op,ast.LShift): return val(n.left)<<val(n.right)
 return ast.literal_eval(n)
def assigns(t):
 r={}
 for n in t.body:
  if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
   try:r[n.targets[0].id]=val(n.value)
   except(ValueError,TypeError):pass
 return r
b,c=assigns(base),assigns(cand)
added=c['TIMING_PAIRS']-b['TIMING_PAIRS']
assert len(defs(base))==12 and len(b['TIMING_PAIRS'])==50 and len(c['TIMING_PAIRS'])==70 and len(added)==20
assert not b['TIMING_PAIRS']-c['TIMING_PAIRS'] and all(a=='cold_native_ha' for a,b in added)
for k,v in {'MAX_INPUT':2097152,'MAX_MARKERS':128,'MAX_OUTPUT':65536,'TOTAL_SECONDS':15.0,'MAX_TIMING_LINE':65536}.items():assert b[k]==c[k]==v
for k in ('PHASES','CODES','TIMING_KEYS','BUCKET_KEYS','COUNT_KEYS','TIME_KEYS','U128_MAX','U64_MAX','EXPECTED_INPUT_FIELDS'):assert b[k]==c[k]
assert len(c['EXPECTED_INPUT_IDENTITY'])==10 and all(type(x) is str for x in c['EXPECTED_INPUT_IDENTITY'])
print(json.dumps({'nonmain_definitions_byte_equal':len(defs(base)),'old_pairs':50,'new_pairs':20,'total_allowed_pairs':70,'fixed_caps_equal':True,'closed_parser_constants_equal':True,'module_executed':False}))
