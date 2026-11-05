import ast,hashlib,json,sys,difflib
p=json.loads(sys.stdin.read())
checks=[]
def check(name,value):
 if not value: raise AssertionError(name)
 checks.append({'case':name,'passed':True})
old,new=p['before'],p['after']
trees=[ast.parse(x) for x in (old,new)]
for tree in trees: compile(tree,'<public-formatter-source>','exec')
check('two_whole_python_sources_ast_compile_only',True)
original=old
for before,after in p['replacements']:
 check('unique_literal_'+str(len(checks)),original.count(before)==1)
 original=original.replace(before,after)
check('five_unique_replacements_reconstruct_candidate',original==new)
for before,after in reversed(p['replacements']):
 check('reverse_unique_'+str(len(checks)),original.count(after)==1)
 original=original.replace(after,before)
check('reverse_reconstructs_complete_original',original==old)
old_functions={n.name:ast.get_source_segment(old,n) for n in trees[0].body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
new_functions={n.name:ast.get_source_segment(new,n) for n in trees[1].body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
check('all_five_helpers_whole_source_unchanged',len(old_functions)==5 and old_functions==new_functions)
request=p['request']
check('exact_request_schema',set(request)=={'host','executable','args','cwd','stdin','timeout_seconds','idempotency_key'})
check('request_binds_exact_candidate_without_execution',request['args']==['-I','-S','-B','-c',new] and request['host']=='rog' and request['executable']=='/usr/bin/python3' and request['cwd']=='/home/qian-qi' and request['timeout_seconds']==60)
data=json.loads(request['stdin'])
check('exact_four_public_input_names',set(data)==set(p['input_pins'])==set(p['expected']) and len(data)==4)
for name,text in data.items():
 raw=text.encode()
 check('input_exact_'+name,len(raw)==p['input_pins'][name]['bytes'] and hashlib.sha256(raw).hexdigest()==p['input_pins'][name]['sha256']==p['expected'][name][1])
check('stdin_under_original_256kib_bound',len(request['stdin'].encode())<=262144)
check('same_rustfmt_argv_and_50_10_60_caps',"START=time.monotonic(); LIMIT=50.0" in new and "argv=[str(FMT),'--edition','2024','--emit','stdout']" in new and "'timeoutSeconds':10" in new and "timeout=min(10.0,remain())" in new and "'newRemoteSupervisorSeconds':60" in new)
report={'schema':'heptabao.cold-h2-format-carrier-source-checks.r1','status':'passed','checks':checks,'passed':len(checks),'candidate_imported_or_executed':False,'actual_formatter_children':0,'rust_compiled_or_executed':False,'host_calls':0,'source_only':True}
diff=''.join(difflib.unified_diff(old.splitlines(keepends=True),new.splitlines(keepends=True),fromfile='before/format.py',tofile='candidate/format.py'))
print(json.dumps({'report':report,'diff':diff},sort_keys=True))
