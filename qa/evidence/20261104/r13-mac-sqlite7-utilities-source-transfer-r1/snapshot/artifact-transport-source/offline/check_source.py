import ast,difflib,hashlib,json,sys
x=json.loads(sys.argv[1]);checks=[];part=x['part'];before=x['before'];after=x['after']
def ok(name,value):
 assert value,name
 checks.append(name)
bt=ast.parse(before);at=ast.parse(after);compile(after,part+'.py','exec')
rows=[n for n in bt.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
newrows=[n for n in at.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
ok('same_definition_names',[n.name for n in rows]==[n.name for n in newrows])
ok('all_definition_source_bytes_equal',all(ast.get_source_segment(before,a)==ast.get_source_segment(after,b) for a,b in zip(rows,newrows)))
reverse=after
for i,e in enumerate(reversed(x['edits'])):
 ok('inverse_unique_'+str(i),reverse.count(e['after'])==1)
 reverse=reverse.replace(e['after'],e['before'],1)
ok('inverse_whole_equal',reverse==before)
g={}
for n in at.body:
 if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
  try:g[n.targets[0].id]=ast.literal_eval(n.value)
  except (ValueError,TypeError):pass
if part!='inert':
 ok('actual_fixed_three_files',g['FILES']==x['files'] and len(g['FILES'])==3)
 ok('source_binding',g['HEAD']==x['commit'] and g['TREE']==x['tree'])
print(json.dumps({'schema':'heptabao.phaseb3cb.transport-single-source-check.v1','status':'passed','part':part,'checks':checks,'function_count':sum(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) for n in rows),'class_count':sum(isinstance(n,ast.ClassDef) for n in rows),'diff':''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='reference/'+part+'.py',tofile='candidate/'+part+'.py')),'candidate_executed':False,'target_host_access':False},sort_keys=True))
