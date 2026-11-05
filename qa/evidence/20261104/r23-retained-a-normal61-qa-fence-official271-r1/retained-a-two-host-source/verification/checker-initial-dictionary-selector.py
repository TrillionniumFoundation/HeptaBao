import ast,difflib,hashlib,json,pathlib
data=json.loads(pathlib.Path('/tmp/heptabao_retained_a_successor_r1/input.json').read_text())
checks=[]
def check(name,value):
 if not value: raise AssertionError(name)
 checks.append(name)
def pin(s):
 b=s.encode()
 return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def literal(tree,name):
 n=next(x for x in tree.body if isinstance(x,ast.Assign) and len(x.targets)==1 and isinstance(x.targets[0],ast.Name) and x.targets[0].id==name)
 return ast.literal_eval(n.value)
def definitions(s,t):
 return {x.name:ast.get_source_segment(s,x) for x in t.body if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
diffs={}; counts={}
for k,after in data['after'].items():
 before=data['before'][k];bt=ast.parse(before);at=ast.parse(after)
 compile(at,k,'exec')
 check(k+'.whole_pin',pin(after)==data['pins'][k])
 check(k+'.all_definitions_exact',definitions(before,bt)==definitions(after,at))
 counts[k]=len(definitions(after,at))
 diffs[k]=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/'+k+'.py',tofile='b/'+k+'.py'))
 if k.endswith('runner'):
  check(k+'.original_build_test_and_final_tail_exact',before[before.index('def write('):]==after[after.index('def write('):])
  for field in ['INGRESS_OBSERVER_TESTS','COLD_H2_TESTS','SAME_ROOT_PUBLICATION_TESTS','ORIGINAL_OUTER_SECONDS','PRIOR_DF026_FILES']:
   check(k+'.'+field, literal(bt,field)==literal(at,field))
  check(k+'.commit',literal(at,'DIAGNOSTIC_COMMIT')==data['canonical']['commit'])
  check(k+'.tree',literal(at,'DIAGNOSTIC_TREE')==data['canonical']['tree'])
 if k.endswith('stager'):
  check(k+'.stage_seconds',literal(at,'STAGE_SECONDS')==300.0)
  check(k+'.commit',literal(at,'COMMIT')==data['canonical']['commit'])
  check(k+'.tree',literal(at,'TREE')==data['canonical']['tree'])
  check(k+'.parent',literal(at,'PARENT')=='1c66541993662f92cf717154e33717abedb2ea74')
  check(k+'.ancestry',literal(at,'ANCESTRY')[1:]==literal(bt,'ANCESTRY') and literal(at,'ANCESTRY')[0]==(data['canonical']['commit'],data['canonical']['parent']))
  check(k+'.old_source_pins',literal(at,'OLD_COMMIT')==literal(bt,'OLD_COMMIT') and literal(at,'OLD_TREE')==literal(bt,'OLD_TREE'))
 if k.endswith('launcher'):
  check(k+'.outer_seconds',literal(at,'ORIGINAL_OUTER_SECONDS')==literal(bt,'ORIGINAL_OUTER_SECONDS'))
for host in ('rog','mac'):
 q=data['stage_requests'][host] if host=='rog' else data['stage_requests'][host]['candidate_request']
 base=data['prior_stage_requests'][host]
 check(host+'.source_request_fixed_fields',all(q[k]==v for k,v in base.items() if k not in ('args','stdin','idempotency_key')))
 check(host+'.source_args_fixed_prefix',q['args'][:4]==base['args'][:4])
 check(host+'.source_exact',q['args'][4]==data['after'][host+'_stager'])
 check(host+'.source_self_sha',q['args'][5:7]==['--self-sha256',pin(q['args'][4])['sha256']])
 check(host+'.source_payload_sha',q['args'][7:9]==['--carrier-sha256',pin(q['stdin'])['sha256']])
 check(host+'.stdin_cap',len(q['stdin'].encode())<=262144)
 payload=json.loads(q['stdin'])
 expected=literal(ast.parse(data['after'][host+'_stager']),'EXPECTED_CONTROLS')
 check(host+'.fixed_controls',set(payload['controls'])==set(expected))
 for name,text in payload['controls'].items():
  check(host+'.payload.'+name,(len(text.encode()),hashlib.sha256(text.encode()).hexdigest())==tuple(expected[name]))
 for name in ('normal-test-groups.public.json',):
  check(host+'.original_groups_exact',payload['controls'][name]==json.loads(base['stdin'])['controls'][name])
 b=data['future_builds'][host]
 check(host+'.future_build_unbound',b['ready'] is False and b['actual_stage_sha256'] is None)
 br=b['candidate_request'];args=br['args']
 check(host+'.future_identity',args[args.index('--commit')+1]==data['canonical']['commit'] and args[args.index('--tree')+1]==data['canonical']['tree'])
 check(host+'.future_runner',args[args.index('--runner-sha256')+1]==data['pins'][host+'_runner']['sha256'])
 check(host+'.future_stage_pending',args[args.index('--stage-sha256')+1]=='__ACTUAL_STAGE_SHA256__')
 check(host+'.future_self_basename',args[3].endswith('/control/launch_normal_same_root_publication.py'))
 check(host+'.future_outer',br['timeout_seconds']==(12000 if host=='rog' else 8280))
 if host=='mac':
  check('mac.bundle_unbound',payload['canonical_bundle_base64'] is None and literal(ast.parse(data['after']['mac_stager']),'CANONICAL_BUNDLE_BYTES') is None and literal(ast.parse(data['after']['mac_stager']),'CANONICAL_BUNDLE_SHA256') is None)
at=ast.parse(data['after']['mac_runner'])
updates=[n for n in at.body if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and isinstance(n.value.func.value,ast.Name) and n.value.func.value.id=='PRIOR_DF026_FILES' and n.value.func.attr=='update']
expected={f['path']:[f['size'],f['sha256'],384] for f in data['failure_fences']}
check('mac.only_four_extra_failure_fences',len(updates)==1 and ast.literal_eval(updates[0].value.args[0])==expected)
check('rog.no_extra_failure_fences','PRIOR_DF026_FILES.update(' not in data['after']['rog_runner'])
out={'schema':'heptabao.retained-a.successor.static-binding-checks.v1','status':'passed','checks':checks,'check_count':len(checks),'definition_counts_unchanged':counts,'diff_hunks':{k:sum(x.startswith('@@ ') for x in v.splitlines()) for k,v in diffs.items()},'diffs':diffs,'host_calls':0,'candidate_module_executions':0,'rust_or_cargo_executions':0,'local_activity':'Read this public JSON, parse/compile AST without import or module execution; generate exact unified diffs.'}
print(json.dumps(out,indent=2))
