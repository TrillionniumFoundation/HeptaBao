import ast, difflib, hashlib, json
from pathlib import Path
root=Path('/tmp/heptabao_qa12_transport_unbound_r1')
data=json.loads((root/'input.json').read_text())
checks=[]
def need(label, ok):
    checks.append({'label':label,'passed':bool(ok)})
    if not ok: raise AssertionError(label)
def defs(source):
    lines=source.splitlines(keepends=True)
    return {n.name:''.join(lines[n.lineno-1:n.end_lineno]) for n in ast.parse(source).body
            if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
def constant(source,name):
    for n in ast.parse(source).body:
        if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError(name)
proof={}
for name, after in data['candidate'].items():
    before=data['old'][name]
    compile(after,name,'exec')
    need(name+':ready_false',constant(after,'ACTUAL_INPUTS_READY') is False)
    top=ast.parse(after).body
    assignment=next(n for n in top if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ACTUAL_INPUTS_READY' for t in n.targets))
    guard=top[top.index(assignment)+1]
    need(name+':guard_immediately_after_ready',isinstance(guard,ast.If))
    try: exec(compile(ast.Module(body=[assignment,guard],type_ignores=[]),'<selected-guard>','exec'),{})
    except RuntimeError: refused=True
    else: refused=False
    need(name+':unbound_selected_guard_refuses',refused)
    table=constant(after,'FILES')
    need(name+':exact_12_rows',table==data['table'] and len(table)==12)
    need(name+':all_actual_slots_none',all(x['bytes'] is x['sha256'] is x['version'] is None for x in table))
    need(name+':modes_separate',all((x['source_mode'],x['target_mode'])==((320,320) if x['role']=='executable' else (384,256)) for x in table))
    need(name+':instrument_commit',constant(after,'HEAD')=='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c')
    need(name+':instrument_tree',constant(after,'TREE')=='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825')
    prior,current=defs(before),defs(after)
    unchanged=[k for k in prior if k!='receive']
    need(name+':all_prior_transport_defs_whole',all(prior[k]==current[k] for k in unchanged))
    diff=''.join(difflib.unified_diff(before.splitlines(keepends=True),after.splitlines(keepends=True),fromfile='before/'+name,tofile='candidate/'+name,n=3))
    (root/(name+'.diff')).write_text(diff)
    proof[name]={'old_bytes':len(before.encode()),'new_bytes':len(after.encode()),
                 'new_sha256':hashlib.sha256(after.encode()).hexdigest(),
                 'unchanged_prior_definitions':unchanged,'hunks':sum(x.startswith('@@ ') for x in diff.splitlines())}
receiver=data['candidate']['receiver.py']; rd=defs(receiver); bd=defs(data['binder'])
for name in ('need','sha','duplicate_free','parse','lock_subset'):
    need('binder_helper_exact:'+name,rd[name]==bd[name])
need('verify_h2_qa_exact_adaptation',rd['verify_h2_qa']==data['expected_method'].rstrip()+'\n')
need('verify_qa_no_file_reads','pin_file(' not in rd['verify_h2_qa'] and 'self.' not in rd['verify_h2_qa'])
for name in ('H2_COMPONENT_TESTS','H2_BUILD_CONTROLLER_SHA','H2_BUILD_CAPS','H2_SOURCE_PINS','CANONICAL_LOCK_SHA','PROFILE'):
    need('binder_constant_exact:'+name,constant(receiver,name)==constant(data['binder'],name))
need('roles_exact',[(r['role'],r['path'],r['name']) for r in data['table']]==[(r['role'],r['source'],r['basename']) for r in data['path_manifest']['files']])
need('roles_names_unique',len({r['role'] for r in data['table']})==12 and len({r['name'] for r in data['table']})==12)
need('same_fd_receipt_bytes',"read_file(fd,item['bytes'],item['sha256'],item['role']!='executable')" in receiver)
need('exact_one_qa_verification',rd['receive'].count('verify_h2_qa(qa_bytes)')==1)
need('old_normal_receipt_predicates_removed','normal_release_provenance_verified' not in receiver and 'native=json.loads' not in receiver)
need('new_qa_semantics_in_relay',"assert receiver_result['qa_build_provenance_verified']" in data['candidate']['relay.py'])
result={'schema':'heptabao.qa12-unbound-source-static.v1','status':'passed','checks':checks,'proof':proof,
        'selected_guard_executions':3,'full_module_executions':0,'host_actions':0,'children':0,
        'transport_execution':False,'actual_source_artifact_qualification':False,'ready':False}
(root/'result.public.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps(result,sort_keys=True))
