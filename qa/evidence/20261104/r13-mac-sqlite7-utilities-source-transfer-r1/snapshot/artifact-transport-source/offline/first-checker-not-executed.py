import ast,base64,difflib,hashlib,json,sys
x=json.loads(sys.argv[1]); checks=[]; diffs={}; counts={}
def ok(name,value):
    assert value,name
    checks.append(name)
def globals_(text):
    t=ast.parse(text); out={}
    for n in t.body:
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
            try:out[n.targets[0].id]=ast.literal_eval(n.value)
            except (ValueError,TypeError):pass
    return t,out
for part in ('sender','receiver','relay','inert'):
    before=x['before'][part];after=x['after'][part]
    bt,bg=globals_(before);at,ag=globals_(after)
    compile(after,part+'.py','exec')
    rows=[n for n in bt.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
    newrows=[n for n in at.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
    ok(part+'_same_definition_names',[n.name for n in rows]==[n.name for n in newrows])
    ok(part+'_all_definition_source_bytes_equal',all(ast.get_source_segment(before,a)==ast.get_source_segment(after,b) for a,b in zip(rows,newrows)))
    counts[part]={'functions':sum(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) for n in rows),'classes':sum(isinstance(n,ast.ClassDef) for n in rows)}
    reverse=after
    for e in reversed(x['edits'][part]):
        ok(part+'_inverse_unique_'+str(len(checks)),reverse.count(e['after'])==1)
        reverse=reverse.replace(e['after'],e['before'],1)
    ok(part+'_inverse_whole_equal',reverse==before)
    diffs[part]=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='reference/'+part+'.py',tofile='candidate/'+part+'.py'))
    if part!='inert':
        ok(part+'_actual_fixed_three_files',ag['FILES']==x['files'] and len(ag['FILES'])==3)
        ok(part+'_source_binding',ag['HEAD']==x['commit'] and ag['TREE']==x['tree'])
payload=json.loads(x['carrier'])
ok('carrier_closed_keys',set(payload)=={'schema','files'} and set(payload['files'])=={'sender.py','receiver.py','relay.py'})
ok('carrier_schema',payload['schema']=='heptabao.phaseb3cb-shared-artifact-inputs.v1')
ig=globals_(x['after']['inert'])[1];rg=globals_(x['after']['relay'])[1]
for name,encoded in payload['files'].items():
    raw=base64.b64decode(encoded,validate=True)
    ok('carrier_exact_'+name,raw==x['after'][name[:-3]].encode())
    ok('inert_pin_exact_'+name,ig['PINS'][name]==[len(raw),hashlib.sha256(raw).hexdigest()])
    if name!='relay.py':ok('parent_helper_pin_exact_'+name,rg['HELPERS'][name]==hashlib.sha256(raw).hexdigest())
for f in x['files']:
    i=x['fileinfo'][f['name']]
    ok('actual_fileinfo_'+f['name'],f['path']==i['path'] and f['version']==i['version'] and f['bytes']==i['size'] and f['sha256']==i['sha256'] and f['source_mode']==i['mode'])
    ok('actual_custody_'+f['name'],i['metadata']['uid']==1000 and i['metadata']['link_count']==1)
n=json.loads(x['native']);b=json.loads(x['release']);f=x['files']
ok('raw_native_bytes_sha',len(x['native'].encode())==f[1]['bytes'] and hashlib.sha256(x['native'].encode()).hexdigest()==f[1]['sha256'])
ok('raw_release_bytes_sha',len(x['release'].encode())==f[2]['bytes'] and hashlib.sha256(x['release'].encode()).hexdigest()==f[2]['sha256'])
ok('raw_receipt_commit_tree',n['source_commit']==b['source_commit']==x['commit'] and n['source_tree']==b['source_tree']==x['tree'])
ok('raw_receipt_binary',n['binary_sha256']==b['artifacts']['heptabao-server']['sha256']==f[0]['sha256'] and b['artifacts']['heptabao-server']['bytes']==f[0]['bytes'])
ok('native_provenance',n['provenance']['result_sha256']==f[2]['sha256'])
ok('default_normal_features',n['features']==b['artifacts']['heptabao-server']['features']==['default','native-v6-ha','native-v6-storage'])
ok('normal_completion',n['build_exit_code']==b['build_exit_code']==0 and n['source_freeze_verified'] and b['source_freeze_verified'] and b['normal_default_candidate'] and b['build_finished_success'] and not b['timed_out'] and not b['owned_group_survivors_after_wait'])
ok('abi',n['native_abi']==b['native_abi']=='x86_64-unknown-linux-gnu')
print(json.dumps({'schema':'heptabao.phaseb3cb.transport-source-check.v1','status':'passed','checks':checks,'counts':counts,'diffs':diffs,'candidate_modules_executed':False,'network_or_children_or_target_files':False},sort_keys=True))
