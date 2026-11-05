import ast, copy, hashlib, json, stat
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).parent
before=(ROOT/'before.py').read_text()
after=(ROOT/'after.py').read_text()
assert hashlib.sha256(before.encode()).hexdigest()=='be5da65ce3bd98586d36b11edba6a4619600b74fbabb93050a3325e89e9ed254'
assert hashlib.sha256(after.encode()).hexdigest()=='c160d3593bd6ddce8e9eaea2acd96991af29b43c55713056ff996e9ffa2d2603'
old=ast.parse(before);new=ast.parse(after)
compile(old,'before.py','exec');compile(new,'after.py','exec')
def fn(tree,name):
    values=[n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name==name]
    assert len(values)==1,name
    return values[0]
def src(raw,node):
    return ''.join(raw.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
def condition(function,code):
    values=[n.args[0] for n in ast.walk(function) if isinstance(n,ast.Call)
      and isinstance(n.func,ast.Name) and n.func.id=='need'
      and len(n.args)==2 and isinstance(n.args[1],ast.Constant) and n.args[1].value==code]
    assert len(values)==1,code
    return compile(ast.Expression(values[0]),'<actual-condition>','eval')
names={'InputRefused','need','identity','inode','parent_custody_identity','same_recorded_input'}
selected=[n for n in new.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
selected=[n for n in new.body if isinstance(n,ast.Assign) and any(
    isinstance(x,ast.Name) and x.id=='PUBLIC_CODE_PARENT_IDENTITIES' for x in n.targets)]+selected
env={'stat':stat}
exec(compile(ast.Module(body=selected,type_ignores=[]),'<selected-pure-definitions>','exec'),env)
keys=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
sample=lambda fields:SimpleNamespace(**dict(zip(keys,map(int,fields))))
records=[]
def case(name,call):
    call()
    records.append({'case':name,'passed':True})
def rejects(call):
    try:call()
    except env['InputRefused']:return
    raise AssertionError('expected exact refusal')
bindings=env['PUBLIC_CODE_PARENT_IDENTITIES']
admit=env['parent_custody_identity']
old_condition=condition(fn(old,'parents'),'readonly_input_parent_custody_or_exact_held_anchor')
def old_refusal():
    for path,fields in bindings.items():
        assert not eval(old_condition,{**env,'named':sample(fields),'anchor':None})
case('actual_original_guard_rejects_both_observed_0775',old_refusal)
def exact_public():
    for path,fields in bindings.items():assert admit(path,sample(fields),None,True)==fields
case('only_two_exact_public_parent_identities_return_all_nine_fields',exact_public)
def original_nonpublic():
    for path,fields in bindings.items():rejects(lambda:admit(path,sample(fields),None,False))
case('private_read_public_and_general_context_keep_original_refusal',original_nonpublic)
def unrelated():
    fields=list(next(iter(bindings.values())))
    for mode in (stat.S_IFDIR|0o775,stat.S_IFDIR|0o777):
        fields[4]=str(mode)
        rejects(lambda:admit('/opt/homebrew/other',sample(fields),None,True))
case('other_775_and_777_parent_never_borrow_homebrew_binding',unrelated)
def changed():
    for path,fields in bindings.items():
        for i in range(9):
            altered=list(fields);altered[i]=str(int(altered[i])+1)
            rejects(lambda:admit(path,sample(altered),None,True))
case('all_nine_substituted_parent_fields_rejected_for_each_binding',changed)
def ordinary():
    values=list(next(iter(bindings.values())));values[4]=str(stat.S_IFDIR|0o755)
    node=sample(values)
    assert admit('/opt/ordinary',node,None,False)==env['inode'](node)
    assert admit('/opt/ordinary',node,None,True)==env['inode'](node)
case('ordinary_strict_parent_retains_original_six_field_custody',ordinary)
before_fd=condition(fn(new,'parents'),'readonly_input_parent_fd')
after_fd=condition(fn(new,'parents'),'readonly_input_parent_changed')
def descriptors():
    for fields in bindings.values():
        row={'fd':27,'identity':fields}
        same=sample(fields)
        ns={**env,'row':row,'fd':27,'named':same,'os':SimpleNamespace(fstat=lambda _fd:same)}
        assert eval(before_fd,ns) and eval(after_fd,ns)
        for i in range(9):
            modified=list(fields);modified[i]=str(int(modified[i])+1);changed_node=sample(modified)
            assert not eval(before_fd,{**ns,'os':SimpleNamespace(fstat=lambda _fd:changed_node)})
            assert not eval(after_fd,{**ns,'named':changed_node})
case('actual_before_and_after_fd_named_expressions_check_all_nine',descriptors)
context=condition(fn(new,'_file'),'only_original_closed_public_pin_code_parent_context')
def contexts():
    original='/opt/homebrew/bin/node';destination='/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
    pin='a'*64
    holder=SimpleNamespace(base_public_codes={original:pin},code_allowed={original:pin})
    values={'private':False,'public_code':original,'pin':pin,'path':destination,'self':holder,
      'Path':lambda _p:SimpleNamespace(resolve=lambda strict:destination)}
    assert eval(context,values)
    assert not eval(context,{**values,'private':True})
    assert not eval(context,{**values,'public_code':'/opt/homebrew/unknown'})
    assert not eval(context,{**values,'pin':'b'*64})
    assert not eval(context,{**values,'path':destination+'.changed'})
    dynamic='/opt/homebrew/new-harness'
    holder.code_allowed[dynamic]=pin
    assert not eval(context,{**values,'public_code':dynamic})
    holder.base_public_codes=None
    assert not eval(context,values)
case('actual_context_requires_original_closed_pin_and_resolved_path_not_private_or_later_added',contexts)
def defaults():
    f=fn(new,'_file')
    assert isinstance(f.args.kw_defaults[f.args.kwonlyargs.index(next(a for a in f.args.kwonlyargs if a.arg=='public_code'))],ast.Constant)
    assert f.args.kw_defaults[f.args.kwonlyargs.index(next(a for a in f.args.kwonlyargs if a.arg=='public_code'))].value is None
    p=fn(new,'parents')
    assert p.args.kw_defaults[0].value is False
    for name in ('read_private','read_public'):
        assert src(before,fn(old,name))==src(after,fn(new,name))
        assert not any(k.arg=='public_code' for n in ast.walk(fn(new,name)) if isinstance(n,ast.Call) for k in n.keywords)
case('default_denies_exception_and_private_public_receipt_functions_are_byte_identical',defaults)
freeze=condition(fn(new,'normal_and_base_sources'),'exact_original_closed_forty_public_code_set')
def frozen_once():
    for n in (39,40,41):
        holder=SimpleNamespace(base_public_codes=None,code_allowed={str(i):str(i) for i in range(n)})
        assert bool(eval(freeze,{'self':holder}))==(n==40)
    assert not eval(freeze,{'self':SimpleNamespace(base_public_codes={},code_allowed={str(i):str(i) for i in range(40)})})
case('closed_set_frozen_once_at_exact_original_forty',frozen_once)
verify=copy.deepcopy(fn(new,'verify'));verify.decorator_list=[]
fake_env={'Path':Path,'need':env['need'],'identity':env['identity']}
exec(compile(ast.Module(body=[verify],type_ignores=[]),'<actual-verify>','exec'),fake_env)
def verify_context():
    calls=[]
    holder=SimpleNamespace(records={
      '/opt/homebrew/Cellar/node/25.9.0_1/bin/node':{'sha256':'a'*64,'cap':268435456,'private':False},
      '/fixed/public/receipt.json':{'sha256':'b'*64,'cap':65536,'private':False},
      '/fixed/private/input.json':{'sha256':'c'*64,'cap':1048576,'private':True}},
      base_code_reads={'/opt/homebrew/Cellar/node/25.9.0_1/bin/node':'/opt/homebrew/bin/node'},aliases={},
      remaining=lambda:None,pin_code=lambda p:calls.append(('pin_code',p)),
      _file=lambda *a,**k:calls.append(('file',a,k)))
    assert fake_env['verify'](holder)
    assert calls[0]==('pin_code','/opt/homebrew/bin/node')
    assert calls[1][0]=='file' and calls[1][2]=={'private':False,'collect':False,'record':False}
    assert calls[2][0]=='file' and calls[2][2]=={'private':True,'collect':False,'record':False}
    assert calls[1][1][2]==65536 and calls[2][1][2]==1048576
case('actual_final_verify_reenters_pin_code_and_preserves_other_read_limits_and_privacy',verify_context)
def invariance():
    for name in ('remaining','_close','read_private','read_public','_admit_code','admit_utilities',
                 'project_frozen','admit_actual_harnesses','public_pins','close','public'):
        assert src(before,fn(old,name))==src(after,fn(new,name)),name
    assert condition(fn(old,'_file'),'finite_input_file_custody').co_code==condition(fn(new,'_file'),'finite_input_file_custody').co_code
case('eleven_unchanged_methods_and_original_per_file_cap_predicate_retained',invariance)
old_record_condition=condition(fn(old,'_file'),'same_original_input_identity')
prior={'path':'/Users/qianqi/.openclaw/extensions/openclaw-authbus/index.js',
 'bytes':54455,'sha256':'b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b',
 'identity':['16777233','527753287','501','20','33188','1','54455','1786452790844162483','1786452790844261399'],
 'private':False,'cap':268435456}
collected={**prior,'cap':8388608}
same_record=env['same_recorded_input']
def old_cap_failure():
    assert not eval(old_record_condition,{'value':collected,'path':prior['path'],
       'self':SimpleNamespace(records={prior['path']:prior})})
case('actual_original_record_comparison_refuses_same_plugin_at_smaller_collect_cap',old_cap_failure)
def new_cap_only():
    assert same_record(collected,prior,prior['path'])
    assert same_record(prior,prior,prior['path'])
    assert not same_record(collected,prior,None)
    private_prior={**prior,'private':True};private_collect={**private_prior,'cap':8388608}
    assert not same_record(private_collect,private_prior,None)
case('new_public_code_comparison_separates_call_cap_private_and_read_public_stay_exact',new_cap_only)
def changed_record():
    for key,new_value in [('path',prior['path']+'.changed'),('bytes',54456),('sha256','b'*64),('private',True)]:
        changed={**collected,key:new_value}
        assert not same_record(changed,prior,prior['path'])
    for i in range(9):
        values=list(prior['identity']);values[i]=str(int(values[i])+1)
        assert not same_record({**collected,'identity':values},prior,prior['path'])
case('every_real_file_identity_field_and_all_nine_metadata_fields_remain_exact',changed_record)
def caps_unchanged():
    assignments=lambda tree:[n for n in ast.walk(fn(tree,'pin_code')) if isinstance(n,ast.Assign)
      and any(isinstance(t,ast.Name) and t.id=='cap' for t in n.targets)]
    assert len(assignments(old))==len(assignments(new))==1
    assert ast.dump(assignments(old)[0],include_attributes=False)==ast.dump(assignments(new)[0],include_attributes=False)
    cap_expression=compile(ast.Expression(assignments(new)[0].value),'<actual-cap>','eval')
    assert eval(cap_expression,{'collect':True,'MAX_CODE':268435456})==8388608
    assert eval(cap_expression,{'collect':False,'MAX_CODE':268435456})==268435456
    gate=condition(fn(new,'_file'),'finite_input_file_custody')
    normal=SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_size=9*1024*1024,st_uid=501,st_nlink=1)
    assert not eval(gate,{'stat':stat,'before':normal,'cap':8388608,'private':False})
    assert eval(gate,{'stat':stat,'before':normal,'cap':268435456,'private':False})
    aggregate=condition(fn(new,'_file'),'one_outer_aggregate_input_hash_bound')
    assert eval(aggregate,{'self':SimpleNamespace(total_hashed=1073741824),'MAX_ALL_HASHED':1073741824})
    assert not eval(aggregate,{'self':SimpleNamespace(total_hashed=1073741825),'MAX_ALL_HASHED':1073741824})
case('actual_8m_collect_256m_hash_and_1g_aggregate_caps_are_unchanged_and_enforced',caps_unchanged)

result={'schema':'heptabao.mac-public-parent-guard-pure-components.r1','status':'passed',
 'checks':records,'passed':len(records),'failed':0,
 'scope':'AST-selected actual parent/context/FD/final-verify logic and static invariance only',
 'whole_module_executed':False,'actual_fd_operations':0,'actual_sockets':0,'children':0,
 'network':0,'sqlite':0,'physical_host_calls':0,
 'read_cap_identity_source_boundary_checked':True,'full_runtime_qualified':False}
print(json.dumps(result,indent=2,sort_keys=True))
