import ast, copy, hashlib, json
from pathlib import Path
ROOT=Path(__file__).parent
before=(ROOT/'before.py').read_text()
after=(ROOT/'after.py').read_text()
left=ast.parse(before,filename='before.py')
right=ast.parse(after,filename='after.py')
compile(left,'before.py','exec')
compile(right,'after.py','exec')
def selected(tree, code):
    rows=[x for x in ast.walk(tree) if isinstance(x,ast.Call)
          and isinstance(x.func,ast.Name) and x.func.id=='need' and len(x.args)>1
          and isinstance(x.args[1],ast.Constant) and x.args[1].value==code]
    assert len(rows)==1
    return rows[0].args[0]
cross='same_qa_directory_inode_and_runtime_paths_still_absent'
window='exact_qa_members_no_unlisted_entries'
assert ast.dump(selected(left,window))==ast.dump(selected(right,window))
before_pred=compile(ast.Expression(selected(left,cross)),'selected-before-cross','eval')
after_pred=compile(ast.Expression(selected(right,cross)),'selected-after-cross','eval')
window_pred=compile(ast.Expression(selected(right,window)),'selected-same-window','eval')
original=json.loads((ROOT/'metadata.public.json').read_text())['qa_identity_before']
changed=original.copy()
changed[5]=str(int(original[5])+2)
changed[6]=str(int(original[6])+64)
changed[7]=str(int(original[7])+1)
changed[8]=str(int(original[8])+1)
report={'qaBefore':{'identity':original},'qaAfter':{'identity':changed},
        'runtimeAbsenceBefore':[{'path':'synthetic','twiceAbsent':True}],
        'runtimeAbsenceAfter':[{'path':'synthetic','twiceAbsent':True}]}
checks=[]
def check(name,passed):
    assert passed,name
    checks.append({'case':name,'passed':True})
check('old_cross_append_nlink_predicate_refuses',
      eval(before_pred,{'__builtins__':{}},{'report':report}) is False)
check('new_cross_append_object_identity_accepts_bounded_metadata_change',
      eval(after_pred,{'__builtins__':{}},{'report':report}) is True)
for index,name in enumerate(('device','inode','uid','gid','mode')):
    bad=copy.deepcopy(report)
    bad['qaAfter']['identity'][index]=str(int(original[index])+1)
    check('cross_append_'+name+'_change_refused',
          eval(after_pred,{'__builtins__':{}},{'report':bad}) is False)
same_window_final=original.copy()
same_window_final[5]=str(int(original[5])+1)
check('inside_single_enumeration_full_nine_fields_still_required',
      eval(window_pred,{'__builtins__':{},'len':len,'set':set},
           {'initial':original,'final':same_window_final,
            'members':['synthetic'],'expected':['synthetic']}) is False)
def functions(source,tree):
    lines=source.splitlines(keepends=True)
    out={}
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            if node.name=='main':continue
            start=min([node.lineno]+[x.lineno for x in node.decorator_list])
            out[node.name]=''.join(lines[start-1:node.end_lineno])
    return out
lf=functions(before,left);rf=functions(after,right)
assert set(lf)==set(rf) and len(lf)==8
assert all(lf[k]==rf[k] for k in lf)
source_hash=lambda s:hashlib.sha256(s.encode()).hexdigest()
print(json.dumps({
 'schema':'heptabao.mac-qa20-inert-r5-selected-pure-components.r1',
 'status':'passed','checks':checks,'passed':len(checks),
 'before_sha256':source_hash(before),'after_sha256':source_hash(after),
 'whole_source_ast_compile_only':2,
 'eight_top_level_helper_source_bytes_identical':True,
 'helper_sha256':{k:source_hash(v) for k,v in lf.items()},
 'qa_window_full_nine_predicate_ast_unchanged':True,
 'cross_append_source_expression':ast.get_source_segment(after,selected(right,cross)),
 'candidate_modules_imported_or_executed':False,
 'candidate_host_operations':0,'actual_sockets':0,'actual_child_processes':0,
 'candidate_file_operations':0,'private_data':False,
 'scope':'Only AST-selected expressions with finite synthetic dictionaries. Python harness reads these public local source fixtures; no candidate module, host, directory mutation or filesystem custody function executes.'
},sort_keys=True,indent=2))
