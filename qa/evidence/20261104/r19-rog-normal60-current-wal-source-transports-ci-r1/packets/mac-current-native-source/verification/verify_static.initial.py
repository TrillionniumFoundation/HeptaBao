#!/usr/bin/env python3
"""Static source/closure verification only; no candidate module executes."""
import ast, hashlib, json
from pathlib import Path
HERE=Path(__file__).parent
bundle=json.loads((HERE/'sources.public.json').read_text())
before=bundle['before'];after=bundle['after']
rename={'mac_current_capture_entry_r1.py':'mac_current_capture_entry_native_r1.py',
        'mac_current_outer_r4.py':'mac_current_outer_native_r1.py'}
need=lambda condition,code: None if condition else (_ for _ in ()).throw(AssertionError(code))
def pins(source):
    raw=source.encode()
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def syntax(source,name):
    tree=ast.parse(source,filename=name)
    compile(tree,name,'exec')
    return tree
def definition_bytes(source,tree):
    lines=source.splitlines(keepends=True);out={}
    def walk(body,prefix=''):
        for node in body:
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                first=min([node.lineno]+[x.lineno for x in node.decorator_list])
                out[prefix+node.name]=''.join(lines[first-1:node.end_lineno])
                if isinstance(node,ast.ClassDef):walk(node.body,prefix+node.name+'.')
    walk(tree.body)
    return out
def value(tree,name):
    found=[node.value for node in tree.body if isinstance(node,ast.Assign)
           and any(isinstance(target,ast.Name) and target.id==name for target in node.targets)]
    need(len(found)==1,'one_assignment:'+name)
    return ast.literal_eval(found[0])
need(len(before)==18 and len(after)==21,'18_plus_3_inventory')
trees={name:syntax(source,name) for name,source in after.items() if name.endswith('.py')}
oldtrees={name:syntax(source,name) for name,source in before.items() if name.endswith('.py')}
changed_expected={'mac_current_capture_entry_r1.py':{'capture_profile','main'},
                  'mac_current_outer_r4.py':{'capture_once','main'}}
new_expected={'mac_current_capture_entry_r1.py':{'admitted_native'}}
records=[];unchanged=[];all_same_definitions=0
for oldname,source in before.items():
    newname=rename.get(oldname,oldname);new=after[newname]
    row={'before_name':oldname,'after_name':newname,'before':pins(source),'after':pins(new)}
    if source==new:unchanged.append(oldname)
    if oldname.endswith('.py'):
        olddefs=definition_bytes(source,oldtrees[oldname]);newdefs=definition_bytes(new,trees[newname])
        changed={name for name in olddefs if name in newdefs and olddefs[name]!=newdefs[name]}
        added=set(newdefs)-set(olddefs);removed=set(olddefs)-set(newdefs)
        need(not removed,'no_removed_definition:'+oldname)
        need(changed==changed_expected.get(oldname,set()),'only_named_definitions_changed:'+oldname+':'+str(changed))
        need(added==new_expected.get(oldname,set()),'only_named_new_definitions:'+oldname)
        same=set(olddefs)&set(newdefs)-changed
        all_same_definitions+=len(same)
        row.update(unchanged_definitions=sorted(same),changed_definitions=sorted(changed),
                   added_definitions=sorted(added))
    else:
        need(new.replace(bundle['newRoot'],bundle['oldRoot'])==source,'javascript_only_root_literal:'+oldname)
        row['only_root_literal_or_whole_unchanged']=True
    records.append(row)
need(len(unchanged)==7,'seven_exact_unchanged_original_sources')
for name,source in bundle['nativeExact'].items():
    need(after[name]==source,'exact_publicly_qualified_native_module:'+name)
outer=trees['mac_current_outer_native_r1.py'];entry=trees['mac_current_capture_entry_native_r1.py']
need(set(value(outer,'NAMES'))==set(after),'exact_outer_21')
need(value(outer,'ENTRY_NAMES')==value(entry,'NAMES'),'exact_entry_caller_names')
need(set(value(entry,'NAMES'))<=set(after) and len(value(entry,'NAMES'))==6,'six_capture_import_pins')
need(value(outer,'NATIVE_BINDING')==value(entry,'NATIVE_BINDING'),'same_actual_native_binding')
need(value(outer,'NATIVE_BINDING')['modulePins']=={name:pins(source)['sha256']
      for name,source in bundle['nativeExact'].items()},'native_binding_exact_new_sources')
need(value(outer,'SYNTHETIC')==value(oldtrees['mac_current_outer_r4.py'],'SYNTHETIC'),
     'original_sqlite_synthetic_binding_unchanged')
for name in ('NEW_OUTER_SECONDS','NEW_OUTER_FAILURE_CLEANUP_SECONDS','NEW_LISTENER_READY_SECONDS',
             'HTTP_SECONDS','CAPTURE_SECONDS','MAX_HTTP_BODY','MAX_PUBLIC_REPORT','FIXED_UTILITIES'):
    need(value(outer,name)==value(oldtrees['mac_current_outer_r4.py'],name),'same_outer_bound_or_tool:'+name)
need(value(entry,'CAPTURE_SOURCE_SHA')==pins(after['mac_guarded_current_capture_r3.py'])['sha256'],
     'same_capture_library_source_pin')
need(value(entry,'SYNTHETIC_SOURCE_SHA')==pins(after['mac_capture_sqlite_synthetic_r2.py'])['sha256'],
     'same_synthetic_controller_pin')
for name in ('mac_native_process_observer_r1.py','mac_guarded_current_capture_r3.py',
             'mac_owned_commands_r1.py','mac_owned_unreaped_r1.py',
             'mac_capture_sqlite_synthetic_r1.py','mac_capture_sqlite_synthetic_r2.py',
             'mac_authbus_cache_cas_r1.mjs'):
    need(before[name]==after[name],'unchanged_critical_source:'+name)
need(after['mac_t5_volume_guard_r1.py'].replace(
     "hepta-vnext-recovery-20261013/mac-authbus-r10-current-native-custody-r1",
     "hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1")
     ==before['mac_t5_volume_guard_r1.py'],'held_guard_only_root_rebinding')
result={'schema':'heptabao.mac-native-current-source-static-review.v1',
        'status':'PASS_STATIC_SOURCE_CLOSURE_AND_INVARIANCE','python_sources_compiled_without_execution':len(trees),
        'baseline_python_sources_compiled_without_execution':len(oldtrees),
        'source_count':len(after),'exact_original_sources':unchanged,
        'original_definitions_whole_bytes_unchanged':all_same_definitions,
        'native_three_modules_whole_exact':True,'same_original_budgets_and_utilities':True,
        'entry_import_closure':list(value(entry,'NAMES')),'per_source':records,
        'native_pins':{name:pins(source) for name,source in bundle['nativeExact'].items()},
        'candidate_modules_executed':0,'host_requests':0,'sqlite_or_private_reads':0,
        'network_calls':0,'subprocesses_started':0}
raw=json.dumps(result,indent=2,sort_keys=True)+'\n'
(HERE/'static-result.public.json').write_text(raw)
print(raw,end='')
