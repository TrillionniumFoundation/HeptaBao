#!/usr/bin/env python3
"""Offline source comparison only; never imports candidate modules."""
import ast, difflib, hashlib, json
from pathlib import Path
BASE=Path(__file__).parent
checks=[]; products={}
def need(ok,label):
    checks.append({'case':label,'passed':bool(ok)})
    if not ok: raise AssertionError(label)
def funcs(raw):
    tree=ast.parse(raw); result={}
    def visit(nodes,prefix=''):
        for n in nodes:
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
                result[prefix+n.name]=ast.get_source_segment(raw,n)
            elif isinstance(n,ast.ClassDef):visit(n.body,prefix+n.name+'.')
    visit(tree.body);return result
def assigned(raw):
    result={}
    for n in ast.parse(raw).body:
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
            result[n.targets[0].id]=ast.dump(n.value,include_attributes=False)
    return result
for name,changed in [('inputs',{'Inputs.__init__','Inputs._file','Inputs.pin_code','Inputs.admit_actual_harnesses'}),
                     ('materializer',{'consumer_profile','Materializer.materialize'})]:
    before=(BASE/(name+'.before.py')).read_text()
    after=(BASE/(name+'.after.draft1.py')).read_text()
    compile(ast.parse(after),name,'exec')
    old,new=funcs(before),funcs(after)
    for k,v in old.items():
        if k not in changed:need(new.get(k)==v,name+'.unchanged.'+k)
    for k,v in assigned(before).items():need(assigned(after).get(k)==v,name+'.old_constant.'+k)
    need(set(old)-set(new)==set(),name+'.no_removed_definitions')
    diff=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),
        fromfile=name+'.before.py',tofile=name+'.after.draft1.py',n=3))
    (BASE/(name+'.review.diff')).write_text(diff)
    products[name]={'beforeBytes':len(before.encode()),'beforeSha256':hashlib.sha256(before.encode()).hexdigest(),
       'afterBytes':len(after.encode()),'afterSha256':hashlib.sha256(after.encode()).hexdigest(),
       'diffBytes':len(diff.encode()),'diffSha256':hashlib.sha256(diff.encode()).hexdigest(),
       'hunks':sum(line.startswith('@@ ') for line in diff.splitlines())}
before=(BASE/'worker.before.mjs').read_text();after=(BASE/'worker.after.draft1.mjs').read_text()
start=after.index('\nfunction actualHarnessOwnerWitness(');end=after.index('\nfunction privateRead(file)',start)
stripped=after[:start]+after[end:]
start=stripped.index('  // This export only returns the active registry for an argument-free call.')
end=stripped.index('  const nativeApi =',start)
stripped=stripped[:start]+stripped[end:]
start=stripped.index('  const ownerAfter = actualHarnessOwnerWitness(')
end=stripped.index("  check('source_pins_unchanged'",start)
stripped=stripped[:start]+stripped[end:]
need(stripped==before,'worker.remove_three_insertions_whole_equals_original')
selection="""  await loader.t({ scope:'all', config:cfg, activationSourceConfig:cfg,
    workspaceDir:plan.workspace, onlyPluginIds:plan.harnessOwnerPluginIds });
  const selectedHarness = selector.o({ provider:plan.model.provider, modelId:plan.model.id,
    config:cfg, agentId:plan.agentId });
  check('actual_loader_and_selector_choose_codex', selectedHarness?.id === 'codex');
  check('selected_harness_is_actual_registered_instance', registry.r('codex')?.harness === selectedHarness);
"""
need(selection in before and selection in after,'worker.original_loader_selector_and_two_guards_exact')
need(after.count('await loader.t(')==before.count('await loader.t(')==1,'worker.no_extra_loader_call')
need(after.count('selector.o(')==before.count('selector.o(')==1,'worker.no_extra_selection_call')
diff=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),
    fromfile='worker.before.mjs',tofile='worker.after.draft1.mjs',n=3))
(BASE/'worker.review.diff').write_text(diff)
products['worker']={'beforeBytes':len(before.encode()),'beforeSha256':hashlib.sha256(before.encode()).hexdigest(),
 'afterBytes':len(after.encode()),'afterSha256':hashlib.sha256(after.encode()).hexdigest(),
 'diffBytes':len(diff.encode()),'diffSha256':hashlib.sha256(diff.encode()).hexdigest(),
 'hunks':sum(line.startswith('@@ ') for line in diff.splitlines())}
result={'schema':'heptabao.owner-repair.source-comparison.v1','passed':len(checks),'checks':checks,'products':products,
 'candidateModulesExecuted':False,'runtimeCalls':0,'oldCapsAndConstantsPreserved':True,
 'OWNER_PUBLIC_BINDING_READY':False,'newSourceEntryPinsBound':False}
print(json.dumps(result,indent=2))
