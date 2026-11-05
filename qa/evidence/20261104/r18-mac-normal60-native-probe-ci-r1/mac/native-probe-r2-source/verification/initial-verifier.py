#!/usr/bin/env python3
"""Only exact source/selected profile/diagnostic projection; no candidate main."""
import ast,base64,errno,hashlib,json
from pathlib import Path
BASE=Path(__file__).parent
old=(BASE/'native_proc_sandbox_probe_r1.py').read_bytes()
new=(BASE/'native_proc_sandbox_probe_r2.py').read_bytes()
ot=ast.parse(old);nt=ast.parse(new);compile(nt,'native_proc_sandbox_probe_r2.py','exec')
def defs(raw,tree):
    s=raw.decode()
    return {n.name:ast.get_source_segment(s,n) for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
od,nd=defs(old,ot),defs(new,nt)
assert od.keys()==nd.keys()
changed=[name for name in od if od[name]!=nd[name]]
assert set(changed)=={'safe_error','profiles','typed_child','main'},changed
unchanged=[name for name in od if od[name]==nd[name]]
def value(tree,name):
    node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
    return ast.literal_eval(node.value)
def payload(tree):
    node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='NATIVE_MODULES' for t in n.targets))
    return json.loads(ast.literal_eval(node.value.args[0]))
assert payload(ot)==payload(nt)
for name in ('ORIGINAL_CAPTURE_SECONDS','PUBLIC_HASH_BOUND','READ_NULL_RULE'):
    assert value(ot,name)==value(nt,name)
root=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1')
def profile_ns(tree,generation):
    ns={'Path':Path,'json':json,'hashlib':hashlib,'ROOT':root,'QA':root/'qa',
        'LIVE':Path('/Users/qianqi/.openclaw'),'AGENTS':value(tree,'AGENTS'),
        'CACHE_NAMES':value(tree,'CACHE_NAMES'),'PROBE_ROOT':root/('native-proc-sandbox-probe-'+generation),
        'READ_NULL_RULE':value(tree,'READ_NULL_RULE')}
    if generation=='r2':ns['ANCESTOR_READ_RULE']=value(tree,'ANCESTOR_READ_RULE')
    chosen=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in
            ('Refused','need','sha','capture_profile','profiles')]
    exec(compile(ast.Module(body=chosen,type_ignores=[]),'<selected-pure-profile>','exec'),ns)
    return ns,ns['profiles']()
old_ns,op=profile_ns(ot,'r1');new_ns,np=profile_ns(nt,'r2')
rule=value(nt,'ANCESTOR_READ_RULE')
expected=b'(allow file-read* (literal "/Volumes/T5/hepta-vnext-recovery-20261013"))\n'
assert rule==expected
normalize=lambda b:b.replace(b'native-proc-sandbox-probe-r2',b'native-proc-sandbox-probe-r1')
assert normalize(np['original'])==op['original']
assert np['patched'].count(rule)==1 and rule not in op['patched']
assert normalize(np['patched']).replace(rule,b'',1)==op['patched']
assert b'(subpath "/Volumes/T5/hepta-vnext-recovery-20261013")' not in np['patched']
write_or_network=lambda b:[line for line in b.splitlines() if b'file-write' in line or b'network' in line]
assert write_or_network(normalize(np['patched']))==write_or_network(op['patched'])
for name,data in np.items():(BASE/('r2-'+name+'.sb')).write_bytes(data)
# Test only reporting a synthetic traceback; no file, descriptor, socket or process action in selected function.
ns=dict(new_ns,BASE=new_ns['PROBE_ROOT'],WORKER=new_ns['PROBE_ROOT']/'probe.py')
node=next(n for n in nt.body if isinstance(n,ast.FunctionDef) and n.name=='safe_error')
exec(compile(ast.Module(body=[node],type_ignores=[]),'<selected-safe-error>','exec'),ns)
diagnostics=[]
def synthetic(filename,deep=False):
    body=("def fail(n):\n    if n:return fail(n-1)\n    raise PermissionError(1,'SYNTHETIC_PRIVATE_MESSAGE','/synthetic/private/credential')\n" if deep else
          "def fail(n):\n    raise PermissionError(1,'SYNTHETIC_PRIVATE_MESSAGE','/synthetic/private/credential')\n")
    fake={};exec(compile(body,filename,'exec'),fake)
    try:fake['fail'](20 if deep else 0)
    except PermissionError as error:
        report={};ns['safe_error'](report,error,'fixed_public_diagnostic')
        output=json.dumps(report)
        assert 'SYNTHETIC_PRIVATE_MESSAGE' not in output and '/synthetic/private/credential' not in output
        assert filename not in output
        assert report['errorErrno']==1 and len(report['publicErrorFrames'])<=16
        return report
r=synthetic(str(root/'qa/mac_t5_volume_guard_r1.py'))
assert r['publicErrorFrames'] and set(x['source'] for x in r['publicErrorFrames'])=={'held_t5'}
diagnostics.append('known-public-source-label-and-line-only')
r=synthetic('/synthetic/unlisted-source.py')
assert r['publicErrorFrames']==[] and r['unlistedFramesWithinBound']>0
diagnostics.append('unlisted-filename-and-error-values-omitted')
r=synthetic(str(ns['WORKER']),True)
assert r['additionalFramesTruncated'] is True and len(r['publicErrorFrames'])<=16
diagnostics.append('traceback-bound-with-explicit-truncation')
print(json.dumps({'schema':'heptabao.native-probe-r2-source-delta-verification.r1',
 'source_sha256':hashlib.sha256(new).hexdigest(),'source_bytes':len(new),
 'whole_source_ast_compile':True,'candidate_main_executed':False,
 'native_api_calls':0,'host_actions':0,'unchanged_definition_names':unchanged,
 'changed_definition_names':changed,'three_native_modules_exact':True,
 'original_deadlines_and_read_bound_equal':True,'old_profiles_equal_after_only_new_root_binding':True,
 'additional_permission_rule':rule.decode(),'additional_permission_bytes':len(rule),
 'only_one_extra_directory_literal':True,'no_new_descendant_subtree_or_write_or_network_rule':True,
 'four_kernel_refusal_body_equal':od['kernel_refusals']==nd['kernel_refusals'],
 'diagnostic_selected_cases':diagnostics,
 'policies':{name:{'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in np.items()},
 'harness_public_source_file_reads_and_local_policy_artifact_writes':True},sort_keys=True))
