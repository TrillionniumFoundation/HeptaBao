import ast, hashlib, json
from pathlib import Path
root=Path(__file__).parent
before=(root/'entry.before.py').read_text()
after=(root/'entry.policy-after.py').read_text()
probe=(root/'mac_capture_devnull_probe_r1.py').read_text()
trees={name:ast.parse(source,filename=name) for name,source in
       [('entry.before.py',before),('entry.policy-after.py',after),('mac_capture_devnull_probe_r1.py',probe)]}
for name,tree in trees.items():compile(tree,name,'exec')
def node(tree,name):
    found=[x for x in tree.body if isinstance(x,(ast.FunctionDef,ast.ClassDef)) and x.name==name]
    assert len(found)==1
    return found[0]
def pure_ns(tree,functions):
    ns={'Path':Path,'json':json,'ROOT':Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1'),
        'QA':Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1/qa'),
        'LIVE':Path('/Users/qianqi/.openclaw'),
        'AGENTS':('main','trnm','hepta-ui','hepta','hepta-backend'),
        'CACHE_NAMES':('applied-profiles.json','publish-baseline.json','bad-refresh-quarantine.json',
                       'refresh-backoff.json','lease-epochs.json','status.json')}
    selected=[node(tree,x) for x in ('Refused','need',*functions)]
    exec(compile(ast.fix_missing_locations(ast.Module(body=selected,type_ignores=[])),'selected_public_pure_functions','exec'),ns)
    return ns
old=pure_ns(trees['entry.before.py'],('capture_profile',))
new=pure_ns(trees['entry.policy-after.py'],('capture_profile',))
check=pure_ns(trees['mac_capture_devnull_probe_r1.py'],('capture_profile','profiles','safe_error'))
rule=b'(allow file-read* (literal "/dev/null"))\n'
check['READ_NULL_RULE']=rule
actual_old=old['capture_profile']('before')
assert hashlib.sha256(actual_old).hexdigest()=='de74f118ead7f9769dd12e692b116fc80aaaa5953d559c8f63b0f8c3125cf387'
assert new['capture_profile']('before').replace(rule,b'',1)==actual_old
assert ast.dump(node(trees['entry.before.py'],'capture_profile'),include_attributes=False)==ast.dump(
    node(trees['mac_capture_devnull_probe_r1.py'],'capture_profile'),include_attributes=False)
before_kernel=ast.get_source_segment(before,node(trees['entry.before.py'],'kernel_refusals'))
after_kernel=ast.get_source_segment(probe,node(trees['mac_capture_devnull_probe_r1.py'],'kernel_refusals'))
assert before_kernel.replace("directory=ROOT/'captures'/stage/'probe';",
                             "directory=BASE/'probe';",1)==after_kernel
fresh=check['ROOT']/'devnull-sandbox-probe-r1'
check['PROBE_ROOT']=fresh
check['sha']=lambda raw:hashlib.sha256(raw).hexdigest()
p=check['profiles']()
oldprefix=str(check['ROOT']/'captures/before').encode()
assert actual_old.count(oldprefix)==3
assert p['original']==old['capture_profile']('before').replace(oldprefix,str(fresh).encode())
assert p['patched']==new['capture_profile']('before').replace(oldprefix,str(fresh).encode())
assert p['patched'].replace(rule,b'',1)==p['original'] and p['patched'].count(rule)==1
assert b'(allow network' not in p['original'] and b'(allow network' not in p['patched']
assert [x for x in p['original'].splitlines() if b'file-write' in x]==[
        x for x in p['patched'].splitlines() if b'file-write' in x]
diagnostic={}
check['safe_error'](diagnostic,PermissionError(13,'synthetic-secret-message','/synthetic-secret-path'),
                    'child_diskutil_command')
assert diagnostic=={'errorStage':'child_diskutil_command','errorType':'PermissionError',
                    'errorCode':None,'errorErrno':13}
assert 'synthetic-secret' not in json.dumps(diagnostic)
result={'schema':'heptabao.mac-devnull-probe-pure-source-check.r1',
        'ast_compile_only_sources':list(trees),'full_modules_executed':False,
        'actual_failed_capture_profile_sha256':hashlib.sha256(actual_old).hexdigest(),
        'capture_profile_ast_exact':True,'kernel_refusals_only_owned_directory_binding_changed':True,
        'profile_delta_exactly_one_devnull_literal':True,'private_literals_write_network_rules_unchanged':True,
        'fresh_root':str(fresh),
        'original_profile':{'bytes':len(p['original']),'sha256':hashlib.sha256(p['original']).hexdigest()},
        'patched_profile':{'bytes':len(p['patched']),'sha256':hashlib.sha256(p['patched']).hexdigest()},
        'fixed_errno_diagnostic_omits_exception_message_and_filename':True,
        'host_calls':0,'subprocesses':0,'sockets':0,'sqlite_connections':0,'private_inputs_opened':0}
(root/'original.sb').write_bytes(p['original'])
(root/'patched.sb').write_bytes(p['patched'])
print(json.dumps(result,sort_keys=True,indent=2))
