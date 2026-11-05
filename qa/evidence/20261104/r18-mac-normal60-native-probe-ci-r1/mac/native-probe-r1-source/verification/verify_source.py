#!/usr/bin/env python3
import ast,base64,hashlib,json
from pathlib import Path
base=Path(__file__).parent
names=('mac_darwin_owned_projection_r1.py','mac_native_owned_unreaped_r1.py',
       'mac_native_owned_commands_r1.py','native_proc_sandbox_probe_r1.py')
files={name:(base/name).read_bytes() for name in names}
parsed={}
for name,raw in files.items():
    parsed[name]=ast.parse(raw,filename=name);compile(parsed[name],name,'exec')
def definitions(raw):
    text=raw.decode();tree=ast.parse(text)
    return {n.name:ast.get_source_segment(text,n) for n in tree.body
            if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
old=(base/'original_devnull_probe.py').read_bytes()
olddefs=definitions(old);newdefs=definitions(files[names[-1]])
unchanged=[]
for name in ('need','sha','encoded','ident','critical','interrupted','remaining','close_fd',
             'source_snapshot','utility_snapshot','safe_error','absence_twice',
             'capture_profile','profiles','kernel_refusals','null_read_case'):
    assert olddefs[name]==newdefs[name],name
    unchanged.append({'name':name,'bytes':len(newdefs[name].encode()),
                      'sha256':hashlib.sha256(newdefs[name].encode()).hexdigest()})
original_commands=(base/'original_commands.py').read_bytes()
assert original_commands.replace(b'from mac_owned_unreaped_r1 import',
    b'from mac_native_owned_unreaped_r1 import')==files['mac_native_owned_commands_r1.py']
body=parsed[names[-1]].body
assignment=next(n for n in body if isinstance(n,ast.Assign)
    and any(isinstance(t,ast.Name) and t.id=='NATIVE_MODULES' for t in n.targets))
payload=json.loads(ast.literal_eval(assignment.value.args[0]))
assert set(payload)==set(names[:3])
for name,pin in payload.items():
    raw=base64.b64decode(pin['source_base64'],validate=True)
    assert raw==files[name] and len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256']
g={'hashlib':hashlib,'Path':Path,'json':json,
   'ROOT':Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1'),
   'LIVE':Path('/Users/qianqi/.openclaw'),
   'AGENTS':('main','trnm','hepta-ui','hepta','hepta-backend'),
   'CACHE_NAMES':('applied-profiles.json','publish-baseline.json','bad-refresh-quarantine.json',
                  'refresh-backoff.json','lease-epochs.json','status.json'),
   'READ_NULL_RULE':b'(allow file-read* (literal "/dev/null"))\n'}
g['QA']=g['ROOT']/'qa';g['PROBE_ROOT']=g['ROOT']/'native-proc-sandbox-probe-r1'
for name in ('Refused','need','sha','capture_profile','profiles'):
    node=next(n for n in body if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name==name)
    exec(compile(ast.Module(body=[node],type_ignores=[]),'<pure-profile-definition>','exec'),g)
policies=g['profiles']()
assert policies['patched'].replace(g['READ_NULL_RULE'],b'',1)==policies['original']
assert len(policies['patched'])-len(policies['original'])==41
for name,raw in policies.items():
    assert b'with no-sandbox' not in raw and b'devnull-sandbox-probe-r1' not in raw
    (base/(name+'.sb')).write_bytes(raw)
proof={'schema':'heptabao.native-proc-probe-source-invariance.r1',
    'compiled_sources':[{ 'path':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
                        for name,raw in files.items()],
    'full_candidate_modules_executed':False,'native_libraries_loaded':0,'host_actions':0,
    'commands_only_import_binding_changed':True,'embedded_modules_exact':True,
    'source_functions_byte_equal':unchanged,
    'pure_profile_definitions_only_executed':True,'policy_permission_delta_bytes':41,
    'profile_pins':{name:{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
                    for name,raw in policies.items()}}
print(json.dumps(proof,sort_keys=True))
