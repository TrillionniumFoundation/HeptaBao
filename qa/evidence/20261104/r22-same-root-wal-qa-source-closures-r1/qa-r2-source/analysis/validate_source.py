import ast, argparse, difflib, hashlib, json, os, pathlib, signal, stat, subprocess, sys, time, types, re
if len(sys.argv)==3 and sys.argv[1]=='--input':
    data=json.loads(pathlib.Path(sys.argv[2]).read_text())
    f=data['files']; old=data['original']
else:
    root=pathlib.Path(sys.argv[1])
    names=['source/build_native_h2_client_r1.py','source/publish_h2_qa_inputs_r1.py',
           'source/build-binding.private.json','components/linux_owned_components.py',
           'components/mock_components.py','components/sources.carrier.json',
           'requests/owned-components.proposed.exact.json','requests/inert.proposed.exact.json',
           'requests/build.proposed.exact.json','carrier/qa-build-inputs.json']
    f={name:(root/name).read_text() for name in names}
    for name in ('native_h2_client.rs','native_h2_client_tests.rs','Cargo.toml',
                 'canonical.Cargo.lock','owned_reference_phaseb_r3.py','official_cli_reference_r4.py'):
        f['source/inputs/'+name]=(root/'source/inputs'/name).read_text()
    old={name:(root/ref).read_text() for name,ref in {
        'source/build_native_h2_client_r1.py':'reference/builder-r1.py',
        'source/publish_h2_qa_inputs_r1.py':'reference/publisher-r1.py',
        'source/build-binding.private.json':'reference/build-binding-r1.private.json',
        'requests/build.exact.json':'reference/build-request-r1.json'}.items()}
    data={'mock_report':json.loads((root/'components/mock-components.stdout.original.json').read_text())}
checks=[]
def need(name, value):
    checks.append({'name':name,'passed':bool(value)})
    assert value, name
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def assignments(source):
    out={}
    for n in ast.parse(source).body:
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
            try: out[n.targets[0].id]=ast.literal_eval(n.value)
            except (ValueError,TypeError): pass
    return out
def defs(source):
    return {n.name:ast.get_source_segment(source,n) for n in ast.parse(source).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
def select(source,names,namespace):
    ns=[n for n in ast.parse(source).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
    assert {n.name for n in ns}==set(names)
    module=ast.Module(body=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0),*ns],type_ignores=[])
    exec(compile(ast.fix_missing_locations(module),'<selected-definitions>','exec'),namespace)
builder=f['source/build_native_h2_client_r1.py']; pub=f['source/publish_h2_qa_inputs_r1.py']; component=f['components/linux_owned_components.py']
for name in ['source/build_native_h2_client_r1.py','source/publish_h2_qa_inputs_r1.py','components/linux_owned_components.py','components/mock_components.py']:
    compile(ast.parse(f[name]),name,'exec'); need('compile_only_'+name,True)
need('original_caps_equal',assignments(builder)['CAPS']==assignments(old['source/build_native_h2_client_r1.py'])['CAPS'])
need('all_publisher_functions_same',defs(pub)==defs(old['source/publish_h2_qa_inputs_r1.py']))
binding=json.loads(f['source/build-binding.private.json']); previous=json.loads(old['source/build-binding.private.json'])
inverse=json.loads(json.dumps(binding))
inverse['root']=inverse['root'].replace('-20261105-r2','-20261105-r1')
inverse['control']=inverse['control'].replace('-20261105-r2','-20261105-r1')
for pin in inverse['inputs'].values(): pin['path']=pin['path'].replace('qa-controls-df026-20261105-r2','qa-controls-df026-20261105-r1')
need('binding_inverse_exact',inverse==previous)
need('target_identity_unchanged',binding['target_identity']==previous['target_identity'])
need('tools_normal_source_caps_unchanged',all(binding[k]==previous[k] for k in ('tools','normal_product_result','source','candidate_commit','candidate_tree','cargo_home','target','caps','host')))
import base64
carrier=json.loads(f['carrier/qa-build-inputs.json']); pins=assignments(pub)['PINS']
oldpins=assignments(old['source/publish_h2_qa_inputs_r1.py'])['PINS']
need('fixed_eight_inputs',set(carrier['files'])==set(pins)==set(oldpins) and len(pins)==8)
for name,pin in pins.items():
    decoded=base64.b64decode(carrier['files'][name],validate=True).decode()
    need('carrier_exact_'+name,decoded==f['source/'+name] and pin==[len(decoded.encode()),sha(decoded)])
for name in carrier['files']:
    if name.startswith('inputs/'):
        need('retained_input_exact_'+name,[len(f['source/'+name].encode()),sha(f['source/'+name])]==oldpins[name])
inert=json.loads(f['requests/inert.proposed.exact.json'])
need('inert_source_argv_exact',inert['args']==['-I','-S','-B','-c',pub])
need('inert_carrier_exact',inert['stdin']==f['carrier/qa-build-inputs.json'])
need('inert_original_outer',inert['timeout_seconds']==60)
build=json.loads(f['requests/build.proposed.exact.json'])
need('build_fixed_args',build['args']==['-I','-S','-B',binding['control']+'/build_native_h2_client_r1.py','--binding',binding['control']+'/build-binding.private.json','--binding-sha256',sha(f['source/build-binding.private.json']),'--self-sha256',sha(builder)])
need('build_same_host_executable_cwd_caps',all(build[k]==json.loads(old['requests/build.exact.json'])[k] for k in ('host','executable','cwd','timeout_seconds')))
req=json.loads(f['requests/owned-components.proposed.exact.json']); ccar=json.loads(f['components/sources.carrier.json'])
need('component_exact_argv',req['args']==['-I','-S','-B','-c',component,'--self-sha256',sha(component),'--carrier-sha256',sha(f['components/sources.carrier.json'])])
need('component_exact_stdin',req['stdin']==f['components/sources.carrier.json'])
need('component_tools_exact',assignments(component)['TOOLS']=={k:binding['tools'][k] for k in ('python','git')})
for role,(size,digest) in assignments(component)['SOURCE_PINS'].items():
    raw=ccar['sources'][role]
    need('component_source_pin_'+role,len(raw.encode())==size and sha(raw)==digest)
need('component_builder_exact',ccar['sources']['builder']==builder)
need('memory_components_actual_18',data['mock_report']['passed']==18 and all(x['passed'] for x in data['mock_report']['results']) and data['mock_report']['actual_children']==0)
ns={'Path':pathlib.Path,'hashlib':hashlib,'os':os,'signal':signal,'stat':stat,'subprocess':subprocess,'sys':sys,'time':time,'re':re,'ROOT':pathlib.Path('/home/qian-qi'),'TOOL_ROOT':pathlib.Path('/tools'),'OPEN_FDS':set(),'FD_CLOSE_FAILED':False}
select(builder,{'BindingError','open_fd','close_fd','need','remaining','sha','identity','exact_path','no_symlink_ancestors','read_file','pin_file','fixed_error','qa_command_owner_class'},ns)
cn={'Path':pathlib.Path,'hashlib':hashlib,'os':os,'signal':signal,'subprocess':subprocess,'time':time}
select(ccar['sources']['cli_reference'],{'Refused','process_identity','group_members','stop_owned','stop_provisional','Owner'},cn)
on={'Path':pathlib.Path,'require':ns['need']}; select(ccar['sources']['owner_reference'],{'owner_class'},on)
owner=ns['qa_command_owner_class'](types.SimpleNamespace(owner_class=on['owner_class']),types.SimpleNamespace(**cn))(ns['ROOT'])
need('selected_classes_construct_without_phasea_init',owner.children==[] and owner.command_custody=={} and ns['OPEN_FDS']==set())
diffs={}
for title,before,after in [('publisher-r1-to-r2',old['source/publish_h2_qa_inputs_r1.py'],pub),('binding-r1-to-r2',old['source/build-binding.private.json'],f['source/build-binding.private.json'])]:
    diffs['diffs/'+title+'.review.diff']=''.join(difflib.unified_diff(before.splitlines(keepends=True),after.splitlines(keepends=True),fromfile=title+'-before',tofile=title+'-after'))
report={'schema':'qa-custody-r2-full-source-validation-v1','checks':checks,'passed':len(checks),'target_main_executed':False,'actual_children':0,'source_class_definitions_constructed':True,'owned_linux_components_executed':False,'new_host_operations':0}
print(json.dumps({'report':report,'diffs':diffs},sort_keys=True))
