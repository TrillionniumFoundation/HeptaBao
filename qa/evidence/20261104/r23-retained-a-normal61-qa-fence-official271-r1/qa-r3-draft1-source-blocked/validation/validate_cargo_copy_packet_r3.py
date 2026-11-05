import argparse
import ast
import base64
import hashlib
import json
from pathlib import Path
import sys

inputs=json.loads(Path(__file__).with_name('cargo-copy-r3-validation-input.json').read_text())
source=inputs['after'];before=inputs['before'];publisher=inputs['publisher']
inert=json.loads(inputs['inert']);build=json.loads(inputs['build']);binding=json.loads(inputs['binding'])
checks=[]
def checked(name,value):
    assert value,name
    checks.append({'name':name,'passed':True})
def sha(raw):return hashlib.sha256(raw).hexdigest()
def parsed(raw):
    tree=ast.parse(raw);compile(tree,'<compile-only>','exec')
    return tree
builder_ast=parsed(source);publisher_ast=parsed(publisher)
checked('builder-and-publisher-AST-compile-only',True)
def assignments(tree):
    return {t.id:n.value for n in tree.body if isinstance(n,ast.Assign)
            for t in n.targets if isinstance(t,ast.Name)}
assigned=assignments(builder_ast);pub_assign=assignments(publisher_ast)
pins=ast.literal_eval(pub_assign['PINS'])
checked('publisher-ready-after-actual-alias',ast.literal_eval(pub_assign['ACTUAL_INPUTS_READY']) is True)
checked('inert-original-host-python-cwd-cap',(inert['host'],inert['executable'],inert['cwd'],inert['timeout_seconds'])==('rog','/usr/bin/python3','/home/qian-qi',60))
checked('inert-only-five-args',inert['args']==['-I','-S','-B','-c',publisher])
payload=json.loads(inert['stdin']);checked('carrier-original-schema',payload['schema']=='heptabao.native-h2-qa-build-inputs.v1')
checked('carrier-original-524288-cap',0<len(inert['stdin'].encode())<=524288)
checked('eight-exact-payload-names',set(payload['files'])==set(pins) and len(pins)==8)
decoded={}
for name,(length,digest) in pins.items():
    raw=base64.b64decode(payload['files'][name],validate=True)
    checked('payload-whole-'+name,len(raw)==length and sha(raw)==digest)
    decoded[name]=raw
checked('carried-builder-exact',decoded['build_native_h2_client_r1.py']==source.encode())
checked('carried-binding-exact',decoded['build-binding.private.json']==inputs['binding'].encode())
input_pins=ast.literal_eval(assigned['INPUT_PINS'])
for role,(name,length,digest) in input_pins.items():
    checked('retained-input-'+role,pins['inputs/'+name]==[length,digest] and
            binding['inputs'][role]['sha256']==digest and binding['inputs'][role]['bytes']==length)
checked('binding-ready',binding['ready'] is True)
checked('same-original-caps',binding['caps']==ast.literal_eval(assigned['CAPS'])=={
    'total_seconds':600,'git_seconds':15,'tool_seconds':15,'lock_seconds':20,
    'build_seconds':180,'components_build_seconds':180,'list_seconds':15,
    'components_seconds':30,'cleanup_term_seconds':5,'cleanup_kill_seconds':5})
checked('df026-identity',binding['candidate_commit']==ast.literal_eval(assigned['COMMIT'])=='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c' and binding['candidate_tree']==ast.literal_eval(assigned['TREE'])=='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825')
control=ast.literal_eval(assigned['CONTROL'].args[0]);root=ast.literal_eval(assigned['ROOT'].args[0])
checked('fresh-r3-literal-roots',control==binding['control']=='/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3' and root==binding['root']=='/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3')
checked('publisher-exact-control-basename',ast.literal_eval(pub_assign['BASE'].right)==Path(control).name)
checked('all-six-input-paths',all(row['path']==control+'/inputs/'+input_pins[role][0] for role,row in binding['inputs'].items()))
checked('build-fixed-host-python-cwd-cap',(build['host'],build['executable'],build['cwd'],build['timeout_seconds'])==('rog','/usr/bin/python3.12','/home/qian-qi',660))
checked('build-exact-executable-source-path',build['args'][:4]==['-I','-S','-B',control+'/build_native_h2_client_r1.py'])
main=next(n for n in builder_ast.body if isinstance(n,ast.FunctionDef) and n.name=='main')
parser_nodes=[]
for node in main.body:
    if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('parser','args') for t in node.targets):parser_nodes.append(node)
    elif isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Attribute) and isinstance(node.value.func.value,ast.Name) and node.value.func.value.id=='parser':parser_nodes.append(node)
checked('exact-five-parser-statements',len(parser_nodes)==5)
oldargv=sys.argv;scope={'argparse':argparse,'Path':Path}
try:
    sys.argv=[build['args'][3],*build['args'][4:]]
    exec(compile(ast.Module(body=parser_nodes,type_ignores=[]),'<only-original-argparse-five>','exec'),scope)
finally:sys.argv=oldargv
actual_args=scope['args']
checked('required-binding-argument',actual_args.binding==Path(control)/'build-binding.private.json')
checked('required-binding-whole-digest',actual_args.binding_sha256==sha(inputs['binding'].encode()))
checked('required-self-whole-digest',actual_args.self_sha256==sha(source.encode()))
oldpub=inputs['publisher_before']
inverse=publisher.replace('heptabao-native-h2-qa-controls-df026-20261105-r3','heptabao-native-h2-qa-controls-df026-20261105-r2').replace(str(len(source.encode())),'42820').replace(sha(source.encode()),'c961a54dfc35332be035bb16fc1ae697199e35da496b0c9ea52c35dc3f8455d8').replace(sha(inputs['binding'].encode()),'d995e45f61507ba9b99500daf736fa2e179839e95babe4d8db25c3cb11536693')
checked('publisher-four-literal-inverse-whole-exact',inverse==oldpub)
checked('existing-private-binding-format-and-mode',binding['schema']=='heptabao.native-h2-qa.build-binding.v1' and all(x['mode']==384 for x in binding['inputs'].values()))
print(json.dumps({'schema':'heptabao.qa-r3.cargo-copy.source-carrier-validation.v1',
    'status':'passed-source-only','checks':checks,'check_count':len(checks),
    'compiled_changed_sources':2,'builder_main_calls':0,'publisher_main_calls':0,
    'original_argparse_statements_executed':5,'new_host_or_cargo_requests':0,
    'source_sha256':sha(source.encode()),'binding_sha256':sha(inputs['binding'].encode()),
    'inert_request_sha256':sha(inputs['inert'].encode()),'build_request_sha256':sha(inputs['build'].encode())},indent=2,sort_keys=True))
