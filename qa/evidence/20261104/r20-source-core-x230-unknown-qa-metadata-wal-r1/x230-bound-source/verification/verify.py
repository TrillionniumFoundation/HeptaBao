#!/usr/bin/env python3
"""Offline AST/whole-diff/argv proof only. No submitted module is imported or run."""
from pathlib import Path, PurePosixPath
import ast, base64, difflib, hashlib, json, shlex, sys, types

ROOT = Path(__file__).parent
value = json.loads((ROOT / 'input.json').read_text())
checks = []
def require(ok, label):
    if not ok:
        raise AssertionError(label)
    checks.append(label)
def pin(text):
    raw = text.encode()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
def assigned(tree, name):
    rows = [n for n in tree.body if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    require(len(rows) == 1, 'unique assignment ' + name)
    return rows[0]
def literal(tree, name):
    return ast.literal_eval(assigned(tree, name).value)
def definitions(tree, text):
    rows = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rows[(type(node).__name__, node.name, node.lineno)] = ast.get_source_segment(text, node)
    return rows
def stripped(tree, names):
    nodes = [n for n in tree.body
             if not (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in n.targets))]
    return ast.dump(ast.Module(body=nodes, type_ignores=[]), include_attributes=False)
def path_expr(node, env):
    if isinstance(node, ast.Name):
        return env[node.id]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'Path' and len(node.args) == 1 and not node.keywords:
        return PurePosixPath(ast.literal_eval(node.args[0]))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return path_expr(node.left, env) / path_expr(node.right, env)
    raise AssertionError('unsupported fixed path expression')
trees, diffs, counts, pins = {}, {}, {}, {}
for name in ('sender', 'receiver', 'relay'):
    old, new = value['before'][name], value['after'][name]
    bt, at = ast.parse(old), ast.parse(new)
    compile(at, '<candidate-' + name + '>', 'exec')
    compile(bt, '<reference-' + name + '>', 'exec')
    names = {'FILES', 'BINDING_READY'} | ({'HELPERS'} if name == 'relay' else set())
    require(stripped(bt, names) == stripped(at, names), name + ' complete nonbinding AST exact')
    bd, ad = definitions(bt, old), definitions(at, new)
    require(bd == ad, name + ' every definition source byte exact')
    counts[name] = len(ad)
    require(literal(bt, 'BINDING_READY') is False and literal(at, 'BINDING_READY') is True, name + ' ready-only binding')
    old_files, files = literal(bt, 'FILES'), literal(at, 'FILES')
    require(old_files == value['plan']['planned_files'], name + ' original table exact')
    require(len(files) == len(value['actual_file_infos']) == 7, name + ' exact seven inputs')
    for index, (oldrow, row, info) in enumerate(zip(old_files, files, value['actual_file_infos'], strict=True)):
        preserve = {k: v for k, v in row.items() if k not in ('bytes', 'sha256', 'version')}
        require(preserve == {k: v for k, v in oldrow.items() if k not in ('bytes', 'sha256', 'version')},
                name + ' fixed path/name/mode/order ' + str(index))
        require(row['path'] == info['path'] and row['bytes'] == info['size']
                and row['sha256'] == info['sha256'] and row['version'] == info['version']
                and row['source_mode'] == info['mode'], name + ' actual metadata binding ' + str(index))
        require(info['metadata']['uid'] == info['metadata']['gid'] == 1000
                and info['metadata']['link_count'] == 1, name + ' metadata ownership ' + str(index))
    trees[name] = at
    pins[name] = pin(new)
    diffs[name + '.binding.diff'] = ''.join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                                   'reference/' + name + '.py', 'candidate/' + name + '.py'))
require(literal(trees['sender'], 'FILES') == literal(trees['receiver'], 'FILES') == literal(trees['relay'], 'FILES'),
        'three exact common file tables')
require(literal(trees['relay'], 'HELPERS') == {n + '.py': pins[n]['sha256'] for n in ('sender','receiver')},
        'relay helper whole pins')
bt, at = ast.parse(value['carrier_before']), ast.parse(value['carrier_after'])
compile(at, '<candidate-carrier>', 'exec')
require(definitions(bt, value['carrier_before']) == definitions(at, value['carrier_after']),
        'carrier five definitions source byte exact')
counts['carrier'] = len(definitions(at, value['carrier_after']))
old_schemas = ['heptabao.df026-shared-normal5-inert-carrier.v1', 'heptabao.df026-shared-normal5-inputs.v1']
new_schemas = ['heptabao.df026-x230-normal7-inert-carrier.v1', 'heptabao.df026-x230-normal7-inputs.v1']
rebuilt = value['carrier_after'].replace("BASE = PARENT / 'normal-cold-h2-x230-transfer-controls-r1'",
                                      "BASE = PARENT / 'normal-cold-h2-shared-artifact-controls-r1'")
for new, old in zip(new_schemas, old_schemas, strict=True):
    require(rebuilt.count(new) == 1, 'unique carrier schema ' + new)
    rebuilt = rebuilt.replace(new, old)
newpins, oldpins = literal(at, 'PINS'), literal(bt, 'PINS')
rebuilt = rebuilt.replace('PINS = ' + json.dumps(newpins, indent=4), 'PINS = ' + json.dumps(oldpins, indent=4))
require(rebuilt == value['carrier_before'], 'carrier only BASE/schema/three pins exact inverse')
require(newpins == {n + '.py': [pins[n]['bytes'], pins[n]['sha256']] for n in ('sender','receiver','relay')},
        'carrier exact three pins')
diffs['inert-carrier.binding.diff'] = ''.join(difflib.unified_diff(value['carrier_before'].splitlines(keepends=True),
                    value['carrier_after'].splitlines(keepends=True), 'reference/inert.py', 'candidate/inert.py'))
payload = json.loads(value['stdin'])
require(set(payload) == {'schema','files'} and payload['schema'] == new_schemas[1], 'payload exact schema')
require(set(payload['files']) == set(newpins), 'payload exact three names')
require(0 < len(value['stdin'].encode()) <= 262144, 'original stdin cap262144')
for name, encoded in payload['files'].items():
    raw = base64.b64decode(encoded, validate=True)
    require(raw == value['after'][name.removesuffix('.py')].encode(), 'payload exact source ' + name)
    compile(raw, '<payload-' + name + '>', 'exec')
req = value['inert_request']
require(set(req) == {'host','executable','args','cwd','stdin','timeout_seconds','idempotency_key'}, 'inert exact request keys')
require(req['host'] == 'desktop' and req['executable'] == '/usr/bin/python3'
        and req['args'] == ['-I','-S','-B','-c',value['carrier_after']]
        and req['stdin'] == value['stdin'] and req['timeout_seconds'] == 60
        and req['cwd'] == '/home/qian-qi/heptabao-ha-closure-20261103-r1', 'inert exact argv/stdin/outer60')
env = {}
for key in ('BASE','SOURCES','ROOT','TARGET','CONTROL'):
    env[key] = path_expr(assigned(trees['relay'], key).value, env)
rr = value['relay_request']
require(set(rr) == {'host','executable','args','cwd','timeout_seconds','idempotency_key'}, 'relay exact request keys')
require(rr['args'] == ['-I','-S','-B',str(env['SOURCES'] / 'relay.py')]
        and rr['host'] == 'desktop' and rr['executable'] == '/usr/bin/python3'
        and rr['cwd'] == str(env['BASE']) and rr['timeout_seconds'] == 360, 'relay exact path and argv contract')
remote_node = next(n for n in trees['relay'].body if isinstance(n, ast.FunctionDef) and n.name == 'remote_command')
scope = {'hashlib':hashlib,'shlex':shlex}
exec(compile(ast.Module(body=[remote_node], type_ignores=[]), '<selected-pure-remote-command>', 'exec'), scope)
receiver_text = value['after']['receiver']
remote_argv = shlex.split(scope['remote_command']('/usr/bin/python3', receiver_text))
require(remote_argv == ['/usr/bin/python3','-I','-S','-B','-c',receiver_text,pins['receiver']['sha256']],
        'actual pure remote_command includes exact receiver self SHA')
toptry = next(n for n in trees['receiver'].body if isinstance(n, ast.Try))
entry_asserts = [n for n in toptry.body if isinstance(n, ast.Assert) and
                 ('sys.argv' in ast.unparse(n.test) or 'sys.orig_argv' in ast.unparse(n.test))]
require(len(entry_asserts) == 4, 'exact four original receiver argv/self assertions selected')
def entry_accepts(argv, orig):
    ns = {'sys':types.SimpleNamespace(argv=argv, orig_argv=orig),'re':__import__('re'),
          'controller_raw':receiver_text.encode(),'digest':lambda raw:hashlib.sha256(raw).hexdigest()}
    return all(eval(compile(ast.Expression(body=n.test), '<original-entry-assert>', 'eval'), ns) for n in entry_asserts)
require(entry_accepts(['-c', pins['receiver']['sha256']], remote_argv), 'receiver exact original entry accepts')
require(not entry_accepts(['-c'], remote_argv[:-1]), 'receiver missing selfSHA rejected')
require(not entry_accepts(['-c','0'*64],remote_argv[:-1]+['0'*64]), 'receiver wrong selfSHA rejected')
require(not entry_accepts(['-c',pins['receiver']['sha256'],'extra'],remote_argv+['extra']), 'receiver extra argument rejected')
all_receiver_argv_uses = [n for n in ast.walk(trees['receiver']) if isinstance(n, ast.Attribute)
                          and isinstance(n.value,ast.Name) and n.value.id == 'sys'
                          and n.attr in ('argv','orig_argv')]
require(len(all_receiver_argv_uses) == 8, 'receiver argv uses confined to inspected contract')
for name in ('sender','relay'):
    require(not any(isinstance(n,ast.Attribute) and isinstance(n.value,ast.Name)
                    and n.value.id == 'sys' and n.attr in ('argv','orig_argv')
                    for n in ast.walk(trees[name])), name + ' no extra self argument contract')
raw = value['actual_normal_inputs']
normal_raw = {'normal60-result.public.json':raw['normal-release-tests-result.public.json'],
              'native-build.public.json':raw['native-build.public.json'],'groups.json':raw['groups.json']}
selected = [n for n in trees['receiver'].body if isinstance(n,ast.FunctionDef) and n.name in ('need','verify_normal60')]
require(len(selected) == 2, 'actual pure normal60 checker selected')
nspace = {'json':json,'CANONICAL':'df026fe323dd7cf0f0ec57d7d2d9c5a79897053c',
          'TREE':'424463ccd2310ddc1e7b2bbcd7b7af29ae58c825',
          'digest':lambda raw:hashlib.sha256(raw.encode() if isinstance(raw,str) else raw).hexdigest(),'result':{}}
exec(compile(ast.Module(body=selected,type_ignores=[]),'<selected-pure-normal60-receipts>','exec'),nspace)
nspace['verify_normal60'](normal_raw)
require(nspace['result'].get('normal60_qualification_verified') is True, 'unchanged actual normal60 predicate passes real df026 raw receipts')
report={'schema':'heptabao.df026.x230-normal7-offline-proof.r1','status':'passed',
        'checks':checks,'checks_passed':len(checks),'definition_counts':counts,
        'source_pins':pins,'carrier_pin':pin(value['carrier_after']),
        'inert_stdin_pin':pin(value['stdin']),
        'fixed_desktop_controls':str(env['SOURCES']),'fixed_relay_root':str(env['ROOT']),
        'fixed_x230_root':str(env['TARGET']),'remote_receiver_argv_count':len(remote_argv),
        'module_execution':False,'selected_pure_functions_executed':['remote_command','need','verify_normal60'],
        'selected_original_asserts_evaluated':4,'host_operations':0,'network_operations':0,
        'product_operations':0,'child_operations':0,'diffs':diffs}
(ROOT/'output.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':'passed','checks_passed':len(checks),'definition_counts':counts,
                  'host_operations':0,'module_execution':False,'source_pins':pins},sort_keys=True))
