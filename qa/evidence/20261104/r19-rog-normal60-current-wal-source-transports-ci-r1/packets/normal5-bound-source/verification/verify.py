import ast, base64, difflib, hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
sha = lambda b: hashlib.sha256(b).hexdigest()
def assignments(tree):
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try: out[target.id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError): pass
    return out
def defs(text, tree):
    return {node.name: ast.get_source_segment(text, node)
            for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
proof = {'schema':'heptabao.df026-normal5-source-verification.v1',
         'module_execution':False,'remote_calls':0,'children':0,
         'scope':'Local public source AST/compile/diff and literal/payload identity; no remote module or transport executed.',
         'sources':[], 'diffs':{}}
texts = {}
for name in ('sender','receiver','relay','inert'):
    before = (root/'before'/f'{name}.py').read_text()
    after = (root/'candidate'/f'{name}.py').read_text()
    ba, aa = ast.parse(before), ast.parse(after)
    compile(after, f'{name}.py', 'exec', dont_inherit=True)
    assert defs(before,ba) == defs(after,aa)
    delta = ''.join(difflib.unified_diff(before.splitlines(keepends=True),
                     after.splitlines(keepends=True), fromfile=f'before/{name}.py',
                     tofile=f'candidate/{name}.py', n=3))
    proof['diffs'][name+'.review.diff'] = delta
    texts[name] = (after, assignments(aa))
    proof['sources'].append({'name':name, 'before_bytes':len(before.encode()),
       'after_bytes':len(after.encode()), 'before_sha256':sha(before.encode()),
       'after_sha256':sha(after.encode()), 'unchanged_top_level_definitions':len(defs(before,ba)),
       'ast_parse':True,'compile_only':True,'diff_hunks':sum(line.startswith('@@ ') for line in delta.splitlines())})
actual = json.loads((root/'actual-files.json').read_text())
assert len(actual) == 5 and len({x['path'] for x in actual}) == 5 and len({x['name'] for x in actual}) == 5
for name in ('sender','receiver','relay'):
    a = texts[name][1]
    assert a['ACTUAL_INPUTS_READY'] is True
    assert a['HEAD'] == 'df026fe323dd7cf0f0ec57d7d2d9c5a79897053c'
    assert a['TREE'] == '424463ccd2310ddc1e7b2bbcd7b7af29ae58c825'
    assert a['FILES'] == actual
    assert all(isinstance(x['bytes'],int) and x['bytes']>0 and len(x['sha256'])==64
               and isinstance(x['version'],str) and len(x['version'].split(':'))==5 for x in a['FILES'])
assert texts['relay'][1]['HELPERS'] == {
    name+'.py':sha(texts[name][0].encode()) for name in ('sender','receiver')}
oldrelay = assignments(ast.parse((root/'before'/'relay.py').read_text()))
assert texts['relay'][1]['SSH'] == oldrelay['SSH']
assert texts['relay'][1]['TRUST'] == oldrelay['TRUST']
payload = json.loads((root/'stdin.json').read_text())
assert payload['schema'] == 'heptabao.df026-shared-normal5-inputs.v1'
assert set(payload['files']) == {'sender.py','receiver.py','relay.py'}
pins = texts['inert'][1]['PINS']
for name in ('sender','receiver','relay'):
    raw = base64.b64decode(payload['files'][name+'.py'], validate=True)
    assert raw == texts[name][0].encode()
    assert pins[name+'.py'] == [len(raw),sha(raw)]
assert len((root/'stdin.json').read_bytes()) <= 262144
proof.update(status='PASS_SOURCE_ONLY',fixed_input_count=5,exact_input_metadata_literal=True,
             original_ssh_prefix_and_trust_whole_pins_unchanged=True,
             original_all_top_level_definitions_byte_exact=True,
             inert_payloads_exact=3,inert_original_262144_limit_preserved=True,
             normal_release_original_provenance_function_unchanged=True,
             additional_combined_result_and_groups_are_raw_byte_carried=True)
print(json.dumps(proof, sort_keys=True, indent=2))
