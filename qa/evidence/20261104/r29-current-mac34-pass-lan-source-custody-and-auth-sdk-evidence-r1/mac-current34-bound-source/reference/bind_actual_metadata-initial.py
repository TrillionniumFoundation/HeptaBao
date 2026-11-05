"""Offline SOURCE assembler; no Runtime API, network or product invocation."""
import ast
import base64
import difflib
import hashlib
import json
import stat
from pathlib import Path

REFERENCE_WRAPPER_SHA = '039034faff156ee8a617cac9d16ce21daeb4b0f093de8187a19c4fcaf7c3baca'
SYSTEM_GIT_UNBOUND_SHA = '0a8e879b3accb189fe2cd3c6849e56b8c8600b66896d4ba8507cfe16db0e1386'
PUBLISHER_UNBOUND_SHA = '23595e6f147bd39afc26a8d4470fae9a0d988d42939ebab70d0d6cb09fe523c0'
PROJECTION_SHA = 'cf332426eb34c1161bc695904178f3a0bd3d4414d65a8ed9ac353b1de3665354'
ROOT_REVIEW_SHA = 'f62334d4b31e6067ad6d29337b0155847f4ede8ff6a9460b0c97a1b182939448'

def sha(raw):
    return hashlib.sha256(raw.encode()).hexdigest()

def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)

def constants(source):
    result = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ('BINDING_READY', 'INPUT_METADATA', 'INPUT_PATHS', 'EXPECTED_SHA', 'EXPECTED_BYTES', 'PINS'):
                result[name] = ast.literal_eval(node.value)
    return result

def functions(source):
    return {node.name: ast.get_source_segment(source, node) for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}

def replace_once(source, old, new):
    assert source.count(old) == 1, 'one_literal_occurrence'
    return source.replace(old, new, 1)

def assemble(reference, wrapper, publisher, projection_raw, root_review_raw):
    assert sha(reference) == REFERENCE_WRAPPER_SHA
    assert sha(wrapper) == SYSTEM_GIT_UNBOUND_SHA
    assert sha(publisher) == PUBLISHER_UNBOUND_SHA
    assert sha(projection_raw) == PROJECTION_SHA
    assert sha(root_review_raw) == ROOT_REVIEW_SHA
    original = constants(reference)
    c = constants(wrapper)
    assert c['BINDING_READY'] is False and all(v is None for v in c['INPUT_METADATA'].values())
    assert c == original
    projection = strict_json(projection_raw)
    assert projection['status'] == 'SIX_NATIVE_READS_COMPLETE_KNOWN_GIT_SINGLE_LINK_BINDING_REFUSAL'
    assert projection['checks_passed'] == 158 and projection['candidate_wrapper_changed'] is False
    table = projection['observed_full9_projection']
    assert set(table) == set(c['INPUT_PATHS']) == set(c['INPUT_METADATA'])
    for role, m in table.items():
        assert set(m) == {'path', 'bytes', 'sha256', 'identity', 'version'}
        assert m['path'] == c['INPUT_PATHS'][role]
        assert type(m['bytes']) is int and 0 < m['bytes'] <= 512 * 1024 * 1024
        assert isinstance(m['identity'], list) and len(m['identity']) == 9 and all(type(x) is int for x in m['identity'])
        assert m['identity'][6] == m['bytes'] and stat.S_ISREG(m['identity'][4])
        assert m['identity'][5] == (78 if role == 'git' else 1)
        assert ':'.join(str(m['identity'][i]) for i in (0, 1, 6, 7, 8)) == m['version']
        assert c['EXPECTED_BYTES'][role] is None or m['bytes'] == c['EXPECTED_BYTES'][role]
        assert c['EXPECTED_SHA'][role] is None or m['sha256'] == c['EXPECTED_SHA'][role]
    assert table['git'] == {'path': '/usr/bin/git', 'bytes': 118640, 'sha256': 'b8763cf250e607a778bb4603cecb5b90338814d0a3dfcba0d57b1de242f610e9', 'identity': [16777233, 1152921500312571562, 0, 0, stat.S_IFREG | 0o755, 78, 118640, 1786589515000000000, 1786589515000000000], 'version': '16777233:1152921500312571562:118640:1786589515000000000:1786589515000000000'}
    table = {role: table[role] for role in c['INPUT_PATHS']}
    old_line = next(line for line in wrapper.splitlines() if line.startswith('INPUT_METADATA='))
    new_line = 'INPUT_METADATA=' + json.dumps(table, ensure_ascii=True, separators=(',', ':'))
    bound_wrapper = replace_once(replace_once(wrapper, old_line, new_line), 'BINDING_READY=False', 'BINDING_READY=True')
    assert bound_wrapper.replace(new_line, old_line, 1).replace('BINDING_READY=True', 'BINDING_READY=False', 1) == wrapper
    assert functions(bound_wrapper) == functions(wrapper)
    assert functions(bound_wrapper)['fixed_file'] == functions(reference)['fixed_file']
    pc = constants(publisher)
    assert pc['BINDING_READY'] is False and pc['PINS'] == {'run_current_mac_full34_r1.py': [None, None]}
    pins = {'run_current_mac_full34_r1.py': [len(bound_wrapper.encode()), sha(bound_wrapper)]}
    pin_line = "PINS = {'run_current_mac_full34_r1.py': [None, None]}"
    new_pins = 'PINS = ' + repr(pins)
    bound_publisher = replace_once(replace_once(publisher, pin_line, new_pins), 'BINDING_READY = False', 'BINDING_READY = True')
    assert bound_publisher.replace(new_pins, pin_line, 1).replace('BINDING_READY = True', 'BINDING_READY = False', 1) == publisher
    assert functions(bound_publisher) == functions(publisher)
    compile(bound_wrapper, '<proposed-wrapper>', 'exec')
    compile(bound_publisher, '<proposed-inert>', 'exec')
    carrier = json.dumps({'schema': 'heptabao.current-mac-full34-inert-inputs.v1', 'files': {'run_current_mac_full34_r1.py': base64.b64encode(bound_wrapper.encode()).decode()}}, sort_keys=True, separators=(',', ':')) + '\n'
    assert base64.b64decode(strict_json(carrier)['files']['run_current_mac_full34_r1.py'], validate=True) == bound_wrapper.encode()
    root = '/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-official271-full34-4e808-r1'
    python = c['INPUT_PATHS']['python']
    inert = {'host': 'mac', 'executable': python, 'args': ['-I', '-S', '-B', '-c', bound_publisher], 'cwd': '/Volumes/T5/hepta-vnext-recovery-20261013', 'stdin': carrier, 'timeout_seconds': 60, 'idempotency_key': 'heptabao-mac-current-full34-inert-' + sha(bound_publisher)[:8] + '-20261105-r1'}
    prepare = {'host': 'mac', 'executable': python, 'args': ['-I', '-S', '-B', root + '/control/run_current_mac_full34_r1.py', '--prepare-only'], 'cwd': root, 'timeout_seconds': 90, 'idempotency_key': 'heptabao-mac-current-full34-prepare-' + sha(bound_wrapper)[:8] + '-20261105-r1'}
    return {'wrapper': bound_wrapper, 'publisher': bound_publisher, 'carrier': carrier, 'metadata': table, 'inert': inert, 'prepare': prepare}

def main():
    # This command is run only in the offline source workspace. It emits proposal
    # files; it does not call a Runtime API or grant permission to use a request.
    root = Path(__file__).resolve().parents[1]
    output = root / 'proposed-bound'
    output.mkdir(mode=0o700)
    reference = (root / 'reference/mac-wrapper-unbound.py').read_text()
    wrapper = (root / 'candidate/mac-wrapper-system-git.UNBOUND.py').read_text()
    publisher = (root / 'candidate/inert-publisher.UNBOUND.py').read_text()
    projection = (root / 'reference/six-metadata-projection.public.json').read_text()
    review = (root / 'reference/six-metadata-root-review.public.json').read_text()
    result = assemble(reference, wrapper, publisher, projection, review)
    files = {'run_current_mac_full34_r1.py': result['wrapper'], 'inert-publisher.py': result['publisher'], 'carrier.json': result['carrier'], 'input-metadata.public.json': json.dumps(result['metadata'], indent=2, sort_keys=True) + '\n', 'INERT.request.REVIEW-ONLY.json': json.dumps(result['inert'], indent=2, sort_keys=True) + '\n', 'PREPARE.request.REVIEW-ONLY.json': json.dumps(result['prepare'], indent=2, sort_keys=True) + '\n'}
    for name, raw in files.items():
        with (output / name).open('x') as stream:
            stream.write(raw)
    for name, before, after in [('metadata-binding.diff', wrapper, result['wrapper']), ('publisher-binding.diff', publisher, result['publisher'])]:
        (root / 'diff' / name).write_text(''.join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True), fromfile='a/unbound', tofile='b/proposed-bound')))
    report = {'schema': 'heptabao.mac-full34-offline-binding-proposal.v1', 'all_input_metadata_root_reviewed': True, 'root_review_blob': 'b137fc849b441e3e70e44a0c29cbf6d8bb3676ca', 'proposed_readiness_requires_new_source_review_and_explicit_runtime_go': True, 'published_to_host': False, 'runtime_requests_submitted': 0, 'live_request_generated': False, 'binding_only_functions_byte_equal': True, 'generic_fixed_file_byte_equal': True, 'files': [{'path': name, 'bytes': len(raw.encode()), 'sha256': sha(raw)} for name, raw in files.items()]}
    (root / 'review/offline-binding-proposal.public.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report))

if __name__ == '__main__':
    main()
