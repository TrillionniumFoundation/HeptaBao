import ast, hashlib, json, sys, time
started = time.monotonic()
payload = json.load(sys.stdin)
expected = {
    'launch_normal_r10_full128_r1.py',
    'launch_normal_r10_pocket_direct98_r1.py',
    'native_v6_pocket_source_direct98_r10_r1.py',
    'probe_normal_build_r10_r1.py',
}
assert set(payload) == expected
rows = []
for name in sorted(expected):
    item = payload[name]
    raw = item['source'].encode('ascii')
    assert len(raw) == item['bytes'] <= 20000
    assert hashlib.sha256(raw).hexdigest() == item['sha256']
    parsed = ast.parse(item['source'], filename=name)
    compile(parsed, name, 'exec', dont_inherit=True)
    rows.append({'name': name, 'bytes': len(raw), 'sha256': item['sha256'],
                 'ast_parsed': True, 'compiled_not_executed': True})
print(json.dumps({'schema': 'heptabao.r10-ha-controls-ast-only.v1',
                  'status': 'passed', 'files': rows, 'candidate_executed': False,
                  'file_writes': 0, 'child_processes': 0, 'network_calls': 0,
                  'elapsed_seconds': time.monotonic() - started}, sort_keys=True), flush=True)
