from pathlib import Path
import ast
import hashlib
import json
import sys

root = Path(__file__).resolve().parent
isolation = root / 'python_guard_isolation'
entries = json.loads((root / 'fixed-tree.json').read_text())['tree']
expected = {x['path']: x['sha'] for x in entries if x['type'] == 'blob'}
manifest = json.loads((root / 'candidate-file-manifest.json').read_text())
expected.update({x['path']: x['git_blob'] for x in manifest['files']})
modules = {}
for path in expected:
    for prefix in ('qa/openbao-acceptance/', 'qa/single-node/', 'clients/python/'):
        if path.startswith(prefix) and path.endswith('.py'):
            module = path[len(prefix):-3].replace('/', '.')
            if module.endswith('.__init__'):
                module = module[:-9]
            modules[module] = path
missing = set()
unknown = set()
rows = []
for path in sorted(isolation.rglob('*.py')):
    relative = path.relative_to(isolation).as_posix()
    raw = path.read_bytes()
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    assert expected.get(relative) == blob, (relative, expected.get(relative), blob)
    rows.append({'path': relative, 'git_blob': blob, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    current = next(name for name, item in modules.items() if item == relative)
    package = current if relative.endswith('/__init__.py') else current.rpartition('.')[0]
    def consider(name):
        if name in modules:
            dependency = modules[name]
            if not (isolation / dependency).exists():
                missing.add(dependency)
            parts = name.split('.')
            for index in range(1, len(parts)):
                parent = '.'.join(parts[:index])
                if parent in modules and not (isolation / modules[parent]).exists():
                    missing.add(modules[parent])
        elif name.split('.')[0] not in sys.stdlib_module_names:
            unknown.add(name)
    for node in ast.walk(ast.parse(raw, filename=relative)):
        if isinstance(node, ast.Import):
            for item in node.names:
                consider(item.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split('.') if package else []
                parts = parts[:len(parts) - node.level + 1]
                if node.module:
                    parts.extend(node.module.split('.'))
                name = '.'.join(parts)
            else:
                name = node.module or ''
            if name:
                consider(name)
                for item in node.names:
                    candidate = name + '.' + item.name
                    if candidate in modules:
                        consider(candidate)
result = {'source_commit': '0e3237fe287553c49e14109ddfbdf33b674e8a64', 'files': rows, 'missing_fixed_dependencies': sorted(missing), 'unresolved_nonstdlib_import_names': sorted(unknown), 'module_imported': False, 'tests_executed': False}
(isolation / 'dependency-scan.public.json').write_text(json.dumps(result, indent=2) + '\n')
(isolation / 'dependency-pending.json').write_text(json.dumps(sorted(missing), indent=2) + '\n')
print(json.dumps({key: value for key, value in result.items() if key != 'files'}, indent=2))
print('Verified source dependency files:', len(rows))
