#!/usr/bin/env python3
"""Assemble immutable public Python input pins; no remote action."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent / 'HeptaBao-current-924b'
COMMIT = 'af91ec0cecbb1c0bd717095d6d8696a3f73a1cee'
records = subprocess.check_output(['git', 'ls-tree', '-rz', COMMIT], cwd=REPO)
selected = []
for record in records.split(b'\0'):
    if not record:
        continue
    header, path = record.split(b'\t', 1)
    name = path.decode('utf-8')
    if name.endswith('.py') and (name.startswith('qa/') or name.startswith('tools/')) and '/evidence/' not in name:
        mode, kind, sha = header.decode().split()
        assert kind == 'blob' and mode in ('100644', '100755')
        selected.append((name, sha))
assert len(selected) == 613
child = subprocess.Popen(['git', 'cat-file', '--batch'], cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
raw, error = child.communicate(('\n'.join(sha for _, sha in selected) + '\n').encode(), timeout=30)
assert child.returncode == 0 and not error
pins = {}
offset = 0
for name, expected in selected:
    end = raw.index(b'\n', offset)
    sha, kind, size = raw[offset:end].decode().split()
    assert sha == expected and kind == 'blob'
    size = int(size)
    start = end + 1
    data = raw[start:start + size]
    assert len(data) == size and raw[start + size:start + size + 1] == b'\n'
    offset = start + size + 1
    pins[name] = {'bytes': size, 'sha256': hashlib.sha256(data).hexdigest()}
assert offset == len(raw)
body = (ROOT / 'launch_ha128_current_r1.body.py').read_text()
marker = 'PINS = {}  # ASSEMBLED_AF91_PYTHON_PINS'
assert body.count(marker) == 1
source = body.replace(marker, 'PINS = ' + repr(pins))
compile(source, 'launch_ha128_current_r1.py', 'exec')
(ROOT / 'launch_ha128_current_r1.py').write_text(source)
(ROOT / 'source-pins.public.json').write_text(json.dumps({'sourceCommit': COMMIT, 'pins': pins}, sort_keys=True, indent=2) + '\n')
print(json.dumps({'launcherBytes': len(source.encode()), 'launcherSha256': hashlib.sha256(source.encode()).hexdigest(), 'dependencies': len(pins)}, sort_keys=True))
