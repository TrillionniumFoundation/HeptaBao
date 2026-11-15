#!/usr/bin/env python3
"""Keep failed initial business cycles from registering a running poller."""
from pathlib import Path
import difflib
import hashlib
import json
import shutil

WORK = Path(__file__).resolve().parent
SOURCE = WORK / 'production-plugin-r1'
TARGET = WORK / 'production-plugin-r2'
PINS = {'mac-rog': '31b2f098547880484e7c3b254540863f6c6488b7dff122276911874d04e40b54',
        'pocket4': '6326a8342634c8a61a4d57e1b862ae5bce4d24939a4a1f4f9095ba119b40e30f'}

def once(text, old, new):
    assert text.count(old) == 1, old[:80]
    return text.replace(old, new, 1)

TARGET.mkdir(exist_ok=False)
manifest = {'schema': 'heptabao.production-plugin-integration-source.r2', 'installed': False,
            'actualTlsOrSdkQualified': False, 'change': 'Initial cycle failure propagates through original stop/close path.',
            'periodicCycleFailurePolicyUnchanged': True, 'variants': {}}
for variant, expected in PINS.items():
    source, target = SOURCE / variant, TARGET / variant
    raw = (source / 'index.js').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    original = raw.decode()
    changed = once(original, '    async function cycle(ctx) {',
                   '    async function cycle(ctx, { propagateFailure = false } = {}) {')
    changed = once(changed, '          await cycle(ctx);',
                   '          await cycle(ctx, { propagateFailure: true });')
    changed = once(changed,
        '          error: error instanceof Error ? error.message : String(error),\n        });\n      } finally {\n        running = false;',
        '          error: error instanceof Error ? error.message : String(error),\n        });\n'
        '        if (propagateFailure) throw error;\n      } finally {\n        running = false;')
    shutil.copytree(source, target)
    (target / 'index.js').write_text(changed)
    package = json.loads((target / 'package.json').read_text())
    assert package['version'].endswith('-heptabao.1')
    package['version'] = package['version'][:-1] + '2'
    (target / 'package.json').write_text(json.dumps(package, indent=2) + '\n')
    delta = []
    for name in ('index.js', 'package.json'):
        delta.extend(difflib.unified_diff((source / name).read_text().splitlines(True),
                     (target / name).read_text().splitlines(True),
                     fromfile=variant + '/r1/' + name, tofile=variant + '/r2/' + name))
    (TARGET / (variant + '.diff')).write_text(''.join(delta))
    manifest['variants'][variant] = {'parentIndexSha256': expected,
        'preparedFiles': {str(p.relative_to(target)): {'bytes': len(p.read_bytes()),
            'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(target.rglob('*')) if p.is_file()}}
(TARGET / 'manifest.public.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
print(json.dumps({'ok': True, 'preparedVariants': 2, 'installed': False}))
