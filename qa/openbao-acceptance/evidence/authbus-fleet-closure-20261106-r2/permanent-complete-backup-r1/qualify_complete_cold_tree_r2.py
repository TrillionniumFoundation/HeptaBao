#!/usr/bin/env python3
"""Exercise the new executable admission on real isolated local files."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from complete_cold_tree_backup_r2 import CompleteColdCopy, BackupRefused

start = time.monotonic()
os.umask(0o077)
def check():
    assert time.monotonic() < start + 30
rows = []
with tempfile.TemporaryDirectory(prefix='heptabao-full-runtime-copy-') as tmp:
    root = Path(tmp)
    source = root / 'runtime'; source.mkdir(mode=0o700)
    (source / 'server').write_bytes(b'public-synthetic-executable' * 913)
    (source / 'server').chmod(0o500)
    (source / 'state').write_bytes(b'private-synthetic-placeholder')
    pin = {'server': ((source / 'server').stat().st_size,
                      hashlib.sha256((source / 'server').read_bytes()).hexdigest())}
    for name, pins, success in (
        ('explicit-public-executable-copied-and-mode-preserved', pin, True),
        ('executable-without-exact-path-authority-denied', {}, False),
        ('wrong-whole-executable-pin-denied', {'server': (pin['server'][0], '0' * 64)}, False),
        ('missing-explicit-public-executable-denied', {'missing': pin['server']}, False),
    ):
        copier = CompleteColdCopy(source, root / name, check=check, public_executables=pins)
        try:
            manifest = copier.run()
            assert success and copier.result['ok']
            assert (root / name / 'server').stat().st_mode & 0o777 == 0o500
            restore = CompleteColdCopy(root / name, root / 'restored', check=check,
                                       public_executables=pin, expected_manifest=manifest)
            assert restore.run()['files'] == manifest['files'] and restore.result['ok']
        except BackupRefused:
            assert not success and not copier.result['ok']
        assert copier.result['allDescriptorsClosedOnce']
        rows.append({'case': name, 'passed': True})
print(json.dumps({'schema': 'heptabao.complete-runtime-copy-public-executable-local.r2',
    'passed': len(rows), 'required': 4, 'cases': rows,
    'actualMacOrServerExecution': False, 'networkOrServiceActions': 0}, sort_keys=True))
