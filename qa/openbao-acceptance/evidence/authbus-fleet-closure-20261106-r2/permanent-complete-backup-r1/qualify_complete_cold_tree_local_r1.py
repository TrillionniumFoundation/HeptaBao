#!/usr/bin/env python3
"""Finite real-filesystem checks; not actual Mac/server/production evidence."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time

from complete_cold_tree_backup_r1 import CompleteColdCopy, BackupRefused

start = time.monotonic()
until = start + 30
rows = []
old_umask = os.umask(0o077)

def check():
    assert time.monotonic() < until

def fixture(parent, name):
    root = parent / name; root.mkdir(mode=0o700)
    (root / 'objects').mkdir(mode=0o700)
    (root / 'state.hbs').write_bytes(b'private-synthetic-encrypted-placeholder' * 31)
    (root / 'journal.hbj').write_bytes(b'')
    (root / 'objects' / 'entry.bin').write_bytes(b'\x07' * (2 * 1024 * 1024 + 19))
    (root / 'objects' / 'entry.bin').chmod(0o400)
    return root

def completed(name, operation):
    result = operation()
    rows.append({'case': name, 'passed': True, **result})

def refused(source, destination, *, expected=None, hook=check, error=None):
    run = CompleteColdCopy(source, destination, check=hook, expected_manifest=expected)
    try:
        run.run()
    except (BackupRefused, OSError) as caught:
        if error is not None:
            assert type(caught).__name__ == error
        assert run.result['ok'] is False and run.result['allDescriptorsClosedOnce']
        assert run.result['originalDirectoryLockReleased'] and run.result['destinationDirectoryLockReleased']
        return {'refused': True, 'explicitDescriptors': run.result['explicitDescriptors'],
                'allDescriptorsClosedOnce': True, 'errorClass': type(caught).__name__}
    raise AssertionError('unexpected copy success')

try:
    with tempfile.TemporaryDirectory(prefix='heptabao-cold-tree-local-') as tmp:
        parent = Path(tmp); source = fixture(parent, 'source')
        first = CompleteColdCopy(source, parent / 'backup', check=check)
        manifest = first.run()
        assert first.result['ok'] and manifest['completeFileCount'] == 3 and manifest['sourceFilesExcluded'] == 0
        assert {x['path'] for x in manifest['files']} == {'state.hbs', 'journal.hbj', 'objects/entry.bin'}
        for entry in manifest['files']:
            a, b = (source / entry['path']).read_bytes(), (parent / 'backup' / entry['path']).read_bytes()
            assert a == b and hashlib.sha256(b).hexdigest() == entry['sha256']
            assert (parent / 'backup' / entry['path']).stat().st_mode & 0o777 == entry['mode']
        completed('complete-nested-empty-readonly-and-multiblock-copy', lambda: first.result)
        second = CompleteColdCopy(parent / 'backup', parent / 'restore', check=check, expected_manifest=manifest)
        restored = second.run()
        assert second.result['ok'] and restored['files'] == manifest['files']
        completed('complete-manifest-bound-restore-copy', lambda: second.result)
        completed('existing-destination-refused-without-overwrite', lambda: refused(source, parent / 'backup', error='FileExistsError'))
        held = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            completed('independent-held-directory-lock-refused', lambda: refused(source, parent / 'busy', error='BlockingIOError'))
            assert not (parent / 'busy').exists()
        finally:
            os.close(held)
        linked = fixture(parent, 'linked'); os.link(linked / 'state.hbs', linked / 'extra.hbs')
        completed('hardlinked-source-refused', lambda: refused(linked, parent / 'hardlink-output', error='BackupRefused'))
        symbolic = fixture(parent, 'symbolic'); (symbolic / 'extra.hbs').symlink_to(symbolic / 'state.hbs')
        completed('symlinked-source-refused', lambda: refused(symbolic, parent / 'symlink-output', error='BackupRefused'))
        bad_manifest = copy.deepcopy(manifest); bad_manifest['files'][0]['sha256'] = '0' * 64
        completed('different-manifest-rejected-before-success', lambda: refused(source, parent / 'bad-manifest', expected=bad_manifest, error='BackupRefused'))
        changed = fixture(parent, 'changed'); target = parent / 'changed-copy'; injected = [False]
        def source_change():
            check()
            if (target / 'objects' / 'entry.bin').exists() and not injected[0]:
                injected[0] = True
                (changed / 'state.hbs').write_bytes(b'changed-by-fixture-outside-copy')
        completed('source-change-during-copy-refused', lambda: refused(changed, target, hook=source_change, error='BackupRefused'))
        assert injected[0]
        changed_target_source = fixture(parent, 'changed-target-source'); changed_target = parent / 'changed-target'; tampered = [False]
        def target_change():
            check()
            file = changed_target / 'journal.hbj'
            later = changed_target / 'objects' / 'entry.bin'
            if file.exists() and later.exists() and not tampered[0]:
                tampered[0] = True
                file.write_bytes(b'changed-destination-after-readback')
        completed('destination-change-after-readback-refused', lambda: refused(changed_target_source, changed_target, hook=target_change, error='BackupRefused'))
        assert tampered[0]
    print(json.dumps({'schema': 'heptabao.complete-cold-tree-local-qualification.r1',
        'passed': len(rows), 'total': 9, 'cases': rows, 'actualServerWriterLockInteroperability': False,
        'actualMacFilesystem': False, 'productionBackupOrRestoreQualified': False,
        'syntheticLocalFilesOnly': True, 'elapsedSeconds': time.monotonic() - start}, sort_keys=True))
    assert len(rows) == 9
finally:
    os.umask(old_umask)
