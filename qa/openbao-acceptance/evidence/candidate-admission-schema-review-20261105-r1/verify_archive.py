#!/usr/bin/env python3
"""Offline exact-byte archive verification. No extraction or product execution."""
import ast, hashlib, io, json, tarfile
from pathlib import Path

here = Path(__file__).resolve().parent
receipt = json.loads((here / 'result.public.json').read_bytes())
raw = (here / 'draft-admission-and-recovery-schema-review.tar.gz').read_bytes()
assert len(raw) == receipt['archive']['bytes']
assert hashlib.sha256(raw).hexdigest() == receipt['archive']['sha256']
manifest_raw = (here / 'MANIFEST.public.json').read_bytes()
assert hashlib.sha256(manifest_raw).hexdigest() == receipt['manifest']['sha256']
manifest = json.loads(manifest_raw)
expected = {row['archive_path']: row for row in manifest['members']}
assert len(expected) == manifest['member_count'] == 51
closed = []
with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
    members = archive.getmembers()
    assert len(members) == 52 and {x.name for x in members} == set(expected) | {'MANIFEST.public.json'}
    for member in members:
        assert member.isfile() and not member.name.startswith('/') and '..' not in Path(member.name).parts
        data = archive.extractfile(member).read()
        if member.name == 'MANIFEST.public.json':
            assert data == manifest_raw
            continue
        row = expected[member.name]
        assert len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256']
        if member.name.endswith('.py'):
            values = [node.value.value for node in ast.parse(data).body
                      if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                      and any(isinstance(target, ast.Name) and target.id == 'DRAFT_ONLY' for target in node.targets)]
            if values:
                assert values == [True]
                closed.append(member.name)
assert len(closed) == 4
print(json.dumps({'status': 'exact_bytes_verified', 'original_members': 51, 'tar_members': 52,
                  'draft_entries_closed': 4, 'actual_thirteen_origin_positive_admission': False,
                  'formal_recovery_25_executions': 0, 'replacement_qualified': False}, sort_keys=True))
