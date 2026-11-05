#!/usr/bin/env python3
"""Offline verification; never extract, execute or access a remote host."""
import hashlib, io, json, tarfile
from pathlib import Path

here = Path(__file__).resolve().parent
manifest = json.loads((here / 'manifest.public.json').read_bytes())
raw = (here / manifest['archive']).read_bytes()
assert len(raw) == manifest['bytes']
assert hashlib.sha256(raw).hexdigest() == manifest['sha256']
expected = {row['path']: row for row in manifest['files']}
assert len(expected) == len(manifest['files'])
with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
    members = archive.getmembers()
    assert len(members) == len(expected) and {m.name for m in members} == set(expected)
    for member in members:
        assert member.isfile() and not member.name.startswith('/') and '..' not in Path(member.name).parts
        data = archive.extractfile(member).read()
        row = expected[member.name]
        assert member.size == row['bytes'] == len(data)
        assert hashlib.sha256(data).hexdigest() == row['sha256']
print(json.dumps({'status': 'exact_archive_and_all_members_verified', 'members': len(expected),
                  'original_evidence_complete': manifest['original_evidence_complete'],
                  'replacement_qualified': False}, sort_keys=True))
