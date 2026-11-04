from pathlib import Path, PurePosixPath
import base64
import hashlib
import io
import json
import os
import stat
import sys
import tarfile

os.umask(0o077)
BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-blocker-closure-r1')
ROOT = BASE / 'root-reviewed-checkpoint-r7'
payload = json.load(sys.stdin)
transport = Path(sys.argv[1])
assert transport == BASE / 'root-reviewed-checkpoint-r7-transport-authbus-r1.tar.gz'
assert transport.parent.resolve(strict=True) == transport.parent
fd = os.open(transport, os.O_RDONLY | os.O_NOFOLLOW)
try:
    before = os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() == 501
    assert before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
    assert before.st_size == payload['archive_bytes'] == 658311
    chunks = []
    remaining = before.st_size
    while remaining:
        block = os.read(fd, min(65536, remaining))
        assert block, 'incomplete frozen transport'
        chunks.append(block)
        remaining -= len(block)
    assert os.read(fd, 1) == b''
    archive = b''.join(chunks)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                          s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert identity(before) == identity(os.fstat(fd)) == identity(transport.lstat())
finally:
    os.close(fd)
sha = lambda b: hashlib.sha256(b).hexdigest()
assert len(archive) == payload['archive_bytes'] and sha(archive) == payload['archive_sha256']
assert BASE.resolve(strict=True) == BASE and BASE.stat().st_uid == os.getuid() == 501
assert not ROOT.exists() and not ROOT.is_symlink(), 'fresh checkpoint required'
entries = {}
with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
    for member in tar.getmembers():
        path = PurePosixPath(member.name)
        assert member.isfile() and not path.is_absolute() and '..' not in path.parts
        assert path.parts and all(p not in ('', '.') for p in path.parts)
        assert member.name not in entries and member.size <= 2_000_000
        entries[member.name] = tar.extractfile(member).read()
manifest_raw = entries.pop('manifest.public.json')
assert sha(manifest_raw) == payload['manifest_sha256']
manifest = json.loads(manifest_raw)
assert set(entries) == {f['path'] for f in manifest['files']}
for item in manifest['files']:
    b = entries[item['path']]
    assert len(b) == item['bytes'] and sha(b) == item['sha256']
ROOT.mkdir(mode=0o700)
directories = {ROOT, BASE, BASE.parent}

def write(path, data):
    chain = []
    parent = path.parent
    while parent != ROOT:
        chain.append(parent)
        parent = parent.parent
    for directory in reversed(chain):
        if not directory.exists():
            directory.mkdir(mode=0o700)
        s = directory.lstat()
        assert stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid()
        directories.add(directory)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    assert sha(path.read_bytes()) == sha(data)

for name, data in entries.items():
    write(ROOT / name, data)
write(ROOT / 'manifest.public.json', manifest_raw)
write(ROOT / 'checkpoint.tar.gz', archive)
for directory in sorted(directories, key=lambda p: len(p.parts), reverse=True):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
receipt = {'schema': 'heptabao.root-reviewed-mac-checkpoint.v1', 'root': str(ROOT),
           'archive_bytes': len(archive), 'archive_sha256': sha(archive),
           'manifest_sha256': sha(manifest_raw), 'files': len(entries),
           'uncompressed_bytes': sum(len(b) for b in entries.values()),
           'directories_fsynced': [str(p) for p in sorted(directories)],
           'file_readback_verified': True, 'production_changed': False,
           'validation_commit': manifest['validation_commit'], 'qa_commit': manifest['qa_commit']}
raw = (json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode()
write(ROOT / 'checkpoint-receipt.public.json', raw)
for directory in [ROOT, BASE, BASE.parent]:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
print(json.dumps({'ok': True, 'receipt': str(ROOT / 'checkpoint-receipt.public.json'),
                  'receipt_sha256': sha(raw), 'archive_sha256': sha(archive),
                  'files': len(entries), 'directories_fsynced': len(directories)}, sort_keys=True))
