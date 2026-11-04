from pathlib import Path, PurePosixPath
import base64, hashlib, io, json, os, stat, subprocess, sys, tarfile
os.umask(0o077)
BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
FROZEN = BASE / 'continuation-20261104-ha-root-pull-response-r1/source'
ROOT = BASE / 'continuation-20261104-native-ssh-http-r7'
SOURCE, CONTROL = ROOT / 'source', ROOT / 'control'
BASE_COMMIT = '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
BASE_TREE = 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
ROG_COMMIT = 'dc1c02dbd4803f4301097a8268d121e5d7f27464'
TREE = '97d4e782ffa1f2e5d4e116747c34d8c9fb5390d8'
ARCHIVE_SHA = '4f38d2b8b1e3e899ff8063138706369a57ad16088d017ded26993c756b366cd4'
MANIFEST_SHA = 'cba2f8a95d4781e33ce157feb49aa0ed15bae1941892639306996a8ed3067b9c'
PINS = {
    'builder': ('build_normal.py', '026aa2ab4a1af663424ae2d0dcc678a48c4f3b9ba0429574f4bb60345a83dea2'),
    'runner': ('mac_normal_exact_tests.py', 'eb6f53b842f79d221e78b79628690df6db37002284c0ca4a400b18eac817b728'),
    'groups': ('normal-test-groups.public.json', '3c6415b0584ef2add08694133e99937bf20f74fcc1c1825f9667d0a07f8aa83b'),
}
def sha(b): return hashlib.sha256(b).hexdigest()
def git(root, *args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(root), *args], stderr=subprocess.PIPE, timeout=90)
def freeze():
    return {'commit': git(FROZEN, 'rev-parse', 'HEAD').decode().strip(),
            'tree': git(FROZEN, 'rev-parse', 'HEAD^{tree}').decode().strip(),
            'status': git(FROZEN, 'status', '--porcelain').decode()}
def write(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
def js(path, value): write(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())
payload_path = BASE / 'continuation-20261104-native-ssh-http-r7-stage-payload.json'
assert BASE.resolve(strict=True) == BASE and BASE.stat().st_uid == os.getuid() == 501
assert payload_path.resolve(strict=True) == payload_path
fd = os.open(payload_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    before_payload = os.fstat(fd)
    assert stat.S_ISREG(before_payload.st_mode) and before_payload.st_uid == 501
    assert before_payload.st_nlink == 1 and stat.S_IMODE(before_payload.st_mode) & 0o077 == 0
    assert before_payload.st_size == 513735
    raw_payload = bytearray()
    while len(raw_payload) <= 513735:
        part = os.read(fd, min(65536, 513736 - len(raw_payload)))
        if not part: break
        raw_payload.extend(part)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert identity(before_payload) == identity(os.fstat(fd)) == identity(payload_path.lstat())
    assert len(raw_payload) == 513735 and sha(raw_payload) == '4cbdf6cfc0a8690edbf5b5a0726346f5a2eb7a5865c8f77e7c7d2010a9abc1b1'
    payload = json.loads(raw_payload)
finally:
    os.close(fd)
assert set(payload) == {'archive', *PINS}
archive = base64.b64decode(payload['archive'], validate=True)
assert len(archive) == 364472 and sha(archive) == ARCHIVE_SHA
small = {k: base64.b64decode(payload[k], validate=True) for k in PINS}
for key, (_, pin) in PINS.items(): assert sha(small[key]) == pin
assert os.uname().sysname == 'Darwin' and os.uname().machine == 'arm64'
assert BASE.resolve(strict=True) == BASE and BASE.stat().st_uid == os.getuid() == 501
assert not ROOT.exists() and not ROOT.is_symlink()
before = freeze(); assert before == {'commit': BASE_COMMIT, 'tree': BASE_TREE, 'status': ''}
entries = {}
with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as t:
    for member in t.getmembers():
        name = PurePosixPath(member.name)
        assert member.isfile() and not name.is_absolute() and '..' not in name.parts
        assert member.name not in entries and member.size <= 1000000
        entries[member.name] = t.extractfile(member).read()
raw = entries['manifest.public.json']; assert sha(raw) == MANIFEST_SHA
m = json.loads(raw)
assert (m['base_commit'], m['base_tree'], m['commit'], m['tree']) == (BASE_COMMIT, BASE_TREE, ROG_COMMIT, TREE)
assert len(m['files']) == 24 and len({x['path'] for x in m['files']}) == 24
assert set(entries) == {'manifest.public.json', 'source.patch', 'r6-to-r7-formatted.diff'} | {'files/' + x['path'] for x in m['files']}
patch = entries['source.patch']; assert sha(patch) == m['patch_sha256']
assert sha(entries['r6-to-r7-formatted.diff']) == m['delta_sha256']
for x in m['files']:
    path = PurePosixPath(x['path']); assert not path.is_absolute() and '..' not in path.parts
    b = entries['files/' + x['path']]
    assert len(b) == x['bytes'] and sha(b) == x['sha256']
    assert hashlib.sha1(b'blob ' + str(len(b)).encode() + b'\0' + b).hexdigest() == x['git_blob']
groups = json.loads(small['groups'])
assert [len(g['tests']) for g in groups] == [25, 1, 5]
assert len({n for g in groups for n in g['tests']}) == 31
ROOT.mkdir(mode=0o700); CONTROL.mkdir(mode=0o700)
js(CONTROL / 'stage-intent.public.json', {'schema': 'heptabao.combined-r7-mac-source-stage-intent.v1',
    'archive_sha256': ARCHIVE_SHA, 'manifest_sha256': MANIFEST_SHA, 'before': before,
    'target': str(SOURCE), 'expected_tree': TREE, 'production_changed': False})
write(CONTROL / 'ssh-http-r7-source-mirror.tar.gz', archive)
write(CONTROL / 'source.patch', patch); write(CONTROL / 'manifest.public.json', raw)
write(CONTROL / 'r6-to-r7-formatted.diff', entries['r6-to-r7-formatted.diff'])
for key, (name, _) in PINS.items(): write(CONTROL / name, small[key])
git(FROZEN, 'worktree', 'add', '--detach', str(SOURCE), BASE_COMMIT)
git(SOURCE, 'apply', '--check', str(CONTROL / 'source.patch'))
git(SOURCE, 'apply', '--index', str(CONTROL / 'source.patch'))
assert git(SOURCE, 'write-tree').decode().strip() == TREE
for x in m['files']: assert sha((SOURCE / x['path']).read_bytes()) == x['sha256']
git(SOURCE, '-c', 'user.name=Codex', '-c', 'user.email=codex@local.invalid', 'commit', '-m',
    'Prepare combined SSH explicit reply and complete HTTP redirect candidate r7')
commit = git(SOURCE, 'rev-parse', 'HEAD').decode().strip()
assert git(SOURCE, 'rev-parse', 'HEAD^{tree}').decode().strip() == TREE and not git(SOURCE, 'status', '--porcelain')
assert freeze() == before
receipt = {'schema': 'heptabao.combined-r7-mac-source-stage-result.v1', 'ok': True,
    'root': str(ROOT), 'source': str(SOURCE), 'physical_mac_commit': commit,
    'physical_rog_commit': ROG_COMMIT, 'source_tree': TREE, 'exact_tree_equal': True,
    'source_clean': True, 'archive_sha256': ARCHIVE_SHA, 'manifest_sha256': MANIFEST_SHA,
    'patch_sha256': m['patch_sha256'], 'control_pins': {k: p for k, (_, p) in PINS.items()},
    'files': m['files'], 'old_source_before': before, 'old_source_after': freeze(),
    'git_common_directory': git(SOURCE, 'rev-parse', '--git-common-dir').decode().strip(),
    'shared_common_git_directory_dependency': True, 'server_started': False, 'production_changed': False}
js(CONTROL / 'stage-result.public.json', receipt)
for p in [CONTROL, ROOT, BASE]:
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
print(json.dumps({'ok': True, 'receipt': str(CONTROL / 'stage-result.public.json'),
    'receipt_sha256': sha((CONTROL / 'stage-result.public.json').read_bytes()),
    'physical_mac_commit': commit, 'source_tree': TREE, 'source_clean': True,
    'server_started': False}, sort_keys=True))
