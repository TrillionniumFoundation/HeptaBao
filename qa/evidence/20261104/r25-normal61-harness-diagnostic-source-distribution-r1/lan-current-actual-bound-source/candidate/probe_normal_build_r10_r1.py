"""Read-only build/source provenance probe; no target binary is executed."""
from pathlib import Path
import base64
import hashlib
import json
import os
import stat
import subprocess
import sys

cfg = json.load(sys.stdin)
source = Path(cfg['source'])
build = Path(cfg['build'])


def git(*args):
    p = subprocess.run(['git', '-C', str(source), *args], capture_output=True, timeout=45)
    assert p.returncode == 0
    return p.stdout.decode().strip()


def identity(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_uid, stat.S_IMODE(s.st_mode),
            s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)


def fresh(relative, maximum, mode, keep=False):
    path = build / relative
    assert path.resolve(strict=True) == path
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        assert before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == mode
        assert 0 < before.st_size <= maximum
        h, blocks = hashlib.sha256(), []
        count = 0
        while block := f.read(1024 * 1024):
            h.update(block); count += len(block)
            assert count <= maximum
            if keep:
                blocks.append(block)
        after, named = os.fstat(f.fileno()), path.stat(follow_symlinks=False)
        assert identity(before) == identity(after) == identity(named)
        assert count == before.st_size
    return {'path': str(path), 'bytes': count, 'sha256': h.hexdigest(),
            'identity': list(identity(before))}, b''.join(blocks)


assert source.resolve(strict=True) == source
assert git('rev-parse', 'HEAD') == cfg['commit']
assert git('rev-parse', 'HEAD^{tree}') == cfg['tree']
assert git('status', '--porcelain') == ''
files, raw = {}, {}
for relative, maximum, mode, keep in [
    ('native-build.public.json', 65536, 0o600, True),
    ('normal-release-result.public.json', 65536, 0o600, True),
    ('normal-release-build.stdout', 32 * 1024 * 1024, 0o600, True),
    ('artifacts/heptabao-server', 160 * 1024 * 1024, 0o500, False),
    ('artifacts/heptabao-seed', 160 * 1024 * 1024, 0o500, False),
]:
    files[relative], raw[relative] = fresh(relative, maximum, mode, keep)
    assert files[relative]['sha256'] == cfg['files'][relative]
native = json.loads(raw['native-build.public.json'])
result = json.loads(raw['normal-release-result.public.json'])
normal = ['default', 'native-v6-ha', 'native-v6-storage']
assert native['schema'] == 'heptabao.native-build.v1'
assert result['schema'] == 'heptabao.native-default-build-result.v1'
for v in (native, result):
    assert v['source_commit'] == cfg['commit'] and v['source_tree'] == cfg['tree']
    assert v['native_abi'] == cfg['abi'] and v['source_freeze_verified'] is True
    assert type(v['build_exit_code']) is int and v['build_exit_code'] == 0
assert native['binary_sha256'] == files['artifacts/heptabao-server']['sha256']
assert sorted(native['features']) == normal
assert native['provenance']['result_path'] == str(build / 'normal-release-result.public.json')
assert native['provenance']['result_sha256'] == files['normal-release-result.public.json']['sha256']
assert native['provenance']['cargo_events_sha256'] == files['normal-release-build.stdout']['sha256']
assert result['cargo_events_sha256'] == files['normal-release-build.stdout']['sha256']
assert result['normal_default_candidate'] is True and result['build_finished_success'] is True
assert result['timed_out'] is False and result['owned_group_survivors_after_wait'] is False
assert isinstance(cfg['cargo'], str) and Path(cfg['cargo']).is_absolute()
assert Path(cfg['cargo']).name == 'cargo'
assert result['command'] == [cfg['cargo'], 'build', '--release', '--locked', '--offline',
    '-p', 'heptabao-server', '--bin', 'heptabao-server', '--bin', 'heptabao-seed',
    '--message-format=json-render-diagnostics']
assert result['build_driver_sha256'] == cfg['build_driver_sha256']
assert result['requested_release_profile'] == {
    'CARGO_PROFILE_RELEASE_OPT_LEVEL': '3',
    'CARGO_PROFILE_RELEASE_CODEGEN_UNITS': '16',
    'CARGO_PROFILE_RELEASE_LTO': 'false',
    'CARGO_PROFILE_RELEASE_DEBUG': '0',
    'CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS': 'true',
    'CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS': 'true',
    'CARGO_PROFILE_RELEASE_PANIC': 'unwind',
}
assert set(result['artifacts']) == {'heptabao-server', 'heptabao-seed'}
for name, artifact in result['artifacts'].items():
    assert artifact['path'] == str(build / 'artifacts' / name)
    assert artifact['sha256'] == files['artifacts/' + name]['sha256']
    assert artifact['bytes'] == files['artifacts/' + name]['bytes']
    assert sorted(artifact['features']) == normal
    p = artifact['profile']
    assert str(p['opt_level']) == '3' and p['debug_assertions'] is True
    assert p['overflow_checks'] is True and p['test'] is False
events = [json.loads(line) for line in raw['normal-release-build.stdout'].splitlines() if line.strip()]
assert any(e.get('reason') == 'build-finished' and e.get('success') is True for e in events)
project_features = []
for event in events:
    if event.get('reason') != 'compiler-artifact' or 'heptabao-' not in event.get('package_id', ''):
        continue
    features = sorted(event.get('features', []))
    assert not any(x.startswith('private-') or x.startswith('experimental') for x in features)
    project_features.append({'target': event['target']['name'], 'features': features})
for name in ('heptabao-server', 'heptabao-seed'):
    assert any(row['target'] == name and row['features'] == normal for row in project_features)
for name in ('heptabao_raft_runtime', 'heptabao_ha_service'):
    assert any(row['target'] == name for row in project_features)
assert git('rev-parse', 'HEAD') == cfg['commit']
assert git('rev-parse', 'HEAD^{tree}') == cfg['tree'] and git('status', '--porcelain') == ''
print(json.dumps({'schema': 'heptabao.normal-r10-build-fresh-probe.v1',
    'source': str(source), 'source_commit': cfg['commit'], 'source_tree': cfg['tree'],
    'source_clean': True, 'files': files, 'normal_project_features': project_features,
    'private_diagnostic_feature_enabled': False, 'target_executed': False,
    'native_raw_base64': base64.b64encode(raw['native-build.public.json']).decode(),
    'result_raw_base64': base64.b64encode(raw['normal-release-result.public.json']).decode()}, sort_keys=True))
