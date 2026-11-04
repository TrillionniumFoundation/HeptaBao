#!/usr/bin/env python3
"""Correct the unstarted node/data draft to the native Raft node/state contract.

Preserves original configuration, Mac binding and plist as immutable evidence.
Refuses initialized data, activation material, unknown input versions and reruns.
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import socket
import stat
import subprocess
import sys

MAC = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1')
MAC_STAGE = '50347e3e23e2721381fed5f4627a80facea10a5e644a333bae8d88e88c1659dc'
MAC_PLIST = '189d43c22dc321b7613769fd4b288c43aaa545f2c20b6c5ff8c5a5cada7f85d4'
LINUX = {
    'qian-qi-ROG-Flow-Z13-GZ302EA-GZ302EA': ('rog', '/home/qian-qi', '9932d1e739e57926346ed76a1336b9417101e80179020cc6949613062019e507'),
    'alex-G1628-04': ('pocket4', '/home/alex', '94e9afcaabb762a2f0b2cdcb610d5390e0efe9be8a97a0f59fab926c926cdc66'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(obj):
    return (json.dumps(obj, sort_keys=True, indent=2) + '\n').encode()


def read(path, mode=0o600):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        assert stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid()
        assert st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == mode and st.st_size < 262144
        raw = os.read(fd, st.st_size + 1)
        end = os.fstat(fd)
        assert (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) == (
            end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns, end.st_ctime_ns)
        assert len(raw) == st.st_size
        return raw
    finally:
        os.close(fd)


def put(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    sync(path.parent)


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def replace(path, before, after, mode=0o600):
    assert read(path, mode) == before
    put(path.with_name(path.name + '.r1-preserved'), before, mode)
    tmp = path.with_name(path.name + '.r2-prepared')
    put(tmp, after, mode)
    assert read(path, mode) == before
    os.replace(tmp, path)
    sync(path.parent)
    assert read(path, mode) == after


def main():
    os.umask(0o077)
    name = socket.gethostname()
    is_mac = sys.platform == 'darwin'
    stage = stage_raw = plist_raw = None
    if is_mac:
        assert os.getuid() == 501 and name == 'MacBook-Pro.local'
        root, node = MAC, 'mac'
        stage_raw = read(root / 'control/stage.private.json')
        assert sha(stage_raw) == MAC_STAGE
        stage = json.loads(stage_raw)
        expected_server = stage['files']['config/server.json']['sha256']
        plist_raw = read(root / 'service/org.heptabao.node.plist')
        assert sha(plist_raw) == MAC_PLIST
    else:
        assert sys.platform == 'linux' and os.getuid() == 1000
        node, home, expected_server = LINUX[name]
        assert Path.home() == Path(home)
        root = Path(home) / 'heptabao-production-20261104-r1'
    assert not (root / 'state-path-correction.public.json').exists()
    for f in ['control/activation.private.json', 'control/activation.sha256']:
        assert not (root / f).exists()
    for directory in [root, root / 'node', root / 'node/data', root / 'node/raft']:
        s = directory.lstat()
        assert stat.S_ISDIR(s.st_mode) and not directory.is_symlink()
        assert s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700
    assert not list((root / 'node/data').iterdir()) and not list((root / 'node/raft').iterdir())
    server_path = root / 'config/server.json'
    before = read(server_path)
    assert sha(before) == expected_server
    server = json.loads(before)
    assert server['data_dir'] == str(root / 'node/data')
    native = server['storage']['native_v6_raft']
    assert native['path'] == str(root / 'node') and native['node_id'] == node
    (root / 'node/state').mkdir(mode=0o700)
    sync(root / 'node')
    server['data_dir'] = str(root / 'node/state')
    after = encode(server)
    # Validate the actual condition in normal33 validate_storage_runtime.
    assert Path(server['data_dir']) == Path(native['path']) / 'state'
    replace(server_path, before, after)
    result = {'schema': 'heptabao.staged-state-path-correction.v1', 'ok': False,
              'root': str(root), 'node': node, 'source_commit': '33cafa4c6e29f0bde1553e041550d21b4c725d9c',
              'reason': 'Native Raft requires data_dir == storage.path/state; initial draft used node/data.',
              'server_config_sha256_before': sha(before), 'server_config_sha256_after': sha(after),
              'old_config_preserved': True, 'old_empty_directory_retained': True,
              'initialized_data_present': False, 'service_started': False,
              'production_client_changed': False, 'traffic_cutover': False}
    if is_mac:
        guard_path = root / 'release/heptabao_mac_node_start.py'
        guard_before = read(guard_path, 0o500)
        guard_pin = stage['files']['release/heptabao_mac_node_start.py']['sha256']
        assert sha(guard_before) == guard_pin
        assert guard_before.count(b"'node/data'") == 1
        guard_after = guard_before.replace(b"'node/data'", b"'node/state'")
        compile(guard_after, str(guard_path), 'exec')
        replace(guard_path, guard_before, guard_after, 0o500)
        stage['files']['config/server.json']['sha256'] = sha(after)
        stage['files']['release/heptabao_mac_node_start.py']['sha256'] = sha(guard_after)
        stage_after = encode(stage)
        replace(root / 'control/stage.private.json', stage_raw, stage_after)
        plist = plistlib.loads(plist_raw)
        argv = plist['ProgramArguments']
        assert argv[-1] == MAC_STAGE and argv[8] == 'serve' and argv[7] == guard_pin
        argv[-1] = sha(stage_after)
        argv[7] = sha(guard_after)
        plist_after = plistlib.dumps(plist, sort_keys=True)
        replace(root / 'service/org.heptabao.node.plist', plist_raw, plist_after)
        lint = subprocess.run(['/usr/bin/plutil', '-lint', str(root / 'service/org.heptabao.node.plist')],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        assert lint.returncode == 0
        check = list(argv)
        check[8] = 'check-stage'
        # Execute the actual plist bootstrap in its read-only check mode. The
        # repaired guard now checks the real node/state directory at each start.
        checked = subprocess.run(check, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=30)
        assert checked.returncode == 0
        value = json.loads(checked.stdout)
        assert value['stage_verified'] is True and value['service_started'] is False
        result.update(stage_binding_sha256_before=MAC_STAGE, stage_binding_sha256_after=sha(stage_after),
                      plist_sha256_before=MAC_PLIST, plist_sha256_after=sha(plist_after),
                      guard_sha256_before=guard_pin, guard_sha256_after=sha(guard_after),
                      actual_plist_lint_and_guard_check=True)
    result['ok'] = True
    raw = encode(result)
    put(root / 'state-path-correction.public.json', raw)
    print(json.dumps({'ok': True, 'node': node, 'receipt_sha256': sha(raw),
                      'server_config_sha256_after': sha(after), 'service_started': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'ok': False, 'error_type': type(exc).__name__, 'service_started': False,
                          'automatic_retry': False, 'inspect_preserved_files_before_next_action': True}))
        raise SystemExit(2)
