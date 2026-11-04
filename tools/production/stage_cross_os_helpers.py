#!/usr/bin/env python3
"""Create only the fixed public helper files for the Mac-to-ROG seed proof."""
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys

os.umask(0o077)
packet = json.loads(sys.stdin.buffer.read(131073))
nodes = {
    'mac': ('MacBook-Pro.local', 501,
        '/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1',
        '3c76be847908ecc9e96263822a5ae2852c0b674216c17bbdeb5d5d1d37fca2fc',
        'heptabao_mac_node_start.py', {'verify_seed_cross_os_61ff_r2.py':
            '3357566596695c88e06fde82aab7b9ce09eb635b49c571cb17590c986bf104e8'}),
    'rog': ('qian-qi-ROG-Flow-Z13-GZ302EA-GZ302EA', 1000,
        '/home/qian-qi/heptabao-production-20261104-r1',
        'd7620ba81d28e39985980f0211086be6b5b18105a8c6bd39bff787e157940b53',
        'heptabao_linux_node_start.py', {
            'recover_seed_linux_61ff_r2.py': '908e477fbd2470b2f7824caee35841a508b4c4a5d3afc66c495cacc9a7264a65',
            'recover_seed_transport_61ff_b7_r2.py': 'b7b14b6fcbf767d76873b215ce10119fe58beb50ec3fbd164b4925ceb188cfea'}),
}
assert set(packet) == {'node', 'files'} and packet['node'] in nodes
hostname, uid, root_text, stage_sha, guard, pins = nodes[packet['node']]
root = Path(root_text)
assert socket.gethostname() == hostname and os.getuid() == uid
assert set(packet['files']) == set(pins)
for path in (root, root / 'control', root / 'release'):
    info = path.lstat()
    assert stat.S_ISDIR(info.st_mode) and not path.is_symlink()
    assert info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700
raw = (root / 'control/stage.private.json').read_bytes()
assert hashlib.sha256(raw).hexdigest() == stage_sha
binding = json.loads(raw)
assert binding['source_commit'] == '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
assert binding['source_tree'] == 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
checked = subprocess.run([sys.executable, '-I', '-S', '-B', str(root / 'release' / guard),
    'check-stage', '--stage', str(root / 'control/stage.private.json'), '--stage-sha256', stage_sha],
    capture_output=True, text=True, timeout=20)
assert checked.returncode == 0 and not checked.stderr and json.loads(checked.stdout)['ok'] is True
for name, expected in pins.items():
    assert not (root / 'control' / name).exists() and not (root / 'control' / name).is_symlink()
    assert hashlib.sha256(packet['files'][name].encode()).hexdigest() == expected
receipt = root / 'control/seed-cross-os-source-staged-61ff-r2.public.json'
assert not receipt.exists() and not receipt.is_symlink()
for name, content in packet['files'].items():
    fd = os.open(root / 'control' / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content.encode())
        stream.flush()
        os.fsync(stream.fileno())
result = {'schema': 'heptabao.cross-os-seed-helper-stage.v1', 'ok': True,
          'node': packet['node'], 'pins': pins, 'stage_sha256': stage_sha,
          'service_started': False, 'credentials_transferred': False, 'initialization_repeated': False}
raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as stream:
    stream.write(raw)
    stream.flush()
    os.fsync(stream.fileno())
fd = os.open(root / 'control', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
os.fsync(fd)
os.close(fd)
print(json.dumps({'ok': True, 'node': packet['node'], 'pins': pins,
                  'receipt_sha256': hashlib.sha256(raw).hexdigest(), 'service_started': False}))
