#!/usr/bin/env python3
"""Start one explicitly activated Linux node; no initialization or unseal here."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import socket


class Refused(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


def read_file(path, *, mode=0o600, limit=1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute_path_required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode
             and before.st_size <= limit, 'file_custody')
        blocks, size = [], 0
        while size <= limit:
            block = os.read(fd, min(65536, limit + 1 - size))
            if not block:
                break
            blocks.append(block)
            size += len(block)
        after = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns,
                            s.st_uid, s.st_mode, s.st_nlink)
        need(fields(before) == fields(after) and size == before.st_size, 'file_changed')
        return b''.join(blocks)
    finally:
        os.close(fd)


def digest_file(path, mode):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode,
             'pinned_file_custody')
        h = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            h.update(block)
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             'pinned_file_changed')
        return h.hexdigest(), before.st_dev
    finally:
        os.close(fd)


def volume_guard(root, binding):
    need(sys.platform == 'linux' and socket.gethostname() == binding['hostname'], 'exact_linux_host')
    need(root == Path.home() / 'heptabao-production-20261104-r1', 'exact_linux_root')
    for path in [root, *root.parents]:
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and not path.is_symlink(), 'stage_parent_symlink')
    info = root.lstat()
    need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'stage_directory_custody')
    return info.st_dev


def python_guard(binding):
    path = Path(binding['python']['path'])
    need(Path(sys.executable).resolve() == path, 'python_path_changed')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
             and stat.S_IMODE(st.st_mode) == 0o755, 'python_binary_custody')
        h = hashlib.sha256()
        while True:
            part = os.read(fd, 1024 * 1024)
            if not part:
                break
            h.update(part)
        end = os.fstat(fd)
        fields = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        need(fields(st) == fields(end) and h.hexdigest() == binding['python']['sha256'], 'python_binary_changed')
    finally:
        os.close(fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=('check-stage', 'serve'))
    p.add_argument('--stage', required=True, type=Path)
    p.add_argument('--stage-sha256', required=True)
    args = p.parse_args()
    raw = read_file(args.stage)
    need(hashlib.sha256(raw).hexdigest() == args.stage_sha256, 'stage_binding_pin')
    binding = json.loads(raw)
    need(binding['schema'] == 'heptabao.linux-bound-node-stage.v1', 'stage_schema')
    root = Path(binding['root'])
    need(args.stage == root / 'control/stage.private.json' and binding['uid'] == os.geteuid(),
         'stage_owner_or_path')
    device = volume_guard(root, binding)
    for relative in ('release', 'config', 'control', 'tls', 'node', 'node/state', 'node/raft', 'logs'):
        path = root / relative
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and info.st_dev == device
             and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
             'node_directory_custody_or_device')
    python_guard(binding)
    for relative, pin in binding['files'].items():
        name = Path(relative)
        need(not name.is_absolute() and '..' not in name.parts, 'stage_relative_file_path')
        path = root / name
        for parent in path.parents:
            if parent == root:
                break
            need(not parent.is_symlink() and parent.stat().st_dev == device, 'stage_file_parent_changed')
        actual, file_device = digest_file(path, pin['mode'])
        need(actual == pin['sha256'] and file_device == device, 'stage_file_pin_or_device')
    need(time.time() < binding['tls_not_after_unix'], 'node_certificate_expired')
    if args.command == 'check-stage':
        print(json.dumps({'ok': True, 'stage_verified': True, 'service_started': False,
                          'activation_present': (root / 'control/activation.private.json').exists()}))
        return 0
    pin_path = root / 'control/activation.sha256'
    need(pin_path.exists(), 'activation_pin_missing')
    expected = read_file(pin_path, limit=80).decode().strip()
    need(len(expected) == 64 and all(c in '0123456789abcdef' for c in expected), 'activation_pin_shape')
    activation_raw = read_file(root / 'control/activation.private.json')
    need(hashlib.sha256(activation_raw).hexdigest() == expected, 'activation_pin_mismatch')
    a = json.loads(activation_raw)
    need(a.get('schema') == 'heptabao.production-ha-activation.v1'
         and a.get('stage_sha256') == args.stage_sha256
         and a.get('source_commit') == binding['source_commit']
         and a.get('source_tree') == binding['source_tree']
         and a.get('binary_sha256') == binding['files']['release/heptabao-server']['sha256']
         and a.get('normal_ha_passed') == 128 and a.get('normal_ha_total') == 128
         and a.get('normal_ha_unknown') == 0 and a.get('cohort_node_start_authorized') is True,
         'production_qualification_binding')
    need(a.get('private_diagnostic_feature_enabled') is False, 'normal_build_qualification_required')
    need(all(isinstance(a.get(k), str) and len(a[k]) == 64
             and all(c in '0123456789abcdef' for c in a[k])
             for k in ('normal_ha_receipt_sha256', 'ha_config_sha256', 'peer_registry_sha256')),
         'activation_evidence_pins')
    ha_raw = read_file(root / 'config/ha.json')
    need(hashlib.sha256(ha_raw).hexdigest() == a['ha_config_sha256'], 'ha_configuration_pin')
    peers_raw = read_file(root / 'control/peer-registry.private.json')
    need(hashlib.sha256(peers_raw).hexdigest() == a['peer_registry_sha256'], 'peer_registry_pin')
    peers = json.loads(peers_raw)
    ha = json.loads(ha_raw)
    need(ha.get('peers') == peers and set(peers) == {'1', '2', '3'}
         and ha.get('node_id') == binding['node_id'] and ha.get('cluster_id') == a.get('cluster_id')
         and isinstance(a.get('cluster_id'), str) and bool(a['cluster_id'])
         and ha.get('raft_dir') == str(root / 'node/raft')
         and ha.get('listen') == binding['raft_listen']
         and ha.get('ca_file') == str(root / 'tls/ca.crt')
         and ha.get('cert_file') == str(root / 'tls/tls.crt')
         and ha.get('key_file') == str(root / 'tls/tls.key')
         and ha.get('replication_key_file') == str(root / 'tls/replication.key')
         and not ha.get('allow_legacy_peer_v1') and not ha.get('emit_legacy_peer_v1')
         and all(not v.get('certificate_sha256_next') for v in peers.values()), 'exact_native_ha_binding')
    need(ha.get('bootstrap') is False, 'linux_peer_not_initial_bootstrap')
    local = peers[str(binding['node_id'])]
    need(local['node_name'] == binding['node_name'] and local['address'] == binding['raft_listen']
         and local['api_address'] == binding['api_address']
         and local['cluster_address'] == 'https://' + binding['raft_listen']
         and local['server_name'] == binding['server_name']
         and local['certificate_sha256'] == binding['leaf_der_sha256'], 'local_peer_identity')
    binary = root / 'release/heptabao-server'
    # This path neither initializes storage, sends native-v6 activation nor
    # unseals. Those are separate journaled operations with no unknown replay.
    # Client/publisher cutover and exclusion of old writers are later gates;
    # starting this new, separately initialized cohort does not switch traffic.
    os.execv(str(binary), [str(binary), '--config', str(root / 'config/server.json'),
                          '--ha-config', str(root / 'config/ha.json')])


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'ok': False, 'service_started': False,
                          'error': str(exc) if isinstance(exc, Refused) else 'node_guard_' + type(exc).__name__}))
        raise SystemExit(2)
