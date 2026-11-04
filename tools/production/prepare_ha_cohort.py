#!/usr/bin/env python3
"""Bind three prepared nodes; copy the peer key only over authenticated SSH.

This is an offline configuration operation. It never initializes the secret
store, starts a service, opens a firewall or switches a client. An uncertain SSH
outcome is retained and must be inspected, never retried by this script.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import time
import uuid

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1')
SOURCE = '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
TREE = 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
SIGNING_SHA = '0c1afa40d36b70bc75fd9f57555eb5d27e1fd8d2be3783dcddf1d25c2f7b5cef'

REMOTE = r'''
import base64,hashlib,json,os,socket,stat,sys
from pathlib import Path
os.umask(0o077)
d=json.loads(sys.argv[1])
root=Path(d['root'])
assert root==Path.home()/'heptabao-production-20261104-r1'
assert socket.gethostname()==d['hostname'] and os.getuid()==1000
def digest(raw):return hashlib.sha256(raw).hexdigest()
def write(p,raw):
 if not isinstance(raw,bytes):raw=(json.dumps(raw,sort_keys=True,indent=2)+'\n').encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 return digest(raw)
for p in [root,root/'tls',root/'control',root/'config']:
 s=p.lstat();assert stat.S_ISDIR(s.st_mode) and not p.is_symlink() and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700
prepared=(root/'prepared-csr.public.json').read_bytes()
certified=(root/'certificates-installed.public.json').read_bytes()
assert digest(prepared)==d['prepared_sha256'] and digest(certified)==d['certificate_receipt_sha256']
p=json.loads(prepared)
assert p['source_commit']==d['source_commit'] and p['source_tree']==d['source_tree']
assert digest((root/'release/heptabao-server').read_bytes())==p['binary_sha256']
c=json.loads(certified);assert c['ok'] is True and c['chain_server_client_san_verified'] is True and c['local_private_key_matches'] is True
assert digest((root/'tls/tls.crt').read_bytes())==c['certificate_pem_sha256']
assert digest((root/'tls/ca.crt').read_bytes())==c['ca_pem_sha256']
server=json.loads((root/'config/server.json').read_bytes())
native=server['storage']['native_v6_raft'];local=d['peers'][str(d['ha']['node_id'])]
assert server['data_dir']==str(root/'node/state') and native['path']==str(root/'node')
assert native['node_id']==local['node_name'] and native['cluster_addr']==local['cluster_address']
assert native['api_addr']==local['api_address'] and d['ha']['raft_dir']==str(root/'node/raft')
repair_raw=(root/'state-path-correction.public.json').read_bytes()
assert digest(repair_raw)==d['repair_receipt_sha256']
repair=json.loads(repair_raw)
assert repair['ok'] is True and digest((root/'config/server.json').read_bytes())==repair['server_config_sha256_after']
assert d['ha']['peers']==d['peers'] and set(d['peers'])=={'1','2','3'}
assert d['peers'][str(d['ha']['node_id'])]['certificate_sha256']==c['certificate_der_sha256']
for rel in ['tls/replication.key','control/peer-registry.private.json','config/ha.json','cohort-prepared.public.json','control/cohort-preparation-intent.private.json','control/activation.private.json','control/activation.sha256']:
 assert not (root/rel).exists() and not (root/rel).is_symlink()
for rel in ['node/state','node/raft']:
 assert not list((root/rel).iterdir())
# Prove the actual destination and all pinned stage material on this same SSH
# connection before the caller releases any replication-key bytes.
ready={'ready':True,'nonce':d['handshake_nonce'],'hostname':socket.gethostname(),'uid':os.getuid(),'root':str(root),'node_id':d['ha']['node_id'],'prepared_sha256':digest(prepared),'certificate_receipt_sha256':digest(certified),'repair_receipt_sha256':digest(repair_raw)}
print(json.dumps(ready,sort_keys=True),flush=True)
raw=sys.stdin.buffer.readline(4097)
assert len(raw)<=4096 and raw.endswith(b'\n')
packet=json.loads(raw)
assert set(packet)=={'nonce','replication_key_b64'} and packet['nonce']==d['handshake_nonce']
key=base64.b64decode(packet['replication_key_b64'],validate=True)
assert len(key)==32 and digest(key)==d['replication_key_sha256']
del raw,packet
write(root/'control/cohort-preparation-intent.private.json',{'cluster_id':d['ha']['cluster_id'],'source_commit':d['source_commit'],'source_tree':d['source_tree'],'peers':d['peers'],'service_started':False})
files={}
files['tls/replication.key']=write(root/'tls/replication.key',key)
del key
files['control/peer-registry.private.json']=write(root/'control/peer-registry.private.json',d['peers'])
files['config/ha.json']=write(root/'config/ha.json',d['ha'])
result={'schema':'heptabao.offline-ha-peer-prepared.v1','ok':True,'hostname':socket.gethostname(),'root':str(root),'source_commit':d['source_commit'],'source_tree':d['source_tree'],'cluster_id':d['ha']['cluster_id'],'node_id':d['ha']['node_id'],'files':files,'private_key_exported':False,'replication_key_transport':'authenticated SSH stdin after same-connection destination identity and stage verification; no credential output','identity_before_key_transfer_verified':True,'service_started':False,'traffic_cutover':False,'seed_initialized':False,'activation_created':False}
h=write(root/'cohort-prepared.public.json',result)
print(json.dumps({'ok':True,'receipt_sha256':h,'node_id':d['ha']['node_id'],'files':files,'service_started':False}))
'''


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def put(path, raw):
    if not isinstance(raw, bytes):
        raw = (json.dumps(raw, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return sha(raw)


def config(root, node_id, ip, cluster_id, peers):
    return {'bootstrap': node_id == 1, 'ca_file': str(root / 'tls/ca.crt'),
            'cert_file': str(root / 'tls/tls.crt'), 'key_file': str(root / 'tls/tls.key'),
            'replication_key_file': str(root / 'tls/replication.key'),
            'cluster_id': cluster_id, 'forward_timeout_ms': 8000, 'listen': ip + ':8201',
            'max_inflight': 32, 'node_id': node_id, 'peer_timeout_ms': 1500,
            'peers': peers, 'raft_dir': str(root / 'node/raft')}


def send_peer(argv, metadata, key, work, name):
    deadline = time.monotonic() + 45
    ready_raw = bytearray()
    key_sent = False
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while not ready_raw.endswith(b'\n'):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError('peer identity handshake deadline')
                block = os.read(child.stdout.fileno(), 4097 - len(ready_raw))
                if not block:
                    raise RuntimeError('peer closed before identity handshake')
                ready_raw.extend(block)
                if len(ready_raw) > 4096:
                    raise RuntimeError('peer identity handshake size')
        ready = json.loads(ready_raw)
        expected = {'ready': True, 'nonce': metadata['handshake_nonce'],
                    'hostname': metadata['hostname'], 'uid': 1000, 'root': metadata['root'],
                    'node_id': metadata['ha']['node_id'],
                    'prepared_sha256': metadata['prepared_sha256'],
                    'certificate_receipt_sha256': metadata['certificate_receipt_sha256'],
                    'repair_receipt_sha256': metadata['repair_receipt_sha256']}
        assert ready == expected
        put(work / (name + '-identity-verified.public.json'), ready)
        packet = (json.dumps({'nonce': metadata['handshake_nonce'],
                              'replication_key_b64': base64.b64encode(key).decode()}) + '\n').encode()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('peer key transfer deadline')
        key_sent = True
        out, err = child.communicate(packet, timeout=remaining)
        del packet
        put(work / (name + '-response.private.log'), bytes(ready_raw) + out + err)
        assert child.returncode == 0
        result = json.loads(out)
        assert result['ok'] is True and result['node_id'] == metadata['ha']['node_id']
        assert result['files']['tls/replication.key'] == metadata['replication_key_sha256']
        return result
    except BaseException:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        out, err = child.communicate(timeout=5)
        failure_path = work / (name + '-failure.private.log')
        put(failure_path, bytes(ready_raw) + out + err)
        put(work / (name + '-failure.public.json'),
            {'host': name, 'key_transfer_attempted': key_sent, 'automatic_retry': False,
             'remote_outcome_requires_read_only_reconciliation': key_sent,
             'returncode': child.returncode, 'service_started': False})
        raise


def main():
    os.umask(0o077)
    assert os.getuid() == 501 and socket.gethostname() == 'MacBook-Pro.local'
    stage_raw = (ROOT / 'control/stage.private.json').read_bytes()
    stage = json.loads(stage_raw)
    repair = json.loads((ROOT / 'state-path-correction.public.json').read_bytes())
    assert repair['ok'] is True and sha(stage_raw) == repair['stage_binding_sha256_after']
    assert repair['stage_binding_sha256_before'] == '50347e3e23e2721381fed5f4627a80facea10a5e644a333bae8d88e88c1659dc'
    server_raw = (ROOT / 'config/server.json').read_bytes()
    assert sha(server_raw) == repair['server_config_sha256_after']
    server = json.loads(server_raw)
    native = server['storage']['native_v6_raft']
    assert server['data_dir'] == str(ROOT / 'node/state') and native['path'] == str(ROOT / 'node')
    assert native['node_id'] == 'mac' and native['cluster_addr'] == 'https://192.168.0.8:8201'
    assert native['api_addr'] == 'https://192.168.0.8:8200'
    signing_raw = (ROOT / 'authority/linux-peers-20261104-r1/result.public.json').read_bytes()
    assert sha(signing_raw) == SIGNING_SHA
    signing = json.loads(signing_raw)
    assert signing['ok'] and stage['source_commit'] == SOURCE and stage['source_tree'] == TREE
    kp = ROOT / 'tls/replication.key'
    st = kp.lstat()
    assert stat.S_ISREG(st.st_mode) and not kp.is_symlink() and st.st_uid == os.getuid()
    assert stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and st.st_size == 32
    key = kp.read_bytes()
    key_sha = sha(key)
    assert key_sha == stage['files']['tls/replication.key']['sha256']
    hosts = {
        'mac': (1, '192.168.0.8', 'MacBook-Pro.local', str(ROOT), stage['leaf_der_sha256']),
        'rog': (2, '192.168.0.10', 'qian-qi-ROG-Flow-Z13-GZ302EA-GZ302EA',
                '/home/qian-qi/heptabao-production-20261104-r1', signing['peers']['rog']['certificate_der_sha256']),
        'pocket4': (3, '192.168.0.9', 'alex-G1628-04',
                    '/home/alex/heptabao-production-20261104-r1', signing['peers']['pocket4']['certificate_der_sha256']),
    }
    peers = {str(n): {'address': ip + ':8201', 'api_address': 'https://' + ip + ':8200',
                     'cluster_address': 'https://' + ip + ':8201', 'node_name': name,
                     'server_name': host, 'certificate_sha256': cert}
             for name, (n, ip, host, root, cert) in hosts.items()}
    cluster_id = str(uuid.uuid4())
    work = ROOT / 'control/cohort-prepare-20261104-r1'
    work.mkdir(mode=0o700)
    put(work / 'intent.public.json', {'schema': 'heptabao.offline-cohort-intent.v1',
                                    'cluster_id': cluster_id, 'source_commit': SOURCE,
                                    'source_tree': TREE, 'peers': peers, 'service_started': False})
    cert_receipts = {'rog': 'ea45030d9ef2ee50c04f656e1aa7de51c5b2b86d47478e7790294ae48a43e530',
                     'pocket4': None}
    repair_receipts = {'rog': '5b54af7bcda8f3fd5b189708d10147e3ceb2b4e713b3d947711b04abba9bbbc4',
                       'pocket4': '4f8ee718791b07172c49d4967e9105c9c6668da0b287aa036c8fc4f76e2dc285'}
    # The caller supplies only the Pocket4 public installation receipt hash.
    import sys
    pins = json.load(sys.stdin)
    assert set(pins) == {'pocket4_certificate_receipt_sha256'}
    cert_receipts['pocket4'] = pins['pocket4_certificate_receipt_sha256']
    assert len(cert_receipts['pocket4']) == 64 and all(c in '0123456789abcdef' for c in cert_receipts['pocket4'])
    results = {}
    for name in ('rog', 'pocket4'):
        n, ip, host, root, cert = hosts[name]
        payload = {'root': root, 'hostname': host, 'source_commit': SOURCE, 'source_tree': TREE,
                   'ha': config(Path(root), n, ip, cluster_id, peers), 'peers': peers,
                   'prepared_sha256': signing['peers'][name]['receipt_sha256'],
                   'certificate_receipt_sha256': cert_receipts[name],
                   'repair_receipt_sha256': repair_receipts[name],
                   'handshake_nonce': secrets.token_hex(16), 'replication_key_sha256': key_sha}
        # Host aliases are existing operator registrations. Strict host-key
        # validation is retained; the remote receiver also checks the real host.
        argv = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1', name,
                '/usr/bin/python3 -c ' + shlex.quote(REMOTE) + ' ' + shlex.quote(json.dumps(payload))]
        put(work / (name + '-attempt.public.json'), {'host': name, 'node_id': n,
                                                   'cluster_id': cluster_id, 'retry': False})
        result = send_peer(argv, payload, key, work, name)
        del payload
        results[name] = result
    del key
    files = {}
    files['control/peer-registry.private.json'] = put(ROOT / 'control/peer-registry.private.json', peers)
    files['config/ha.json'] = put(ROOT / 'config/ha.json', config(ROOT, 1, '192.168.0.8', cluster_id, peers))
    receipt = {'schema': 'heptabao.offline-three-node-cohort.v1', 'ok': True,
               'source_commit': SOURCE, 'source_tree': TREE, 'cluster_id': cluster_id,
               'peers': peers, 'mac_files': files, 'linux_receipts': results,
               'replication_key_sha256': key_sha, 'ca_key_exported': False,
               'identity_before_key_transfer_verified': True,
               'node_private_keys_exported': False, 'service_started': False,
               'service_loaded': False, 'seed_initialized': False, 'activation_created': False,
               'traffic_cutover': False, 'firewall_or_routing_changed': False}
    digest = put(work / 'result.public.json', receipt)
    print(json.dumps({'ok': True, 'receipt': str(work / 'result.public.json'), 'sha256': digest,
                      'cluster_id': cluster_id, 'service_started': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'ok': False, 'error_type': type(exc).__name__, 'service_started': False,
                          'automatic_retry': False, 'inspect_attempt_receipts_before_next_action': True}))
        raise SystemExit(2)
