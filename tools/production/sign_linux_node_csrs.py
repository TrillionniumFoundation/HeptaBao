#!/usr/bin/env python3
"""Sign the two registered Linux CSRs using the existing offline Mac CA.

Input contains only public CSRs and public preparation receipts. The CA key is
used locally by OpenSSL and is never copied, printed, or placed in tool input.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1')
OPENSSL = Path('/opt/homebrew/Cellar/openssl@3/3.6.3/bin/openssl')
OPENSSL_SHA = '103fc7706cf6646f226d96f29242d81890363499afc730e7ef1fadd64b3a123c'
CA_DER_SHA = '9c6bb844653d6fe415b76be7c11863bd59df729ce7367b924e1b3e0cd33c2b13'
STAGE_SHA = '2a2223789632f111a2fa78bccbad5dac392e73f8441b7e95f21da270bddc83ff'
PEERS = {
    'rog': {'hostname': 'qian-qi-ROG-Flow-Z13-GZ302EA-GZ302EA', 'ip': '192.168.0.10',
            'csr_sha256': '5949bff9ab1c53c300f1aa0a39b941fcdc28b2cd3f368c14afe5ab5ba79ff9ce',
            'receipt_sha256': 'a3c46341002b414835d976d1874f22dc03c06f330b723960e6a1743be24851d2'},
    'pocket4': {'hostname': 'alex-G1628-04', 'ip': '192.168.0.9',
                'csr_sha256': '3456ac3cca417790b69746eb2d0e6e3d7d803b4e678f960e5c9a43acf8ff9207',
                'receipt_sha256': 'f658bd6e5af0523c7ac2a9140d8a8145682e870cbce7efab771907f104967828'},
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def command(argv):
    p = subprocess.run(list(map(str, argv)), stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    need(p.returncode == 0, 'openssl_operation_failed')
    return p.stdout


def put(path, raw):
    if not isinstance(raw, bytes):
        raw = (json.dumps(raw, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return sha(raw)


def main():
    os.umask(0o077)
    need(os.getuid() == 501 and socket.gethostname() == 'MacBook-Pro.local', 'mac_owner')
    need(sha(OPENSSL.read_bytes()) == OPENSSL_SHA, 'openssl_pin')
    need(sha((ROOT / 'prepared.public.json').read_bytes()) == STAGE_SHA, 'stage_pin')
    ca, ca_key = ROOT / 'authority/ca.crt', ROOT / 'authority/ca.key'
    for p in [ROOT, ROOT / 'authority', ca, ca_key]:
        s = p.lstat()
        need(not p.is_symlink() and s.st_uid == os.getuid(), 'ca_custody')
        need(stat.S_IMODE(s.st_mode) == (0o700 if p.is_dir() else 0o600), 'ca_mode')
    need(sha(command([OPENSSL, 'x509', '-in', ca, '-outform', 'DER'])) == CA_DER_SHA,
         'ca_identity')
    data = json.load(sys.stdin)
    need(set(data) == set(PEERS), 'exact_peer_set')
    for name, pin in PEERS.items():
        record = data[name]
        need(sha(record['csr'].encode()) == pin['csr_sha256'], 'csr_pin')
        need(sha(record['receipt'].encode()) == pin['receipt_sha256'], 'receipt_pin')
        receipt = json.loads(record['receipt'])
        need(receipt['ok'] is True and receipt['hostname'] == pin['hostname']
             and receipt['ip'] == pin['ip'] and receipt['node_name'] == name
             and receipt['source_commit'] == '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
             and receipt['binary_sha256'] == '7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba',
             'peer_preparation_binding')
    work = ROOT / 'authority/linux-peers-20261104-r1'
    work.mkdir(mode=0o700)
    put(work / 'intent.public.json', {'schema': 'heptabao.two-peer-csr-signing-intent.v1',
                                     'peers': PEERS, 'ca_der_sha256': CA_DER_SHA})
    rows = {}
    for name, pin in PEERS.items():
        csr = work / (name + '.csr')
        put(csr, data[name]['csr'].encode())
        put(work / (name + '-prepared.public.json'), data[name]['receipt'].encode())
        command([OPENSSL, 'req', '-in', csr, '-verify', '-noout'])
        subject = command([OPENSSL, 'req', '-in', csr, '-noout', '-subject', '-nameopt', 'RFC2253']).decode().strip()
        need(subject == 'subject=CN=' + pin['hostname'], 'csr_subject')
        ext = work / (name + '.ext')
        put(ext, ('basicConstraints=critical,CA:FALSE\n'
                  'keyUsage=critical,digitalSignature,keyEncipherment\n'
                  'extendedKeyUsage=serverAuth,clientAuth\n'
                  'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n'
                  'subjectAltName=DNS:' + pin['hostname'] + ',IP:' + pin['ip']
                  + ',IP:127.0.0.1\n').encode())
        cert = work / (name + '.crt')
        raw = command([OPENSSL, 'x509', '-req', '-in', csr, '-CA', ca, '-CAkey', ca_key,
                       '-set_serial', '0x' + secrets.token_hex(16), '-days', '180',
                       '-sha256', '-extfile', ext])
        pem_sha = put(cert, raw)
        for purpose in ['sslserver', 'sslclient']:
            command([OPENSSL, 'verify', '-x509_strict', '-CAfile', ca, '-purpose', purpose, cert])
        command([OPENSSL, 'verify', '-x509_strict', '-CAfile', ca, '-verify_ip', pin['ip'], cert])
        command([OPENSSL, 'verify', '-x509_strict', '-CAfile', ca,
                 '-verify_hostname', pin['hostname'], cert])
        need(command([OPENSSL, 'req', '-in', csr, '-pubkey', '-noout'])
             == command([OPENSSL, 'x509', '-in', cert, '-pubkey', '-noout']), 'csr_public_key')
        rows[name] = dict(pin, certificate_path=str(cert), certificate_pem_sha256=pem_sha,
                         certificate_der_sha256=sha(command([OPENSSL, 'x509', '-in', cert,
                                                           '-outform', 'DER'])),
                         csr_signature_verified=True, certificate_san_and_chain_verified=True,
                         private_node_key_received=False)
    receipt = {'schema': 'heptabao.linux-peer-signing-result.v1', 'ok': True, 'peers': rows,
               'ca_der_sha256': CA_DER_SHA, 'ca_key_exported': False, 'provider_called': False,
               'service_started': False, 'traffic_cutover': False}
    digest = put(work / 'result.public.json', receipt)
    print(json.dumps({'ok': True, 'receipt': str(work / 'result.public.json'), 'sha256': digest}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'ok': False, 'error_type': type(exc).__name__, 'service_started': False}))
        raise SystemExit(2)
