#!/usr/bin/env python3
"""Install only public CA/leaf material, matching the host-owned private key."""
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys


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


def main():
    os.umask(0o077)
    d = json.load(sys.stdin)
    root = Path.home() / 'heptabao-production-20261104-r1'
    raw = (root / 'prepared-csr.public.json').read_bytes()
    assert sha(raw) == d['preparation_sha256']
    r = json.loads(raw)
    assert r['uid'] == os.getuid() and r['hostname'] == socket.gethostname()
    for p in [root, root / 'tls', root / 'tls/tls.key']:
        s = p.lstat()
        assert not p.is_symlink() and s.st_uid == os.getuid()
        assert stat.S_IMODE(s.st_mode) == (0o700 if p.is_dir() else 0o600)
    openssl = Path(r['openssl_path'])
    assert sha(openssl.read_bytes()) == r['openssl_sha256']

    def command(args):
        c = subprocess.run([str(openssl), *map(str, args)], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        assert c.returncode == 0
        return c.stdout

    assert sha(d['ca'].encode()) == d['ca_pem_sha256']
    assert sha(d['cert'].encode()) == d['cert_pem_sha256']
    ca, cert = root / 'tls/ca.crt', root / 'tls/tls.crt'
    put(ca, d['ca'].encode())
    put(cert, d['cert'].encode())
    assert sha(command(['x509', '-in', ca, '-outform', 'DER'])) == d['ca_der_sha256']
    assert sha(command(['x509', '-in', cert, '-outform', 'DER'])) == d['cert_der_sha256']
    assert command(['pkey', '-in', root / 'tls/tls.key', '-pubout']) == command(
        ['x509', '-in', cert, '-pubkey', '-noout'])
    for purpose in ['sslclient', 'sslserver']:
        command(['verify', '-x509_strict', '-CAfile', ca, '-purpose', purpose, cert])
    command(['verify', '-x509_strict', '-CAfile', ca, '-verify_ip', r['ip'], cert])
    command(['verify', '-x509_strict', '-CAfile', ca, '-verify_hostname', r['hostname'], cert])
    result = {'schema': 'heptabao.linux-node-certificates-installed.v1', 'ok': True,
              'root': str(root), 'node': r['node_name'], 'preparation_sha256': d['preparation_sha256'],
              'ca_pem_sha256': d['ca_pem_sha256'], 'ca_der_sha256': d['ca_der_sha256'],
              'certificate_pem_sha256': d['cert_pem_sha256'],
              'certificate_der_sha256': d['cert_der_sha256'],
              'chain_server_client_san_verified': True, 'local_private_key_matches': True,
              'private_key_exported': False, 'service_started': False, 'traffic_cutover': False}
    digest = put(root / 'certificates-installed.public.json', result)
    print(json.dumps({'ok': True, 'node': r['node_name'], 'receipt_sha256': digest,
                      'service_started': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'ok': False, 'error_type': type(exc).__name__, 'service_started': False}))
        raise SystemExit(2)
