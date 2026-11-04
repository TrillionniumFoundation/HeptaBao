#!/usr/bin/env python3
"""Bind an offline Linux node guard and systemd user-unit template.

Never registers a unit, starts a server, initializes storage, or sends HTTP.
The guard refuses serve until a separately verified activation is present.
"""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys

PINS = {
    'qian-qi-ROG-Flow-Z13-GZ302EA-GZ302EA': ('rog', 2, '192.168.0.10', '/home/qian-qi',
        '062cdcb29df625a2efb683e9e4223b76de7d1dd3b26e414dba7a27f8f9f357bd'),
    'alex-G1628-04': ('pocket4', 3, '192.168.0.9', '/home/alex',
        '044d1a15ab74e82a1d6c51514cfe516b1fad39e87d6edc9976ba44ede752a07e'),
}
INPUT_PINS = {
    'rog': {
        'prepared-csr.public.json': 'a3c46341002b414835d976d1874f22dc03c06f330b723960e6a1743be24851d2',
        'state-path-correction.public.json': '5b54af7bcda8f3fd5b189708d10147e3ceb2b4e713b3d947711b04abba9bbbc4',
        'certificates-installed.public.json': 'ea45030d9ef2ee50c04f656e1aa7de51c5b2b86d47478e7790294ae48a43e530',
    },
    'pocket4': {
        'prepared-csr.public.json': 'f658bd6e5af0523c7ac2a9140d8a8145682e870cbce7efab771907f104967828',
        'state-path-correction.public.json': '4f8ee718791b07172c49d4967e9105c9c6668da0b287aa036c8fc4f76e2dc285',
        'certificates-installed.public.json': 'f061523f5bafd3f59475b717bdf4e9c217772015e650d22dbab987c842904c30',
    },
}
BOOTSTRAP = '''import hashlib,os,stat,sys
p=sys.argv[1]; expected=sys.argv[2]
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
try:
    before=os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.geteuid() and stat.S_IMODE(before.st_mode)==0o500 and before.st_size<=262144
    chunks=[]; size=0
    while size<=262144:
        block=os.read(fd,min(65536,262145-size))
        if not block: break
        chunks.append(block); size+=len(block)
    after=os.fstat(fd)
finally: os.close(fd)
fields=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_uid,s.st_mode,s.st_nlink)
raw=b''.join(chunks)
assert fields(before)==fields(after) and len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==expected
sys.argv=[p]+sys.argv[3:]
exec(compile(raw,p,'exec'),{'__name__':'__main__','__file__':p})
'''


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path, mode=0o600, uid=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1
        assert st.st_uid == (os.getuid() if uid is None else uid) and stat.S_IMODE(st.st_mode) == mode
        blocks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
        end = os.fstat(fd)
        fields = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        assert fields(st) == fields(end)
        return b''.join(blocks)
    finally:
        os.close(fd)


def put(path, value, mode=0o600):
    raw = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return sha(raw)


def quote_unit_argument(value):
    assert '\x00' not in value and '\r' not in value and '\n' not in value
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def main():
    os.umask(0o077)
    assert sys.platform == 'linux' and os.getuid() == 1000
    hostname = socket.gethostname()
    name, node_id, ip, home, receipt_pin = PINS[hostname]
    assert Path.home() == Path(home)
    root = Path(home) / 'heptabao-production-20261104-r1'
    for rel in ['', 'release', 'control', 'config', 'tls', 'node', 'node/state', 'node/raft', 'logs', 'service']:
        p = root / rel
        st = p.lstat()
        assert stat.S_ISDIR(st.st_mode) and not p.is_symlink()
        assert st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700
    for rel in ['control/stage.private.json', 'control/activation.private.json', 'control/activation.sha256',
                'release/heptabao_linux_node_start.py', 'service/heptabao-node.service', 'service-prepared.public.json']:
        assert not (root / rel).exists() and not (root / rel).is_symlink()
    assert not list((root / 'node/state').iterdir()) and not list((root / 'node/raft').iterdir())
    assert not (Path(home) / '.config/systemd/user/heptabao-node.service').exists()
    cohort_raw = regular(root / 'cohort-prepared.public.json')
    assert sha(cohort_raw) == receipt_pin
    cohort = json.loads(cohort_raw)
    pinned = {}
    for filename, expected in INPUT_PINS[name].items():
        raw = regular(root / filename)
        assert sha(raw) == expected
        pinned[filename] = json.loads(raw)
    prepared = pinned['prepared-csr.public.json']
    repaired = pinned['state-path-correction.public.json']
    certified = pinned['certificates-installed.public.json']
    assert cohort['ok'] and repaired['ok'] and certified['ok']
    assert cohort['node_id'] == node_id and cohort['hostname'] == hostname
    assert prepared['source_commit'] == cohort['source_commit'] and prepared['source_tree'] == cohort['source_tree']
    assert sha(regular(root / 'release/heptabao-server', 0o700)) == prepared['binary_sha256']
    assert sha(regular(root / 'config/server.json')) == repaired['server_config_sha256_after']
    for rel, expected in cohort['files'].items():
        assert sha(regular(root / rel)) == expected
    assert sha(regular(root / 'tls/ca.crt')) == certified['ca_pem_sha256']
    assert sha(regular(root / 'tls/tls.crt')) == certified['certificate_pem_sha256']
    python = Path(prepared['python_path'])
    assert sha(regular(python, 0o755, 0)) == prepared['python_sha256']
    assert Path(sys.executable).resolve() == python
    openssl = Path(prepared['openssl_path']).resolve()
    assert sha(regular(openssl, 0o755, 0)) == prepared['openssl_sha256']
    response = subprocess.run([str(openssl), 'x509', '-in', str(root / 'tls/tls.crt'), '-noout', '-enddate'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True)
    not_after = response.stdout.decode().strip().split('=', 1)[1]
    expires = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc).timestamp()
    inputs = json.load(sys.stdin)
    assert set(inputs) == {'guard_source', 'guard_sha256'}
    guard = inputs['guard_source'].encode()
    assert sha(guard) == inputs['guard_sha256']
    compile(guard, 'heptabao_linux_node_start.py', 'exec')
    guard_path = root / 'release/heptabao_linux_node_start.py'
    put(guard_path, guard, 0o500)
    files = {}
    for rel, mode in [('release/heptabao-server', 0o700), ('release/heptabao_linux_node_start.py', 0o500),
                      ('config/server.json', 0o600), ('config/ha.json', 0o600),
                      ('control/peer-registry.private.json', 0o600), ('tls/ca.crt', 0o600),
                      ('tls/tls.crt', 0o600), ('tls/tls.key', 0o600), ('tls/replication.key', 0o600)]:
        files[rel] = {'sha256': sha(regular(root / rel, mode)), 'mode': mode}
    binding = {'schema': 'heptabao.linux-bound-node-stage.v1', 'root': str(root), 'uid': os.getuid(),
               'hostname': hostname, 'node_name': name, 'node_id': node_id,
               'source_commit': cohort['source_commit'], 'source_tree': cohort['source_tree'],
               'files': files, 'python': {'path': str(python), 'sha256': prepared['python_sha256']},
               'server_name': hostname, 'api_address': 'https://' + ip + ':8200', 'raft_listen': ip + ':8201',
               'leaf_der_sha256': certified['certificate_der_sha256'], 'ca_der_sha256': certified['ca_der_sha256'],
               'tls_not_after_unix': expires}
    stage_path = root / 'control/stage.private.json'
    stage_sha = put(stage_path, binding)
    loader = "import base64;exec(base64.b64decode('" + base64.b64encode(BOOTSTRAP.encode()).decode() + "'))"
    argv = [str(python), '-I', '-S', '-B', '-c', loader, str(guard_path), inputs['guard_sha256'],
            'serve', '--stage', str(stage_path), '--stage-sha256', stage_sha]
    unit = ('[Unit]\nDescription=HeptaBao native V6 node\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\n'
            + 'ExecStart=' + ' '.join(map(quote_unit_argument, argv)) + '\n'
            + 'WorkingDirectory=' + str(root) + '\nUMask=0077\nNoNewPrivileges=yes\n'
            + 'Restart=on-failure\nRestartPreventExitStatus=2\nRestartSec=30s\nTimeoutStopSec=20s\n'
            + 'KillMode=control-group\nKillSignal=SIGTERM\nLimitNOFILE=8192\n'
            + 'StandardOutput=append:' + str(root / 'logs/node.stdout.log') + '\n'
            + 'StandardError=append:' + str(root / 'logs/node.stderr.log') + '\n\n[Install]\nWantedBy=default.target\n')
    unit_path = root / 'service/heptabao-node.service'
    unit_sha = put(unit_path, unit.encode())
    analysis = subprocess.run(['/usr/bin/systemd-analyze', '--user', 'verify', str(unit_path)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    put(root / 'control/service-verify.private.log', analysis.stdout + analysis.stderr)
    assert analysis.returncode == 0
    checked = list(argv)
    checked[8] = 'check-stage'
    result = subprocess.run(checked, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=20)
    assert result.returncode == 0
    value = json.loads(result.stdout)
    assert value['stage_verified'] is True and value['service_started'] is False and value['activation_present'] is False
    # Exercise the real serve entry with no activation: it must refuse before
    # exec. This does not install or launch the proposed systemd service.
    refused = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=20)
    assert refused.returncode == 2
    refusal = json.loads(refused.stdout)
    assert refusal['error'] == 'activation_pin_missing' and refusal['service_started'] is False
    receipt = {'schema': 'heptabao.linux-service-offline-prepared.v1', 'ok': True,
               'node': name, 'hostname': hostname, 'root': str(root), 'node_id': node_id,
               'source_commit': cohort['source_commit'], 'source_tree': cohort['source_tree'],
               'cluster_id': cohort['cluster_id'], 'cohort_receipt_sha256': receipt_pin,
               'stage_sha256': stage_sha, 'guard_sha256': inputs['guard_sha256'], 'unit_sha256': unit_sha,
               'systemd_analyze_user_verify_passed': True, 'exact_guard_check_passed': True,
               'missing_activation_serve_refused': True, 'python': binding['python'],
               'script_sha256': sha(Path(__file__).read_bytes()),
               'service_loaded': False, 'service_started': False, 'seed_initialized': False,
               'activation_created': False, 'traffic_cutover': False, 'production_client_changed': False}
    digest = put(root / 'service-prepared.public.json', receipt)
    print(json.dumps({'ok': True, 'node': name, 'receipt_sha256': digest, 'service_started': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'ok': False, 'error_type': type(error).__name__, 'automatic_retry': False,
                          'inspect_created_files_before_next_action': True, 'service_started': False}))
        raise SystemExit(2)
