#!/usr/bin/env python3
"""Install exact public QA bytes and run one owner-local credential acceptance."""
from pathlib import Path
import base64
import gzip
import hashlib
import json
import os
import pwd
import signal
import stat
import subprocess
import sys
import time

ROOT = Path('/home/qian-qi/heptabao-next-gates-20261017')
PACKET = ROOT / 'authbus-owned-source-r2-packet.json.gz'
PACKET_SHA = '15761be9e3be93ea9b3267906e674b9d33d579e4d565b7629db43ac793179e1a'
SOURCE = ROOT / 'authbus-owned-source-candidate-r2'
WORK = ROOT / 'authbus-owned-source-actual-r2'
CONTROL = ROOT / 'authbus-owned-source-r2-controller'
BINARY = ROOT / 'native-r8j-linux-freeze-01/heptabao-server'
BINARY_SHA = 'c0821bae2a8435eddea8506311a09cd3e1f0533948b8489f1e606e210a073560'
EXPECTED = {
    'qa/openbao-acceptance/native_v6_authbus_owned_source_live.py': 'fb44eab74e56b5d098a8fe0656ff764332fcccca9fe6ab0c7bcc4f2dfe21c121',
    'qa/openbao-acceptance/native_v6_authbus_owned_source_consumer.mjs': 'dc3120ba49f6088197dd4175054dd3c1d908efc79916599e9cee7ac85a46c4af',
    'qa/openbao-acceptance/native_v6_authbus_client_live.py': '2357c3486d9312da65617705b13e42b70434231efe5b3812c6131f71d3735a0e',
    'qa/openbao-acceptance/native_v6_openclaw_authbus_live.py': '6d785c4d69ad800b7c9ac5f8510397031362ff5bca9947be024700e91235c98a',
    'qa/openbao-acceptance/cert_auth_live.py': '17da3c53ccb5379b6b63790fb34dc0502666662ae5528dfad97eccfb3ac1acc9',
    'qa/openbao-acceptance/owned_process.py': '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0',
    'qa/openbao-acceptance/fixture_mounts.py': '55075ee436c22816a176dfb06cec387df37fdadd581c16acc07dabc837ba85b5',
    'qa/single-node/smoke.py': 'ced4e40a825d3d98a285598d40b58c61083cfc397d0859a783958d855a161971',
    'tools/authbus/authbus_coordinator.py': '81bfbacfd14df399c1e8eef963447803cee8e01aebc2474c0f39c2595e7fce47',
}

def require(value, code):
    if not value:
        raise RuntimeError(code)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def identity(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns

def read_owned(path, bound):
    require(path.is_absolute() and path.resolve(strict=True) == path, 'noncanonical_file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and not before.st_mode & 0o022
                and before.st_size <= bound, 'owned_file_metadata')
        pieces = []
        count = 0
        while True:
            piece = os.read(fd, min(65536, bound + 1 - count))
            if not piece:
                break
            pieces.append(piece)
            count += len(piece)
            require(count <= bound, 'owned_file_grew')
        require(identity(before) == identity(os.fstat(fd))
                == identity(os.stat(path, follow_symlinks=False)), 'owned_file_changed')
        return b''.join(pieces)
    finally:
        os.close(fd)

def verify_immutable_binary():
    require(BINARY.resolve(strict=True) == BINARY, 'noncanonical_binary')
    fd = os.open(BINARY, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and not before.st_mode & 0o022
                and before.st_size == 739732592, 'immutable_binary_metadata')
        value = hashlib.sha256()
        count = 0
        while True:
            chunk = os.read(fd, min(1048576, 739732593 - count))
            if not chunk:
                break
            count += len(chunk)
            require(count <= 739732592, 'immutable_binary_grew')
            value.update(chunk)
        require(count == 739732592 and value.hexdigest() == BINARY_SHA
                and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(BINARY, follow_symlinks=False)), 'immutable_binary_changed')
    finally:
        os.close(fd)

def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())

def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def main():
    os.umask(0o077)
    require(os.getuid() != 0 and pwd.getpwuid(os.getuid()).pw_dir == '/home/qian-qi', 'main_owner_required')
    require(ROOT.resolve(strict=True) == ROOT and ROOT.stat().st_uid == os.getuid()
            and not ROOT.stat().st_mode & 0o022, 'root_not_owned')
    packet_bytes = read_owned(PACKET, 101883)
    require(len(packet_bytes) == 101883 and digest(packet_bytes) == PACKET_SHA, 'source_packet_changed')
    packet = json.loads(gzip.decompress(packet_bytes))
    require(packet.get('schema') == 'heptabao.authbus-owned-source-r2-packet.v1'
            and set(packet['files']) == set(EXPECTED), 'source_packet_contract')
    decoded = {}
    for name, expected in EXPECTED.items():
        item = packet['files'][name]
        value = base64.b64decode(item['data_base64'], validate=True)
        require(len(value) == item['size'] and item['sha256'] == expected
                and digest(value) == expected, 'source_file_changed')
        decoded[name] = value
    verify_immutable_binary()
    require(not any(os.path.lexists(p) for p in (SOURCE, WORK, CONTROL)), 'fresh_owned_roots_required')
    SOURCE.mkdir(mode=0o700)
    CONTROL.mkdir(mode=0o700)
    for name, value in decoded.items():
        target = SOURCE / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_new(target, value, 0o400)
    write_new(SOURCE / 'source-manifest.public.json', json_bytes({'packet_sha256': PACKET_SHA, 'files': EXPECTED}))
    original = ROOT / 'authbus-sdk-owned-inspection-r1'
    command = ['/usr/bin/python3', '-B', str(SOURCE / 'qa/openbao-acceptance/native_v6_authbus_owned_source_live.py'),
               '--binary', str(BINARY), '--central-source', str(SOURCE / 'tools/authbus/authbus_coordinator.py'),
               '--plugin-root', '/home/qian-qi/.openclaw/extensions/openclaw-authbus',
               '--openclaw-root', '/home/qian-qi/.npm-global/lib/node_modules/openclaw',
               '--node', '/usr/bin/node', '--source-receipt', str(original / 'owner-export-r1-7b0b24e17c16/snapshot/public-receipt.json'),
               '--source-receipt-sha256', '41197f8d23229f9103b51505b319cc09eef0a48192631821caf7da2172d74907',
               '--source-inspector', str(original / 'authbus_sdk_owned_source.mjs'), '--work-dir', str(WORK)]
    record = {'schema': 'heptabao.authbus-owned-source-r2-controller.v1', 'command': command,
              'source_packet_sha256': PACKET_SHA, 'binary_sha256': BINARY_SHA,
              'binary_source_commit': '4f0bacd59be21d204783d69b500d2a19ef6af55a',
              'binary_source_tree': '9514b66b8cda559938e135d6c7c5b9606296fd4a',
              'production_cutover': False, 'provider_called': False, 'automatic_retry_allowed': False}
    write_new(CONTROL / 'request.public.json', json_bytes(record))
    started = time.monotonic()
    timed_out = False
    with (CONTROL / 'driver.stdout.private.log').open('xb') as output, (CONTROL / 'driver.stderr.private.log').open('xb') as error:
        process = subprocess.Popen(command, cwd=SOURCE, stdin=subprocess.DEVNULL, stdout=output, stderr=error,
                                   env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, start_new_session=True)
        try:
            code = process.wait(timeout=400)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait(timeout=5)
    source_unchanged = all(digest(read_owned(SOURCE / name, len(value))) == EXPECTED[name] for name, value in decoded.items())
    record.update(exit_code=code, timed_out=timed_out, elapsed_seconds=round(time.monotonic()-started, 3),
                  source_unchanged_after=source_unchanged, ok=False, mutation_outcome_unknown=timed_out)
    receipt_path = WORK / 'public-receipt.json'
    if receipt_path.exists():
        raw = read_owned(receipt_path, 1024 * 1024)
        receipt = json.loads(raw)
        checks = receipt.get('checks', [])
        names = [item.get('case') for item in checks]
        valid = bool(checks) and all(item.get('passed') is True for item in checks) and len(set(names)) == len(names)
        record.update(public_receipt_path=str(receipt_path), public_receipt_bytes=len(raw), public_receipt_sha256=digest(raw),
                      observed_checks=len(checks), passed_checks=sum(item.get('passed') is True for item in checks),
                      mutation_outcome_unknown=bool(timed_out or receipt.get('mutationOutcomeUnknown')),
                      driver_error_code=receipt.get('error'),
                      ok=(code == 0 and not timed_out and source_unchanged and valid and receipt.get('ok') is True
                          and receipt.get('schema') == 'native-v6-authbus-real-owned-source-live-v1'
                          and receipt.get('production_cutover') is False and receipt.get('provider_called') is False))
    write_new(CONTROL / 'public-receipt.json', json_bytes(record))
    print(json.dumps({key: record[key] for key in ('ok', 'exit_code', 'timed_out', 'source_unchanged_after', 'mutation_outcome_unknown')}
                     | {'controller_receipt': str(CONTROL / 'public-receipt.json'),
                        'controller_receipt_sha256': digest(json_bytes(record))}, sort_keys=True), flush=True)
    return 0 if record['ok'] else 1

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'ok': False, 'error_class': type(error).__name__,
                          'error': str(error) if isinstance(error, RuntimeError) else 'controller_preflight_or_io_failure',
                          'automatic_retry_allowed': False}), flush=True)
        raise SystemExit(2)
