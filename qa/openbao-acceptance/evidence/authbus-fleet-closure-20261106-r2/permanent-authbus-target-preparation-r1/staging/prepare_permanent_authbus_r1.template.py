#!/usr/bin/env python3
"""Create-only independent trust/runtime staging; no service or API dispatch."""
import ast
import hashlib
import json
import os
from pathlib import Path
import plistlib
import ssl
import stat
import sys
import time
import types

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production')
HOME = Path('/Users/qianqi')
CUSTODY = HOME / 'heptabao-authbus-production-custody'
BACKUPS = HOME / 'heptabao-authbus-production-backups'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
SOURCE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/build-test-4bde9-r1/artifacts/heptabao-server')
PRODUCT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
BIN_SHA = '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
BIN_BYTES = 92359328
TOOL_PINS = {
    str(PYTHON): (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    '/usr/bin/openssl': (1130832, 'f81b4fcec5048ea1eceb40fc08f4e06f1668181f0b5bacfa8be27d0da181dcb7'),
    '/usr/sbin/diskutil': (1937776, '624a8601b97ddfaa4b18dd2854c299e084cd45eb18fc152011c97615c3b9da1f'),
    '/bin/ps': (170432, '3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'),
}
# PAYLOAD_PLACEHOLDER
START = time.monotonic()
UNTIL = START + 180
FDS = []
CODE_PIN_COMPLETIONS = []
report = {'schema': 'heptabao.permanent-authbus-create-only-preparation.r1', 'ok': False,
          'serviceActions': 0, 'apiRequests': 0, 'currentCredentialReads': 0,
          'providerCalls': 0, 'productionClientWrites': 0, 'legacyDeletions': 0,
          'privateKeyBytesOrDigestsPublished': False, 'productionReady': False,
          'automaticRetry': False, 'root': str(ROOT), 'custodyRoot': str(CUSTODY),
          'backupRoot': str(BACKUPS), 'productCommit': PRODUCT}

def need(value, code):
    if not value:
        raise RuntimeError(code)

def remaining():
    left = UNTIL - time.monotonic()
    need(left > 0, 'original_preparation_180_second_deadline')
    return left

def identity(info):
    return tuple(str(getattr(info, k)) for k in ('st_dev', 'st_ino', 'st_uid',
        'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def open_fd(path, flags, *, dir_fd=None, mode=0o600):
    remaining()
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode,
                 **({} if dir_fd is None else {'dir_fd': dir_fd}))
    row = {'fd': fd, 'closeAttempts': 0, 'closed': False}
    FDS.append(row)
    return row

def close_fd(row):
    if row['closeAttempts']:
        return row['closed']
    row['closeAttempts'] = 1
    os.close(row['fd'])
    row['closed'] = True
    return True

def write_all(fd, raw):
    view = memoryview(raw)
    while view:
        remaining()
        count = os.write(fd, view)
        need(count > 0, 'complete_new_file_write')
        view = view[count:]

class HomeTrees:
    """Only two new fixed private roots under one held existing HOME."""
    def __init__(self):
        before = HOME.lstat()
        need(HOME.resolve(strict=True) == HOME and stat.S_ISDIR(before.st_mode)
             and before.st_uid == 501 and not before.st_mode & 0o022, 'protected_home_parent')
        self.home = open_fd(HOME, os.O_RDONLY | os.O_DIRECTORY)
        self.home_identity = identity(before)[:5]
        self.directories = {HOME: (self.home, self.home_identity)}
        self.check()

    def check(self):
        remaining()
        for path, (row, expected) in self.directories.items():
            need(identity(os.fstat(row['fd']))[:5] == identity(path.lstat())[:5] == expected,
                 'same_held_private_directory')

    def mkdir(self, path):
        self.check()
        need(path in (CUSTODY, BACKUPS, CUSTODY / 'pki', CUSTODY / 'operations')
             and path.parent in self.directories, 'finite_new_home_directory')
        parent = self.directories[path.parent][0]
        os.mkdir(path.name, mode=0o700, dir_fd=parent['fd'])
        os.fsync(parent['fd'])
        row = open_fd(path.name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent['fd'])
        info = os.fstat(row['fd'])
        need(info.st_uid == 501 and info.st_gid == 20 and stat.S_IMODE(info.st_mode) == 0o700
             and identity(info) == identity(os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)),
             'new_private_home_directory')
        self.directories[path] = (row, identity(info)[:5])
        self.check()

    def write(self, path, raw):
        self.check()
        need(path.parent in self.directories and path.parent != HOME
             and isinstance(raw, bytes) and len(raw) <= 1048576, 'finite_private_new_file')
        parent = self.directories[path.parent][0]
        row = open_fd(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, dir_fd=parent['fd'])
        try:
            before = os.fstat(row['fd'])
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
                 and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600,
                 'new_private_file_metadata')
            write_all(row['fd'], raw)
            os.fsync(row['fd'])
            os.fsync(parent['fd'])
            after = os.fstat(row['fd'])
            need(identity(after) == identity(os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False))
                 and identity(before)[:6] == identity(after)[:6] and after.st_size == len(raw),
                 'new_private_file_generation')
        finally:
            close_fd(row)
        self.check()

    def public_certificate(self, path):
        self.check()
        need(path == CUSTODY / 'pki/ca.crt', 'only_public_ca_read')
        row = open_fd(path.name, os.O_RDONLY | os.O_NONBLOCK, dir_fd=self.directories[path.parent][0]['fd'])
        try:
            before = os.fstat(row['fd'])
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_nlink == 1
                 and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 16384,
                 'private_custody_public_certificate')
            raw = os.read(row['fd'], 16385)
            need(len(raw) == before.st_size and identity(before) == identity(os.fstat(row['fd']))
                 == identity(path.lstat()), 'whole_public_ca_generation')
            return raw
        finally:
            close_fd(row)

def key_metadata(path):
    info = path.lstat()
    need(path in (CUSTODY / 'pki/ca.key', ROOT / 'tls/server.key') and path.resolve(strict=True) == path
         and stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
         and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
         and 0 < info.st_size <= 16384, 'new_private_key_metadata_only')
    return {'owner': 501, 'group': 20, 'mode': '0600', 'regularSingleLink': True}

def sync_generated_file(path):
    allowed = (CUSTODY / 'pki/ca.key', CUSTODY / 'pki/ca.crt', ROOT / 'tls/server.key',
               ROOT / 'tls/server.csr', ROOT / 'tls/server.crt')
    need(path in allowed and path.resolve(strict=True) == path, 'fixed_generated_file_to_sync')
    row = open_fd(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
             and 0 < before.st_size <= 16384 and identity(before) == identity(path.lstat()),
             'exact_generated_file_before_sync')
        # In particular, private key bytes and digests are never read here.
        os.fsync(row['fd'])
        need(identity(before) == identity(os.fstat(row['fd'])) == identity(path.lstat()),
             'same_generated_file_after_sync')
    finally:
        close_fd(row)
    directory = open_fd(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory['fd'])
    finally:
        close_fd(directory)

def main():
    os.umask(0o077)
    guard = home = commands = signals = None
    code_before = {}
    try:
        need(sys.platform == 'darwin' and os.getuid() == 501 and os.getgid() == 20
             and Path(sys.executable).resolve(strict=True) == PYTHON, 'exact_mac_owner_and_interpreter')
        need(set(PAYLOAD) == {'sources', 'pins', 'plan'} and len(PAYLOAD['sources']) == 4,
             'four_fixed_public_libraries')
        for name, source in PAYLOAD['sources'].items():
            raw = source.encode()
            need(name in PAYLOAD['pins'] and len(raw) == PAYLOAD['pins'][name]['bytes']
                 and hashlib.sha256(raw).hexdigest() == PAYLOAD['pins'][name]['sha256'],
                 'whole_reviewed_library_pin')
            ast.parse(source)
        for name in ('mac_owned_unreaped_r1.py', 'mac_owned_commands_r1.py',
                     'mac_public_code_pin_excerpt_r1.py', 'mac_production_t5_guard_r1.py'):
            module = types.ModuleType(Path(name).stem)
            module.__file__ = str(ROOT / 'source' / name)
            sys.modules[module.__name__] = module
            exec(compile(PAYLOAD['sources'][name], module.__file__, 'exec'), module.__dict__)
        from mac_owned_commands_r1 import Signals, Commands
        from mac_public_code_pin_excerpt_r1 import public_code_pin
        from mac_production_t5_guard_r1 import HeldT5
        signals = Signals()
        signals.install()
        commands = Commands(signals)
        for path, expected in TOOL_PINS.items():
            actual = public_code_pin(path, remaining=remaining, critical=signals.critical)
            CODE_PIN_COMPLETIONS.append({'path': path, 'phase': 'before', 'originalDescriptorClosedBeforeReturn': True})
            need((actual['bytes'], actual['sha256']) == expected, 'exact_current_native_tool_pin')
            code_before[path] = actual
        for path in (ROOT, CUSTODY, BACKUPS):
            need(not path.exists() and not path.is_symlink(), 'every_new_stage_root_absent')
        need(not (HOME / 'Library/LaunchAgents/org.heptabao.authbus.plist').exists()
             and not (HOME / 'Library/LaunchAgents/org.heptabao.authbus.plist').is_symlink(),
             'proposed_registration_path_still_absent')
        anchor = {'schema': 'heptabao.mac-current-t5-public-anchor.r1',
                  'source_inventory_sha256': hashlib.sha256(encoded(PAYLOAD['pins'])).hexdigest(),
                  'volumeUUID': 'FB804D1B-24CB-4D6E-AEA7-A9E180807758',
                  'expectedVolumeDevice': str(Path('/Volumes/T5').lstat().st_dev),
                  'anchors': [{'path': path, 'identity': list(identity(Path(path).lstat()))}
                              for path in ('/', '/Volumes', '/Volumes/T5')]}
        anchor_raw = encoded(anchor)
        guard = HeldT5(anchor_raw, hashlib.sha256(anchor_raw).hexdigest(), remaining, signals.critical)
        row, out, err = commands.run('fixed-t5-volume', ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
                                    until=min(UNTIL, time.monotonic() + 15), maximum=262144)
        need(row['exitCode'] == 0 and not row['outcomeUnknown'] and not err, 'known_actual_t5_volume')
        guard.accept_diskutil(out)
        home = HomeTrees()
        need(os.fstat(home.home['fd']).st_dev != int(anchor['expectedVolumeDevice']),
             'data_and_backup_distinct_filesystems')
        for path in (CUSTODY, CUSTODY / 'pki', CUSTODY / 'operations', BACKUPS):
            home.mkdir(path)
        home.write(CUSTODY / 'deployment-plan.private.json', encoded(PAYLOAD['plan']))
        for part in ('', 'releases', 'releases/' + PRODUCT, 'etc', 'data', 'tls', 'log', 'service', 'source'):
            guard.mkdir_new(ROOT / part)
        guard.write_new(ROOT / 'source/public-source-pins.json', encoded(PAYLOAD['pins']))
        for name, source in PAYLOAD['sources'].items():
            guard.write_new(ROOT / 'source' / name, source.encode())
        binary = ROOT / 'releases' / PRODUCT / 'heptabao-server'
        original = open_fd(SOURCE, os.O_RDONLY | os.O_NONBLOCK)
        try:
            before = os.fstat(original['fd'])
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_nlink == 1
                 and stat.S_IMODE(before.st_mode) == 0o700 and before.st_size == BIN_BYTES
                 and identity(before) == identity(SOURCE.lstat()), 'qualified_normal_source_binary')
            with guard.parent(binary) as (parent, name):
                target = open_fd(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, dir_fd=parent)
                try:
                    digest, count = hashlib.sha256(), 0
                    while True:
                        remaining()
                        block = os.read(original['fd'], 1048576)
                        if not block:
                            break
                        count += len(block)
                        need(count <= BIN_BYTES, 'normal_binary_copy_bound')
                        digest.update(block)
                        write_all(target['fd'], block)
                    need(count == BIN_BYTES and digest.hexdigest() == BIN_SHA
                         and identity(before) == identity(os.fstat(original['fd'])) == identity(SOURCE.lstat()),
                         'whole_qualified_source_binary_unchanged')
                    os.fchmod(target['fd'], 0o500)
                    os.fsync(target['fd'])
                    os.fsync(parent)
                    after = os.fstat(target['fd'])
                    need(after.st_uid == 501 and after.st_nlink == 1 and stat.S_IMODE(after.st_mode) == 0o500
                         and after.st_size == BIN_BYTES
                         and identity(after) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                         'new_normal_binary_generation')
                    os.lseek(target['fd'], 0, os.SEEK_SET)
                    copied_digest, copied_count = hashlib.sha256(), 0
                    while True:
                        remaining()
                        copied = os.read(target['fd'], 1048576)
                        if not copied:
                            break
                        copied_count += len(copied)
                        need(copied_count <= BIN_BYTES, 'bounded_copied_binary_readback')
                        copied_digest.update(copied)
                    need(copied_count == BIN_BYTES and copied_digest.hexdigest() == BIN_SHA
                         and identity(after) == identity(os.fstat(target['fd']))
                         == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                         'entire_new_normal_binary_readback')
                finally:
                    close_fd(target)
        finally:
            close_fd(original)
        ca_config = b'[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\nCN=HeptaBao AuthBus Independent CA\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n'
        leaf_config = b'[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=server\n[dn]\nCN=MacBook-Pro.local\n[server]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:MacBook-Pro.local,DNS:localhost,IP:192.168.0.8,IP:127.0.0.1,IP:10.77.0.3,IP:100.77.61.24\n'
        home.write(CUSTODY / 'pki/ca.cnf', ca_config)
        guard.write_new(ROOT / 'tls/server.cnf', leaf_config)
        serial = '0x' + os.urandom(16).hex()
        argv = [
            ('new-independent-ca', ['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '3650', '-config', str(CUSTODY / 'pki/ca.cnf'), '-keyout', str(CUSTODY / 'pki/ca.key'), '-out', str(CUSTODY / 'pki/ca.crt')]),
            ('new-server-key-csr', ['/usr/bin/openssl', 'req', '-new', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-config', str(ROOT / 'tls/server.cnf'), '-keyout', str(ROOT / 'tls/server.key'), '-out', str(ROOT / 'tls/server.csr')]),
            ('sign-new-server-certificate', ['/usr/bin/openssl', 'x509', '-req', '-in', str(ROOT / 'tls/server.csr'), '-CA', str(CUSTODY / 'pki/ca.crt'), '-CAkey', str(CUSTODY / 'pki/ca.key'), '-set_serial', serial, '-days', '365', '-sha256', '-extfile', str(ROOT / 'tls/server.cnf'), '-extensions', 'server', '-out', str(ROOT / 'tls/server.crt')]),
            ('verify-new-certificate-chain', ['/usr/bin/openssl', 'verify', '-CAfile', str(CUSTODY / 'pki/ca.crt'), str(ROOT / 'tls/server.crt')]),
        ]
        for ordinal, (label, command) in enumerate(argv):
            home.check()
            guard.check()
            outputs = {0: (CUSTODY / 'pki/ca.key', CUSTODY / 'pki/ca.crt'),
                       1: (ROOT / 'tls/server.key', ROOT / 'tls/server.csr'),
                       2: (ROOT / 'tls/server.crt',), 3: ()}[ordinal]
            need(all(not path.exists() and not path.is_symlink() for path in outputs),
                 'original_crypto_output_names_absent')
            home.write(CUSTODY / 'operations' / ('%02d-intent.private.json' % ordinal), encoded({'label': label, 'argv': command, 'status': 'dispatched_or_unknown'}))
            row, out, err = commands.run(label, command, until=min(UNTIL, time.monotonic() + 30), maximum=262144)
            home.write(CUSTODY / 'operations' / ('%02d-completion.private.json' % ordinal), encoded(row))
            need(row['exitCode'] == 0 and not row['outcomeUnknown'], 'original_crypto_command_known_complete')
            home.check()
            guard.check()
        for generated in (CUSTODY / 'pki/ca.key', CUSTODY / 'pki/ca.crt', ROOT / 'tls/server.key',
                          ROOT / 'tls/server.csr', ROOT / 'tls/server.crt'):
            sync_generated_file(generated)
        report['generatedKeyAndCertificateFilesSyncedWithoutReadingPrivateKeys'] = 5
        report['privateKeyMetadata'] = {'ca': key_metadata(CUSTODY / 'pki/ca.key'), 'server': key_metadata(ROOT / 'tls/server.key')}
        ca = home.public_certificate(CUSTODY / 'pki/ca.crt')
        leaf = guard.read(ROOT / 'tls/server.crt', 16384)
        ca_der = ssl.PEM_cert_to_DER_cert(ca.decode('ascii'))
        leaf_der = ssl.PEM_cert_to_DER_cert(leaf.decode('ascii'))
        guard.write_new(ROOT / 'tls/ca.crt', ca)
        config = {'listen': '192.168.0.8:31080', 'data_dir': str(ROOT / 'data'),
                  'audit_file': str(ROOT / 'log/audit.jsonl'), 'tls_cert_file': str(ROOT / 'tls/server.crt'),
                  'tls_key_file': str(ROOT / 'tls/server.key'), 'max_connections': 64, 'timeout_seconds': 15,
                  'rate_limit_per_second': 2000, 'rate_limit_burst': 4000, 'rate_limit_entries': 512,
                  'storage': {'native_v6_file': {'path': str(ROOT / 'data')}}}
        guard.write_new(ROOT / 'etc/server.json', encoded(config))
        bootstrap = dict(config, listen='127.0.0.1:31080')
        guard.write_new(ROOT / 'etc/server-bootstrap.json', encoded(bootstrap))
        for name in ('server.stdout.log', 'server.stderr.log'):
            guard.write_new(ROOT / 'log' / name, b'')
        plist = {'Label': 'org.heptabao.authbus', 'ProgramArguments': [str(binary), '--config', str(ROOT / 'etc/server.json')],
                 'WorkingDirectory': str(ROOT), 'EnvironmentVariables': {'HOME': str(HOME), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'},
                 'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 10, 'ExitTimeOut': 30, 'Umask': 0o077,
                 'StandardOutPath': str(ROOT / 'log/server.stdout.log'), 'StandardErrorPath': str(ROOT / 'log/server.stderr.log')}
        guard.write_new(ROOT / 'service/org.heptabao.authbus.plist', plistlib.dumps(plist, sort_keys=True))
        report['staged'] = {'normalBinarySha256': BIN_SHA, 'normalBinaryBytes': BIN_BYTES,
                            'newCaDerSha256': hashlib.sha256(ca_der).hexdigest(),
                            'newLeafDerSha256': hashlib.sha256(leaf_der).hexdigest(),
                            'certificateChainVerified': True, 'servicePlistInstalled': False,
                            'bootstrapConfigOnlyLoopback': True, 'plannedClientAddress': 'https://192.168.0.8:31080',
                            'independentRootTrustCreated': True, 'dataBackupDifferentFilesystems': True}
        for path in TOOL_PINS:
            current = public_code_pin(path, remaining=remaining, critical=signals.critical)
            CODE_PIN_COMPLETIONS.append({'path': path, 'phase': 'after', 'originalDescriptorClosedBeforeReturn': True})
            need(current == code_before[path],
                 'original_native_tools_unchanged')
        home.check()
        guard.check()
        report['toolPins'] = {path: {'bytes': value[0], 'sha256': value[1]} for path, value in TOOL_PINS.items()}
        home.write(CUSTODY / 'staging-complete.private.json', encoded(report['staged']))
        report['ok'] = True
    except BaseException as error:
        report['errorClass'] = type(error).__name__
        report['errorCode'] = str(error) if isinstance(error, RuntimeError) else 'create_only_stage_failed'
    finally:
        if guard is not None:
            try:
                guard.close()
            except BaseException:
                report['ok'] = False
            report['volumeClosure'] = guard.public_state()
        close_errors = []
        for row in reversed(FDS):
            try:
                close_fd(row)
            except BaseException as error:
                close_errors.append(type(error).__name__)
        report['allExplicitDescriptorsClosedOnce'] = all(row['closeAttempts'] == 1 and row['closed'] for row in FDS)
        report['explicitDescriptorCount'] = len(FDS)
        report['descriptorCloseErrors'] = close_errors
        report['publicCodePinCompletions'] = CODE_PIN_COMPLETIONS
        report['commands'] = commands.public() if commands is not None else {'commands': [], 'allOwnedCommandsStopped': True, 'unknownCommandCount': 0}
        report['ok'] = bool(report['ok'] and report['allExplicitDescriptorsClosedOnce'] and not close_errors
                            and report.get('volumeClosure', {}).get('allDescriptorsClosed')
                            and report.get('volumeClosure', {}).get('lastAnchorCheckPassed')
                            and not report.get('volumeClosure', {}).get('closeErrors')
                            and report['commands']['allOwnedCommandsStopped']
                            and report['commands']['unknownCommandCount'] == 0)
        report['elapsedSeconds'] = time.monotonic() - START
        print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
