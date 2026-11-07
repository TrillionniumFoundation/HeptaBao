#!/usr/bin/env python3
"""Qualify the frozen coordinator against a new normal HeptaBao TLS fixture.

All OAuth payloads are synthetic. The only AppRole/root/unseal material is newly
created in this private fixture. No live AuthBus client, SDK profile, production
service registration, provider, J3160, or existing HeptaBao data is touched.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
import types

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/fixed-slot-coordinator-normal-20261107-r1')
CALLER_HOME = Path('/Users/qianqi')
CLIENT_ROOT = CALLER_HOME / 'heptabao-fixed-slot-coordinator-normal-20261107-r1'
CUSTODY = CLIENT_ROOT
OPERATIONS = CUSTODY / 'custody'
CODE = CLIENT_ROOT / 'code'
STATE = CLIENT_ROOT / 'state'
PKI = CLIENT_ROOT / 'pki'
INPUT = CLIENT_ROOT / 'input'
RESULTS = CLIENT_ROOT / 'results'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
NODE = '/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
PRODUCT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
BINARY = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production/releases') / PRODUCT / 'heptabao-server'
BINARY_BYTES = 92359328
BINARY_SHA = '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
IMPLEMENTATION = '248057b53a13708cc0650b73c83bc86729a7572e0d1bf24768ea94b8d3fd8265'
OWNER = '5c2073c4-7a2f-4542-9d96-ddcf35aa33f3'
EPOCH = 'f84a000c-fdbb-49bd-9733-8eb91d420268'
HOST = 'qualified-mac'
PORT = 31126
CONFIG = ROOT / 'server.json'
WORKER = CODE / 'mac_coordinator_actual_worker_r1.mjs'
SANDBOX = INPUT / 'worker.sb'
TOOL_PINS = {
    str(PYTHON): (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    '/usr/sbin/diskutil': (1937776, '624a8601b97ddfaa4b18dd2854c299e084cd45eb18fc152011c97615c3b9da1f'),
    '/bin/ps': (170432, '3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'),
    '/usr/bin/openssl': (1130832, 'f81b4fcec5048ea1eceb40fc08f4e06f1668181f0b5bacfa8be27d0da181dcb7'),
    '/usr/bin/sandbox-exec': 'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a',
    NODE: 'a46ed02589ca3af795237111ff854262064f8ff5c5b58d75c1509f37311eb15e',
}
# PAYLOAD_PLACEHOLDER
START = time.monotonic()
UNTIL = START + 600
FDS = []
CONTROL_SIGNALS = None
REPORT = {'schema': 'heptabao.fixed-slot-normal-qualification.r1', 'ok': False,
    'productCommit': PRODUCT, 'productBinarySha256': BINARY_SHA,
    'coordinatorImplementationSha256': IMPLEMENTATION, 'syntheticCredentialsOnly': True,
    'currentCredentialReads': 0, 'providerCalls': 0, 'productionClientChanges': 0,
    'launchAgentInstalled': False, 'legacyChanges': 0, 'j3160Requests': 0,
    'rootKeyValuesOrDigestsPublished': False, 'productionCutoverQualified': False,
    'parentSeconds': 600, 'nodePhaseSeconds': 120, 'eachApiPhaseSeconds': 120,
    'supervisorSeconds': 630, 'automaticRetry': False,
    'networkResponseLossSimulated': False, 'localReceiptInterruptionOnly': True,
    'serverProcesses': [], 'apiPhases': [], 'nodePhases': [], 'nodeBusinessOutcomeUnknown': False,
    'kernelLocalSinglePortIsNotIpv4Only': True, 'strictClientFixedIpv4Endpoint': True}

class Refused(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def remaining():
    need(CONTROL_SIGNALS is None or CONTROL_SIGNALS.pending is None, 'bootstrap_cancelled')
    value = UNTIL - time.monotonic()
    need(value > 0, 'bootstrap_original_parent_deadline')
    return value

def full9(value):
    return tuple(str(getattr(value, name)) for name in ('st_dev', 'st_ino', 'st_uid',
        'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def own(fd, label):
    row = {'fd': fd, 'label': label, 'attempts': 0, 'closed': False}
    FDS.append(row)
    return row

def close(row):
    if row['attempts']:
        return
    row['attempts'] = 1
    os.close(row['fd'])
    row['closed'] = True

def open_fd(path, flags, label, *, dir_fd=None):
    remaining()
    return own(os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
        0o600, **({} if dir_fd is None else {'dir_fd': dir_fd})), label)

class PrivateOperations:
    def __init__(self):
        self.counter = 0
        self.dirs = []
        previous = None
        for path in (Path('/'), Path('/Users'), CALLER_HOME, CUSTODY):
            row = open_fd(path if previous is None else path.name, os.O_RDONLY | os.O_DIRECTORY,
                          'private-parent', dir_fd=None if previous is None else previous['fd'])
            info = os.fstat(row['fd'])
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == (0 if path in (Path('/'), Path('/Users')) else 501)
                 and not info.st_mode & 0o022 and full9(info) == full9(path.lstat()), 'bootstrap_private_parent')
            if path == CUSTODY:
                need(stat.S_IMODE(info.st_mode) == 0o700, 'bootstrap_custody_private')
            self.dirs.append((path, row, full9(info)[:5]))
            previous = row
        self.check()
        os.mkdir(OPERATIONS.name, 0o700, dir_fd=previous['fd'])
        os.fsync(previous['fd'])
        self.root = open_fd(OPERATIONS.name, os.O_RDONLY | os.O_DIRECTORY, 'operation-directory', dir_fd=previous['fd'])
        info = os.fstat(self.root['fd'])
        need(info.st_uid == 501 and info.st_gid == 20 and stat.S_IMODE(info.st_mode) == 0o700,
             'bootstrap_new_operation_directory')
        self.dirs.append((OPERATIONS, self.root, full9(info)[:5]))
        self.check()

    def check(self):
        remaining()
        for path, row, identity in self.dirs:
            need(full9(os.fstat(row['fd']))[:5] == full9(path.lstat())[:5] == identity,
                 'bootstrap_same_private_parent')

    def create(self, name):
        self.check()
        need(re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,120}', name), 'bootstrap_fixed_private_name')
        row = open_fd(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, name, dir_fd=self.root['fd'])
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600,
             'bootstrap_private_new_regular_file')
        os.fsync(row['fd']); os.fsync(self.root['fd'])
        return row

    def write(self, name, raw):
        need(isinstance(raw, bytes) and len(raw) <= 1048576, 'bootstrap_private_body_bound')
        row = self.create(name)
        try:
            start = full9(os.fstat(row['fd']))[:6]
            offset = 0
            while offset < len(raw):
                remaining()
                count = os.write(row['fd'], raw[offset:offset + 65536])
                need(count > 0, 'bootstrap_private_write_progress')
                offset += count
            os.fsync(row['fd']); os.fsync(self.root['fd'])
            after = os.fstat(row['fd'])
            need(full9(after)[:6] == start and after.st_size == len(raw)
                 and full9(after) == full9(os.stat(name, dir_fd=self.root['fd'], follow_symlinks=False)),
                 'bootstrap_private_write_generation')
        finally:
            close(row)
        self.check()

    def append(self, category, value):
        need(self.counter < 512 and category in ('api-request-intent', 'api-request-result',
             'server-start-intent', 'server-stop-result', 'bootstrap-recovery',
             'crypto-intent', 'crypto-result', 'node-request-intent', 'node-request-result'), 'bootstrap_finite_journal')
        self.write('event-%04d.private.json' % self.counter, encoded({'category': category, 'value': value}))
        self.counter += 1

    def response_bytes(self, phase, ordinal, raw):
        need(phase in ('initial', 'cold-new-process') and 1 <= ordinal <= 192, 'bootstrap_exact_response_slot')
        self.write('%s-%03d.response.private.bin' % (phase, ordinal), raw)


def new_home_root():
    """Create one private fixture under the named, held protected HOME."""
    ancestors = []
    parent = None
    try:
        for path in (Path('/'), Path('/Users'), CALLER_HOME):
            row = open_fd(path if parent is None else path.name, os.O_RDONLY | os.O_DIRECTORY,
                          'fixture-home-parent', dir_fd=None if parent is None else parent['fd'])
            info = os.fstat(row['fd'])
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == (501 if path == CALLER_HOME else 0)
                 and not info.st_mode & 0o022 and full9(info) == full9(path.lstat()), 'fixture_protected_home_chain')
            ancestors.append((path, row, full9(info)[:5]))
            parent = row
        os.mkdir(CLIENT_ROOT.name, 0o700, dir_fd=parent['fd'])
        os.fsync(parent['fd'])
        for path, row, expected in ancestors:
            need(full9(os.fstat(row['fd']))[:5] == full9(path.lstat())[:5] == expected, 'fixture_home_chain_after_create')
    finally:
        errors = []
        for _path, row, _expected in reversed(ancestors):
            try:
                close(row)
            except BaseException:
                errors.append('home_parent_close')
        need(not errors, 'fixture_home_parent_closure')


class FixtureFiles:
    """Held HOME fixture directories and complete, create-only regular files."""
    def __init__(self, operations):
        self.operations = operations
        self.directories = {}
        self.protected = {}
        self._hold(CLIENT_ROOT)

    def _hold(self, path):
        row = open_fd(path, os.O_RDONLY | os.O_DIRECTORY, 'fixture-directory')
        info = os.fstat(row['fd'])
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
             and stat.S_IMODE(info.st_mode) == 0o700 and full9(info) == full9(path.lstat()), 'fixture_owned_directory')
        self.directories[path] = (row, full9(info)[:5])

    def check(self):
        self.operations.check()
        for path, (row, expected) in self.directories.items():
            need(full9(os.fstat(row['fd']))[:5] == full9(path.lstat())[:5] == expected, 'fixture_held_directory_identity')
        for path, expected in self.protected.items():
            need(full9(path.lstat()) == expected, 'fixture_protected_source_generation')

    def mkdir(self, path):
        self.check()
        need(path.parent in self.directories and path not in self.directories, 'fixture_finite_directory_parent')
        parent = self.directories[path.parent][0]
        os.mkdir(path.name, 0o700, dir_fd=parent['fd'])
        os.fsync(parent['fd'])
        self._hold(path)
        self.check()

    def create(self, path):
        self.check()
        need(path.parent in self.directories and path not in self.protected, 'fixture_new_file_parent')
        parent = self.directories[path.parent][0]
        row = open_fd(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 'fixture-new-file', dir_fd=parent['fd'])
        info = os.fstat(row['fd'])
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
             and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, 'fixture_new_file_custody')
        os.fsync(row['fd']); os.fsync(parent['fd'])
        return row

    def write(self, path, raw, *, public=False):
        need(isinstance(raw, bytes) and 0 < len(raw) <= 1048576, 'fixture_file_write_bound')
        row = self.create(path)
        parent = self.directories[path.parent][0]
        try:
            original = full9(os.fstat(row['fd']))[:6]
            offset = 0
            while offset < len(raw):
                remaining()
                count = os.write(row['fd'], raw[offset:offset + 65536])
                need(count > 0, 'fixture_file_write_progress')
                offset += count
            os.fsync(row['fd']); os.fsync(parent['fd'])
            held = os.fstat(row['fd'])
            need(full9(held)[:6] == original and held.st_size == len(raw)
                 and full9(held) == full9(path.lstat()), 'fixture_written_same_file')
            os.lseek(row['fd'], 0, os.SEEK_SET)
            seen = bytearray()
            while len(seen) <= len(raw):
                block = os.read(row['fd'], min(65536, len(raw) + 1 - len(seen)))
                if not block:
                    break
                seen.extend(block)
            need(bytes(seen) == raw and full9(held) == full9(os.fstat(row['fd'])) == full9(path.lstat()),
                 'fixture_complete_written_readback')
            self.protected[path] = full9(held)
            return {'bytes': len(raw), **({'sha256': hashlib.sha256(raw).hexdigest()} if public else {})}
        finally:
            close(row)

    def adopt_crypto_output(self, path, *, key=False):
        """Generated keys are fsynced and identity-bound without reading/hashing."""
        self.check()
        need(path.parent == PKI and path not in self.protected, 'fixture_fixed_crypto_output')
        parent = self.directories[PKI][0]
        row = open_fd(path.name, os.O_RDWR, 'generated-private-key' if key else 'generated-public-certificate', dir_fd=parent['fd'])
        try:
            info = os.fstat(row['fd'])
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20 and info.st_nlink == 1
                 and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 16384
                 and full9(info) == full9(path.lstat()), 'fixture_generated_crypto_file_custody')
            os.fsync(row['fd']); os.fsync(parent['fd'])
            need(full9(info) == full9(os.fstat(row['fd'])) == full9(path.lstat()), 'fixture_generated_crypto_generation')
            self.protected[path] = full9(info)
            if key:
                return None
            raw = os.read(row['fd'], 16385)
            need(len(raw) == info.st_size and not os.read(row['fd'], 1)
                 and full9(info) == full9(os.fstat(row['fd'])) == full9(path.lstat()), 'fixture_public_certificate_whole_read')
            return raw
        finally:
            close(row)

    def read_generated_result(self, path):
        self.check()
        need(path == RESULTS / 'initial-state.private.json', 'fixture_only_generated_private_state')
        row = open_fd(path.name, os.O_RDONLY, 'original-generated-state', dir_fd=self.directories[RESULTS][0]['fd'])
        try:
            before = os.fstat(row['fd'])
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20 and before.st_nlink == 1
                 and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 1048576, 'fixture_generated_state_custody')
            raw = bytearray()
            while len(raw) <= 1048576:
                part = os.read(row['fd'], min(65536, 1048577 - len(raw)))
                if not part:
                    break
                raw.extend(part)
            need(len(raw) == before.st_size and full9(before) == full9(os.fstat(row['fd'])) == full9(path.lstat()),
                 'fixture_generated_state_exact_generation')
            return json.loads(raw)
        finally:
            close(row)


def binary_pin(volume):
    """Whole pinned public executable, with held component-by-component names."""
    volume.check()
    rows, parents = [], []
    previous = volume.anchors[-1]
    try:
        for path in list(BINARY.parents)[:4][::-1]:
            need(path.is_relative_to(Path('/Volumes/T5')) and path != Path('/Volumes/T5'), 'fixture_binary_parent_scope')
            named = os.stat(path.name, dir_fd=previous['fd'], follow_symlinks=False)
            need(stat.S_ISDIR(named.st_mode) and named.st_uid == 501 and named.st_gid == 20
                 and not named.st_mode & 0o022 and named.st_dev == int(volume.expected['expectedVolumeDevice']),
                 'fixture_binary_parent_custody')
            row = open_fd(path.name, os.O_RDONLY | os.O_DIRECTORY, 'public-binary-parent', dir_fd=previous['fd'])
            rows.append(row)
            need(full9(os.fstat(row['fd'])) == full9(named), 'fixture_binary_held_parent')
            parents.append((path, row, full9(named)))
            previous = row
        row = open_fd(BINARY.name, os.O_RDONLY, 'fixed-normal-binary', dir_fd=previous['fd'])
        rows.append(row)
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20 and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o500 and before.st_size == BINARY_BYTES, 'fixture_normal_binary_metadata')
        digest, count = hashlib.sha256(), 0
        while count <= BINARY_BYTES:
            remaining()
            raw = os.read(row['fd'], min(1048576, BINARY_BYTES + 1 - count))
            if not raw:
                break
            count += len(raw); digest.update(raw)
        need(count == BINARY_BYTES and digest.hexdigest() == BINARY_SHA
             and full9(before) == full9(os.fstat(row['fd'])) == full9(BINARY.lstat()), 'fixture_exact_normal_binary')
        for path, held, expected in parents:
            need(full9(os.fstat(held['fd'])) == full9(path.lstat()) == expected, 'fixture_binary_parent_unchanged')
        volume.check()
        return {'file': full9(before), 'parents': [(str(path), expected) for path, _held, expected in parents]}
    finally:
        errors = []
        for row in reversed(rows):
            try:
                close(row)
            except BaseException:
                errors.append('binary_fd_close')
        need(not errors, 'fixture_binary_all_original_fds_closed')


def node_sandbox():
    """The qualified local-one-port rule plus the original strict IPv4 client."""
    literals = {CALLER_HOME, Path('/Users'), Path('/'), CLIENT_ROOT, CODE, INPUT, PKI, STATE, RESULTS}
    for path in (WORKER, INPUT / 'initial-plan.private.json', INPUT / 'cold-plan.private.json'):
        literals.update(path.parents)
    lines = ['(version 1)', '(deny default)', '(allow process*)', '(allow signal (target children))',
        '(allow sysctl-read)', '(allow mach-lookup)', '(allow file-read-metadata)',
        '(allow file-read* (subpath "/System") (subpath "/usr") (subpath "/bin") (subpath "/sbin")'
        ' (subpath "/Library") (subpath "/private/etc") (subpath "/opt/homebrew") (subpath "/dev/fd"))']
    lines.extend('(allow file-read* (literal ' + json.dumps(str(path)) + '))' for path in sorted(literals, key=str))
    lines.extend(['(allow file-read* (subpath ' + json.dumps(str(CODE)) + ') (subpath ' + json.dumps(str(INPUT)) + ')'
                  ' (literal ' + json.dumps(str(PKI / 'ca.crt')) + '))',
        '(allow file-read* file-write* (subpath ' + json.dumps(str(STATE)) + ') (subpath ' + json.dumps(str(RESULTS)) + '))',
        '(allow file-read* (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom"))',
        '(allow file-write* (literal "/dev/null"))',
        '(allow network-outbound (remote tcp "localhost:' + str(PORT) + '"))'])
    return ('\n'.join(lines) + '\n').encode()


def public_command(row):
    # Even a failed Node diagnostic can contain secrets. No stream digest or
    # arbitrary argv/error text is exported from the original command receipt.
    return {key: row[key] for key in ('label', 'pid', 'exitCode', 'completeBeforeDeadline',
        'commandDeadlineMonotonic', 'elapsedSeconds', 'cleanup', 'stdoutBytes', 'stderrBytes',
        'streamsClosed', 'outcomeUnknown')}


def validate_worker_report(value, phase):
    need(isinstance(value, dict) and value.get('schema') == 'heptabao.fixed-slot-actual-worker.r1'
         and value.get('phase') == phase and value.get('ok') is True
         and value.get('sourceImplementationSha256') == IMPLEMENTATION, 'fixture_actual_worker_schema')
    need(value.get('syntheticCredentialsOnly') is True and value.get('actualNormalHeptaBao') is True
         and value.get('sdkImported') is False and value.get('j3160Contacted') is False
         and all(type(value.get(k)) is int and value[k] == 0 for k in
             ('productionCredentialReads', 'providerCalls', 'productionActions', 'childProcessAttempts', 'unexpectedConsoleCalls')),
         'fixture_worker_exact_effect_scope')
    need(value.get('networkResponseLossSimulated') is False and value.get('completedWithinOriginalPhase') is True
         and value.get('localReceiptInterruptionInjected') is (phase == 'initial')
         and value.get('originalOperationPendingForColdReconciliation') is (phase == 'initial'), 'fixture_worker_interruption_scope')
    need(value.get('closureFailures') == [] and value.get('sqlite', {}).get('allOriginalHandlesClosedOnce') is True
         and value.get('explicitFiles', {}).get('allOriginalExplicitDescriptorsClosedOnce') is True, 'fixture_worker_original_handle_closure')
    wire = value.get('wire', {})
    need(all(wire.get(k) is True for k in ('allOriginalRequestsClosed', 'allDispatchedResponsesComplete',
         'allOriginalSocketsClosed', 'allDispatchedTlsVerified')) and wire.get('deniedOtherNetwork') == 0,
         'fixture_worker_complete_original_wire')
    need(value.get('kernelSandbox') == {'readDenied': True, 'writeDenied': True, 'otherLoopbackDenied': True,
         'originalProbeSocketClosed': True, 'productionFileProbed': False}, 'fixture_worker_actual_kernel_boundaries')
    need(isinstance(value.get('checks'), list) and value['checks'] and all(
         set(row) == {'case', 'passed'} and row['passed'] is True and re.fullmatch(r'[a-z0-9._-]{1,110}', row['case'])
         for row in value['checks']), 'fixture_worker_all_actual_cases')
    # Only success with the fully frozen worker report is exported. Failure
    # streams remain private and cannot be used as a new request authorization.
    return value


def main():
    global CONTROL_SIGNALS
    os.umask(0o077); sys.dont_write_bytecode = True
    volume = operations = commands = signals = files = None
    current = None
    process_rows, apis, sensitive = [], [], []
    tools_before = {}
    try:
        need(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 501 and os.getgid() == 20
             and Path(sys.executable).resolve(strict=True) == PYTHON, 'fixture_exact_mac_owner_runtime')
        for name, source in PAYLOAD['sources'].items():
            raw = source.encode()
            need(len(raw) == PAYLOAD['pins'][name]['bytes'] and hashlib.sha256(raw).hexdigest() == PAYLOAD['pins'][name]['sha256'],
                 'fixture_complete_python_source_pin')
            ast.parse(source)
            module = types.ModuleType(Path(name).stem); module.__file__ = str(OPERATIONS / name)
            sys.modules[module.__name__] = module
            exec(compile(source, module.__file__, 'exec'), module.__dict__)
        from mac_owned_commands_r1 import Commands, Signals
        from mac_owned_unreaped_r1 import require_waitid, capture_child, stop_once_unreaped
        from mac_fixedslot_t5_guard_r1 import HeldT5
        from mac_public_code_pin_excerpt_r1 import public_code_pin
        from fixedslot_actual_api_r1 import Api
        signals = Signals(); signals.install(); CONTROL_SIGNALS = signals; commands = Commands(signals)
        for name, expected in TOOL_PINS.items():
            value = public_code_pin(name, remaining=remaining, critical=signals.critical)
            need(((value['bytes'], value['sha256']) == expected) if isinstance(expected, tuple)
                 else value['sha256'] == expected, 'fixture_exact_native_tool')
            tools_before[name] = value
        need(not ROOT.exists() and not ROOT.is_symlink() and not CLIENT_ROOT.exists() and not CLIENT_ROOT.is_symlink(),
             'fixture_create_only_new_roots')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(('127.0.0.1', PORT))
        anchor = {'schema': 'heptabao.mac-current-t5-public-anchor.r1',
            'source_inventory_sha256': hashlib.sha256(encoded(PAYLOAD['pins'])).hexdigest(),
            'volumeUUID': 'FB804D1B-24CB-4D6E-AEA7-A9E180807758',
            'expectedVolumeDevice': str(Path('/Volumes/T5').lstat().st_dev),
            'anchors': [{'path': p, 'identity': list(full9(Path(p).lstat()))} for p in ('/', '/Volumes', '/Volumes/T5')]}
        raw = encoded(anchor); volume = HeldT5(raw, hashlib.sha256(raw).hexdigest(), remaining, signals.critical)
        row, out, err = commands.run('fixedslot-t5-volume', ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
                                     until=min(UNTIL, time.monotonic() + 15), maximum=262144)
        need(type(row['exitCode']) is int and row['exitCode'] == 0 and not row['outcomeUnknown'] and not err, 'fixture_known_volume_observation')
        volume.accept_diskutil(out)
        new_home_root(); operations = PrivateOperations(); files = FixtureFiles(operations)
        for path in (CODE, CODE / 'transport', STATE, STATE / 'coordinator', STATE / 'producer', PKI, INPUT, RESULTS):
            files.mkdir(path)
        for path in (ROOT, ROOT / 'data', ROOT / 'log'):
            volume.mkdir_new(path)
        # Creating ROOT changes its known shared QA parent metadata. Freeze the
        # original executable's complete parent generations only after these
        # owned mkdir effects; no executable has been launched at this point.
        before_binary = binary_pin(volume)
        for name, source in PAYLOAD['sources'].items():
            operations.write(name, source.encode())
        operations.write('source-pins.public.json', encoded({'python': PAYLOAD['pins'], 'node': PAYLOAD['assetPins']}))
        need(len(PAYLOAD['assets']) == 11 and set(PAYLOAD['assets']) == set(PAYLOAD['assetPins']), 'fixture_exact_eleven_node_sources')
        for name, source in PAYLOAD['assets'].items():
            raw = source.encode(); pin = PAYLOAD['assetPins'][name]
            need(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256']
                 and not Path(name).is_absolute() and '..' not in Path(name).parts, 'fixture_node_original_source_pin')
            files.write(CODE / name, raw, public=True)
        for name in ('protected-read', 'protected-write'):
            files.write(CLIENT_ROOT / name, b'SYNTHETIC KERNEL DENIAL PROBE\n')
        files.write(SANDBOX, node_sandbox(), public=True)
        ca_configuration = b'''[req]
prompt=no
distinguished_name=dn
x509_extensions=ca
[dn]
CN=HeptaBao Fixed Slot Synthetic QA CA
[ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
'''
        csr_configuration = b'''[req]
prompt=no
distinguished_name=dn
[dn]
CN=localhost
'''
        leaf_extensions = b'''basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
subjectAltName=DNS:localhost,IP:127.0.0.1
'''
        for name, raw in (('ca.cnf', ca_configuration), ('csr.cnf', csr_configuration), ('leaf.ext', leaf_extensions)):
            files.write(PKI / name, raw, public=True)

        def crypto(label, argv, outputs):
            files.check(); volume.check()
            need(all(not (PKI / name).exists() and not (PKI / name).is_symlink() for name, _key in outputs), 'fixture_crypto_outputs_absent')
            operations.append('crypto-intent', {'label': label, 'argv': argv, 'newOutputs': [name for name, _key in outputs]})
            row, out, err = commands.run(label, argv, until=min(UNTIL, time.monotonic() + 30), maximum=262144)
            operations.write(label + '.stdout.private.bin', out); operations.write(label + '.stderr.private.bin', err)
            operations.append('crypto-result', row)
            need(type(row['exitCode']) is int and row['exitCode'] == 0 and not row['outcomeUnknown'], 'fixture_original_crypto_known_success')
            values = {}
            for name, key in outputs:
                values[name] = files.adopt_crypto_output(PKI / name, key=key)
            files.check(); volume.check()
            return values

        ca = crypto('fixedslot-new-ca', ['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '1',
            '-config', str(PKI / 'ca.cnf'), '-keyout', str(PKI / 'ca.key'), '-out', str(PKI / 'ca.crt')], [('ca.key', True), ('ca.crt', False)])['ca.crt']
        crypto('fixedslot-new-csr', ['/usr/bin/openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-config', str(PKI / 'csr.cnf'),
            '-keyout', str(PKI / 'server.key'), '-out', str(PKI / 'server.csr')], [('server.key', True), ('server.csr', False)])
        leaf = crypto('fixedslot-sign-leaf', ['/usr/bin/openssl', 'x509', '-req', '-in', str(PKI / 'server.csr'), '-CA', str(PKI / 'ca.crt'),
            '-CAkey', str(PKI / 'ca.key'), '-set_serial', '1', '-days', '1', '-sha256', '-extfile', str(PKI / 'leaf.ext'),
            '-out', str(PKI / 'server.crt')], [('server.crt', False)])['server.crt']
        crypto('fixedslot-verify-chain', ['/usr/bin/openssl', 'verify', '-CAfile', str(PKI / 'ca.crt'), str(PKI / 'server.crt')], [])
        ca_pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.decode('ascii'))).hexdigest()
        leaf_pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf.decode('ascii'))).hexdigest()
        REPORT['caCertificateDerSha256'] = ca_pin; REPORT['leafCertificateDerSha256'] = leaf_pin
        config = {'listen': '127.0.0.1:' + str(PORT), 'data_dir': str(ROOT / 'data'), 'audit_file': str(ROOT / 'log/audit.jsonl'),
            'tls_cert_file': str(PKI / 'server.crt'), 'tls_key_file': str(PKI / 'server.key'), 'max_connections': 64, 'timeout_seconds': 15,
            'rate_limit_per_second': 2000, 'rate_limit_burst': 4000, 'rate_limit_entries': 512,
            'storage': {'native_v6_file': {'path': str(ROOT / 'data')}}}
        config_receipt = volume.write_new(CONFIG, encoded(config))
        need(volume.read(CONFIG, 16384) == encoded(config), 'fixture_complete_server_config_readback')
        t5_directories = {path: full9(path.lstat())[:5] for path in (ROOT, ROOT / 'data', ROOT / 'log')}

        class BoundGuard:
            def check(self):
                volume.check(); files.check()
                need(full9(CONFIG.lstat()) == tuple(config_receipt['identity']), 'fixture_original_server_config_generation')
                need(full9(BINARY.lstat()) == before_binary['file'], 'fixture_original_normal_binary_generation')
                for path, identity in before_binary['parents']:
                    need(full9(Path(path).lstat()) == identity, 'fixture_original_binary_parents')
                for path, expected in t5_directories.items():
                    need(full9(path.lstat())[:5] == expected, 'fixture_original_t5_mutable_directory')
        fence = BoundGuard(); fence.check()

        def start_server(phase):
            nonlocal current
            need(current is None and len(process_rows) < 2 and phase in ('initial', 'cold-new-process'), 'fixture_two_original_server_starts')
            require_waitid(); fence.check()
            need(binary_pin(volume) == before_binary, 'fixture_binary_whole_recheck_before_exec')
            outputs = [operations.create(phase + '.' + label + '.private.log') for label in ('stdout', 'stderr')]
            intent = {'phase': phase, 'argv': [str(BINARY), '--config', str(CONFIG)], 'state': 'dispatched_or_unknown'}
            operations.append('server-start-intent', intent)
            current = {'phase': phase, 'process': None, 'custody': None, 'stopAttempted': False, 'outputs': outputs}
            process_rows.append(current)
            with signals.critical():
                p = subprocess.Popen(intent['argv'], cwd=str(ROOT), stdin=subprocess.DEVNULL,
                    stdout=outputs[0]['fd'], stderr=outputs[1]['fd'], start_new_session=True, close_fds=True,
                    env={'HOME': str(CALLER_HOME), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'})
                current['process'] = p
            current['custody'] = capture_child(p, until=min(UNTIL, time.monotonic() + 15))
            api = Api({'port': PORT, 'certificateLeafSha256': leaf_pin}, phase, min(UNTIL, time.monotonic() + 120), operations, fence)
            apis.append(api)
            return api

        def stop_server():
            nonlocal current
            if current is None:
                return
            need(not current['stopAttempted'], 'fixture_original_server_stop_once')
            current['stopAttempted'] = True
            with signals.critical():
                current['cleanup'] = (stop_once_unreaped(current['process'], current['custody']) if current['process'] is not None
                    else {'ok': False, 'outcomeUnknown': True})
            logs, errors = [], []
            for descriptor in current['outputs']:
                try:
                    os.fsync(descriptor['fd']); before = os.fstat(descriptor['fd'])
                    need(before.st_size <= 2097152, 'fixture_original_stopped_log_bound')
                    os.lseek(descriptor['fd'], 0, os.SEEK_SET); raw = bytearray()
                    while len(raw) <= 2097152:
                        part = os.read(descriptor['fd'], min(65536, 2097153 - len(raw)))
                        if not part:
                            break
                        raw.extend(part)
                    need(len(raw) == before.st_size and full9(before) == full9(os.fstat(descriptor['fd'])), 'fixture_stopped_log_generation')
                    logs.append({'bytes': len(raw), 'newCredentialMaterialLogged': any(value.encode() in raw for value in sensitive if value)})
                except BaseException:
                    errors.append('original_server_log_validation_failed')
                finally:
                    try:
                        close(descriptor)
                    except BaseException:
                        errors.append('original_server_log_close_failed')
            row = {'phase': current['phase'], 'cleanup': current['cleanup'], 'logs': logs, 'errors': errors}
            REPORT['serverProcesses'].append(row)
            operations.append('server-stop-result', row)
            need(current['cleanup'].get('ok') is True and not errors and not any(x['newCredentialMaterialLogged'] for x in logs),
                 'fixture_original_server_complete_closure')
            current = None

        api = start_server('initial')
        health = api.call('initial.health_strict_before_init', 'GET', '/v1/sys/health', token='', expected=501, category='health', readiness=True)
        api.check('initial.exact_uninitialized_and_sealed', health.get('initialized') is False and health.get('sealed') is True)
        initialized = api.call('initial.once_init', 'POST', '/v1/sys/init', {'secret_shares': 1, 'secret_threshold': 1}, token='', category='init')
        root_token, unseal = initialized.get('root_token'), initialized.get('keys_base64', [None])[0]
        need(isinstance(root_token, str) and len(root_token) >= 8 and isinstance(unseal, str) and len(unseal) >= 8, 'fixture_original_init_material')
        sensitive.extend((root_token, unseal)); operations.append('bootstrap-recovery', {'rootToken': root_token, 'unsealKey': unseal})
        api.root_token = root_token
        api.check('initial.unsealed', api.call('initial.unseal', 'POST', '/v1/sys/unseal', {'key': unseal}, token='', category='unseal').get('sealed') is False)
        api.call('initial.kv_mount', 'POST', '/v1/sys/mounts/openclaw-auth', {'type': 'kv', 'options': {'version': '2'}}, expected=204, category='mount')
        api.call('initial.approle_mount', 'POST', '/v1/sys/auth/approle', {'type': 'approle'}, expected=204, category='mount')
        api.call('initial.native_activate', 'POST', '/v1/sys/storage/native-v6/activate', {}, expected=204, category='activate')
        api.check('initial.normal_native_kv2_format', api.call('initial.capacity', 'GET', '/v1/sys/internal/capacity', category='capacity').get('data', {}).get('native_kv2_reader_format') == 2)
        api.call('initial.bounded_kv_configuration', 'POST', '/v1/openclaw-auth/config', {'max_versions': 2, 'cas_required': True}, expected=204, category='kv-write')
        report_key = 'transport-v1/' + HOST + '/reports/' + hashlib.sha256(b'main').hexdigest()
        slot_key = 'transport-v1/' + HOST + '/outbox/slot-000'
        ack_key = 'transport-v1/' + HOST + '/ack/slot-000'
        self_policy = [('auth/token/lookup-self', ['read']), ('auth/token/renew-self', ['update']), ('auth/token/revoke-self', ['update'])]
        coordinator_policy = self_policy + [('openclaw-auth/config', ['read']), ('openclaw-auth/metadata/*', ['read'])]
        for key in ('manifest', 'profiles/*', 'coordinator-receipts/*', 'transport-v1/control', slot_key, ack_key, report_key):
            coordinator_policy.append(('openclaw-auth/data/' + key, ['read', 'create', 'update']))
        producer_policy = self_policy + [('openclaw-auth/data/' + key, ['read']) for key in ('manifest', 'profiles/*', 'transport-v1/control', ack_key)]
        producer_policy += [('openclaw-auth/data/' + key, ['read', 'update']) for key in (slot_key, report_key)]
        roles = {}
        for name, rules in (('coordinator', coordinator_policy), ('producer', producer_policy)):
            role = 'fixedslot-actual-' + name + '-r1'
            policy = ''.join('path ' + json.dumps(path) + ' { capabilities = ' + json.dumps(caps) + ' }\n' for path, caps in rules)
            api.call('initial.policy_' + name, 'PUT', '/v1/sys/policies/acl/' + role, {'policy': policy}, expected=204, category='policy')
            base = '/v1/auth/approle/role/' + role
            api.call('initial.role_' + name, 'POST', base, {'token_policies': [role], 'token_ttl': '1200s', 'token_max_ttl': '3600s',
                'secret_id_num_uses': 0, 'secret_id_ttl': '3600s'}, expected=204, category='role')
            role_id = api.call('initial.role_id_' + name, 'GET', base + '/role-id', category='role-id')['data']['role_id']
            secret_id = api.call('initial.secret_id_' + name, 'POST', base + '/secret-id', {}, category='secret-id')['data']['secret_id']
            need(isinstance(role_id, str) and isinstance(secret_id, str) and 8 <= len(role_id) <= 16384 and 8 <= len(secret_id) <= 16384,
                 'fixture_new_scoped_role_material')
            sensitive.extend((role_id, secret_id)); roles[name] = {'base': base, 'role_id': role_id, 'secret_id': secret_id}
            files.write(INPUT / (name + '-role-id'), (role_id + '\n').encode())
            files.write(INPUT / (name + '-secret-id'), (secret_id + '\n').encode())
        api.check('initial.complete_original_python_phase', not api.unknown)

        def run_worker(phase):
            fence.check()
            need(phase in ('initial', 'cold') and len(REPORT['nodePhases']) < 2, 'fixture_two_finite_original_workers')
            phase_until = min(UNTIL, apis[-1].until, time.monotonic() + 120)
            duration = phase_until - time.monotonic()
            need(duration > 0, 'fixture_node_within_original_api_phase')
            config = {'schema': 'heptabao.fixed-slot-coordinator.r1.config', 'address': 'https://127.0.0.1:' + str(PORT),
                'stateDir': str(STATE / 'coordinator'), 'ownerId': OWNER, 'implementationSha256': IMPLEMENTATION,
                'operationMs': 30000, 'pollMs': 1000, 'scanLimit': 1, 'bootstrapProfileCount': 1,
                'serverCertificateSha256': leaf_pin, 'caFile': str(PKI / 'ca.crt'),
                'roleIdFile': str(INPUT / 'coordinator-role-id'), 'secretIdFile': str(INPUT / 'coordinator-secret-id'),
                'topology': [{'host_id': HOST, 'epoch': EPOCH, 'slots': 1, 'agents': ['main']}]}
            producer = {key: config[key] for key in ('address', 'caFile', 'serverCertificateSha256')}
            producer.update(roleIdFile=str(INPUT / 'producer-role-id'), secretIdFile=str(INPUT / 'producer-secret-id'))
            parent_now_ns = time.monotonic_ns()
            original_until_ns = int(phase_until * 1000000000)
            need(0 < original_until_ns - parent_now_ns <= 120000000000, 'fixture_original_node_absolute_ns_budget')
            plan = {'schema': 'heptabao.coordinator-actual-plan.r1', 'phase': phase, 'parentPid': os.getpid(),
                'parentNowMonotonicNs': str(parent_now_ns), 'phaseUntilMonotonicNs': str(original_until_ns),
                'coordinator': config, 'producer': producer,
                'sourcePins': [{'path': str(CODE / name), **pin} for name, pin in PAYLOAD['assetPins'].items()]}
            files.write(INPUT / (phase + '-plan.private.json'), encoded(plan))
            fence.check(); operations.append('node-request-intent', {'phase': phase, 'state': 'dispatched_or_unknown'})
            REPORT['nodeBusinessOutcomeUnknown'] = True
            row, out, err = commands.run('fixedslot-node-' + phase,
                ['/usr/bin/sandbox-exec', '-f', str(SANDBOX), NODE, '--no-warnings', str(WORKER), str(INPUT / (phase + '-plan.private.json'))],
                until=phase_until, maximum=1048576)
            operations.write('node-' + phase + '.stdout.private.json', out)
            operations.write('node-' + phase + '.stderr.private.bin', err)
            operations.append('node-request-result', row)
            need(type(row['exitCode']) is int and row['exitCode'] == 0 and not row['outcomeUnknown'] and not err,
                 'fixture_original_node_known_success')
            value = validate_worker_report(json.loads(out), phase)
            REPORT['nodePhases'].append(value); REPORT['nodeBusinessOutcomeUnknown'] = False
            fence.check()
            return value

        run_worker('initial')
        private_state = files.read_generated_result(RESULTS / 'initial-state.private.json')
        need(private_state.get('schema') == 'heptabao.coordinator-local-interruption.private.r1'
             and private_state.get('active', {}).get('phase') == 'dispatched', 'fixture_original_pending_local_receipt')
        pending_bearer = private_state.get('coordinatorAuth', {}).get('token')
        need(isinstance(pending_bearer, str) and len(pending_bearer) >= 8, 'fixture_retained_original_coordinator_bearer')
        sensitive.append(pending_bearer)
        stop_server()
        cold = start_server('cold-new-process'); cold.root_token = root_token
        health = cold.call('cold.health', 'GET', '/v1/sys/health', token='', expected=503, category='health', readiness=True)
        cold.check('cold.existing_sealed_store', health.get('initialized') is True and health.get('sealed') is True)
        cold.check('cold.original_unseal', cold.call('cold.unseal', 'POST', '/v1/sys/unseal', {'key': unseal}, token='', category='unseal').get('sealed') is False)
        cold.check('cold.native_format_two', cold.call('cold.capacity', 'GET', '/v1/sys/internal/capacity', category='capacity').get('data', {}).get('native_kv2_reader_format') == 2)
        run_worker('cold')
        # These are original known tokens/SIDs. No login fallback or refreshed
        # replacement is introduced to manufacture revocation evidence.
        cold.call('cold.original_coordinator_bearer_revoked', 'GET', '/v1/auth/token/lookup-self', token=pending_bearer, expected=403, category='lookup')
        for name, material in roles.items():
            cold.call('cold.destroy_sid_' + name, 'POST', material['base'] + '/secret-id/destroy', {'secret_id': material['secret_id']},
                      expected=204, category='secret-destroy')
            cold.call('cold.destroyed_sid_denied_' + name, 'POST', '/v1/auth/approle/login',
                {'role_id': material['role_id'], 'secret_id': material['secret_id']}, token='', expected=400, category='login')
        stop_server()
        fence.check()
        need(binary_pin(volume) == before_binary, 'fixture_original_binary_unchanged_at_completion')
        for name, expected in tools_before.items():
            need(public_code_pin(name, remaining=remaining, critical=signals.critical) == expected, 'fixture_native_tools_unchanged')
        REPORT.update(ok=True, actualNormalTlsFixedSlotQualified=True, actualTwoProcessColdReconciliation=True,
                      originalUnknownPreimageNeverReplayed=True, finalServerRunning=False)
    except BaseException as error:
        REPORT['errorType'] = type(error).__name__ if type(error).__name__ in ('Refused', 'CommandRefused', 'VolumeRefused',
            'OSError', 'FileNotFoundError', 'PermissionError', 'TimeoutError', 'JSONDecodeError', 'KeyError') else 'OtherException'
        REPORT['errorCode'] = str(error) if isinstance(error, Refused) and re.fullmatch(r'[a-z0-9._-]{1,120}', str(error)) else 'fixture_failed_no_replay'
        REPORT['ok'] = False
    finally:
        if current is not None:
            try:
                stop_server()
            except BaseException:
                REPORT['finalServerClosureFailed'] = True; REPORT['ok'] = False
        REPORT['apiPhases'] = [api.public() for api in apis]
        REPORT['originalServerCleanupRecords'] = [{'phase': row['phase'], 'stopAttempted': row['stopAttempted'],
            'pid': row['process'].pid if row['process'] is not None else None, 'cleanup': row.get('cleanup')} for row in process_rows]
        REPORT['allOriginalServersClosed'] = all(row['stopAttempted'] and row.get('cleanup', {}).get('ok') is True for row in process_rows)
        if files is not None:
            try:
                files.check()
                REPORT['allProtectedSourcesAndPrivateInputsUnchanged'] = True
            except BaseException:
                REPORT['allProtectedSourcesAndPrivateInputsUnchanged'] = False; REPORT['ok'] = False
        if volume is not None:
            try:
                volume.close()
            except BaseException:
                REPORT['ok'] = False
            REPORT['volumeClosure'] = volume.public_state()
        errors = []
        for row in reversed(FDS):
            try:
                close(row)
            except BaseException:
                errors.append('original_descriptor_close_failed')
        REPORT['allExplicitDescriptorsClosedOnce'] = all(row['attempts'] == 1 and row['closed'] for row in FDS)
        REPORT['explicitDescriptors'] = len(FDS); REPORT['descriptorCloseErrors'] = errors
        command_state = commands.public() if commands is not None else {'commands': [], 'allOwnedCommandsStopped': True, 'unknownCommandCount': 0}
        REPORT['commands'] = {**command_state, 'commands': [public_command(row) if row is not None else None for row in command_state['commands']]}
        REPORT['deadlineAfterClosurePassed'] = time.monotonic() < UNTIL
        REPORT['cancellationObserved'] = CONTROL_SIGNALS is not None and CONTROL_SIGNALS.pending is not None
        REPORT['ok'] = bool(REPORT['ok'] and REPORT['allOriginalServersClosed'] and REPORT['allExplicitDescriptorsClosedOnce']
            and not errors and command_state['allOwnedCommandsStopped'] and command_state['unknownCommandCount'] == 0
            and not REPORT['nodeBusinessOutcomeUnknown'] and REPORT['deadlineAfterClosurePassed'] and not REPORT['cancellationObserved']
            and REPORT.get('volumeClosure', {}).get('lastAnchorCheckPassed') and REPORT['volumeClosure']['allDescriptorsClosed'])
        REPORT['elapsedSeconds'] = time.monotonic() - START
        print(json.dumps(REPORT, sort_keys=True), flush=True)
    return 0 if REPORT['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
