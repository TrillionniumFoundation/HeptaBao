#!/usr/bin/env python3
"""Read finite source selectors of four prior-bound processes; no auth-file IO."""
import ast
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time
import types

START = time.monotonic()
UNTIL = START + 20
ROOT = Path('/Users/qianqi/heptabao-authbus-finite-codex-selectors-20261107-r4')
CALLER_HOME = Path('/Users/qianqi')
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
PYTHON_PIN = (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13')
CHATGPT_CODEX = '/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex'
STANDALONE_CODEX = '/opt/homebrew/lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex'
# PAYLOAD_PLACEHOLDER

codes, descriptors, directories, received_signals = set(), [], {}, []
report = {'schema': 'heptabao.finite-codex-selector-observation.r4', 'ok': False,
          'scope': 'four_prior_full_birth_processes', 'selectedPids': [66414, 66687, 89324, 89325],
          'rawArgumentOrEnvironmentBytesPublished': False, 'rawArgumentOrEnvironmentBytesPersisted': False,
          'onlyAllowlistedSourceSelectorValuesPersistedPrivately': True,
          'selectorValuesOrDigestsPublished': False, 'authFileContentsRead': False,
          'keychainReads': 0, 'sqliteCalls': 0, 'networkRequests': 0, 'childProcesses': 0,
          'processSignalsToObservedConsumers': 0, 'productionWrites': 0, 'serviceActions': 0,
          'activeCredentialBackendQualified': False, 'credentialEqualityCompared': False,
          'consumerQuiescenceQualified': False, 'completeActiveConsumerClosure': False,
          'argumentStackIsNotRunningApplicationConfiguration': True,
          'observationsAreDiscreteNotAtomic': True, 'automaticRetry': False,
          'parentSeconds': 20, 'supervisorSeconds': 30,
          'nativeSysctlReadCalls': 0, 'nativeSysctlWriteCalls': 0}


def need(value, code):
    if not value:
        codes.add(code)
        raise RuntimeError(code)


def remaining():
    need(not received_signals and time.monotonic() < UNTIL, 'selector_original_deadline_or_cancellation')


def full9(info):
    return tuple(str(getattr(info, key)) for key in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
        'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def opened(path, flags, *, dir_fd=None):
    remaining()
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600,
                 **({} if dir_fd is None else {'dir_fd': dir_fd}))
    row = {'fd': fd, 'closeAttempts': 0, 'closed': False}
    descriptors.append(row)
    return row


def close_once(row):
    if row['closeAttempts']:
        return row['closed']
    row['closeAttempts'] = 1
    os.close(row['fd'])
    row['closed'] = True
    return True


def check_directories():
    remaining()
    for path, item in directories.items():
        named = path.lstat() if item['parent'] is None else os.stat(
            path.name, dir_fd=item['parent']['row']['fd'], follow_symlinks=False)
        need(full9(named)[:5] == full9(os.fstat(item['row']['fd']))[:5] == item['first5'],
             'selector_held_parent_first5_unchanged')


def setup_private_directories():
    parent = None
    for path in (Path('/'), Path('/Users'), CALLER_HOME, ROOT, ROOT / 'output'):
        if path in (ROOT, ROOT / 'output'):
            os.mkdir(path.name, 0o700, dir_fd=parent['row']['fd'])
            os.fsync(parent['row']['fd'])
        named = path.lstat() if parent is None else os.stat(path.name,
            dir_fd=parent['row']['fd'], follow_symlinks=False)
        expected_uid = 0 if path in (Path('/'), Path('/Users')) else 501
        need(stat.S_ISDIR(named.st_mode) and named.st_uid == expected_uid
             and not stat.S_IMODE(named.st_mode) & 0o022, 'selector_private_parent_owner_mode')
        if path in (ROOT, ROOT / 'output'):
            need(stat.S_IMODE(named.st_mode) == 0o700 and named.st_gid == 20,
                 'selector_new_private_directory_0700')
        row = opened(str(path) if parent is None else path.name, os.O_RDONLY | os.O_DIRECTORY,
                     dir_fd=None if parent is None else parent['row']['fd'])
        need(full9(named) == full9(os.fstat(row['fd'])), 'selector_held_directory_name_identity')
        item = {'row': row, 'parent': parent, 'first5': full9(named)[:5]}
        directories[path] = item
        parent = item
    check_directories()


def private_output(name, packet):
    need(name in ('selectors-first.private.json', 'selectors-second.private.json'),
         'selector_fixed_private_output_names')
    raw = (json.dumps(packet, sort_keys=True, separators=(',', ':')) + '\n').encode()
    need(len(raw) <= 131072, 'selector_bounded_private_packet')
    check_directories()
    parent = directories[ROOT / 'output']['row']
    row = opened(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, dir_fd=parent['fd'])
    try:
        at = 0
        while at < len(raw):
            remaining()
            count = os.write(row['fd'], raw[at:at + 65536])
            need(count > 0, 'selector_private_complete_write')
            at += count
        os.fsync(row['fd'])
        named = os.stat(name, dir_fd=parent['fd'], follow_symlinks=False)
        held = os.fstat(row['fd'])
        need(full9(named) == full9(held) and stat.S_ISREG(held.st_mode)
             and held.st_uid == 501 and held.st_gid == 20 and stat.S_IMODE(held.st_mode) == 0o600
             and held.st_nlink == 1 and held.st_size == len(raw), 'selector_private_file_0600_single_inode')
        os.fsync(parent['fd'])
    finally:
        close_once(row)
    check_directories()


def pin_public(path, expected):
    row = opened(path, os.O_RDONLY)
    try:
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid in (0, 501)
             and not stat.S_IMODE(before.st_mode) & 0o022 and before.st_nlink == 1
             and before.st_size == expected[0] <= 65536, 'selector_bounded_public_file_custody')
        digest, count = hashlib.sha256(), 0
        while count <= before.st_size:
            remaining()
            chunk = os.read(row['fd'], min(65536, before.st_size + 1 - count))
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
        need(count == before.st_size and digest.hexdigest() == expected[1]
             and full9(before) == full9(os.fstat(row['fd'])) == full9(Path(path).lstat()),
             'selector_exact_public_file_pin_and_full9')
        return full9(before)
    finally:
        close_once(row)


class ArgsReader:
    def __init__(self):
        need(sys.byteorder == 'little' and ctypes.sizeof(ctypes.c_int) == 4,
             'selector_exact_darwin_int_abi')
        self.lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        self.lib.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
        self.lib.sysctl.restype = ctypes.c_int
        maximum = ctypes.c_int()
        length = ctypes.c_size_t(ctypes.sizeof(maximum))
        self.call((1, 8), ctypes.byref(maximum), length)
        need(length.value == 4 and maximum.value == 1048576,
             'selector_actual_kernel_argument_budget')
        # Preserve the original 256 KiB + argc allocation. XNU's insufficient
        # buffer branch returns exactly the supplied size; reject that size
        # rather than accepting possibly truncated data or enlarging the cap.
        self.maximum = 262144 + 4
        report['kernelArgumentBudget'] = maximum.value
        report['maximumArgumentReadBytesIncludingArgc'] = self.maximum
        report['kernelBudgetDiagnosticJob'] = '1a1b398a4c8-fc05-83c2'
        report['originalReadAllocationCeilingUnchanged'] = True

    def call(self, mib_values, out, length):
        remaining()
        need(mib_values == (1, 8) or len(mib_values) == 3 and mib_values[:2] == (1, 49)
             and mib_values[2] in (66414, 66687, 89324, 89325), 'selector_only_fixed_readonly_mibs')
        mib = (ctypes.c_int * len(mib_values))(*mib_values)
        ctypes.set_errno(0)
        report['nativeSysctlReadCalls'] += 1
        returned = self.lib.sysctl(mib, len(mib_values), out, ctypes.byref(length), None, 0)
        if returned != 0:
            report['nativeSysctlErrno'] = ctypes.get_errno()
        need(returned == 0, 'selector_native_readonly_sysctl_known_success')
        remaining()

    def read(self, pid):
        memory = ctypes.create_string_buffer(self.maximum)
        length = ctypes.c_size_t(self.maximum)
        try:
            self.call((1, 49, pid), memory, length)
            need(6 <= length.value < self.maximum, 'selector_complete_returned_procargs_strictly_below_cap')
            raw = memory.raw[:length.value]
            try:
                return parse_procargs(raw)
            finally:
                # No raw stack bytes are retained in reports or artifacts.
                del raw
        finally:
            ctypes.memset(memory, 0, len(memory))


def sample(reader, args_reader, expected, ordinal):
    remaining()
    current = reader.read(expected['pid'])
    need({key: current[key] for key in expected} == expected and current['uid'] == 501,
         'selector_prior_full_numeric_birth_identity_exact')
    wanted = CHATGPT_CODEX if ordinal < 2 else STANDALONE_CODEX if ordinal == 3 else None
    if wanted is not None:
        need(current['executable'] == str(Path(wanted).resolve(strict=True)),
             'selector_prior_codex_executable_exact')
    else:
        need(Path(current['executable']).name == 'node', 'selector_prior_node_parent_executable_class')
    parsed = args_reader.read(expected['pid'])
    need(current == reader.read(expected['pid']), 'selector_birth_and_executable_unchanged_across_sysctl')
    need(str(Path(parsed['private']['savedExecutable']).resolve(strict=True)) == current['executable'],
         'selector_saved_exec_path_matches_live_executable')
    return {'ordinal': ordinal, 'pid': expected['pid'], 'identity': current,
            'private': parsed['private'], 'public': parsed['public']}


try:
    os.umask(0o077)
    sys.dont_write_bytecode = True
    need(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 501 and os.getgid() == 20
         and Path(sys.executable).resolve(strict=True) == PYTHON, 'selector_exact_mac_python_caller')
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda number, _frame: received_signals.append(number))
    pins = {str(PYTHON): PYTHON_PIN, **PAYLOAD['publicFilePins']}
    before_pins = {path: pin_public(path, expected) for path, expected in pins.items()}
    need(set(PAYLOAD['sources']) == {'mac_owned_unreaped_r1.py', 'mac_native_process_observer_r1.py',
         'mac_procargs_selectors_r4.py'}, 'selector_exact_three_source_modules')
    for name, source in PAYLOAD['sources'].items():
        need(hashlib.sha256(source.encode()).hexdigest() == PAYLOAD['sourcePins'][name],
             'selector_exact_module_whole_source_pin')
        ast.parse(source)
    need([row['pid'] for row in PAYLOAD['processes']] == [66414, 66687, 89324, 89325]
         and all(set(row) == {'pid','ppid','pgid','uid','birthSec','birthUsec'}
                 and all(type(value) is int for value in row.values()) for row in PAYLOAD['processes']),
         'selector_exact_four_original_numeric_identities')
    setup_private_directories()
    for name, source in PAYLOAD['sources'].items():
        module = types.ModuleType(Path(name).stem)
        module.__file__ = str(ROOT / name)
        sys.modules[module.__name__] = module
        exec(compile(source, module.__file__, 'exec'), module.__dict__)
    from mac_native_process_observer_r1 import ProcessReader
    from mac_procargs_selectors_r4 import parse_procargs, SelectorRefused
    reader, args_reader = ProcessReader(), ArgsReader()
    first = []
    for ordinal, expected in enumerate(PAYLOAD['processes']):
        report['observationOrdinal'] = ordinal
        first.append(sample(reader, args_reader, expected, ordinal))
    private_output('selectors-first.private.json', {'schema': 'heptabao.finite-selectors.private.r1',
        'priorAuthority': PAYLOAD['priorAuthority'], 'observations': first})
    second = []
    for ordinal, expected in enumerate(PAYLOAD['processes']):
        report['observationOrdinal'] = ordinal
        second.append(sample(reader, args_reader, expected, ordinal))
    private_output('selectors-second.private.json', {'schema': 'heptabao.finite-selectors.private.r1',
        'priorAuthority': PAYLOAD['priorAuthority'], 'observations': second})
    need(first == second, 'selector_all_four_selected_bindings_unchanged_between_observations')
    need(all(reader.read(row['pid']) == row['identity'] for row in first),
         'selector_final_four_process_births_unchanged')
    after_pins = {path: pin_public(path, expected) for path, expected in pins.items()}
    need(before_pins == after_pins, 'selector_all_public_code_full9_and_hash_unchanged')
    check_directories()
    report.pop('observationOrdinal', None)
    report['observations'] = [{'ordinal': row['ordinal'], 'pid': row['pid'], **row['public']} for row in first]
    report['allFourPriorBirthsAndCurrentExecutablesReverified'] = True
    report['allSelectedBindingsStableAcrossTwoObservations'] = True
    report['standaloneParentChildRelationExact'] = first[3]['identity']['ppid'] == first[2]['identity']['pid']
    report['standaloneInstalledPackageVersion'] = '0.133.0'
    report['chatGptBundleVersionIsNativeVersion'] = False
    report['nativeVersionFromProcessMemoryQualified'] = False
    report['sourcePins'] = PAYLOAD['sourcePins']
    report['publicFilePins'] = {path: {'bytes': value[0], 'sha256': value[1]} for path, value in pins.items()}
    report['priorAuthority'] = PAYLOAD['priorAuthority']
    report['ok'] = True
except BaseException as error:
    report['ok'] = False
    report['errorClass'] = type(error).__name__ if type(error).__name__ in (
        'RuntimeError','SelectorRefused','ObservationRefused','OSError','FileNotFoundError',
        'PermissionError','UnicodeDecodeError') else 'OtherException'
    code = str(error)
    report['errorCode'] = code if code in codes or type(error).__name__ in (
        'SelectorRefused','ObservationRefused') and code.isascii() and code.replace('_','').isalnum() else 'selector_observation_refused'
finally:
    errors = []
    for row in reversed(descriptors):
        try:
            close_once(row)
        except BaseException:
            errors.append('explicit_descriptor_close_failed')
    report['explicitDescriptorClosures'] = [{'closeAttempts': row['closeAttempts'], 'closed': row['closed']}
                                           for row in descriptors]
    report['allExplicitDescriptorsClosedOnce'] = all(row['closeAttempts'] == 1 and row['closed'] for row in descriptors)
    report['closeErrors'] = errors
    report['cancellationObserved'] = bool(received_signals)
    report['deadlineAfterClosurePassed'] = time.monotonic() < UNTIL
    report['elapsedSeconds'] = time.monotonic() - START
    report['ok'] = bool(report['ok'] and report['allExplicitDescriptorsClosedOnce'] and not errors
        and report['deadlineAfterClosurePassed'] and not report['cancellationObserved'])
    print(json.dumps(report, sort_keys=True, separators=(',', ':')), flush=True)
raise SystemExit(0 if report['ok'] else 1)
