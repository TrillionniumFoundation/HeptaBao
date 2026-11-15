#!/usr/bin/env python3
"""One finite live-PID to known-file inode observation; no credential/SQL reads."""
import ast
import hashlib
import json
import locale
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

START = time.monotonic()
UNTIL = START + 45
ROOT = Path('/Users/qianqi/heptabao-authbus-finite-consumer-inodes-20261107-r1')
CALLER_HOME = Path('/Users/qianqi')
LIVE = CALLER_HOME / '.openclaw'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
LSOF = '/usr/sbin/lsof'
RUNTIME_PINS = {
    str(PYTHON): (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    '/bin/ps': (170432, '3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'),
    LSOF: (306768, 'b1b9151bbc56f4749890dbe4e533af9a4f8700240ad431a6c9ddf70fe137c165'),
}
AGENTS = ('main', 'trnm', 'hepta-ui', 'hepta', 'hepta-backend')
CACHES = ('applied-profiles.json', 'publish-baseline.json', 'bad-refresh-quarantine.json',
          'refresh-backoff.json', 'lease-epochs.json', 'status.json')
LEGACY = ('auth-profiles.json', 'auth-state.json', 'auth.json')
# PAYLOAD_PLACEHOLDER

codes, fds = set(), []
commands = None
write_directories = {}
report = {'schema': 'heptabao.actual-finite-consumer-inode-observation.r1', 'ok': False,
          'databaseContentsRead': False, 'credentialValuesRead': False, 'sqliteCalls': 0,
          'keychainReads': 0, 'otherProcessArgumentsRead': False, 'otherProcessEnvironmentRead': False,
          'networkRequests': 0, 'productionWrites': 0, 'serviceActions': 0,
          'processSignalsToObservedConsumers': 0, 'completeActiveConsumerClosure': False,
          'consumerQuiescenceQualified': False, 'kernelWideVisibilityClaimed': False,
          'noMatchingOpenFileImpliesNoCachedCredentialUse': False,
          'observationIsDiscreteNotAtomic': True, 'automaticRetry': False,
          'parentSeconds': 45, 'lsofSeconds': 10, 'supervisorSeconds': 70}


def need(value, code):
    if not value:
        codes.add(code)
        raise RuntimeError(code)


def remaining():
    left = UNTIL - time.monotonic()
    need(left > 0, 'finite_original_parent_deadline')
    return left


def full9(value):
    return tuple(str(getattr(value, name)) for name in ('st_dev', 'st_ino', 'st_uid',
        'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def opened(path, flags, *, dir_fd=None, mode=0o600):
    remaining()
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, mode,
                 **({} if dir_fd is None else {'dir_fd': dir_fd}))
    row = {'fd': fd, 'closeAttempts': 0, 'closed': False}
    fds.append(row)
    return row


def closed(row):
    if row['closeAttempts']:
        return row['closed']
    row['closeAttempts'] = 1
    os.close(row['fd'])
    row['closed'] = True
    return True


def private(path, raw):
    need(path.parent in (ROOT / 'code', ROOT / 'output') and isinstance(raw, bytes)
         and len(raw) <= 1048576, 'finite_create_only_output_scope')
    for directory, item in write_directories.items():
        named = os.stat(directory.name, dir_fd=item['parent']['fd'], follow_symlinks=False)
        need(full9(named)[:5] == full9(os.fstat(item['row']['fd']))[:5] == item['first5'],
             'finite_owned_output_directory_unchanged')
    parent = write_directories[path.parent]['row']
    row = opened(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, dir_fd=parent['fd'])
    try:
        offset = 0
        while offset < len(raw):
            remaining()
            count = os.write(row['fd'], raw[offset:offset + 65536])
            need(count > 0, 'finite_output_complete_write')
            offset += count
        os.fsync(row['fd'])
        info = os.fstat(row['fd'])
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
             and info.st_size == len(raw) and full9(info) == full9(os.stat(path.name,
                 dir_fd=parent['fd'], follow_symlinks=False)),
             'finite_private_output_generation')
        os.fsync(parent['fd'])
    finally:
        closed(row)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def public_file(path, expected):
    row = opened(path, os.O_RDONLY)
    try:
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid in (0, 501)
             and not stat.S_IMODE(before.st_mode) & 0o022 and before.st_nlink == 1
             and before.st_size == expected[0] <= 1048576,
             'finite_exact_bounded_public_executable')
        content = bytearray()
        while len(content) <= before.st_size:
            remaining()
            block = os.read(row['fd'], min(65536, before.st_size + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        need(len(content) == before.st_size and hashlib.sha256(content).hexdigest() == expected[1]
             and full9(before) == full9(os.fstat(row['fd'])) == full9(Path(path).lstat()),
             'finite_whole_public_executable_unchanged')
        return full9(before)
    finally:
        closed(row)


class KnownFiles:
    def __init__(self):
        self.directories, self.files, self.absences = {}, [], []
        previous = None
        for path in (Path('/'), Path('/Users'), CALLER_HOME, LIVE):
            before = path.lstat() if previous is None else os.stat(path.name, dir_fd=previous['row']['fd'], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode) and before.st_uid == (0 if path in (Path('/'), Path('/Users')) else 501)
                 and not stat.S_IMODE(before.st_mode) & 0o022, 'finite_known_parent_owner_and_mode')
            row = opened(str(path) if previous is None else path.name, os.O_RDONLY | os.O_DIRECTORY,
                         dir_fd=None if previous is None else previous['row']['fd'])
            need(full9(before) == full9(os.fstat(row['fd'])), 'finite_known_parent_open_identity')
            current = {'row': row, 'first5': full9(before)[:5], 'path': path, 'parent': previous}
            self.directories[path] = current
            previous = current

    def parent(self, path):
        need(path.is_relative_to(LIVE) and path != LIVE and '..' not in path.parts,
             'finite_source_file_path_scope')
        previous = self.directories[LIVE]
        current_path = LIVE
        for component in path.parent.relative_to(LIVE).parts:
            current_path = current_path / component
            if current_path in self.directories:
                previous = self.directories[current_path]
                continue
            try:
                named = os.stat(component, dir_fd=previous['row']['fd'], follow_symlinks=False)
            except FileNotFoundError:
                self.absences.append({'parent': previous, 'name': component})
                return None
            need(stat.S_ISDIR(named.st_mode) and named.st_uid == 501
                 and not stat.S_IMODE(named.st_mode) & 0o022, 'finite_source_directory_custody')
            row = opened(component, os.O_RDONLY | os.O_DIRECTORY, dir_fd=previous['row']['fd'])
            need(full9(named) == full9(os.fstat(row['fd'])), 'finite_source_directory_open_identity')
            current = {'row': row, 'first5': full9(named)[:5], 'path': current_path, 'parent': previous}
            self.directories[current_path] = current
            previous = current
        return previous

    def hold(self, path, ordinal, kind, member):
        parent = self.parent(path)
        public = {'ordinal': ordinal, 'kind': kind, 'member': member, 'present': False}
        if parent is None:
            self.files.append({'path': path, 'public': public, 'row': None, 'parent': None})
            return
        try:
            named = os.stat(path.name, dir_fd=parent['row']['fd'], follow_symlinks=False)
        except FileNotFoundError:
            self.absences.append({'parent': parent, 'name': path.name})
            self.files.append({'path': path, 'public': public, 'row': None, 'parent': parent})
            return
        need(stat.S_ISREG(named.st_mode) and named.st_uid == 501 and named.st_gid == 20
             and named.st_nlink == 1 and not stat.S_IMODE(named.st_mode) & 0o022,
             'finite_selected_regular_single_owner_file')
        row = opened(path.name, os.O_RDONLY, dir_fd=parent['row']['fd'])
        need(full9(named) == full9(os.fstat(row['fd'])), 'finite_metadata_only_held_file')
        public.update(present=True, device=named.st_dev, inode=named.st_ino, size=named.st_size)
        self.files.append({'path': path, 'public': public, 'row': row,
                           'parent': parent, 'full9': full9(named)})

    def verify(self):
        for path, item in self.directories.items():
            remaining()
            current = path.lstat() if item['parent'] is None else os.stat(path.name,
                dir_fd=item['parent']['row']['fd'], follow_symlinks=False)
            need(full9(current)[:5] == full9(os.fstat(item['row']['fd']))[:5] == item['first5'],
                 'finite_all_parent_inodes_unchanged')
        differences = []
        names = ('device', 'inode', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs')
        for item in self.files:
            if item['row'] is not None:
                current = os.stat(item['path'].name, dir_fd=item['parent']['row']['fd'], follow_symlinks=False)
                named, held = full9(current), full9(os.fstat(item['row']['fd']))
                if not named == held == item['full9']:
                    differences.append({'ordinal': item['public']['ordinal'],
                        'kind': item['public']['kind'], 'member': item['public']['member'],
                        'changedFields': [name for number, name in enumerate(names)
                            if named[number] != held[number] or named[number] != item['full9'][number]]})
        if differences:
            report['sourceGenerationDifferences'] = differences
        need(not differences, 'finite_known_file_full9_unchanged')
        for item in self.absences:
            try:
                os.stat(item['name'], dir_fd=item['parent']['row']['fd'], follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise RuntimeError('finite_known_absence_changed')

    def targets(self):
        return [{key: item['public'][key] for key in ('ordinal', 'kind', 'member', 'device', 'inode')}
                for item in self.files if item['public']['present']]

    def packet(self):
        return [{'path': str(item['path']), 'full9': item.get('full9'),
                 'metadata': item['public'], 'fileContentsRead': False} for item in self.files]


def match_prior_start(identity, previous):
    need(type(previous) is str and previous.startswith('ps:'), 'finite_native_start_identity_shape')
    actual = time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(identity['birthSec'])).split()
    wanted = previous[3:].split()
    need(len(actual) == len(wanted) == 5 and actual[:2] == wanted[:2]
         and int(actual[2]) == int(wanted[2]) and actual[3:] == wanted[3:],
         'finite_prior_native_start_second_matches_current_full_birth')


def safe_commands():
    if commands is None:
        return []
    return [{key: row['public'][key] for key in ('label', 'pid', 'exitCode', 'completeBeforeDeadline',
             'cleanup', 'stdoutBytes', 'stderrBytes', 'streamsClosed', 'outcomeUnknown')}
            if row.get('public') is not None else {'label': row['label'], 'outcomeUnknown': True}
            for row in commands.rows]


try:
    os.umask(0o077)
    sys.dont_write_bytecode = True
    locale.setlocale(locale.LC_TIME, 'C')
    need(sys.platform == 'darwin' and os.getuid() == 501 and os.getgid() == 20
         and Path(sys.executable).resolve(strict=True) == PYTHON, 'finite_exact_mac_runtime')
    before_runtime = {path: public_file(path, expected) for path, expected in RUNTIME_PINS.items()}
    need(set(PAYLOAD['sources']) == {'mac_owned_unreaped_r1.py', 'mac_owned_commands_r1.py',
         'mac_native_process_observer_r1.py', 'mac_finite_lsof_fields_r1.py'}, 'finite_four_source_modules')
    for name, source in PAYLOAD['sources'].items():
        need(hashlib.sha256(source.encode()).hexdigest() == PAYLOAD['sourcePins'][name],
             'finite_qualified_source_whole_pin')
        ast.parse(source)
    need({item['pid'] for item in PAYLOAD['processes']} == {964, 983, 987, 989, 18437, 66414, 66687, 89324, 89325}
         and len(PAYLOAD['processes']) == 9, 'finite_nine_observed_processes_only')
    files = KnownFiles()
    for path in (ROOT, ROOT / 'code', ROOT / 'output'):
        parent = files.directories[CALLER_HOME]['row'] if path == ROOT else write_directories[ROOT]['row']
        os.mkdir(path.name, mode=0o700, dir_fd=parent['fd'])
        row = opened(path.name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent['fd'])
        info = os.fstat(row['fd'])
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
             and stat.S_IMODE(info.st_mode) == 0o700 and full9(info) == full9(os.stat(
                 path.name, dir_fd=parent['fd'], follow_symlinks=False)), 'finite_new_private_output_directory')
        write_directories[path] = {'row': row, 'parent': parent, 'first5': full9(info)[:5]}
        os.fsync(parent['fd'])
    files.verify()
    for name, source in PAYLOAD['sources'].items():
        private(ROOT / 'code' / name, source.encode())
        module = types.ModuleType(Path(name).stem)
        module.__file__ = str(ROOT / 'code' / name)
        sys.modules[module.__name__] = module
        exec(compile(source, module.__file__, 'exec'), module.__dict__)
    from mac_owned_commands_r1 import Commands, Signals
    from mac_native_process_observer_r1 import ProcessReader
    from mac_finite_lsof_fields_r1 import parse_fields, match_files
    signals = Signals()
    signals.install()
    commands = Commands(signals)
    reader = ProcessReader()
    before_processes = {}
    for index, previous in enumerate(PAYLOAD['processes']):
        remaining()
        report['processAdmissionOrdinal'] = index
        current = reader.read(previous['pid'])
        need(current['uid'] == 501, 'finite_observed_process_still_same_owner')
        match_prior_start(current, previous['identity'])
        if previous['name'].startswith('/'):
            need(current['executable'] == str(Path(previous['name']).resolve(strict=True)),
                 'finite_observed_executable_path_same')
        before_processes[previous['pid']] = current
    report.pop('processAdmissionOrdinal')
    report['processAdmissionsComplete'] = len(before_processes)
    paths = [LIVE / 'agents' / agent / 'agent/openclaw-agent.sqlite' for agent in AGENTS]
    paths.append(LIVE / 'state/openclaw.sqlite')
    ordinal = 0
    for path in paths:
        for suffix, member in (('', 'base'), ('-wal', 'wal'), ('-shm', 'shm'), ('-journal', 'journal')):
            files.hold(Path(str(path) + suffix), ordinal, 'database', member)
            ordinal += 1
    for name in CACHES:
        files.hold(LIVE / 'authbus' / name, ordinal, 'cache', 'file')
        ordinal += 1
    for agent in AGENTS:
        for name in LEGACY:
            files.hold(LIVE / 'agents' / agent / 'agent' / name, ordinal, 'legacy', 'file')
            ordinal += 1
    need(ordinal == 45, 'finite_forty_five_file_metadata_targets')
    files.verify()
    private(ROOT / 'output/source-bindings.private.json', encoded(files.packet()))
    private(ROOT / 'output/process-before.private.json', encoded(before_processes))
    # -Di ignores the device cache; -nP prevents name/service resolution.
    # Explicit fields omit n/c/L: no filenames, commands or login names.
    argv = [LSOF, '-nP', '-Di', '-p', ','.join(str(pid) for pid in sorted(before_processes)), '-F0pufatDi']
    row, out, err = commands.run('finite-current-file-inodes', argv,
        until=min(UNTIL, time.monotonic() + 10), maximum=1048576)
    private(ROOT / 'output/lsof.stdout.original', out)
    private(ROOT / 'output/lsof.stderr.private', err)
    need(type(row.get('exitCode')) is int and row['exitCode'] == 0
         and row.get('outcomeUnknown') is False and not err,
         'finite_original_lsof_known_complete_without_visibility_warning')
    parsed = parse_fields(out, set(before_processes))
    report['matches'] = match_files(parsed, files.targets())
    after_processes = {pid: reader.read(pid) for pid in before_processes}
    private(ROOT / 'output/process-after.private.json', encoded(after_processes))
    report['changedProcessFields'] = [{'pid': pid, 'fields': [key for key in before_processes[pid]
        if before_processes[pid][key] != after_processes[pid][key]]} for pid in before_processes
        if before_processes[pid] != after_processes[pid]]
    need(after_processes == before_processes, 'finite_full_process_birth_and_executable_stable')
    files.verify()
    private(ROOT / 'output/source-after.private.json', encoded(files.packet()))
    after_runtime = {path: public_file(path, expected) for path, expected in RUNTIME_PINS.items()}
    need(after_runtime == before_runtime, 'finite_native_tools_full9_and_hash_unchanged')
    report['processes'] = [{key: row[key] for key in ('pid', 'ppid', 'pgid', 'uid', 'birthSec', 'birthUsec')}
                           for row in before_processes.values()]
    report['sourceMetadata'] = [item['public'] for item in files.files]
    report['observedProcesses'] = len(parsed['processes'])
    report['observedFileRecords'] = parsed['fileRecords']
    report['allFortyFiveKnownMetadataBindingsUnchanged'] = True
    report['allNineProcessBirthsAndExecutablesUnchanged'] = True
    report['nativeExecutablePins'] = {path: {'bytes': pin[0], 'sha256': pin[1]} for path, pin in RUNTIME_PINS.items()}
    report['sourcePins'] = PAYLOAD['sourcePins']
    report['ok'] = True
except BaseException as error:
    report['ok'] = False
    report['errorClass'] = type(error).__name__
    code = str(error)
    report['errorCode'] = code if code in codes or type(error).__name__ in (
        'ObservationRefused', 'FieldRefused', 'Refusal', 'CommandRefused') and re.fullmatch(
            r'[a-z][a-z0-9_]{0,127}', code) else 'finite_consumer_observation_refused'
finally:
    errors = []
    for row in reversed(fds):
        try:
            closed(row)
        except BaseException as error:
            errors.append(type(error).__name__)
    report['explicitDescriptors'] = [{key: row[key] for key in ('closeAttempts', 'closed')} for row in fds]
    report['allExplicitDescriptorsClosedOnce'] = all(row['closeAttempts'] == 1 and row['closed'] for row in fds)
    report['closeErrors'] = errors
    report['originalCommands'] = safe_commands()
    closure = commands.public() if commands is not None else {'allOwnedCommandsStopped': True, 'unknownCommandCount': 0}
    report['allOriginalCommandsClosed'] = closure['allOwnedCommandsStopped']
    report['unknownCommandCount'] = closure['unknownCommandCount']
    report['elapsedSeconds'] = time.monotonic() - START
    report['ok'] = bool(report['ok'] and report['allExplicitDescriptorsClosedOnce'] and not errors
        and report['allOriginalCommandsClosed'] and report['unknownCommandCount'] == 0 and time.monotonic() < UNTIL)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')), flush=True)
raise SystemExit(0 if report['ok'] else 1)
