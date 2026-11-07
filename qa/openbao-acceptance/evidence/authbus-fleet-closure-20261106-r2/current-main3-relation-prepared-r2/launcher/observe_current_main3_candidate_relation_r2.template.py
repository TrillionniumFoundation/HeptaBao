#!/usr/bin/env python3
"""Same-parent fixed candidate files and one fresh main3 SQL projection, privately."""
import ast
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import stat
import sys
import time
import types

START = time.monotonic()
UNTIL = START + 45
ROOT = Path('/Users/qianqi/heptabao-authbus-current-main3-candidate-relation-20261107-r2')
QUAL = Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2/qa')
CALLER_HOME = Path('/Users/qianqi')
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
PYTHON_PIN = (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13')
CHATGPT_CODEX = '/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex'
STANDALONE_CODEX = '/opt/homebrew/lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex'
PAYLOAD = __RELATION_PAYLOAD__

codes, descriptors, directories, received_signals = set(), [], {}, []
candidate_inputs = None
owner = child = None
current_private = None
report = {'schema': 'heptabao.current-main3-candidate-relation.parent.r2', 'ok': False,
          'scope': 'four_prior_full_birth_processes', 'selectedPids': [66414, 66687, 89324, 89325],
          'rawArgumentOrEnvironmentBytesPublished': False, 'rawArgumentOrEnvironmentBytesPersisted': False,
          'onlyAllowlistedSourceSelectorValuesPersistedPrivately': True,
          'selectorValuesOrDigestsPublished': False, 'authFileContentsRead': False,
          'keychainReads': 0, 'currentMainSqlObservationCount': 0, 'providerNetworkRequests': 0, 'childProcesses': 0,
          'processSignalsToObservedConsumers': 0, 'productionWrites': 0, 'serviceActions': 0,
          'activeCredentialBackendQualified': False, 'credentialEqualityCompared': False,
          'consumerQuiescenceQualified': False, 'completeActiveConsumerClosure': False,
          'argumentStackIsNotRunningApplicationConfiguration': True,
          'observationsAreDiscreteNotAtomic': True, 'automaticRetry': False,
          'parentSeconds': 45, 'candidateAndSqlWorkerSeconds': 20, 'supervisorSeconds': 70,
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
    for path in (Path('/'), Path('/Users'), CALLER_HOME, ROOT, ROOT / 'code', ROOT / 'output'):
        if path == ROOT / 'output':
            parent = directories[ROOT]
        if path in (ROOT, ROOT / 'code', ROOT / 'output'):
            os.mkdir(path.name, 0o700, dir_fd=parent['row']['fd'])
            os.fsync(parent['row']['fd'])
        named = path.lstat() if parent is None else os.stat(path.name,
            dir_fd=parent['row']['fd'], follow_symlinks=False)
        expected_uid = 0 if path in (Path('/'), Path('/Users')) else 501
        need(stat.S_ISDIR(named.st_mode) and named.st_uid == expected_uid
             and not stat.S_IMODE(named.st_mode) & 0o022, 'selector_private_parent_owner_mode')
        if path in (ROOT, ROOT / 'code', ROOT / 'output'):
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
    need(name in ('selectors-first.private.json', 'selectors-second.private.json',
                  'candidate-files.private.json'),
         'selector_fixed_private_output_names')
    raw = (json.dumps(packet, sort_keys=True, separators=(',', ':')) + '\n').encode()
    need(len(raw) <= (2 * 1048576 if name == 'candidate-files.private.json' else 131072),
         'selector_bounded_private_packet')
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



def bounded_original_read(path, maximum, *, private=False):
    row = opened(path, os.O_RDONLY)
    try:
        value = os.fstat(row['fd'])
        need(stat.S_ISREG(value.st_mode) and value.st_uid in (0, 501) and value.st_nlink == 1
             and not stat.S_IMODE(value.st_mode) & 0o022 and 0 < value.st_size <= maximum,
             'relation_parent_bounded_original_file')
        if private:
            need(value.st_uid == 501 and value.st_gid == 20 and stat.S_IMODE(value.st_mode) == 0o600,
                 'relation_parent_private_owned_file')
        parts, count = [], 0
        while count <= value.st_size:
            remaining()
            part = os.read(row['fd'], min(65536, value.st_size + 1 - count))
            if not part:
                break
            parts.append(part); count += len(part)
        need(count == value.st_size and full9(value) == full9(os.fstat(row['fd'])) == full9(path.lstat()),
             'relation_parent_whole_file_full_nine')
        return b''.join(parts), full9(value)
    finally:
        close_once(row)


def create_owned(path, raw):
    need(path.parent in (ROOT, ROOT / 'code', ROOT / 'output') and type(raw) is bytes
         and len(raw) <= 2097152, 'relation_parent_exact_new_output_scope')
    parent = directories[path.parent]['row']
    row = opened(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL, dir_fd=parent['fd'])
    try:
        view = memoryview(raw)
        while view:
            remaining(); count = os.write(row['fd'], view)
            need(count > 0, 'relation_parent_create_only_write_progress'); view = view[count:]
        os.fsync(row['fd'])
        value = os.fstat(row['fd'])
        need(stat.S_ISREG(value.st_mode) and value.st_uid == 501 and value.st_gid == 20
             and stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink == 1
             and value.st_size == len(raw) and os.pread(row['fd'], len(raw) + 1, 0) == raw
             and full9(value) == full9(os.fstat(row['fd'])) == full9(path.lstat()),
             'relation_parent_durable_owned_original_bytes')
        os.fsync(parent['fd'])
    finally:
        close_once(row)
    check_directories()


def prepare_reader():
    need(set(PAYLOAD['readerSources']) == {'main3_source_authority.py', 'mac_current_selected_main3_r2.py',
         'mac_codex_candidate_backend_r1.py', 'read_current_main3_candidate_relation_r2.py'},
         'relation_parent_four_reader_sources')
    for name, source in PAYLOAD['readerSources'].items():
        need(hashlib.sha256(source.encode()).hexdigest() == PAYLOAD['readerPins'][name],
             'relation_parent_reader_source_hash')
        compile(source, name, 'exec')
        create_owned(ROOT / 'code' / name, source.encode())
    create_owned(ROOT / 'code/reader-plan.public.json', (json.dumps({
        'schema': 'heptabao.current-main3-relation-reader-plan.r1', 'readerPins': PAYLOAD['readerPins'],
        'originalChildren': 1, 'providerCalls': 0, 'sourceWritesAuthorized': False,
        'historicalCapsuleUsedOnlyForAuthorizedIds': True}, sort_keys=True) + '\n').encode())
    create_owned(ROOT / 'protected-read', b'synthetic read-denial fixture\n')
    policy = ['(version 1)', '(deny default)', '(allow process*)', '(allow signal (target children))',
        '(allow sysctl-read)', '(allow mach-lookup)', '(allow file-read-metadata)']
    for name in ('/System', '/usr', '/bin', '/sbin', '/Library', '/private/etc', '/opt/homebrew', '/dev/fd'):
        policy.append('(allow file-read* (subpath ' + json.dumps(name) + '))')
    for path in (ROOT / 'code', ROOT / 'output'):
        policy.append('(allow file-read* (subpath ' + json.dumps(str(path)) + '))')
    fixed = {Path('/Users/qianqi/.openclaw/openclaw.json'),
        Path('/Users/qianqi/heptabao-authbus-main3-sdk-inline-capsule-20261106-r4/output/selected-owner-credentials.private.json'),
        *[QUAL / name for name in PAYLOAD['originalReaderSourcePins']],
        *[Path('/Users/qianqi/.openclaw/agents/main/agent/openclaw-agent.sqlite' + suffix)
          for suffix in ('', '-wal', '-shm', '-journal')]}
    literals = set(fixed) | {ROOT, *ROOT.parents, QUAL, *QUAL.parents}
    for path in fixed:
        literals.update(path.parents)
    for path in sorted(literals, key=str):
        policy.append('(allow file-read* (literal ' + json.dumps(str(path)) + '))')
    for name in ('/dev/null', '/dev/random', '/dev/urandom'):
        policy.append('(allow file-read* (literal ' + json.dumps(name) + '))')
    policy.extend(['(allow file-write* (subpath ' + json.dumps(str(ROOT / 'output')) + '))',
                   '(allow file-write* (literal "/dev/null"))'])
    create_owned(ROOT / 'reader.sb', ('\n'.join(policy) + '\n').encode())
    authority = PAYLOAD['custodyQualificationAuthority']
    need(authority['job_id'] == '1a1b141ef40-fc05-7750' and authority['state'] == 'succeeded'
         and authority['exit_code'] == 0 and all(authority[key] is True for key in
             ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
         and all(authority[key] is False for key in ('timed_out', 'cancelled', 'automatic_retry')),
         'relation_parent_original_custody_authority')
    proof, _ = bounded_original_read(QUAL.parent / 'result.public.json', 65536)
    need(len(proof) == 58701 and hashlib.sha256(proof).hexdigest()
         == '67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e',
         'relation_parent_original_actual_custody_proof')
    value = json.loads(proof)
    need(value['ok'] and value['allCasesMatched'] and value['allOwnedClosed']
         and value['custody']['passed_process_custody'] and value['custody']['original_count'] == 18,
         'relation_parent_original_eighteen_custody_cases')
    return None


def reader_source_fence():
    remaining()
    for name, expected in PAYLOAD['readerPins'].items():
        raw, _ = bounded_original_read(ROOT / 'code' / name, 65536)
        need(hashlib.sha256(raw).hexdigest() == expected, 'relation_parent_reader_whole_source_exact')
    for name, expected in {**PAYLOAD['originalReaderSourcePins'], **PAYLOAD['custodyPins']}.items():
        raw, _ = bounded_original_read(QUAL / name, 65536)
        need(hashlib.sha256(raw).hexdigest() == expected, 'relation_parent_original_readonly_sources_exact')
    raw, _ = bounded_original_read(Path('/usr/bin/sandbox-exec'), 2097152)
    need(hashlib.sha256(raw).hexdigest() == 'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a',
         'relation_parent_actual_sandbox_runtime_exact')


def close_original_streams():
    if child is not None:
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def execute_reader(candidate_until):
    global owner, child
    reader_source_fence()
    for name in PAYLOAD['custodyPins']:
        need(Path(name).stem not in sys.modules, 'relation_original_custody_import_once')
    sys.path.insert(0, str(QUAL))
    import kv2_dr_process_custody as custody
    with custody.activated() as owner:
        left = min(20, candidate_until - time.monotonic(), UNTIL - time.monotonic())
        need(left > 0, 'relation_original_reader_fits_remaining_candidate_deadline')
        report['originalReadonlyChildLaunchAttempts'] = 1
        report['childProcesses'] = None
        report['currentMainSqlObservationCount'] = None
        child = subprocess.Popen(['/usr/bin/sandbox-exec', '-f', str(ROOT / 'reader.sb'), str(PYTHON),
            '-I', '-S', '-B', str(ROOT / 'code/read_current_main3_candidate_relation_r2.py'),
            repr(min(candidate_until, UNTIL))], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(ROOT),
            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/Users/qianqi', 'LANG': 'C', 'LC_ALL': 'C'})
        report['childProcesses'] = 1
        out, err = child.communicate(timeout=left)
        close_original_streams()
        need(len(out) <= 65536 and len(err) <= 65536, 'relation_original_child_bounded_streams')
        create_owned(ROOT / 'output/reader.stdout.public.json', out)
        create_owned(ROOT / 'output/reader.stderr.private', err)
        report['originalReader'] = {'exitCode': child.returncode, 'stdoutBytes': len(out),
            'stderrBytes': len(err), 'streamsClosed': True}
        if out:
            report['currentReader'] = json.loads(out)
            report['credentialEqualityCompared'] = report['currentReader'].get(
                'privateCandidateEqualityComparisonPerformed') is True
            closure = report['currentReader'].get('currentReadClosure')
            if type(closure) is dict:
                report['currentMainSqlObservationCount'] = closure.get('queryCount')
        need(child.returncode == 0 and not err and report['currentReader']['ok'],
             'relation_original_reader_known_success')
        value = report['currentReader']
        need(value['currentSelectedOwnerCount'] == 3 and value['providerCalls'] == 0
             and value['sdkImports'] == 0 and value['productionWrites'] == 0
             and value['serviceActions'] == 0 and value['keychainReads'] == 0
             and value['allOriginalDescriptorsClosedOnce'] and value['closedScopeNamesExact']
             and value['scopeClosure']['allOriginalDescriptorsClosedOnce']
             and len(value['kernelDenials']) == 4 and all(row['denied'] for row in value['kernelDenials'])
             and value['probeSocketClosed'] and value['currentReadClosure']['allOwnedDescriptorsClosed']
             and value['currentReadClosure']['allReturnedConnectionsClosed']
             and value['currentReadClosure']['allExplicitCursorsClosed'],
             'relation_original_current_read_and_resources_closed')
    report['custody'] = owner.receipt()
    need(report['custody']['passed_process_custody'] and report['custody']['original_count'] == 1,
         'relation_original_reader_child_custody_complete')
    reader_source_fence()
    raw, identity = bounded_original_read(ROOT / 'output/current-main3-candidate-relation.private.json',
                                         2097152, private=True)
    value = json.loads(raw)
    need(value['schema'] == 'heptabao.current-main3-candidate-relation.private.r1'
         and value['originalParentPid'] == os.getpid(), 'relation_original_same_parent_private_result')
    for name in ('main3_source_authority.py', 'mac_current_selected_main3_r2.py'):
        source = PAYLOAD['readerSources'][name]
        key = Path(name).stem
        need(key not in sys.modules, 'relation_parent_current_namespace_module_once')
        module = types.ModuleType(key); module.__file__ = str(ROOT / 'code' / name)
        sys.modules[key] = module
        exec(compile(source, module.__file__, 'exec'), module.__dict__)
    from mac_current_selected_main3_r2 import verify_current_namespace
    verify_current_namespace(value['currentSelectedOwners'], until=candidate_until)
    return value, raw, identity, verify_current_namespace


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
         'mac_codex_backend_procargs_r1.py', 'mac_codex_candidate_backend_r1.py',
         'mac_codex_fixed_candidate_inputs_r1.py'}, 'candidate_exact_five_source_modules')
    for name, source in PAYLOAD['sources'].items():
        need(hashlib.sha256(source.encode()).hexdigest() == PAYLOAD['sourcePins'][name],
             'selector_exact_module_whole_source_pin')
        ast.parse(source)
    need([row['pid'] for row in PAYLOAD['processes']] == [66414, 66687, 89324, 89325]
         and all(set(row) == {'pid','ppid','pgid','uid','birthSec','birthUsec'}
                 and all(type(value) is int for value in row.values()) for row in PAYLOAD['processes']),
         'selector_exact_four_original_numeric_identities')
    setup_private_directories()
    prepare_reader()
    for name, source in PAYLOAD['sources'].items():
        module = types.ModuleType(Path(name).stem)
        module.__file__ = str(ROOT / name)
        sys.modules[module.__name__] = module
        exec(compile(source, module.__file__, 'exec'), module.__dict__)
    from mac_native_process_observer_r1 import ProcessReader
    from mac_codex_backend_procargs_r1 import parse_procargs, SelectorRefused
    from mac_codex_fixed_candidate_inputs_r1 import FixedCandidateInputs, InputsRefused
    from mac_codex_candidate_backend_r1 import CandidateRefused
    reader, args_reader = ProcessReader(), ArgsReader()
    first = []
    for ordinal, expected in enumerate(PAYLOAD['processes']):
        report['observationOrdinal'] = ordinal
        first.append(sample(reader, args_reader, expected, ordinal))
    private_output('selectors-first.private.json', {'schema': 'heptabao.finite-selectors.private.r1',
        'priorAuthority': PAYLOAD['priorAuthority'], 'observations': first})
    def candidate_source_fence():
        remaining()
        need({path: pin_public(path, expected) for path, expected in pins.items()} == before_pins,
             'candidate_actual_public_code_generation_exact')
    candidate_until = min(UNTIL, time.monotonic() + 20)
    candidate_inputs = FixedCandidateInputs(until=candidate_until, source_fence=candidate_source_fence,
        private_write=private_output)
    candidate_inputs.capture([{'private': row['private'], 'public': row['public']} for row in first])
    current_private, current_raw, current_identity, verify_current_namespace = execute_reader(candidate_until)
    second = []
    for ordinal, expected in enumerate(PAYLOAD['processes']):
        report['observationOrdinal'] = ordinal
        second.append(sample(reader, args_reader, expected, ordinal))
    private_output('selectors-second.private.json', {'schema': 'heptabao.finite-selectors.private.r1',
        'priorAuthority': PAYLOAD['priorAuthority'], 'observations': second})
    need(first == second, 'selector_all_four_selected_bindings_unchanged_between_observations')
    need(all(reader.read(row['pid']) == row['identity'] for row in first),
         'selector_final_four_process_births_unchanged')
    candidate_inputs.verify()
    verify_current_namespace(current_private["currentSelectedOwners"], until=candidate_until)
    need(bounded_original_read(ROOT / "output/current-main3-candidate-relation.private.json",
                               2097152, private=True) == (current_raw, current_identity),
         "relation_original_private_result_still_exact")
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
    report['originalR4ActualEvidenceMap'] = PAYLOAD['originalR4ActualEvidenceMap']
    report['currentMain3ComparisonPerformed'] = True
    report['candidateFileObservationIsCurrentBackendProof'] = False
    report['credentialEqualityCompared'] = True
    report['currentMainSqlObservationCount'] = report['currentReader']['currentReadClosure']['queryCount']
    report['historicalValuesUsedAsCurrent'] = False
    report['originalCandidateActualEvidenceMap'] = '0d02daa98cea1a18815f3d3ab0141312910d300d'
    report['publicFilePins'] = {path: {'bytes': value[0], 'sha256': value[1]} for path, value in pins.items()}
    report['priorAuthority'] = PAYLOAD['priorAuthority']
    report['ok'] = True
except BaseException as error:
    report['ok'] = False
    report['errorClass'] = type(error).__name__ if type(error).__name__ in (
        'RuntimeError','SelectorRefused','ObservationRefused','InputsRefused','CandidateRefused','OSError','FileNotFoundError',
        'PermissionError','UnicodeDecodeError') else 'OtherException'
    code = str(error)
    report['errorCode'] = code if code in codes or type(error).__name__ in (
        'SelectorRefused','ObservationRefused','InputsRefused','CandidateRefused') and code.isascii() and code.replace('_','').isalnum() else 'selector_observation_refused'
finally:
    errors = []
    close_original_streams()
    if owner is not None:
        report["custody"] = owner.receipt()
        if not report["custody"].get("passed_process_custody"):
            report["ok"] = False
    if candidate_inputs is not None:
        try:
            report['candidateInputs'] = candidate_inputs.close()
            report['authFileContentsRead'] = report['candidateInputs']['authFileContentsRead']
            report['ok'] = bool(report['ok'] and report['candidateInputs']['ok']
                and report['candidateInputs']['allSourceDescriptorsClosedOnce']
                and report['candidateInputs'].get('closedSourceNamesStillExact') is True)
        except BaseException:
            errors.append('candidate_original_source_close_or_generation_unknown')
            report['ok'] = False
    if report["ok"] and current_private is not None:
        try:
            verify_current_namespace(current_private["currentSelectedOwners"], until=candidate_until)
            report["mainGenerationExactAfterCandidateClose"] = True
        except BaseException:
            report["ok"] = False
            report["mainGenerationExactAfterCandidateClose"] = False
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
