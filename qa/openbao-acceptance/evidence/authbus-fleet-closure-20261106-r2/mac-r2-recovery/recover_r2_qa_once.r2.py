#!/usr/bin/env python3
"""Independent, once-only cleanup of a reconciled failed Mac QA registration.

No business replay, production mutation, original result overwrite, or data deletion.
"""
import ast
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import time

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r2')
HOME = Path('/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r2')
LABEL = 'org.heptabao.qa.mac-authbus-4e808-home-r2.server'
TARGET = 'gui/501/' + LABEL
PID = 32527
KERNEL_PYTHON = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python'
LAUNCHER = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
MANAGER_SHA = '8feb3f9db05fa59986409c6c1306b48213102c7deaae6035219afa959add5ae4'
CANDIDATE_SHA = '59aa264489cc8ebea2943a0a7bab68c419da52d645532391ec369b973d555941'
OBSERVER_SHA = 'cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b'
OLD = """            typed_value=fields[name]
            if name=='last exit code' and typed_value=='78: EX_CONFIG':
"""
NEW = """            typed_value=fields[name]
            if name=='last exit code' and typed_value=='(never exited)':
                # An unexited registration has no successful exit observation.
                # Keep None so actual_launchd_phase_exit_zero still rejects it.
                fields[name]=None
                continue
            if name=='last exit code' and typed_value=='78: EX_CONFIG':
"""

class Refused(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def safe_read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501
             and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             'bounded_regular_owner_file')
        raw = os.read(fd, maximum + 1)
        need(len(raw) == before.st_size and not os.read(fd, 1), 'whole_file_read')
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'stable_whole_file_identity')
        return raw, identity(before)
    finally:
        os.close(fd)

def walk(value):
    pending = [('$', value)]
    visited = 0
    while pending:
        path, item = pending.pop()
        visited += 1
        need(visited < 15000, 'bounded_public_json_tree')
        if isinstance(item, dict):
            yield path, item
            pending.extend((path + '.' + str(k), v) for k, v in item.items()
                           if isinstance(v, (dict, list)))
        elif isinstance(item, list):
            pending.extend((path + '[' + str(i) + ']', v) for i, v in enumerate(item)
                           if isinstance(v, (dict, list)))

def extract(raw, names, namespace):
    nodes = [n for n in ast.parse(raw).body
             if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    need(len(nodes) == len(names) and {n.name for n in nodes} == set(names),
         'exact_pinned_pure_definitions')
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<pinned-readonly-definitions>', 'exec'), namespace)
    return namespace

import errno

RECOVERY_ROOT = Path('/Users/qianqi/heptabao-mac-authbus-r2-recovery-20261106-r2')
WRAPPER_SHA = '34aa6a9799419573dfc8cf6b63f479162b3e9e316dc391d54c5f0c0c54cdedb1'
EXPECTED_IDENTITY = {
    'pid': 32527, 'ppid': 1, 'pgid': 32527, 'uid': 501,
    'birthSec': 1793969379, 'birthUsec': 298893, 'executable': KERNEL_PYTHON,
}
CLEANUP_SECONDS = 60
TERM_GRACE_SECONDS = 20
KILL_GRACE_SECONDS = 10
QUERY_SECONDS = 10
PS_SECONDS = 4
POLL_SECONDS = 0.25
READONLY_JOB = '1a1b101ed2a-fc05-74d6'


class Journal:
    """One create-only recovery directory, held by fd; no resume or overwrite."""

    def __init__(self):
        self.fd = None
        self.closed = False
        self.written = []
        parent = os.open(RECOVERY_ROOT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == 501
                 and not info.st_mode & 0o022, 'private_operator_parent')
            os.mkdir(RECOVERY_ROOT.name, 0o700, dir_fd=parent)
            os.fsync(parent)
            self.fd = os.open(RECOVERY_ROOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=parent)
        finally:
            os.close(parent)
        info = os.fstat(self.fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 501
             and stat.S_IMODE(info.st_mode) == 0o700, 'new_private_journal')
        self.bound = identity(info)[:5]
        self.check()

    def check(self):
        need(self.fd is not None and not self.closed, 'journal_fd_open')
        need(identity(os.fstat(self.fd))[:5] == identity(RECOVERY_ROOT.lstat())[:5] == self.bound,
             'held_named_journal_identity')

    def write_new(self, name, value):
        self.check()
        need(re.fullmatch(r'[0-9]{3}-[a-z0-9-]+\.public\.json', name) is not None
             and name not in self.written, 'once_fixed_journal_leaf')
        raw = (json.dumps(value, sort_keys=True) + '\n').encode()
        need(len(raw) <= 262144, 'bounded_journal_record')
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 501
                 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                 'private_regular_journal_leaf')
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                need(count > 0, 'journal_write_progress')
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self.fd)
        self.check()
        self.written.append(name)
        return sha(raw)

    def close_once(self):
        if self.fd is None or self.closed:
            return
        self.check()
        fd = self.fd
        self.fd = None
        os.close(fd)
        self.closed = True


class Recovery:
    """A new cleanup-only operation; never reopens the old business state machine."""

    def __init__(self):
        self.started = time.monotonic()
        self.until = self.started + CLEANUP_SECONDS
        self.journal = None
        self.bindings = []
        self.attempts = {}
        self.commands = []
        self.observation_count = 0
        self.report = {
            'schema': 'heptabao.mac-authbus-r2-recovery-cleanup.r2',
            'previousRecoveryPreflightFailureJob': '1a1b11278be-fc05-7587',
            'previousRecoveryMutationAttemptsWereEmpty': True,
            'executedHelperSha256': globals().get('__source_sha256__'),
            'ok': False, 'recoveryOutcomeUnknown': False, 'target': TARGET,
            'expectedCurrentIdentity': EXPECTED_IDENTITY, 'readOnlyReconciliationJob': READONLY_JOB,
            'cleanupSeconds': CLEANUP_SECONDS, 'termGraceSeconds': TERM_GRACE_SECONDS,
            'killGraceSeconds': KILL_GRACE_SECONDS, 'querySeconds': QUERY_SECONDS,
            'psSeconds': PS_SECONDS, 'originalBusinessDeadlineRenewed': False,
            'originalFailedResultModified': False, 'oldManagerImported': False,
            'oldBirthIdentityReconstructed': False, 'originalRunSuccessClaimed': False,
            'businessExecutionStarted': False, 'providerRequested': False, 'j3160Contacted': False,
            'productionServiceOperationDispatched': False, 'dataFilesDeleted': False,
            'noNumericQaPidOrGroupSignals': True, 'credentialValuesOrDigestsIncluded': False,
            'hostileEscapedDescendantContainmentClaimed': False,
            'serviceMutationAttempts': self.attempts,
            'helperCommandReceipts': self.commands,
            'newJournalRoot': str(RECOVERY_ROOT),
        }

    def remaining(self, cap=None):
        value = self.until - time.monotonic()
        need(value > 0, 'single_recovery_cleanup_deadline')
        return value if cap is None else min(value, cap)

    def read_bound(self, path, maximum, public_name=None, required_sha=None):
        self.remaining()
        raw, bound = safe_read(path, maximum)
        self.remaining()
        digest = sha(raw)
        if required_sha is not None:
            need(digest == required_sha, 'pinned_immutable_public_source')
        self.bindings.append((path, maximum, bound, digest))
        if public_name is not None:
            self.report.setdefault('publicInputSha256', {})[public_name] = digest
        return raw

    def guard(self):
        self.remaining()
        for path, maximum, bound, digest in self.bindings:
            raw, current = safe_read(path, maximum)
            need(current == bound and sha(raw) == digest, 'original_input_changed')
            self.remaining()
        for suffix in ('ready.public.json', 'admitted.private.json', 'exec-ready.public.json'):
            try:
                (ROOT / 'launchd' / ('server-initial.' + suffix)).lstat()
            except FileNotFoundError:
                continue
            raise Refused('unexpected_business_admission_artifact')
        if self.journal is not None:
            self.journal.check()
        self.remaining()

    def call(self, label, argv, cap=QUERY_SECONDS):
        self.remaining()
        need(len(self.commands) < 384, 'finite_recovery_command_count')
        row = {'index': len(self.commands), 'label': label, 'attempted': True,
               'complete': False, 'outcomeUnknown': False}
        self.commands.append(row)
        try:
            proc = subprocess.run(argv, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.remaining(cap), check=False,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
            self.remaining()
            need(len(proc.stdout) <= 262144 and len(proc.stderr) <= 4096,
                 'bounded_helper_output')
            row.update(complete=True, exitCode=proc.returncode,
                       stdoutBytes=len(proc.stdout), stderrBytes=len(proc.stderr))
            return row, proc.stdout, proc.stderr
        except BaseException:
            row['outcomeUnknown'] = True
            self.report['recoveryOutcomeUnknown'] = True
            raise

    def preflight(self):
        need(sys.platform == 'darwin' and os.geteuid() == 501, 'fixed_mac_operator')
        need(re.fullmatch(r'[0-9a-f]{64}', str(globals().get('__source_sha256__'))) is not None,
             'source_hash_supplied_by_pinned_loader')
        raw = self.read_bound(ROOT / 'qa/mac_owned_launchd_r3.py', 65536,
                              'originalManager', MANAGER_SHA)
        source = raw.decode('utf-8', 'strict')
        need(source.count(OLD) == 1, 'one_known_parser_patch')
        candidate = source.replace(OLD, NEW, 1)
        need(sha(candidate.encode()) == CANDIDATE_SHA, 'pinned_readonly_parser')
        self.parse = extract(candidate, ['parse_print'], {'need': need, 're': re})['parse_print']
        observer = self.read_bound(ROOT / 'qa/mac_native_process_observer_r1.py', 65536,
                                   'libprocObserver', OBSERVER_SHA)
        ns = extract(observer, ['ObservationRefused', 'require', 'BsdInfo', 'ProcessReader'],
                     {'ctypes': ctypes, 'Path': Path, 'sys': sys})
        self.reader = ns['ProcessReader']()
        self.BsdInfo = ns['BsdInfo']
        self.read_bound(ROOT / 'qa/mac_current_server_owner_r1.py', 65536,
                        'originalWrapper', WRAPPER_SHA)
        self.read_bound(HOME / 'mac_current_server_owner_r1.py', 65536,
                        'homeWrapper', WRAPPER_SHA)
        raw = self.read_bound(ROOT / 'outer-native-r1/result.public.json', 524288,
                              'originalFailedPublicResult')
        original = json.loads(raw)
        manager = original.get('manager', {})
        need(manager.get('schema') == 'heptabao.mac-owned-launchd-manager.r3'
             and manager.get('ok') is False and manager.get('outcomeUnknown') is True
             and manager.get('failureCleanupAttempted') is True
             and manager.get('completedOperationCount') == 0,
             'original_failed_manager_unchanged')
        entries = manager.get('registrations')
        need(isinstance(entries, list) and len(entries) == 1, 'single_original_registration')
        entry = entries[0]
        need(entry.get('label') == LABEL and entry.get('generation') == 'server-initial'
             and entry.get('kind') == 'server' and entry.get('wrapperIdentity') is None
             and entry.get('execIdentity') is None and entry.get('knownOwnedGroups') == []
             and entry.get('registrationClosed') is False and entry.get('lineagesClosed') is False
             and entry.get('cleanupErrorCode') == 'typed_launchctl_integer',
             'original_unadmitted_registration')
        attempts = entry.get('attempts', {})
        need(set(attempts) == {'bootstrap'} and attempts['bootstrap'].get('attempted') is True
             and attempts['bootstrap'].get('complete') is True
             and attempts['bootstrap'].get('exitCode') == 0, 'original_bootstrap_only_ledger')
        commands = manager.get('ownedCommands', {})
        need(commands.get('allOwnedCommandsStopped') is True
             and commands.get('unknownCommandCount') == 0, 'original_helpers_closed')
        rows = commands.get('commands')
        need(isinstance(rows, list), 'original_command_rows_present')
        launches = [r for r in rows if isinstance(r.get('label'), str)
                    and r['label'].startswith('launchd-')]
        need(len(launches) == 6 and sum(r['label'] == 'launchd-bootstrap' for r in launches) == 1
             and all(r['label'] in ('launchd-print', 'launchd-bootstrap')
                     and r.get('outcomeUnknown') is False
                     and r.get('completeBeforeDeadline') is True for r in launches),
             'no_original_signal_or_bootout_dispatched')
        self.report['originalLedgerVerified'] = {
            'bootstrapCompleteExitZero': True, 'termKillBootoutNeverAttempted': True,
            'ownedCommandUnknownCount': 0, 'launchctlCommandCount': len(launches),
            'oldWrapperIdentityAbsent': True, 'oldExecIdentityAbsent': True,
        }
        event = json.loads(self.read_bound(
            ROOT / 'launchd/000-server-initial-bootstrap-intent.public.json', 4096,
            'originalBootstrapIntent'))
        cleanup = json.loads(self.read_bound(ROOT / 'launchd/server-initial.cleanup-intent.public.json',
                                            4096, 'originalCleanupIntent'))
        self.plist_path = HOME / 'server-initial.plist'
        plist_raw = self.read_bound(self.plist_path, 65536, 'originalPlist')
        plist = plistlib.loads(plist_raw)
        plan_raw = self.read_bound(ROOT / 'launchd/server-initial.private.json', 4096)
        detail = event.get('detail', {})
        need(event.get('schema') == 'heptabao.mac-owned-launchd-event.r3'
             and event.get('kind') == 'bootstrap-intent' and event.get('index') == 0
             and event.get('generation') == 'server-initial'
             and detail.get('argv') == ['/bin/launchctl', 'bootstrap', 'gui/501', str(self.plist_path)]
             and sha(plist_raw) == entry.get('plistSha256') == detail.get('plistSha256')
             and sha(plan_raw) == entry.get('planSha256') == detail.get('planSha256'),
             'original_plist_plan_bootstrap_binding')
        need(cleanup.get('schema') == 'heptabao.mac-owned-launchd-cleanup-intent.r3'
             and cleanup.get('generation') == 'server-initial' and cleanup.get('target') == TARGET
             and cleanup.get('termArgv') == ['/bin/launchctl', 'kill', 'SIGTERM', TARGET]
             and cleanup.get('killArgv') == ['/bin/launchctl', 'kill', 'SIGKILL', TARGET]
             and cleanup.get('bootoutArgv') == ['/bin/launchctl', 'bootout', TARGET]
             and cleanup.get('newCleanupSeconds') == CLEANUP_SECONDS,
             'original_fixed_cleanup_intent')
        self.args = plist.get('ProgramArguments')
        need(isinstance(self.args, list) and self.args[:5] == [LAUNCHER, '-I', '-S', '-B',
             str(HOME / 'mac_current_server_owner_r1.py')], 'exact_python_wrapper_prefix')
        expected_plist = {
            'Label': LABEL, 'ProgramArguments': self.args, 'RunAtLoad': True, 'KeepAlive': False,
            'AbandonProcessGroup': False, 'ProcessType': 'Background', 'ExitTimeOut': 10,
            'Umask': 0o077, 'WorkingDirectory': str(HOME),
            'StandardOutPath': str(HOME / 'server-initial.stdout.private'),
            'StandardErrorPath': str(HOME / 'server-initial.stderr.private'),
            'EnvironmentVariables': {'PATH': '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
                                     'LANG': 'C', 'LC_ALL': 'C'},
        }
        need(plist == expected_plist, 'entire_original_plist_no_restart')
        self.report['originalPlistPlanAndSourceBindingsVerified'] = True
        self.report['privatePlanDigestPublished'] = False
        self.guard()
        first = self.observe()
        second = self.observe()
        need(first['state'] == second['state'] == 'live', 'same_live_wrapper_before_recovery')
        self.report['initialObservation'] = second
        self.journal = Journal()
        intent = {
            'schema': 'heptabao.mac-authbus-r2-independent-cleanup-intent.r1',
            'target': TARGET, 'expectedCurrentIdentity': EXPECTED_IDENTITY,
            'readOnlyReconciliationJob': READONLY_JOB,
            'publicInputSha256': self.report['publicInputSha256'],
            'originalBootstrapOnlyLedgerVerified': True,
            'exactOriginalPlistAndAllRegisteredArgumentsVerified': True,
            'privatePlanDigestPublished': False, 'initialObservation': second,
            'cleanupSeconds': CLEANUP_SECONDS, 'termGraceSeconds': TERM_GRACE_SECONDS,
            'killGraceSeconds': KILL_GRACE_SECONDS,
            'mutationOrder': ['term-once', 'optional-kill-once', 'bootout-once'],
            'noBusinessReplay': True, 'noOriginalResultRewrite': True,
            'noNumericQaPidOrGroupSignals': True, 'noDataFileDeletion': True,
        }
        self.remaining()
        self.report['durableInitialIntentSha256'] = self.journal.write_new('001-intent.public.json', intent)
        self.guard()

    def query(self):
        row, out, err = self.call('launchctl-print', ['/bin/launchctl', 'print', TARGET])
        if row['exitCode'] in (3, 113) and not out:
            expected = 'Could not find service "' + LABEL + '" in domain for user gui: 501'
            lines = err.decode('utf-8', 'strict').splitlines()
            need(lines in ([expected], ['Bad request.', expected]), 'exact_absence_response')
            return None
        need(row['exitCode'] == 0 and not err, 'known_launchctl_query')
        state = self.parse(out, TARGET)
        need(state.get('path') == str(self.plist_path) and state.get('program') == self.args[0]
             and state.get('arguments') == self.args and state.get('runs') == 1,
             'same_exact_registration_and_run')
        need(state.get('pid') in (None, PID), 'no_replacement_registration_pid')
        return state

    def related_rows(self):
        row, out, err = self.call('ps-fixed-metadata',
            ['/bin/ps', '-axo', 'pid=,ppid=,pgid=,uid=,stat='], PS_SECONDS)
        need(row['exitCode'] == 0 and not err, 'complete_process_metadata')
        rows = []
        for line in out.decode('ascii', 'strict').splitlines():
            fields = line.split()
            need(len(fields) == 5 and all(v.isdecimal() for v in fields[:3])
                 and (fields[3].isdecimal() or fields[3] == '-2')
                 and re.fullmatch(r'[A-Za-z0-9+<>=-]{1,16}', fields[4]) is not None,
                 'typed_process_metadata')
            pid, ppid, pgid, uid = map(int, fields[:4])
            if pid == PID or ppid == PID or pgid == PID:
                rows.append({'pid': pid, 'ppid': ppid, 'pgid': pgid, 'uid': uid, 'stat': fields[4]})
        return rows

    def native_absent(self):
        info = self.BsdInfo()
        ctypes.set_errno(0)
        count = self.reader.lib.proc_pidinfo(PID, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
        error = ctypes.get_errno()
        need(count == 0 and error == errno.ESRCH, 'native_original_pid_absent')
        return {'returnedBytes': count, 'errno': error, 'originalPidAbsent': True}

    def observe(self, allow_missing=False):
        self.guard()
        state = self.query()
        need(state is not None or allow_missing, 'no_unexplained_registration_disappearance')
        rows = self.related_rows()
        self.observation_count += 1
        record = {'index': self.observation_count, 'relatedProcessRows': rows,
                  'allRegisteredArgumentsExact': state is not None}
        if state is None:
            need(not rows, 'no_related_process_after_registration_absence')
            record.update(state='absent', nativePidAbsence=self.native_absent())
        elif state.get('pid') is None:
            need(not rows, 'no_pid_group_or_child_before_bootout')
            record.update(state='retired', nativePidAbsence=self.native_absent(),
                launchctlTerminal={k: state.get(k) for k in
                    ('runs', 'state', 'last exit code', 'last terminating signal')})
        elif not rows:
            record.update(state='retiring', nativePidAbsence=self.native_absent())
        else:
            need(len(rows) == 1 and rows[0]['pid'] == PID and rows[0]['ppid'] == 1
                 and rows[0]['pgid'] == PID and rows[0]['uid'] == 501,
                 'no_new_child_or_group_member')
            if 'Z' in rows[0]['stat']:
                info = self.BsdInfo()
                count = self.reader.lib.proc_pidinfo(PID, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
                need(count == ctypes.sizeof(info)
                     and (info.pid, info.ppid, info.pgid, info.uid, info.birth_sec, info.birth_usec)
                     == (PID, 1, PID, 501, EXPECTED_IDENTITY['birthSec'], EXPECTED_IDENTITY['birthUsec']),
                     'same_birth_retiring_zombie')
                record['state'] = 'retiring'
            else:
                current = self.reader.read(PID)
                need(current == EXPECTED_IDENTITY, 'exact_current_libproc_identity')
                children = self.reader.children(PID)
                need(children == [], 'no_new_direct_child')
                record.update(state='live', processIdentity=current, directChildPids=children)
        self.guard()
        return record

    def dispatch_once(self, operation):
        need(operation in ('term', 'kill', 'bootout') and operation not in self.attempts,
             'one_new_recovery_action_per_operation')
        required_state = 'retired' if operation == 'bootout' else 'live'
        before = self.observe()
        need(before['state'] == required_state, 'mutation_precondition_exact_state')
        if operation == 'kill':
            need(self.attempts.get('term', {}).get('complete') is True
                 and self.report.get('termGraceExpiredSameBirth') is True,
                 'kill_only_after_complete_term_and_same_birth_grace')
        if operation == 'bootout':
            need(self.attempts.get('term', {}).get('complete') is True,
                 'bootout_only_after_known_recovery_signal')
        number = {'term': 10, 'kill': 20, 'bootout': 30}[operation]
        argv = {'term': ['/bin/launchctl', 'kill', 'SIGTERM', TARGET],
                'kill': ['/bin/launchctl', 'kill', 'SIGKILL', TARGET],
                'bootout': ['/bin/launchctl', 'bootout', TARGET]}[operation]
        intent = {
            'schema': 'heptabao.mac-authbus-r2-cleanup-action-intent.r1',
            'operation': operation, 'argv': argv, 'expectedCurrentIdentity': EXPECTED_IDENTITY,
            'inputBindingsSha256': self.report['publicInputSha256'],
            'initialIntentSha256': self.report['durableInitialIntentSha256'],
            'before': before, 'remainingSecondsAtIntent': self.remaining(),
            'originalOperationWasNeverDispatched': True,
        }
        digest = self.journal.write_new('%03d-%s-intent.public.json' % (number, operation), intent)
        self.remaining()
        # The second observation occurs after the fsynced intent and before dispatch.
        second = self.observe()
        need(second['state'] == required_state, 'mutation_post_intent_state_unchanged')
        self.attempts[operation] = {'attempted': True, 'complete': False, 'intentSha256': digest}
        row, out, err = self.call('launchctl-' + operation, argv)
        self.attempts[operation].update(complete=True, exitCode=row['exitCode'])
        receipt = {'schema': 'heptabao.mac-authbus-r2-cleanup-command.r1',
                   'operation': operation, 'receipt': row,
                   'stdout': out.decode('utf-8', 'strict'), 'stderr': err.decode('utf-8', 'strict')}
        self.journal.write_new('%03d-%s-command.public.json' % (number + 1, operation), receipt)
        need(row['exitCode'] == 0 and not out and not err, 'known_empty_launchctl_mutation_success')
        self.guard()
        after = self.observe(allow_missing=operation == 'bootout')
        self.journal.write_new('%03d-%s-observed.public.json' % (number + 2, operation), after)
        self.report[operation + 'ImmediateAfter'] = after
        return after

    def wait_retired(self, seconds):
        grace_until = min(self.until, time.monotonic() + seconds)
        last = None
        while True:
            last = self.observe()
            need(last['state'] in ('live', 'retiring', 'retired'), 'finite_retirement_state')
            if last['state'] == 'retired':
                return last
            remaining = min(self.remaining(), grace_until - time.monotonic())
            if remaining <= 0:
                return last
            time.sleep(min(POLL_SECONDS, remaining))

    def run(self):
        self.preflight()
        after = self.dispatch_once('term')
        retired = after if after['state'] == 'retired' else self.wait_retired(TERM_GRACE_SECONDS)
        if retired['state'] != 'retired':
            need(retired['state'] == 'live', 'grace_expired_only_same_live_identity_can_escalate')
            self.report['termGraceExpiredSameBirth'] = True
            after = self.dispatch_once('kill')
            retired = after if after['state'] == 'retired' else self.wait_retired(KILL_GRACE_SECONDS)
        need(retired['state'] == 'retired', 'known_original_wrapper_retired')
        self.report['beforeBootout'] = retired
        after = self.dispatch_once('bootout')
        end = min(self.until, time.monotonic() + QUERY_SECONDS)
        while after['state'] != 'absent':
            need(after['state'] == 'retired', 'no_revival_after_bootout')
            need(time.monotonic() < end, 'bounded_bootout_absence_wait')
            time.sleep(min(POLL_SECONDS, self.remaining()))
            after = self.observe(allow_missing=True)
        second = self.observe(allow_missing=True)
        need(second['state'] == 'absent', 'stable_exact_label_and_process_absence')
        self.report['finalAbsence'] = second
        self.report['registrationClosedByThisRecovery'] = True
        self.report['knownOriginalPidGroupAndChildrenAbsent'] = True
        self.guard()
        self.report['ok'] = True
        self.report['observationCount'] = self.observation_count
        self.report['elapsedSecondsBeforeFinalJournal'] = time.monotonic() - self.started
        self.report['finalJournalReceiptIsCandidateUntilStdoutAndRuntimeTerminal'] = True
        self.report['finalJournalSha256'] = self.journal.write_new('900-result.public.json', self.report)
        self.remaining()


def main():
    recovery = Recovery()
    try:
        recovery.run()
    except Refused as error:
        recovery.report['ok'] = False
        recovery.report['recoveryOutcomeUnknown'] = True
        recovery.report['errorCode'] = str(error)
    except BaseException as error:
        recovery.report['ok'] = False
        recovery.report['recoveryOutcomeUnknown'] = True
        recovery.report['errorType'] = type(error).__name__
    finally:
        journal = recovery.journal
        if journal is not None:
            if not recovery.report['ok']:
                try:
                    journal.write_new('999-unknown.public.json', recovery.report)
                except BaseException as error:
                    recovery.report['unknownJournalErrorType'] = type(error).__name__
            try:
                journal.close_once()
                recovery.report['journalDescriptorClosed'] = journal.closed
            except BaseException as error:
                recovery.report['ok'] = False
                recovery.report['recoveryOutcomeUnknown'] = True
                recovery.report['journalCloseErrorType'] = type(error).__name__
        else:
            recovery.report['journalCreated'] = False
        recovery.report['elapsedSeconds'] = time.monotonic() - recovery.started
        print(json.dumps(recovery.report, sort_keys=True), flush=True)
    return 0 if recovery.report['ok'] and not recovery.report['recoveryOutcomeUnknown'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
