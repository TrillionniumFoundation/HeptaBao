#!/usr/bin/env python3
"""Read-only reconciliation evidence for one failed, fixed Mac QA registration.

This does not authorize cleanup, import a manager, or renew an old deadline.
Private plans and launch arguments are compared in memory and never emitted.
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

def main():
    started = time.monotonic()
    until = started + 45
    report = {
        'schema': 'heptabao.mac-authbus-r2-recovery-readonly.r1',
        'ok': False, 'target': TARGET, 'observations': [],
        'oldManagerImported': False, 'serviceMutationDispatched': False,
        'qaProcessSignalDispatched': False, 'oldBusinessDeadlineRenewed': False,
        'providerRequested': False, 'j3160Contacted': False,
        'credentialValuesOrDigestsIncluded': False,
        'originalRunSuccessClaimed': False, 'cleanupAuthorized': False,
    }
    try:
        need(sys.platform == 'darwin' and os.geteuid() == 501, 'fixed_mac_operator')
        raw_manager, manager_id = safe_read(ROOT / 'qa/mac_owned_launchd_r3.py', 65536)
        need(sha(raw_manager) == MANAGER_SHA, 'pinned_original_manager')
        source = raw_manager.decode('utf-8', 'strict')
        need(source.count(OLD) == 1, 'one_known_parser_patch')
        candidate = source.replace(OLD, NEW, 1)
        need(sha(candidate.encode()) == CANDIDATE_SHA, 'pinned_readonly_parser_candidate')
        parse = extract(candidate, ['parse_print'], {'need': need, 're': re})['parse_print']
        observer, observer_id = safe_read(ROOT / 'qa/mac_native_process_observer_r1.py', 65536)
        need(sha(observer) == OBSERVER_SHA, 'pinned_libproc_reader_source')
        observer_ns = extract(observer, ['ObservationRefused', 'require', 'BsdInfo', 'ProcessReader'],
                              {'ctypes': ctypes, 'Path': Path, 'sys': sys})
        reader = observer_ns['ProcessReader']()
        report['publicSourceSha256'] = {'manager': MANAGER_SHA, 'parserCandidate': CANDIDATE_SHA,
                                      'observer': OBSERVER_SHA}

        original_raw, original_id = safe_read(ROOT / 'outer-native-r1/result.public.json', 524288)
        original = json.loads(original_raw)
        managers = [(path, value) for path, value in walk(original)
                    if value.get('schema') == 'heptabao.mac-owned-launchd-manager.r3']
        report['originalManagerPaths'] = [p for p, _ in managers]
        need(managers and all(value == managers[0][1] for _, value in managers),
             'unambiguous_original_manager_record')
        manager = managers[0][1]
        registrations = manager.get('registrations')
        need(isinstance(registrations, list) and len(registrations) == 1,
             'single_original_registration')
        entry = registrations[0]
        need(entry.get('label') == LABEL and entry.get('generation') == 'server-initial'
             and entry.get('kind') == 'server', 'fixed_original_registration')
        attempts = entry.get('attempts')
        need(isinstance(attempts, dict), 'original_attempt_ledger_present')
        report['originalRegistration'] = {
            k: entry.get(k) for k in ('kind', 'generation', 'label', 'wrapperIdentity',
                'execIdentity', 'knownOwnedGroups', 'registrationClosed', 'lineagesClosed',
                'completeKnownSuccess', 'cleanupErrorType', 'cleanupErrorCode')}
        report['originalAttempts'] = {name: {k: value.get(k) for k in
            ('attempted', 'complete', 'exitCode')} for name, value in attempts.items()}
        commands = manager.get('ownedCommands', {})
        report['originalManagerTerminal'] = {k: manager.get(k) for k in
            ('ok', 'outcomeUnknown', 'failureCleanupAttempted', 'completedOperationCount',
             'allRegistrationsClosed', 'allKnownLineagesClosed', 'allOwnedCommandsStopped')}
        report['originalOwnedCommandLedger'] = {k: commands.get(k) for k in
            ('allOwnedCommandsStopped', 'unknownCommandCount')}
        report['originalOwnedCommandLedgerKeys'] = sorted(commands)
        launch_commands = []
        for _, item in walk(commands):
            label = item.get('label')
            if isinstance(label, str) and label.startswith('launchd-'):
                need(re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', label) is not None, 'safe_command_label')
                launch_commands.append({k: item.get(k) for k in
                    ('label', 'exitCode', 'outcomeUnknown', 'completeBeforeDeadline')})
        report['originalLaunchctlCommandSummaries'] = launch_commands
        report['originalNoSignalOrBootoutAttemptRecorded'] = not any(
            name in attempts for name in ('term', 'kill', 'bootout'))
        report['originalBootstrapKnownSucceeded'] = attempts.get('bootstrap', {}).get('attempted') is True \
            and attempts.get('bootstrap', {}).get('complete') is True \
            and attempts.get('bootstrap', {}).get('exitCode') == 0

        event_raw, event_id = safe_read(ROOT / 'launchd/000-server-initial-bootstrap-intent.public.json', 4096)
        event = json.loads(event_raw)
        cleanup_raw, cleanup_id = safe_read(ROOT / 'launchd/server-initial.cleanup-intent.public.json', 4096)
        cleanup = json.loads(cleanup_raw)
        plist_path = HOME / 'server-initial.plist'
        plist_raw, plist_id = safe_read(plist_path, 65536)
        plist = plistlib.loads(plist_raw)
        plan_raw, plan_id = safe_read(ROOT / 'launchd/server-initial.private.json', 4096)
        detail = event.get('detail', {})
        bindings = {
            'bootstrapEventExact': event.get('schema') == 'heptabao.mac-owned-launchd-event.r3'
                and event.get('kind') == 'bootstrap-intent' and event.get('index') == 0
                and event.get('generation') == 'server-initial'
                and detail.get('argv') == ['/bin/launchctl', 'bootstrap', 'gui/501', str(plist_path)],
            'plistMatchesOriginalAndIntent': sha(plist_raw) == entry.get('plistSha256') == detail.get('plistSha256'),
            'privatePlanMatchesOriginalAndIntent': sha(plan_raw) == entry.get('planSha256') == detail.get('planSha256'),
            'fixedPlistNoRestart': plist.get('Label') == LABEL and plist.get('RunAtLoad') is True
                and plist.get('KeepAlive') is False and plist.get('AbandonProcessGroup') is False
                and plist.get('WorkingDirectory') == str(HOME),
            'cleanupIntentExact': cleanup.get('schema') == 'heptabao.mac-owned-launchd-cleanup-intent.r3'
                and cleanup.get('generation') == 'server-initial' and cleanup.get('target') == TARGET
                and cleanup.get('termArgv') == ['/bin/launchctl', 'kill', 'SIGTERM', TARGET]
                and cleanup.get('killArgv') == ['/bin/launchctl', 'kill', 'SIGKILL', TARGET]
                and cleanup.get('bootoutArgv') == ['/bin/launchctl', 'bootout', TARGET],
        }
        report['exactOriginalFileBindings'] = bindings
        need(all(bindings.values()), 'all_fixed_original_file_bindings')
        args = plist.get('ProgramArguments')
        need(isinstance(args, list) and args[:5] == [LAUNCHER, '-I', '-S', '-B',
            str(HOME / 'mac_current_server_owner_r1.py')], 'fixed_python_wrapper_arguments')
        presence = {}
        for suffix in ('ready.public.json', 'admitted.private.json', 'exec-ready.public.json'):
            path = ROOT / 'launchd' / ('server-initial.' + suffix)
            try:
                path.lstat()
                presence[suffix] = True
            except FileNotFoundError:
                presence[suffix] = False
        report['originalAdmissionArtifactPresence'] = presence
        report['privateStdioMetadataOnly'] = {}
        for name in ('server-initial.stdout.private', 'server-initial.stderr.private'):
            info = (HOME / name).lstat()
            report['privateStdioMetadataOnly'][name] = {'bytes': info.st_size,
                'owner501': info.st_uid == 501, 'regularSingleLink': stat.S_ISREG(info.st_mode) and info.st_nlink == 1}

        for index in range(2):
            remaining = until - time.monotonic()
            need(remaining > 0, 'new_readonly_observation_deadline')
            proc = subprocess.run(['/bin/launchctl', 'print', TARGET], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(10, remaining),
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}, check=False)
            need(proc.returncode == 0 and not proc.stderr and len(proc.stdout) <= 262144,
                 'complete_fixed_registration_query')
            current = parse(proc.stdout, TARGET)
            row = {'index': index, 'queryExitCode': proc.returncode,
                'safeLaunchctlFields': {k: current.get(k) for k in
                    ('pid', 'runs', 'state', 'last exit code', 'last terminating signal')},
                'registeredPathExact': current.get('path') == str(plist_path),
                'registeredProgramExact': current.get('program') == args[0],
                'registeredAllArgumentsExact': current.get('arguments') == args}
            report['observations'].append(row)
            need(all(row[k] for k in ('registeredPathExact', 'registeredProgramExact', 'registeredAllArgumentsExact'))
                 and current.get('pid') == PID and current.get('runs') == 1, 'unchanged_fixed_registration')
            process = reader.read(PID)
            children = reader.children(PID)
            row['processIdentity'] = process
            row['directChildIdentities'] = [reader.read(child) for child in children]
            row['expectedUnadmittedWrapperImage'] = process['executable'] == KERNEL_PYTHON
            need(process['uid'] == 501 and process['pgid'] == PID,
                 'current_owner_and_process_group')
        report['currentIdentityStableAcrossQueries'] = report['observations'][0]['processIdentity'] \
            == report['observations'][1]['processIdentity']
        need(report['currentIdentityStableAcrossQueries'], 'stable_current_process_lifetime')
        unchanged = [(ROOT / 'qa/mac_owned_launchd_r3.py', manager_id),
            (ROOT / 'qa/mac_native_process_observer_r1.py', observer_id),
            (ROOT / 'outer-native-r1/result.public.json', original_id),
            (ROOT / 'launchd/000-server-initial-bootstrap-intent.public.json', event_id),
            (ROOT / 'launchd/server-initial.cleanup-intent.public.json', cleanup_id),
            (plist_path, plist_id), (ROOT / 'launchd/server-initial.private.json', plan_id)]
        report['inputFileIdentitiesUnchangedThroughObservation'] = all(identity(p.lstat()) == expected for p, expected in unchanged)
        need(report['inputFileIdentitiesUnchangedThroughObservation'], 'fixed_input_identity_interval')
        report['originalBirthIdentityAvailable'] = entry.get('wrapperIdentity') is not None or entry.get('execIdentity') is not None
        report['originalResultBytes'] = len(original_raw)
        report['currentBirthIsNewObservationOnly'] = True
        report['ok'] = True
    except Refused as error:
        report['errorCode'] = str(error)
    except BaseException as error:
        report['errorType'] = type(error).__name__
    report['elapsedSeconds'] = time.monotonic() - started
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
