#!/usr/bin/env python3
"""One exact Ensure error diagnostic under the original Mac workspace feature graph.

The frozen Darwin runner owns preparation, guards, environment, target flock,
children and cleanup. This adapter never calls its full6 execute/finish path.
All zero-selected workspace groups remain zero evidence, not passed tests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import sys
import types

SCHEMA = 'heptabao.missing-only-ensure-sync-workspace-diagnostic.r1'
DERIVED_FROM_CONTROLLER_SHA = 'f994b2b2670edda72ac385788bfef269eefe7562b2e7b24a787e481268c216e7'
RUNNER_BYTES = 87399
RUNNER_SHA = '4bcacbbf92682bce8b994981ed1ee58fb88c0f2e257df958775c77e0d73b528d'
BASE_COMMIT = '8c56e2adc414f4b0f73e8959ff23632fa19fc629'
BASE_TREE = '16653849d0728a5e838227d70bea265832a80354'
BASE_MAP = '5346a875552b369d39f222207535f276283307c03bd3deca0f9310a9f563a2c4'
BASE_FILES = {
    'crates/heptabao-ha-service/src/v6_closure_quorum_tests.rs':
        'a1684acf0b3d8aa7fb8d4ec6014fc591851983a9bbdae724e8a3a6f0b753ecca',
    'crates/heptabao-ha-service/src/v6_closure_quorum.rs':
        'c20512c250be14ce0af47a92dd8021c298f637b45c211757af3245d5d7feced7',
    'crates/heptabao-ha-service/src/closure_phase_diagnostic.rs':
        '039344349897ea80d1f1d7ad64c3c439b27d137450c6a21edf927e3d1f62a24e',
    'crates/heptabao-ha-service/src/v6_closure_batch.rs':
        'd37665919f976016e158413ad736876ff367d47bec536a0ca9226c1b7d349db5',
}
TEST_NAME = ('v6_closure_quorum::tests::'
             'missing_only_quorum_keeps_real_fsync_cold_bytes_and_unknown_ack_fences')
ORIGINAL_WORKSPACE = (
    'test', '--release', '--locked', '--offline', '--workspace',
    '--all-targets', '--no-fail-fast', '--', '--test-threads=1',
)
CARGO_ARGUMENTS = (
    'test', '--release', '--locked', '--offline', '--workspace',
    '--all-targets', '--no-fail-fast', TEST_NAME, '--',
    '--test-threads=1', '--exact', '--nocapture',
)
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_GROUPS = 1024
MAX_PHASE_RECORDS = 20000
NONCLAIMS = {
    'fullProduct': False, 'fullReplacement': False, 'productionCutover': False,
    'fullNativeQualification': False, 'nativeBuildQualified': False,
    'workspaceTestsPassed': False, 'runtimeQualified': False,
    'allPassed': False, 'complete': False, 'nativeBuildReceiptIssued': False,
    'full6CommandsExecuted': False, 'productFixVerified': False,
}
HA_ERRORS = frozenset((
    'InvalidNode', 'InvalidCluster', 'InvalidOperation', 'InvalidFrame',
    'InvalidSnapshot', 'InvalidMembership', 'UnknownPeer',
    'PeerAuthenticationFailed', 'ReplayDetected', 'WriterBusy',
    'QuorumUnavailable', 'NotLeader', 'OperationIdConflict',
    'StaleLeaderResponse', 'CapacityExceeded', 'Transport', 'OutcomeUnknown',
    'InvalidRoot', 'Tampered', 'Io',
))
PHASE_NAMES = frozenset((
    'collector_admission', 'source_preflight', 'frame_capacity', 'frame_payload',
    'worker_queue', 'client_connect', 'client_handshake', 'frame_write_header',
    'frame_write_body', 'frame_flush', 'frame_read_header', 'frame_read_body',
    'server_handshake', 'receiver_admission', 'receiver_verify',
    'receiver_owner_lock', 'receiver_ensure', 'receiver_batch_prepare',
    'receiver_storage_inclusive', 'receiver_storage_gate', 'receiver_batch_post',
    'finalize_manifest', 'reply_verify', 'frame_wait_inclusive',
    'final_admission', 'final_verify',
))
RESULT = re.compile(
    r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; '
    r'(\d+) ignored; (\d+) measured; (\d+) filtered out; '
    r'finished in (\d+(?:\.\d+)?)s')
TIMING = re.compile(
    r'HBHA-PRIVATE-CLOSURE-TIMING observation=(\d+) side=(collector|receiver) '
    r'phase=([a-z_]+) calls=(\d+) failed=(\d+) total_ns=(\d+) max_ns=(\d+) '
    r'bounded_calls=(\d+) min_original_remaining_ns=(\d+)')
FRAMES = re.compile(
    r'HBHA-PRIVATE-CLOSURE-FRAMES observation=(\d+) side=(collector|receiver) '
    r'kind=(\d+) frames=(\d+) payload_bytes=(\d+)')
PEER = re.compile(
    r'HBHA-PRIVATE-PEER-RETURN observation=(\d+) side=(collector|receiver) '
    r'phase=(transport_return|worker_return) target=(\d+) kind=(\d+) '
    r'error=([A-Za-z]+) cancelled_at_observation=(true|false) '
    r'original_remaining_ns=(\d+)')
FIXTURE = re.compile(
    r'HBHA-MISSING-ONLY-RETURN '
    r'phase=(final_replicate|final_verify_for_publication) '
    r'object_count=(\d+) missing_count=(\d+) error=([A-Za-z]+) '
    r'original_remaining_ns=(\d+)')


def require(value, message):
    if not value:
        raise ValueError(message)


def log_text(raw):
    require(isinstance(raw, bytes) and len(raw) <= MAX_LOG_BYTES,
            'diagnostic log byte bound exceeded')
    return raw.decode('utf-8', errors='strict')


def observe_workspace_exact(raw, return_code):
    """All complete serial groups; exactly one real selected named case."""
    groups = []
    group = None
    for number, line in enumerate(log_text(raw).splitlines(), 1):
        if not line:
            continue
        start = re.fullmatch(r'running (\d+) tests?', line)
        if start:
            require(group is None and len(groups) < MAX_GROUPS,
                    'overlapping or excessive workspace libtest groups')
            selected = int(start[1])
            require(selected in (0, 1), 'workspace exact filter selected extra tests')
            group = {'selected': selected, 'rows': [], 'failureSection': False,
                     'startedLine': number}
            continue
        require(group is not None, 'nonempty stdout outside workspace libtest group')
        result = RESULT.fullmatch(line)
        if result:
            status = result[1]
            passed, failed, ignored, measured, filtered = map(int, result.groups()[1:6])
            rows = group['rows']
            require(ignored == measured == 0 and passed + failed == group['selected']
                    and len(rows) == group['selected'],
                    'workspace selected tests did not all execute')
            require(passed == sum(x['result'] == 'ok' for x in rows)
                    and failed == sum(x['result'] == 'FAILED' for x in rows)
                    and ((status == 'ok' and failed == 0)
                         or (status == 'FAILED' and failed == 1)),
                    'workspace named rows and aggregate status differ')
            require(group['selected'] == 0 or filtered == 65,
                    'the original HA66 target group must have exactly65 filtered tests')
            group.update({'status': status, 'passed': passed, 'failed': failed,
                          'ignored': ignored, 'measured': measured,
                          'filteredOut': filtered, 'finishedLine': number})
            groups.append(group)
            group = None
            continue
        named = re.fullmatch(r'test (\S+) \.\.\. (ok|FAILED)', line)
        if named:
            require(group['selected'] == 1 and not group['rows']
                    and not group['failureSection'] and named[1] == TEST_NAME,
                    'unexpected or duplicate actual test result')
            group['rows'].append({'name': named[1], 'result': named[2]})
            continue
        if line == 'failures:':
            require(group['rows'] == [{'name': TEST_NAME, 'result': 'FAILED'}],
                    'failure section without the one actual failed target')
            group['failureSection'] = True
            continue
        require(group['failureSection'], 'unrecognized serial libtest stdout')
        # Failure text is never copied into public structured output. Names,
        # summaries or group delimiters cannot be accepted as arbitrary prose.
        if line.lstrip() == TEST_NAME:
            continue
        if line.startswith('---- '):
            require(line == '---- ' + TEST_NAME + ' stdout ----',
                    'failure section names a different test')
            continue
        require(not line.startswith(('test ', 'test result:', 'running ')),
                'malformed execution record inside failure prose')
    require(group is None, 'unfinished workspace libtest group')
    selected_groups = [x for x in groups if x['selected'] == 1]
    require(len(selected_groups) == 1, 'exactly one nonzero actual test group required')
    target = selected_groups[0]
    expected_rc = 0 if target['passed'] == 1 else 101
    require(return_code == expected_rc,
            'Cargo return code differs from actual target result')
    return {'schema': SCHEMA + '.libtest', 'testStatus':
            'passed' if expected_rc == 0 else 'test-failed',
            'cargoReturnCode': return_code, 'selected': 1,
            'passed': target['passed'], 'failed': target['failed'],
            'ignored': 0, 'measured': 0, 'targetFilteredOut': 65,
            'observedTests': target['rows'], 'groups': groups,
            'zeroSelectedGroupCount': len(groups) - 1,
            'zeroGroupsCountedAsPassingTests': False,
            'otherFilteredOut': sum(x['filteredOut'] for x in groups if not x['selected']),
            'workspaceTestsPassed': False}


def observe_phases(stdout, stderr):
    """Typed observations only; receiver aggregates never identify an operation."""
    rows = []
    unique = set()
    fixture = []
    for stream, raw in (('stdout', stdout), ('stderr', stderr)):
        for number, line in enumerate(log_text(raw).splitlines(), 1):
            if not line.startswith(('HBHA-PRIVATE-CLOSURE-TIMING ',
                                    'HBHA-PRIVATE-CLOSURE-FRAMES ',
                                    'HBHA-PRIVATE-PEER-RETURN ',
                                    'HBHA-MISSING-ONLY-RETURN ')):
                continue
            require(len(rows) < MAX_PHASE_RECORDS, 'phase record bound exceeded')
            m = TIMING.fullmatch(line)
            if m:
                observation, side, phase = int(m[1]), m[2], m[3]
                calls, failed, total, maximum, bounded, remaining = map(int, m.groups()[3:])
                require(observation > 0 and phase in PHASE_NAMES and 0 < calls < 2**64
                        and 0 <= failed <= calls and 0 <= bounded <= calls
                        and 0 <= maximum <= total < 2**64 and 0 <= remaining <= 8_000_000_000,
                        'invalid typed timing counters')
                key = ('timing', observation, side, phase)
                row = {'kind': 'timing', 'observationId': observation, 'side': side,
                       'phase': phase, 'calls': calls, 'failed': failed, 'totalNs': total,
                       'maximumNs': maximum, 'boundedCalls': bounded,
                       'minimumOriginalRemainingNs': remaining}
            else:
                m = FRAMES.fullmatch(line)
                if m:
                    observation, side = int(m[1]), m[2]
                    kind, count, payload = map(int, m.groups()[2:])
                    require(observation > 0 and 1 <= kind <= 8 and 0 < count < 2**64
                            and 0 <= payload < 2**64, 'invalid typed frame counters')
                    key = ('frames', observation, side, kind)
                    row = {'kind': 'frames', 'observationId': observation, 'side': side,
                           'wireKind': kind, 'count': count, 'payloadBytes': payload}
                else:
                    m = PEER.fullmatch(line)
                    if m:
                        observation, side, phase = int(m[1]), m[2], m[3]
                        target, kind, error, cancelled, remaining = (
                            int(m[4]), int(m[5]), m[6], m[7] == 'true', int(m[8]))
                        require(observation > 0 and side == 'collector' and target in (1, 2, 3)
                                and 1 <= kind <= 8 and error in HA_ERRORS
                                and 0 <= remaining <= 8_000_000_000,
                                'invalid typed peer error observation')
                        # This fixed three-object fixture sends each wire kind
                        # at most once to a target in one collector operation.
                        key = ('peerError', observation, phase, target, kind)
                        row = {'kind': 'peerError', 'observationId': observation, 'side': side,
                               'phase': phase, 'target': target, 'wireKind': kind,
                               'errorVariant': error, 'cancelledAtObservation': cancelled,
                               'originalRemainingNs': remaining}
                    else:
                        m = FIXTURE.fullmatch(line)
                        require(m is not None, 'malformed fixed diagnostic record')
                        phase, objects, missing, error, remaining = (
                            m[1], int(m[2]), int(m[3]), m[4], int(m[5]))
                        require(objects == 3 and missing == 1 and error in HA_ERRORS
                                and 0 <= remaining <= 8_000_000_000 and not fixture,
                                'invalid or duplicate fixture returned error')
                        key = None
                        row = {'kind': 'fixtureError', 'phase': phase, 'objectCount': objects,
                               'missingCount': missing, 'errorVariant': error,
                               'originalRemainingNs': remaining}
                        fixture.append(row)
            if key is not None:
                require(key not in unique, 'duplicate phase aggregate bucket')
                unique.add(key)
            row.update({'stream': stream, 'line': number})
            rows.append(row)
    collector_ids = sorted({x['observationId'] for x in rows
                            if x.get('side') == 'collector' and x['kind'] == 'timing'})
    sides = {}
    frame_keys = {(x['observationId'], x['side'], x['wireKind'])
                  for x in rows if x['kind'] == 'frames'}
    for row in rows:
        if 'observationId' in row:
            prior = sides.setdefault(row['observationId'], row['side'])
            require(prior == row['side'], 'one observation identity has two sides')
        if row['kind'] == 'peerError':
            require(row['observationId'] in collector_ids
                    and (row['observationId'], 'collector', row['wireKind']) in frame_keys,
                    'peer returned error lacks its retained collector phase context')
    return {'schema': SCHEMA + '.phases', 'records': rows,
            'collectorObservationIds': collector_ids,
            'fixtureReturnedErrors': fixture,
            'receiverStatsScope': 'whole receiver lifetime, spanning distinct fixture operations',
            'receiverAggregateFailureAttributedToFinalOperation': False,
            'cancellationSampleEstablishesEarlierEventOrder': False,
            'rootCauseAutomaticallyConcluded': False}


def load_runner(path):
    require(platform.system() == 'Darwin', 'native Darwin host required')
    path = path.resolve(strict=True)
    raw = path.read_bytes()
    require(len(raw) == RUNNER_BYTES and hashlib.sha256(raw).hexdigest() == RUNNER_SHA,
            'frozen Darwin retained runner byte pin differs')
    name = '_heptabao_frozen_darwin_owner_for_missing_only'
    require(name not in sys.modules, 'frozen runner module name already occupied')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), 'exec'), module.__dict__)
    except BaseException:
        del sys.modules[name]
        raise
    require((module.STEP_TIMEOUT, module.PROBE_TIMEOUT, module.TERM_GRACE,
             module.KILL_GRACE) == (7200, 300, 10, 10), 'original bounds differ')
    require(tuple(dict(module.STEP_COMMANDS)['workspace-tests']) == ORIGINAL_WORKSPACE,
            'original workspace command differs')
    return module


def observe_tmpdir(q, expected):
    require(expected.is_absolute() and q.environment.get('TMPDIR') == str(expected)
            and expected.resolve(strict=True) == expected,
            'explicit original TMPDIR differs or is indirect')
    info = expected.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and not info.st_mode & 0o022, 'TMPDIR owner or permissions differ')
    return {'path': str(expected), 'device': info.st_dev, 'inode': info.st_ino,
            'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
            'scope': 'named directory identity at observation boundaries'}


def observe_lineage(q):
    parent = q.git_probe(['rev-parse', 'HEAD^'], 'diagnostic-parent').decode().strip()
    require(parent == BASE_COMMIT and q.args.expected_commit != BASE_COMMIT,
            'diagnostic source must be one explicit child of8c56')
    changed = q.git_probe(['diff', '--name-only', BASE_COMMIT, 'HEAD'],
                          'diagnostic-four-file-scope').decode().splitlines()
    require(sorted(changed) == sorted(BASE_FILES), 'diagnostic changed-file scope differs')
    rows = []
    for index, (path, pin) in enumerate(BASE_FILES.items(), 1):
        before = q.git_probe(['show', BASE_COMMIT + ':' + path],
                             f'diagnostic-before-file-{index}')
        require(hashlib.sha256(before).hexdigest() == pin, 'diagnostic old source pin differs')
        rows.append({'path': path, 'beforeSha256': pin,
                     'afterSourceMapSha256': q.args.expected_map_sha256})
    return {'baseCommit': BASE_COMMIT, 'baseTree': BASE_TREE, 'baseMapSha256': BASE_MAP,
            'actualParentCommit': parent, 'changedFiles': rows,
            'controllerDerivedFromSha256': DERIVED_FROM_CONTROLLER_SHA,
            'changedFileCount': 4,
            'afterSourceBoundByOriginalBeforeAndAfterGuards': True}


def read_owned_log(q, process, label, stream):
    pin = process['logs'][stream]
    path = q.out / 'logs' / (label + '.' + stream)
    require(pin['path'] == str(path) and 0 <= pin['bytes'] <= MAX_LOG_BYTES,
            'owned log path or size differs')
    raw = path.read_bytes()
    require(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'],
            'owned log content differs from original receipt')
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('--runner', type=Path, required=True)
    parser.add_argument('--expected-tmpdir', type=Path, required=True)
    initial, rest = parser.parse_known_args(argv)
    runner = load_runner(initial.runner)
    args = runner.normalized_args(runner.parse_args(rest))
    require(args.expected_file_count == 3688, 'diagnostic source file count differs')
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    for child in ('logs', 'processes', 'guards', 'artifacts'):
        (args.out / child).mkdir(mode=0o700)

    class DiagnosticQualification(runner.Qualification):
        def save(self):
            runner.write_json(self.out / 'diagnostic.summary.json', self.summary)

    q = DiagnosticQualification(args)
    q.summary.pop('steps')
    task = {'name': 'workspace-missing-only-exact', 'status': 'pending',
            'before': None, 'after': None, 'process': None,
            'actualArgv': [q.cargo, *CARGO_ARGUMENTS]}
    q.summary.update({'schema': SCHEMA, 'status': 'initializing', **NONCLAIMS,
        'diagnosticRunClosed': False, 'actualTargetPassed': False,
        'controller': runner.identity(Path(__file__)), 'frozenRunnerCodeUnmodified': True,
        'scope': 'one exact test selected from the original workspace/all-targets feature graph',
        'contract': {'commandTimeoutSeconds': runner.STEP_TIMEOUT,
                     'probeTimeoutSeconds': runner.PROBE_TIMEOUT,
                     'termGraceSeconds': runner.TERM_GRACE, 'killGraceSeconds': runner.KILL_GRACE,
                     'processAllowedReturnCodes': [0, 101],
                     'originalWorkspaceCommand': list(ORIGINAL_WORKSPACE),
                     'explicitFeatureFlagsAdded': False, 'packageSelectionAdded': False,
                     'onlyTestFilterAndNocaptureAdded': True,
                     'fixtureSeconds': 8, 'peerFrameSeconds': 4,
                     'exactTarget': TEST_NAME, 'targetFilteredOutRequired': 65,
                     'otherGroupsMustSelectZero': True,
                     'zeroGroupsCountedAsPassingTests': False, 'retryAllowed': False,
                     'targetLock': 'original Qualification.prepare LOCK_EX|LOCK_NB through final guard'},
        'diagnosticCommand': task})
    handlers = {n: signal.getsignal(n) for n in (signal.SIGTERM, signal.SIGINT)}
    for number in handlers:
        signal.signal(number, q.owner.on_signal)
    error = None
    exit_code = 2
    label = 'diagnostic-workspace-missing-only-exact'
    try:
        q.prepare()
        q.summary['tmpdirBefore'] = observe_tmpdir(q, initial.expected_tmpdir)
        task['before'] = q.guard(label + '-before')
        q.summary['diagnosticLineage'] = observe_lineage(q)
        task['status'] = 'running'
        q.summary['status'] = 'running-diagnostic-command'
        q.save()
        pending = None
        try:
            output, process = q.owner.run(task['actualArgv'], q.source, label,
                                          runner.STEP_TIMEOUT, allowed=(0, 101))
            task['process'] = process
            runner.validate_full6_process_receipt(process, runner.STEP_TIMEOUT)
            q.retained_receipts['steps'] += 1
            stdout = read_owned_log(q, process, label, 'stdout')
            require(output == stdout, 'owner stdout differs from its closed log')
            stderr = read_owned_log(q, process, label, 'stderr')
            task['tests'] = observe_workspace_exact(stdout, process['returnCode'])
            task['phaseDiagnostics'] = observe_phases(stdout, stderr)
            require(not task['phaseDiagnostics']['fixtureReturnedErrors']
                    or task['tests']['testStatus'] == 'test-failed',
                    'fixture error contradicts a successful test row')
        except BaseException as caught:
            pending = caught
            receipt_path = q.out / 'processes' / (label + '.json')
            if receipt_path.exists():
                task['process'] = json.loads(receipt_path.read_text())
            task['failure'] = {'type': type(caught).__name__, 'message': str(caught)}
        finally:
            task['status'] = 'checking-after'
            q.save()
            if q.owner.stop_signal is None:
                try:
                    task['after'] = q.guard(label + '-after')
                    q.summary['tmpdirAfter'] = observe_tmpdir(q, initial.expected_tmpdir)
                    require(q.summary['tmpdirBefore'] == q.summary['tmpdirAfter'],
                            'original TMPDIR identity changed')
                except BaseException as caught:
                    task['afterFailure'] = {'type': type(caught).__name__, 'message': str(caught)}
                    pending = pending or caught
            else:
                task['afterNotRunReason'] = 'signal interrupted run; no after-state asserted'
        if pending is not None:
            raise pending
        q.owner.request_check()
        require(runner.identity(Path(runner.__file__))['sha256'] == RUNNER_SHA,
                'frozen runner changed during diagnostic')
        require(runner.identity(Path(__file__)) == q.summary['controller'],
                'diagnostic controller changed during observation')
        passed = task['tests']['testStatus'] == 'passed'
        task['status'] = 'passed' if passed else 'test-failed'
        q.summary.update({'diagnosticRunClosed': True, 'actualTargetPassed': passed,
                          'status': 'diagnostic-passed' if passed else 'test-failed'})
        exit_code = 0 if passed else 1
    except BaseException as caught:
        error = caught
    finally:
        for number in handlers:
            signal.signal(number, signal.SIG_IGN)
        try:
            if q.owner.stop_signal is not None:
                error = runner.StopRequested(q.owner.stop_signal)
            if error is not None:
                q.summary.update({'status': 'interrupted' if isinstance(error, runner.StopRequested)
                                  else 'incomplete', 'diagnosticRunClosed': False,
                                  'actualTargetPassed': False,
                                  'failure': {'type': type(error).__name__, 'message': str(error)}})
                exit_code = 128 + error.signum if isinstance(error, runner.StopRequested) else 2
            q.summary.update(NONCLAIMS)
            q.summary.update({'ownerStillRetainsUnreapedChild': q.owner.active is not None,
                              'finishedAt': runner.utc_now(), 'exitCode': exit_code})
            q.save()
        finally:
            if q.lock_stream is not None:
                q.lock_stream.close()
            for number, handler in handlers.items():
                signal.signal(number, handler)
    print(json.dumps({'schema': SCHEMA, 'status': q.summary['status'],
        'summary': str(args.out / 'diagnostic.summary.json'), 'exitCode': exit_code,
        'diagnosticRunClosed': q.summary['diagnosticRunClosed'],
        'actualTargetPassed': q.summary['actualTargetPassed'], **NONCLAIMS}, sort_keys=True))
    return exit_code


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'schema': SCHEMA, 'status': 'bootstrap-or-publication-failed',
            'failure': {'type': type(error).__name__, 'message': str(error)},
            'diagnosticRunClosed': False, 'actualTargetPassed': False,
            **NONCLAIMS}, sort_keys=True))
        raise SystemExit(2)
