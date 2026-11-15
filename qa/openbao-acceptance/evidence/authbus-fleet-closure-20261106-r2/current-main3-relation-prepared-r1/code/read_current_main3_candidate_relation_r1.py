#!/usr/bin/env python3
"""One sandboxed current-main3 read and private fixed-candidate comparison.

Parent owns the four process observations and holds the two candidate files.
This child reads only that same-parent private copy, the previous SDK scope,
the current configuration and the exact main primary row. No SDK import,
refresh, provider operation, service change, or production write is permitted.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import sys
import time
import types
import base64

START = time.monotonic()
PARENT_UNTIL = float(sys.argv[1])
UNTIL = min(PARENT_UNTIL, START + 20)
ROOT = Path('/Users/qianqi/heptabao-authbus-current-main3-candidate-relation-20261107-r1')
QUAL = Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2/qa')
CONFIG = Path('/Users/qianqi/.openclaw/openclaw.json')
MAIN = CONFIG.parent / 'agents/main/agent/openclaw-agent.sqlite'
PACKET = ROOT / 'output/candidate-files.private.json'
SOURCE_PINS = {
    'mac_guarded_current_capture_r3.py': '606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693',
    'mac_registry_readonly_wal_r1.py': '60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed',
    'authbus_current_auth_wal.py': 'ad443869e259da06de2be71131e5d1854680477d1cf77248e05a3c1704160f8c',
}
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
rows, codes, cancelled = [], set(), []
scope = None
report = {'schema': 'heptabao.current-main3-candidate-relation.worker.r1', 'ok': False,
    'providerCalls': 0, 'sdkImports': 0, 'productionWrites': 0, 'serviceActions': 0,
    'keychainReads': 0, 'childProcesses': 0, 'sourceDatabasesCopied': 0,
    'historicalCredentialValuesUsedAsCurrent': False, 'sdkSelectionRerun': False,
    'credentialValuesIdsPathsOrDigestsPublished': False,
    'runningCachedCredentialRelation': 'unknown', 'effectiveBackendQualified': False,
    'productionRefreshAdmission': False, 'currentSelectedOwnerCount': 0,
    'privateCandidateEqualityComparisonPerformed': False,
    'observationsAreDiscreteNotAtomic': True, 'automaticRetry': False,
    'workerSeconds': 20, 'originalAuthQueryMaximumSeconds': 3,
    'kernelDenials': [], 'probeSocketClosed': False, 'currentReadClosure': None}


def need(value, code):
    if not value:
        codes.add(code)
        raise RuntimeError(code)


def within():
    need(not cancelled and time.monotonic() < UNTIL, 'relation_original_worker_deadline')


def full(value):
    return tuple(str(getattr(value, key)) for key in FIELDS)


def strict_document(raw, maximum):
    need(type(raw) is bytes and 0 < len(raw) <= maximum, 'relation_bounded_complete_json_document')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'relation_duplicate_private_json_key')
            result[key] = value
        return result
    def invalid(_):
        raise RuntimeError('relation_nonfinite_private_json')
    return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs, parse_constant=invalid)


def opened(path, flags, mode=0o600):
    within()
    row = {'fd': os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, mode),
           'closeAttempts': 0, 'closed': False}
    rows.append(row)
    return row


def close(row):
    if row['closeAttempts']:
        return
    row['closeAttempts'] = 1
    os.close(row['fd']); row['closed'] = True


def bounded_read(path, maximum, *, private=False):
    row = opened(path, os.O_RDONLY)
    try:
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid in (0, 501)
             and not stat.S_IMODE(before.st_mode) & 0o022 and before.st_nlink == 1
             and 0 < before.st_size <= maximum, 'relation_bounded_owned_file')
        if private:
            need(before.st_uid == 501 and before.st_gid == 20 and stat.S_IMODE(before.st_mode) == 0o600,
                 'relation_private_single_inode_file')
        raw = bytearray()
        while len(raw) <= before.st_size:
            within()
            part = os.read(row['fd'], min(65536, before.st_size + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        need(len(raw) == before.st_size and full(before) == full(os.fstat(row['fd'])) == full(path.lstat()),
             'relation_complete_named_file_bytes_and_generation')
        return bytes(raw), full(before)
    finally:
        close(row)


def private_output(name, value):
    need(name == 'current-main3-candidate-relation.private.json', 'relation_one_private_output')
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    need(len(raw) <= 2097152, 'relation_private_output_bound')
    path = ROOT / 'output' / name
    row = opened(path, os.O_RDWR | os.O_CREAT | os.O_EXCL)
    try:
        view = memoryview(raw)
        while view:
            within()
            count = os.write(row['fd'], view)
            need(count > 0, 'relation_private_write_progress')
            view = view[count:]
        os.fsync(row['fd'])
        value = os.fstat(row['fd'])
        need(value.st_uid == 501 and value.st_gid == 20 and stat.S_IMODE(value.st_mode) == 0o600
             and value.st_nlink == 1 and value.st_size == len(raw)
             and os.pread(row['fd'], len(raw) + 1, 0) == raw
             and full(value) == full(os.fstat(row['fd'])) == full(path.lstat()),
             'relation_durable_complete_private_output')
    finally:
        close(row)
    row = opened(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(row['fd'])
    finally:
        close(row)


def source_fence():
    within()
    for name, expected in SOURCE_PINS.items():
        raw, generation = bounded_read(QUAL / name, 65536)
        need(hashlib.sha256(raw).hexdigest() == expected
             and source_generations[name] == generation, 'relation_original_auth_reader_source_exact')
    for name, expected in own_pins.items():
        raw, generation = bounded_read(ROOT / 'code' / name, 65536)
        need(hashlib.sha256(raw).hexdigest() == expected
             and own_generations[name] == generation, 'relation_staged_own_source_exact')


def denied(label, action):
    value = None
    try:
        value = action()
    except PermissionError as error:
        need(error.errno in (1, 13), 'relation_expected_kernel_permission_denial')
        report['kernelDenials'].append({'label': label, 'denied': True})
        return
    finally:
        if type(value) is int:
            os.close(value)
    raise RuntimeError('relation_kernel_denial_missing')


try:
    os.umask(0o077); sys.dont_write_bytecode = True
    need(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 501 and os.getgid() == 20,
         'relation_exact_mac_owner')
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, lambda value, _frame: cancelled.append(value))
    denied('live-main-write-open', lambda: os.open(MAIN, os.O_WRONLY | os.O_NOFOLLOW))
    denied('live-configuration-write-open', lambda: os.open(CONFIG, os.O_WRONLY | os.O_NOFOLLOW))
    denied('protected-private-read', lambda: os.open(ROOT / 'protected-read', os.O_RDONLY | os.O_NOFOLLOW))
    probe = socket.socket()
    try:
        denied('nonprovider-loopback-network', lambda: probe.connect(('127.0.0.1', 9)))
    finally:
        probe.close(); report['probeSocketClosed'] = True
    own_manifest, _ = bounded_read(ROOT / 'code/reader-plan.public.json', 65536)
    own_plan = strict_document(own_manifest, 65536)
    own_pins = own_plan['readerPins']
    need(set(own_pins) == {'main3_source_authority.py', 'mac_current_selected_main3_r1.py',
                          'mac_codex_candidate_backend_r1.py', Path(__file__).name},
         'relation_four_fixed_own_sources')
    own_generations = {}
    for name, expected in own_pins.items():
        raw, generation = bounded_read(ROOT / 'code' / name, 65536)
        need(hashlib.sha256(raw).hexdigest() == expected, 'relation_staged_source_hash')
        own_generations[name] = generation
    source_generations = {}
    for name, expected in SOURCE_PINS.items():
        raw, generation = bounded_read(QUAL / name, 65536)
        need(hashlib.sha256(raw).hexdigest() == expected, 'relation_original_reader_source_hash')
        source_generations[name] = generation
        key = Path(name).stem
        need(key not in sys.modules, 'relation_original_reader_import_once')
        module = types.ModuleType(key); module.__file__ = str(QUAL / name)
        sys.modules[key] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    sys.path.insert(0, str(ROOT / 'code'))
    import authbus_current_auth_wal as auth
    from mac_current_selected_main3_r1 import (ScopeInputs, read_current, CurrentOwnersCaptureFailure,
                                              verify_current_namespace)
    from mac_codex_candidate_backend_r1 import strict_json, compare_candidate_auth
    packet_raw, packet_generation = bounded_read(PACKET, 2097152, private=True)
    packet = strict_document(packet_raw, 2097152)
    need(type(packet) is dict and packet.get('schema') == 'heptabao.fixed-codex-candidate-files.private.r1'
         and packet.get('originalParentPid') == os.getppid() and type(packet.get('files')) is list
         and len(packet['files']) == 2, 'relation_original_same_parent_candidate_copy')
    auth_entry = packet['files'][1]
    need(auth_entry.get('path') == '/Users/qianqi/.codex/auth.json', 'relation_exact_observed_candidate_file')
    encoded_auth = auth_entry.get('bytesBase64')
    need(encoded_auth is None or type(encoded_auth) is str and len(encoded_auth) <= 174764,
         'relation_bounded_same_parent_auth_copy')
    candidate = None if encoded_auth is None else base64.b64decode(encoded_auth, validate=True)
    scope = ScopeInputs(until=UNTIL, source_fence=source_fence)
    try:
        current, closure = read_current(auth=auth, scope=scope, until=UNTIL,
            critical=contextlib.nullcontext, cancelled=lambda: bool(cancelled), source_fence=source_fence)
        report['currentReadClosure'] = closure
        report['currentSelectedOwnerCount'] = 3
    except CurrentOwnersCaptureFailure as error:
        report['currentReadClosure'] = error.closure
        raise
    relation = compare_candidate_auth(candidate, current['ownerEntries'])
    report['privateCandidateEqualityComparisonPerformed'] = True
    need(bounded_read(PACKET, 2097152, private=True) == (packet_raw, packet_generation),
         'relation_original_candidate_copy_unchanged')
    scope.verify(); source_fence(); verify_current_namespace(current, until=UNTIL)
    private_output('current-main3-candidate-relation.private.json', {
        'schema': 'heptabao.current-main3-candidate-relation.private.r1', 'originalParentPid': os.getppid(),
        'currentSelectedOwners': current, 'candidatePacketIdentity': packet_generation,
        'relationship': relation['private'], 'runningCachedCredentialRelation': 'unknown',
        'providerOrServiceAdmissionGranted': False})
    scope.verify(); source_fence(); verify_current_namespace(current, until=UNTIL)
    report.update(ok=True, currentSelectedOwnerCount=3, currentOwnerIdsCameFromPriorAuthorizedSdkScope=True,
        allCurrentCredentialValuesFromNewQualifiedAuthQuery=True,
        duplicateRefreshObjectsRefused=True, relationship=relation['public'],
        newCurrentMainGenerationCapturedAfterSqlClosure=True, privateRelationshipDurablyCaptured=True)
except BaseException as error:
    report['ok'] = False
    report['errorClass'] = type(error).__name__ if type(error).__name__ in (
        'RuntimeError', 'CurrentOwnersRefused', 'CurrentOwnersCaptureFailure', 'CandidateRefused',
        'CaptureRefused', 'FileNotFoundError', 'PermissionError') else 'OtherException'
    text = str(error)
    report['errorCode'] = text if text in codes or type(error).__name__ in (
        'CurrentOwnersRefused', 'CurrentOwnersCaptureFailure', 'CandidateRefused', 'CaptureRefused') \
        and text.isascii() and text.replace('_', '').isalnum() else 'relation_original_observation_refused'
finally:
    errors = []
    if scope is not None:
        report['scopeClosure'] = scope.close()
        try:
            if report['ok']:
                report['closedScopeNamesExact'] = scope.closed_fence()
        except BaseException:
            report['closedScopeNamesExact'] = False
            report['ok'] = False
        report['ok'] = bool(report['ok'] and report['scopeClosure']['allOriginalDescriptorsClosedOnce'])
    for row in reversed(rows):
        try:
            close(row)
        except BaseException:
            errors.append('relation_original_descriptor_close_failed')
    report.update(originalDescriptorsOpened=len(rows), allOriginalDescriptorsClosedOnce=all(
        row['closeAttempts'] == 1 and row['closed'] for row in rows), closeErrors=errors,
        cancellationObserved=bool(cancelled), elapsedSeconds=time.monotonic()-START)
    report['ok'] = bool(report['ok'] and report['allOriginalDescriptorsClosedOnce']
        and not errors and not cancelled and time.monotonic() < UNTIL)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')), flush=True)
raise SystemExit(0 if report['ok'] else 1)
