#!/usr/bin/env python3
"""Read only the closed original fixture and its durable once-init receipts.

No service, child, SQL, network, write, deletion or retry is available. The
private initialization response is validated in memory; neither its content nor
its digest is published. This is recovery input observation, not permission to
replay the original request or to initialize the existing store again.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/fixed-slot-coordinator-normal-20261107-r1')
CLIENT = Path('/Users/qianqi/heptabao-fixed-slot-coordinator-normal-20261107-r1')
CUSTODY = CLIENT / 'custody'
JOB = Path('/Users/qianqi/.local/state/hepta-runtime-mac-worker/jobs/1a1b3e976fc-fc05-8575')
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
SOURCE_SHA = '0399270ee35c5c47d3431e263d9a338028393c1b4ebf09babbb23d9fa7923752'
REQUEST_SHA = '541a526c1aac1a0ab8974cd897421b2e457c079fb01d8b55b7e2d7d28a6b0762'
STDOUT_SHA = '05c2f864b2f6e72a8afacbbe622e55639d39a9850bdf3bffa475674927ff7ded'
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
UNTIL = time.monotonic() + 20
ROWS = []
REPORT = {'schema': 'heptabao.fixed-slot-original-init-observation.r1', 'ok': False,
          'originalJob': '1a1b3e976fc-fc05-8575', 'originalAttemptStillFailed': True,
          'childProcesses': 0, 'sqlConnections': 0, 'networkOperations': 0,
          'sourceWrites': 0, 'serviceActions': 0, 'providerCalls': 0,
          'initializationRequests': 0, 'privateValuesOrDigestsPublished': False,
          'originalPreInitDirectoryInodeWasSeparatelyRecorded': False,
          'currentMetadataAloneProvesThePreInitInode': False,
          'actualCoordinatorBusinessQualified': False, 'automaticRetry': False}


class Refused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def deadline():
    need(time.monotonic() < UNTIL, 'original_readonly_twenty_seconds')


def stamp(value):
    return tuple(str(getattr(value, name)) for name in FIELDS)


def close(row):
    need(row['attempts'] == 0, 'one_original_fd_close')
    row['attempts'] += 1
    os.close(row['fd'])
    row['closed'] = True


def open_owned(path, directory=False):
    deadline()
    path = Path(path)
    parents = []
    previous = None
    try:
        for component in [Path('/'), *list(path.parents)[::-1][1:], path]:
            is_directory = component != path or directory
            fd = os.open(component if previous is None else component.name,
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                         | (os.O_DIRECTORY if is_directory else 0),
                         **({} if previous is None else {'dir_fd': previous['fd']}))
            row = {'fd': fd, 'attempts': 0, 'closed': False}
            ROWS.append(row)
            info = os.fstat(fd)
            need(stamp(info) == stamp(component.lstat()), 'same_named_held_component')
            need(stat.S_ISDIR(info.st_mode) if is_directory else stat.S_ISREG(info.st_mode),
                 'fixed_regular_or_directory_type')
            if not is_directory:
                need(info.st_uid == 501 and info.st_gid == 20 and info.st_nlink == 1
                     and stat.S_IMODE(info.st_mode) == 0o600, 'original_private_single_link_file')
            if component in (ROOT, ROOT / 'data', ROOT / 'log', CLIENT, CUSTODY, JOB):
                need(info.st_uid == 501 and info.st_gid == 20
                     and stat.S_IMODE(info.st_mode) == 0o700, 'original_owned_private_directory')
            parents.append((component, row, stamp(info)))
            previous = row
        return parents
    except BaseException:
        errors = []
        for _path, row, _before in reversed(parents):
            try:
                close(row)
            except BaseException:
                errors.append('original_open_failure_fd_close')
        if errors:
            REPORT['openFailureDescriptorErrors'] = errors
        raise


def verify(rows):
    deadline()
    for path, row, before in rows:
        need(stamp(os.fstat(row['fd'])) == stamp(path.lstat()) == before,
             'original_complete_component_generation')


def read_file(path, maximum, expected_size=None, public_sha=None):
    rows = open_owned(path)
    try:
        before = os.fstat(rows[-1][1]['fd'])
        need(0 < before.st_size <= maximum and
             (expected_size is None or before.st_size == expected_size), 'fixed_original_file_size')
        raw = bytearray()
        while len(raw) <= before.st_size:
            deadline()
            block = os.read(rows[-1][1]['fd'], min(65536, before.st_size + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        verify(rows)
        need(len(raw) == before.st_size, 'complete_original_file_bytes')
        if public_sha is not None:
            need(hashlib.sha256(raw).hexdigest() == public_sha, 'original_public_receipt_hash')
        return bytes(raw)
    finally:
        errors = []
        for _path, row, _before in reversed(rows):
            try:
                close(row)
            except BaseException:
                errors.append('original_read_fd_close')
        need(not errors, 'all_original_read_descriptors_closed')


def directory(path, ordinal):
    rows = open_owned(path, directory=True)
    try:
        verify(rows)
        value = os.fstat(rows[-1][1]['fd'])
        REPORT.setdefault('currentFixtureDirectories', []).append({
            'ordinal': ordinal, 'device': str(value.st_dev), 'inode': str(value.st_ino),
            'uid': value.st_uid, 'gid': value.st_gid, 'mode': stat.S_IMODE(value.st_mode),
            'directory': stat.S_ISDIR(value.st_mode), 'originalSameGenerationRead': True})
        return rows
    except BaseException:
        for _path, row, _before in reversed(rows):
            if not row['attempts']:
                close(row)
        raise


def main():
    held = []
    try:
        need(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 501
             and os.getgid() == 20 and Path(sys.executable).resolve(strict=True) == PYTHON,
             'fixed_original_mac_interpreter_owner')
        request = json.loads(read_file(JOB / 'request.json', 524288, 248444, REQUEST_SHA))
        need(request.get('job_id') == JOB.name and request.get('job_dir') == str(JOB)
             and request.get('executable') == str(PYTHON)
             and request.get('timeout_seconds') == 630
             and request.get('args', [])[:4] == ['-I', '-S', '-B', '-c']
             and len(request['args']) == 5 and len(request['args'][4].encode()) == 242236
             and hashlib.sha256(request['args'][4].encode()).hexdigest() == SOURCE_SHA,
             'exact_original_request_and_whole_source')
        original = json.loads(read_file(JOB / 'stdout.log', 16384, 10618, STDOUT_SHA))
        need(original.get('ok') is False and original.get('errorCode') == 'fixture_original_t5_mutable_directory'
             and original.get('nodePhases') == [] and original.get('nodeBusinessOutcomeUnknown') is False
             and original.get('allOriginalServersClosed') is True
             and original.get('allExplicitDescriptorsClosedOnce') is True
             and original.get('commands', {}).get('allOwnedCommandsStopped') is True
             and original.get('commands', {}).get('unknownCommandCount') == 0
             and len(original.get('apiPhases', [])) == 1,
             'original_failed_but_complete_owned_closure')
        requests = original['apiPhases'][0]['requests']
        need(len(requests) == 2 and [row.get('routeCategory') for row in requests] == ['health', 'init']
             and [row.get('status') for row in requests] == [501, 200]
             and all(row.get('dispatched') is True and row.get('responseComplete') is True
                     and row.get('responsePrivatelyDurable') is True and row.get('socketsClosed') is True
                     and row.get('outcomeUnknown') is False for row in requests),
             'exact_original_once_init_complete_response')
        held = [directory(path, ordinal) for ordinal, path in enumerate((ROOT, ROOT / 'data', ROOT / 'log'))]
        categories = ['crypto-intent', 'crypto-result'] * 4 + ['server-start-intent',
                      'api-request-intent', 'api-request-result', 'api-request-intent',
                      'api-request-result', 'server-stop-result']
        packets = []
        for ordinal, category in enumerate(categories):
            value = json.loads(read_file(CUSTODY / ('event-%04d.private.json' % ordinal), 65536))
            need(set(value) == {'category', 'value'} and value['category'] == category,
                 'original_event_sequence_no_business_replay')
            packets.append(value['value'])
        for ordinal, expected in ((10, requests[0]), (12, requests[1])):
            need(packets[ordinal] == expected, 'original_http_receipt_exact_public_row')
        need(packets[13].get('phase') == 'initial' and packets[13].get('cleanup', {}).get('ok') is True,
             'original_server_retirement_journal')
        need(not (CUSTODY / 'event-0014.private.json').exists()
             and not (CUSTODY / 'event-0014.private.json').is_symlink(), 'no_unrecorded_later_original_event')
        initialized = json.loads(read_file(CUSTODY / 'initial-002.response.private.bin', 16384))
        keys = initialized.get('keys_base64')
        need(type(initialized.get('root_token')) is str and 8 <= len(initialized['root_token']) <= 16384
             and type(keys) is list and len(keys) == 1 and type(keys[0]) is str
             and 8 <= len(keys[0]) <= 16384, 'original_private_init_material_shape')
        for path in (CLIENT / 'input/initial-plan.private.json', CLIENT / 'input/cold-plan.private.json',
                     CLIENT / 'input/coordinator-role-id', CLIENT / 'input/coordinator-secret-id',
                     CLIENT / 'input/producer-role-id', CLIENT / 'input/producer-secret-id',
                     CLIENT / 'results/initial-state.private.json'):
            need(not path.exists() and not path.is_symlink(), 'original_undispatched_node_material_absent')
        for path in (CLIENT / 'state/coordinator', CLIENT / 'state/producer', CLIENT / 'results'):
            rows = open_owned(path, directory=True)
            try:
                need(os.listdir(rows[-1][1]['fd']) == [], 'original_undispatched_private_state_empty')
                verify(rows)
            finally:
                for _path, row, _before in reversed(rows):
                    close(row)
        for rows in held:
            verify(rows)
        REPORT.update(ok=True, originalRequestAndStdoutExactlyPinned=True,
                      originalOnceInitKnown200AndPrivatelyDurable=True, originalJournalEvents=14,
                      originalNoUnsealOrCoordinatorBusinessDispatched=True,
                      originalPrivateInitMaterialPresent=True, originalNodeStateStillEmpty=True,
                      recoveryMustUseSameInitializedStoreAndOriginalKey=True,
                      anotherInitializationForbidden=True)
    except BaseException as error:
        REPORT['ok'] = False
        REPORT['errorType'] = type(error).__name__
        REPORT['errorCode'] = str(error) if isinstance(error, Refused) else 'fixed_original_artifact_observation_failed'
    finally:
        errors = []
        for row in reversed(ROWS):
            if not row['attempts']:
                try:
                    close(row)
                except BaseException:
                    errors.append('original_descriptor_close_failed')
        REPORT['descriptorCount'] = len(ROWS)
        REPORT['allOriginalDescriptorsClosedOnce'] = all(row['attempts'] == 1 and row['closed'] for row in ROWS)
        REPORT['descriptorCloseErrors'] = errors
        REPORT['withinOriginalTwentySeconds'] = time.monotonic() < UNTIL
        if errors or not REPORT['allOriginalDescriptorsClosedOnce'] or not REPORT['withinOriginalTwentySeconds']:
            REPORT['ok'] = False
        print(json.dumps(REPORT, sort_keys=True, separators=(',', ':')), flush=True)
    return 0 if REPORT['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
