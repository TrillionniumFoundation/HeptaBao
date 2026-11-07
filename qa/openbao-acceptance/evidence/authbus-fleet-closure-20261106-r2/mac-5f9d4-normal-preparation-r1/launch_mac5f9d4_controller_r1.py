#!/usr/bin/env python3
"""Pin the staged controller/selection/bundle and execute one original campaign.

This loader adds no subprocess and does not alter the original controller's
8,280-second deadline, build/test flags, exact 107 cases or source custody.
The separately identified directed15 group shares that same parent deadline.
The native supervisor is 8,400 seconds, including this bounded loader and final
descriptor checks. It does not permit a controller pass beyond 8,280 seconds.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
OUT = ROOT / 'build-test-5f9d4-r1'
SOURCE = ROOT / 'source-5f9d4-r1'
CONTROLLER = OUT / 'controller.original.py'
SELECTION = OUT / 'test-selection.public.json'
BUNDLE = ROOT / 'control/candidate-5f9d4-from-4bde9.bundle'
MARKER = OUT / 'dispatch-once.public.json'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
PINS = {
    CONTROLLER: (34437, 'c37951667705d4aee25f40a84fe8bb87ffb9398d2f1a040517b7b09a28f5f264'),
    SELECTION: (58766, '8ccaedc58a44bfcc6f7af7b6062bc8c0c35c099771bdbab45d865b13ea921bc1'),
    BUNDLE: (9985724, 'e57a93e8f3c13f83259cc6f1a5ca1ddb2ebe8451a0da5ff677c38c83ee8d3d72'),
}
KEY = 'heptabao-mac-normal-5f9d4-107-and-directed15-20261107-r1'
START = time.monotonic()
ADMISSION_UNTIL = START + 10
FDS, DIRECTORIES, FILES = [], {}, {}
RESULT = {'schema': 'heptabao.mac-normal5f9d4-once-loader.r1', 'ok': False,
    'executionKey': KEY, 'controllerDispatchAttempted': False,
    'controllerExitCode': None, 'controllerBusinessSeconds': 8280,
    'nativeSupervisorSeconds': 8400, 'additionalLoaderChildProcesses': 0,
    'automaticRetry': False, 'productionServiceActions': 0}


class Refused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def full9(value):
    return tuple(str(getattr(value, name)) for name in ('st_dev', 'st_ino', 'st_uid',
        'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def track(fd):
    row = {'fd': fd, 'attempts': 0, 'closed': False}
    FDS.append(row)
    return row


def directory(path):
    need(time.monotonic() < ADMISSION_UNTIL, 'loader_admission_ten_seconds')
    if path in DIRECTORIES:
        return DIRECTORIES[path][0]
    parent = None if path == Path('/') else directory(path.parent)
    named = path.lstat() if parent is None else os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)
    need(stat.S_ISDIR(named.st_mode), 'loader_original_directory_type')
    if path.is_relative_to(ROOT):
        need(named.st_uid == 501 and named.st_gid == 20 and stat.S_IMODE(named.st_mode) == 0o700
             and named.st_dev == 16777244, 'loader_private_t5_directory')
    row = track(os.open(path if parent is None else path.name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        **({} if parent is None else {'dir_fd': parent['fd']})))
    need(full9(named) == full9(os.fstat(row['fd'])), 'loader_same_directory_name_and_fd')
    DIRECTORIES[path] = (row, full9(named)[:5])
    return row


def source(path, size, digest):
    parent = directory(path.parent)
    row = track(os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent['fd']))
    before = os.fstat(row['fd'])
    need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
         and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
         and before.st_dev == 16777244 and before.st_size == size, 'loader_original_source_metadata')
    count, digesting, parts = 0, hashlib.sha256(), []
    while count <= size:
        need(time.monotonic() < ADMISSION_UNTIL, 'loader_bounded_original_read')
        raw = os.read(row['fd'], min(1048576, size + 1 - count))
        if not raw:
            break
        count += len(raw); digesting.update(raw)
        if path != BUNDLE:
            parts.append(raw)
    need(count == size and digesting.hexdigest() == digest
         and full9(before) == full9(os.fstat(row['fd'])) == full9(path.lstat()), 'loader_complete_original_source_pin')
    FILES[path] = (row, full9(before))
    return b''.join(parts) if path != BUNDLE else None


def verify():
    for path, (row, expected) in DIRECTORIES.items():
        need(full9(os.fstat(row['fd']))[:5] == full9(path.lstat())[:5] == expected, 'loader_held_directory_identity')
    for path, (row, expected) in FILES.items():
        need(full9(os.fstat(row['fd'])) == full9(path.lstat()) == expected, 'loader_held_source_generation')


try:
    os.umask(0o077); sys.dont_write_bytecode = True
    need(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 501 and os.getgid() == 20
         and Path(sys.executable).resolve(strict=True) == PYTHON, 'loader_actual_mac_runtime_owner')
    need(not SOURCE.exists() and not SOURCE.is_symlink(), 'loader_create_only_new_source')
    contents = {path: source(path, *pin) for path, pin in PINS.items()}
    need(set(os.listdir(DIRECTORIES[OUT][0]['fd'])) == {'controller.original.py', 'test-selection.public.json'},
         'loader_only_prepared_output_files')
    manifest = json.loads(contents[SELECTION])
    need(manifest['execution_source_commit'] == '5f9d4263b136685244aba93e45a69139cb8aba41'
         and manifest['execution_source_tree'] == '2c69f04159c112a883abe57f0d367a2627197c7a'
         and manifest['original_budgets']['outer_seconds'] == 8280, 'loader_exact_candidate_and_original_budget')
    verify()
    parent = DIRECTORIES[OUT][0]
    marker = track(os.open(MARKER.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                           0o600, dir_fd=parent['fd']))
    raw = (json.dumps({'schema': 'heptabao.mac-normal-build-once-intent.r1', 'key': KEY,
        'controllerSha256': PINS[CONTROLLER][1], 'selectionSha256': PINS[SELECTION][1],
        'bundleSha256': PINS[BUNDLE][1], 'originalControllerSeconds': 8280,
        'state': 'dispatched_or_unknown'}, sort_keys=True, separators=(',', ':')) + '\n').encode()
    offset = 0
    while offset < len(raw):
        need(time.monotonic() < ADMISSION_UNTIL, 'loader_once_intent_deadline')
        count = os.write(marker['fd'], raw[offset:]); need(count > 0, 'loader_intent_write_progress'); offset += count
    os.fsync(marker['fd']); os.fsync(parent['fd'])
    info = os.fstat(marker['fd'])
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20 and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(raw), 'loader_original_private_once_intent')
    need(os.pread(marker['fd'], len(raw) + 1, 0) == raw and full9(info) == full9(MARKER.lstat()),
         'loader_once_intent_whole_readback')
    FILES[MARKER] = (marker, full9(info)); verify()
    need(time.monotonic() < ADMISSION_UNTIL, 'loader_admission_complete_in_ten_seconds')
    code = compile(contents[CONTROLLER], str(CONTROLLER), 'exec')
    RESULT['controllerDispatchAttempted'] = True
    try:
        exec(code, {'__name__': '__main__', '__file__': str(CONTROLLER)})
    except SystemExit as ended:
        need(type(ended.code) is int, 'loader_typed_original_controller_exit')
        RESULT['controllerExitCode'] = ended.code
    else:
        raise Refused('loader_original_controller_did_not_exit')
    verify()
    need(RESULT['controllerExitCode'] == 0, 'loader_original_controller_failed')
    RESULT['ok'] = True
except BaseException as error:
    RESULT['errorCode'] = str(error) if isinstance(error, Refused) else 'original_mac_controller_refused_or_unknown'
    RESULT['errorType'] = type(error).__name__
    RESULT['ok'] = False
finally:
    try:
        verify()
    except BaseException:
        RESULT['originalSourceNamesChangedOrUnreadable'] = True; RESULT['ok'] = False
    errors = []
    for row in reversed(FDS):
        row['attempts'] += 1
        try:
            os.close(row['fd']); row['closed'] = True
        except BaseException:
            errors.append('loader_original_descriptor_close_failed')
    RESULT['descriptorCount'] = len(FDS)
    RESULT['allLoaderDescriptorsClosedOnce'] = all(row['attempts'] == 1 and row['closed'] for row in FDS)
    RESULT['descriptorCloseErrors'] = errors
    RESULT['elapsedSeconds'] = time.monotonic() - START
    RESULT['ok'] = bool(RESULT['ok'] and RESULT['allLoaderDescriptorsClosedOnce'] and not errors
                        and RESULT['elapsedSeconds'] < 8400)
    print(json.dumps(RESULT, sort_keys=True), flush=True)
raise SystemExit(0 if RESULT['ok'] else 1)
