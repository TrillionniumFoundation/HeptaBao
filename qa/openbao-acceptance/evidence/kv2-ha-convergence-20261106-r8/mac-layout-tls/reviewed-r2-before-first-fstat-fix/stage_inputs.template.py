#!/usr/bin/env python3
"""Create-only eleven public preparation inputs; never runs the preparation."""
import time
ENTRY = time.monotonic()
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys

PARENT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control')
OUT = PARENT / 'formal-kv2-layout-tls-inputs-r1'
EXPECTED_NAMES = {
    'layout_tls_prepare.py', 'bootstrap_layout.py', 'fixed-inputs.public.json',
    'mac107-result.public.json', 'mac107-runtime-terminal.original.json',
    'environment-result.public.json', 'environment-runtime-terminal.original.json',
    'readback-result.public.json', 'readback-runtime-terminal.original.json',
    'service-preflight-result.public.json', 'service-preflight-runtime-terminal.original.json',
}
END = ENTRY + 52
PENDING = None
FIRED = False
PROTECTED = 0
FINISHING = False
PARENT_FD = None
OUT_FD = None
PARENT_PIN = None
OUT_PIN = None
FILES = {}
FILE_OPENED = 0
FILE_CLOSED = 0
PUBLIC = {
    'schema': 'heptabao.normal-kv2-layout-tls-input-stage.v1', 'status': 'failed',
    'work_seconds': 52, 'runtime_seconds': 60, 'preparation_executed': False,
    'private_key_created': False, 'service_started': False, 'business_source_opened': False,
    'provider_or_j3160_called': False, 'product_or_sdk_executed': False,
    'old_assets_or_inputs_replaced': False, 'subprocesses_started': False,
    'original_count': 0, 'automatic_retry': False, 'formal_kv2_qualified': False,
    'durable_completion_authority': 'original_runtime_terminal_and_final_stdout_with_60_second_cap',
    'primary_failure_code': None, 'cleanup_failure_codes': [],
}


class Refused(Exception):
    pass


class Interrupted(BaseException):
    pass


def need(ok, label):
    if not ok:
        raise Refused(label)


def check():
    if PENDING is not None or FIRED or time.monotonic() >= END:
        raise Interrupted()


def interrupt(signum, _frame):
    global PENDING, FIRED
    if PENDING is None:
        PENDING = signum
    FIRED = FIRED or signum == signal.SIGALRM
    if not PROTECTED and not FINISHING:
        raise Interrupted()


def dirpin(path, fd=None):
    need(path.resolve(strict=True) == path, 'canonical_directory_required')
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == 501 and st.st_gid == 20
         and stat.S_IMODE(st.st_mode) == 0o700, 'owned_private_directory_required')
    pin = [st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)]
    if fd is not None:
        held = os.fstat(fd)
        need(stat.S_ISDIR(held.st_mode)
             and pin == [held.st_dev, held.st_ino, held.st_uid, held.st_gid, stat.S_IMODE(held.st_mode)],
             'original_directory_handle_binding')
    return pin


def directories_unchanged():
    need(dirpin(PARENT, PARENT_FD) == PARENT_PIN and dirpin(OUT, OUT_FD) == OUT_PIN,
         'directory_identity_changed')


def filepin(st):
    return {'dev': st.st_dev, 'inode': st.st_ino, 'uid': st.st_uid, 'gid': st.st_gid,
            'mode': stat.S_IMODE(st.st_mode), 'file_type': stat.S_IFMT(st.st_mode),
            'nlink': st.st_nlink, 'bytes': st.st_size, 'mtime_ns': st.st_mtime_ns, 'ctime_ns': st.st_ctime_ns}


def open_owned(path, flags, mode=0o600, dir_fd=None):
    global PROTECTED, FILE_OPENED
    PROTECTED += 1
    try:
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dir_fd)
        FILES[fd] = filepin(os.fstat(fd))
        FILE_OPENED += 1
        return fd
    finally:
        PROTECTED -= 1


def close_owned(fd):
    global PROTECTED, FILE_CLOSED
    PROTECTED += 1
    try:
        need(fd in FILES, 'unknown_numeric_fd_close_refused')
        old, current = FILES[fd], filepin(os.fstat(fd))
        need(all(old[k] == current[k] for k in ('dev', 'inode', 'uid', 'gid', 'mode', 'file_type')),
             'original_file_handle_changed')
        del FILES[fd]
        os.close(fd)
        FILE_CLOSED += 1
    finally:
        PROTECTED -= 1


def create(name, raw):
    directories_unchanged()
    fd = open_owned(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, dir_fd=OUT_FD)
    try:
        offset = 0
        while offset < len(raw):
            if not FINISHING:
                check()
            count = os.write(fd, memoryview(raw)[offset:offset + 65536])
            need(count > 0, 'write_without_progress')
            offset += count
        os.fsync(fd)
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 501 and st.st_gid == 20
             and st.st_nlink == 1 and st.st_size == len(raw) and stat.S_IMODE(st.st_mode) == 0o600,
             'created_input_file_custody')
    finally:
        close_owned(fd)
    os.fsync(OUT_FD)
    directories_unchanged()


def readback(item):
    check()
    fd = open_owned(item['name'], os.O_RDONLY, dir_fd=OUT_FD)
    try:
        before = filepin(os.fstat(fd))
        need(before['file_type'] == stat.S_IFREG and before['uid'] == 501 and before['gid'] == 20
             and before['nlink'] == 1 and before['mode'] == 0o600 and before['bytes'] == item['bytes'],
             'readback_file_custody')
        raw = bytearray()
        while len(raw) <= item['bytes']:
            check()
            part = os.read(fd, min(65536, item['bytes'] + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        need(len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256']
             and before == filepin(os.fstat(fd))
             == filepin(os.stat(item['name'], dir_fd=OUT_FD, follow_symlinks=False)), 'exact_input_readback')
        return before
    finally:
        close_owned(fd)


def run(items):
    global PROTECTED, PARENT_FD, OUT_FD, PARENT_PIN, OUT_PIN
    check()
    need(sys.platform == 'darwin' and os.geteuid() == 501 and os.getegid() == 20
         and sys.version_info[:3] == (3, 14, 3) and sys.flags.isolated and sys.flags.no_site
         and sys.dont_write_bytecode, 'fixed_mac_isolated_interpreter')
    python = Path(sys.executable).resolve(strict=True)
    before = filepin(python.lstat())
    fd = open_owned(python, os.O_RDONLY)
    try:
        raw = os.read(fd, 34641)
        need(len(raw) == 34640 and hashlib.sha256(raw).hexdigest()
             == 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
             and before == filepin(os.fstat(fd)) == filepin(python.lstat()), 'fixed_python_bytes_and_identity')
    finally:
        close_owned(fd)
    need(type(items) is list and len(items) == 11 and {x['name'] for x in items} == EXPECTED_NAMES,
         'exact_eleven_inputs_required')
    need(sum(x['bytes'] for x in items) <= 400000, 'input_total_cap')
    for item in items:
        need(set(item) == {'name', 'bytes', 'sha256', 'text'}
             and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', item['name'])
             and type(item['bytes']) is int and 0 < item['bytes'] <= 200000,
             'fixed_input_shape')
        raw = item['text'].encode('utf-8')
        need(len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256'],
             'exact_request_input_content')
    PARENT_PIN = dirpin(PARENT)
    need(PARENT_PIN[0] == 16777244, 'expected_external_device')
    need(not os.path.lexists(OUT), 'new_stage_root_must_be_absent')
    PROTECTED += 1
    try:
        PARENT_FD = os.open(PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(dirpin(PARENT, PARENT_FD) == PARENT_PIN, 'parent_before_create')
        os.mkdir(OUT.name, 0o700, dir_fd=PARENT_FD)
        os.fsync(PARENT_FD)
        OUT_FD = os.open(OUT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=PARENT_FD)
        OUT_PIN = dirpin(OUT, OUT_FD)
    finally:
        PROTECTED -= 1
    PUBLIC['input_root_created'] = True
    PUBLIC['input_root_identity'] = OUT_PIN
    rows = []
    for item in items:
        check()
        create(item['name'], item['text'].encode('utf-8'))
        ident = readback(item)
        rows.append({'name': item['name'], 'bytes': item['bytes'], 'sha256': item['sha256'],
                     'identity': ident, 'exact_readback': True})
    for item in items:
        need(readback(item) == next(x['identity'] for x in rows if x['name'] == item['name']),
             'second_original_input_readback_changed')
    directories_unchanged()
    check()
    PUBLIC.update(status='passed', staged_inputs=11, staged_public_inputs=11, staged_private_inputs=0,
                  all_input_bytes_modes_and_original_identities_exact=True,
                  all_original_directories_preserved=True, inputs=rows)


def main(items):
    global FINISHING, PROTECTED
    previous = {}
    armed = False
    old_umask = os.umask(0o077)
    try:
        need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'foreign_timer_refused')
        for signum in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupt)
        PROTECTED += 1
        try:
            armed = True
            signal.setitimer(signal.ITIMER_REAL, max(0.000001, END - time.monotonic()))
        finally:
            PROTECTED -= 1
        run(items)
        check()
    except BaseException as error:
        label = str(error) if isinstance(error, Refused) else type(error).__name__
        PUBLIC['primary_failure_code'] = label if re.fullmatch(r'[A-Za-z0-9_]{1,100}', label) else 'stage_failure'
        PUBLIC['status'] = 'failed'
    finally:
        FINISHING = True
        for fd in list(FILES):
            try:
                close_owned(fd)
            except BaseException:
                PUBLIC['cleanup_failure_codes'].append('original_file_retirement_incomplete')
        try:
            if OUT_FD is not None:
                directories_unchanged()
        except BaseException:
            PUBLIC['cleanup_failure_codes'].append('original_directory_identity_changed')
        if PENDING is not None or FIRED or time.monotonic() >= END:
            PUBLIC['cleanup_failure_codes'].append('original_deadline_or_interrupt')
        if PUBLIC['primary_failure_code'] or PUBLIC['cleanup_failure_codes']:
            PUBLIC['status'] = 'failed'
        PUBLIC['elapsed_observation_before_receipt_publication_seconds'] = time.monotonic() - ENTRY
        PUBLIC['partial_new_inputs_retained'] = PUBLIC['status'] != 'passed'
        if OUT_FD is not None:
            try:
                create('input-stage-result.public.json', (json.dumps(PUBLIC, indent=2, sort_keys=True) + '\n').encode())
            except BaseException:
                PUBLIC['cleanup_failure_codes'].append('stage_receipt_publication_failed')
        closed = 0
        for fd in (OUT_FD, PARENT_FD):
            if fd is not None:
                try:
                    os.close(fd)
                    closed += 1
                except OSError:
                    PUBLIC['cleanup_failure_codes'].append('original_directory_close_failed')
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
        for signum, prior in previous.items():
            signal.signal(signum, prior)
        os.umask(old_umask)
        PUBLIC.update(owned_directory_handles_closed=closed,
                      all_owned_directory_handles_retired=closed == int(OUT_FD is not None) + int(PARENT_FD is not None),
                      owned_file_handles_opened=FILE_OPENED, owned_file_handles_closed=FILE_CLOSED,
                      all_owned_file_handles_retired=FILE_OPENED == FILE_CLOSED and not FILES,
                      deadline_fired=FIRED, interrupted_signal=PENDING)
        if not PUBLIC['all_owned_file_handles_retired']:
            PUBLIC['cleanup_failure_codes'].append('file_descriptor_denominator_not_closed')
        if PENDING is not None or FIRED or time.monotonic() >= END:
            PUBLIC['cleanup_failure_codes'].append('final_deadline_or_interrupt')
        if PUBLIC['primary_failure_code'] or PUBLIC['cleanup_failure_codes']:
            PUBLIC['status'] = 'failed'
        print(json.dumps(PUBLIC, sort_keys=True, separators=(',', ':')), flush=True)
    return 0 if PUBLIC['status'] == 'passed' else 1


# The eleven exact public inputs are appended as one private transport literal.
