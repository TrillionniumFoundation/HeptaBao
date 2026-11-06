#!/usr/bin/env python3
"""Create one private allrows projection from an already verified restore.

No live-source reads, provider/network calls, services, subprocesses or retries.
Input pins and every credential/content commitment are private. Public output
contains fixed check names, counts and scope only.
"""
import time
ENTRY = time.monotonic()

# Declared stdlib dependency of the extracted future-annotations AST.
# Load it before the restrictive audit starts; do not widen the audit paths.
import __future__
import argparse
import ast
import contextlib
from dataclasses import dataclass
from decimal import Decimal
import errno
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import sqlite3
import stat
import sys
from typing import Any, Mapping
import urllib.parse

WORK_END, TOTAL_END = ENTRY + 52, ENTRY + 60
MIB, UID = 1024 * 1024, 501
ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
INPUT = ROOT / 'control/formal-kv2-allrows-projection-inputs-r3'
OUT = ROOT / 'control/formal-kv2-allrows-projection-execution-r3'
CURRENT = Path('/Users/qianqi/heptabao-formal-kv2-current-20261106-r1')
DEST = CURRENT / 'projections/formal-kv2-current-r3'
READBACK = ROOT / 'control/current-sqlite-independent-readback-execution-r1'
CURRENT_ID = {'dev': 16777233, 'inode': 593473266, 'uid': 501, 'gid': 20, 'mode': 0o700}
PROTOCOL_PIN = {'bytes': 91070, 'sha256': 'f93749dcac3d4f8517c71ff97171aa3cf2083d33f09a16638861e3c4bb012f20'}
READBACK_RESULT_PIN = {'bytes': 10944, 'sha256': 'f0db2d9807b73fa7723b1030ddc9c4d70dd7fbb077855cafe560988d0dfff397'}
READBACK_TERMINAL_PIN = {'bytes': 731, 'sha256': 'b2f396467eed32d27d71a3cf13de64341152f4bf980cae4e6d738d4a81a8fd51'}
VERIFIER_JOB = '1a1b2364646-fc05-7cfa'
TABLES = {'auth_profile_store': ('store_key', 'store_json', 'updated_at'),
          'auth_profile_state': ('state_key', 'state_json', 'updated_at')}
FAMILY = ('', '-wal', '-shm', '-journal')
CHECK_NAMES = (
    'completed_independent_readback_and_exact_private_closure',
    'same_restored_capture_and_all_database_original_identities',
    'all_present_database_hashes_cold_schema_and_sidecars',
    'every_agent_both_tables_exact_original_row_commitments',
    'same_frozen_protocol_projection_schema_and_complete_denominators',
    'create_only_private_projection_full_readback',
    'original_inputs_roots_and_all_database_bytes_unchanged',
    'all_readonly_connections_files_and_owned_directory_handles_closed',
)
FIRED = INTERRUPTED = FINISHING = TIMER_OWNED = False
DIRECTORIES, INPUTS, DATABASES, CHECKS = {}, {}, [], []
ALLOWED_READS, ALLOWED_WRITES, ALLOWED_MKDIRS, ALLOWED_URIS = set(), set(), set(), set()
OPENED = CLOSED = 0
DENIALS = 0
OUTPUT_READY = False
PROTOCOL = None
CLEANUP_ERRORS = []
PUBLIC = {
    'schema': 'heptabao.formal-kv2-allrows-projection.public.v1', 'status': 'failed',
    'projection_complete': False, 'new_work_seconds': 52, 'new_runtime_seconds': 60,
    'deadline_renewed': False, 'automatic_retry': False,
    'source_live_database_opened': False, 'source_live_configuration_opened': False,
    'existing_capture_archive_key_restore_modified': False,
    'network_provider_or_j3160_called': False, 'new_child_processes_spawned': 0,
    'product_sdk_or_service_executed': False, 'credential_values_or_content_fingerprints_published': False,
    'historical_openbao_versions_supplied': False, 'source_live_freshness_qualified': False,
    'cross_database_atomic_snapshot_qualified': False, 'formal_kv2_qualified': False,
    'ha_qualified': False, 'authbus_qualified': False, 'traffic_cutover_performed': False,
    'old_assets_removed': False,
}


class Refused(Exception):
    pass


class Cancelled(BaseException):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def check():
    need(not FIRED and not INTERRUPTED and time.monotonic() < WORK_END, 'original_projection_deadline')


def interrupt(signum, frame):
    global FIRED, INTERRUPTED
    if signum == signal.SIGALRM:
        FIRED = True
    else:
        INTERRUPTED = True
    # Our handlers never raise in the open/dup/connect -> registry interval.
    # Every bounded read/write and SQLite progress callback observes this sticky
    # state. Birth is registered before fstat or the next cancellation check.


def resource_check():
    if FINISHING:
        need(time.monotonic() < TOTAL_END, 'original_projection_cleanup_deadline')
    else:
        check()
        need(not CLEANUP_ERRORS, 'prior_original_resource_cleanup_failed')


def arm_work_timer():
    global TIMER_OWNED
    # Retain ownership even if setitimer or its immediate signal path fails.
    TIMER_OWNED = True
    signal.setitimer(signal.ITIMER_REAL, max(0.000001, WORK_END - time.monotonic()))
    check()


def disarm_owned_timer():
    global TIMER_OWNED
    if TIMER_OWNED:
        signal.setitimer(signal.ITIMER_REAL, 0)
        TIMER_OWNED = False


class OwnedResources:
    """Original FD/connection birth registry; one explicit close attempt only.

    This follows the reviewed launch_guard Admission pattern. Fixed signal
    handlers only set sticky state, so even failure of the first fstat leaves
    the newly returned handle registered for cleanup. A failed close is never
    retried on its possibly reused numeric descriptor.
    """
    def __init__(self):
        self.fds, self.connections, self.redirects = [], [], []

    def _fd_birth(self, factory, kind):
        resource_check()
        row = {'fd': None, 'kind': kind, 'birth_registered': False, 'first_identity': None,
               'first_fstat_failed': False, 'close_attempted': False, 'close_succeeded': False}
        self.fds.append(row)
        fd = factory()
        row['fd'] = fd
        row['birth_registered'] = True
        try:
            row['first_identity'] = identity(os.fstat(fd))
        except BaseException:
            row['first_fstat_failed'] = True
            raise
        resource_check()
        return fd

    def open(self, path, flags, mode=0o600, *, dir_fd=None, kind='file'):
        return self._fd_birth(lambda: os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC,
                                              mode, dir_fd=dir_fd), kind)

    def dup(self, fd):
        return self._fd_birth(lambda: os.dup(fd), 'stdio_saved')

    def close(self, fd):
        matches = [row for row in self.fds if row['fd'] == fd and row['birth_registered']
                   and not row['close_attempted']]
        if len(matches) != 1:
            CLEANUP_ERRORS.append('unknown_or_repeated_original_fd_close')
            return
        row = matches[0]
        row['close_attempted'] = True
        try:
            os.close(fd)
            row['close_succeeded'] = True
        except BaseException:
            CLEANUP_ERRORS.append('original_fd_close_failed_no_retry')

    def connect(self, uri):
        global OPENED
        need(not FINISHING, 'no_new_sqlite_connection_during_cleanup')
        check()
        row = {'connection': None, 'birth_registered': False,
               'close_attempted': False, 'close_succeeded': False}
        self.connections.append(row)
        connection = sqlite3.connect(uri, uri=True, timeout=1)
        row['connection'] = connection
        row['birth_registered'] = True
        OPENED += 1
        check()
        return connection

    def close_connection(self, connection):
        global CLOSED
        matches = [row for row in self.connections if row['connection'] is connection
                   and row['birth_registered'] and not row['close_attempted']]
        if len(matches) != 1:
            CLEANUP_ERRORS.append('unknown_or_repeated_original_sqlite_close')
            return
        row = matches[0]; row['close_attempted'] = True
        try:
            connection.close()
            row['close_succeeded'] = True; CLOSED += 1
        except BaseException:
            CLEANUP_ERRORS.append('original_sqlite_close_failed_no_retry')

    def redirect(self, target, source, saved):
        row = {'target': target, 'saved': saved, 'redirect_attempted': True,
               'redirect_completed': False, 'restore_attempted': False, 'restore_completed': False}
        self.redirects.append(row)
        os.dup2(source, target)
        row['redirect_completed'] = True
        resource_check()

    def restore_stdio(self):
        for row in reversed(self.redirects):
            if row['restore_attempted']:
                continue
            row['restore_attempted'] = True
            try:
                os.dup2(row['saved'], row['target'])
                row['restore_completed'] = True
            except BaseException:
                CLEANUP_ERRORS.append('original_stdio_restore_failed_no_retry')

    def close_all(self):
        self.restore_stdio()
        for row in reversed(self.connections):
            if row['birth_registered'] and not row['close_attempted']:
                self.close_connection(row['connection'])
        for row in reversed(self.fds):
            if row['birth_registered'] and not row['close_attempted']:
                self.close(row['fd'])

    def summary(self):
        rows = [row for row in self.fds if row['birth_registered']]
        connections = [row for row in self.connections if row['birth_registered']]
        kinds = {name: sum(row['kind'] == name for row in rows)
                 for name in ('file', 'directory', 'stdio_saved', 'stdio_private')}
        complete = (all(row['close_attempted'] and row['close_succeeded'] for row in rows + connections)
                    and all(row['restore_attempted'] and row['restore_completed'] for row in self.redirects)
                    and not CLEANUP_ERRORS)
        return {'fd_birth_count': len(rows), 'fd_births_by_kind': kinds,
                'fd_first_fstat_failure_count': sum(row['first_fstat_failed'] for row in rows),
                'fd_close_attempt_count': sum(row['close_attempted'] for row in rows),
                'fd_close_success_count': sum(row['close_succeeded'] for row in rows),
                'unattempted_original_fd_count': sum(not row['close_attempted'] for row in rows),
                'sqlite_connection_birth_count': len(connections),
                'sqlite_close_attempt_count': sum(row['close_attempted'] for row in connections),
                'sqlite_close_success_count': sum(row['close_succeeded'] for row in connections),
                'stdio_redirect_attempt_count': len(self.redirects),
                'stdio_redirect_completed_count': sum(row['redirect_completed'] for row in self.redirects),
                'stdio_restore_attempt_count': sum(row['restore_attempted'] for row in self.redirects),
                'stdio_restore_completed_count': sum(row['restore_completed'] for row in self.redirects),
                'all_original_handles_and_stdio_retired': complete,
                'close_errors': list(CLEANUP_ERRORS)}

    def private_snapshot(self):
        return {'schema': 'heptabao.projection-original-resource-prefix.private.v1',
                'fd_rows': [dict(row) for row in self.fds],
                'connection_rows': [{key: value for key, value in row.items() if key != 'connection'}
                                    for row in self.connections],
                'stdio_redirects': [dict(row) for row in self.redirects],
                'summary_at_snapshot': self.summary(),
                'excludes_own_writer_and_later_publication_fds': True,
                'final_authority': 'complete_final_stdout_resource_custody_and_authoritative_runtime_terminal'}


RESOURCES = OwnedResources()


def unique(rows):
    result = {}
    for key, value in rows:
        need(key not in result, 'duplicate_input_json_key')
        result[key] = value
    return result


def decoded(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: need(False, 'nonfinite_json'))


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False, default=lambda value: {'blobHex': value.hex()}
                      if isinstance(value, bytes) else None).encode()


def identity(st):
    return {'dev': st.st_dev, 'inode': st.st_ino, 'uid': st.st_uid, 'gid': st.st_gid,
            'mode': stat.S_IMODE(st.st_mode), 'file_type': stat.S_IFMT(st.st_mode),
            'nlink': st.st_nlink, 'bytes': st.st_size, 'mtime_ns': st.st_mtime_ns,
            'ctime_ns': st.st_ctime_ns}


def native_version(value):
    return ':'.join(str(value[key]) for key in ('dev', 'inode', 'bytes', 'mtime_ns', 'ctime_ns'))


def canonical_path(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical_existing_path')
    return path


def hold_directory(path, expected=None):
    path = canonical_path(path)
    if str(path) in DIRECTORIES:
        value = DIRECTORIES[str(path)]
        held, current = identity(os.fstat(value['fd'])), identity(path.lstat())
        need(all(value['identity'][key] == held[key] == current[key]
                 for key in ('dev', 'inode', 'uid', 'gid', 'mode', 'file_type')), 'same_held_directory')
        return value
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == UID and stat.S_IMODE(st.st_mode) == 0o700,
         'owned_private_directory')
    observed = identity(st)
    if expected is not None:
        need(all(observed[key] == expected[key] for key in ('dev', 'inode', 'uid', 'gid', 'mode')),
             'original_directory_identity')
    ALLOWED_READS.add(str(path))
    fd = RESOURCES.open(path, os.O_RDONLY | os.O_DIRECTORY, kind='directory')
    need(identity(os.fstat(fd)) == observed, 'held_directory_same_open_identity')
    value = {'path': path, 'fd': fd, 'identity': observed}
    DIRECTORIES[str(path)] = value
    return value


def retained_directories():
    for value in DIRECTORIES.values():
        actual = identity(os.fstat(value['fd']))
        current = identity(value['path'].lstat())
        fields = ('dev', 'inode', 'uid', 'gid', 'mode', 'file_type')
        need(all(actual[k] == current[k] == value['identity'][k] for k in fields), 'original_directory_retained')


def mkdir_exact(path):
    path = Path(path)
    parent = hold_directory(path.parent)
    need(not path.exists() and not path.is_symlink(), 'fresh_output_directory_required')
    ALLOWED_MKDIRS.add(str(path))
    os.mkdir(path.name, mode=0o700, dir_fd=parent['fd'])
    os.fsync(parent['fd'])
    return hold_directory(path)


def read_file(path, maximum, *, pin=None, expected_identity=None, remember=False, keep=True):
    check()
    path = canonical_path(path)
    ALLOWED_READS.add(str(path))
    fd = RESOURCES.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        before = identity(os.fstat(fd))
        need(before['uid'] == UID and before['mode'] == 0o600 and before['nlink'] == 1
             and before['file_type'] == stat.S_IFREG and 0 <= before['bytes'] <= maximum,
             'bounded_private_regular_input')
        if expected_identity is not None:
            need(before == expected_identity, 'exact_original_input_identity')
        h, pieces, count = hashlib.sha256(), [], 0
        while True:
            check()
            block = os.read(fd, MIB)
            if not block:
                break
            count += len(block)
            need(count <= maximum, 'input_size_bound')
            h.update(block)
            if keep:
                pieces.append(block)
        need(count == before['bytes'] and before == identity(os.fstat(fd)) == identity(path.lstat()),
             'unchanged_input_during_full_read')
        actual = {'bytes': count, 'sha256': h.hexdigest()}
        if pin is not None:
            need(actual == {key: pin[key] for key in ('bytes', 'sha256')}, 'exact_original_input_bytes')
        if remember:
            old = INPUTS.get(str(path))
            row = {'identity': before, 'pin': actual, 'maximum': maximum}
            need(old is None or old == row, 'original_input_reobserved_equal')
            INPUTS[str(path)] = row
        return (b''.join(pieces) if keep else None), before, actual
    finally:
        RESOURCES.close(fd)


def create_file(path, raw):
    path = Path(path)
    need(str(path) in ALLOWED_WRITES and isinstance(raw, bytes), 'fixed_create_only_output')
    parent = DIRECTORIES[str(path.parent)]
    fd = RESOURCES.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600, dir_fd=parent['fd'])
    try:
        offset = 0
        while offset < len(raw):
            resource_check()
            written = os.write(fd, memoryview(raw)[offset:offset + 65536])
            need(written > 0, 'private_projection_write_progress')
            offset += written
        os.fsync(fd)
        observed = identity(os.fstat(fd))
        need(observed['uid'] == UID and observed['mode'] == 0o600 and observed['nlink'] == 1
             and observed['bytes'] == len(raw), 'private_output_identity')
    finally:
        RESOURCES.close(fd)
    os.fsync(parent['fd'])
    ALLOWED_READS.add(str(path))
    return observed


@contextlib.contextmanager
def private_stdio():
    originals, opened = [], []
    prior_errors = len(CLEANUP_ERRORS)
    try:
        sys.stdout.flush(); sys.stderr.flush()
        for number, name in ((1, 'runtime.stdout.private'), (2, 'runtime.stderr.private')):
            path = DEST / name
            ALLOWED_WRITES.add(str(path))
            fd = RESOURCES.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, kind='stdio_private')
            opened.append(fd)
            saved = RESOURCES.dup(number)
            originals.append(saved)
            RESOURCES.redirect(number, fd, saved)
        check()
        yield
    finally:
        primary = sys.exc_info()[1]
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except BaseException:
                CLEANUP_ERRORS.append('private_stdio_flush_failed')
        RESOURCES.restore_stdio()
        for original in reversed(originals):
            RESOURCES.close(original)
        for fd in opened:
            try:
                os.fsync(fd)
            except BaseException:
                CLEANUP_ERRORS.append('private_stdio_sync_failed')
            finally:
                RESOURCES.close(fd)
        if str(DEST) in DIRECTORIES:
            try:
                os.fsync(DIRECTORIES[str(DEST)]['fd'])
            except BaseException:
                CLEANUP_ERRORS.append('private_stdio_directory_sync_failed')
        if primary is None and len(CLEANUP_ERRORS) != prior_errors:
            raise Refused('private_stdio_cleanup_failed')


def audit(event, args):
    global DENIALS
    denied = event.startswith(('socket.', 'subprocess.', 'os.exec', 'os.spawn', 'os.posix_spawn', 'os.fork'))
    denied = denied or event in ('os.system', 'sqlite3.enable_load_extension', 'sqlite3.load_extension',
                                 'os.remove', 'os.rmdir', 'os.rename', 'os.link', 'os.symlink', 'os.chmod')
    if event == 'sqlite3.connect':
        denied = args[0] not in ALLOWED_URIS
    if event == 'open' and not isinstance(args[0], int):
        value = os.fsdecode(args[0]); flags = args[2]
        write = type(flags) is int and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        # dir_fd-relative calls use only basenames of the same predeclared outputs.
        allowed = ALLOWED_WRITES if write else ALLOWED_READS
        denied = value not in allowed and not (write and '/' not in value and value in {Path(p).name for p in allowed})
    if event == 'os.mkdir':
        value = os.fsdecode(args[0])
        denied = value not in ALLOWED_MKDIRS and value not in {Path(p).name for p in ALLOWED_MKDIRS}
    if denied:
        DENIALS += 1
        raise Refused('forbidden_projection_effect')


def extract_protocol(raw, path):
    need(len(raw) == PROTOCOL_PIN['bytes'] and hashlib.sha256(raw).hexdigest() == PROTOCOL_PIN['sha256'],
         'fixed_protocol_module_for_pure_extraction')
    parsed = ast.parse(raw)
    functions = {'Refused', 'need', 'digest', 'fixed_json', 'PrivatePin', 'ProjectionSource',
                 'stat_identity', 'ReadbackGenerationAdapter', 'read_pin', 'safe_path',
                 'projection_rows', 'sqlite_projection_decode'}
    constants = {'MIB', 'JSON_REQUEST_MAX', 'TABLES', 'READBACK_CHECKS'}
    selected = [node for node in parsed.body if (
        isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in functions) or (
        isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name) and node.targets[0].id in constants)]
    names = {node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else node.targets[0].id for node in selected}
    need(names == functions | constants and len(selected) == len(names), 'exact_pure_protocol_extraction')
    module = ast.Module(body=[ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0), *selected],
                        type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(dataclass=dataclass, Decimal=Decimal, Path=Path, Any=Any, Mapping=Mapping,
                     json=json, os=os, re=re, stat=stat, time=time, hashlib=hashlib)
    exec(compile(module, str(path), 'exec'), namespace)
    return namespace


def load_protocol(path):
    raw, _, _ = read_file(path, 128 * 1024, pin=PROTOCOL_PIN, remember=True)
    return extract_protocol(raw, path)


class Helpers:
    def decode(self, raw):
        return json.loads(raw, object_pairs_hook=unique, parse_float=Decimal,
                          parse_constant=lambda _: need(False, 'nonfinite_json'))

    def private_read(self, path, maximum):
        raw, _, _ = read_file(path, maximum, remember=True)
        return raw


def checked(name):
    need(name in CHECK_NAMES and name not in CHECKS, 'unique_projection_obligation')
    CHECKS.append(name)


def family_state(path):
    return {suffix: os.path.lexists(str(path) + suffix) for suffix in FAMILY}


def restored_path(restore, relative, *, present):
    need(isinstance(relative, str) and '\\' not in relative and '\0' not in relative, 'relative_database_name')
    path = PurePosixPath(relative)
    need(not path.is_absolute() and str(path) == relative
         and all(part not in ('', '.', '..') for part in path.parts), 'canonical_relative_database_name')
    result = restore / 'baseline-state' / relative
    need(result.is_relative_to(restore), 'restored_database_only')
    current = result.parent
    parents = []
    while current != restore:
        parents.append(current); current = current.parent
    for parent in reversed(parents):
        if os.path.lexists(parent):
            hold_directory(parent)
        else:
            need(not present, 'present_database_parent_missing')
    return result


def query_allrows(connection):
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
    grouped = {}
    for table, columns in TABLES.items():
        values = connection.execute('SELECT ' + ','.join(columns) + ' FROM ' + table
            + ' ORDER BY ' + columns[0] + ' LIMIT 4097').fetchall() if table in tables else []
        need(len(values) <= 4096, 'complete_per_table_row_bound')
        grouped[table] = values
    return grouped


def cold_database(path, row):
    # Fixed Mac/POSIX scope: encode the filesystem bytes directly. Path.as_uri
    # in Python 3.14 lazily imports urllib.request, which this audit forbids.
    need(os.name == 'posix' and isinstance(path, Path) and path.anchor == '/',
         'fixed_absolute_posix_database_uri')
    uri = 'file://' + urllib.parse.quote_from_bytes(os.fsencode(path), safe='/') + '?mode=ro&immutable=1'
    ALLOWED_URIS.add(uri)
    connection = None
    try:
        connection = RESOURCES.connect(uri)
        connection.execute('PRAGMA query_only=ON')
        connection.set_progress_handler(lambda: int(FIRED or INTERRUPTED or time.monotonic() >= WORK_END), 1000)
        need(connection.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'restored_database_quick_check')
        schema = connection.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').fetchall()
        need(hashlib.sha256(encoded(schema)).hexdigest() == row['schema_sha256']
             and connection.execute('PRAGMA page_count').fetchone()[0] == row['page_count'], 'restored_schema_and_pages_exact')
        grouped = query_allrows(connection) if row['kind'] == 'agent' else None
        if grouped is not None:
            need(hashlib.sha256(encoded(grouped)).hexdigest() == row['auth_rows_sha256']
                 and len(grouped['auth_profile_store']) == row['auth_store_rows']
                 and len(grouped['auth_profile_state']) == row['auth_state_rows'], 'complete_original_agent_rows')
        return decoded(encoded(grouped)) if grouped is not None else None
    finally:
        if connection is not None:
            RESOURCES.close_connection(connection)
        ALLOWED_URIS.discard(uri)


def no_source_fds(identities):
    targets = {(row['dev'], row['inode']) for row in identities}
    surface = Path('/dev/fd' if sys.platform == 'darwin' else '/proc/self/fd')
    matches = 0
    for entry in surface.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            a, b = os.fstat(int(entry.name)), os.fstat(int(entry.name))
        except OSError as error:
            need(error.errno == errno.EBADF, 'fd_census_gap')
            continue
        need((a.st_dev, a.st_ino, a.st_mode) == (b.st_dev, b.st_ino, b.st_mode), 'fd_census_changed')
        matches += (a.st_dev, a.st_ino) in targets
    need(matches == 0, 'owned_original_database_or_input_fd_still_open')


def run(inputs):
    global PROTOCOL
    need(inputs['schema'] == 'heptabao.formal-kv2-allrows-projection-inputs.private.v1'
         and inputs['verifier_job_id'] == VERIFIER_JOB, 'fixed_qualified_generation')
    need(inputs['readback_result'] == READBACK_RESULT_PIN and inputs['readback_terminal'] == READBACK_TERMINAL_PIN,
         'actual_independent_success_public_pins')
    PROTOCOL = load_protocol(INPUT / 'formal_kv2_protocol.py')
    pin_type = PROTOCOL['PrivatePin']; h = Helpers()
    pin = inputs['private_closure']
    private_path = READBACK / 'verification.private.json'
    raw, private_identity, actual = read_file(private_path, 16 * MIB, pin=pin['file'],
                                            expected_identity=pin['full_identity'], remember=True)
    need(native_version(private_identity) == pin['file']['version'], 'actual_private_closure_native_version')
    private = decoded(raw)
    original = private['original_completed_file_pins']['restore_capture_manifest']
    restore_identity = private['actual_attempt_root_identities']['restore']
    restore = Path(restore_identity['path'])
    hold_directory(restore, restore_identity)
    need(Path(original['path']) == restore / 'capture.private.json', 'original_restore_capture_only')
    capture_pin = pin_type(Path(original['path']), original['identity']['bytes'], original['sha256'])
    source = PROTOCOL['ProjectionSource'](capture_pin, pin_type(DEST / 'projection.private.json', 0, '0' * 64),
        pin_type(INPUT / 'readback-result.public.json', **READBACK_RESULT_PIN),
        pin_type(INPUT / 'readback-terminal.original.json', **READBACK_TERMINAL_PIN),
        pin_type(INPUT / 'readback-stdout.original', **inputs['readback_stdout']),
        pin_type(private_path, pin['file']['bytes'], pin['file']['sha256']))
    class Deadline:
        work_end = WORK_END
    proof = PROTOCOL['ReadbackGenerationAdapter'](h).reconcile(source, deadline=Deadline())
    need(proof['terminal'].get('job_id') == VERIFIER_JOB
         and proof['result']['original_successful_workflow_job_id'] == pin['original_producer_job_id']
         and pin['verifier_job_id'] == VERIFIER_JOB, 'same_actual_independent_job_and_producer')
    checked(CHECK_NAMES[0])
    capture_raw, _, _ = read_file(capture_pin.path, 16 * MIB,
        pin={'bytes': capture_pin.bytes, 'sha256': capture_pin.sha256}, expected_identity=original['identity'], remember=True)
    capture = decoded(capture_raw)
    need(capture.get('schema') == 'heptabao.closed-current-sqlite-capture.v1' and capture.get('ok') is True
         and capture.get('sqlite_family_suffixes') == list(FAMILY), 'same_complete_closed_capture')
    rows = capture['database_rows']; agents = [row for row in rows if row['kind'] == 'agent']
    expected_cold = proof['result']['cold_sqlite']['restore']
    need(len(rows) == proof['result']['declared_database_family_count'] == len(agents) + 4
         and len(agents) == capture['configured_agent_count'] == proof['result']['captured_agent_count'],
         'dynamic_complete_database_and_agent_denominator')
    originals = private['data_file_original_identity_observations']
    manifest = {row['path']: row for row in capture['files']}
    database_rows = []
    for row in rows:
        path = restored_path(restore, row['relative_path'], present=row['present'])
        declared = manifest['baseline-state/' + row['relative_path']]
        need(declared['present'] is row['present'], 'manifest_same_database_presence')
        members = family_state(path)
        if not row['present']:
            need(not any(members.values()) and str(path) not in originals, 'original_absent_database_family')
            database_rows.append((path, row, None)); continue
        need(members[''] and not any(members[suffix] for suffix in FAMILY[1:]), 'no_restored_database_sidecars')
        old = originals[str(path)]
        need(identity(path.lstat()) == old and old['bytes'] == row['snapshot_bytes'] == declared['bytes']
             and row['snapshot_sha256'] == declared['sha256'], 'actual_original_database_identity_and_manifest')
        database_rows.append((path, row, old))
    checked(CHECK_NAMES[1])
    projection = {'schema': 'heptabao.current-sqlite-allrows-to-kv2.private.v1',
                  'capture_sha256': capture_pin.sha256, 'rows': []}
    agent_slot, counts = 0, {'present': 0, 'absent': 0, 'empty': 0, 'nonempty': 0}
    for index, (path, row, old) in enumerate(database_rows):
        check()
        grouped = {name: [] for name in TABLES}
        if old is None:
            counts['absent'] += 1
        else:
            counts['present'] += 1
            expected_pin = {'bytes': row['snapshot_bytes'], 'sha256': row['snapshot_sha256']}
            read_file(path, row['snapshot_bytes'], pin=expected_pin, expected_identity=old, keep=False)
            if row.get('empty_database_marker'):
                need(row['snapshot_bytes'] == 0, 'exact_empty_database_marker'); counts['empty'] += 1
            else:
                fd = RESOURCES.open(path, os.O_RDONLY | os.O_NONBLOCK)
                try:
                    need(identity(os.fstat(fd)) == old, 'same_database_held_during_sqlite')
                    observed = cold_database(path, row)
                    need(identity(os.fstat(fd)) == old == identity(path.lstat()), 'unchanged_held_database_after_sqlite')
                finally:
                    RESOURCES.close(fd)
                if observed is not None:
                    grouped = observed
                counts['nonempty'] += 1
            read_file(path, row['snapshot_bytes'], pin=expected_pin, expected_identity=old, keep=False)
            need(not any(family_state(path)[suffix] for suffix in FAMILY[1:]), 'no_created_database_sidecars')
            DATABASES.append({'path': str(path), 'identity': old, 'pin': expected_pin})
        if row['kind'] == 'agent':
            for table_index, (table, columns) in enumerate(TABLES.items()):
                for ordinal, fields in enumerate(grouped[table]):
                    record = f'a{agent_slot:04d}-t{table_index}-r{ordinal:04d}'
                    projection['rows'].append({'record_id': record, 'agent_slot': agent_slot, 'table': table,
                        'row_fields': dict(zip(columns, fields)), 'kv_mount': inputs['business_mount'], 'kv_key': record})
            agent_slot += 1
    need(counts['nonempty'] == expected_cold['nonempty_cold_checked']
         and counts['empty'] == expected_cold['empty_markers_verified']
         and counts['absent'] == expected_cold['absent_families_verified']
         and counts['present'] + counts['absent'] == len(rows) and OPENED == CLOSED == counts['nonempty'],
         'whole_database_partition_matches_independent_readback')
    checked(CHECK_NAMES[2]); checked(CHECK_NAMES[3])
    raw_projection = encoded(projection)
    need(len(raw_projection) <= 64 * MIB, 'bounded_complete_projection')
    record_values, protocol_counts = PROTOCOL['projection_rows'](capture,
        PROTOCOL['sqlite_projection_decode'](raw_projection), inputs['business_mount'], capture_pin.sha256)
    need(protocol_counts['agents'] == len(agents) and protocol_counts['database_families'] == len(rows)
         and protocol_counts['auth_profile_store_rows'] == expected_cold['all_agent_auth_store_rows']
         and protocol_counts['auth_profile_state_rows'] == expected_cold['all_agent_auth_state_rows'],
         'actual_qualified_allrows_denominators')
    del record_values
    checked(CHECK_NAMES[4])
    projection_path = DEST / 'projection.private.json'
    projection_identity = create_file(projection_path, raw_projection)
    projection_pin = {'bytes': len(raw_projection), 'sha256': hashlib.sha256(raw_projection).hexdigest()}
    back, _, _ = read_file(projection_path, 64 * MIB, pin=projection_pin, expected_identity=projection_identity)
    need(back == raw_projection, 'independent_whole_projection_readback')
    checked(CHECK_NAMES[5])
    for path, row, old in database_rows:
        if old is None:
            need(not any(family_state(path).values()), 'final_absent_family_unchanged')
        else:
            need(identity(path.lstat()) == old and not any(family_state(path)[s] for s in FAMILY[1:]),
                 'final_original_database_identity_and_no_sidecars')
    for path, row in tuple(INPUTS.items()):
        read_file(path, row['maximum'], pin=row['pin'], expected_identity=row['identity'])
    retained_directories(); checked(CHECK_NAMES[6])
    need(OPENED == CLOSED and not ALLOWED_URIS and DENIALS == 0, 'no_forbidden_effect_or_open_connection')
    no_source_fds([row['identity'] for row in DATABASES] + [row['identity'] for row in INPUTS.values()])
    private_receipt = {'schema': 'heptabao.formal-kv2-allrows-projection.private.v1',
        'projection': {'path': str(projection_path), 'pin': projection_pin, 'identity': projection_identity},
        'restore_root': restore_identity, 'capture_pin': original,
        'qualified_readback_private_pin': pin, 'inputs': INPUTS, 'databases': DATABASES,
        'counts': protocol_counts, 'new_history_baseline': 1,
        'source_updated_at_preserved_as_provenance': True, 'historical_openbao_versions_supplied': False}
    create_file(DEST / 'projection-binding.private.json', encoded(private_receipt))
    PUBLIC.update(counts=protocol_counts, database_partition=counts,
        complete_schema_accepted_by_frozen_protocol=True, projection_complete=True,
        original_verified_restored_generation_preserved=True,
        source_updated_at_and_sqlite_cell_encoding_preserved=True,
        private_projection_file_identity=projection_identity)
    check()


def main():
    global FINISHING, OUTPUT_READY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--controller-sha256', required=True)
    args = parser.parse_args()
    signals = (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    old_handlers = {number: signal.getsignal(number) for number in signals}
    old_timer = signal.getitimer(signal.ITIMER_REAL)
    old_umask = os.umask(0o077)
    failure, cleanup = None, []
    try:
        need(os.geteuid() == UID and sys.platform == 'darwin', 'fixed_actual_mac_owner')
        need(sys.version_info[:2] == (3, 14) and sys.flags.isolated == 1
             and sys.flags.no_site == 1 and sys.dont_write_bytecode, 'isolated_existing_homebrew_python314')
        need(old_timer == (0.0, 0.0) and old_handlers[signal.SIGALRM] == signal.SIG_DFL, 'ambient_timer_refused')
        need(all(re.fullmatch('[0-9a-f]{64}', value) for value in (args.inputs_sha256, args.controller_sha256)),
             'fixed_input_and_controller_pins')
        for number in signals:
            signal.signal(number, interrupt)
        arm_work_timer()
        hold_directory(INPUT); hold_directory(ROOT / 'control'); hold_directory(CURRENT, CURRENT_ID)
        mkdir_exact(OUT); OUTPUT_READY = True
        parent = CURRENT / 'projections'
        if os.path.lexists(parent):
            hold_directory(parent)
        else:
            mkdir_exact(parent)
        mkdir_exact(DEST)
        ALLOWED_WRITES.update(str(path) for path in (OUT / 'result.public.json',
            DEST / 'projection.private.json', DEST / 'projection-binding.private.json', DEST / 'failure.private.json',
            DEST / 'original-resource-prefix.private.json'))
        sys.addaudithook(audit)
        with private_stdio():
            raw, _, _ = read_file(INPUT / 'fixed-inputs.private.json', 128 * 1024, remember=True)
            need(hashlib.sha256(raw).hexdigest() == args.inputs_sha256, 'exact_fixed_private_inputs')
            own = Path(__file__).resolve(strict=True)
            source, _, _ = read_file(own, 128 * 1024, remember=True)
            need(hashlib.sha256(source).hexdigest() == args.controller_sha256, 'exact_controller_bytes')
            run(decoded(raw))
        check()
    except BaseException as error:
        FINISHING = True
        failure = str(error) if isinstance(error, Refused) else (
            'cancelled' if isinstance(error, Cancelled) else 'projection_unexpected_failure')
        if PROTOCOL is not None and isinstance(error, PROTOCOL['Refused']):
            failure = str(error)
        # Private detail is retained separately; no arbitrary exception text is public.
        if str(DEST) in DIRECTORIES:
            try:
                create_file(DEST / 'failure.private.json', encoded({'exception_class': type(error).__name__,
                    'exception_text': str(error), 'fixed_failure_code': failure}))
            except BaseException:
                cleanup.append('private_failure_receipt_not_published')
    finally:
        FINISHING = True
        try:
            retained_directories()
        except BaseException:
            cleanup.append('final_original_fd_or_directory_custody')
        if str(DEST) in DIRECTORIES:
            try:
                create_file(DEST / 'original-resource-prefix.private.json', encoded(RESOURCES.private_snapshot()))
            except BaseException:
                cleanup.append('private_original_resource_prefix_not_published')
        RESOURCES.close_all()
        try:
            need(OPENED == CLOSED and not ALLOWED_URIS, 'all_cold_connections_closed')
            no_source_fds([row['identity'] for row in DATABASES] + [row['identity'] for row in INPUTS.values()])
        except BaseException:
            cleanup.append('final_original_database_or_input_handle_retirement')
        work_resources = RESOURCES.summary()
        work_closed_at = time.monotonic()
        PUBLIC.update(work_resource_custody=work_resources,
            cold_connections_opened=OPENED, cold_connections_closed=CLOSED,
            deadline_fired=FIRED, interrupted=INTERRUPTED, forbidden_effect_attempt_count=DENIALS)
        if (not failure and not cleanup and not CLEANUP_ERRORS and not FIRED and not INTERRUPTED
                and work_resources['all_original_handles_and_stdio_retired'] and work_closed_at < WORK_END):
            checked(CHECK_NAMES[7])
        else:
            PUBLIC['projection_complete'] = False
        successful = (not failure and not cleanup and not CLEANUP_ERRORS and CHECKS == list(CHECK_NAMES)
                      and not FIRED and not INTERRUPTED and work_closed_at < WORK_END)
        PUBLIC.update(status='passed' if successful else 'failed', primary_failure_code=failure,
            cleanup_failure_codes=cleanup + CLEANUP_ERRORS, checks=[{'check': name, 'passed': True} for name in CHECKS],
            required_check_count=len(CHECK_NAMES), observed_check_count=len(CHECKS),
            elapsed_work_observation_seconds=work_closed_at - ENTRY,
            work_and_original_handles_completed_before_52_seconds=work_closed_at < WORK_END,
            result_requires_final_stdout_handle_closeout=True)
        # Work and all original handles end inside 52s. Receipt publication uses
        # only the reserved eight seconds; it is not an extension of the work.
        if TIMER_OWNED:
            try:
                signal.setitimer(signal.ITIMER_REAL, max(0.000001, TOTAL_END - time.monotonic()))
            except BaseException:
                cleanup.append('original_fixed_publication_timer_failed')
                successful = False; PUBLIC.update(status='failed', projection_complete=False)
        receipt_handles_closed = False
        if OUTPUT_READY:
            try:
                fd = RESOURCES.open(OUT, os.O_RDONLY | os.O_DIRECTORY, kind='directory')
                try:
                    actual = identity(os.fstat(fd)); original = DIRECTORIES[str(OUT)]['identity']
                    need(all(actual[k] == original[k] for k in ('dev', 'inode', 'uid', 'gid', 'mode')),
                         'same_public_output_after_original_close')
                    target = RESOURCES.open('result.public.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                            0o600, dir_fd=fd)
                    try:
                        raw = encoded(PUBLIC); offset = 0
                        while offset < len(raw):
                            resource_check()
                            written = os.write(target, raw[offset:offset + 65536])
                            need(written > 0, 'public_receipt_write_progress')
                            offset += written
                        os.fsync(target)
                    finally:
                        RESOURCES.close(target)
                    os.fsync(fd)
                finally:
                    RESOURCES.close(fd)
                receipt_handles_closed = RESOURCES.summary()['all_original_handles_and_stdio_retired']
            except BaseException:
                successful = False; PUBLIC.update(status='failed', projection_complete=False)
                cleanup.append('public_receipt_persistence_failed')
        RESOURCES.close_all()
        final_resources = RESOURCES.summary()
        if (FIRED or INTERRUPTED or time.monotonic() >= TOTAL_END or cleanup or CLEANUP_ERRORS
                or not final_resources['all_original_handles_and_stdio_retired']):
            successful = False; PUBLIC.update(status='failed', projection_complete=False)
        try:
            disarm_owned_timer()
        except BaseException:
            successful = False; PUBLIC.update(status='failed', projection_complete=False)
            cleanup.append('owned_timer_not_disarmed')
        if FIRED or INTERRUPTED or time.monotonic() >= TOTAL_END:
            successful = False; PUBLIC.update(status='failed', projection_complete=False)
        for number, handler in old_handlers.items():
            try:
                signal.signal(number, handler)
            except BaseException:
                cleanup.append('original_signal_handler_restore_failed')
        try:
            os.umask(old_umask)
        except BaseException:
            cleanup.append('original_umask_restore_failed')
        # A sticky signal may have arrived while disarming/restoring. Decide
        # once more after those operations; do not leave a stale success bit.
        if (FIRED or INTERRUPTED or time.monotonic() >= TOTAL_END or cleanup or CLEANUP_ERRORS
                or not receipt_handles_closed):
            successful = False; PUBLIC.update(status='failed', projection_complete=False)
        PUBLIC['cleanup_failure_codes'] = cleanup + CLEANUP_ERRORS
        PUBLIC.update(deadline_fired=FIRED, interrupted=INTERRUPTED,
                      receipt_publication_handles_closed=receipt_handles_closed,
                      final_resource_custody=final_resources)
        print(json.dumps(PUBLIC, sort_keys=True, separators=(',', ':')), flush=True)
    return 0 if successful else 1


if __name__ == '__main__':
    raise SystemExit(main())
