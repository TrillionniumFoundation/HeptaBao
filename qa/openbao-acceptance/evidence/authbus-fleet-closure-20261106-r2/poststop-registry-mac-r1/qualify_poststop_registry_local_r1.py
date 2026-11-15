#!/usr/bin/env python3
"""Actual local SQLite checks of the new fixed registry composition.

The namespace harness is synthetic and does not qualify Mac custody, sandbox,
runtime source pins, or production quiescence. Original WalInputs SQL/cursor/
connection methods, original fixed registry reader and original full9 bundle
verifier are loaded from their already captured public source bytes unchanged.
No live path, provider, credential or service is accessed.
"""
from __future__ import annotations
import ast
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import time
import types

HERE = Path(__file__).resolve().parent
WAL = HERE.parent / 'mac-rollout-source-work/reference/mac_registry_readonly_wal_r1.py'
AUTH = HERE.parent / 'HeptaBao-current-924b/qa/openbao-acceptance/authbus_current_auth_wal.py'
WAL_SHA = '60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed'
AUTH_SHA = 'ad443869e259da06de2be71131e5d1854680477d1cf77248e05a3c1704160f8c'

class Refused(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def identity(info):
    return tuple(str(value) for value in (info.st_dev, info.st_ino, info.st_uid,
        info.st_gid, info.st_mode, info.st_nlink, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns))

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

class FixtureInputs:
    def remaining(self, until=None):
        need(not self.closed and time.monotonic() < min(self.until, until or self.until),
             'fixture_original_deadline')
    def account(self, count):
        self.byte_count += count
        need(self.byte_count <= 4 * 1024 * 1024, 'fixture_account_bound')
    def directory(self, path):
        path = Path(path)
        if str(path) in self.parents:
            return self.parents[str(path)]
        parent = None if path == Path('/') else self.directory(path.parent)
        fd = (os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW) if parent is None else
              os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent['fd']))
        row = {'fd': fd, 'path': str(path), 'name': path.name, 'parent': parent,
               'expected': identity(os.fstat(fd)), 'closeAttempted': False, 'closed': False}
        self.fds.append(row)
        self.parents[str(path)] = row
        return row
    def hold(self, path, *, optional=False, maximum=4*1024*1024):
        self.remaining()
        path = Path(path)
        if str(path) in self.files:
            return self.files[str(path)]
        if str(path) in self.absent:
            return None
        parent = self.directory(path.parent)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent['fd'])
        except FileNotFoundError:
            need(optional, 'fixture_required_file')
            self.absent[str(path)] = {'name': path.name, 'parent': parent}
            return None
        row = {'fd': fd, 'path': str(path), 'name': path.name, 'parent': parent,
               'expected': identity(os.fstat(fd)), 'closeAttempted': False, 'closed': False}
        self.fds.append(row)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, 'fixture_regular_bound')
        self.files[str(path)] = row
        return row
    def verify(self):
        self.remaining()
        for row in [*self.parents.values(), *self.files.values()]:
            named = (os.lstat('/') if row['parent'] is None else
                     os.stat(row['name'], dir_fd=row['parent']['fd'], follow_symlinks=False))
            need(identity(named) == identity(os.fstat(row['fd'])) == row['expected'],
                 'fixture_whole_namespace_changed')
        for row in self.absent.values():
            try:
                os.stat(row['name'], dir_fd=row['parent']['fd'], follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise Refused('fixture_absence_changed')
        self.verified = True

base = types.ModuleType('mac_guarded_current_capture_r3')
base.FixedInputs = FixtureInputs
base.CaptureRefused = Refused
base.need, base.identity, base.encoded = need, identity, encoded
base.MIB, base.MAX_QUERY_SECONDS = 1024*1024, 3
base.MAX_ROW_BYTES, base.MAX_RETURNED_AND_READ_BYTES = 256*1024, 4*1024*1024
base.LIVE = Path('/synthetic/no-production-read')
sys.modules[base.__name__] = base
wal_raw, auth_raw = WAL.read_bytes(), AUTH.read_bytes()
assert hashlib.sha256(wal_raw).hexdigest() == WAL_SHA
assert hashlib.sha256(auth_raw).hexdigest() == AUTH_SHA
wal = types.ModuleType('actual_public_registry_wal')
exec(compile(wal_raw, str(WAL), 'exec'), wal.__dict__)
auth = types.SimpleNamespace(wal=wal, base=base)
auth_tree = ast.parse(auth_raw)
definition = [node for node in auth_tree.body if isinstance(node, ast.FunctionDef)
              and node.name == 'verify_auth_bundle']
assert len(definition) == 1
namespace = {'wal': wal, 'base': base, 'need': need, 'os': os}
exec(compile(ast.Module(body=definition, type_ignores=[]), str(AUTH), 'exec'), namespace)
auth.verify_auth_bundle = namespace['verify_auth_bundle']
bridge_raw = (HERE/'mac_poststop_registry_read_r1.py').read_bytes()
bridge_text = bridge_raw.decode()
owner_literal = "row['expected'][3] == '20'"
assert bridge_text.count(owner_literal) == 1
# The local executor cannot chown into the Mac group. This one literal is
# explicitly fixture-derived; full9 still contains the actual local metadata.
# No UID/group admission claim is made from this harness.
bridge_fixture = bridge_text.replace(owner_literal,
    "row['expected'][3] == " + repr(str(os.getegid())))
bridge = types.ModuleType('local_fixture_poststop_registry')
exec(compile(bridge_fixture, str(HERE/'mac_poststop_registry_read_r1.py'), 'exec'), bridge.__dict__)

def inputs(live):
    # Explicit fixture-only initialization; never bypasses actual Mac admission
    # in the production library and is not exported as a production constructor.
    obj = object.__new__(wal.WalInputs)
    obj.live, obj.synthetic, obj.until = live, True, time.monotonic() + 10
    obj.critical, obj.cancelled = contextlib.nullcontext, lambda: False
    obj.uid, obj.byte_count, obj.closed, obj.verified = os.geteuid(), 0, False, False
    obj.fds, obj.parents, obj.files, obj.absent = [], {}, {}, {}
    obj.connections, obj.connect_attempts, obj.cursors, obj.queries, obj.bundles = [], [], [], [], []
    obj.code_fds, obj.returned_rows, obj.close_errors = [], [], []
    obj.current_phase, obj.failure, obj.original_immutable_route_invoked = 'fixture', None, False
    return obj

CASES = []
TOTAL = {'connections': 0, 'cursors': 0, 'descriptors': 0}
fixture_root = Path(tempfile.mkdtemp(prefix='registry-composition-local-', dir=HERE))
columns = ['index_key', 'plugins_json'] + ['field_' + chr(97+i) for i in range(11)]
create_sql = 'CREATE TABLE installed_plugin_index (' + ','.join(
    name + (' TEXT PRIMARY KEY' if name == 'index_key' else ' TEXT') for name in columns) + ')'
insert_sql = 'INSERT INTO installed_plugin_index VALUES (' + ','.join('?' for _ in columns) + ')'

def group_fixture(path):
    for suffix in ('', '-wal', '-shm'):
        file = Path(str(path) + suffix)
        if file.exists():
            os.chmod(file, 0o600)

def run(name, mode, operation, expected_error=False):
    live = fixture_root / name / 'live'
    (live / 'state').mkdir(parents=True, mode=0o700)
    path = live / 'state/openclaw.sqlite'
    writer = sqlite3.connect(path, isolation_level=None)
    writer.execute(create_sql).close()
    writer.execute(insert_sql, ['installed-plugin-index', '["base"]'] + ['synthetic']*11).close()
    writer.execute(insert_sql, ['unrelated-key', '["unrelated"]'] + ['synthetic-other']*11).close()
    if mode in ('nonempty', 'uncommitted'):
        writer.execute('PRAGMA journal_mode=WAL').close()
        writer.execute('PRAGMA wal_autocheckpoint=0').close()
        writer.execute("UPDATE installed_plugin_index SET plugins_json='[\"committed\"]' WHERE index_key='installed-plugin-index'").close()
        if mode == 'uncommitted':
            writer.execute('BEGIN IMMEDIATE').close()
            writer.execute("UPDATE installed_plugin_index SET plugins_json='[\"uncommitted\"]' WHERE index_key='installed-plugin-index'").close()
    else:
        writer.close()
        writer = None
        if mode in ('empty', 'empty-shm'):
            Path(str(path)+'-wal').touch(mode=0o600)
        if mode in ('empty-shm', 'orphan-shm'):
            Path(str(path)+'-shm').write_bytes(b'\0'*32768)
        if mode == 'journal':
            Path(str(path)+'-journal').touch(mode=0o600)
    group_fixture(path)
    bridge.LIVE, bridge.DATABASE = live, path
    item = inputs(live)
    outcome, unexpected = None, None
    try:
        operation(item, path)
        outcome = not expected_error
    except (Refused, sqlite3.Error) as error:
        outcome = expected_error
        if not expected_error:
            unexpected = type(error).__name__ + ':' + str(error)
    except BaseException as error:
        outcome = False
        unexpected = type(error).__name__ + ':' + str(error)
    finally:
        item.close()
        closure = (all(row['closed'] for row in item.connections)
                   and all(row['closed'] for row in item.cursors)
                   and all(row['closed'] for row in item.fds))
        if writer is not None:
            if mode == 'uncommitted':
                writer.rollback()
            writer.close()
        for key, rows in (('connections', item.connections), ('cursors', item.cursors),
                          ('descriptors', item.fds)):
            TOTAL[key] += len(rows)
        CASES.append({'name': name, 'passed': bool(outcome and closure),
                      'originalResourcesClosed': closure, 'unexpected': unexpected})

def read_expected(value, route):
    def operation(item, _path):
        bundle = bridge.registry_database(auth, item)
        record, actual_route = bridge.read_registry(auth, item, bundle)
        assert actual_route == route
        assert record['row'][0:2] == ['installed-plugin-index', value]
        assert all(query['queryClosureKnown'] and query['success'] for query in item.queries)
        item.verify()
    return operation

run('rollback_no_sidecar', 'absent', read_expected('["base"]', bridge.IMMUTABLE_ROUTE))
run('empty_wal_no_shm', 'empty', read_expected('["base"]', bridge.IMMUTABLE_ROUTE))
run('empty_wal_existing_shm', 'empty-shm', read_expected('["base"]', bridge.IMMUTABLE_ROUTE))
run('committed_not_checkpointed_visible', 'nonempty', read_expected('["committed"]', bridge.WAL_ROUTE))
run('uncommitted_not_published', 'uncommitted', read_expected('["committed"]', bridge.WAL_ROUTE))
run('orphan_shm_refused', 'orphan-shm', lambda item, _: bridge.registry_database(auth, item), True)
run('rollback_journal_refused', 'journal', lambda item, _: bridge.registry_database(auth, item), True)

def replace_after_admission(item, path):
    bundle = bridge.registry_database(auth, item)
    alternate = path.with_name('new.sqlite')
    alternate.write_bytes(path.read_bytes())
    os.replace(alternate, path)
    bridge.read_registry(auth, item, bundle)
run('same_bytes_new_inode_refused', 'absent', replace_after_admission, True)

def appeared_sidecar(item, path):
    bundle = bridge.registry_database(auth, item)
    Path(str(path)+'-wal').touch()
    bridge.read_registry(auth, item, bundle)
run('new_sidecar_after_admission_refused', 'absent', appeared_sidecar, True)

def query_authorizer(item, _):
    bundle = bridge.registry_database(auth, item)
    original = wal.read_registry
    def wrapped(inputs_, connection, *, until):
        record = original(inputs_, connection, until=until)
        for sql in ('DELETE FROM installed_plugin_index', 'CREATE TABLE denied(x)',
                    'ATTACH DATABASE ":memory:" AS other'):
            try:
                inputs_.execute(connection, sql, until=until, label='fixture-denied-query')
            except sqlite3.DatabaseError:
                pass
            else:
                raise AssertionError('actual authorizer unexpectedly allowed write')
        return record
    wal.read_registry = wrapped
    try:
        record, route = bridge.read_registry(auth, item, bundle)
        assert record['row'][1] == '["base"]' and route == bridge.IMMUTABLE_ROUTE
    finally:
        wal.read_registry = original
run('fixed_reader_denies_write_ddl_attach', 'absent', query_authorizer)

def closure_failure(item, _):
    bundle = bridge.registry_database(auth, item)
    original = item.close_connection_once
    def close_unknown(row):
        original(row)
        row['closed'] = False
        return False
    item.close_connection_once = close_unknown
    try:
        try:
            bridge.read_registry(auth, item, bundle)
        finally:
            # The real close succeeded; keep the deliberately unknown report
            # through the refusal, then restore only the synthetic ledger for
            # fixture cleanup. No second native close is made.
            for row in item.connections:
                row['closed'] = True
    finally:
        item.close_connection_once = original
run('unknown_original_connection_close_refused', 'absent', closure_failure, True)

report = {'schema': 'heptabao.poststop-registry-local-composition.r1',
          'ok': all(row['passed'] for row in CASES), 'cases': CASES,
          'passed': sum(row['passed'] for row in CASES), 'expected': 11,
          'actualLocalSQLite': True, 'actualMacQualified': False,
          'namespaceCustodyHarnessOnly': True, 'actualOwnerGroupAdmissionQualified': False,
          'fixtureOwnerGroupLiteralDerivationCount': 1, 'liveSourcesRead': False,
          'providerDispatched': False, 'productionServiceChanged': False,
          'sourcePins': {'originalWal': WAL_SHA, 'originalAuth': AUTH_SHA,
                         'newBridge': hashlib.sha256((HERE/'mac_poststop_registry_read_r1.py').read_bytes()).hexdigest()},
          'resourceCounts': TOTAL}
assert len(CASES) == report['expected']
print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if report['ok'] else 1)
