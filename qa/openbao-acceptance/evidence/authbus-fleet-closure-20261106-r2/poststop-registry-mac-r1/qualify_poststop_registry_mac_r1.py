#!/usr/bin/env python3
"""One actual Mac synthetic registry reader composition; no live data reads."""
from __future__ import annotations
import contextlib,errno,hashlib,json,os,sqlite3,stat,sys,time,types
from pathlib import Path
START=time.monotonic();UNTIL=float(sys.argv[1])
ROOT=Path('/Users/qianqi/heptabao-authbus-poststop-registry-qualification-20261106-r1');QUAL=Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2')
PINS={'mac_guarded_current_capture_r3.py': '606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693', 'mac_registry_readonly_wal_r1.py': '60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed', 'authbus_current_auth_wal.py': 'ad443869e259da06de2be71131e5d1854680477d1cf77248e05a3c1704160f8c'}
source_fds=[];fixture_connections=[];fixture_cursors=[];probes=[];sock=None
def remaining():
 if time.monotonic()>=UNTIL:raise RuntimeError('original_registry_worker_deadline')
def read_source(path,expected):
 remaining();fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);row={'closed':False};source_fds.append(row)
 try:
  before=os.fstat(fd)
  assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid in (0,501) and not stat.S_IMODE(before.st_mode)&0o022 and 0<before.st_size<=65536
  data=bytearray()
  while len(data)<=before.st_size:
   remaining();part=os.read(fd,min(65536,before.st_size+1-len(data)))
   if not part:break
   data.extend(part)
  def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  assert len(data)==before.st_size and ident(before)==ident(os.fstat(fd))==ident(path.lstat()) and hashlib.sha256(data).hexdigest()==expected
  return bytes(data)
 finally:os.close(fd);row['closed']=True
def fixture_execute(db,sql,args=()):
 remaining();cursor=db.cursor();row={'closed':False};fixture_cursors.append(row)
 try:cursor.execute(sql,args)
 finally:cursor.close();row['closed']=True
def close_fixture(row):
 if row['closeAttempted']:return
 row['closeAttempted']=True;row['db'].close();row['closed']=True
assert sys.platform=='darwin' and os.getuid()==501 and START<UNTIL<=START+30
assert sqlite3.sqlite_version=='3.53.4'
os.umask(0o077);sys.dont_write_bytecode=True
for code,path,flags in [('own-protected-read',ROOT/'protected-read',os.O_RDONLY),
 ('own-protected-write',ROOT/'protected-write',os.O_WRONLY),
 ('live-configuration-read',Path('/Users/qianqi/.openclaw/openclaw.json'),os.O_RDONLY)]:
 try:fd=os.open(path,flags)
 except OSError as error:assert error.errno in (errno.EPERM,errno.EACCES);probes.append({'name':code,'denied':True})
 else:os.close(fd);raise RuntimeError('synthetic_kernel_path_not_refused')
import socket
try:
 sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM);sock.settimeout(.1);sock.connect(('127.0.0.1',9))
except OSError as error:assert error.errno in (errno.EPERM,errno.EACCES);probes.append({'name':'network','denied':True})
else:raise RuntimeError('synthetic_kernel_network_not_refused')
finally:
 if sock is not None:sock.close()
source={name:read_source(QUAL/'qa'/name,pin) for name,pin in PINS.items()}
sys.path.insert(0,str(QUAL/'qa'))
import mac_guarded_current_capture_r3 as base
import mac_registry_readonly_wal_r1 as wal
auth_raw=source['authbus_current_auth_wal.py'].decode()
old='SYNTHETIC_ROOT = Path("/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2")'
assert auth_raw.count(old)==1
derived=auth_raw.replace(old,'SYNTHETIC_ROOT = Path('+repr(str(ROOT/'output'))+')')
auth=types.ModuleType('fixture_original_auth_reader');auth.__file__=str(ROOT/'code/fixture_original_auth_reader.py')
exec(compile(derived,auth.__file__,'exec'),auth.__dict__)
sys.path.insert(0,str(ROOT/'code'))
import mac_poststop_registry_read_r1 as bridge
Refused,need=base.CaptureRefused,base.need
def inputs(live):
 return auth.AuthInputs(until=min(UNTIL,time.monotonic()+20),critical=contextlib.nullcontext,cancelled=lambda:False,live=live,synthetic=True)
CASES = []
TOTAL = {'connections': 0, 'cursors': 0, 'descriptors': 0}
fixture_root = ROOT / 'output'
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
    remaining();live = fixture_root / 'cases' / ('A%02d' % (len(CASES)+1)) / 'live'
    (live / 'state').mkdir(parents=True, mode=0o700)
    path = live / 'state/openclaw.sqlite'
    writer = sqlite3.connect(path, isolation_level=None)
    writer_row={'db':writer,'closeAttempted':False,'closed':False}
    fixture_connections.append(writer_row)
    fixture_execute(writer, create_sql)
    fixture_execute(writer, insert_sql, ['installed-plugin-index', '["base"]'] + ['synthetic']*11)
    fixture_execute(writer, insert_sql, ['unrelated-key', '["unrelated"]'] + ['synthetic-other']*11)
    if mode in ('nonempty', 'uncommitted'):
        fixture_execute(writer, 'PRAGMA journal_mode=WAL')
        fixture_execute(writer, 'PRAGMA wal_autocheckpoint=0')
        fixture_execute(writer, "UPDATE installed_plugin_index SET plugins_json='[\"committed\"]' WHERE index_key='installed-plugin-index'")
        if mode == 'uncommitted':
            fixture_execute(writer, 'BEGIN IMMEDIATE')
            fixture_execute(writer, "UPDATE installed_plugin_index SET plugins_json='[\"uncommitted\"]' WHERE index_key='installed-plugin-index'")
    else:
        close_fixture(writer_row)
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
                fixture_execute(writer, 'ROLLBACK')
            close_fixture(writer_row)
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

for name,pin in PINS.items():read_source(QUAL/'qa'/name,pin)
remaining()
report={'schema':'heptabao.actual-mac-poststop-registry-composition.r1',
 'ok':len(CASES)==11 and all(row['passed'] for row in CASES),
 'cases':CASES,'passed':sum(row['passed'] for row in CASES),'expected':11,
 'actualMacSQLite':True,'sqliteVersion':sqlite3.sqlite_version,
 'actualOriginalHeldFdAndReadonlyWalRoutes':True,
 'fixedProductionNamespaceQualifiedBySyntheticFixture':False,
 'fixtureRootDerivationOnly':True,'fixtureOwnerGroupLiteralChanged':False,
 'originalAuthSyntheticRootOnlyDerivation':True,'productionSourcesRead':False,
 'productionQuiescenceQualified':False,'providerDispatched':False,'serviceChanged':False,
 'kernelDenials':probes,'probeSocketClosed':sock is not None and sock.fileno()==-1,
 'sourcePins':PINS,'resourceCounts':TOTAL,
 'allSourceCodeDescriptorsClosedOnce':all(row['closed'] for row in source_fds),
 'allFixtureWriterConnectionsClosedOnce':all(row['closeAttempted'] and row['closed'] for row in fixture_connections),
 'allFixtureCursorsClosedOnce':all(row['closed'] for row in fixture_cursors),
 'fixtureWriterConnectionCount':len(fixture_connections),'fixtureCursorCount':len(fixture_cursors),
 'elapsedSeconds':time.monotonic()-START}
report['ok']=report['ok'] and report['probeSocketClosed'] and all(report[k] for k in (
 'allSourceCodeDescriptorsClosedOnce','allFixtureWriterConnectionsClosedOnce','allFixtureCursorsClosedOnce'))
print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if report['ok'] else 1)
