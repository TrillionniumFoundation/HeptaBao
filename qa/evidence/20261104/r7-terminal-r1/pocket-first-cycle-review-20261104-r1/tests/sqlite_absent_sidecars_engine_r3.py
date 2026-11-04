#!/usr/bin/env python3
"""Synthetic SQLite engine check; does not replace the actual RO kernel gate.

Run the engine in a child with verified denial of directory write permission.
No production inputs, helper guard mocking, network, or provider calls occur.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def child(root):
    os.umask(0o077)
    root = Path(root)
    source = root / 'source'
    private = root / 'private-copy'
    source.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    database = source / 'openclaw.sqlite'
    columns = ['index_key'] + ['field_' + chr(97 + i) for i in range(12)]
    row = ['installed-plugin-index'] + ['synthetic-' + str(i) for i in range(12)]
    connection = sqlite3.connect(database)
    assert connection.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal'
    connection.execute('CREATE TABLE installed_plugin_index (' + ','.join(c + ' TEXT' for c in columns) + ')')
    connection.execute('INSERT INTO installed_plugin_index VALUES (' + ','.join('?' for _ in columns) + ')', row)
    connection.commit()
    connection.close()
    os.chmod(database, 0o600)
    os.chmod(source, 0o500)

    def snapshot():
        s = database.lstat()
        return {'identity': [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                             s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns],
                'sha256': hashlib.sha256(database.read_bytes()).hexdigest(),
                'sidecars': {suffix: Path(str(database) + suffix).exists() for suffix in ('-wal', '-shm')}}

    def query(path):
        db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=3)
        try:
            db.execute('PRAGMA query_only=ON')
            db.execute('PRAGMA temp_store=MEMORY')
            db.execute('BEGIN')
            actual_columns = [x[1] for x in db.execute('PRAGMA table_info(installed_plugin_index)')]
            actual_rows = db.execute('SELECT ' + ','.join('"' + c + '"' for c in columns)
                                    + ' FROM installed_plugin_index WHERE index_key=?',
                                    ('installed-plugin-index',)).fetchall()
            db.rollback()
            return actual_columns, actual_rows
        finally:
            db.close()

    before = snapshot()
    assert not any(before['sidecars'].values())
    denied = False
    try:
        fd = os.open(source / 'owned-permission-probe', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    except PermissionError:
        denied = True
    assert denied, 'The component requires real DAC denial, including under UID 0'
    direct = None
    try:
        query(database)
    except sqlite3.OperationalError as error:
        direct = {'class': type(error).__name__, 'code': error.sqlite_errorcode,
                  'name': error.sqlite_errorname,
                  'messageSha256': hashlib.sha256(str(error).encode()).hexdigest()}
    assert direct is not None and direct['code'] == sqlite3.SQLITE_CANTOPEN
    clone = private / 'openclaw.sqlite'
    with database.open('rb') as src, clone.open('xb') as dst:
        shutil.copyfileobj(src, dst)
        dst.flush()
        os.fsync(dst.fileno())
    actual_columns, actual_rows = query(clone)
    assert actual_columns == columns and actual_rows == [tuple(row)]
    after = snapshot()
    assert before == after
    checks = [
        ('actual_directory_create_permission_denied', denied),
        ('directory_write_permission_denied', source.stat().st_mode & 0o222 == 0),
        ('actual_wal_database_without_source_sidecars', not any(before['sidecars'].values())),
        ('actual_readonly_uri_cantopen_14', direct['code'] == 14),
        ('owned_copy_exact_13_columns', len(actual_columns) == 13 and actual_columns == columns),
        ('owned_copy_exact_original_row', actual_rows == [tuple(row)]),
        ('source_identity_bytes_and_sidecar_absence_unchanged', before == after),
    ]
    print(json.dumps({'ok': all(v for _, v in checks), 'checks': [{'case': k, 'passed': v} for k, v in checks],
        'sqliteVersion': sqlite3.sqlite_version, 'uid': os.geteuid(), 'directError': direct,
        'sourceBefore': before, 'sourceAfter': after, 'scope': 'Synthetic SQLite engine component only',
        'actualProductionHelperExercised': False, 'kernelReadonlyMountExercised': False,
        'helperGuardsMocked': False, 'productionInputsRead': False, 'networkCalls': 0}))


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--child':
        child(sys.argv[2])
        return
    root = Path(tempfile.mkdtemp(prefix='heptabao-registry-sqlite-engine-r3-'))
    source = Path(__file__).read_text()
    result = subprocess.run(['/usr/bin/python3', '-I', '-S', '-B', '-c', source, '--child', str(root)],
        capture_output=True, timeout=10,
        env={'PATH': '/usr/bin:/bin'})
    report = {'schema': 'heptabao.pocket-registry-sqlite-engine-component.v1',
        'scriptSha256': hashlib.sha256(source.encode()).hexdigest(), 'childReturncode': result.returncode,
        'ownedRoot': str(root), 'childReaped': True, 'parentTimeoutSeconds': 10,
        'stdoutSha256': hashlib.sha256(result.stdout).hexdigest(),
        'stderrSha256': hashlib.sha256(result.stderr).hexdigest()}
    if result.returncode == 0:
        report['result'] = json.loads(result.stdout)
        report['ok'] = report['result']['ok']
    else:
        report.update(ok=False, error='synthetic_child_failed', stderr=result.stderr.decode())
    print(json.dumps(report, sort_keys=True, indent=2))
    raise SystemExit(0 if report['ok'] else 1)


if __name__ == '__main__':
    main()
