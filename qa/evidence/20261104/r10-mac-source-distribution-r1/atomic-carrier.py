#!/usr/bin/env python3
"""Create-only Mac distribution of four fixed public R10 inputs; execute none."""
from pathlib import Path
import base64, hashlib, json, os, plistlib, signal, stat, subprocess, sys, time

os.umask(0o077)
BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
RECEIPT = BASE / 'normal-r10-inert-carrier-mac-r1.result.public.json'
PINS = {
    'normal-r10-source-stager-r1.py': (27150, '90bc84593ba4a2845cbce6141277e22e01dfc9be3fce126a31448a9428f8c990'),
    'normal-r10-launcher-r1.py': (20167, 'd1542351492f9efb41ba18c3b25e9548be7eb658db5cb13c5b4bf80f097a55ad'),
    'continuation-20261104-native-http-r10.bundle.zlib': (70406, '6be899e6fcd09beadcf788e81b36fc4eaf211413dea07d0cee41300fe264af4c'),
    'canonical-r10-from-r9.bundle': (1522, '543ad493d0b3e224f9620b5418e7eda260a000ccc1d8c3c0153bc49a963dad36'),
}
children = []
protected = 0
pending_signal = None
prewrite_guard_record = None
volume_verified = False

class Cancelled(BaseException):
    pass

def on_signal(signum, _frame):
    global pending_signal
    pending_signal = signum
    if not protected:
        raise Cancelled()


for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(signum, on_signal)

def group_members(pgid):
    raw = subprocess.check_output(
        ['/bin/ps', '-axo', 'pid=,ppid=,pgid=,stat='], text=True, timeout=10)
    result = []
    for line in raw.splitlines():
        values = line.split()
        if len(values) >= 4 and int(values[2]) == pgid:
            result.append({'pid': int(values[0]), 'ppid': int(values[1]),
                           'pgid': int(values[2]), 'state': values[3]})
    return result


def stop_owned(process):
    # Signal only while the original direct child has not been reaped.
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    # A residual group after reap is a failure, never authority to signal it.
    return group_members(process.pid)


def prewrite_volume_guard():
    # Original diskutil 30-second cap, with the same protected Popen/owned group.
    # No path on the candidate volume is written until its exact UUID is known.
    global protected, prewrite_guard_record
    argv = ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5']
    prefix = '%03d-t5-volume-identity' % len(children)
    start = time.monotonic()
    timed_out = False
    protected += 1
    try:
        process = subprocess.Popen(argv, env=dict(os.environ), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        children.append((prefix, process))
    finally:
        protected -= 1
    if pending_signal is not None:
        raise Cancelled()
    try:
        out, err = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        timed_out = True
        stop_owned(process)
        out, err = process.communicate(timeout=5)
    finally:
        if process.poll() is None:
            stop_owned(process)
    remaining = group_members(process.pid)
    assert len(out) <= 65536 and len(err) <= 65536
    receipt = {'argv': argv, 'exit_code': process.returncode, 'timed_out': timed_out,
               'elapsed_seconds': time.monotonic() - start, 'limit_seconds': 30,
               'pid': process.pid, 'direct_child_reaped': process.returncode is not None,
               'remaining': remaining, 'stdout_sha256': sha(out), 'stderr_sha256': sha(err)}
    prewrite_guard_record = (prefix, out, err, receipt)
    assert process.returncode == 0 and not timed_out and not remaining
    info = plistlib.loads(out)
    assert info.get('VolumeUUID') == 'FB804D1B-24CB-4D6E-AEA7-A9E180807758'
    return info['VolumeUUID']


def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def ident(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)
def sync_dir():
    fd = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
def exact(path, raw):
    assert path.resolve(strict=True) == path
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == 501
        assert before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
        assert before.st_size == len(raw)
        parts, count = [], 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            count += len(block)
            assert count <= len(raw)
            parts.append(block)
        assert b''.join(parts) == raw
        assert ident(before) == ident(os.fstat(fd)) == ident(path.lstat())
        return {'bytes': count, 'sha256': sha(raw), 'mode': '0600', 'identity': list(ident(before))}
    finally:
        os.close(fd)
def publish(name, raw):
    destination = BASE / name
    if os.path.lexists(destination):
        return {'path': str(destination), 'publication': 'existing_exact', **exact(destination, raw)}
    temporary = BASE / ('.' + name + '.hepta-r10-inert-mac-r1.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), 0o600)
        os.fsync(stream.fileno())
        made = os.fstat(stream.fileno())
    assert stat.S_ISREG(made.st_mode) and made.st_uid == 501 and made.st_nlink == 1
    assert ident(made) == ident(temporary.lstat())
    publication = 'created'
    try:
        os.link(temporary, destination, follow_symlinks=False)
    except FileExistsError:
        publication = 'existing_after_race'
    # Only unlink the temporary inode that this attempt exclusively created.
    current = temporary.lstat()
    assert (current.st_dev, current.st_ino) == (made.st_dev, made.st_ino)
    os.unlink(temporary)
    sync_dir()
    return {'path': str(destination), 'publication': publication, **exact(destination, raw)}

assert (os.uname().sysname, os.uname().machine) == ('Darwin', 'arm64')
assert os.getuid() == 501 and BASE.resolve(strict=True) == BASE and BASE.stat().st_uid == 501
assert not os.path.lexists(RECEIPT)
result = {'schema': 'heptabao.r10-inert-input-carrier.mac.v1', 'status': 'failed',
          'started_ns': time.time_ns(), 'files': [], 'source_executed': False,
          'git_started': False, 'compiler_started': False, 'service_started': False}
try:
    result['external_volume_uuid'] = prewrite_volume_guard()
    volume_verified = True
    incoming = sys.stdin.buffer.read(262145)
    assert 0 < len(incoming) <= 262144
    payload = json.loads(incoming)
    assert set(payload) == {'schema', 'files'} and payload['schema'] == 'heptabao.r10-inert-inputs.mac.v1'
    assert set(payload['files']) == set(PINS)
    decoded = {}
    for name, (length, digest) in PINS.items():
        raw = base64.b64decode(payload['files'][name], validate=True)
        assert len(raw) == length and sha(raw) == digest
        decoded[name] = raw
    result['stdin_bytes'] = len(incoming)
    result['stdin_sha256'] = sha(incoming)
    for name, raw in decoded.items():
        result['files'].append(publish(name, raw))
    result['status'] = 'prepared'
except BaseException as error:
    result['error_type'] = type(error).__name__
finally:
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, signal.SIG_IGN)
    cleanup = []
    for label, process in reversed(children):
        try:
            remaining = stop_owned(process)
            cleanup.append({'label': label, 'pid': process.pid, 'exit_code': process.returncode,
                            'direct_child_reaped': process.returncode is not None, 'remaining': remaining})
        except BaseException as error:
            cleanup.append({'label': label, 'pid': process.pid, 'cleanup_error': type(error).__name__})
    result['cleanup'] = cleanup
    result['all_owned_stopped'] = all(
        x.get('direct_child_reaped') and x.get('remaining') == [] and not x.get('cleanup_error')
        for x in cleanup)
    if pending_signal is not None or not result['all_owned_stopped']:
        result['status'] = 'failed'
    result['volume_verified_before_writes'] = volume_verified
    if prewrite_guard_record is not None:
        result['volume_guard'] = prewrite_guard_record[3]
    result['terminal_ns'] = time.time_ns()
    if volume_verified:
        raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
        publish(RECEIPT.name, raw)
    print(json.dumps(result, sort_keys=True), flush=True)
sys.exit(0 if result['status'] == 'prepared' else 1)
