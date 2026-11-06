"""Four narrow local FD/signal guards; no Darwin or product qualification."""
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('reviewed_launch_guard', HERE / 'launch_guard.py')
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
results = []


def closed(fd):
    try:
        os.fstat(fd)
    except OSError as exc:
        assert exc.errno == errno.EBADF
    else:
        raise AssertionError('original descriptor remained open')


def item(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'identity': g.file_identity(path.lstat())}


with tempfile.TemporaryDirectory(prefix='heptabao-launch-guard-') as name:
    path = Path(name) / 'owned-fixture'
    path.write_bytes(b'local non-production fixture\n')
    os.chmod(path, 0o600)
    original_open, original_close = os.open, os.close

    clock = g.LaunchClock(time.monotonic() + 5)
    guard = g.Admission(clock.end, clock)
    born, attempts = [], []

    def interrupted_birth(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        born.append(fd)
        clock.interrupted(signal.SIGTERM, None)
        return fd

    def once_close(fd):
        attempts.append(fd)
        original_close(fd)

    with patch.object(g.os, 'open', interrupted_birth), patch.object(g.os, 'close', once_close):
        try:
            guard.open_fd(path, os.O_RDONLY)
        except g.Refused as exc:
            assert str(exc) == 'original_launch_deadline'
        else:
            raise AssertionError('pending signal admitted a descriptor')
        assert len(guard.handles) == 1
        assert guard.close() == []
    assert attempts == born and len(born) == 1 and not guard.handles
    closed(born[0])
    results.append('signal_between_open_and_registration_preserves_once_close')

    guard = g.Admission(time.monotonic() + 5)
    bad = item(path)
    bad['sha256'] = '0' * 64
    captured = None
    try:
        guard.read_file(bad, maximum=1024, private=False)
    except g.Refused as exc:
        captured = exc
    assert str(captured) == 'original_file_content' and len(guard.handles) == 1
    fd = next(iter(guard.handles))
    attempts = []

    def retired_but_error(number):
        attempts.append(number)
        original_close(number)
        raise OSError(errno.EIO, 'injected unknown close result')

    with patch.object(g.os, 'close', retired_but_error):
        errors = guard.close()
        # A second cleanup only returns the existing error; it cannot reclose.
        assert guard.close() == errors
    assert errors == ['original_handle_close_failed'] and attempts == [fd]
    assert str(captured) == 'original_file_content'
    closed(fd)
    results.append('validation_primary_survives_close_error_without_reclose')

    guard = g.Admission(time.monotonic() + 5)
    with patch.object(g.os, 'read', side_effect=AssertionError('private key bytes read')):
        assert guard.read_file(item(path), maximum=1024, private=False,
                               materialize=False, verify_bytes=False) is None
    assert len(guard.files) == 1 and guard.files[0]['byte_hash_checked'] is False
    assert guard.close() == []
    results.append('key_metadata_admission_does_not_read_key_bytes')

    # Exercise the actual main() early-failure/finally path with a real timer.
    old_handler = signal.getsignal(signal.SIGALRM)
    old_timer = signal.getitimer(signal.ITIMER_REAL)
    assert old_timer == (0.0, 0.0)
    signal.signal(signal.SIGALRM, lambda _s, _f: None)
    signal.setitimer(signal.ITIMER_REAL, 20.0)
    try:
        with patch.object(g.sys, 'platform', 'darwin'), patch.object(g.sys, 'argv',
              ['launch_guard.py', '--binding', str(g.BINDING)]):
            try:
                g.main()
            except g.Refused as exc:
                assert str(exc) == 'no_inherited_launch_timer'
            else:
                raise AssertionError('inherited timer admitted')
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        assert 19.0 < remaining <= 20.0 and interval == 0.0
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
    results.append('inherited_timer_rejected_without_cancellation_by_finally')

print(json.dumps({'schema': 'heptabao.launch-guard-local-boundary-checks.v1',
                  'checks': results, 'passed': len(results), 'failed': 0,
                  'platform': sys.platform, 'python': list(sys.version_info[:3]),
                  'darwin_service_or_product_executed': False,
                  'formal_kv2_qualified': False}, sort_keys=True))
