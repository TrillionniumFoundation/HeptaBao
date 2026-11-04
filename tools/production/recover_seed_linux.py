#!/usr/bin/env python3
"""Restore the exact stopped Mac r3 seed on one private ROG loopback node.

The only secret input is two recovery shares and the existing root token over
the same authenticated SSH connection after its public identity handshake.
No initialization, production activation, persistent share file or client edit.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys

ROOT = Path('/home/qian-qi/heptabao-production-20261104-r1')
WORK = ROOT / 'control/seed-cold-recovery-rog-61ff-r2'
HOST = 'qian-qi-ROG-Flow-Z13-GZ302EA-GZ302EA'
BASE = ROOT / 'control/recover_seed_transport_61ff_b7_r2.py'
BASE_SHA = 'b7b14b6fcbf767d76873b215ce10119fe58beb50ec3fbd164b4925ceb188cfea'
STAGE_SHA = 'd7620ba81d28e39985980f0211086be6b5b18105a8c6bd39bff787e157940b53'
GUARD_SHA = 'cb883080dd0346d6d69f8517b98a9c60a0a07279c936b355c2993e4c08c09aba'
BINARY_SHA = '7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'
LEAF_SHA = 'e64b926438be3e8acbf63f7f2f876c4a05a7b260972de9d43b875d17f327c4a6'
ARCHIVE_SHA = 'c50dbae852e748763038d0e0dcdfe2eae7dbc2a254f2b29642dec47c3117e64b'
CLUSTER_ID = '0c56fad8-4061-349e-84a8-0a4cbc7ca12a'
MAC_RESULT_SHA = 'ef640ced21b11be8cfd2dd8cac9342cff5cc0406e1ee17f0bb07cf85c37d7ecb'
FILES = {
    'journal.hbj': {'bytes': 29443, 'sha256': '44a07026ad4a1e6002f890741c9643e0d58ba327ec8c684c10b2443ade309edb'},
    'ledger.hbl': {'bytes': 398, 'sha256': '8e85f26ac225f4e34810231e83fb5b9ad0fe1e6b2e721707835feba6b616566d'},
    'seal.json': {'bytes': 206, 'sha256': '4229d5cc3044af2af0e5e6779277d0573ae3b1a0a112037a90c7af166fac7469'},
    'state.hbs': {'bytes': 97, 'sha256': 'b29a33870609ad6ba2777bd4a0edeaf220523623217c71153cb44ac3f738c18c'},
}


def initial_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == 1000 and before.st_nlink == 1
        assert stat.S_IMODE(before.st_mode) == 0o500 and before.st_size < 65536
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(65537)
        after = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        assert fields(before) == fields(after) and len(raw) == before.st_size
        return raw
    finally:
        os.close(fd)


def load_base():
    raw = initial_read(BASE)
    assert hashlib.sha256(raw).hexdigest() == BASE_SHA
    spec = importlib.util.spec_from_file_location('fixed_seed_transport', BASE)
    base = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(BASE), 'exec'), base.__dict__)
    # Exactly three host configuration constants change. All HTTP framing,
    # deadlines, file checks, archive extraction and owned-process code remain
    # the byte-identical b7 module exercised by the 13 TLS/signal component cases.
    base.ROOT, base.BINARY_SHA, base.LEAF_SHA = ROOT, BINARY_SHA, LEAF_SHA
    return base


base = load_base()


def boundary():
    base.need(sys.platform == 'linux' and os.getuid() == 1000
              and socket.gethostname() == HOST, 'exact_linux_actor')
    base.need(Path(sys.executable).resolve() == Path('/usr/bin/python3.14'), 'exact_linux_python_path')
    raw = base.private_read(ROOT / 'control/stage.private.json', maximum=65536)
    base.need(base.sha(raw) == STAGE_SHA, 'exact_linux_stage')
    binding = json.loads(raw)
    base.need(binding['source_commit'] == base.SOURCE and binding['source_tree'] == base.TREE
              and binding['files']['release/heptabao-server']['sha256'] == BINARY_SHA
              and binding['leaf_der_sha256'] == LEAF_SHA, 'normal_linux_stage_source_binding')
    guard = ROOT / 'release/heptabao_linux_node_start.py'
    base.need(base.sha(base.private_read(guard, 0o500)) == GUARD_SHA, 'linux_guard_pin')
    checked = subprocess.run(['/usr/bin/python3.14', '-I', '-S', '-B', str(guard),
        'check-stage', '--stage', str(ROOT / 'control/stage.private.json'), '--stage-sha256', STAGE_SHA],
        capture_output=True, text=True, timeout=20)
    base.need(checked.returncode == 0 and not checked.stderr, 'actual_linux_stage_check')
    value = json.loads(checked.stdout)
    base.need(value.get('ok') is True and value.get('activation_present') is False, 'linux_stage_not_activated')
    for relative in ('node/state', 'node/raft'):
        base.need(not list((ROOT / relative).iterdir()), 'production_linux_state_still_empty')
    base.need(not (ROOT / 'control/activation.sha256').exists(), 'no_linux_activation_pin')
    return {'stage_sha256': STAGE_SHA, 'source': base.SOURCE, 'tree': base.TREE,
            'binary_sha256': BINARY_SHA, 'leaf_sha256': LEAF_SHA}


def phase(run, label):
    code, status = run.request(label + '-sealed', 'GET', 'sys/seal-status')
    run.check(label + '.cold_threshold', code == 200 and status.get('sealed') is True
              and status.get('n') == 3 and status.get('t') == 2 and status.get('progress') == 0)
    run.unseal_pair((0, 1), label)
    code, mounts = run.request(label + '-mounts', 'GET', 'sys/mounts', auth=True)
    run.check(label + '.temporary_mount_absent', code == 200
              and 'heptabao-seed-recovery-61ff/' not in mounts.get('data', mounts))
    run.seal(label)
    run.stop()


def main():
    os.umask(0o077)
    base.need(len(sys.argv) == 2 and len(sys.argv[1]) == 32
              and all(c in '0123456789abcdef' for c in sys.argv[1]), 'nonce_shape')
    nonce = sys.argv[1]
    before = boundary()
    own_sha = base.sha(initial_read(Path(__file__)))
    base.need(not WORK.exists() and not WORK.is_symlink(), 'fresh_cross_os_work_required')
    base.mkdir(WORK)
    base.mkdir(WORK / 'journal')
    base.put(WORK / 'intent.public.json', {'schema': 'heptabao.cross-os-seed-intent.v1',
        'nonce': nonce, 'source_mac_result_sha256': MAC_RESULT_SHA, 'archive_sha256': ARCHIVE_SHA,
        'helper_sha256': own_sha, 'transport_sha256': BASE_SHA, 'initialize': False,
        'same_connection_identity_required': True, 'production_started': False})
    run = base.SeedRun(WORK)
    run.report.update(schema='heptabao.mac-to-linux-seed-cold-recovery.v1',
        source_mac_result_sha256=MAC_RESULT_SHA, archive_sha256=ARCHIVE_SHA,
        source_helper_sha256=own_sha, transport_source_sha256=BASE_SHA,
        transport_host_bindings={'ROOT': str(ROOT), 'BINARY_SHA': BINARY_SHA, 'LEAF_SHA': LEAF_SHA},
        initialization_repeated=False, complete_initialization_response_received=False,
        transitional_complete_init_response_retained_privately=False,
        recovery_shares_received_in_memory=0, recovery_shares_persisted_on_linux=False,
        shares_distributed=False, boundary_before=before, nonce=nonce)
    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM)
    old = {s: signal.signal(s, lambda number, frame: run.handle_signal(number)) for s in signals}
    signal.alarm(180)
    try:
        print(json.dumps({'ready': True, 'nonce': nonce, 'hostname': HOST, 'uid': os.getuid(),
            'stage_sha256': STAGE_SHA, 'root': str(ROOT), 'work': str(WORK),
            'helper_sha256': own_sha, 'transport_sha256': BASE_SHA, 'binary_sha256': BINARY_SHA}), flush=True)
        raw = sys.stdin.buffer.readline(131073)
        base.need(0 < len(raw) <= 131072 and raw.endswith(b'\n'), 'bounded_private_transfer')
        packet = json.loads(raw)
        base.need(set(packet) == {'nonce', 'archive_b64', 'root_token', 'shares'} and packet['nonce'] == nonce,
                  'same_connection_transfer_binding')
        run.root_token, run.shares = packet['root_token'], packet['shares']
        base.need(isinstance(run.root_token, str) and 16 <= len(run.root_token) <= 1024
                  and isinstance(run.shares, list) and len(run.shares) == 2
                  and len(set(run.shares)) == 2
                  and all(isinstance(s, str) and 16 <= len(s) <= 1024 for s in run.shares), 'recovery_material_shape')
        run.secret_values = [run.root_token, *run.shares,
                             *[base64.b64decode(s, validate=True).hex() for s in run.shares]]
        archive = base64.b64decode(packet['archive_b64'], validate=True)
        base.need(len(archive) == 30494 and base.sha(archive) == ARCHIVE_SHA, 'exact_mac_archive')
        del raw, packet
        run.report['recovery_shares_received_in_memory'] = 2
        run.archive = WORK / 'source-mac-seed-state.tgz'
        base.put(run.archive, archive)
        del archive
        run.seed_inventory = FILES
        run.cluster_id = CLUSTER_ID
        run.restore('restored')
        run.start('restored')
        phase(run, 'first-linux-restore')
        first = base.inventory(WORK / 'restored/state')
        # Preserve the first exact config and both logs, then restart against
        # the SAME durable directory with a new owned process and fresh port.
        for name in ('server.private.json', 'server.stdout.private.log', 'server.stderr.private.log'):
            old_path = WORK / 'restored' / name
            saved = old_path.with_name('first-' + name)
            base.private_read(old_path)
            base.need(not saved.exists(), 'restart_archive_name_occupied')
            os.rename(old_path, saved)
        base.fsync_dir(WORK / 'restored')
        run.check('same_linux_state_before_restart', base.inventory(WORK / 'restored/state') == first)
        run.start('restored')
        phase(run, 'second-linux-cold-start')
        run.check('original_archive_unchanged', base.sha(base.private_read(run.archive)) == ARCHIVE_SHA)
        run.report['boundary_after'] = boundary()
        run.check('production_linux_boundary_unchanged', run.report['boundary_after'] == before)
        for path in sorted(WORK.rglob('*')):
            if path.is_file():
                content = base.private_read(path, stat.S_IMODE(path.stat().st_mode))
                run.check('no_plaintext_secret_' + base.sha(str(path.relative_to(WORK)).encode())[:16],
                          all(secret.encode() not in content for secret in run.secret_values))
        run.report.update(ok=True, cluster_id=CLUSTER_ID,
            actual_same_directory_cold_restart=True, first_stopped_state_inventory=first,
            final_stopped_state_inventory=base.inventory(WORK / 'restored/state'))
    except BaseException as exc:
        run.report.update(ok=False, failure=str(exc) if isinstance(exc, base.Refused) else type(exc).__name__)
    finally:
        signal.alarm(0)
        try:
            run.stop()
        except BaseException as exc:
            run.report.update(ok=False, cleanup_failure=str(exc) if isinstance(exc, base.Refused) else type(exc).__name__)
        run.report['all_owned_children_stopped'] = all(p['stopped'] for p in run.report['processes'])
        base.need(all(s.encode() not in base.encoded(run.report) for s in run.secret_values), 'public_report_secret_scan')
        digest = base.put(WORK / 'result.public.json', run.report)
        run.root_token = None
        run.shares = []
        run.secret_values = []
        for s, handler in old.items():
            signal.signal(s, handler)
    print(json.dumps({'ok': run.report['ok'], 'result_sha256': digest, 'result': run.report}), flush=True)
    return 0 if run.report['ok'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc) if isinstance(exc, base.Refused) else type(exc).__name__,
                          'automatic_retry': False, 'initialization_repeated': False}))
        raise SystemExit(2)
