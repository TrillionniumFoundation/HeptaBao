#!/usr/bin/env python3
"""Send one exact encrypted Mac seed to the pinned ROG recovery receiver.

Existing root and two shares remain on the authenticated SSH channel and in
receiver memory. No private value appears in argv, tool input or public output.
An uncertain result is retained for read-only reconciliation, never replayed.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import shlex
import signal
import stat
import subprocess
import time
import uuid

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1')
BASE = ROOT / 'control/prepare_recoverable_seed_61ff_http_v2.py'
BASE_SHA = 'b7b14b6fcbf767d76873b215ce10119fe58beb50ec3fbd164b4925ceb188cfea'
R1 = ROOT / 'authority/seed-custody/bootstrap-61ff8bef-r1'
R3 = ROOT / 'authority/seed-custody/bootstrap-61ff8bef-r3'
WORK = ROOT / 'authority/seed-custody/cross-os-rog-61ff-r1'
R3_SHA = 'ef640ced21b11be8cfd2dd8cac9342cff5cc0406e1ee17f0bb07cf85c37d7ecb'
INIT_SHA = 'f2ebe0e0a356ead15bed458038c8f2c240a226d6548995951fb2feb885eae119'
ARCHIVE_SHA = 'c50dbae852e748763038d0e0dcdfe2eae7dbc2a254f2b29642dec47c3117e64b'
REMOTE_ROOT = '/home/qian-qi/heptabao-production-20261104-r1'
REMOTE_WORK = REMOTE_ROOT + '/control/seed-cold-recovery-rog-61ff-r1'
REMOTE_HELPER = REMOTE_ROOT + '/control/recover_seed_linux_61ff_r1.py'
REMOTE_HELPER_SHA = 'f29743d3b7cfc25acecb79b911d4dc705eddc79887db4411e84b745f19072c93'
REMOTE_STAGE_SHA = 'd7620ba81d28e39985980f0211086be6b5b18105a8c6bd39bff787e157940b53'
REMOTE_BINARY_SHA = '7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'


def load_base():
    fd = os.open(BASE, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_nlink == 1
        assert stat.S_IMODE(before.st_mode) == 0o500
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(65537)
        after = os.fstat(fd)
        assert len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == BASE_SHA
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        assert fields(before) == fields(after)
    finally:
        os.close(fd)
    spec = importlib.util.spec_from_file_location('pinned_mac_seed_base', BASE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load_base()


class Transfer:
    def __init__(self):
        self.child = None
        self.creating = False
        self.interrupted = False
        self.sent = False

    def signal(self, number):
        if self.creating:
            self.interrupted = True
            return
        raise base.Refused('owned_cross_os_controller_interrupted')

    def start(self, argv):
        self.creating = True
        try:
            self.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=0, start_new_session=False)
        finally:
            self.creating = False
        base.need(not self.interrupted, 'interrupted_after_owned_ssh_spawn')

    def stop(self):
        if self.child is None:
            return
        if self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=5)


def main():
    os.umask(0o077)
    before = base.boundary()
    r3_raw = base.private_read(R3 / 'result.public.json')
    base.need(base.sha(r3_raw) == R3_SHA, 'source_recovery_receipt_pin')
    r3 = json.loads(r3_raw)
    base.need(r3['ok'] and r3['all_owned_children_stopped']
              and r3['cold_recovery_pairs_verified'] == [[1, 2], [1, 3], [2, 3]], 'source_seed_recovery_required')
    source_inventory = base.inventory(R3 / 'seed/state')
    base.need(source_inventory == r3['seed_archive']['files'], 'exact_stopped_mac_seed')
    archive = base.private_read(R3 / 'seed-state.tgz')
    base.need(len(archive) == 30494 and base.sha(archive) == ARCHIVE_SHA, 'source_archive_pin')
    init_raw = base.private_read(R1 / 'initialization-response.private.json')
    base.need(len(init_raw) == 591 and base.sha(init_raw) == INIT_SHA, 'original_private_initialization_pin')
    init = json.loads(init_raw)
    base.need(len(init['keys_base64']) == 3, 'source_share_count')
    secrets = [init['root_token'], *init['keys_base64'], *init.get('keys', [])]
    base.need(not WORK.exists() and not WORK.is_symlink(), 'fresh_mac_transfer_work_required')
    base.mkdir(WORK)
    nonce = uuid.uuid4().hex
    report = {'schema': 'heptabao.mac-to-linux-seed-controller.v1', 'ok': False,
        'nonce': nonce, 'source_result_sha256': R3_SHA, 'source_archive_sha256': ARCHIVE_SHA,
        'linux_receiver_sha256': REMOTE_HELPER_SHA, 'transport_source_sha256': BASE_SHA,
        'boundary_before': before, 'source_seed_modified': False, 'initialization_repeated': False,
        'production_started': False, 'client_changed': False, 'j3160_contacted': False,
        'credentials_exported_to_control_plane': False, 'private_transfer_attempted': False,
        'automatic_retry': False, 'remote_outcome': 'not_attempted'}
    base.put(WORK / 'intent.public.json', report)
    transfer = Transfer()
    old = {s: signal.signal(s, lambda number, frame: transfer.signal(number))
           for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    ready_raw = bytearray()
    try:
        argv = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1', 'rog',
                '/usr/bin/python3.14 -I -S -B ' + shlex.quote(REMOTE_HELPER) + ' ' + shlex.quote(nonce)]
        end = time.monotonic() + 210
        handshake_end = min(end, time.monotonic() + 45)
        transfer.start(argv)
        report['owned_ssh_pid'] = transfer.child.pid
        with selectors.DefaultSelector() as selector:
            selector.register(transfer.child.stdout, selectors.EVENT_READ)
            while not ready_raw.endswith(b'\n'):
                remaining = handshake_end - time.monotonic()
                base.need(remaining > 0 and bool(selector.select(remaining)), 'destination_handshake_deadline')
                block = os.read(transfer.child.stdout.fileno(), 4097 - len(ready_raw))
                base.need(bool(block), 'destination_closed_before_handshake')
                ready_raw.extend(block)
                base.need(len(ready_raw) <= 4096, 'destination_handshake_bound')
        ready = json.loads(ready_raw)
        expected = {'ready': True, 'nonce': nonce, 'hostname': 'qian-qi-ROG-Flow-Z13-GZ302EA-GZ302EA',
            'uid': 1000, 'stage_sha256': REMOTE_STAGE_SHA, 'root': REMOTE_ROOT, 'work': REMOTE_WORK,
            'helper_sha256': REMOTE_HELPER_SHA, 'transport_sha256': BASE_SHA, 'binary_sha256': REMOTE_BINARY_SHA}
        base.need(ready == expected, 'same_connection_exact_destination')
        base.put(WORK / 'identity-verified.public.json', ready)
        report['same_connection_identity_verified_before_secret_transfer'] = True
        packet = (json.dumps({'nonce': nonce, 'archive_b64': base64.b64encode(archive).decode(),
            'root_token': init['root_token'], 'shares': init['keys_base64'][:2]}, separators=(',', ':')) + '\n').encode()
        base.need(len(packet) <= 131072, 'private_packet_bound')
        base.need(end > time.monotonic(), 'original_transfer_deadline')
        transfer.sent = True
        report['private_transfer_attempted'] = True
        report['remote_outcome'] = 'unknown'
        out, err = transfer.child.communicate(packet, timeout=end - time.monotonic())
        del packet, init, init_raw, archive
        base.put(WORK / 'ssh-stdout.private.log', bytes(ready_raw) + out)
        base.put(WORK / 'ssh-stderr.private.log', err)
        base.need(len(out) <= 65536 and len(err) <= 16384
                  and all(s.encode() not in out + err for s in secrets), 'bounded_secret_free_remote_result')
        result = json.loads(out)
        base.need(transfer.child.returncode == 0 and result.get('ok') is True, 'remote_recovery_failed')
        value = result['result']
        digest = base.sha(base.encoded(value))
        base.need(digest == result['result_sha256'] and value['nonce'] == nonce
                  and value['source_helper_sha256'] == REMOTE_HELPER_SHA
                  and value['archive_sha256'] == ARCHIVE_SHA and value['source_mac_result_sha256'] == R3_SHA,
                  'exact_remote_receipt_binding')
        base.need(value['ok'] and value['all_owned_children_stopped']
                  and value['actual_same_directory_cold_restart'] is True
                  and len(value['processes']) == 2
                  and all(p['stopped'] and p['returncode'] == -15 and not p['forced_kill'] for p in value['processes'])
                  and len(value['requests']) == 16
                  and all(q['outcome'] == 'response_received' and q['replayed'] is False and q['http_seconds'] == 12
                          for q in value['requests']), 'real_linux_cold_restart_complete')
        base.put(WORK / 'linux-result.public.json', value)
        base.need(base.inventory(R3 / 'seed/state') == source_inventory
                  and base.sha(base.private_read(R3 / 'result.public.json')) == R3_SHA
                  and base.sha(base.private_read(R3 / 'seed-state.tgz')) == ARCHIVE_SHA
                  and base.sha(base.private_read(R1 / 'initialization-response.private.json')) == INIT_SHA,
                  'original_mac_seed_and_receipts_unchanged')
        report['boundary_after'] = base.boundary()
        base.need(report['boundary_after'] == before, 'mac_production_boundary_unchanged')
        report.update(ok=True, remote_outcome='confirmed_success', remote_result_sha256=digest,
            remote_owned_servers_reaped=2, remote_known_http_outcomes=16,
            actual_cluster_id=value['cluster_id'], source_seed_verified_unchanged=True,
            native_v6_qualification=False, full_34_mib_qualification=False, production_start_qualified=False)
    except BaseException as exc:
        report.update(ok=False, failure=str(exc) if isinstance(exc, base.Refused) else type(exc).__name__)
    finally:
        try:
            transfer.stop()
        except BaseException as exc:
            report.update(ok=False, local_cleanup_failure=type(exc).__name__)
        report['owned_ssh_stopped'] = transfer.child is None or transfer.child.poll() is not None
        report['owned_ssh_returncode'] = None if transfer.child is None else transfer.child.returncode
        report['remote_readonly_reconciliation_required'] = transfer.sent and report['remote_outcome'] != 'confirmed_success'
        base.need(all(s.encode() not in base.encoded(report) for s in secrets), 'controller_public_secret_scan')
        digest = base.put(WORK / 'result.public.json', report)
        secrets = []
        for s, handler in old.items():
            signal.signal(s, handler)
    print(json.dumps({'ok': report['ok'], 'result': str(WORK / 'result.public.json'), 'sha256': digest,
        'remote_outcome': report['remote_outcome'], 'owned_ssh_stopped': report['owned_ssh_stopped'],
        'automatic_retry': False, 'production_started': False}))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc) if isinstance(exc, base.Refused) else type(exc).__name__,
                          'automatic_retry': False, 'production_started': False}))
        raise SystemExit(2)
