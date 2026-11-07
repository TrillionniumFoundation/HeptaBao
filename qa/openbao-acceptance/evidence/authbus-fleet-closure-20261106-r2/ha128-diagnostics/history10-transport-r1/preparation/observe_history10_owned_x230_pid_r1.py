"""One <=5-second read-only view of the new diagnostic's exact owned Linux PID.

No process signals, child, socket, product API, key/value read or filesystem
write. Dynamic /proc rows are explicitly non-atomic observations. Missing
visibility produces an observation refusal, never proof of zero usage.
"""
import collections
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import stat
import sys
import time

ROOT = Path('/home/qian/heptabao-ha-history10-transport-20261107-r1')
PORTS = (31040, 31041)
STATES = {'01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1',
          '05': 'FIN_WAIT2', '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT',
          '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING', '0C': 'NEW_SYN_RECV'}
WAITS = {'futex_wait_queue', 'futex_wait_queue_me', 'do_epoll_wait', 'ep_poll',
         'inet_csk_accept', 'wait_woken', 'pipe_read', 'hrtimer_nanosleep',
         'io_schedule', 'wait_on_page_bit_common', 'folio_wait_bit_common',
         'do_wait', 'do_select', 'poll_schedule_timeout', 'tcp_recvmsg',
         '__skb_wait_for_more_packets', 'sk_wait_data'}
OPENED = CLOSED = 0


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(path, maximum, private=False, *, directory_fd=None):
    global OPENED, CLOSED
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=directory_fd)
    OPENED += 1
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode), 'regular_metadata_input')
        if private:
            need(before.st_uid == 1000 and before.st_nlink == 1
                 and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= maximum,
                 'private_original_process_metadata')
        raw = bytearray()
        while True:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
            need(len(raw) <= maximum, 'bounded_metadata_read')
        if private:
            need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                 == identity(os.stat(path, dir_fd=directory_fd, follow_symlinks=False)),
                 'stable_original_process_metadata')
        return bytes(raw)
    finally:
        os.close(fd)
        CLOSED += 1


def fields(path):
    raw = read(path, 8192).decode('ascii')
    split = raw.rfind(') ')
    need(split >= 0, 'proc_stat_shape')
    values = raw[split + 2:].split()
    need(len(values) >= 22 and values[19].isdecimal(), 'proc_stat_fields')
    return values


def main():
    global OPENED, CLOSED
    started = time.monotonic()
    report = {'schema': 'heptabao.history10-owned-x230-pid-observation.v1', 'ok': False,
              'children': 0, 'networkCalls': 0, 'writes': 0, 'signals': 0,
              'keyReads': 0, 'dynamicProcRowsAtomic': False, 'metadataOnly': True}
    pidfd = rootfd = None
    try:
        need(sys.platform == 'linux' and platform.node() == 'qian-ThinkPad-X230'
             and os.geteuid() == 1000 and len(sys.argv) == 3, 'fixed_host_and_arguments')
        run_id, raw_pid = sys.argv[1:]
        need(re.fullmatch(r'[0-9a-f]{32}', run_id) and raw_pid.isdecimal(), 'finite_original_owner')
        pid = int(raw_pid)
        need(pid > 1, 'original_pid')
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Refused('snapshot_deadline')))
        signal.setitimer(signal.ITIMER_REAL, 5)
        root = ROOT.lstat()
        need(ROOT.resolve(strict=True) == ROOT and stat.S_ISDIR(root.st_mode)
             and root.st_uid == 1000 and stat.S_IMODE(root.st_mode) == 0o700, 'original_private_root')
        rootfd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        OPENED += 1
        need(identity(os.fstat(rootfd)) == identity(root), 'held_original_private_root')
        marker_raw = read('native-ha-fixture.json', 8192, True, directory_fd=rootfd)
        marker = json.loads(marker_raw)
        need(marker.get('run_id') == run_id and marker.get('root') == str(ROOT)
             and marker.get('root_device') == root.st_dev and marker.get('root_inode') == root.st_ino
             and marker.get('production_authority') is False, 'original_fixture_marker')
        owner_raw = read('process.identity.json', 8192, True, directory_fd=rootfd)
        owner = json.loads(owner_raw)
        pid_raw = read('process.pid', 128, True, directory_fd=rootfd)
        need(pid_raw.decode().strip() == str(pid) and owner.get('pid') == pid
             and owner.get('platform') == 'Linux', 'original_published_pid')
        need(hasattr(os, 'pidfd_open'), 'pidfd_observation_required')
        pidfd = os.pidfd_open(pid, 0)
        OPENED += 1
        poll = select.poll()
        poll.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        need(not poll.poll(0), 'original_pidfd_live')
        proc = Path('/proc') / str(pid)
        before = fields(proc / 'stat')
        expected_argv = [str(ROOT / 'heptabao-server'), '--config', str(ROOT / 'server.json'),
                         '--ha-config', str(ROOT / 'ha.json')]
        need(before[0] not in ('Z', 'X') and before[19] == owner.get('start')
             and os.readlink(proc / 'exe') == owner.get('executable') == expected_argv[0]
             and owner.get('arguments') == expected_argv
             and read(proc / 'cmdline', 8192).rstrip(b'\0').split(b'\0')
                 == [value.encode() for value in expected_argv], 'same_original_native_process')
        status = read(proc / 'status', 32768).decode('ascii')
        memory = {}
        uid_observed = False
        for line in status.splitlines():
            if line.startswith('Uid:'):
                need([int(x) for x in line.split()[1:]] == [1000] * 4, 'original_uid')
                uid_observed = True
            for name in ('VmRSS', 'VmSwap', 'VmSize', 'Threads'):
                if line.startswith(name + ':'):
                    values = line.split()
                    need(values[1].isdecimal() and (name == 'Threads' or values[2:] == ['kB']),
                         'numeric_process_resource')
                    memory[name] = int(values[1])
        need(uid_observed and set(memory) == {'VmRSS', 'VmSwap', 'VmSize', 'Threads'}, 'complete_process_resource')
        tasks = os.listdir(proc / 'task')
        need(len(tasks) <= 1024 and all(name.isdecimal() for name in tasks), 'bounded_task_list')
        task_states, waits = collections.Counter(), collections.Counter()
        vanished = hidden = 0
        for task in tasks:
            task_path = proc / 'task' / task
            try:
                observed = fields(task_path / 'stat')
                need(observed[0] in 'RSDZTWtXxKWPIN', 'task_state')
                task_states[observed[0]] += 1
                try:
                    wait = read(task_path / 'wchan', 256).decode('ascii').strip()
                    waits[wait if wait in WAITS else 'hidden_or_other_kernel_wait'] += 1
                except PermissionError:
                    hidden += 1
            except FileNotFoundError:
                vanished += 1
        fd_names = os.listdir(proc / 'fd')
        need(len(fd_names) <= 4096 and all(name.isdecimal() for name in fd_names), 'bounded_process_fds')
        inodes = set()
        vanished_fds = 0
        for name in fd_names:
            try:
                target = os.readlink(proc / 'fd' / name)
                match = re.fullmatch(r'socket:\[([0-9]+)\]', target)
                if match:
                    inodes.add(match.group(1))
            except FileNotFoundError:
                vanished_fds += 1
        sockets = {str(port): {'states': {}, 'queuedTransmitBytes': 0, 'queuedReceiveBytes': 0}
                   for port in PORTS}
        for family in ('tcp', 'tcp6'):
            lines = read(Path('/proc/net') / family, 1024 * 1024).decode('ascii').splitlines()
            need(lines and 'local_address' in lines[0], 'tcp_table_header')
            for line in lines[1:]:
                values = line.split()
                need(len(values) >= 10, 'tcp_table_row')
                port = int(values[1].split(':')[1], 16)
                if port not in PORTS or values[9] not in inodes:
                    continue
                need(values[3] in STATES, 'tcp_state')
                selected = sockets[str(port)]
                name = STATES[values[3]]
                selected['states'][name] = selected['states'].get(name, 0) + 1
                tx, rx = values[4].split(':')
                selected['queuedTransmitBytes'] += int(tx, 16)
                selected['queuedReceiveBytes'] += int(rx, 16)
        after = fields(proc / 'stat')
        need(not poll.poll(0) and after[19] == before[19] and after[0] not in ('Z', 'X')
             and identity(ROOT.lstat())[:5] == identity(os.fstat(rootfd))[:5] == identity(root)[:5]
             and read('native-ha-fixture.json', 8192, True, directory_fd=rootfd) == marker_raw
             and read('process.identity.json', 8192, True, directory_fd=rootfd) == owner_raw
             and read('process.pid', 128, True, directory_fd=rootfd) == pid_raw,
             'same_original_pid_and_private_owner_after')
        report.update(ok=True, pid=pid, sameOriginalBirthBeforeAfter=True,
                      resources=memory, taskStates=dict(task_states), waitStates=dict(waits),
                      taskRowsVanished=vanished, taskWaitRowsHidden=hidden,
                      listedFdCount=len(fd_names), fdRowsVanished=vanished_fds,
                      selectedOwnedPortSockets=sockets,
                      cpuUserTicks=int(after[11]), cpuSystemTicks=int(after[12]),
                      minorFaults=int(after[7]), majorFaults=int(after[9]))
    except BaseException as error:
        report['failureClass'] = type(error).__name__
        report['failureCode'] = str(error) if isinstance(error, Refused) else 'readonly_snapshot_unavailable'
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for descriptor in (pidfd, rootfd):
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
                CLOSED += 1
            except Exception:
                report['ok'] = False
        report['fdCloseFacts'] = {'opened': OPENED, 'closed': CLOSED}
        if OPENED != CLOSED:
            report['ok'] = False
        report['elapsedSeconds'] = time.monotonic() - started
        print(json.dumps(report, sort_keys=True))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
