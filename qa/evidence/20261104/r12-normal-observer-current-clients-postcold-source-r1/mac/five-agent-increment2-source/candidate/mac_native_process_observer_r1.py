#!/usr/bin/env python3
"""Read-only outer-parent custody of one Node -> launcher -> native process chain.

No credential, application-file or network reads. The response pipe's write end
is retained exclusively by the outer parent; a shared run directory is not an
authority channel. Exact Apple public libproc declarations and proc_bsdinfo ABI:
  xnu/bsd/sys/proc_info.h Git blob 718a69fcf5340f547893ed8dc85908f253c1ce81
  xnu/libsyscall/wrappers/libproc/libproc.h 602e4fe897d1fc5a7ceacc372c78f184ea242bfe
  xnu/libsyscall/wrappers/libproc/libproc.c c3e7369f886fbb7bbc8d77f8fca9ecc943bb5f4e
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import re
import select
import sys
import time


from mac_owned_unreaped_r1 import exit_observation as retained_exit_observation

class ObservationRefused(RuntimeError):
    pass


def require(value, code):
    if not value:
        raise ObservationRefused(code)


class BsdInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        'flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid',
        'ruid', 'rgid', 'svuid', 'svgid', 'reserved',
    )] + [
        ('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32),
        ('nfiles', ctypes.c_uint32), ('pgid', ctypes.c_uint32),
        ('jobc', ctypes.c_uint32), ('ttydev', ctypes.c_uint32),
        ('tty_pgid', ctypes.c_uint32), ('nice', ctypes.c_int32),
        ('birth_sec', ctypes.c_uint64), ('birth_usec', ctypes.c_uint64),
    ]


class ProcessReader:
    def __init__(self):
        require(sys.platform == 'darwin' and ctypes.sizeof(BsdInfo) == 136,
                'exact_darwin_process_abi')
        self.lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        self.lib.proc_pidinfo.argtypes = [
            ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
            ctypes.c_void_p, ctypes.c_int,
        ]
        self.lib.proc_pidinfo.restype = ctypes.c_int
        self.lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.lib.proc_pidpath.restype = ctypes.c_int
        self.lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_listchildpids.restype = ctypes.c_int

    def read(self, pid):
        require(type(pid) is int and pid > 1, 'exact_pid_required')
        info = BsdInfo()
        count = self.lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
        require(count == ctypes.sizeof(info) and info.pid == pid, 'process_info_complete')
        executable = ctypes.create_string_buffer(4096)
        length = self.lib.proc_pidpath(pid, executable, len(executable))
        require(0 < length < len(executable), 'process_path_complete')
        actual_path = executable.value.decode('utf-8', errors='strict')
        require(actual_path.startswith('/'), 'absolute_process_path')
        # A second birth read binds path lookup to the same process lifetime.
        again = BsdInfo()
        count = self.lib.proc_pidinfo(pid, 3, 0, ctypes.byref(again), ctypes.sizeof(again))
        require(count == ctypes.sizeof(again)
                and (again.pid, again.ppid, again.pgid, again.uid,
                     again.birth_sec, again.birth_usec)
                == (info.pid, info.ppid, info.pgid, info.uid,
                    info.birth_sec, info.birth_usec), 'process_identity_changed_during_read')
        return {
            'pid': pid, 'ppid': info.ppid, 'pgid': info.pgid, 'uid': info.uid,
            'birthSec': info.birth_sec, 'birthUsec': info.birth_usec,
            'executable': str(Path(actual_path).resolve()),
        }

    def children(self, verified_pid):
        # proc_listchildpids returns a PID count, not bytes. The fixed bound is
        # fail-closed; it is not a process-wide command/argument enumeration.
        buffer = (ctypes.c_int * 32)()
        count = self.lib.proc_listchildpids(verified_pid, buffer, ctypes.sizeof(buffer))
        require(0 <= count < len(buffer), 'bounded_owned_child_list')
        return [int(buffer[i]) for i in range(count) if buffer[i] > 1]


def stable_identity(first, second):
    return first == second


class OwnedNativeObserver:
    def __init__(self, expected):
        self.expected = {
            'nodeExecutable': str(Path(expected['nodeExecutable']).resolve()),
            'nativeExecutable': str(Path(expected['nativeExecutable']).resolve()),
        }
        self.reader = ProcessReader()
        self.request_read, request_write = os.pipe()
        response_read, self.response_write = os.pipe()
        self.child_fds = (request_write, response_read)
        self.child_env = {
            'HEPTABAO_NATIVE_OBSERVER_REQUEST_FD': str(request_write),
            'HEPTABAO_NATIVE_OBSERVER_RESPONSE_FD': str(response_read),
        }
        os.set_blocking(self.request_read, False)
        os.set_blocking(self.response_write, False)
        self.buffer = bytearray()
        self.handled = False
        self.rejected = False
        self.child_ends_closed = False
        self.report = {
            'required': True, 'verified': False,
            'ackAuthority': 'outer_parent_only_anonymous_pipe_write_end',
            'applicationFilesRead': False, 'networkUsed': False,
            'otherProcessArgumentsRead': False, 'requests': 0,
        }

    def parent_after_spawn(self, proc):
        for fd in self.child_fds:
            os.close(fd)
        self.child_ends_closed = True
        self.proc = proc
        self.outer_pid = os.getpid()

    def verify_chain(self, request, deadline):
        require(set(request) == {'schema', 'nonce', 'nodePid', 'launcherPid'},
                'observer_request_shape')
        require(request['schema'] == 'heptabao.owned-native-request.v1'
                and isinstance(request['nonce'], str)
                and re.fullmatch(r'[0-9a-f]{64}', request['nonce']) is not None,
                'observer_request_nonce')
        require(type(request['nodePid']) is int and request['nodePid'] == self.proc.pid
                and type(request['launcherPid']) is int
                and request['launcherPid'] > 1, 'observer_owned_request_pids')
        node_pid, launcher_pid = self.proc.pid, request['launcherPid']
        node = self.reader.read(node_pid)
        require(retained_exit_observation(self.proc) is None and node['ppid'] == self.outer_pid
                and node['pgid'] == node_pid and node['uid'] == os.geteuid()
                and node['executable'] == self.expected['nodeExecutable'],
                'owned_node_birth_parent_group_executable')
        pinned_launcher = None
        while time.monotonic() < deadline:
            require(retained_exit_observation(self.proc) is None and stable_identity(node, self.reader.read(node_pid)),
                    'owned_node_lifetime_changed')
            launcher = self.reader.read(launcher_pid)
            require(launcher['ppid'] == node_pid and launcher['pgid'] == node_pid
                    and launcher['uid'] == node['uid']
                    and (launcher['birthSec'], launcher['birthUsec'])
                    >= (node['birthSec'], node['birthUsec']),
                    'launcher_real_parent_group_birth')
            # /usr/bin/env may briefly precede the pinned shebang Node runtime.
            # No ACK is issued until the exact managed Node launcher is live.
            if launcher['executable'] != self.expected['nodeExecutable']:
                time.sleep(0.025)
                continue
            if pinned_launcher is None:
                pinned_launcher = launcher
            require(stable_identity(pinned_launcher, launcher), 'launcher_lifetime_changed')
            native_candidates = []
            for pid in self.reader.children(launcher_pid):
                try:
                    child = self.reader.read(pid)
                except ObservationRefused:
                    continue
                if child['executable'] == self.expected['nativeExecutable']:
                    native_candidates.append(child)
            require(len(native_candidates) <= 1, 'single_exact_native_child')
            if not native_candidates:
                time.sleep(0.025)
                continue
            native = native_candidates[0]
            require(native['ppid'] == launcher_pid and native['pgid'] == node_pid
                    and native['uid'] == node['uid']
                    and (native['birthSec'], native['birthUsec'])
                    >= (launcher['birthSec'], launcher['birthUsec']),
                    'native_real_parent_group_birth')
            first = {'node': node, 'launcher': launcher, 'native': native}
            time.sleep(0.02)
            second = {key: self.reader.read(value['pid']) for key, value in first.items()}
            require(retained_exit_observation(self.proc) is None and first == second,
                    'entire_chain_birth_and_executable_recheck')
            require(time.monotonic() < deadline, 'observer_deadline_after_recheck')
            return first
        raise ObservationRefused('owned_native_chain_observation_deadline')

    def poll(self, outer_deadline):
        if self.handled:
            return
        require(time.monotonic() < outer_deadline, 'parent_deadline_before_observation')
        ready, _, _ = select.select([self.request_read], [], [], 0)
        if not ready:
            return
        part = os.read(self.request_read, 8193)
        if not part:
            return
        self.buffer.extend(part)
        require(len(self.buffer) <= 8192, 'bounded_observer_request')
        if b'\n' not in self.buffer:
            return
        self.handled = True
        self.report['requests'] = 1
        nonce = None
        observation_deadline = min(time.monotonic() + 3, outer_deadline)
        try:
            line, remaining = self.buffer.split(b'\n', 1)
            require(not remaining, 'single_observer_request')
            request = json.loads(line.decode('utf-8'))
            nonce = request.get('nonce') if isinstance(request, dict) else None
            chain = self.verify_chain(request, observation_deadline)
            require(time.monotonic() < observation_deadline, 'observer_deadline_before_success_ack')
            ack = {'schema': 'heptabao.owned-native-ack.v1',
                   'nonce': nonce, 'verified': True, 'identities': chain}
        except Exception as error:
            self.rejected = True
            safe_error = str(error) if isinstance(error, ObservationRefused) else type(error).__name__
            self.report['error'] = safe_error
            ack = {'schema': 'heptabao.owned-native-ack.v1',
                   'nonce': nonce, 'verified': False, 'error': safe_error}
        data = (json.dumps(ack, separators=(',', ':')) + '\n').encode()
        require(len(data) <= 4096, 'bounded_atomic_observer_ack')
        if ack['verified']:
            require(time.monotonic() < observation_deadline, 'observer_deadline_at_success_ack')
        count = os.write(self.response_write, data)
        require(count == len(data), 'complete_observer_ack')
        if ack['verified']:
            self.report.update(verified=True, identities=chain,
                               birthMicrosecondsBound=True,
                               beforeFirstNativeRpc=True,
                               nativeObservationBudgetSeconds=3,
                               parentAbsoluteDeadlinePreserved=True)
        os.close(self.response_write)
        self.response_write = None

    def close(self):
        if not self.child_ends_closed:
            for fd in self.child_fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
        for name in ('request_read', 'response_write'):
            fd = getattr(self, name, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, name, None)
