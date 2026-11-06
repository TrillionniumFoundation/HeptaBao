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


