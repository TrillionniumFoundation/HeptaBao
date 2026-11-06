class FixedCurrentPid:
    """Finite metadata only for self and the actual label-mapped PID 32527."""
    def __init__(self):
        self.rows = []
        self.numeric_calls = 0
        self.path_calls = 0
        self.child_calls = 0
        self.self_checked = False
        self.pairs = []
        need(sys.platform == 'darwin' and ctypes.sizeof(BsdInfo) == 136
             and BsdInfo.pid.offset == 12 and BsdInfo.ppid.offset == 16
             and BsdInfo.uid.offset == 20 and BsdInfo.pgid.offset == 108
             and BsdInfo.birth_sec.offset == 120 and BsdInfo.birth_usec.offset == 128,
             'current_pid_exact_bsdinfo_abi')
        self.lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        self.lib.proc_pidinfo.argtypes = [ctypes.c_int,ctypes.c_int,ctypes.c_uint64,
                                          ctypes.c_void_p,ctypes.c_int]
        self.lib.proc_pidinfo.restype = ctypes.c_int
        self.lib.proc_pidpath.argtypes = [ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32]
        self.lib.proc_pidpath.restype = ctypes.c_int
        self.lib.proc_listchildpids.argtypes = [ctypes.c_int,ctypes.c_void_p,ctypes.c_int]
        self.lib.proc_listchildpids.restype = ctypes.c_int

    def check_time(self, until_ns):
        remaining()
        need(time.monotonic_ns() < until_ns and time.monotonic_ns() < HELPER_ADMISSION_END_NS,
             'current_pid_original_clipped_deadline')

    def call(self, kind, pid, until_ns, function, *args):
        self.check_time(until_ns)
        need(pid in (os.getpid(),EXPECTED_CURRENT_PID) and len(self.rows) < 10,
             'current_pid_fixed_call_scope')
        row = {'ordinal':len(self.rows),'kind':kind,'pid':pid,
               'attempted':False,'returned':False,'result':None,'errno':None}
        self.rows.append(row)
        with signals.critical():
            self.check_time(until_ns)
            row['attempted'] = True
            ctypes.set_errno(0)
            value = function(*args)
            number = ctypes.get_errno()
            row['returned'] = True
            row['result'] = int(value)
            row['errno'] = int(number)
        self.check_time(until_ns)
        return value,number

    def numeric(self, pid, until_ns):
        need(self.numeric_calls < 6,'current_pid_numeric_call_cap')
        self.numeric_calls += 1
        info = BsdInfo()
        count,number = self.call('bsdinfo-arg1',pid,until_ns,self.lib.proc_pidinfo,
                                 pid,3,1,ctypes.byref(info),ctypes.sizeof(info))
        need(count == 136 and number == 0 and info.pid == pid,
             'current_pid_complete_numeric_sample')
        value = {'pid':int(info.pid),'ppid':int(info.ppid),'pgid':int(info.pgid),
                 'uid':int(info.uid),'gid':int(info.gid),'birthSec':int(info.birth_sec),
                 'birthUsec':int(info.birth_usec),'status':int(info.status),
                 'exitStatusNumeric':int(info.xstatus),'flagsNumeric':int(info.flags)}
        need(value['pid'] > 1 and value['birthSec'] > 0 and 0 <= value['birthUsec'] < 1000000,
             'current_pid_numeric_shape')
        return value

    def lifetime(self, value):
        return tuple(value[key] for key in ('pid','ppid','pgid','uid','gid','birthSec','birthUsec'))

    def verify_self(self, until_ns):
        first = self.numeric(os.getpid(),until_ns)
        second = self.numeric(os.getpid(),until_ns)
        need(self.lifetime(first) == self.lifetime(second)
             and first['pid'] == os.getpid() and first['ppid'] == os.getppid()
             and first['pgid'] == os.getpgrp() and first['uid'] == os.geteuid()
             and first['gid'] == os.getegid(),'current_pid_self_numeric_crosscheck')
        self.self_checked = True

    def pair(self, ordinal, until_ns):
        need(self.self_checked and ordinal in (1,2) and len(self.pairs) == ordinal-1,
             'current_pid_pair_sequence')
        self.check_time(until_ns)
        pair = {'ordinal':ordinal,'pid':EXPECTED_CURRENT_PID,'before':None,'after':None,
                'imageMatches':None,'directChildCount':None,'sameLifetimeWithinPair':False,
                'otherPathOrChildPidsPublished':False,'qualifiedKnownPython':False}
        self.pairs.append(pair)
        first = self.numeric(EXPECTED_CURRENT_PID,until_ns)
        pair['before'] = first
        need(self.path_calls < 2,'current_pid_path_call_cap')
        self.path_calls += 1
        path_buffer = ctypes.create_string_buffer(4096)
        count,number = self.call('pidpath-known-bools',EXPECTED_CURRENT_PID,until_ns,
            self.lib.proc_pidpath,EXPECTED_CURRENT_PID,path_buffer,len(path_buffer))
        need(0 < count < len(path_buffer) and number == 0,'current_pid_complete_path')
        image = path_buffer.value
        pair['imageMatches'] = {'kernelPython':image == KERNEL_PYTHON_IMAGE.encode('ascii'),
                                'launcherPython':image == PYTHON.encode('ascii'),
                                'knownServerBinary':image == KNOWN_SERVER_BINARY.encode('ascii')}
        need(self.child_calls < 2,'current_pid_child_count_cap')
        self.child_calls += 1
        children = (ctypes.c_int * 32)()
        count,number = self.call('direct-child-count-only',EXPECTED_CURRENT_PID,until_ns,
            self.lib.proc_listchildpids,EXPECTED_CURRENT_PID,children,ctypes.sizeof(children))
        need(0 <= count < len(children) and number == 0,'current_pid_complete_child_count')
        need(all(children[i] > 1 for i in range(count)),'current_pid_child_count_shape')
        pair['directChildCount'] = int(count)
        second = self.numeric(EXPECTED_CURRENT_PID,until_ns)
        pair['after'] = second
        pair['sameLifetimeWithinPair'] = self.lifetime(first) == self.lifetime(second)
        need(pair['sameLifetimeWithinPair'],'current_pid_lifetime_changed')
        pair['qualifiedKnownPython'] = bool(first['uid'] == 501 and first['pgid'] == EXPECTED_CURRENT_PID
                                           and pair['imageMatches']['kernelPython'])
        self.check_time(until_ns)
        return pair

    def public(self):
        return {'fixedPid':EXPECTED_CURRENT_PID,'rows':self.rows,
                'numericCalls':self.numeric_calls,'pathCalls':self.path_calls,
                'directChildCountCalls':self.child_calls,'selfCrosschecked':self.self_checked,
                'pairs':self.pairs,'allAttemptedCallsReturned':all(
                    not row['attempted'] or row['returned'] for row in self.rows),
                'otherProcessArgumentsRead':False,'childPidsPublished':False,
                'childProcessesFollowed':False,'rawUnknownPathPublished':False,
                'nativeLibraryLoaderInternalFdsNotEnumerated':True,
                'bsdExitStatusIsNotLaunchdExitCode':True}

def require_current_pid_mapping(print_record):
    need(not print_record['registrationAbsent']
         and print_record['projection']['scanComplete']
         and all(print_record['projection']['fixedRegistrationFieldsMatch'].values()),
         'current_pid_exact_registration_mapping')
    facts = print_record['projection']['fieldFacts']
    need(facts['pid']['unique'] and facts['pid']['typedInteger'] == EXPECTED_CURRENT_PID
         and facts['runs']['unique'] and facts['runs']['typedInteger'] == 1
         and facts['state']['unique'] and facts['state']['knownState'] == 'running',
         'current_pid_current_running_mapping')

