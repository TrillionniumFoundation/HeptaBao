    def native_pid_once(self, reader, pid, until_ns):
        remaining()
        need(time.monotonic_ns() < until_ns, 'native_pid_absolute_query_deadline')
        need(self.native_calls < 6 and type(pid) is int and 1 < pid <= 2147483647,
             'fixed_native_pid_call_cap')
        self.native_calls += 1
        info = BsdInfo()
        try:
            ctypes.set_errno(0)
            count = reader.lib.proc_pidinfo(pid,3,1,ctypes.byref(info),ctypes.sizeof(info))
            number = ctypes.get_errno()
            remaining()
            need(time.monotonic_ns() < until_ns, 'native_pid_absolute_query_deadline')
            if count == 0 and number == errno.ESRCH:
                return {'kind':'lookup_esrch','returnedBytes':0,'errno':number,'identity':None}
            need(count == ctypes.sizeof(info) and info.pid == pid
                 and info.birth_sec > 0 and info.birth_usec < 1000000,
                 'native_pid_complete_numeric_sample')
            return {'kind':'present','returnedBytes':count,
                    'identity':(info.pid,info.ppid,info.pgid,info.uid,info.status,
                                info.birth_sec,info.birth_usec)}
        except BaseException:
            self.unknown = True
            raise

    def qualify_native_self(self, reader, until_ns):
        if self.native_self is not None:
            return
        expected_offsets = {'status':4,'pid':12,'ppid':16,'uid':20,'pgid':100,
                            'birth_sec':120,'birth_usec':128}
        need(ctypes.sizeof(BsdInfo) == 136 and all(
             getattr(BsdInfo,key).offset == value for key,value in expected_offsets.items()),
             'native_pid_exact_numeric_offsets')
        expected = (os.getpid(),os.getppid(),os.getpgrp(),os.geteuid())
        first = self.native_pid_once(reader,expected[0],until_ns)
        second = self.native_pid_once(reader,expected[0],until_ns)
        need(first['kind'] == second['kind'] == 'present'
             and first['identity'] == second['identity']
             and first['identity'][:4] == expected and expected[3] == 501,
             'native_pid_self_numeric_crosscheck')
        self.native_self = {'fixedLibrary':'/usr/lib/libproc.dylib','flavor':3,'arg':1,
            'sizeof':136,'offsetsMatched':True,'twoSelfSamples':True,
            'selfPidParentGroupUidMatched':True,'selfBirthStable':True,
            'installedKernelWholePinClaimed':False,'zombieBranchExecutedBySelfClaimed':False}

    def pid_observation(self, ordinal, ready_identity, reader):
        remaining()
        need(time.monotonic_ns() < HELPER_ADMISSION_END_NS, 'helper_cleanup_reserve')
        until_ns = min(HELPER_ADMISSION_END_NS,time.monotonic_ns()+4000000000)
        self.qualify_native_self(reader,until_ns)
        pid = ready_identity['pid']
        first = self.native_pid_once(reader,pid,until_ns)
        second = self.native_pid_once(reader,pid,until_ns)
        need(first['kind'] == second['kind'], 'native_pid_two_sample_kind_changed')
        if first['kind'] == 'lookup_esrch':
            return {'ordinal':ordinal,'originalReadyPid':pid,'kind':'lookup_esrch',
                'originalBirthPresent':None,'sampleCount':2,'returnedBytes':[0,0],
                'errno':errno.ESRCH,'zombieLookupRequested':True,
                'existenceOrDepartureAutomaticallyConcluded':False,
                'processNotOwnedOrSignalled':True}
        need(first['identity'] == second['identity'], 'diagnostic_stable_pid_birth')
        actual = first['identity']
        same_birth = actual[5:] == (ready_identity['birthSec'],ready_identity['birthUsec'])
        same_numeric_identity = actual[:4] == tuple(ready_identity[k] for k in ('pid','ppid','pgid','uid'))
        return {'ordinal':ordinal,'originalReadyPid':pid,
            'kind':'same_birth_present' if same_birth else 'reused_different_birth',
            'originalBirthPresent':same_birth,'sameNumericIdentity':same_numeric_identity,
            'sampleCount':2,'returnedBytes':[136,136],'zombieLookupRequested':True,
            'processNotOwnedOrSignalled':True}
