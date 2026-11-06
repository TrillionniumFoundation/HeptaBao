    def pid_observation(self, ordinal, ready_identity, reader):
        pid = ready_identity['pid']
        row,out,err = self.call('readonly-ready-pid-%d' % ordinal,
            ['/bin/ps','-p',str(pid),'-o','pid=,ppid=,pgid=,uid=,stat='],
            seconds=4.0,maximum=4096)
        need(not err, 'exact_pid_projection_stderr_empty')
        if row['exitCode'] == 1 and not out.strip():
            return {'ordinal':ordinal,'originalReadyPid':pid,'kind':'absent',
                    'originalBirthPresent':False,'processNotOwnedOrSignalled':True}
        need(row['exitCode'] == 0, 'known_pid_projection')
        lines = out.decode('ascii','strict').splitlines()
        need(len(lines) == 1, 'one_observed_pid_row')
        fields = lines[0].split()
        need(len(fields) == 5 and all(re.fullmatch(r'[0-9]{1,10}',v) for v in fields[:4])
             and int(fields[0]) == pid and re.fullmatch(r'[A-Za-z+<>\-]{1,16}',fields[4]),
             'numeric_observed_pid_projection')
        snapshots = []
        for _ in range(2):
            remaining()
            info = BsdInfo()
            n = reader.lib.proc_pidinfo(pid,3,0,ctypes.byref(info),ctypes.sizeof(info))
            need(n == ctypes.sizeof(info) and info.pid == pid
                 and info.birth_sec > 0 and info.birth_usec < 1000000, 'complete_reuse_birth')
            snapshots.append((info.pid,info.ppid,info.pgid,info.uid,info.birth_sec,info.birth_usec))
            remaining()
        need(snapshots[0] == snapshots[1], 'diagnostic_stable_pid_birth')
        actual = snapshots[0]
        same_birth = actual[4:] == (ready_identity['birthSec'],ready_identity['birthUsec'])
        same_numeric_identity = actual[:4] == tuple(ready_identity[k] for k in ('pid','ppid','pgid','uid'))
        return {'ordinal':ordinal,'originalReadyPid':pid,
                'kind':'same_birth_present' if same_birth else 'reused_different_birth',
                'originalBirthPresent':same_birth,
                'sameNumericIdentity':same_numeric_identity,
                'processNotOwnedOrSignalled':True}
