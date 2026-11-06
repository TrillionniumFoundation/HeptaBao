#!/usr/bin/env python3
"""One bounded public projection of this Python process; no application file bodies, children or service changes."""
import time
START_NS = time.monotonic_ns()
UNTIL_NS = START_NS + 5000000000
from contextlib import contextmanager
import ctypes, json, os, re, signal, sys
from pathlib import Path

PYTHON = "/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
PYTHON_FRAMEWORK = "/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14"
IDENTITY_KEYS = ('pid','ppid','pgid','uid','birthSec','birthUsec','executable')
OUTPUT_CAP = 8192

class Signals:
    def __init__(self):
        self.protected=0;self.pending=None
    def receive(self,signum,_frame):
        self.pending=signum
        if not self.protected:raise KeyboardInterrupt()
    def install(self):
        signal.signal(signal.SIGTERM,self.receive);signal.signal(signal.SIGINT,self.receive)
    @contextmanager
    def critical(self):
        self.protected+=1
        try:yield
        finally:self.protected-=1


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




class ProjectionRefused(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise ProjectionRefused(code)

ERROR_CODES = frozenset((
    'self_platform_and_launcher', 'self_projection_deadline', 'self_query_late',
    'self_projection_cancelled', 'self_identity_shape', 'self_identity_numbers',
    'same_self_identity_across_reads',
    'exact_darwin_process_abi', 'exact_pid_required', 'process_info_complete',
    'process_path_complete', 'absolute_process_path',
    'process_identity_changed_during_read', 'bounded_owned_child_list',
))

def fixed_error(error):
    kind = type(error).__name__
    if kind not in ('ProjectionRefused','ObservationRefused','KeyboardInterrupt',
                    'OSError','ValueError','UnicodeDecodeError','TypeError','AttributeError'):
        kind = 'other'
    code = str(error) if isinstance(error, (ProjectionRefused,ObservationRefused)) else None
    if code not in ERROR_CODES:
        code = None
    number = getattr(error, 'errno', None)
    if type(number) is not int or not 0 <= number <= 4096:
        number = None
    return {'type':kind,'code':code,'errno':number}

def public_self(value):
    need(isinstance(value,dict) and set(value) == set(IDENTITY_KEYS),
         'self_identity_shape')
    need(all(type(value[k]) is int and 0 <= value[k] < 2**63 for k in IDENTITY_KEYS[:-1])
         and isinstance(value['executable'],str), 'self_identity_numbers')
    path = value['executable']
    public_path = (len(path) <= 512 and path.isascii()
        and re.fullmatch(r'[A-Za-z0-9_./@+\-]+',path) is not None
        and path.startswith(PYTHON_FRAMEWORK + '/')
        and os.path.normpath(path) == path)
    predicates = {
        'pid_gt_1':value['pid'] > 1,
        'pgid_gt_1':value['pgid'] > 1,
        'uid_eq_501':value['uid'] == 501,
        'birth_sec_gt_0':value['birthSec'] > 0,
        'birth_usec_lt_1000000':value['birthUsec'] < 1000000,
        'executable_eq_fixed_python':path == PYTHON,
    }
    return {
        'numeric':{k:value[k] for k in IDENTITY_KEYS[:-1]},
        'publicExecutablePath':path if public_path else None,
        'pathWithinFixedPublicPythonFramework':public_path,
        'originalPredicates':predicates,
        'originalCompositePassed':all(predicates.values()),
    }

def main():
    signals = Signals()
    saved = {}
    started = 0
    returned = 0
    stage = 'entry'
    result = {
        'schema':'heptabao.public-python-self-identity.observation.r1',
        'ok':False,'observationComplete':False,'outcomeUnknown':False,
        'declaredLauncher':PYTHON,'publicPythonFramework':PYTHON_FRAMEWORK,
        'originalReaderSourceBlob':'6ca7a8debfe9d9a31d19d1237ca3e84176cc40f5',
        'originalReaderExtractBlob':'ec2182b5075246b30ef96c5b6472adeafb6654c8',
        'sameIdentityAndBirthAcrossReads':None,
        'sysExecutableEqualsFixedLauncher':False,
        'applicationDescriptorsOpened':0,'applicationChildrenCreated':0,
        'directoryCreationAttempted':False,'launchdOperationAttempted':False,
        'explicitT5PathReadAttempted':False,'applicationFileBodyReadAttempted':False,
        'sdkOrCredentialRead':False,'oldRegistrationTouched':False,
        'interpreterAndDynamicLoaderDescriptorsNotEnumerated':True,
        'originalReaderPathResolveMetadataOnly':True,
        'sharedSeconds':5,'perReadLateReturnLimitSeconds':4,'outerSeconds':60,
        'synchronousQueriesNotIndividuallyPreemptible':True,
        'kernelExecutableFileIdentityOrContentQualified':False,
        'originalR3FailurePreserved':True,
    }
    def remaining():
        need(signals.pending is None, 'self_projection_cancelled')
        need(time.monotonic_ns() < UNTIL_NS, 'self_projection_deadline')
    try:
        need(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 501
             and sys.executable == PYTHON, 'self_platform_and_launcher')
        result['sysExecutableEqualsFixedLauncher'] = True
        saved = {s:signal.getsignal(s) for s in (signal.SIGTERM,signal.SIGINT)}
        signals.install()
        remaining()
        reader = ProcessReader()
        current_pid = os.getpid()
        values = []
        for index in range(2):
            stage = 'self_first' if index == 0 else 'self_second'
            remaining()
            query_until = min(UNTIL_NS,time.monotonic_ns()+4000000000)
            with signals.critical():
                started += 1
                value = reader.read(current_pid)
                returned += 1
                values.append(value)
            need(time.monotonic_ns() < query_until, 'self_query_late')
            remaining()
            result['first' if index == 0 else 'second'] = public_self(value)
        stage = 'same_self'
        result['sameIdentityAndBirthAcrossReads'] = values[0] == values[1]
        need(result['sameIdentityAndBirthAcrossReads'], 'same_self_identity_across_reads')
        result['publicPathProjectionComplete'] = all(
            result[k]['pathWithinFixedPublicPythonFramework'] for k in ('first','second'))
        result['allOriginalPredicatesPassed'] = all(
            result[k]['originalCompositePassed'] for k in ('first','second'))
        result['observationComplete'] = True
        stage = 'complete'
    except BaseException as error:
        result['error'] = fixed_error(error)
    finally:
        restore_errors = []
        with signals.critical():
            for sig, old in saved.items():
                try:
                    signal.signal(sig,old)
                except BaseException as error:
                    restore_errors.append({'signal':int(sig),'error':fixed_error(error)})
        final_ns = time.monotonic_ns()
        result['stage'] = stage
        result['selfReadCallsStarted'] = started
        result['selfReadCallsReturned'] = returned
        result['allStartedSelfReadsReturned'] = started == returned
        result['signalRestoreErrors'] = restore_errors
        result['pendingSignalAfterRestore'] = signals.pending
        result['deadlineMetAfterClosure'] = final_ns < UNTIL_NS
        result['elapsedSeconds'] = (final_ns-START_NS)/1000000000
        result['outcomeUnknown'] = bool(started != returned or restore_errors
            or signals.pending is not None or result['sameIdentityAndBirthAcrossReads'] is False
            or not result['deadlineMetAfterClosure'])
        result['ok'] = bool(result['observationComplete'] and not result['outcomeUnknown'])
        raw = (json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                          allow_nan=False)+'\n').encode('ascii')
        if len(raw) > OUTPUT_CAP:
            raise SystemExit(1)
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
    raise SystemExit(0 if result['ok'] and time.monotonic_ns() < UNTIL_NS else 1)

if __name__ == '__main__':
    main()
