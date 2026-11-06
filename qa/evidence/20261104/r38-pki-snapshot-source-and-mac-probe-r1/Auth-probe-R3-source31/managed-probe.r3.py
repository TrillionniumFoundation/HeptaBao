#!/usr/bin/env python3
"""Independent public launchd context probe; no SDK, credential or product execution."""
from contextlib import contextmanager
import base64, ctypes, errno, hashlib, json, os, plistlib, re, signal, stat, sys, time, types
from pathlib import Path

PYTHON = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
PYTHON_SHA = 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
PYTHON_ID = ('16777233','587518380','501','80','33261','1','34640','1793798038915516382','1793798038915695047')
HOME_PARENT = Path('/Users/qianqi')
HOME = HOME_PARENT / 'heptabao-launchd-home-t5-context-20261106-r1'
T5_PARENT = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
WORK = T5_PARENT / 'launchd-home-t5-context-20261106-r1'
LABEL = 'org.heptabao.qa.home-t5-context-20261106-r1'
TARGET = 'gui/501/' + LABEL
SENTINEL = b'heptabao-public-home-t5-context-r1\n'
CHILD = HOME / 'probe.public.py'
PLAN = HOME / 'plan.public.json'
PLIST = HOME / 'probe.plist'
STDOUT = HOME / 'probe.stdout.public'
STDERR = HOME / 'probe.stderr.public'
READY = HOME / 'ready.public.json'
READY_MARK = HOME / 'ready.complete'
ADMISSION = HOME / 'admission.public.json'
ADMISSION_MARK = HOME / 'admission.complete'
PUBLIC_SENTINEL = WORK / 'sentinel.public.txt'
IDENTITY_KEYS = ('pid','ppid','pgid','uid','birthSec','birthUsec','executable')
PYTHON_PATHS = tuple(Path(p) for p in ["/opt","/opt/homebrew","/opt/homebrew/Cellar","/opt/homebrew/Cellar/python@3.14","/opt/homebrew/Cellar/python@3.14/3.14.3_1","/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks","/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework","/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions","/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14","/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin"])
DIRECTORY_OBJECT_PINS = {"/":["16777233","2","0","0","16877"],"/opt":["16777233","18335","0","0","16877"],"/Volumes":["16777233","18336","0","0","16877"],"/opt/homebrew":["16777233","10827966","501","80","16877"],"/Volumes/T5":["16777244","2","0","0","16893"],"/opt/homebrew/Cellar":["16777233","10827980","501","80","16893"],"/Volumes/T5/hepta-vnext-recovery-20261013":["16777244","64176096","501","20","16832"],"/opt/homebrew/Cellar/python@3.14":["16777233","13738376","501","80","16877"],"/opt/homebrew/Cellar/python@3.14/3.14.3_1":["16777233","13278341","501","80","16877"],"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks":["16777233","13278344","501","80","16877"],"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework":["16777233","13278345","501","80","16877"],"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions":["16777233","13278349","501","80","16877"],"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14":["16777233","13278350","501","80","16877"],"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin":["16777233","13278368","501","80","16877"]}
ANCHOR_FULL9 = {"/":["16777233","2","0","0","16877","22","704","1786589515000000000","1786589515000000000"],"/Volumes":["16777233","18336","0","0","16877","5","160","1793100597756515591","1793100597756515591"],"/Volumes/T5":["16777244","2","0","0","16893","12","384","1793152973144260495","1793152973144260495"]}
PUBLIC_ERROR_TYPES = tuple(["ProbeRefused","VolumeRefused","CommandRefused","Refusal","ObservationRefused","PermissionError","FileNotFoundError","FileExistsError","NotADirectoryError","IsADirectoryError","OSError","TimeoutError","KeyboardInterrupt","UnicodeDecodeError","JSONDecodeError","ValueError","TypeError","KeyError","OtherException"])
PUBLIC_ERROR_CODES = frozenset(["absence_exact_enoent","absolute_process_path","actual_reap_matches_retained_exit","actual_t5_uuid_mount","all_helper_returned_byte_cap","already_reaped_no_group_signal","bounded_actual_diskutil_bytes","bounded_atomic_observer_ack","bounded_capture_sink","bounded_observer_request","bounded_owned_child_list","bounded_owned_read","bounded_owned_write","capture_sink_custody","capture_sink_stable","captured_anchor_fd_identity","captured_anchor_named_identity","captured_volume_device","child_absolute_deadline","child_actual_io_counts","child_actual_sentinel_success","child_actual_t5_working_directory","child_admission_marker_stable","child_admission_not_observed","child_already_reaped_no_signal","child_cancelled","child_created_file_completed","child_each_fd_closed","child_each_fd_fixed_path","child_exact_arguments","child_exact_io_caps","child_exact_public_plan","child_exact_public_sentinel","child_exact_same_birth_admission","child_exit_identity_changed","child_fd_row_count","child_final_same_birth_no_children","child_fixed_creations_only","child_fixed_error_projection","child_generation_shape","child_initial_no_children","child_io_no_directory_creation","child_io_schema","child_launchd_home_working_directory","child_open_ledger_complete","child_open_ledger_schema","child_parent_absolute_deadline","child_platform_uid","child_public_plan_fields","child_public_plan_scope","child_reported_known_closure","child_same_home_object","child_same_python_whole","child_source_payload","child_t5_same_observed_device","child_terminal_boolean_types","child_terminal_closed_schema","child_terminal_fixed_stage","child_terminal_same_instance","child_whole_source","cleanup_exact_inactive_registration","cleanup_first_actual_same_birth","cleanup_registration_still_present","cleanup_second_actual_same_birth","command_cancelled","command_output_bound","complete_observer_ack","complete_reuse_birth","controller_actual_regular_python_whole","controller_cancelled","controller_exact_platform_python","created_leaf_full9","created_public_sentinel_exact","direct_child_reaping_policy_changed","direct_helper_outcome_unknown","directory_open_full9","embedded_original_helper_whole","empty_complete_marker","entire_chain_birth_and_executable_recheck","exact_darwin_process_abi","exact_fresh_probe_registration","exact_pid_projection_stderr_empty","exact_pid_required","exact_public_anchor_paths","exact_ready_keys","expected_leaf_full9_before","explicit_argv","fd_ledger_cap","file_close_failed","finite_helper_call_and_bytes","finite_print_observations","fixed_command_output_bound","fixed_create_only_write","fixed_directory_full9","fixed_directory_only","fixed_known_probe_state","fixed_leaf_mode","fixed_marker_only","fixed_owned_t5_scope","fixed_read_only_leaf","fixed_regular_leaf_shape","fresh_label_initially_absent","fresh_registration_absent_after_bootout","fresh_root_already_present","fresh_root_exact_mode","held_directory_full9_stable","held_directory_not_closed","held_directory_same_object","held_directory_type","held_t5_anchor_changed","held_t5_device_changed","helper_cleanup_reserve","inactive_observation_count_exhausted","known_actual_t5_uuid_command","known_empty_launchd_mutation","known_inactive_probe_exit","known_pid_projection","known_probe_print","label_still_absent_before_second_pid_check","launchd_exit_matches_public_terminal","launchd_not_controller_child","launcher_lifetime_changed","launcher_real_parent_group_birth","marker_absence_enoent","metadata_cap","native_real_parent_group_birth","new_leaf_empty","new_observed_directory_owner_mode","new_owned_directory","new_owned_file_inode","new_owned_file_name","new_owned_write_progress","new_work_on_actual_t5","no_cleanup_dispatch_after_helper_unknown","no_existing_helper_module","no_unexplained_label_disappearance","no_unexplained_registration_disappearance","numeric_observed_pid_projection","observed_directory_object","observed_identity_before_pid_check","observed_ready_before_admission","observer_child_end_close_unconfirmed","observer_deadline_after_recheck","observer_deadline_at_success_ack","observer_deadline_before_success_ack","observer_fd_signal_guard_required","observer_owned_request_pids","observer_request_nonce","observer_request_shape","observer_response_end_close_unconfirmed","once_fresh_launchd_operation","once_fresh_root","one_observed_pid_row","one_public_managed_terminal_empty_stderr","original_birth_still_present_or_reuse_unproven","original_command_deadline_exhausted","original_stop_deadline_expired","owned_child_identity_changed_no_signal","owned_child_identity_missing","owned_child_scope_mismatch","owned_component_shape","owned_directory_uid","owned_exit_not_retained","owned_file_custody","owned_file_stable_read","owned_group_uid_changed_no_signal","owned_live_api_failed_without_retained_exit","owned_live_session_changed_no_signal","owned_live_session_mismatch","owned_native_chain_observation_deadline","owned_node_birth_parent_group_executable","owned_node_lifetime_changed","owned_parent_changed","owned_parent_close_failed","owned_parent_custody","owned_parent_fd_identity","owned_zombie_identity_changed_no_signal","parent_deadline_before_observation","process_identity_changed_during_read","process_identity_fixed_python","process_identity_numbers","process_identity_shape","process_info_complete","process_path_complete","process_projection_ambiguous","process_projection_bound","process_projection_deadline_expired","process_projection_malformed","process_projection_unavailable","public_anchor_identity_shape","public_anchor_input_bound","public_anchor_schema","public_anchor_whole_sha","read_call_cap","read_complete_full9","read_content_cap","read_eof_byte_budget","read_leaf_cap","read_open_full9","read_size_cap","read_total_cap","ready_actual_same_birth","ready_exact_public_bindings","ready_inside_child_deadline","ready_marker_stable","ready_observation_count_exhausted","ready_same_launchd_pid","registered_public_input_unchanged","safe_command_label","same_label_pid_observation_until_exit","second_same_birth_before_admission","shared_45_second_deadline","single_exact_native_child","single_observer_request","source_ready_before_child_window","two_fresh_roots_only","unknown_observer_fd_no_close","unobserved_active_managed_probe_no_bootout","uuid_before_owned_private_io","volume_guard_not_closed","wnowait_required_no_child_started","write_call_cap","write_progress","write_total_cap"])

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



class ProbeRefused(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise ProbeRefused(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')

def identity(info):
    return tuple(str(x) for x in (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
        info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns))

def error_projection(error):
    allowed = PUBLIC_ERROR_TYPES
    name = type(error).__name__
    code = str(error) if name in ('ProbeRefused','VolumeRefused','CommandRefused',
                                 'Refusal','ObservationRefused') else None
    if code not in PUBLIC_ERROR_CODES:
        code = None
    number = getattr(error, 'errno', None)
    return {'type': name if name in allowed else 'OtherException',
            'code': code, 'errno': number if type(number) is int and 0 <= number <= 4096 else None}

def validate_process(value):
    need(isinstance(value, dict) and set(value) == set(IDENTITY_KEYS), 'process_identity_shape')
    need(all(type(value[k]) is int and 0 <= value[k] < 2**63 for k in IDENTITY_KEYS[:-1]),
         'process_identity_numbers')
    need(value['pid'] > 1 and value['pgid'] > 1 and value['uid'] == 501
         and value['birthSec'] > 0 and value['birthUsec'] < 1000000
         and value['executable'] == PYTHON, 'process_identity_fixed_python')
    return dict(value)

class FixedIO:
    """Only declared paths; all returned FDs registered before cancellation resumes."""
    def __init__(self, signals, remaining, *, read_cap, write_cap):
        self.signals = signals
        self.remaining = remaining
        self.rows = []
        self.open_ledger = {'attempts':0, 'knownNoReturnErrors':0, 'registered':0,
                            'pending':0, 'registrationUnknown':False}
        self.dirs = {}
        self.close_errors = []
        self.counts = {'metadata':0, 'readCalls':0, 'readBytes':0, 'writeCalls':0, 'writeBytes':0}
        self.read_cap = read_cap
        self.write_cap = write_cap
        self.created_directories = []
        self.directory_attempts = []
        self.max_rows = 64
        self.max_metadata = 4096
        self.max_reads = 256
        self.max_writes = 64
        self.allowed_dirs = {Path('/'), Path('/Users'), HOME_PARENT, HOME,
            Path('/Volumes'), Path('/Volumes/T5'), T5_PARENT, WORK}
        self.allowed_dirs.update(PYTHON_PATHS)
        self.allowed_files = {CHILD:65536, PLAN:8192, PLIST:16384, STDOUT:32768,
            STDERR:4096, READY:8192, READY_MARK:0, ADMISSION:8192,
            ADMISSION_MARK:0, PUBLIC_SENTINEL:len(SENTINEL), Path(PYTHON):34640}
        self.writable = {CHILD, PLAN, PLIST, STDOUT, STDERR, READY, READY_MARK,
                         ADMISSION, ADMISSION_MARK, PUBLIC_SENTINEL}

    def meta(self, fn, *args, **kwargs):
        self.remaining()
        need(self.counts['metadata'] < self.max_metadata, 'metadata_cap')
        self.counts['metadata'] += 1
        value = fn(*args, **kwargs)
        self.remaining()
        return value

    def open_fd(self, path, flags, mode=None, *, parent=None, role='file'):
        need(len(self.rows) < self.max_rows and self.open_ledger['attempts'] < self.max_rows,
             'fd_ledger_cap')
        with self.signals.critical():
            self.remaining()
            ledger = self.open_ledger
            ledger['attempts'] += 1
            ledger['pending'] += 1
            try:
                fd = os.open(str(path) if parent is None else path.name, flags,
                             *(() if mode is None else (mode,)),
                             **({} if parent is None else {'dir_fd':parent['fd']}))
            except OSError:
                # This handler covers the syscall expression only: no FD was returned.
                ledger['knownNoReturnErrors'] += 1
                ledger['pending'] -= 1
                raise
            try:
                row = {'fd':fd, 'path':str(path), 'role':role,
                       'created':bool(flags & os.O_CREAT), 'writeComplete':False,
                       'closeAttempted':False, 'closed':False}
                self.rows.append(row)
                ledger['registered'] += 1
                ledger['pending'] -= 1
            except BaseException:
                # Even a subsequently closed row cannot erase this incomplete transfer.
                # Do not guess a descriptor, blind-close, or retry registration.
                ledger['registrationUnknown'] = True
                raise
        return row

    def close_one(self, row):
        if row['closeAttempted']:
            return row['closed']
        with self.signals.critical():
            row['closeAttempted'] = True
            try:
                os.close(row['fd'])
                row['closed'] = True
            except BaseException as error:
                row['closeError'] = error_projection(error)
                self.close_errors.append(row['closeError'])
        return row['closed']

    def open_dir(self, path, *, full9=None):
        path = Path(path)
        need(path in self.allowed_dirs, 'fixed_directory_only')
        if path in self.dirs:
            row = self.dirs[path]
            self.check_dir(row)
        else:
            parent = None if path == Path('/') else self.open_dir(path.parent)
            before = self.meta(os.lstat, '/') if parent is None else self.meta(
                os.stat, path.name, dir_fd=parent['fd'], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode), 'held_directory_type')
            if str(path) in DIRECTORY_OBJECT_PINS:
                need(identity(before)[:5] == tuple(DIRECTORY_OBJECT_PINS[str(path)]),
                     'observed_directory_object')
            else:
                need(before.st_uid in (0,501) and stat.S_IMODE(before.st_mode) & 0o022 == 0,
                     'new_observed_directory_owner_mode')
            if path in (HOME_PARENT, HOME, T5_PARENT, WORK):
                need(before.st_uid == 501, 'owned_directory_uid')
            row = self.open_fd(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                               parent=parent, role='directory')
            row['parent'] = parent
            row['initial'] = identity(before)
            self.dirs[path] = row
            after = self.meta(os.fstat, row['fd'])
            named = self.meta(os.lstat, '/') if parent is None else self.meta(
                os.stat, path.name, dir_fd=parent['fd'], follow_symlinks=False)
            need(identity(before) == identity(after) == identity(named), 'directory_open_full9')
        if str(path) in ANCHOR_FULL9:
            full9 = ANCHOR_FULL9[str(path)]
        if full9 is not None:
            need(len(full9) == 9 and tuple(full9) == identity(self.meta(os.fstat, row['fd'])),
                 'fixed_directory_full9')
            row['fullFence'] = tuple(full9)
            self.check_dir(row)
        return row

    def check_dir(self, row):
        need(not row['closed'], 'held_directory_not_closed')
        path = Path(row['path'])
        parent = row['parent']
        named = self.meta(os.lstat, '/') if parent is None else self.meta(
            os.stat, path.name, dir_fd=parent['fd'], follow_symlinks=False)
        held = self.meta(os.fstat, row['fd'])
        need(identity(named)[:5] == identity(held)[:5] == row['initial'][:5],
             'held_directory_same_object')
        if 'fullFence' in row:
            need(identity(named) == identity(held) == row['fullFence'], 'held_directory_full9_stable')

    def check_all(self):
        for row in self.dirs.values():
            self.check_dir(row)

    def absent(self, path):
        path = Path(path)
        need(path in (HOME, WORK), 'two_fresh_roots_only')
        parent = self.open_dir(path.parent)
        self.check_dir(parent)
        try:
            self.meta(os.stat, path.name, dir_fd=parent['fd'], follow_symlinks=False)
        except FileNotFoundError as error:
            need(error.errno == errno.ENOENT, 'absence_exact_enoent')
            return
        raise ProbeRefused('fresh_root_already_present')

    def mkdir(self, path):
        path = Path(path)
        need(path in (HOME, WORK) and path not in self.directory_attempts, 'once_fresh_root')
        self.absent(path)
        self.check_all()
        parent = self.open_dir(path.parent)
        with self.signals.critical():
            self.remaining()
            self.directory_attempts.append(path)
            os.mkdir(path.name, 0o700, dir_fd=parent['fd'])
            self.created_directories.append(path)
        os.fsync(parent['fd'])
        row = self.open_dir(path)
        need(stat.S_IMODE(int(row['initial'][4])) == 0o700, 'fresh_root_exact_mode')
        return row

    def present_marker(self, path):
        need(path in (READY_MARK, ADMISSION_MARK), 'fixed_marker_only')
        parent = self.open_dir(HOME)
        self.check_dir(parent)
        try:
            before = self.meta(os.stat, path.name, dir_fd=parent['fd'], follow_symlinks=False)
        except FileNotFoundError as error:
            need(error.errno == errno.ENOENT, 'marker_absence_enoent')
            return None
        self.file_shape(before, path)
        need(before.st_size == 0, 'empty_complete_marker')
        return identity(before)

    def file_shape(self, info, path):
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_nlink == 1
             and 0 <= info.st_size <= self.allowed_files[path], 'fixed_regular_leaf_shape')
        expected_mode = 0o755 if path == Path(PYTHON) else 0o600
        need(stat.S_IMODE(info.st_mode) == expected_mode, 'fixed_leaf_mode')

    def write(self, path, raw):
        path = Path(path)
        need(path in self.writable and isinstance(raw, bytes)
             and len(raw) <= self.allowed_files[path], 'fixed_create_only_write')
        need(self.counts['writeBytes'] + len(raw) <= self.write_cap, 'write_total_cap')
        parent = self.open_dir(path.parent)
        self.check_all()
        row = self.open_fd(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                           0o600, parent=parent)
        try:
            first = self.meta(os.fstat, row['fd'])
            self.file_shape(first, path)
            need(first.st_size == 0, 'new_leaf_empty')
            offset = 0
            while offset < len(raw):
                self.remaining()
                need(self.counts['writeCalls'] < self.max_writes, 'write_call_cap')
                self.counts['writeCalls'] += 1
                n = os.write(row['fd'], raw[offset:offset+65536])
                need(n > 0, 'write_progress')
                self.counts['writeBytes'] += n
                offset += n
            os.fsync(row['fd'])
            os.fsync(parent['fd'])
            last = self.meta(os.fstat, row['fd'])
            named = self.meta(os.stat, path.name, dir_fd=parent['fd'], follow_symlinks=False)
            need(identity(last) == identity(named) and last.st_size == len(raw)
                 and identity(first)[:5] == identity(last)[:5], 'created_leaf_full9')
            self.check_dir(parent)
            row['writeComplete'] = True
            return {'path':str(path), 'identity':list(identity(last)), 'bytes':len(raw), 'sha256':sha(raw)}
        finally:
            need(self.close_one(row), 'file_close_failed')

    def read(self, path, *, expected=None, maximum=None):
        path = Path(path)
        need(path in self.allowed_files, 'fixed_read_only_leaf')
        maximum = self.allowed_files[path] if maximum is None else maximum
        need(type(maximum) is int and 0 <= maximum <= self.allowed_files[path], 'read_leaf_cap')
        parent = self.open_dir(path.parent)
        self.check_dir(parent)
        before = self.meta(os.stat, path.name, dir_fd=parent['fd'], follow_symlinks=False)
        self.file_shape(before, path)
        need(before.st_size <= maximum, 'read_size_cap')
        if expected is not None:
            need(identity(before) == tuple(expected), 'expected_leaf_full9_before')
        row = self.open_fd(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, parent=parent)
        try:
            need(identity(self.meta(os.fstat, row['fd'])) == identity(before), 'read_open_full9')
            raw = bytearray()
            while True:
                self.remaining()
                need(self.counts['readCalls'] < self.max_reads, 'read_call_cap')
                left = self.read_cap - self.counts['readBytes']
                need(left > 0, 'read_total_cap')
                want = min(65536, maximum+1-len(raw), left)
                need(want > 0, 'read_eof_byte_budget')
                self.counts['readCalls'] += 1
                block = os.read(row['fd'], want)
                self.counts['readBytes'] += len(block)
                if not block:
                    break
                raw.extend(block)
                need(len(raw) <= maximum, 'read_content_cap')
            after = self.meta(os.fstat, row['fd'])
            named = self.meta(os.stat, path.name, dir_fd=parent['fd'], follow_symlinks=False)
            need(identity(before) == identity(after) == identity(named)
                 and len(raw) == before.st_size, 'read_complete_full9')
            self.check_dir(parent)
            return bytes(raw), list(identity(after))
        finally:
            need(self.close_one(row), 'file_close_failed')

    def close(self):
        with self.signals.critical():
            for row in reversed(self.rows):
                self.close_one(row)

    def public(self):
        ledger = self.open_ledger
        accounted = (ledger['attempts'] == ledger['knownNoReturnErrors'] + ledger['registered']
            and ledger['registered'] == len(self.rows) and ledger['pending'] == 0
            and ledger['registrationUnknown'] is False)
        return {'fdRows':[{'ordinal':i,'path':r['path'],'role':r['role'],
            'closeAttempted':r['closeAttempted'],'closed':r['closed'],
            'closeError':r.get('closeError'),'created':r['created'],
            'writeComplete':r['writeComplete']} for i,r in enumerate(self.rows)],
            'allClosed':accounted and all(r['closed'] for r in self.rows) and not self.close_errors,
            'openLedger':dict(ledger),
            'counts':dict(self.counts), 'caps':{'fdRows':self.max_rows,
            'metadata':self.max_metadata,'readCalls':self.max_reads,'writeCalls':self.max_writes,
            'readBytes':self.read_cap,'writeBytes':self.write_cap},
            'createdDirectories':[str(p) for p in self.created_directories],
            'directoryAttempts':[str(p) for p in self.directory_attempts],
            'interpreterAndDynamicLoaderInternalFdsNotEnumerated':True}

def restore_handlers(saved):
    failures = []
    for sig, old in saved.items():
        try:
            signal.signal(sig, old)
        except BaseException as error:
            failures.append(error_projection(error))
    return failures

def child_main():
    signals = Signals()
    saved = {}
    io = None
    now_ns = time.monotonic_ns()
    hard_until_ns = now_ns + 30000000000
    stage = 'entry'
    outcome = {'schema':'heptabao.public-launchd-home-t5-probe.child.r1',
        'ok':False, 'stage':stage, 'identity':None, 'readyPublished':False,
        'sameBirthAdmission':False, 'enteredT5':False, 'sentinelMatched':False,
        'explicitApplicationChildrenCreated':0, 'sdkOrCredentialRead':False,
        'launchdOwnsThisProcess':True, 'controllerDirectChild':False,
        'parentReapedThisProcess':False, 'newFixedPathsOnly':True}
    def remaining():
        need(signals.pending is None, 'child_cancelled')
        left = (hard_until_ns-time.monotonic_ns())/1000000000
        need(left > 0, 'child_absolute_deadline')
        return left
    try:
        saved = {s:signal.getsignal(s) for s in (signal.SIGTERM,signal.SIGINT)}
        signals.install()
        need(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 501,
             'child_platform_uid')
        need(sys.executable == PYTHON and sys.argv[1:4] == ['--plan',str(PLAN),'--plan-sha256']
             and len(sys.argv) == 5 and re.fullmatch(r'[0-9a-f]{64}',sys.argv[4]),
             'child_exact_arguments')
        io = FixedIO(signals, remaining, read_cap=131072, write_cap=16384)
        stage = 'home_plan'
        home = io.open_dir(HOME)
        need(os.getcwd() == str(HOME), 'child_launchd_home_working_directory')
        raw, _ = io.read(PLAN)
        need(sha(raw) == sys.argv[4], 'child_exact_public_plan')
        plan = json.loads(raw)
        need(set(plan) == {'schema','label','home','work','sourceSha256','homeObject',
            'workFull9','sentinelFull9','sentinelSha256','childUntilNs','controllerUntilNs',
            'controllerIdentity','generation'}, 'child_public_plan_fields')
        need(plan['schema'] == 'heptabao.public-launchd-home-t5-plan.r1'
             and plan['label'] == LABEL and plan['home'] == str(HOME)
             and plan['work'] == str(WORK) and type(plan['childUntilNs']) is int
             and type(plan['controllerUntilNs']) is int
             and plan['controllerUntilNs']-plan['childUntilNs'] == 20000000000,
             'child_public_plan_scope')
        need(time.monotonic_ns() < plan['childUntilNs'] <= hard_until_ns,
             'child_parent_absolute_deadline')
        hard_until_ns = plan['childUntilNs']
        need(home['initial'][:5] == tuple(plan['homeObject']), 'child_same_home_object')
        need(isinstance(plan['generation'],str) and re.fullmatch(r'[0-9a-f]{64}',plan['generation']),
             'child_generation_shape')
        source, _ = io.read(CHILD)
        need(re.fullmatch(r'[0-9a-f]{64}',plan['sourceSha256'])
             and sha(source) == plan['sourceSha256'], 'child_whole_source')
        python, _ = io.read(Path(PYTHON), expected=PYTHON_ID)
        need(sha(python) == PYTHON_SHA, 'child_same_python_whole')
        stage = 'home_identity'
        reader = ProcessReader()
        actual = validate_process(reader.read(os.getpid()))
        controller = validate_process(plan['controllerIdentity'])
        need(actual['pid'] != controller['pid'] and actual['ppid'] != controller['pid'],
             'launchd_not_controller_child')
        need(reader.children(actual['pid']) == [], 'child_initial_no_children')
        outcome['identity'] = actual
        ready = {'schema':'heptabao.public-launchd-home-t5-ready.r1','generation':plan['generation'],
            'planSha256':sha(raw),'sourceSha256':plan['sourceSha256'],'identity':actual,
            'homeObject':list(home['initial'][:5]),'initialChildren':[],
            't5AccessAttempted':False}
        io.write(READY, encoded(ready))
        io.write(READY_MARK, b'')
        outcome['readyPublished'] = True
        stage = 'home_admission'
        marker = None
        for _ in range(120):
            remaining()
            marker = io.present_marker(ADMISSION_MARK)
            if marker is not None:
                break
            time.sleep(min(0.1,remaining()))
        need(marker is not None, 'child_admission_not_observed')
        admitted_raw, _ = io.read(ADMISSION)
        need(io.present_marker(ADMISSION_MARK) == marker, 'child_admission_marker_stable')
        admitted = json.loads(admitted_raw)
        expected = {'schema':'heptabao.public-launchd-home-t5-admission.r1',
            'generation':plan['generation'],'planSha256':sha(raw),'identity':actual,
            'target':TARGET,'readySha256':sha(encoded(ready))}
        need(admitted == expected and reader.read(actual['pid']) == actual,
             'child_exact_same_birth_admission')
        outcome['sameBirthAdmission'] = True
        stage = 't5_open_ancestors'
        work = io.open_dir(WORK, full9=plan['workFull9'])
        need(work['initial'][0] == ANCHOR_FULL9['/Volumes/T5'][0],
             'child_t5_same_observed_device')
        stage = 't5_chdir'
        os.chdir(str(WORK))
        need(identity(io.meta(os.stat,'.',follow_symlinks=False)) == tuple(plan['workFull9'])
             and os.getcwd() == str(WORK), 'child_actual_t5_working_directory')
        outcome['enteredT5'] = True
        stage = 't5_sentinel_read'
        sentinel, sentinel_id = io.read(PUBLIC_SENTINEL, expected=plan['sentinelFull9'])
        need(sentinel == SENTINEL and sha(sentinel) == plan['sentinelSha256'],
             'child_exact_public_sentinel')
        io.check_dir(work)
        need(reader.read(actual['pid']) == actual and reader.children(actual['pid']) == [],
             'child_final_same_birth_no_children')
        outcome['sentinelMatched'] = True
        outcome['sentinelBytes'] = len(sentinel)
        outcome['sentinelSha256'] = sha(sentinel)
        outcome['sentinelFull9'] = sentinel_id
        io.check_all()
        remaining()
        outcome['ok'] = True
        stage = 'complete'
    except BaseException as error:
        outcome['error'] = error_projection(error)
    finally:
        outcome['stage'] = stage
        if io is not None:
            io.close()
            outcome['io'] = io.public()
        else:
            outcome['io'] = None
        restore_errors = restore_handlers(saved)
        outcome['signalRestoreErrors'] = restore_errors
        outcome['pendingSignalAfterRestore'] = signals.pending
        final_ns = time.monotonic_ns()
        outcome['deadlineMetAfterClosure'] = final_ns < hard_until_ns
        outcome['elapsedSeconds'] = (final_ns-now_ns)/1000000000
        outcome['allReturnedApplicationFdsClosed'] = io is None or io.public()['allClosed']
        outcome['ok'] = bool(outcome['ok'] and outcome['allReturnedApplicationFdsClosed']
            and not restore_errors and signals.pending is None and outcome['deadlineMetAfterClosure'])
        outcome['outcomeUnknown'] = bool(not outcome['allReturnedApplicationFdsClosed']
            or restore_errors or signals.pending is not None)
        final_raw = encoded(outcome)
        if len(final_raw) > 32768:
            raise SystemExit(1)
        sys.stdout.buffer.write(final_raw)
        sys.stdout.buffer.flush()
    raise SystemExit(0 if outcome['ok'] and time.monotonic_ns() < hard_until_ns else 1)

if __name__ == '__main__':
    child_main()
