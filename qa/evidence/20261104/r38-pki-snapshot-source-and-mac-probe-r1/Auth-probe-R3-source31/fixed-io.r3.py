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
