class InputAudit:
    """Two fixed public executables only; held full9/hash witnesses, no arbitrary input."""
    def __init__(self, signals):
        self.signals=signals;self.remaining=remaining
        self.rows=[];self.close_errors=[];self.max_rows=2
        self.open_ledger={'attempts':0,'knownNoReturnErrors':0,'registered':0,
                          'pending':0,'registrationUnknown':False}
        self.read_calls=0;self.read_bytes=0;self.metadata_calls=0;self.admitted={}
    def meta(self, fn, *args, **kwargs):
        remaining();need(self.metadata_calls<128,'input_metadata_cap')
        self.metadata_calls+=1;value=fn(*args,**kwargs);remaining();return value
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

    def close(self):
        with self.signals.critical():
            for row in reversed(self.rows):
                self.close_one(row)

    def admit(self,path,pin):
        path=Path(path);need(str(path) in INPUT_PINS and str(path) not in self.admitted,
                            'two_fixed_input_once')
        before=self.meta(os.lstat,path)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1
             and tuple(str(v) for v in identity(before))==tuple(pin['identity'])
             and before.st_size==pin['bytes'],'fixed_input_full9_before')
        row=self.open_fd(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        need(identity(self.meta(os.fstat,row['fd']))==identity(before),'fixed_input_open_full9')
        h=hashlib.sha256();total=0
        while True:
            remaining();need(self.read_calls<128 and self.read_bytes<205074,'fixed_input_read_cap')
            self.read_calls+=1
            block=os.read(row['fd'],min(65536,pin['bytes']+1-total,205074-self.read_bytes))
            self.read_bytes+=len(block);total+=len(block)
            need(total<=pin['bytes'] and self.read_bytes<=205074,'fixed_input_byte_cap')
            if not block:break
            h.update(block)
        need(total==pin['bytes'] and h.hexdigest()==pin['sha256'],'fixed_input_whole_hash')
        need(identity(self.meta(os.fstat,row['fd']))==identity(before)
             ==identity(self.meta(os.lstat,path)),'fixed_input_whole_stable')
        row['expected']=identity(before);self.admitted[str(path)]=row
    def verify(self):
        for path,row in self.admitted.items():
            need(not row['closed'] and row['expected']==identity(self.meta(os.fstat,row['fd']))
                 ==identity(self.meta(os.lstat,path)),'fixed_held_input_after')
        return True
    def public(self):
        ledger=dict(self.open_ledger)
        closed=(not ledger['pending'] and not ledger['registrationUnknown']
                and ledger['registered']==len(self.rows)
                and all(row['closed'] for row in self.rows) and not self.close_errors)
        return {'fixedInputCount':len(self.admitted),'returnedFdLedger':ledger,
                'metadataCalls':self.metadata_calls,'readCalls':self.read_calls,
                'readBytes':self.read_bytes,'allReturnedInputFdsClosed':closed,
                'closeErrors':list(self.close_errors)}

