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
