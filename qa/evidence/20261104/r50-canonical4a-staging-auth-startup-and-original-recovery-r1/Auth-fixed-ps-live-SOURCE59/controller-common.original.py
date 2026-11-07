class Refused(RuntimeError):pass
class Cancelled(BaseException):pass
@contextmanager
def critical():
    global protected
    protected += 1
    try: yield
    finally: protected -= 1

def need(value, code):
    if not value: raise Refused(code)

def interrupt(signum, _frame):
    global pending_signal
    pending_signal = signum
    if protected == 0: raise Cancelled()

def remaining(until=UNTIL):
    need(pending_signal is None, 'phase_interrupted')
    value = until - time.monotonic()
    need(value > 0, 'original_shared_phase_deadline_exhausted')
    return value

def sha(raw): return hashlib.sha256(raw).hexdigest()

def encoded(value): return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()

def identity(s):
    return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def error_projection(error):
    name=type(error).__name__
    known=('Refused','ProbeRefused','VolumeRefused','ObservationRefused','Refusal',
           'CommandRefused','OSError','FileNotFoundError','FileExistsError',
           'PermissionError','KeyboardInterrupt','Cancelled','ValueError',
           'TypeError','RuntimeError','MemoryError','SyntaxError','UnicodeError')
    code=str(error) if name in ('Refused','ProbeRefused','VolumeRefused',
         'ObservationRefused','Refusal','CommandRefused') else None
    return {'type':name if name in known else None,
            'code':code if code in ERROR_CODES else None,
            'unknownErrorTextWithheld':bool(code is not None and code not in ERROR_CODES)
                or name not in known,
            'errno':getattr(error,'errno',None) if type(getattr(error,'errno',None)) is int else None}

class SignalFacade:
    @property
    def pending(self):return pending_signal
    def critical(self):return critical()

