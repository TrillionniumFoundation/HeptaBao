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
