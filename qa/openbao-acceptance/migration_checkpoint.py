"""Private nonblocking checkpoint locks for the logical migration adapters."""

import fcntl
import os
from pathlib import Path
import stat

from bao_http import BaoError, digest, private_json, private_write


class CheckpointLock:
    def __init__(self, filename):
        self.filename, self.fd = str(filename) + ".lock", None

    def __enter__(self):
        try:
            self.fd = os.open(self.filename, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise BaoError("checkpoint_lock_not_private_regular_file")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BaoError):
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            raise BaoError("checkpoint_locked_or_inaccessible") from None
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class ObjectCheckpoint:
    def __init__(self, filename, binding, schema):
        self.filename = Path(filename)
        self.binding = digest(binding)
        if self.filename.exists() or self.filename.is_symlink():
            self.state = private_json(self.filename)
            if (
                not isinstance(self.state, dict)
                or self.state.get("schema") != schema
                or self.state.get("binding") != self.binding
                or not isinstance(self.state.get("objects"), dict)
            ):
                raise BaoError("checkpoint_context_mismatch")
        else:
            self.state = {"schema": schema, "binding": self.binding, "objects": {}}
            private_write(self.filename, self.state, replace=False)

    def save(self):
        private_write(self.filename, self.state)
