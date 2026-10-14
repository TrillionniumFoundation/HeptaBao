"""Linux-only, read-only identity witness for an owned PKCS#11 wrapper.

The argv[0] producer fd slot is not executable authority: its owner may close
and reuse it after exec. Verify the child's actual executable through one held
/proc/PID/exe descriptor, with seals, digest, UID and start-time rechecks.
No configuration, environment, arguments after argv[0], or secret data is read.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import select
from pathlib import Path
from typing import Any


class ObservationGone(Exception):
    """The sampled process disappeared; this sample proves nothing."""


class ObservationRejected(RuntimeError):
    """A live sample failed a required identity/integrity condition."""


def descriptor(st: os.stat_result) -> dict[str, int]:
    return {"device": st.st_dev, "inode": st.st_ino, "size": st.st_size,
            "uid": st.st_uid, "mode": st.st_mode}


def require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise ObservationRejected(label)


def _start_ticks(pid: int) -> str:
    path = Path('/proc') / str(pid)
    require_equal(path.stat().st_uid, os.getuid(), 'process UID changed')
    return (path / 'stat').read_text().rsplit(')', 1)[1].split()[19]


def observe_image(pid: int, expected: dict[str, Any], digest: str,
                  producer_pid: int, producer_start_ticks: str,
                  producer_fd: int) -> dict[str, Any]:
    """Return a positive witness only for a stable, sealed, exact owned image.

    expected is a previously sampled PID/start-time/executable descriptor.
    The caller must independently validate the current descendant owner chain.
    Permission errors, unsupported seals on the actual image, wrong hashes,
    and identity changes are failures, never classified as a process exit.
    """
    require_equal(pid, expected['pid'], 'sample PID differs')
    if min(pid, producer_pid) <= 1 or producer_fd < 0:
        raise ObservationRejected('invalid process or fd identity')
    exe_path = Path('/proc') / str(pid) / 'exe'
    fd = None
    pidfds = []
    try:
        pidfds.append(os.pidfd_open(pid, 0))
        pidfds.append(os.pidfd_open(producer_pid, 0))
        require_equal(_start_ticks(pid), expected['start_ticks'], 'child PID reused')
        require_equal(_start_ticks(producer_pid), producer_start_ticks,
                      'producer PID reused')
        fd = os.open(exe_path, os.O_RDONLY | os.O_CLOEXEC)
        actual = descriptor(os.fstat(fd))
        require_equal(actual, expected['exe_descriptor'], 'actual image differs')
        require_equal(actual['uid'], os.getuid(), 'image UID differs')
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        required = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        require_equal(seals & required, required, 'actual image is not fully sealed')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            found = hashlib.file_digest(stream, 'sha256').hexdigest()
        require_equal(found, digest, 'actual image digest differs')
        require_equal(descriptor(os.fstat(fd)), actual, 'held image changed')

        # Metadata-only diagnosis. A reused producer slot is not read, hashed,
        # or used as authority; it must not veto an independently pinned image.
        slot = Path('/proc') / str(producer_pid) / 'fd' / str(producer_fd)
        try:
            slot_metadata = descriptor(slot.stat())
            slot_state = 'same_image' if slot_metadata == actual else 'reused'
        except (FileNotFoundError, ProcessLookupError):
            slot_metadata, slot_state = None, 'closed'
        require_equal(_start_ticks(pid), expected['start_ticks'], 'child PID reused')
        require_equal(_start_ticks(producer_pid), producer_start_ticks,
                      'producer PID reused')
        require_equal(descriptor(exe_path.stat()), actual, 'child image changed')
        return {'actual_memfd_seals': seals,
                'executable_witness': 'held_child_proc_exe',
                'actual_executable_descriptor': actual,
                'actual_executable_sha256': found,
                'producer_slot_state': slot_state,
                'producer_slot_descriptor': slot_metadata,
                'producer_pid': producer_pid, 'producer_fd': producer_fd,
                'producer_start_ticks': producer_start_ticks}
    except PermissionError as error:
        # procfs can deny a dying task while its PID entry still exists. Only
        # an already-bound kernel pidfd reporting exit may invalidate the sample.
        # A live task permission failure is re-raised, never converted to PASS.
        for identity_fd in pidfds:
            poller = select.poll()
            poller.register(identity_fd, select.POLLIN | select.POLLHUP)
            if poller.poll(0):
                raise ObservationGone('kernel-bound process exited') from error
        raise
    except (FileNotFoundError, ProcessLookupError) as error:
        raise ObservationGone() from error
    finally:
        if fd is not None:
            os.close(fd)
        for identity_fd in pidfds:
            os.close(identity_fd)
