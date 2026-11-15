"""Single-attempt native restore transport for an explicitly unobserved response.

This helper never reads or parses server response bytes. It cannot determine
whether a fully transmitted request committed. That requires separate surviving
voter readback; no transport exception is treated as a successful restore.
"""
from __future__ import annotations
import socket
from pathlib import Path

MAX_SMALL_ARCHIVE = 2 * 1024 * 1024


class UnobservedRestore:
    def __init__(self, tls, *, bytes_sent, body_complete):
        self._tls = tls
        self.bytes_sent = bytes_sent
        self.body_complete = body_complete
        self.closed = False

    def safe_observation(self):
        return {'request_body_bytes_sent': self.bytes_sent,
                'request_body_complete': self.body_complete,
                'response_read_attempted': False,
                'restore_acknowledged': False,
                'publication_determined_by_transport': False,
                'mutation_retry': False}

    def close(self):
        if not self.closed:
            # No TLS unwrap (which can read), no response drain, no retransmit.
            self.closed = True
            self._tls.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


def begin_unobserved_restore(node, token: str, archive: Path, *, omit_final_byte=False):
    """Send all bytes or all-but-one, then return the owned socket to the caller.

    The latter identifies pre-body-completion only, NOT a post-Stage kill point.
    A send exception fails the scenario; it is never silently replayed.
    """
    if not isinstance(token, str) or not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError('invalid_fixture_token_shape')
    if archive.is_symlink() or not archive.is_file():
        raise ValueError('archive_not_regular')
    length = archive.stat().st_size
    if not 1 < length <= MAX_SMALL_ARCHIVE:
        raise ValueError('small_archive_bound')
    body_length = length - int(omit_final_byte)
    header = (f'POST /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: localhost\r\n'
              f'X-Vault-Token: {token}\r\nContent-Type: application/gzip\r\n'
              f'Content-Length: {length}\r\nConnection: close\r\n\r\n').encode()
    raw = socket.create_connection(('127.0.0.1', node.http_port), timeout=5)
    try:
        tls = node.context.wrap_socket(raw, server_hostname='localhost')
    except BaseException:
        raw.close(); raise
    try:
        tls.sendall(header)
        sent = 0
        with archive.open('rb') as stream:
            while sent < body_length:
                value = stream.read(min(65536, body_length-sent))
                if not value: raise ValueError('archive_changed_during_send')
                tls.sendall(value); sent += len(value)
            if stream.read(2) != (b'' if not omit_final_byte else archive_tail(archive)):
                raise ValueError('archive_changed_during_send')
        return UnobservedRestore(tls, bytes_sent=sent, body_complete=not omit_final_byte)
    except BaseException:
        tls.close(); raise


def archive_tail(path):
    with path.open('rb') as stream:
        stream.seek(-1, 2)
        return stream.read(1)
