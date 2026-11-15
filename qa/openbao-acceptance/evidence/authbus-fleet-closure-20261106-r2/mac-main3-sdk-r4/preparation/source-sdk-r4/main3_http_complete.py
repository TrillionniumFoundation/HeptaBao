#!/usr/bin/env python3
"""Bounded, complete HTTP response framing for one already-owned TLS socket.

No connection, dispatch, retry, credential logging or socket ownership is added.
The caller supplies its original absolute deadline and closes the TLS socket.
"""
from __future__ import annotations
import http.client
import io
import re

MAX_BODY = 1048576
MAX_WIRE = 2 * MAX_BODY + 131072
MAX_LINE = 8192
MAX_HEADERS = 100
MAX_HEADER_BYTES = 65536
MAX_TRAILER_BYTES = 16384
MAX_CHUNKS = 4096
_TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_QUOTED = rb'"(?:[\t !#-\[\]-~\x80-\xff]|\\[\t \x21-\x7e\x80-\xff])*"'
_CHUNK_LINE = re.compile(rb'([0-9A-Fa-f]{1,16})(?:[ \t]*;[ \t]*' + _TOKEN +
                         rb'(?:[ \t]*=[ \t]*(?:' + _TOKEN + rb'|' + _QUOTED + rb'))?)*[ \t]*')
_HEADER_NAME = re.compile(_TOKEN)
_FORBIDDEN_TRAILERS = frozenset((
    b'content-length', b'transfer-encoding', b'host', b'connection', b'trailer',
    b'content-encoding', b'content-type', b'content-range', b'authorization',
    b'proxy-authorization', b'www-authenticate', b'proxy-authenticate', b'set-cookie'))


class HttpFramingRefused(Exception):
    def __init__(self, code):
        self.safe_code = code
        super().__init__(code)


def require(value, code):
    if not value:
        raise HttpFramingRefused(code)


class _DeadlineRaw(io.RawIOBase):
    def __init__(self, tls, remaining, projection):
        super().__init__()
        self.tls, self.remaining, self.projection = tls, remaining, projection
        self.wire_bytes = 0

    def readable(self):
        return True

    def readinto(self, buffer):
        self.tls.settimeout(self.remaining())
        require(self.wire_bytes < MAX_WIRE, 'http_wire_limit')
        data = self.tls.recv(min(len(buffer), 8192, MAX_WIRE - self.wire_bytes))
        self.wire_bytes += len(data)
        self.projection['receivedWireBytes'] = self.wire_bytes
        self.remaining()
        buffer[:len(data)] = data
        return len(data)


class DeadlineSocket:
    """Only the response reader owns this file; the original caller owns TLS."""
    def __init__(self, tls, remaining, projection):
        self.raw = _DeadlineRaw(tls, remaining, projection)
        self.reader = None

    def makefile(self, mode):
        require(mode == 'rb' and self.reader is None, 'http_one_response_reader')
        self.reader = io.BufferedReader(self.raw, buffer_size=8192)
        return self.reader

    def close_reader(self):
        if self.reader is not None:
            self.reader.close()
        else:
            self.raw.close()


class CompleteHTTPResponse(http.client.HTTPResponse):
    """Use stdlib status/headers/body parsing with strict bounded chunk endings."""
    def __init__(self, stream, remaining, projection):
        self.remaining, self.projection = remaining, projection
        self.announced_bytes = self.data_chunks = self.trailer_count = 0
        self.terminal_chunk_seen = self.trailers_complete = False
        super().__init__(stream)

    def _read_next_chunk_size(self):
        self.remaining()
        line = self.fp.readline(MAX_LINE + 1)
        require(bool(line), 'http_chunk_size_missing')
        require(len(line) <= MAX_LINE and line.endswith(b'\r\n'), 'http_chunk_size_line')
        match = _CHUNK_LINE.fullmatch(line[:-2])
        require(match is not None, 'http_chunk_size_grammar')
        size = int(match.group(1), 16)
        require(self.announced_bytes + size <= MAX_BODY, 'http_decoded_body_limit')
        if size:
            self.data_chunks += 1
            require(self.data_chunks <= MAX_CHUNKS, 'http_chunk_count_limit')
            self.announced_bytes += size
        else:
            self.terminal_chunk_seen = True
        self.projection.update(dataChunkCount=self.data_chunks,
                               terminalChunkSeen=self.terminal_chunk_seen)
        return size

    def _read_and_discard_trailer(self):
        total = 0
        while True:
            self.remaining()
            line = self.fp.readline(MAX_LINE + 1)
            require(bool(line), 'http_terminal_trailer_missing')
            total += len(line)
            require(len(line) <= MAX_LINE and total <= MAX_TRAILER_BYTES,
                    'http_trailer_limit')
            require(line.endswith(b'\r\n'), 'http_trailer_line_ending')
            if line == b'\r\n':
                self.trailers_complete = True
                self.projection['trailersComplete'] = True
                return
            self.trailer_count += 1
            self.projection['trailerCount'] = self.trailer_count
            require(self.trailer_count <= MAX_HEADERS, 'http_trailer_count_limit')
            name, separator, value = line[:-2].partition(b':')
            require(bool(separator) and _HEADER_NAME.fullmatch(name) is not None,
                    'http_trailer_field_grammar')
            require(name.lower() not in _FORBIDDEN_TRAILERS, 'http_forbidden_trailer')
            require(all(c == 9 or c >= 32 and c != 127 for c in value),
                    'http_trailer_value_grammar')

    def _get_chunk_left(self):
        left = self.chunk_left
        if not left:
            if left is not None:
                require(self._safe_read(2) == b'\r\n', 'http_chunk_data_terminator')
            left = self._read_next_chunk_size()
            if left == 0:
                self._read_and_discard_trailer()
                self._close_conn()
                left = None
            self.chunk_left = left
        return left


def read_complete_body(response, remaining, projection):
    """No unbounded read, EOF inference, response replay or header-value logging."""
    remaining()
    headers = response.getheaders()
    lengths = [v for k, v in headers if k.lower() == 'content-length']
    transfers = [v for k, v in headers if k.lower() == 'transfer-encoding']
    projection.update(contentLengthHeaderCount=len(lengths),
                      transferEncodingHeaderCount=len(transfers),
                      responseFraming='unadmitted')
    require(len(headers) <= MAX_HEADERS, 'http_header_count_limit')
    require(not getattr(response.headers, 'defects', ()), 'http_header_grammar')
    size = 0
    for name, value in headers:
        require(_HEADER_NAME.fullmatch(name.encode('ascii', 'strict')) is not None,
                'http_header_name_grammar')
        require(all(c == '\t' or ord(c) >= 32 and ord(c) != 127 for c in value),
                'http_header_value_grammar')
        size += len(name) + len(value) + 4
        require(len(name) + len(value) + 4 <= MAX_LINE and size <= MAX_HEADER_BYTES,
                'http_header_bytes_limit')
    require(len(lengths) <= 1 and len(transfers) <= 1, 'http_duplicate_framing_header')
    require(not (lengths and transfers), 'http_ambiguous_transfer_and_length')
    require(response.version in (10, 11), 'http_response_version')
    length = lengths[0].strip(' \t') if lengths else None
    require(length is None or re.fullmatch(r'[0-9]{1,9}', length), 'http_length_grammar')
    if length is not None:
        length = int(length)
        projection['declaredContentLength'] = length
        require(length <= MAX_BODY, 'http_decoded_body_limit')
    if response.status == 204:
        require(not transfers and length in (None, 0), 'http_empty_204_frame')
        projection['responseFraming'] = 'no-body'
        expected = 0
    elif transfers:
        require(transfers[0].strip(' \t').lower() == 'chunked' and response.version == 11,
                'http_unsupported_transfer_encoding')
        # The stdlib compares TE literally; admit case/OWS only after rejecting
        # all duplicate/ambiguous framing, then select its original chunk reader.
        response.chunked, response.chunk_left, response.length = True, None, None
        projection.update(responseFraming='chunked', dataChunkCount=0,
                          trailerCount=0, terminalChunkSeen=False, trailersComplete=False)
        expected = None
    else:
        require(length is not None, 'http_content_length_required')
        projection['responseFraming'] = 'content-length'
        expected = length
    data = response.read(MAX_BODY + 1 if expected is None else expected + 1)
    remaining()
    require(len(data) <= MAX_BODY, 'http_decoded_body_limit')
    require(response.isclosed(), 'http_body_incomplete')
    if expected is None:
        require(response.terminal_chunk_seen and response.trailers_complete and
                len(data) == response.announced_bytes, 'http_chunked_body_incomplete')
    else:
        require(len(data) == expected, 'http_body_incomplete')
    projection['decodedBodyBytes'] = len(data)
    return data


def safe_failure_code(error):
    if isinstance(error, HttpFramingRefused):
        return error.safe_code
    if isinstance(error, http.client.IncompleteRead):
        return 'http_body_incomplete'
    if isinstance(error, TimeoutError):
        return 'http_original_deadline'
    if isinstance(error, http.client.HTTPException):
        return 'http_status_or_header_grammar'
    return 'api_transport_or_guard_refused'
