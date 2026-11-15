#!/usr/bin/env python3
"""Synthetic framing and deadline cases; no current credentials or provider I/O."""
import http.client
import json
import time
import unittest
from unittest import mock
import main3_http_complete as h


class MemoryTLS:
    def __init__(self, data, fragment=8192, delay=0):
        self.data, self.fragment, self.delay = data, fragment, delay
        self.offset = 0
        self.closed = False
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, amount):
        if self.delay:
            time.sleep(self.delay)
        value = self.data[self.offset:self.offset + min(amount, self.fragment)]
        self.offset += len(value)
        return value

    def close(self):
        self.closed = True


def frame(body=b'{}', headers=None, status=200, version='HTTP/1.1'):
    headers = [('Content-Length', str(len(body)))] if headers is None else headers
    return (version + ' ' + str(status) + ' Synthetic\r\n' +
            ''.join(k + ': ' + v + '\r\n' for k, v in headers) + '\r\n').encode() + body


def chunked(body=b'2\r\n{}\r\n0\r\n\r\n', headers=None):
    return frame(body, [('Transfer-Encoding', 'chunked')] if headers is None else headers)


class CompleteFraming(unittest.TestCase):
    def parse(self, raw, fragment=8192, remaining=None, delay=0):
        self.projection = {}
        self.socket = MemoryTLS(raw, fragment, delay)
        if remaining is None:
            until = time.monotonic() + 2
            def remaining():
                left = until - time.monotonic()
                if left <= 0:
                    raise TimeoutError('synthetic_absolute_deadline')
                return left
        stream = h.DeadlineSocket(self.socket, remaining, self.projection)
        response = None
        try:
            response = h.CompleteHTTPResponse(stream, remaining, self.projection)
            response.begin()
            data = h.read_complete_body(response, remaining, self.projection)
            return data
        finally:
            if response is not None:
                response.close()
            stream.close_reader()
            self.socket.close()

    def rejects(self, raw, code=None):
        with self.assertRaises((h.HttpFramingRefused, http.client.HTTPException)) as caught:
            self.parse(raw)
        if code is not None:
            self.assertEqual(h.safe_failure_code(caught.exception), code)
        self.assertTrue(self.socket.closed)

    def test_content_length_fragmented_complete(self):
        body = json.dumps({'synthetic': 'x' * 4096}).encode()
        self.assertEqual(self.parse(frame(body), fragment=7), body)
        self.assertEqual(self.projection['responseFraming'], 'content-length')
        self.assertEqual(self.projection['decodedBodyBytes'], len(body))
        self.assertTrue(self.socket.closed)

    def test_content_length_zero(self):
        self.assertEqual(self.parse(frame(b'')), b'')

    def test_empty_204_without_length(self):
        self.assertEqual(self.parse(frame(b'', [], 204)), b'')
        self.assertEqual(self.projection['responseFraming'], 'no-body')

    def test_empty_204_with_zero_length(self):
        self.assertEqual(self.parse(frame(b'', [('Content-Length', '0')], 204)), b'')

    def test_large_multichunk_extensions_and_trailer(self):
        body = json.dumps({'synthetic': 'x' * 4096}).encode()
        first, second = body[:137], body[137:]
        raw = (b'89; kind=one; quoted="two; three"\r\n' + first + b'\r\n' +
               format(len(second), 'X').encode() + b'\r\n' + second +
               b'\r\n0; done=yes\r\nX-Synthetic-Only: closed\r\n\r\n')
        self.assertEqual(self.parse(chunked(raw), fragment=11), body)
        self.assertEqual(self.projection['dataChunkCount'], 2)
        self.assertEqual(self.projection['trailerCount'], 1)
        self.assertTrue(self.projection['terminalChunkSeen'])
        self.assertTrue(self.projection['trailersComplete'])

    def test_chunked_case_and_optional_whitespace(self):
        self.assertEqual(self.parse(chunked(headers=[('Transfer-Encoding', '  ChUnKeD \t')])), b'{}')

    def test_chunked_empty_body_terminal_required(self):
        self.assertEqual(self.parse(chunked(b'0\r\n\r\n')), b'')
        self.assertEqual(self.projection['dataChunkCount'], 0)

    def test_exact_decoded_body_limit(self):
        body = b'x' * h.MAX_BODY
        self.assertEqual(self.parse(chunked(b'100000\r\n' + body + b'\r\n0\r\n\r\n'), fragment=8192), body)

    def test_truncated_content_length(self):
        self.rejects(frame(b'{}', [('Content-Length', '3')]), 'http_body_incomplete')

    def test_missing_length_not_inferred_from_eof(self):
        self.rejects(frame(b'{}', []), 'http_content_length_required')

    def test_duplicate_content_length_rejected_even_identical(self):
        self.rejects(frame(b'{}', [('Content-Length', '2'), ('content-length', '2')]),
                     'http_duplicate_framing_header')

    def test_duplicate_transfer_encoding_rejected(self):
        self.rejects(chunked(headers=[('Transfer-Encoding', 'chunked'), ('transfer-encoding', 'chunked')]),
                     'http_duplicate_framing_header')

    def test_transfer_and_length_ambiguity_rejected(self):
        self.rejects(chunked(headers=[('Transfer-Encoding', 'chunked'), ('Content-Length', '2')]),
                     'http_ambiguous_transfer_and_length')

    def test_unsupported_transfer_codings_rejected(self):
        for value in ('gzip, chunked', 'chunked, chunked', 'identity', ''):
            with self.subTest(value=value):
                self.rejects(chunked(headers=[('Transfer-Encoding', value)]), 'http_unsupported_transfer_encoding')

    def test_invalid_content_length_rejected(self):
        for value in ('-1', '+2', '0x2', '2, 2', 'synthetic', '9999999999'):
            with self.subTest(value=value):
                self.rejects(frame(b'{}', [('Content-Length', value)]), 'http_length_grammar')

    def test_oversized_declared_content_length(self):
        self.rejects(frame(b'{}', [('Content-Length', '1048577')]), 'http_decoded_body_limit')

    def test_body_for_204_rejected(self):
        self.rejects(frame(b'{}', [('Content-Length', '2')], 204), 'http_empty_204_frame')

    def test_chunked_204_rejected(self):
        self.rejects(frame(b'0\r\n\r\n', [('Transfer-Encoding', 'chunked')], 204), 'http_empty_204_frame')

    def test_invalid_chunk_size_grammar(self):
        for value in (b'z', b'-2', b'+2', b'0x2', b' 2', b'2;=bad', b'2;foo="unterminated'):
            with self.subTest(value=value):
                self.rejects(chunked(value + b'\r\n{}\r\n0\r\n\r\n'), 'http_chunk_size_grammar')

    def test_chunk_size_requires_crlf(self):
        self.rejects(chunked(b'2\n{}\r\n0\r\n\r\n'), 'http_chunk_size_line')

    def test_chunk_data_requires_crlf(self):
        self.rejects(chunked(b'2\r\n{}XX0\r\n\r\n'), 'http_chunk_data_terminator')

    def test_truncated_chunk_body(self):
        self.rejects(chunked(b'20\r\n{}'), 'http_body_incomplete')

    def test_missing_zero_chunk_rejected(self):
        self.rejects(chunked(b'2\r\n{}\r\n'), 'http_chunk_size_missing')

    def test_missing_final_trailer_separator_rejected(self):
        self.rejects(chunked(b'2\r\n{}\r\n0\r\n'), 'http_terminal_trailer_missing')

    def test_trailer_bad_line_ending_rejected(self):
        self.rejects(chunked(b'0\r\nX-Synthetic: ok\n\n'), 'http_trailer_line_ending')

    def test_forbidden_framing_trailer_rejected(self):
        self.rejects(chunked(b'0\r\nContent-Length: 0\r\n\r\n'), 'http_forbidden_trailer')

    def test_folded_trailer_rejected(self):
        self.rejects(chunked(b'0\r\n folded: value\r\n\r\n'), 'http_trailer_field_grammar')

    def test_folded_header_rejected(self):
        self.rejects(frame(b'{}', [('Content-Length', '2'), ('X-Synthetic', 'value\r\n folded')]),
                     'http_header_value_grammar')

    def test_oversized_chunk_rejected_before_body(self):
        self.rejects(chunked(b'100001\r\n'), 'http_decoded_body_limit')

    def test_cumulative_decoded_limit_rejected(self):
        self.rejects(chunked(b'100000\r\n' + b'x' * h.MAX_BODY + b'\r\n1\r\nx\r\n0\r\n\r\n'),
                     'http_decoded_body_limit')

    def test_bounded_number_of_chunks(self):
        self.rejects(chunked(b'1\r\nx\r\n' * (h.MAX_CHUNKS + 1) + b'0\r\n\r\n'), 'http_chunk_count_limit')

    def test_bounded_chunk_line(self):
        self.rejects(chunked(b'2;extension=' + b'x' * h.MAX_LINE + b'\r\n{}\r\n0\r\n\r\n'),
                     'http_chunk_size_line')

    def test_bounded_trailer_bytes(self):
        self.rejects(chunked(b'0\r\n' + (b'X-Synthetic: ' + b'x' * 8100 + b'\r\n') * 3 + b'\r\n'),
                     'http_trailer_limit')

    def test_bounded_wire_bytes(self):
        with mock.patch.object(h, 'MAX_WIRE', 48):
            self.rejects(frame(b'x' * 100), 'http_wire_limit')

    def test_absolute_deadline_not_restarted_by_slow_header(self):
        until = time.monotonic() + .045
        def remaining():
            left = until - time.monotonic()
            if left <= 0:
                raise TimeoutError('synthetic_secret_must_not_be_reported')
            return left
        started = time.monotonic()
        with self.assertRaises(TimeoutError) as caught:
            self.parse(frame(), fragment=1, remaining=remaining, delay=.01)
        self.assertEqual(h.safe_failure_code(caught.exception), 'http_original_deadline')
        self.assertLess(time.monotonic() - started, .15)
        self.assertTrue(self.socket.closed)
        self.assertGreater(len(self.socket.timeouts), 2)
        self.assertLess(self.socket.timeouts[-1], self.socket.timeouts[0])

    def test_projection_contains_no_body_header_value_or_digest(self):
        value = 'synthetic-private-marker-not-public'
        self.parse(frame(value.encode(), [('Content-Length', str(len(value))), ('X-Synthetic', value)]))
        public = json.dumps(self.projection)
        self.assertNotIn(value, public)
        self.assertNotIn('sha256', public)
        self.assertNotIn('X-Synthetic', public)


if __name__ == '__main__':
    unittest.main(verbosity=2)
