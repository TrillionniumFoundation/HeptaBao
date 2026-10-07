import contextlib
import http.client
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import MagicMock
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from heptabao.transport import (BaoError, Client, transport_diagnostic,
                                _StatusLineDiagnostic, _TransportDiagnostic)


class StatusLineBoundaryTests(unittest.TestCase):
    def client(self, opener):
        client = object.__new__(Client)
        client.address, client.namespace = "https://localhost:8200", ""
        client._token, client.timeout = "synthetic-private-bearer", 15
        client._opener = opener
        return client

    def actual_bad_response(self, wire):
        with contextlib.ExitStack() as stack:
            left, right = socket.socketpair()
            stack.enter_context(left)
            stack.enter_context(right)
            right.sendall(wire)
            right.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(left)
            stack.callback(response.close)
            opener = MagicMock()
            opener.open.side_effect = lambda *args, **kwargs: response.begin()
            with self.assertRaises(BaoError) as caught:
                self.client(opener).request("POST", "/v1/synthetic-fixture", {})
            self.assertEqual(caught.exception.code, "transport_outcome_unknown")
            self.assertEqual(str(caught.exception), "transport_outcome_unknown")
            self.assertEqual(opener.open.call_count, 1)
            self.assertEqual(opener.open.call_args.kwargs["timeout"], 15)
            return transport_diagnostic(caught.exception)

    def test_actual_malformed_stdlib_statuslines_retain_only_closed_shape(self):
        private = "synthetic-private-peer-response"
        for shape, line in (
                ("non_http_prefix", private + "\r\n"),
                ("http_malformed_status", "HTTP/1.1 malformed " + private + "\r\n"),
                ("http_status_out_of_range", "HTTP/1.1 099 " + private + "\r\n")):
            with self.subTest(shape=shape):
                detail = self.actual_bad_response(line.encode("ascii"))
                self.assertEqual(detail["phase"], "open_response")
                self.assertEqual(detail["exception_class"], "http.client.BadStatusLine")
                self.assertEqual(detail["status_line"], {
                    "shape": shape, "examined_characters": len(line),
                    "length_capped": False, "examined_ascii": True, "terminator": "crlf",
                })
                self.assertNotIn(private, json.dumps(detail))
                self.assertEqual(set(detail["status_line"]), {
                    "shape", "examined_characters", "length_capped", "examined_ascii", "terminator",
                })

    def test_actual_empty_disconnect_is_distinct_from_constructor_sentinel(self):
        detail = self.actual_bad_response(b"")
        self.assertEqual(detail, {"phase": "open_response",
                                  "exception_class": "http.client.RemoteDisconnected"})
        sentinel = transport_diagnostic(http.client.BadStatusLine(""))
        self.assertEqual(sentinel["status_line"], {
            "shape": "stdlib_empty_sentinel", "examined_characters": 2,
            "length_capped": False, "examined_ascii": True, "terminator": "none",
        })

    def test_hostile_line_object_and_exception_subclass_never_convert_peer_text(self):
        class HostileLine:
            def __str__(self):
                raise AssertionError("line str was called")
            def __repr__(self):
                raise AssertionError("line repr was called")
            def __len__(self):
                raise AssertionError("line len was called")
        error = http.client.BadStatusLine("fixed-constructor-input")
        error.line = HostileLine()
        self.assertEqual(transport_diagnostic(error),
                         {"phase": "fixture_call", "exception_class": "http.client.BadStatusLine"})
        wrapped = transport_diagnostic(urllib.error.URLError(error))
        self.assertEqual(wrapped, {"phase": "fixture_call", "exception_class": "urllib.error.URLError",
                                   "reason_exception_class": "http.client.BadStatusLine"})
        class PeerSubclass(http.client.BadStatusLine):
            def __getattribute__(self, name):
                if name == "line":
                    raise AssertionError("subclass line was inspected")
                return super().__getattribute__(name)
            def __str__(self):
                raise AssertionError("subclass str was called")
        self.assertEqual(transport_diagnostic(PeerSubclass("synthetic-private-subclass")),
                         {"phase": "fixture_call", "exception_class": "other"})

    def test_real_wrapped_stdlib_status_failure_is_closed_and_not_retried(self):
        with contextlib.ExitStack() as stack:
            left, right = socket.socketpair()
            stack.enter_context(left)
            stack.enter_context(right)
            private = b"synthetic-private-wrapped-peer"
            right.sendall(private + b"\r\n")
            right.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(left)
            stack.callback(response.close)
            opener = MagicMock()
            def opened(*args, **kwargs):
                try:
                    response.begin()
                except http.client.BadStatusLine as error:
                    raise urllib.error.URLError(error) from None
                raise AssertionError("malformed status unexpectedly accepted")
            opener.open.side_effect = opened
            with self.assertRaises(BaoError) as caught:
                self.client(opener).request("POST", "/v1/synthetic-fixture", {})
            detail = transport_diagnostic(caught.exception)
            self.assertEqual(detail["exception_class"], "urllib.error.URLError")
            self.assertEqual(detail["reason_exception_class"], "http.client.BadStatusLine")
            self.assertEqual(detail["status_line"]["shape"], "non_http_prefix")
            self.assertNotIn(private.decode(), json.dumps(detail))
            self.assertEqual(opener.open.call_count, 1)

    def test_real_line_limit_and_forged_metadata_cannot_expand_public_projection(self):
        detail = self.actual_bad_response(b"synthetic-private-prefix-" + b"x" * 65537 + b"\r\n")
        self.assertEqual(detail["exception_class"], "http.client.LineTooLong")
        self.assertNotIn("status_line", detail)
        for forged in (
                _StatusLineDiagnostic("synthetic-private-shape", 1, False, True, "none"),
                _StatusLineDiagnostic("non_http_prefix", True, False, True, "none"),
                _StatusLineDiagnostic("non_http_prefix", 65538, False, True, "none"),
                _StatusLineDiagnostic("non_http_prefix", 1, False, True, "synthetic-private-ending")):
            error = BaoError("transport_outcome_unknown", _diagnostic=_TransportDiagnostic(
                "open_response", "http.client.BadStatusLine", status_line=forged))
            detail = transport_diagnostic(error)
            self.assertNotIn("status_line", detail)
            self.assertNotIn("synthetic-private", json.dumps(detail))


if __name__ == "__main__":
    unittest.main()
