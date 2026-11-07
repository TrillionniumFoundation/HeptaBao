"""No-network fault checks of the original af91 API plus trace-only binding."""
from __future__ import annotations
import __future__
import ast
import errno
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import socket
import ssl
import types
import urllib.error
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "ha128-r3-actual/ha_multihost_live.af91.readonly.py"
PIN = "2c87ffbcee09fc7706e7ac59c73ac851ac8313ce18a962255a26ad54e90d089e"
spec = importlib.util.spec_from_file_location("observer", ROOT / "ha_http_transport_observer_formal_r1.py")
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
PRIVATE = "SYNTHETIC_PRIVATE_HEADER_OR_ERROR_DO_NOT_EMIT"


class FixtureError(Exception):
    pass


def original_api():
    raw = ORIGINAL.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PIN
    tree = ast.parse(raw.decode())
    definitions = [n for n in tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef))
                   and n.name in ("NoRedirect", "api")]
    assert len(definitions) == 2
    scope = {"ssl": ssl, "urllib": urllib, "json": json, "re": re,
             "FixtureError": FixtureError, "MAX_BODY": 64 * 1024 * 1024}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(ORIGINAL), "exec",
                 flags=__future__.annotations.compiler_flag, dont_inherit=True), scope)
    return scope["api"]


def exercise(name, phase, expected_exception, expected_phase, *, method="GET", status=200):
    rows = []
    bound = observer.bind_original_api(original_api(), rows)
    context = ssl.create_default_context()
    context_before = (context.verify_mode, context.check_hostname, context.minimum_version, context.options)
    counts = {"tcp": 0, "tls": 0, "send": 0, "makefile": 0}
    response_body = b"{}" if status != 400 else b'{"errors":[]}'
    response_bytes = (b"HTTP/1.1 " + str(status).encode() + b" fixture\r\nContent-Length: "
                      + str(len(response_body)).encode() + b"\r\nConnection: close\r\n\r\n"
                      + response_body)

    class Buffer(io.BytesIO):
        def readline(self, *args):
            if phase == "headers":
                raise TimeoutError(PRIVATE)
            return super().readline(*args)

        def read(self, *args):
            if phase == "body":
                raise TimeoutError(PRIVATE)
            return super().read(*args)

    class Endpoint:
        def setsockopt(self, *args):
            assert args == (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def close(self):
            pass

        def sendall(self, data):
            counts["send"] += 1
            if phase == "send" or phase == "body_send" and counts["send"] == 2:
                raise ConnectionResetError(errno.ECONNRESET, PRIVATE)

        def makefile(self, *args, **kwargs):
            counts["makefile"] += 1
            assert args == ("rb",)
            return Buffer(response_bytes)

    def tcp(address, timeout, source_address):
        counts["tcp"] += 1
        assert address == ("127.0.0.1", 31040) and timeout == 15 and source_address is None
        if phase == "tcp":
            raise TimeoutError(PRIVATE)
        if phase == "refused":
            raise ConnectionRefusedError(errno.ECONNREFUSED, PRIVATE)
        return Endpoint()

    def tls(self, endpoint, *, server_hostname):
        counts["tls"] += 1
        assert self is context and isinstance(endpoint, Endpoint) and server_hostname == "127.0.0.1"
        if phase == "tls":
            raise TimeoutError(PRIVATE)
        if phase == "certificate":
            error = ssl.SSLCertVerificationError(1, PRIVATE)
            error.verify_code = 20
            raise error
        return endpoint

    actual = None
    with patch.object(socket, "create_connection", tcp), patch.object(ssl.SSLContext, "wrap_socket", tls), \
         patch.object(socket, "socket", side_effect=AssertionError("network forbidden")):
        try:
            result = bound(context, types.SimpleNamespace(node_id=1, api_origin="https://127.0.0.1:31040"),
                           method, "secret/data/" + PRIVATE,
                           body={"fixture": PRIVATE} if method == "POST" else None,
                           token=PRIVATE, timeout=15)
            assert result[0] == status
        except BaseException as error:
            actual = type(error).__name__
            assert PRIVATE in str(error) if expected_exception else False
    assert actual == expected_exception, (name, actual)
    assert len(rows) == 1 and rows[0]["phase"] == expected_phase, (name, rows)
    row = rows[0]
    assert counts["tcp"] == row["tcpConnectCalls"] == 1
    assert row["connectionObjects"] == row["httpsConnectCalls"] == 1
    assert counts["tls"] == (0 if phase in ("tcp", "refused") else 1)
    assert counts["send"] == (0 if phase in ("tcp", "refused", "tls", "certificate")
                              else (2 if method == "POST" and phase != "send" else 1))
    assert PRIVATE not in json.dumps(row)
    assert context_before == (context.verify_mode, context.check_hostname,
                              context.minimum_version, context.options)
    assert observer.CURRENT.get() is None
    assert bound.binding_changes == {"httpsHandlerConstructorReplacements": 1,
        "originalRequestsDelegatedOnce": True, "originalExceptionsReraised": True,
        "tlsContextChanged": False, "timeoutsChanged": False}
    if expected_exception:
        assert not row["apiReturned"] and "error" in row
    else:
        assert row["apiReturned"] and row["bodyReadReturned"] and row["responseCloseCalls"] == 1
    return {"case": name, "passed": True, "observedException": actual,
            "finalPhase": row["phase"], "tcpCalls": counts["tcp"], "tlsCalls": counts["tls"],
            "sendCalls": counts["send"], "noPrivateTextOutput": True}


def main():
    cases = []
    for name, phase, error, final, method, status in (
        ("get_success_once", "success", None, "api_returned", "GET", 200),
        ("post_success_once", "success", None, "api_returned", "POST", 200),
        ("http_error_remains_known_response", "success", None, "api_returned", "GET", 400),
        ("tcp_timeout_original_urlerror", "tcp", "URLError", "tcp_connect", "GET", 200),
        ("tcp_refused_no_retry", "refused", "URLError", "tcp_connect", "GET", 200),
        ("tls_timeout_after_tcp", "tls", "URLError", "after_tcp_before_tls_complete", "GET", 200),
        ("certificate_failure_preserved", "certificate", "URLError", "after_tcp_before_tls_complete", "GET", 200),
        ("request_send_reset", "send", "URLError", "request_send", "GET", 200),
        ("partial_post_body_reset_no_replay", "body_send", "URLError", "request_send", "POST", 200),
        ("header_timeout_not_rewrapped", "headers", "TimeoutError", "response_headers", "GET", 200),
        ("body_timeout_not_rewrapped", "body", "TimeoutError", "response_body", "GET", 200),
    ):
        cases.append(exercise(name, phase, error, final, method=method, status=status))
    print(json.dumps({"schema": "heptabao.ha-http-observer.synthetic-tests.v1",
                      "passed": len(cases), "required": 11, "cases": cases,
                      "originalQaSourceSha256": PIN,
                      "networkCalls": 0, "productExecutions": 0,
                      "actualHAReproduction": False}, sort_keys=True))


if __name__ == "__main__":
    main()
