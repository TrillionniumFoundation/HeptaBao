#!/usr/bin/env python3
"""RST-tolerant entrypoint for the exact-head P0 transport matrix.

The immutable matrix implementation is retained in
``p0_transport_exact_core_v1``. This entrypoint changes only client-side
response collection and delivery-failure correlation:

* a TCP reset is accepted as end-of-stream only after a complete HTTP response
  has already been received;
* a reset before response bytes remains an explicit socket failure, allowing
  the bounded capacity-release probe to retry without relabelling the event;
* response-delivery failure evidence must belong to one exact request-attempt
  audit graph rather than any matching line from a batch of reset attempts.
"""

from __future__ import annotations

import errno
import socket
import sys
import time
from pathlib import Path
from typing import Protocol

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import p0_transport_exact_core_v1 as core
from p0_transport_exact_core_v1 import *  # noqa: F403 - preserve the v1 public test surface


class _ReadableSocket(Protocol):
    def settimeout(self, value: float) -> None: ...

    def recv(self, size: int) -> bytes: ...


def _is_reset(error: OSError) -> bool:
    return isinstance(error, (ConnectionResetError, BrokenPipeError)) or error.errno in {
        errno.ECONNRESET,
        errno.EPIPE,
        errno.ENOTCONN,
    }


def _raise_reset_before_response(error: OSError, message: str) -> None:
    """Preserve a retryable socket-reset type while attaching a stable reason."""

    raise ConnectionResetError(error.errno or errno.ECONNRESET, message) from error


def _read_response(
    stream: _ReadableSocket,
    *,
    started: float,
    deadline: float,
    timeout_message: str,
    reset_message: str,
) -> core.HttpResponse:
    chunks: list[bytes] = []
    while True:
        remaining = deadline - time.monotonic()
        core.require(remaining > 0, timeout_message)
        stream.settimeout(remaining)
        try:
            block = stream.recv(8192)
        except socket.timeout as error:
            raise core.MatrixFailure(timeout_message) from error
        except OSError as error:
            if not _is_reset(error):
                raise
            if not chunks:
                # The core capacity-release loop explicitly permits bounded
                # transient TCP resets after held sockets are dropped. Keep
                # this as an OSError so that narrow retry can occur there.
                # Everywhere else it still escapes the matrix and produces an
                # explicit failed artifact.
                _raise_reset_before_response(error, reset_message)
            # Linux may deliver a complete response followed by ECONNRESET when
            # the peer closes with unread ingress. Treat the reset as EOF only
            # after bytes exist; parse_http_response below still rejects a
            # partial head, partial body, duplicate header or length mismatch.
            break
        if not block:
            break
        chunks.append(block)
    elapsed = time.monotonic() - started
    return core.parse_http_response(b"".join(chunks), elapsed)


def exchange(
    host: str,
    port: int,
    raw: bytes,
    timeout_seconds: float = 10.0,
) -> core.HttpResponse:
    started = time.monotonic()
    deadline = started + timeout_seconds
    with socket.create_connection((host, port), timeout=timeout_seconds) as stream:
        try:
            stream.sendall(raw)
        except OSError as error:
            if _is_reset(error):
                _raise_reset_before_response(
                    error,
                    "request connection reset before the request was delivered",
                )
            raise
        try:
            stream.shutdown(socket.SHUT_WR)
        except OSError as error:
            if not _is_reset(error):
                raise
        return _read_response(
            stream,
            started=started,
            deadline=deadline,
            timeout_message="response read exceeded client-side safety timeout",
            reset_message="response connection reset before any response bytes",
        )


def trickle_request(host: str, port: int, address: str) -> core.HttpResponse:
    stream = socket.create_connection((host, port), timeout=10.0)
    started = time.monotonic()
    try:
        stream.settimeout(10.0)
        stream.sendall(
            f"GET /v1/sys/health HTTP/1.1\r\nHost: {address}\r\nX-Trickle: ".encode(
                "ascii"
            )
        )
        for _ in range(12):
            time.sleep(0.4)
            try:
                stream.sendall(b"a")
            except OSError as error:
                if _is_reset(error):
                    break
                raise
        return _read_response(
            stream,
            started=started,
            deadline=started + core.MAX_OBSERVED_SECONDS,
            timeout_message="trickled request exceeded the eight-second matrix bound",
            reset_message="trickled request reset before any response bytes",
        )
    finally:
        stream.close()


def _audit_fields(line: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for item in line.split():
        name, separator, value = item.partition("=")
        if separator and name and name not in fields:
            fields[name] = value
    return fields


def _delivery_attempt_matches(lines: list[str], detail: str) -> bool:
    """Require one request-bound acceptance/response/delivery audit graph."""

    parsed = [_audit_fields(line) for line in lines]
    delivery = [item for item in parsed if item.get("detail") == detail]
    if len(delivery) != 1:
        return False
    request_id = delivery[0].get("request_id")
    if not request_id:
        return False
    related = [item for item in parsed if item.get("request_id") == request_id]
    if len(related) < 3:
        return False

    expected = {
        "response-delivery-failed-before-commit": {
            "operation": "KvRead",
            "response_detail": "response-prepared",
            "response_phase": "ResponsePrepared",
            "delivery_commit": "NotCommitted",
        },
        "response-delivery-failed-after-commit": {
            "operation": "KvWrite",
            "response_detail": "response-committed",
            "response_phase": "ResponseCommitted",
            "delivery_commit": "Committed",
        },
    }.get(detail)
    if expected is None:
        return False

    accepted = any(
        item.get("phase") == "RequestAccepted"
        and item.get("operation") == expected["operation"]
        and item.get("detail") == "dispatch-authorized"
        for item in related
    )
    response_audited = any(
        item.get("phase") == expected["response_phase"]
        and item.get("operation") == expected["operation"]
        and item.get("detail") == expected["response_detail"]
        for item in related
    )
    delivery_bound = (
        delivery[0].get("operation") == "NONE"
        and delivery[0].get("status") == "503"
        and delivery[0].get("commit") == expected["delivery_commit"]
    )
    return accepted and response_audited and delivery_bound


def force_delivery_failure_detail(
    host: str,
    port: int,
    address: str,
    audit_path,
    *,
    detail: str,
    raw: bytes,
) -> int:
    """Observe one exact request's delivery failure under bounded RST retries."""

    del address
    attempts = 0
    diagnostics: list[str] = []
    for settle in (0.0, 0.0002, 0.0005, 0.001, 0.002, 0.004) * 8:
        attempts += 1
        start_line = len(core.audit_lines(audit_path))
        try:
            core.send_reset(host, port, raw, settle)
        except OSError as error:
            diagnostics.append(f"attempt={attempts} socket={type(error).__name__}:{error}")
        deadline = time.monotonic() + 0.15
        while time.monotonic() < deadline:
            lines = core.audit_lines(audit_path)[start_line:]
            if _delivery_attempt_matches(lines, detail):
                return attempts
            time.sleep(0.005)
        diagnostics.extend(core.audit_lines(audit_path)[start_line:][-8:])

    raise core.MatrixFailure(
        f"request-bound response delivery failure evidence {detail!r} not observed "
        f"after {attempts} RST attempts; tail={diagnostics[-20:]!r}"
    )


# The core functions resolve these names from their defining module globals.
# Patch those exact globals before exposing the inherited CLI and tests.
core.exchange = exchange
core.trickle_request = trickle_request
core.force_delivery_failure_detail = force_delivery_failure_detail

# Preserve the historical white-box test seam. A wildcard import intentionally
# omits underscore-prefixed names, and assignment to this wrapper module does
# not mutate the delegated core module. Synchronize the one mutable probe-state
# hook immediately before delegating failure classification.
_ACTIVE_RESULTS = core._ACTIVE_RESULTS


def failure_cases(error: BaseException) -> list[dict[str, object]]:
    core._ACTIVE_RESULTS = _ACTIVE_RESULTS
    return core.failure_cases(error)


if __name__ == "__main__":
    raise SystemExit(core.main())
