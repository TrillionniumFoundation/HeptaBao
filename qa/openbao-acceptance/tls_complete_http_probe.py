#!/usr/bin/env python3
"""Read one complete, pinned TLS health response without early client close."""

import argparse
import hashlib
import http.client
import json
import pathlib
import socket
import ssl
import time


def probe(host, port, server_name, ca_file, expected_leaf, origin):
    started = time.monotonic()
    deadline = started + 15
    record = {"origin": origin, "destination": host + ":" + str(port),
              "server_name": server_name, "request_count": 0,
              "tls_verified": False, "http_response_complete": False,
              "passed": False, "initialization_performed": False,
              "credential_supplied": False, "timeout_seconds": 15}
    context = ssl.create_default_context(cafile=str(ca_file))
    raw = None
    tls = None
    response = None
    try:
        raw = socket.create_connection((host, port), timeout=min(5, deadline - time.monotonic()))
        raw.settimeout(max(0.001, deadline - time.monotonic()))
        tls = context.wrap_socket(raw, server_hostname=server_name)
        record.update(tls=tls.version(), leaf_sha256=hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest())
        if record["leaf_sha256"] != expected_leaf:
            raise ValueError("verified certificate differs from required leaf pin")
        record["tls_verified"] = True
        tls.settimeout(max(0.001, deadline - time.monotonic()))
        request = ("GET /v1/sys/health HTTP/1.1\r\nHost: " + server_name
                   + ":" + str(port) + "\r\nConnection: close\r\n\r\n").encode("ascii")
        record["request_count"] = 1
        tls.sendall(request)
        tls.settimeout(max(0.001, deadline - time.monotonic()))
        response = http.client.HTTPResponse(tls)
        response.begin()
        record.update(http_version=response.version, status=response.status, reason=response.reason)
        length = response.getheader("Content-Length")
        if not length or not length.isdecimal() or int(length) > 65536 or response.getheader("Transfer-Encoding"):
            raise ValueError("response lacks the required bounded Content-Length framing")
        tls.settimeout(max(0.001, deadline - time.monotonic()))
        body = response.read(int(length) + 1)
        record.update(content_length=int(length), body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest())
        if len(body) != int(length):
            raise ValueError("incomplete HTTP response body")
        value = json.loads(body)
        record.update(http_response_complete=True, initialized=value.get("initialized"), sealed=value.get("sealed"))
        if response.status != 501 or value.get("initialized") is not False:
            raise ValueError("owned uninitialized fixture did not return complete HTTP 501 health")
        if time.monotonic() > deadline:
            raise TimeoutError("whole probe deadline expired")
        record["passed"] = True
    except Exception as error:
        record.update(error_type=type(error).__name__, error=str(error))
    finally:
        if response is not None:
            response.close()
        if tls is not None:
            tls.close()
        elif raw is not None:
            raw.close()
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--ca-file", required=True, type=pathlib.Path)
    parser.add_argument("--expected-leaf", required=True)
    parser.add_argument("--origin", required=True)
    arguments = parser.parse_args()
    result = probe(arguments.host, arguments.port, arguments.server_name,
                   arguments.ca_file, arguments.expected_leaf, arguments.origin)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
