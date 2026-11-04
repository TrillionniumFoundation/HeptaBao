"""One native-large HTTP/1.1 request; private input arrives only on stdin."""
import hashlib
import http.client
import json
import ssl
import sys
import urllib.parse

MAX_INPUT = 96 * 1024 * 1024
MAX_BODY = 64 * 1024 * 1024
MAX_RESPONSE = 8 * 1024 * 1024
CONTENT_TYPE = "application/vnd.heptabao.kv2-lossless+json"
INPUT_MAGIC = b"HBKV2HTTP1\n"
MAX_HEADER = 128 * 1024


def main():
    source = sys.stdin.buffer
    if source.read(len(INPUT_MAGIC)) != INPUT_MAGIC:
        raise ValueError("input version")
    header = source.readline(MAX_HEADER + 1)
    if len(header) > MAX_HEADER or not header.endswith(b"\n"):
        raise ValueError("header bound")
    packet = json.loads(header)
    if not isinstance(packet, dict) or set(packet) != {
            "address", "headers", "ca_file", "method", "path", "body_bytes", "body_sha256"}:
        raise ValueError("input framing")
    length, expected_digest = packet["body_bytes"], packet["body_sha256"]
    if length is None:
        if expected_digest is not None or source.read(1):
            raise ValueError("absent body framing")
        body = None
    else:
        if (type(length) is not int or not 0 <= length <= MAX_BODY
                or len(INPUT_MAGIC) + len(header) + length > MAX_INPUT
                or not isinstance(expected_digest, str) or len(expected_digest) != 64
                or any(c not in "0123456789abcdef" for c in expected_digest)):
            raise ValueError("body framing")
        # Read at most one byte beyond the declared body. This simultaneously
        # rejects truncation and trailing data before any connection is made.
        body = source.read(length + 1)
        if len(body) != length or hashlib.sha256(body).hexdigest() != expected_digest:
            raise ValueError("body binding")
    url = urllib.parse.urlsplit(packet["address"])
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in ("", "/")):
        raise ValueError("TLS origin required")
    headers = packet["headers"]
    if not isinstance(headers, dict) or set(headers) not in (
            {"X-Vault-Token", "Content-Type"},
            {"X-Vault-Token", "Content-Type", "X-Vault-Namespace"}):
        raise ValueError("header framing")
    if any(not isinstance(value, str) or "\r" in value or "\n" in value
           for value in headers.values()):
        raise ValueError("invalid headers")
    method, path = packet["method"], packet["path"]
    if (method not in ("GET", "LIST", "POST") or not isinstance(path, str)
            or not path or path.startswith("/") or "#" in path
            or any(ord(c) < 32 for c in path)):
        raise ValueError("fixed operation framing")
    if method == "POST":
        query = urllib.parse.urlsplit("/" + path)
        pairs = urllib.parse.parse_qsl(query.query, keep_blank_values=True, strict_parsing=True)
        if (query.path != "/sys/migration/openbao/kv2/native-large"
                or len(pairs) != 1 or pairs[0][0] != "mount" or not pairs[0][1]
                or headers["Content-Type"] != CONTENT_TYPE
                or "X-Vault-Namespace" in headers or not body):
            raise ValueError("native import framing")
    elif body is not None or headers["Content-Type"] != "application/json":
        raise ValueError("read framing")
    context = ssl.create_default_context(cafile=packet["ca_file"])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # http.client uses HTTP/1.1, does not redirect or use environment proxies,
    # and sends an exact Content-Length for these byte bodies. No caller can
    # supply Expect, Transfer-Encoding, arbitrary headers or duplicate lengths.
    connection = http.client.HTTPSConnection(url.hostname, url.port or 443,
                                             context=context, timeout=5)
    try:
        connection.request(method, "/v1/" + path, body=body, headers=headers)
        response = connection.getresponse()
        status = response.status
        if 300 <= status < 400:
            raise ValueError("redirect refused")
        if status not in (200, 204):
            # Do not echo provider diagnostics or secret response bodies.
            sys.stdout.buffer.write(json.dumps({"status": status}).encode("ascii") + b"\n")
            return
        result = response.read(MAX_RESPONSE + 1)
        if len(result) > MAX_RESPONSE:
            raise ValueError("response bound")
        sys.stdout.buffer.write(json.dumps({"status": status}).encode("ascii") + b"\n" + result)
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.stderr.write("HTTP native-large leaf failed\n")
        raise SystemExit(1)
