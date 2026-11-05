#!/usr/bin/env python3
"""One owned, bounded TLS request for the official-history physical fixture.

The controller enforces the original absolute 15-second deadline and reaps this
original child before proceeding. This leaf never retries or follows redirects.
Its enrolled IP, CA and leaf digest all bind the same TLS connection.
"""
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys

MIB = 1024 * 1024
MAX_ARCHIVE = 131 * MIB


def require(value):
    if not value:
        raise ValueError("official_history_wire_contract")


def private_read(path, maximum):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and not before.st_mode & 0o077
                and 0 <= before.st_size <= maximum)
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                row.st_mtime_ns, row.st_ctime_ns)
        require(identity(before) == identity(after) and len(raw) == before.st_size)
        return raw


def response_length(response, maximum, *, binary=False):
    lengths = response.headers.get_all("Content-Length", [])
    encodings = response.headers.get_all("Transfer-Encoding", [])
    if encodings:
        require(not binary and not lengths and len(encodings) == 1
                and encodings[0].lower() == "chunked")
        return None
    if not lengths:
        require(not binary and (response.status in (204, 304) or 100 <= response.status < 200))
        return 0
    require(len(lengths) == 1 and re.fullmatch(r"[0-9]{1,10}", lengths[0]) is not None)
    length = int(lengths[0])
    require(length <= maximum)
    return length


def main():
    packet = json.loads(sys.stdin.buffer.read(6 * MIB + 1))
    require(set(packet) == {"ip", "port", "ca_file", "ca_sha256", "leaf_sha256",
                           "token", "method", "path", "body", "archive_in",
                           "archive_sha256", "archive_out"})
    ip = ipaddress.ip_address(packet["ip"])
    ranges = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    require(ip.version == 4 and any(ip in ipaddress.ip_network(item) for item in ranges)
            and type(packet["port"]) is int and 1024 <= packet["port"] <= 65535)
    require(packet["method"] in ("GET", "POST", "DELETE", "LIST")
            and isinstance(packet["path"], str)
            and re.fullmatch(r"(?:oracle271/(?:config|metadata/history|data/history|undelete/history)"
                             r"(?:\?version=(?:[1-9]|1[0-9]|20))?|sys/storage/raft/snapshot|"
                             r"sys/migration/openbao/kv2/export\?mount=oracle271)",
                             packet["path"]) is not None)
    for name in ("ca_sha256", "leaf_sha256"):
        require(isinstance(packet[name], str)
                and re.fullmatch(r"[0-9a-f]{64}", packet[name]) is not None)
    token = packet["token"]
    require(isinstance(token, str) and 0 < len(token) <= 16384
            and all(32 < ord(char) < 127 for char in token))
    ca = private_read(packet["ca_file"], MIB)
    require(hashlib.sha256(ca).hexdigest() == packet["ca_sha256"])
    body = None if packet["body"] is None else base64.b64decode(packet["body"], validate=True)
    require(body is None or len(body) <= 4 * MIB)
    if packet["archive_in"] is not None:
        require(packet["method"] == "POST" and packet["path"] == "sys/storage/raft/snapshot"
                and body is None and packet["archive_out"] is None)
        body = private_read(packet["archive_in"], MAX_ARCHIVE)
        require(hashlib.sha256(body).hexdigest() == packet["archive_sha256"])
    context = ssl.create_default_context(cadata=ca.decode("ascii"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    tcp = socket.create_connection((str(ip), packet["port"]), timeout=15)
    connection = http.client.HTTPConnection(str(ip), packet["port"], timeout=15)
    try:
        # SAN validation names the exact enrolled IP used for this connection.
        connection.sock = context.wrap_socket(tcp, server_hostname=str(ip))
        leaf = connection.sock.getpeercert(binary_form=True)
        require(leaf and hashlib.sha256(leaf).hexdigest() == packet["leaf_sha256"])
        connection.request(packet["method"], "/v1/" + packet["path"], body=body,
            headers={"X-Vault-Token": token, "Accept": "application/json",
                     "Content-Type": "application/octet-stream" if packet["archive_in"] else "application/json",
                     "Connection": "close"})
        response = connection.getresponse()
        metadata = {"status": response.status, "leaf_sha256": packet["leaf_sha256"]}
        if packet["archive_out"] is not None and response.status == 200:
            require(packet["method"] == "GET" and packet["path"] in (
                "sys/storage/raft/snapshot", "sys/migration/openbao/kv2/export?mount=oracle271"))
            export = packet["path"].startswith("sys/migration/")
            maximum = 64 * MIB if export else MAX_ARCHIVE
            declared = response_length(response, maximum, binary=True)
            require(response.getheader("Content-Type") == (
                "application/vnd.heptabao.kv2-lossless+json" if export else "application/gzip"))
            path = Path(packet["archive_out"])
            parent = path.parent.lstat()
            require(path.parent.resolve(strict=True) == path.parent
                    and stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
                    and not parent.st_mode & 0o077)
            digest, count = hashlib.sha256(), 0
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                   0o600), "wb") as output:
                while chunk := response.read1(64 * 1024):
                    count += len(chunk)
                    require(count <= maximum)
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            require(count == declared)
            metadata.update(archive_bytes=count, archive_sha256=digest.hexdigest())
            raw = b""
        else:
            declared = response_length(response, 4 * MIB)
            raw = response.read(4 * MIB + 1)
            require(len(raw) <= 4 * MIB and (declared is None or len(raw) == declared))
        sys.stdout.buffer.write(json.dumps(metadata, sort_keys=True).encode() + b"\n" + raw)
    finally:
        connection.close()
        tcp.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Do not emit server bodies, credentials, paths or exception messages.
        sys.stderr.write("official_history_wire_failed\n")
        raise SystemExit(1)
