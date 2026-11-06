"""One private TLS request leaf. It never launches a service or retries.

Only the parent can admit this leaf through the pinned original-process custody
owner. The parent enforces the original absolute deadline, at most 15 seconds.
"""
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
from urllib.parse import urlsplit

MIB = 1024 * 1024


def need(value):
    if not value:
        raise ValueError("formal_kv2_wire_contract")


def private_read(path, maximum, expected):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        before = os.fstat(source.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and not before.st_mode & 0o077 and before.st_size <= maximum)
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        need(all(getattr(before, key) == getattr(after, key) for key in fields)
             and len(raw) == before.st_size == expected["bytes"]
             and hashlib.sha256(raw).hexdigest() == expected["sha256"])
        return raw


def content_length(response, maximum, binary):
    lengths = response.headers.get_all("Content-Length", [])
    transfers = response.headers.get_all("Transfer-Encoding", [])
    need(response.getheader("Content-Encoding") in (None, "identity"))
    if transfers:
        need(not binary and transfers == ["chunked"] and not lengths)
        return None
    if not lengths:
        need(not binary and (response.status in (204, 304) or 100 <= response.status < 200))
        return 0
    need(len(lengths) == 1 and re.fullmatch(r"[0-9]{1,10}", lengths[0]))
    length = int(lengths[0])
    need(length <= maximum)
    return length


def main():
    packet_raw = sys.stdin.buffer.read(6 * MIB + 1)
    need(len(packet_raw) <= 6 * MIB)
    p = json.loads(packet_raw)
    need(set(p) == {"origin", "ca_file", "ca_pin", "root_file", "root_pin", "leaf_sha256",
                    "method", "path", "body", "download", "upload", "upload_pin", "maximum", "timeout"})
    origin = urlsplit(p["origin"])
    need(origin.scheme == "https" and not origin.username and not origin.password
         and not origin.path and not origin.query and not origin.fragment and origin.port is not None)
    ip = ipaddress.ip_address(origin.hostname)
    need(ip.is_loopback or (ip.version == 4 and any(ip in ipaddress.ip_network(cidr)
         for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))))
    need(1024 <= origin.port <= 65535 and 0 < p["timeout"] <= 15
         and p["method"] in ("GET", "POST", "LIST"))
    need(isinstance(p["path"], str) and p["path"] and not p["path"].startswith("/")
         and all(32 < ord(c) < 127 for c in p["path"]) and "#" not in p["path"])
    ca = private_read(p["ca_file"], MIB, p["ca_pin"])
    credential = private_read(p["root_file"], 16385, p["root_pin"])
    token = credential[:-1] if credential.endswith(b"\n") else credential
    need(0 < len(token) <= 16384 and all(32 < c < 127 for c in token))
    body = None if p["body"] is None else base64.b64decode(p["body"], validate=True)
    need(body is None or len(body) <= 3 * MIB)
    need(not (p["download"] and p["upload"]))
    if p["upload"]:
        need(p["method"] == "POST" and p["path"] == "sys/storage/raft/snapshot" and body is None)
        body = private_read(p["upload"], 128 * MIB, p["upload_pin"])
    maximum = p["maximum"]
    need(type(maximum) is int and maximum in (4 * MIB, 64 * MIB, 128 * MIB))
    context = ssl.create_default_context(cadata=ca.decode("ascii"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    need(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname)
    connection = http.client.HTTPSConnection(str(ip), origin.port, context=context, timeout=p["timeout"])
    try:
        connection.connect()
        leaf = connection.sock.getpeercert(binary_form=True)
        need(leaf and hashlib.sha256(leaf).hexdigest() == p["leaf_sha256"])
        connection.request(p["method"], "/v1/" + p["path"], body=body, headers={
            "X-Vault-Token": token.decode("ascii"), "Accept": "application/json",
            "Content-Type": "application/octet-stream" if p["upload"] else "application/json",
            "Connection": "close"})
        response = connection.getresponse()
        need(not 300 <= response.status <= 399)
        binary = p["download"] is not None and response.status == 200
        limit = maximum if binary else 4 * MIB
        length = content_length(response, limit, binary)
        headers = {name: response.getheader(name) for name in ("Content-Length", "Content-Type")}
        if binary:
            is_export = p["path"].startswith("sys/migration/openbao/kv2/export?mount=")
            need(p["method"] == "GET" and (is_export or p["path"] == "sys/storage/raft/snapshot"))
            need(headers["Content-Type"] == (
                "application/vnd.heptabao.kv2-lossless+json" if is_export else "application/gzip"))
            need(limit == (64 * MIB if is_export else 128 * MIB))
            target = Path(p["download"])
            parent = target.parent.lstat()
            need(target.is_absolute() and target.parent.resolve(strict=True) == target.parent
                 and stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
                 and stat.S_IMODE(parent.st_mode) == 0o700)
            count = 0
            with os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as output:
                while chunk := response.read1(65536):
                    count += len(chunk)
                    need(count <= limit)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            need(count == length)
            directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                actual_parent = os.fstat(directory_fd)
                need((actual_parent.st_dev, actual_parent.st_ino, actual_parent.st_uid, actual_parent.st_mode)
                     == (parent.st_dev, parent.st_ino, parent.st_uid, parent.st_mode))
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            raw = b""
        else:
            raw = response.read(limit + 1)
            need(len(raw) <= limit and (length is None or length == len(raw)))
        result = {"status": response.status, "body": base64.b64encode(raw).decode("ascii"),
                  "origin": p["origin"], "peer_leaf_sha256": hashlib.sha256(leaf).hexdigest(),
                  "ca_sha256": hashlib.sha256(ca).hexdigest(), "headers": headers,
                  "downloaded_file": p["download"] if binary else None}
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        need(sys.argv[1:] == ["--_wire"])
        main()
    except BaseException:
        sys.stderr.write("formal_kv2_private_wire_failed\n")
        raise SystemExit(1)
