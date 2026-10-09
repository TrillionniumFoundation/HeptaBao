#!/usr/bin/env python3
"""Read-only OpenBao 2.7 KV2 export and single atomic HeptaBao import."""
import time
_ENTRY = time.monotonic()

import argparse
import importlib.util
import base64
import collections
import decimal
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import ssl
import stat
import sys
import signal
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

# Isolated workers load only the adjacent, explicit decoder; no Python path search.
_decoder_path = pathlib.Path(__file__).resolve().with_name("kv2_lossless_raw.py")
_decoder_spec = importlib.util.spec_from_file_location("kv2_lossless_raw", _decoder_path)
_decoder_module = importlib.util.module_from_spec(_decoder_spec)
sys.modules["kv2_lossless_raw"] = _decoder_module
_decoder_spec.loader.exec_module(_decoder_module)

from kv2_lossless_raw import (
    DecodeError, MAX_RECORD, MAX_RECORDS, MAX_TOTAL, decode_records,
    dumps_lossless, need, unicode_scalar, unique_object,
)

MAX_BUNDLE = 16 * 1024 * 1024
MAX_RESPONSE = 2 * MAX_RECORD
TIMEOUT = 5
DEADLINE = 360

def parse_json(raw, maximum):
    need(isinstance(raw, bytes) and len(raw) <= maximum, "JSON byte bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_int=decimal.Decimal, parse_float=decimal.Decimal,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               DecodeError("nonfinite JSON number")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise DecodeError("invalid bounded UTF8 JSON") from error
    pending = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        need(depth <= 128 and nodes <= 1000000, "JSON structural bound")
        if isinstance(current, dict):
            pending.extend((v, depth + 1) for v in current.values())
        elif isinstance(current, list):
            pending.extend((v, depth + 1) for v in current)
        elif isinstance(current, str):
            unicode_scalar(current)
    return value

def private_read(path, maximum):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
             and info.st_nlink == 1 and info.st_mode & 0o077 == 0
             and info.st_size <= maximum, "input requires a private regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        need((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
              info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_nlink,
              after.st_size, after.st_mtime_ns, after.st_ctime_ns)
             and len(raw) == info.st_size, "input changed while read")
        return raw
    finally:
        os.close(fd)

def canonical_path(value, label):
    need(isinstance(value, str) and 0 < len(value.encode("utf-8")) <= 1024
         and not value.startswith("/") and not value.endswith("/")
         and all(part not in ("", ".", "..") for part in value.split("/"))
         and not any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in "\\%?#"
                     for c in value), label)
    return value

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("HTTP redirect refused")

class Client:
    def __init__(self, address, token, namespace="", ca_file=None, *, end=None):
        url = urllib.parse.urlsplit(address)
        need(url.scheme in ("http", "https") and url.hostname
             and not url.username and not url.password and not url.query
             and not url.fragment and url.path in ("", "/"),
             "address must be an HTTP(S) origin")
        if url.scheme == "http":
            try:
                need(ipaddress.ip_address(url.hostname).is_loopback,
                     "cleartext address must be a literal loopback IP")
            except ValueError as error:
                raise DecodeError("cleartext address must be a literal loopback IP") from error
        need(isinstance(token, str) and 0 < len(token) <= 65536
             and all(32 < ord(c) < 127 for c in token), "invalid token file")
        if namespace:
            canonical_path(namespace.rstrip("/"), "invalid namespace")
        self.address = address.rstrip("/")
        self.headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
        if namespace:
            self.headers["X-Vault-Namespace"] = namespace.rstrip("/")
        self.ca_file = ca_file
        self.end = _ENTRY + DEADLINE if end is None else end
        self.last_request_lifecycle = None

    def request(self, method, path, body=None):
        remaining = self.end - time.monotonic()
        need(remaining > 0, "migration original deadline exceeded")
        request_end = min(self.end, time.monotonic() + TIMEOUT)
        packet = json.dumps({
            "address": self.address, "headers": self.headers, "ca_file": self.ca_file,
            "method": method, "path": path,
            "body": None if body is None else base64.b64encode(body).decode("ascii"),
        }, separators=(",", ":")).encode("utf-8")
        need(len(packet) <= MAX_BUNDLE * 2, "HTTP input byte bound")
        leaf = pathlib.Path(__file__).resolve().with_name("kv2_http_once.py")
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", str(leaf)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lifecycle = {"pid": process.pid, "original_popen": True, "planned_signal": None,
                     "returncode": None, "original_wait_completed": False}
        self.last_request_lifecycle = lifecycle
        try:
            try:
                raw, errors = process.communicate(packet, timeout=max(0, request_end - time.monotonic()))
            except subprocess.TimeoutExpired:
                # This exact leaf is trusted, installs no signal handlers, and is never retried.
                lifecycle["planned_signal"] = signal.SIGTERM
                process.terminate()
                try:
                    raw, errors = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    # Default CLI's outer owned session supervisor will terminate the
                    # same group at the original deadline. Do not leave a live leaf
                    # while reporting an ordinary completed failure.
                    process.wait()
                    raise DecodeError("HTTP leaf termination wait exceeded")
                raise DecodeError("migration HTTP absolute request deadline exceeded; no retry performed")
            lifecycle["returncode"] = process.returncode
            lifecycle["original_wait_completed"] = True
            need(time.monotonic() < request_end, "migration HTTP absolute request deadline exceeded")
            need(process.returncode == 0 and not errors, "migration HTTP failed; no retry performed")
            need(len(raw) <= MAX_RESPONSE + 128, "HTTP output byte bound")
            header, separator, response = raw.partition(b"\n")
            need(separator == b"\n" and len(header) <= 128, "HTTP helper response framing")
            metadata = json.loads(header)
            need(isinstance(metadata, dict) and set(metadata) == {"status"}
                 and type(metadata["status"]) is int, "HTTP helper status framing")
            status = metadata["status"]
            need(status in (200, 204), "migration HTTP status " + str(status))
            if status == 204:
                need(not response, "unexpected body for HTTP 204")
                return None
            value = parse_json(response, MAX_RESPONSE)
            need(isinstance(value, dict), "HTTP response must be an object")
            need(time.monotonic() < request_end, "migration HTTP absolute request deadline exceeded")
            return value
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait()
            lifecycle["returncode"] = process.returncode
            lifecycle["original_wait_completed"] = True

    def mount(self, mount):
        response = self.request("GET", "sys/mounts")
        data = response.get("data")
        need(isinstance(data, dict), "mount registry missing")
        entry = data.get(mount + "/")
        need(isinstance(entry, dict) and entry.get("type") == "kv"
             and isinstance(entry.get("options"), dict)
             and entry["options"].get("version") == "2", "source mount is not KV2")
        uuid = entry.get("uuid")
        need(isinstance(uuid, str) and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", uuid),
            "source mount UUID missing")
        return uuid

def acquire(client, uuid):
    root = "logical/" + uuid + "/"
    queue = collections.deque([(root, 0)])
    seen = set()
    records = {}
    total = 0
    while queue:
        path, depth = queue.popleft()
        need(path not in seen and len(seen) < 20000 and depth <= 8,
             "raw prefix bound or alias")
        seen.add(path)
        quoted = urllib.parse.quote(path, safe="/")
        response = client.request("LIST", "sys/raw/" + quoted)
        data = response.get("data")
        need(isinstance(data, dict), "raw list data missing")
        keys = data.get("keys")
        need(isinstance(keys, list) and len(keys) <= MAX_RECORDS,
             "raw list bound")
        children = set()
        for key in keys:
            need(isinstance(key, str) and key not in children, "duplicate raw child")
            children.add(key)
            directory = key.endswith("/")
            child = key[:-1] if directory else key
            canonical_path(child, "invalid raw child")
            need("/" not in child, "raw child must be one segment")
            full = path + key
            need(full.startswith(root), "raw mount boundary")
            if directory:
                queue.append((full, depth + 1))
                continue
            need(full not in records and len(records) < MAX_RECORDS, "raw record count")
            response = client.request("GET", "sys/raw/" +
                                      urllib.parse.quote(full, safe="/") +
                                      "?encoding=base64&compressed=false")
            value = response.get("data", response)
            need(isinstance(value, dict) and isinstance(value.get("value"), str),
                 "raw base64 value missing")
            encoded = value["value"]
            need(len(encoded) <= 4 * ((MAX_RECORD + 2) // 3), "raw base64 bound")
            try:
                raw = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError) as error:
                raise DecodeError("invalid raw base64") from error
            need(len(raw) <= MAX_RECORD, "raw record bound")
            total += len(raw)
            need(total <= MAX_TOTAL, "raw aggregate bound")
            records[full] = raw
    return records

def export_bundle(client, mount):
    canonical_path(mount, "invalid mount")
    uuid = client.mount(mount)
    first = acquire(client, uuid)
    need(client.mount(mount) == uuid, "source mount changed during export")
    second = acquire(client, uuid)
    need(client.mount(mount) == uuid and first == second,
         "source records changed during export; no output produced")
    raw = dumps_lossless(decode_records(sorted(first.items()))).encode("utf-8")
    need(len(raw) <= MAX_BUNDLE, "native bundle capacity exceeded")
    return raw, len(first)

def import_bundle(client, mount, raw):
    canonical_path(mount, "invalid mount")
    value = parse_json(raw, MAX_BUNDLE)
    need(isinstance(value, dict) and set(value) == {"schema", "config", "entries"}
         and value["schema"] == "openbao270-kv2-lossless-v1"
         and isinstance(value["config"], dict)
         and isinstance(value["entries"], dict) and len(value["entries"]) <= 10000,
         "invalid native KV2 bundle")
    body = ('{"mount":' + json.dumps(mount, ensure_ascii=False) +
            ',"bundle":' + dumps_lossless(value) + '}').encode("utf-8")
    need(len(body) <= MAX_BUNDLE, "native request capacity exceeded")
    # Native owner validates every record and publishes once into a pristine KV2 mount.
    # Never retry this write after an uncertain transport outcome.
    result = client.request("POST", "sys/migration/openbao/kv2", body)
    need(result is None, "native import requires HTTP 204")

def check_deadline(end):
    need(time.monotonic() < end, "migration original deadline exceeded")


def exclusive_output(path, raw, *, end):
    check_deadline(end)
    destination = pathlib.Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".kv2-migration-", dir=str(destination.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            for start in range(0, len(raw), 65536):
                check_deadline(end)
                stream.write(raw[start:start + 65536])
            stream.flush()
            os.fsync(stream.fileno())
        check_deadline(end)
        # POSIX exclusive atomic publication. The private staging name is then
        # removed, leaving one link; an existing destination is never replaced.
        os.link(temporary, destination, follow_symlinks=False)
        os.unlink(temporary)
        temporary = None
        check_deadline(end)
    finally:
        if temporary is not None:
            os.unlink(temporary)


def main(argv=None, *, end=None):
    end = _ENTRY + DEADLINE if end is None else end
    check_deadline(end)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("export", "import"))
    parser.add_argument("--address", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--mount", required=True)
    parser.add_argument("--namespace", default="")
    parser.add_argument("--ca-file")
    parser.add_argument("--input")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    need((args.operation == "export" and args.output and not args.input) or
         (args.operation == "import" and args.input and not args.output),
         "export requires --output; import requires --input")
    token = private_read(args.token_file, 65536).decode("ascii").strip()
    client = Client(args.address, token, args.namespace, args.ca_file, end=end)
    if args.operation == "export":
        raw, count = export_bundle(client, args.mount)
        exclusive_output(args.output, raw, end=end)
        receipt = {"operation": "export", "records": count, "bytes": len(raw),
                   "sha256": hashlib.sha256(raw).hexdigest()}
    else:
        raw = private_read(args.input, MAX_BUNDLE)
        import_bundle(client, args.mount, raw)
        receipt = {"operation": "import", "status": 204,
                   "source_sha256": hashlib.sha256(raw).hexdigest()}
    check_deadline(end)
    print(json.dumps(receipt, sort_keys=True))

def supervise(argv, *, end=None):
    # Linux/macOS process groups provide an owned lifecycle for the worker and
    # all HTTP leaves. Other platforms fail before any input or HTTP action.
    need(os.name == "posix", "absolute migration supervisor requires POSIX process groups")
    end = _ENTRY + DEADLINE if end is None else end
    check_deadline(end)
    script = pathlib.Path(__file__).resolve()
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", "-B", str(script), "--_owned-worker"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True)
    lifecycle = {"pid": process.pid, "pgid": process.pid, "original_popen": True,
                 "planned_signal": None, "returncode": None, "original_wait_completed": False}
    supervise.last_lifecycle = lifecycle
    try:
        try:
            stdout, stderr = process.communicate(
                json.dumps({"argv": list(argv), "end": end}).encode("utf-8"),
                timeout=max(0, end - time.monotonic()))
        except subprocess.TimeoutExpired:
            lifecycle["planned_signal"] = signal.SIGTERM
            os.killpg(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            raise DecodeError("migration original absolute deadline exceeded")
        lifecycle["returncode"] = process.returncode
        lifecycle["original_wait_completed"] = True
        check_deadline(end)
        need(len(stdout) <= 4096 and len(stderr) <= 4096, "worker output bound")
        if process.returncode:
            # Trusted worker diagnostics contain no URL, credential or response body.
            sys.stderr.buffer.write(stderr)
            return process.returncode, lifecycle
        need(not stderr, "unexpected worker diagnostics")
        sys.stdout.buffer.write(stdout)
        return 0, lifecycle
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        lifecycle["returncode"] = process.returncode
        lifecycle["original_wait_completed"] = True


def owned_worker():
    raw = sys.stdin.buffer.read(65537)
    need(len(raw) <= 65536, "worker input bound")
    packet = json.loads(raw)
    need(isinstance(packet, dict) and set(packet) == {"argv", "end"}
         and isinstance(packet["argv"], list)
         and all(isinstance(x, str) for x in packet["argv"])
         and type(packet["end"]) in (int, float), "worker input framing")
    check_deadline(packet["end"])
    main(packet["argv"], end=packet["end"])


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--_owned-worker"]:
            owned_worker()
        else:
            code, _ = supervise(sys.argv[1:])
            raise SystemExit(code)
    except (DecodeError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        # Avoid printing transport URLs, server error bodies or file contents.
        print("KV2 migration failed: " +
              (str(error) if isinstance(error, DecodeError) else type(error).__name__),
              file=sys.stderr)
        raise SystemExit(1)
