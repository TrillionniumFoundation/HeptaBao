#!/usr/bin/env python3
"""Bounded OpenBao 2.7.1 raw export and one dedicated native V6 large import.

Legacy decoder defaults, CLI limits and HTTP helper are unchanged. This lane
selects an immutable explicit decoder policy and a separate HTTP/1.1 endpoint.
It never retries an import with an unknown outcome.
"""
import time
_ENTRY = time.monotonic()

import argparse
import base64
import collections
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import urllib.parse

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "kv2_native_large_legacy_primitives", _HERE / "openbao270_kv2_migrate.py")
legacy = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = legacy
_spec.loader.exec_module(legacy)
decoder = legacy._decoder_module
DecodeError, need = decoder.DecodeError, decoder.need

DEADLINE = 360
REQUEST_SECONDS = 5
CONTENT_TYPE = "application/vnd.heptabao.kv2-lossless+json"


@dataclass(frozen=True)
class Limits:
    """Fixed bounds selected by this executable, never read from request JSON."""
    raw: decoder.Bounds = decoder.NATIVE_LARGE_BOUNDS
    bundle_bytes: int = 64 * 1024 * 1024
    response_bytes: int = 8 * 1024 * 1024
    input_bytes: int = 96 * 1024 * 1024

    def __post_init__(self):
        need(self.raw == decoder.NATIVE_LARGE_BOUNDS
             and self.bundle_bytes == 64 * 1024 * 1024
             and self.response_bytes == 8 * 1024 * 1024
             and self.input_bytes == 96 * 1024 * 1024,
             "invalid native-large limits")


LIMITS = Limits()


class Client:
    def __init__(self, address, token, namespace="", ca_file=None, *, end=None, limits=LIMITS):
        origin = urllib.parse.urlsplit(address)
        need(origin.scheme == "https" and origin.hostname and not origin.username
             and not origin.password and not origin.query and not origin.fragment
             and origin.path in ("", "/"), "native-large requires a TLS origin")
        need(isinstance(token, str) and 0 < len(token) <= 65536
             and all(32 < ord(char) < 127 for char in token), "invalid token file")
        need(isinstance(limits, Limits), "invalid explicit native-large limits")
        if namespace:
            legacy.canonical_path(namespace.rstrip("/"), "invalid namespace")
        self.address, self.token = address.rstrip("/"), token
        self.namespace, self.ca_file = namespace.rstrip("/"), ca_file
        self.end = _ENTRY + DEADLINE if end is None else end
        self.limits = limits
        self.last_request_lifecycle = None

    def request(self, method, path, body=None, *, native_import=False):
        request_end = min(self.end, time.monotonic() + REQUEST_SECONDS)
        legacy.check_deadline(request_end)
        need(body is None or isinstance(body, bytes) and len(body) <= self.limits.bundle_bytes,
             "native-large body bound")
        need(native_import is (method == "POST"), "native-large operation profile")
        need(not native_import or not self.namespace, "native-large import requires root namespace")
        headers = {"X-Vault-Token": self.token,
                   "Content-Type": CONTENT_TYPE if native_import else "application/json"}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        packet = json.dumps({
            "address": self.address, "headers": headers, "ca_file": self.ca_file,
            "method": method, "path": path,
            "body": None if body is None else base64.b64encode(body).decode("ascii"),
        }, separators=(",", ":")).encode()
        need(len(packet) <= self.limits.input_bytes, "native-large HTTP input bound")
        legacy.check_deadline(request_end)
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", str(_HERE / "kv2_native_large_http_once.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lifecycle = {"pid": process.pid, "original_popen": True,
                     "planned_signal": None, "returncode": None,
                     "original_wait_completed": False, "retried": False,
                     "mutation": native_import, "status": None, "outcome": "unknown",
                     "original_request_seconds": REQUEST_SECONDS}
        self.last_request_lifecycle = lifecycle
        try:
            try:
                stdout, stderr = process.communicate(
                    packet, timeout=max(0, request_end - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                lifecycle["planned_signal"] = signal.SIGKILL
                process.kill()
                process.communicate(timeout=5)
                raise DecodeError("native-large HTTP absolute deadline exceeded; no retry performed") from error
            lifecycle["returncode"] = process.returncode
            lifecycle["original_wait_completed"] = True
            legacy.check_deadline(request_end)
            need(process.returncode == 0 and not stderr,
                 "native-large HTTP failed; no retry performed")
            need(len(stdout) <= self.limits.response_bytes + 128, "native-large HTTP output bound")
            header, separator, response = stdout.partition(b"\n")
            need(separator == b"\n" and len(header) <= 128, "native-large HTTP framing")
            metadata = json.loads(header)
            need(isinstance(metadata, dict) and set(metadata) == {"status"}
                 and type(metadata["status"]) is int, "native-large status framing")
            status = metadata["status"]
            lifecycle.update(status=status, outcome="response_received")
            need(status in (200, 204), "native-large HTTP status " + str(status))
            if status == 204:
                need(not response, "unexpected HTTP 204 body")
                legacy.check_deadline(request_end)
                return None
            value = legacy.parse_json(response, self.limits.response_bytes)
            need(isinstance(value, dict), "native-large response object required")
            legacy.check_deadline(request_end)
            return value
        finally:
            if process.poll() is None:
                lifecycle["planned_signal"] = signal.SIGKILL
                process.kill()
                process.communicate(timeout=5)
            lifecycle["returncode"] = process.returncode
            lifecycle["original_wait_completed"] = process.poll() is not None

    def mount(self, mount):
        # Existing source mount UUID/type/options validation; only request
        # execution and its explicit bounds are supplied by this client.
        return legacy.Client.mount(self, mount)


def acquire(client, uuid):
    root = "logical/" + uuid + "/"
    queue = collections.deque([(root, 0)])
    seen, records, total = set(), {}, 0
    while queue:
        legacy.check_deadline(client.end)
        path, depth = queue.popleft()
        need(path not in seen and len(seen) < 20000 and depth <= 8, "raw prefix bound or alias")
        seen.add(path)
        response = client.request("LIST", "sys/raw/" + urllib.parse.quote(path, safe="/"))
        data = response.get("data")
        need(isinstance(data, dict), "raw list data missing")
        keys = data.get("keys")
        need(isinstance(keys, list) and len(keys) <= decoder.MAX_RECORDS, "raw list bound")
        children = set()
        for key in keys:
            legacy.check_deadline(client.end)
            need(isinstance(key, str) and key not in children, "duplicate raw child")
            children.add(key)
            directory = key.endswith("/")
            child = key[:-1] if directory else key
            legacy.canonical_path(child, "invalid raw child")
            need("/" not in child, "raw child must be one segment")
            full = path + key
            need(full.startswith(root), "raw mount boundary")
            if directory:
                queue.append((full, depth + 1))
                continue
            need(full not in records and len(records) < decoder.MAX_RECORDS, "raw record count")
            response = client.request(
                "GET", "sys/raw/" + urllib.parse.quote(full, safe="/")
                + "?encoding=base64&compressed=false")
            value = response.get("data", response)
            need(isinstance(value, dict) and isinstance(value.get("value"), str),
                 "raw base64 value missing")
            encoded = value["value"]
            need(len(encoded) <= 4 * ((client.limits.raw.record_bytes + 2) // 3),
                 "raw base64 bound")
            try:
                raw = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError) as error:
                raise DecodeError("invalid raw base64") from error
            need(len(raw) <= client.limits.raw.record_bytes, "raw record bound")
            total += len(raw)
            need(total <= client.limits.raw.total_bytes, "raw aggregate bound")
            records[full] = raw
    return records


def export_bundle(client, mount):
    legacy.canonical_path(mount, "invalid mount")
    uuid = client.mount(mount)
    first = acquire(client, uuid)
    need(client.mount(mount) == uuid, "source mount changed during export")
    second = acquire(client, uuid)
    need(client.mount(mount) == uuid and first == second,
         "source records changed during export; no output produced")
    value = decoder.decode_records(sorted(first.items()), bounds=client.limits.raw)
    raw = decoder.dumps_lossless(value).encode("utf-8")
    need(len(raw) <= client.limits.bundle_bytes, "native-large bundle capacity exceeded")
    legacy.check_deadline(client.end)
    return raw, len(first)


def import_bundle(client, mount, raw):
    legacy.canonical_path(mount, "invalid mount")
    need(not client.namespace, "native-large import requires root namespace")
    value = legacy.parse_json(raw, client.limits.bundle_bytes)
    need(isinstance(value, dict) and set(value) == {"schema", "config", "entries"}
         and value["schema"] == "openbao270-kv2-lossless-v1"
         and isinstance(value["config"], dict) and isinstance(value["entries"], dict)
         and len(value["entries"]) <= decoder.MAX_RECORDS, "invalid native KV2 bundle")
    # Raw closed bundle, no mount/bundle aggregate envelope. The server owns
    # strict graph validation and one publication after pre-body admission.
    result = client.request(
        "POST", "sys/migration/openbao/kv2/native-large?mount="
        + urllib.parse.quote(mount, safe="/"), raw, native_import=True)
    need(result is None, "native-large import requires HTTP 204")


def main(argv=None, *, end=None):
    end = _ENTRY + DEADLINE if end is None else end
    legacy.check_deadline(end)
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
    need((args.operation == "export" and args.output and not args.input)
         or (args.operation == "import" and args.input and not args.output),
         "export requires --output; import requires --input")
    token = legacy.private_read(args.token_file, 65536).decode("ascii").strip()
    client = Client(args.address, token, args.namespace, args.ca_file, end=end)
    if args.operation == "export":
        raw, count = export_bundle(client, args.mount)
        legacy.exclusive_output(args.output, raw, end=end)
        receipt = {"operation": "export", "records": count, "bytes": len(raw),
                   "sha256": hashlib.sha256(raw).hexdigest(), "lane": "native-large"}
    else:
        raw = legacy.private_read(args.input, LIMITS.bundle_bytes)
        import_bundle(client, args.mount, raw)
        receipt = {"operation": "import", "status": 204,
                   "source_sha256": hashlib.sha256(raw).hexdigest(), "lane": "native-large"}
    legacy.check_deadline(end)
    print(json.dumps(receipt, sort_keys=True))


def supervise(argv, *, end=None):
    need(os.name == "posix", "native-large supervisor requires POSIX process groups")
    end = _ENTRY + DEADLINE if end is None else end
    legacy.check_deadline(end)
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--_owned-worker"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True)
    lifecycle = {"pid": process.pid, "pgid": process.pid, "original_popen": True,
                 "planned_signal": None, "returncode": None,
                 "original_wait_completed": False, "retried": False}
    supervise.last_lifecycle = lifecycle
    complete = False
    try:
        try:
            stdout, stderr = process.communicate(
                json.dumps({"argv": list(argv), "end": end}).encode(),
                timeout=max(0, end - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            lifecycle["planned_signal"] = signal.SIGKILL
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
            raise DecodeError("native-large original absolute deadline exceeded") from error
        legacy.check_deadline(end)
        need(len(stdout) <= 4096 and len(stderr) <= 4096, "worker output bound")
        if process.returncode:
            sys.stderr.buffer.write(stderr)
            return process.returncode, lifecycle
        need(not stderr, "unexpected worker diagnostics")
        sys.stdout.buffer.write(stdout)
        complete = True
        return 0, lifecycle
    finally:
        if not complete:
            try:
                lifecycle["planned_signal"] = signal.SIGKILL
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            process.communicate(timeout=5)
        lifecycle["returncode"] = process.returncode
        lifecycle["original_wait_completed"] = process.poll() is not None


def owned_worker():
    raw = sys.stdin.buffer.read(65537)
    need(len(raw) <= 65536, "worker input bound")
    packet = json.loads(raw)
    need(isinstance(packet, dict) and set(packet) == {"argv", "end"}
         and isinstance(packet["argv"], list)
         and all(isinstance(value, str) for value in packet["argv"])
         and type(packet["end"]) in (int, float), "worker input framing")
    main(packet["argv"], end=packet["end"])


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--_owned-worker"]:
            owned_worker()
        else:
            code, _ = supervise(sys.argv[1:])
            raise SystemExit(code)
    except (DecodeError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        print("KV2 native-large migration failed: "
              + (str(error) if isinstance(error, DecodeError) else type(error).__name__),
              file=sys.stderr)
        raise SystemExit(1)
