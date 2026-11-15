"""Native-large transport/decoder checks; no actual Bao server is executed."""
import base64
from dataclasses import FrozenInstanceError
from decimal import Decimal
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.parse

ROOT = Path(__file__).resolve().parents[3]
TMP = ROOT / "controller-tests-tmp"
TMP.mkdir(exist_ok=True)


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


large = load("tested_native_large_migration", "tools/migration/openbao271_kv2_native_large_migrate.py")
raw = large.decoder
legacy = large.legacy
probe = load("tested_kv2_boundary_fixture", "qa/openbao-acceptance/kv2_271_migration_boundary_probe.py")
controller = load("tested_kv2_large_controller", "qa/openbao-acceptance/kv2_271_lossless_native_live.py")


def rich_records(count, size):
    result = []
    for path, value in probe.synthetic_records(count, size):
        if path.endswith("/config"):
            value += probe.integer(2, 1) + probe.integer(400, 1)
        elif "/metadata/" in path:
            pair = probe.binary(1, b"revision") + probe.binary(2, b"second")
            value += (probe.integer(8, 1) + probe.integer(400, 1)
                      + probe.integer(401, 2) + probe.binary(10, pair))
        elif "/versions/" in path:
            fields = raw.message(value, {1: 2, 2: 2, 3: 2}, bounds=raw.NATIVE_LARGE_BOUNDS)
            version = json.loads(fields[1])["version"]
            data = raw.dumps_lossless(controller.payload(version, count, size)).encode()
            value = probe.binary(1, data) + probe.binary(2, fields[2])
        result.append((path, value))
    return result


class RawSource:
    """Synthetic raw API, used only to exercise exact exporter consistency."""
    def __init__(self, records, changing=False):
        self.records = dict(records)
        self.limits = large.LIMITS
        self.end = time.monotonic() + 360
        self.mount_calls = 0
        self.changing = changing

    def mount(self, mount):
        assert mount == "secret"
        self.mount_calls += 1
        return "11111111-1111-4111-8111-111111111111"

    def request(self, method, path):
        parsed = urllib.parse.urlsplit(path)
        assert parsed.path.startswith("sys/raw/")
        name = urllib.parse.unquote(parsed.path.removeprefix("sys/raw/"))
        if method == "LIST":
            children = set()
            for key in self.records:
                if key.startswith(name):
                    suffix = key[len(name):]
                    child = suffix.split("/", 1)[0]
                    children.add(child + ("/" if "/" in suffix else ""))
            return {"data": {"keys": sorted(children)}}
        assert method == "GET"
        value = self.records[name]
        if self.changing and self.mount_calls >= 2 and name.endswith("/salt"):
            value += b"-changed"
        return {"data": {"value": base64.b64encode(value).decode()}}


class OneTLS:
    def __init__(self, root, *, response=b"", status=204):
        self.calls = []
        self.response, self.status = response, status
        self.cert, self.key = root / "ca.crt", root / "tls.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(self.key), "-out", str(self.cert), "-subj", "/CN=localhost",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature,keyEncipherment",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def capture(self):
                declared = int(self.headers.get("Content-Length", 0))
                remaining, digest = declared, hashlib.sha256()
                while remaining:
                    part = self.rfile.read(min(65536, remaining))
                    if not part:
                        break
                    digest.update(part)
                    remaining -= len(part)
                fixture.calls.append({
                    "method": self.command, "path": self.path, "version": self.request_version,
                    "content_type": self.headers.get("Content-Type"), "declared": declared,
                    "read_bytes": declared - remaining, "sha256": digest.hexdigest(),
                    "transfer_encoding": self.headers.get("Transfer-Encoding"),
                    "expect": self.headers.get("Expect"),
                    "token_matches": self.headers.get("X-Vault-Token") == "public-fixture",
                })
                self.send_response(fixture.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(fixture.response)))
                self.send_header("Connection", "close")
                self.end_headers()
                if fixture.response:
                    self.wfile.write(fixture.response)

            do_POST = do_GET = capture

            def log_message(self, *_):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.server.timeout = 2
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.address = "https://127.0.0.1:" + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.handle_request, daemon=True)
        self.thread.start()

    def close(self):
        self.server.server_close()
        self.thread.join(5)
        if self.thread.is_alive():
            raise AssertionError("synthetic listener did not stop")

    def client(self):
        return large.Client(self.address, "public-fixture", ca_file=str(self.cert),
                            end=time.monotonic() + 360)


class NativeLargeMigrationRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = rich_records(17, 2 * probe.MIB)
        cls.projected = raw.decode_records(cls.records, bounds=raw.NATIVE_LARGE_BOUNDS)
        cls.bundle = raw.dumps_lossless(cls.projected).encode()

    def test_explicit_bounds_are_frozen_and_legacy_defaults_still_reject_two_mib(self):
        self.assertEqual(raw.MAX_RECORD, probe.MIB)
        self.assertEqual(legacy.MAX_BUNDLE, 16 * probe.MIB)
        self.assertEqual(legacy.MAX_RESPONSE, 2 * probe.MIB)
        with self.assertRaisesRegex(raw.DecodeError, "record bound"):
            raw.decode_records(self.records)
        with self.assertRaises(FrozenInstanceError):
            raw.NATIVE_LARGE_BOUNDS.record_bytes = 8 * probe.MIB
        with self.assertRaises(raw.DecodeError):
            raw.Bounds(record_bytes=5 * probe.MIB)
        with self.assertRaises(raw.DecodeError):
            large.Limits(response_bytes=16 * probe.MIB)

    def test_full34_preserves_actual_retired_history_exact_numbers_and_metadata(self):
        meta = self.projected["entries"]["synthetic/history"]
        self.assertEqual(meta["current_metadata_version"], 2)
        self.assertTrue(meta["metadata_cas_required"])
        self.assertTrue(meta["cas_required"])
        self.assertEqual(meta["custom_metadata"], {"revision": "second"})
        versions = meta["versions"]
        self.assertTrue(versions["1"]["deletion_time"])
        self.assertFalse(versions["1"]["destroyed"])
        self.assertEqual(versions["1"]["data"], controller.payload(1, 17, 2 * probe.MIB))
        self.assertTrue(versions["2"]["destroyed"])
        self.assertIsNone(versions["2"]["data"])
        live_bytes = sum(len(versions[str(v)]["data"]["payload"]) for v in range(3, 20))
        self.assertEqual(live_bytes, 34 * probe.MIB)
        self.assertEqual(versions["3"]["data"]["wide_integer"], 9007199254740993)
        self.assertEqual(versions["3"]["data"]["exact_decimal"],
                         Decimal("0.123456789012345678901234567890"))
        self.assertEqual(str(versions["3"]["data"]["exact_decimal"]),
                         "0.123456789012345678901234567890")
        self.assertGreater(len(self.bundle), 34 * probe.MIB)
        self.assertLess(len(self.bundle), large.LIMITS.bundle_bytes)
        with self.assertRaisesRegex(raw.DecodeError, "JSON byte bound"):
            legacy.parse_json(self.bundle, legacy.MAX_BUNDLE)
        self.assertEqual(legacy.parse_json(self.bundle, large.LIMITS.bundle_bytes), self.projected)

    def test_exporter_acquires_two_identical_raw_passes_under_explicit_large_limits(self):
        client = RawSource(self.records)
        bundle, count = large.export_bundle(client, "secret")
        self.assertEqual(bundle, self.bundle)
        self.assertEqual(count, len(self.records))
        self.assertEqual(client.mount_calls, 3)
        self.assertEqual(raw.MAX_RECORD, probe.MIB)

    def test_exporter_refuses_changed_source_before_output(self):
        client = RawSource(rich_records(2, 4096), changing=True)
        with self.assertRaisesRegex(raw.DecodeError, "source records changed"):
            large.export_bundle(client, "secret")

    def test_large_decoder_rejects_missing_soft_deleted_payload_and_retained_destroyed_payload(self):
        records = rich_records(2, 4096)
        versions = [row for row in records if "/versions/" in row[0]]
        # Version 1 is the first payload in the boundary fixture.
        missing = [row for row in records if row[0] != versions[0][0]]
        with self.assertRaisesRegex(raw.DecodeError, "version payload missing"):
            raw.decode_records(missing, bounds=raw.NATIVE_LARGE_BOUNDS)
        prefix = "logical/11111111-1111-4111-8111-111111111111/"
        locator = hashlib.sha256(b"public-fixture-salt" + b"synthetic/history|2").hexdigest()
        retained = records + [(prefix + "versions/" + locator[:3] + "/" + locator[3:],
                               versions[0][1])]
        with self.assertRaisesRegex(raw.DecodeError, "destroyed version retains payload"):
            raw.decode_records(retained, bounds=raw.NATIVE_LARGE_BOUNDS)

    def test_large_record_and_bundle_bounds_fail_closed(self):
        with self.assertRaisesRegex(raw.DecodeError, "record bound"):
            raw.message(b"\0" * (4 * probe.MIB + 1), {}, bounds=raw.NATIVE_LARGE_BOUNDS)
        with self.assertRaisesRegex(raw.DecodeError, "JSON byte bound"):
            legacy.parse_json(b" " * (64 * probe.MIB + 1), large.LIMITS.bundle_bytes)

    def test_real_tls_full34_raw_bundle_has_exact_http11_single_length_and_route(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            server = OneTLS(Path(tmp))
            try:
                client = server.client()
                large.import_bundle(client, "secret", self.bundle)
                self.assertEqual(len(server.calls), 1)
                call = server.calls[0]
                self.assertEqual(call["method"], "POST")
                self.assertEqual(call["path"], "/v1/sys/migration/openbao/kv2/native-large?mount=secret")
                self.assertEqual(call["version"], "HTTP/1.1")
                self.assertEqual(call["content_type"], large.CONTENT_TYPE)
                self.assertEqual(call["declared"], len(self.bundle))
                self.assertEqual(call["read_bytes"], len(self.bundle))
                self.assertEqual(call["sha256"], hashlib.sha256(self.bundle).hexdigest())
                self.assertIsNone(call["transfer_encoding"])
                self.assertIsNone(call["expect"])
                self.assertTrue(call["token_matches"])
                self.assertEqual(client.last_request_lifecycle["status"], 204)
                self.assertTrue(client.last_request_lifecycle["original_wait_completed"])
            finally:
                server.close()

    def test_real_tls_raw_response_above_legacy_two_mib_is_bounded_and_exact(self):
        value = {"data": {"value": base64.b64encode(b"X" * (2 * probe.MIB)).decode()}}
        response = json.dumps(value).encode()
        self.assertGreater(len(response), legacy.MAX_RESPONSE)
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            server = OneTLS(Path(tmp), response=response, status=200)
            try:
                client = server.client()
                received = client.request("GET", "sys/raw/logical/public?encoding=base64&compressed=false")
                self.assertEqual(received, value)
                self.assertEqual(len(server.calls), 1)
            finally:
                server.close()

    def test_root_namespace_and_tls_required_before_any_http_child(self):
        with self.assertRaisesRegex(raw.DecodeError, "TLS origin"):
            large.Client("http://127.0.0.1:1", "public-fixture")
        client = large.Client("https://127.0.0.1:1", "public-fixture", namespace="nested",
                              end=time.monotonic() + 360)
        with patch.object(large.subprocess, "Popen") as start:
            with self.assertRaisesRegex(raw.DecodeError, "root namespace"):
                large.import_bundle(client, "secret", self.bundle)
            start.assert_not_called()

    def test_expired_original_deadline_never_dispatches(self):
        client = large.Client("https://127.0.0.1:1", "public-fixture",
                              end=time.monotonic() - 1)
        with patch.object(large.subprocess, "Popen") as start:
            with self.assertRaisesRegex(raw.DecodeError, "deadline"):
                client.request("GET", "sys/health")
            start.assert_not_called()

    def test_unknown_import_times_out_one_owned_child_without_retry(self):
        client = large.Client("https://127.0.0.1:1", "public-fixture",
                              end=time.monotonic() + 0.15)
        original, children = subprocess.Popen, []

        def launch(*_args, **_kwargs):
            process = original([sys.executable, "-c", "import time; time.sleep(30)"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            children.append(process)
            return process

        with patch.object(large.subprocess, "Popen", side_effect=launch):
            with self.assertRaisesRegex(raw.DecodeError, "deadline"):
                client.request("POST", "sys/migration/openbao/kv2/native-large?mount=secret",
                               b"{}", native_import=True)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertIsNone(client.last_request_lifecycle["status"])
        self.assertFalse(client.last_request_lifecycle["retried"])
        self.assertEqual(client.last_request_lifecycle["outcome"], "unknown")
        self.assertTrue(client.last_request_lifecycle["original_wait_completed"])

    def test_real_rejection_is_reported_once_without_echoing_provider_secret(self):
        response = b'{"errors":["synthetic-provider-secret-never-echoed"]}'
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            server = OneTLS(Path(tmp), response=response, status=503)
            try:
                client = server.client()
                with self.assertRaisesRegex(raw.DecodeError, "HTTP status 503") as caught:
                    client.request("POST", "sys/migration/openbao/kv2/native-large?mount=secret",
                                   b"{}", native_import=True)
                self.assertNotIn("provider-secret", str(caught.exception))
                self.assertEqual(len(server.calls), 1)
                self.assertEqual(client.last_request_lifecycle["status"], 503)
                self.assertFalse(client.last_request_lifecycle["retried"])
            finally:
                server.close()


if __name__ == "__main__":
    unittest.main()
