"""Local deadline regressions, never physical HA or Bao correctness evidence.

Listener/leader cases use complete HTTPS responses from a private loopback
responder and the real urllib API path. The fixed 60/35 second native cases
use explicit scripted clock traces plus bounded delayed read callbacks; no
remote process, credential, HA election, mutation or durability is exercised.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


MODULE_ROOT = Path(os.environ.get("HEPTABAO_DEADLINE_MODULE_ROOT",
                                  str(Path(__file__).resolve().parents[1]))).resolve(strict=True)
sys.path.insert(0, str(MODULE_ROOT))
import ha_multihost_live as base
import native_v6_ha_multihost_live as native


class ScriptedClock:
    """Declared monotonic trace: it does not claim 60/35 real seconds elapsed."""

    def __init__(self, observations):
        self.observations = iter(observations)

    def monotonic(self):
        return next(self.observations)

    def sleep(self, _seconds):
        # Delayed callbacks below use the unpatched real time module.
        pass


class OriginalDeadlineRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="native-lan-deadline-")
        root = Path(cls.directory.name)
        cls.cert, cls.key = root / "certificate.pem", root / "private-key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=synthetic-local-deadline-test",
            "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(cls.key), "-out", str(cls.cert),
        ], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15)
        cls.key.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    @contextmanager
    def responder(self, reply):
        calls = []

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                calls.append(self.path)
                status, body, delay = reply(self.path, tuple(calls))
                time.sleep(delay)
                raw = json.dumps(body, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)
                self.wfile.flush()

            def log_message(self, *_):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        server.timeout = 1
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = ssl.TLSVersion.TLSv1_2
        server_context.load_cert_chain(self.cert, self.key)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        client_context = ssl.create_default_context(cafile=str(self.cert))
        client_context.minimum_version = ssl.TLSVersion.TLSv1_2
        node = base.Node(1, "local-unit", "127.0.0.1", "/unused-synthetic-root",
                         server.server_port, 46231)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        try:
            yield client_context, node, calls
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive(), "owned loopback responder did not stop")

    def test_listener_rejects_late_complete_https_response_without_retry(self):
        with self.responder(lambda *_: (501, {"initialized": False}, 0.15)) as (context, node, calls):
            start = time.monotonic()
            with self.assertRaisesRegex(base.FixtureError, "node_1_listener_timeout"):
                base.wait_listener(context, node, seconds=0.05)
            self.assertGreaterEqual(time.monotonic() - start, 0.15)
            self.assertEqual(calls, ["/v1/sys/health"])

    def test_listener_accepts_complete_https_response_inside_same_deadline(self):
        with self.responder(lambda *_: (501, {"initialized": False}, 0)) as (context, node, calls):
            self.assertEqual(base.wait_listener(context, node, seconds=1),
                             (501, {"initialized": False}))
            self.assertEqual(calls, ["/v1/sys/health"])

    def test_leader_rejects_late_stable_complete_https_observation(self):
        def reply(path, calls):
            # Both individual requests remain within their original 2/8 second
            # HTTP limits; only the original enclosing deadline has expired.
            delay = 1.2 if calls.count(path) == 2 else 0
            if path == "/v1/sys/health":
                return 200, {"ha_active": True, "ha_application_ready": True,
                             "standby": False}, delay
            self.assertEqual(path, "/v1/sys/leader")
            return 200, {"is_self": True}, delay

        with self.responder(reply) as (context, node, calls):
            start = time.monotonic()
            with self.assertRaisesRegex(base.FixtureError, "stable_leader_timeout"):
                base.wait_leader(context, [node], "", seconds=2.25)
            self.assertGreaterEqual(time.monotonic() - start, 2.4)
            self.assertEqual(calls, ["/v1/sys/health", "/v1/sys/leader"] * 2)

    def test_fixed_sixty_second_sealed_trace_rejects_boundary_and_late_response(self):
        node = SimpleNamespace(node_id=1)
        for terminal in (60.0, 60.01):
            with self.subTest(terminal=terminal):
                calls = []

                def request(actual, method, path, **options):
                    self.assertIs(actual, node)
                    self.assertEqual((method, path), ("GET", "sys/health"))
                    self.assertEqual(options, {"authenticate": False, "timeout": 2})
                    time.sleep(0.01)
                    calls.append(path)
                    return 503, {"sealed": True, "ha_active": True, "standby": False}

                clock = ScriptedClock((0.0, 0.0, 57.7, 57.8, terminal))
                run = SimpleNamespace(request=request)
                with patch.object(native, "time", clock):
                    with self.assertRaisesRegex(base.FixtureError, "sealed_native_leader_timeout"):
                        native.NativeRun.wait_sealed_leader(run, [node])
                self.assertEqual(calls, ["sys/health", "sys/health"])

    def test_fixed_thirtyfive_second_quorum_trace_rejects_before_denied_mutation(self):
        nodes = [SimpleNamespace(node_id=identifier) for identifier in (1, 2, 3)]
        for terminal in (35.0, 35.01):
            with self.subTest(terminal=terminal):
                calls, checks = [], []

                def request(_node, method, path, **options):
                    self.assertEqual((method, path), ("GET", "sys/health"))
                    self.assertEqual(options, {"authenticate": False, "timeout": 3})
                    time.sleep(0.01)
                    calls.append((method, path))
                    return 503, {"ha_active": False}

                def check(name, condition, **_details):
                    checks.append((name, condition))
                    if name == "single_survivor_loses_authority" and condition is True:
                        self.fail("the original quorum gate accepted a late response")
                    if condition is not True:
                        raise base.FixtureError(name)

                run = SimpleNamespace(
                    nodes=nodes, context=None, run_id="unit-no-authority", event=lambda *_a, **_k: None,
                    stop=lambda node: node.node_id, start=lambda _: None, unseal=lambda _: None,
                    check=check, leader=lambda *_a, **_k: nodes[1], history_reads=lambda _: None,
                    write_small=lambda *_: None, small_reads=lambda _: None, request=request,
                )
                clock = ScriptedClock((0.0, 0.0, terminal))
                with patch.object(native, "time", clock), \
                        patch.object(base, "capture_committed_frontier", return_value=1), \
                        patch.object(base, "wait_local_frontier", return_value=(1, 1)):
                    with self.assertRaisesRegex(base.FixtureError, "single_survivor_loses_authority"):
                        native.NativeRun.failover_and_quorum(run, nodes[0])
                self.assertEqual(calls, [("GET", "sys/health")])
                self.assertEqual(checks[-1], ("single_survivor_loses_authority", False))


if __name__ == "__main__":
    unittest.main()
