"""Controller checks only; no OpenBao/HeptaBao server or replacement admission."""
import importlib.util
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from types import SimpleNamespace
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "kv2_271_lossless_native_live.py"
TMP = Path(__file__).resolve().parents[3] / "controller-tests-tmp"
TMP.mkdir(exist_ok=True)
spec = importlib.util.spec_from_file_location("kv2_271_lossless_native_live_tested", PATH)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def run_fixture(root):
    root.mkdir(mode=0o700)
    (root / "phases").mkdir(mode=0o700)
    return fixture.Run(SimpleNamespace(private_work_root=root, profile="full34",
                                       binary=Path("/unused-binary")))


class ControllerRegression(unittest.TestCase):
    def test_json_exact_decimal_wide_integer_and_unicode(self):
        value = fixture.payload(3, 17, 2 * fixture.MIB)
        decoded = fixture.decode(fixture.canonical(value))
        self.assertEqual(decoded, value)
        self.assertEqual(decoded["wide_integer"], 9007199254740993)
        self.assertEqual(str(decoded["exact_decimal"]), "0.123456789012345678901234567890")
        self.assertEqual(len(decoded["payload"]), 2 * fixture.MIB)
        with self.assertRaises(fixture.Failure):
            fixture.decode(b'{"x":1,"x":2}')

    def test_diagnostic_profiles_do_not_shrink_full34(self):
        count, size, native = fixture.PROFILES["full34"]
        self.assertTrue(native)
        self.assertEqual(count * size, 34 * fixture.MIB)
        count, size, native = fixture.PROFILES["legacy8"]
        self.assertFalse(native)
        self.assertLess(size + 1024, fixture.MIB)
        self.assertGreater(count * size, 8 * fixture.MIB)
        self.assertLess(count * size, 16 * fixture.MIB)

    def test_non_tls_leaf_rejected_without_secret_diagnostic(self):
        token = "synthetic-token-never-in-diagnostic"
        packet = {"address": "http://127.0.0.1:1", "ca_file": "/unused", "token": token,
                  "method": "GET", "path": "sys/health", "body": None,
                  "archive_in": None, "archive_out": None}
        result = subprocess.run([sys.executable, "-B", str(PATH), "--_http_leaf"],
                                input=json.dumps(packet).encode(), capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"private HTTP leaf failed\n")
        self.assertNotIn(token.encode(), result.stderr)

    def test_real_pinned_tls_leaf_roundtrips_two_mib_exactly_once(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            root = Path(tmp)
            run = run_fixture(root / "fixture")
            cert, key = root / "ca.crt", root / "tls.key"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature,keyEncipherment",
                "-addext", "subjectAltName=IP:127.0.0.1",
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            calls = []

            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):
                    raw = self.rfile.read(int(self.headers["Content-Length"]))
                    calls.append({"path": self.path,
                                  "token_matches": self.headers["X-Vault-Token"] == "public-fixture"})
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)

                def log_message(self, *_):
                    pass

            server = HTTPServer(("127.0.0.1", 0), Handler)
            server.timeout = 5
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()
            try:
                endpoint = fixture.Endpoint("https://127.0.0.1:" + str(server.server_port),
                                            cert, "public-fixture", run, "target")
                value = fixture.payload(3, 17, 2 * fixture.MIB)
                status, decoded = endpoint.call("POST", "secret/data/history", value)
                self.assertEqual(status, 200)
                self.assertEqual(decoded, value)
                self.assertEqual(calls, [{"path": "/v1/secret/data/history", "token_matches": True}])
                self.assertEqual(len(run.report["mutations"]), 1)
                self.assertEqual(run.report["mutations"][0]["status"], 200)
            finally:
                server.server_close()
                thread.join(5)
            self.assertFalse(thread.is_alive())

    def test_unknown_mutation_has_one_owned_http_leaf_and_is_not_retried(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            run = run_fixture(Path(tmp) / "fixture")
            endpoint = fixture.Endpoint("https://127.0.0.1:1", Path("/unused"),
                                        "public-fixture", run, "target")
            original = subprocess.Popen
            children = []

            def child(*_args, **_kwargs):
                process = original([sys.executable, "-c", "import time; time.sleep(30)"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                children.append(process)
                return process

            with patch.object(fixture.subprocess, "Popen", side_effect=child):
                with self.assertRaisesRegex(fixture.Failure, "unknown_outcome"):
                    endpoint.call("POST", "secret/data/history", {"data": {"public": True}}, budget=0.05)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll())
            self.assertEqual(len(run.report["mutations"]), 1)
            mutation = run.report["mutations"][0]
            self.assertEqual(mutation["outcome"], "unknown")
            self.assertIsNone(mutation["status"])
            self.assertFalse(mutation["retried"])

    def test_cleanup_failure_still_stops_other_owner_and_publishes_failed_summary(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            run = run_fixture(Path(tmp) / "fixture")
            attempts = []

            def fail_target():
                attempts.append("target")
                raise RuntimeError("synthetic-owner-failure")

            run.candidate = SimpleNamespace(process=SimpleNamespace(poll=lambda: None),
                                            stop=fail_target)
            run.oracle = {"process": SimpleNamespace(poll=lambda: 0)}
            run.stop_oracle = lambda _: attempts.append("source")
            run.finish()
            self.assertEqual(attempts, ["target", "source"])
            report = json.loads((run.root / "summary.json").read_text())
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["full34_qualified"])
            self.assertEqual(report["failure"], "owned_processes_stopped")
            self.assertTrue(report["missing_checks"])

    def test_secret_in_failed_diagnostic_is_redacted_and_never_qualified(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            run = run_fixture(Path(tmp) / "fixture")
            token = "synthetic-credential-that-must-be-redacted"
            run.secrets = [token]
            run.report["unexpected_diagnostic"] = token
            run.finish()
            public = (run.root / "summary.json").read_text()
            self.assertNotIn(token, public)
            report = json.loads(public)
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["full34_qualified"])
            checks = {row["case"]: row["passed"] for row in report["checks"]}
            self.assertFalse(checks["report_excludes_runtime_credentials"])


if __name__ == "__main__":
    unittest.main()
