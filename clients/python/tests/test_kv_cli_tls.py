"""Real HTTPS/subprocess tests for the product CLI's transport boundary.

The server is an original synthetic protocol fixture, not native/OpenBao evidence.
No response stdout, request payload or bearer is written to a receipt or log.
"""
import contextlib
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.methods.append(("GET", self.path))
        if self.headers.get("X-Vault-Token") != "synthetic-tls-bearer" or self.headers.get("X-Vault-Namespace") != "team":
            self.reply(403, {})
        elif self.server.mode == "redirect":
            self.send_response(307)
            self.send_header("Location", self.server.address + "/v1/secret/data/redirected")
            self.end_headers()
        elif self.path.startswith("/v1/sys/internal/ui/mounts/"):
            self.reply(200, {"data": {"type": "kv", "path": "secret/", "options": {"version": "2"}}})
        else:
            self.reply(200, {"data": {"data": {"value": "synthetic-tls-value"}, "metadata": {"version": 1}}})

    def do_POST(self):
        self.server.methods.append(("POST", self.path))
        value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.effects.append(value)
        if self.server.mode == "disconnect":
            self.close_connection = True
            return
        self.reply(200, {"data": {"version": 1}})

    def reply(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        with contextlib.suppress(BrokenPipeError):
            self.wfile.write(body)


class KVRealTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.ca, key = cls.root / "ca.crt", cls.root / "key.pem"
        # The private key is generated and read only by this owned TLS fixture.
        generated = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
                                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                                    "-addext", "basicConstraints=critical,CA:TRUE",
                                    "-addext", "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
                                    "-addext", "extendedKeyUsage=serverAuth",
                                    "-addext", "subjectKeyIdentifier=hash",
                                    "-addext", "authorityKeyIdentifier=keyid:always",
                                    "-keyout", str(key), "-out", str(cls.ca)], capture_output=True, timeout=15)
        if generated.returncode:
            cls.tmp.cleanup()
            raise RuntimeError("synthetic TLS certificate generation failed")
        key.chmod(0o600)
        token = cls.root / "token"
        token.write_text("synthetic-tls-bearer")
        token.chmod(0o600)
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cls.ca), str(key))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.server.address = "https://localhost:" + str(cls.server.server_port)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.environment = {key: value for key, value in os.environ.items() if not key.startswith(("BAO_", "VAULT_"))}
        cls.environment.update({"PYTHONPATH": str(Path(__file__).resolve().parents[1]),
                                "BAO_ADDR": cls.server.address, "BAO_CACERT": str(cls.ca),
                                "BAO_TOKEN_FILE": str(token), "BAO_NAMESPACE": "team", "BAO_CLIENT_TIMEOUT": "1s",
                                "HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1"})

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)
        if cls.thread.is_alive():
            raise RuntimeError("owned TLS fixture did not stop")
        cls.tmp.cleanup()

    def setUp(self):
        self.server.methods, self.server.effects, self.server.mode = [], [], "normal"

    def execute(self, command, environment=None):
        return subprocess.run([sys.executable, "-m", "heptabao", "kv"] + command,
                              env=environment or self.environment, capture_output=True, timeout=5)

    def test_actual_process_outputs_requested_field_over_verified_tls_without_ambient_proxy(self):
        result = self.execute(["get", "-field=value", "secret/key"])
        self.assertEqual(result.returncode, 0)
        # stdout is intentionally consumed in memory only, not a test receipt.
        self.assertTrue(result.stdout == b"synthetic-tls-value")
        self.assertTrue(result.stderr == b"")
        self.assertEqual(self.server.methods, [("GET", "/v1/sys/internal/ui/mounts/secret/key"), ("GET", "/v1/secret/data/key")])

    def test_mount_redirect_is_never_followed_and_discloses_no_bearer(self):
        self.server.mode = "redirect"
        result = self.execute(["get", "secret/key"])
        self.assertEqual(result.returncode, 2)
        self.assertTrue(result.stdout == b"")
        self.assertTrue(b"synthetic-tls-bearer" not in result.stderr)
        self.assertEqual(json.loads(result.stderr)["code"], "redirect_rejected")
        self.assertEqual(len(self.server.methods), 1)

    def test_unknown_mutation_keeps_single_effect_and_no_success_output(self):
        self.server.mode = "disconnect"
        result = self.execute(["put", "secret/key", "value=synthetic-write-value"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(self.server.effects), 1)
        self.assertEqual(self.server.effects[0], {"data": {"value": "synthetic-write-value"}})
        self.assertTrue(result.stdout == b"")
        self.assertTrue(b"synthetic-write-value" not in result.stderr)
        self.assertEqual(json.loads(result.stderr)["code"], "transport_outcome_unknown")

    def test_untrusted_ca_refuses_before_any_http_request(self):
        environment = dict(self.environment)
        environment["BAO_CACERT"] = str(self.root / "does-not-exist.crt")
        result = self.execute(["get", "secret/key"], environment)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.server.methods, [])
        self.assertTrue(result.stdout == b"")
        self.assertEqual(json.loads(result.stderr)["code"], "ca_configuration_invalid")


if __name__ == "__main__":
    unittest.main()
