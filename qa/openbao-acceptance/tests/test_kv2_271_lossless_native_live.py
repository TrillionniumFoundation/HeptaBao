"""Controller checks only; no OpenBao/HeptaBao server or replacement admission."""
import importlib.util
import copy
import hashlib
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


def run_fixture(root, profile="full34"):
    root.mkdir(mode=0o700)
    (root / "phases").mkdir(mode=0o700)
    return fixture.Run(SimpleNamespace(private_work_root=root, profile=profile,
                                       binary=Path("/unused-binary")))


def source_history():
    config = {"max_versions": 10, "cas_required": True, "metadata_cas_required": True}
    metadata = {"current_version": 4, "metadata_cas_required": True, "current_metadata_version": 2,
                "custom_metadata": {"revision": "second"}, "versions": {}}
    versions = {}
    for version in range(1, 5):
        meta = {"created_time": "2026-10-19T00:00:00.000000001Z",
                "deletion_time": "2026-10-19T00:00:01.000000001Z" if version == 1 else "",
                "destroyed": version == 2}
        metadata["versions"][str(version)] = meta
        value = fixture.payload(version, 2, 4096)
        value["wide_integer"] = 9007199254740992
        value["exact_decimal"] = fixture.Decimal("0.12345678901234568")
        versions[str(version)] = {"status": 404 if version < 3 else 200,
            "data": {"data": None if version < 3 else value, "metadata": {**meta, "version": version}}}
    return {"config": config, "metadata": metadata, "versions": versions}


def witness_response(version, metadata, payload):
    raw = fixture.canonical(payload) if payload is not None else b""
    return {"data": {"schema": "heptabao-native-kv2-storage-witness-v1",
        "canonical_profile": "heptabao-lossless-json-v1", "mount": "secret", "path": "history",
        "version": version, **metadata, "payload_present": payload is not None,
        "mount_incarnation": 1, "source_root_sha256": "a" * 64, "source_publication_generation": 0,
        "payload_canonical_bytes": len(raw),
        "payload_canonical_sha256": hashlib.sha256(raw).hexdigest() if payload is not None else None}}


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

    def test_api_token_comparison_preserves_numeric_representation(self):
        self.assertFalse(fixture.same_json_tokens({"x": 1}, {"x": fixture.Decimal("1.0")}))
        self.assertFalse(fixture.same_json_tokens({"x": fixture.Decimal("0.1000")}, {"x": fixture.Decimal("0.1")}))
        self.assertTrue(fixture.same_json_tokens({"a": 1, "b": 2}, {"b": 2, "a": 1}))

    def test_native_storage_canonical_cross_language_vector(self):
        value = {"a": fixture.Decimal("0.123456789012345678901234567890"),
                 "z": 9007199254740993, "unicode": "凭证迁移试验🧪",
                 "nested": [None, True, {"zero": "\\u0000"}]}
        raw = fixture.canonical(value)
        self.assertEqual(len(raw), 134)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "8f55c32f8c1f2f2a8d0e5cc14f08b7007ae6ca496782cdc2ae84143879b40395")
        self.assertEqual(hashlib.sha256(fixture.canonical(fixture.payload(3, 2, 4096))).hexdigest(),
                         "5ae4f8f3c47c234b88807b253fb22d5f1d9e5234fb405f5c5f1c083f6350b8ca")

    def test_seed_captures_observed_api_before_deletion_without_rounding_raw_fixture(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            run = run_fixture(Path(tmp) / "fixture", "native-small")
            original = source_history()
            sequence = [("POST", "sys/mounts/secret", 204, {}),
                        ("POST", "secret/config", 204, {}),
                        ("POST", "secret/metadata/history", 204, {})]
            for version in range(1, 5):
                value = fixture.payload(version, 2, 4096)
                value["wide_integer"] = 9007199254740992
                value["exact_decimal"] = fixture.Decimal("0.12345678901234568")
                sequence += [("POST", "secret/data/history", 200, {}),
                             ("GET", "secret/data/history?version=" + str(version), 200,
                              {"data": {"data": value, "metadata": {"version": version}}})]
            sequence += [("GET", "secret/metadata/history", 200, {"data": {"current_metadata_version": 1}}),
                         ("POST", "secret/metadata/history", 204, {}),
                         ("POST", "secret/delete/history", 204, {}),
                         ("POST", "secret/destroy/history", 204, {})]
            writes = []

            def scripted(method, path, body=None, *, response_evidence=None):
                # Scripted oracle observations only. The real TLS capture is
                # exercised independently by the HTTP leaf regression below.
                expected_method, expected_path, status, response = sequence.pop(0)
                self.assertEqual((method, path), (expected_method, expected_path))
                if method == "POST" and path == "secret/data/history":
                    writes.append(copy.deepcopy(body))
                if response_evidence is not None:
                    fixture.private_write(response_evidence, fixture.canonical(response))
                    run.report.setdefault("source_api_wire_observations", []).append({"synthetic_test_response": True})
                return status, copy.deepcopy(response)

            run.source = SimpleNamespace(call=scripted)
            with patch.object(fixture, "observations", return_value=original):
                self.assertEqual(run.seed_source(2, 4096), original)
            self.assertEqual(sequence, [])
            self.assertEqual(run.source_api_payloads["1"]["wide_integer"], 9007199254740992)
            self.assertEqual(str(run.source_api_payloads["1"]["exact_decimal"]), "0.12345678901234568")
            self.assertTrue(all(body["data"]["wide_integer"] == 9007199254740993 for body in writes))
            self.assertTrue(all(str(body["data"]["exact_decimal"]) == "0.123456789012345678901234567890" for body in writes))
            self.assertIs(run.original, original)
            self.assertEqual(len(list((run.root / "source-api-oracle").glob("*.json"))), 4)

    def test_source_raw_bundle_rejects_api_rounded_numbers(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            run = run_fixture(Path(tmp) / "fixture", "native-small")
            run.original = source_history()
            entry = copy.deepcopy(run.original["metadata"])
            for version in range(1, 5):
                entry["versions"][str(version)]["data"] = None if version == 2 else fixture.payload(version, 2, 4096)
            value = {"schema": "openbao270-kv2-lossless-v1", "config": run.original["config"], "entries": {"history": entry}}
            changed = copy.deepcopy(value)
            changed["entries"]["history"]["versions"]["3"]["data"]["wide_integer"] = 9007199254740992
            path = run.root / "rounded.json"; fixture.private_write(path, fixture.canonical(changed))
            with self.assertRaisesRegex(fixture.Failure, "bundle_retained_payload"):
                run.verify_bundle(path, 2, 4096)
            exact = run.root / "exact.json"; fixture.private_write(exact, fixture.canonical(value))
            run.verify_bundle(exact, 2, 4096)
            self.assertTrue(any(row["case"] == "source_raw_history_exact" and row["passed"] for row in run.report["checks"]))

    def test_storage_witness_requires_precise_payload_and_retained_deleted_destroyed_semantics(self):
        source = source_history()["metadata"]["versions"]
        for version in (1, 2, 3):
            expected = None if version == 2 else fixture.payload(version, 2, 4096)
            response = witness_response(version, source[str(version)], expected)
            fixture.verify_storage_witness(response, version, source[str(version)], expected)
        expected = fixture.payload(3, 2, 4096)
        rounded = copy.deepcopy(expected); rounded["wide_integer"] = 9007199254740992
        with self.assertRaisesRegex(fixture.Failure, "lossless_payload"):
            fixture.verify_storage_witness(witness_response(3, source["3"], rounded), 3, source["3"], expected)
        with self.assertRaisesRegex(fixture.Failure, "lossless_payload"):
            fixture.verify_storage_witness(witness_response(1, source["1"], None), 1, source["1"], fixture.payload(1, 2, 4096))
        with self.assertRaisesRegex(fixture.Failure, "lossless_payload"):
            fixture.verify_storage_witness(witness_response(2, source["2"], fixture.payload(2, 2, 4096)), 2, source["2"], None)
        with self.assertRaisesRegex(fixture.Failure, "exact_identity"):
            fixture.verify_storage_witness(witness_response(3, source["3"], expected), 4, source["3"], expected)
        good = witness_response(3, source["3"], expected)
        for field, bad_values in {
            "mount_incarnation": (None, True, False, 0, -1, 1 << 64, 1.0, "1"),
            "source_root_sha256": (None, True, "", "a" * 63, "A" * 64, "g" * 64, "a" * 64 + "\n"),
            "source_publication_generation": (None, True, False, -1, 1 << 64, 0.0, "0"),
        }.items():
            missing = copy.deepcopy(good); del missing["data"][field]
            with self.subTest(field=field, missing=True), self.assertRaisesRegex(fixture.Failure, "actual_source"):
                fixture.verify_storage_witness(missing, 3, source["3"], expected)
            for bad_value in bad_values:
                malformed = copy.deepcopy(good); malformed["data"][field] = bad_value
                with self.subTest(field=field, value=bad_value), self.assertRaisesRegex(fixture.Failure, "actual_source"):
                    fixture.verify_storage_witness(malformed, 3, source["3"], expected)
        for field in ("data", "payload"):
            leaking = copy.deepcopy(good); leaking["data"][field] = {"secret": "must-never-project"}
            with self.subTest(field=field), self.assertRaisesRegex(fixture.Failure, "no_plaintext"):
                fixture.verify_storage_witness(leaking, 3, source["3"], expected)
        changed_source = copy.deepcopy(good)
        changed_source["data"].update(mount_incarnation=(1 << 64) - 1, source_root_sha256="b" * 64,
                                      source_publication_generation=(1 << 64) - 1)
        for response in (good, changed_source):
            receipt = fixture.verify_storage_witness(response, 3, source["3"], expected)
            for field in ("mount_incarnation", "source_root_sha256", "source_publication_generation"):
                self.assertEqual(receipt[field], response["data"][field])

    def test_api_success_without_all_native_storage_stages_cannot_qualify_full34(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            run = run_fixture(Path(tmp) / "fixture")
            for name in fixture.CHECKS:
                if name not in fixture.STORAGE_CHECKS and name not in ("owned_processes_stopped", "report_excludes_runtime_credentials"):
                    run.check(name, True)
            self.assertEqual(run.finish(), 1)
            self.assertTrue(run.report["api_history_qualified"])
            self.assertFalse(run.report["target_storage_precision_qualified"])
            self.assertFalse(run.report["full34_qualified"])
            self.assertEqual(set(run.report["missing_checks"]), set(fixture.STORAGE_CHECKS))

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

    def test_real_pinned_tls_leaf_roundtrips_two_mib_once_and_captures_get_bytes(self):
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

                def do_GET(self):
                    raw = fixture.canonical(value)
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
            thread = threading.Thread(target=lambda: [server.handle_request() for _ in range(2)], daemon=True)
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
                capture = run.root / "get-response.json"
                source = fixture.Endpoint(endpoint.address, cert, "public-fixture", run, "source")
                get_status, get_value = source.call("GET", "secret/data/history?version=3", response_evidence=capture)
                self.assertEqual((get_status, get_value), (200, value))
                self.assertEqual(fixture.private_read(capture), fixture.canonical(value))
                evidence = run.report["source_api_wire_observations"][0]
                self.assertTrue(evidence["same_response_decoded"])
                self.assertEqual(evidence["body_sha256"], hashlib.sha256(capture.read_bytes()).hexdigest())
                self.assertEqual(len(run.report["mutations"]), 1)
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
