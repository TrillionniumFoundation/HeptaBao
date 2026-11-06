"""Fixture guard tests only; these do not execute or qualify a real HA cluster."""
from __future__ import annotations
from email.message import Message
import gzip
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import ssl
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("ha_destructive_under_test", Path(__file__).resolve().parents[1] / "ha_destructive.py")
assert SPEC and SPEC.loader
HA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HA)


class DestructiveFixtureGuards(unittest.TestCase):
    def cluster(self):
        value = HA.Cluster.__new__(HA.Cluster)
        value.root_token = "synthetic"
        value.scenarios = []
        return value

    def test_successful_stale_read_fails_without_retry(self):
        node = Mock()
        node.call.return_value = (200, {"data": {"data": {"value": "stale"}}})
        with self.assertRaisesRegex(HA.FixtureError, "stale_or_wrong"):
            self.cluster().read(node, "probe", "current")
        node.call.assert_called_once()

    def test_missing_acknowledged_value_fails_without_retry(self):
        node = Mock()
        node.call.return_value = (404, {})
        with self.assertRaisesRegex(HA.FixtureError, "not_visible"):
            self.cluster().read(node, "probe", "current")
        node.call.assert_called_once()

    def test_transient_unavailability_can_retry_read_only(self):
        node = Mock()
        node.call.side_effect = [(503, {}), (200, {"data": {"data": {"value": "current"}}})]
        with patch.object(HA.time, "sleep"):
            self.cluster().read(node, "probe", "current")
        self.assertEqual(2, node.call.call_count)

    def test_ambiguous_write_is_not_replayed(self):
        node = Mock()
        node.call.side_effect = TimeoutError("synthetic timeout")
        with self.assertRaises(TimeoutError):
            self.cluster().write(node, "probe", "new")
        node.call.assert_called_once()

    def test_boolean_version_is_not_a_committed_write_receipt(self):
        node = Mock()
        node.call.return_value = (200, {"data": {"version": True}})
        with self.assertRaises(HA.FixtureError):
            self.cluster().write(node, "probe", "new")

    def test_preexisting_root_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            marker = root / "preserve.txt"
            marker.write_text("retain")
            with self.assertRaises(HA.FixtureError):
                HA.Cluster(Path("/not-used"), root)
            self.assertEqual("retain", marker.read_text())

    def test_redirects_are_not_followed(self):
        self.assertIsNone(HA.NoRedirect().redirect_request(None, None, 302, "", {}, "http://external.invalid"))

    def test_private_write_is_create_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.json"
            HA.private_write(path, b"first")
            with self.assertRaises(FileExistsError):
                HA.private_write(path, b"second")
            self.assertEqual(b"first", path.read_bytes())

    def test_wrong_binary_digest_denied_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = (Path(directory) / "program").resolve()
            path.write_bytes(b"synthetic executable bytes")
            path.chmod(0o700)
            with self.assertRaisesRegex(HA.FixtureError, "digest_mismatch"):
                HA.checked_binary(path, "0" * 64)
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(expected, HA.checked_binary(path, expected))

    def test_exact_startup_rejection_requires_one_terminal_diagnostic(self):
        expected = HA.MISBOUND_BOOTSTRAP_ERROR
        self.assertTrue(HA.exact_startup_rejection(
            1, ("listener ready\n" + expected + "\n").encode(), expected))
        for returncode, payload in [
            (None, expected.encode()),
            (0, expected.encode()),
            (-9, expected.encode()),
            (1, b"different failure\n"),
            (1, (expected + "\ntrailing output\n").encode()),
            (1, b"\xff"),
        ]:
            with self.subTest(returncode=returncode, payload=payload):
                self.assertFalse(HA.exact_startup_rejection(
                    returncode, payload, expected))

    def test_failed_scenario_is_not_recorded_as_success(self):
        cluster = self.cluster()
        with self.assertRaises(HA.FixtureError):
            cluster.check("unobserved", False)
        self.assertEqual([], cluster.scenarios)


class NativeSnapshotDownloadGuards(unittest.TestCase):
    """Real gzip/parser checks with a substituted transport, not a live server."""

    class Response(io.BytesIO):
        def __init__(self, raw, headers, status=200):
            super().__init__(raw)
            self.status, self.headers, self.read_sizes = status, Message(), []
            for name, value in headers:
                self.headers[name] = value

        def read(self, size=-1):
            self.read_sizes.append(size)
            return super().read(size)

    def setUp(self):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.node = HA.Node(1, Path("/unused/binary"), Path("/unused/root"),
                            self.context, ports=(19001, 19002))
        self.raw = gzip.compress(b"synthetic native snapshot bytes", mtime=0)

    def headers(self, raw):
        return [("Content-Type", "application/gzip"), ("Content-Length", str(len(raw)))]

    def invoke(self, response, *, error=None):
        opener = Mock()
        if error is None:
            opener.open.return_value = response
        else:
            opener.open.side_effect = error
        with patch.object(HA.urllib.request, "build_opener", return_value=opener) as build:
            try:
                return self.node.download_snapshot(token="synthetic-token", timeout=20)
            finally:
                opener.open.assert_called_once()
                request = opener.open.call_args.args[0]
                self.assertEqual("https://127.0.0.1:19001/v1/sys/storage/raft/snapshot", request.full_url)
                self.assertEqual("GET", request.get_method())
                self.assertIsNone(request.data)
                self.assertEqual("synthetic-token", request.get_header("X-vault-token"))
                self.assertEqual("application/gzip", request.get_header("Accept"))
                self.assertEqual({"timeout": 20}, opener.open.call_args.kwargs)
                proxy, redirect, tls = build.call_args.args
                self.assertEqual({}, proxy.proxies)
                self.assertIsInstance(redirect, HA.NoRedirect)
                self.assertIs(tls._context, self.context)

    def test_native_gzip_response_succeeds_without_json_decoding(self):
        response = self.Response(self.raw, self.headers(self.raw))
        with patch.object(HA.json, "loads", side_effect=AssertionError("JSON parser used")):
            result = self.invoke(response)
        self.assertTrue(response.closed)
        self.assertEqual([HA.SNAPSHOT_WIRE_LIMIT + 1], response.read_sizes)
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), result["archive_sha256"])
        self.assertEqual(len(self.raw), result["archive_bytes"])
        self.assertTrue(result["gzip_framing_verified"])
        self.assertFalse(result["archive_authenticity_verified"])
        self.assertFalse(result["restore_verified"])
        self.assertNotIn("synthetic native snapshot bytes", repr(result))

    def test_http_denial_and_redirect_close_without_read_or_retry(self):
        for status in (302, 403, 503):
            with self.subTest(status=status):
                response = self.Response(b"private error body", [], status)
                error = HA.urllib.error.HTTPError("https://127.0.0.1/", status,
                                                 "synthetic", Message(), response)
                with self.assertRaisesRegex(HA.FixtureError, "snapshot_download_http_status"):
                    self.invoke(response, error=error)
                self.assertTrue(response.closed)
                self.assertEqual([], response.read_sizes)

    def test_ambiguous_transport_error_is_not_retried(self):
        with self.assertRaises(TimeoutError):
            self.invoke(None, error=TimeoutError("synthetic timeout"))

    def test_wrong_duplicate_or_encoded_media_type_is_rejected(self):
        for headers in (
            [("Content-Type", "application/json"), ("Content-Length", str(len(self.raw)))],
            self.headers(self.raw) + [("Content-Type", "application/gzip")],
            self.headers(self.raw) + [("Transfer-Encoding", "chunked")],
            self.headers(self.raw) + [("Content-Encoding", "gzip")],
        ):
            with self.subTest(headers=headers):
                response = self.Response(self.raw, headers)
                with self.assertRaisesRegex(HA.FixtureError, "snapshot_download_framing"):
                    self.invoke(response)
                self.assertTrue(response.closed)
                self.assertEqual([], response.read_sizes)

    def test_missing_duplicate_and_noncanonical_lengths_are_rejected(self):
        for values in ([], ["1", "1"], ["0"], ["01"], ["-1"], ["+1"], [" 1"],
                       ["1 "], ["1,1"], ["\u0661"], ["100000000"]):
            with self.subTest(values=values):
                headers = [("Content-Type", "application/gzip")]
                headers += [("Content-Length", value) for value in values]
                response = self.Response(self.raw, headers)
                with self.assertRaisesRegex(HA.FixtureError, "snapshot_download_length"):
                    self.invoke(response)
                self.assertTrue(response.closed)
                self.assertEqual([], response.read_sizes)

    def test_declared_wire_bound_is_enforced_before_body_read(self):
        response = self.Response(self.raw, self.headers(self.raw))
        with patch.object(HA, "SNAPSHOT_WIRE_LIMIT", len(self.raw) - 1):
            with self.assertRaisesRegex(HA.FixtureError, "snapshot_download_wire_bound"):
                self.invoke(response)
        self.assertTrue(response.closed)
        self.assertEqual([], response.read_sizes)

    def test_truncated_or_overlong_body_is_rejected(self):
        for raw in (self.raw[:-1], self.raw + b"extra"):
            with self.subTest(length=len(raw)):
                response = self.Response(raw, self.headers(self.raw))
                with self.assertRaisesRegex(HA.FixtureError, "snapshot_download_length_mismatch"):
                    self.invoke(response)
                self.assertTrue(response.closed)

    def test_crc_invalid_and_nongzip_bodies_are_rejected(self):
        corrupt = bytearray(self.raw)
        corrupt[-8] ^= 1
        for raw in (bytes(corrupt), b'{"data":{}}'):
            with self.subTest(raw_length=len(raw)):
                response = self.Response(raw, self.headers(raw))
                with self.assertRaisesRegex(HA.FixtureError, "snapshot_download_invalid_gzip"):
                    self.invoke(response)
                self.assertTrue(response.closed)

    def test_empty_truncated_concatenated_and_trailing_gzip_are_rejected(self):
        for raw in (gzip.compress(b"", mtime=0), self.raw[:-1], self.raw + self.raw,
                    self.raw + b"ignored trailing bytes"):
            with self.subTest(raw_length=len(raw)):
                response = self.Response(raw, self.headers(raw))
                with self.assertRaisesRegex(HA.FixtureError, "snapshot_download_incomplete_or_trailing_gzip"):
                    self.invoke(response)
                self.assertTrue(response.closed)

    def test_expanded_boundary_is_inclusive_and_bounded(self):
        with patch.object(HA, "SNAPSHOT_EXPANDED_LIMIT", 128):
            raw = gzip.compress(b"x" * 128, mtime=0)
            self.assertEqual(128, self.invoke(self.Response(raw, self.headers(raw)))["expanded_bytes"])
            raw = gzip.compress(b"x" * 129, mtime=0)
            with self.assertRaisesRegex(HA.FixtureError, "snapshot_download_expanded_bound"):
                self.invoke(self.Response(raw, self.headers(raw)))


@unittest.skipUnless(os.name == "posix", "actual Unix child-process cleanup")
class StartupRejectionProcessCleanup(unittest.TestCase):
    """Exercise the actual Node/Popen cleanup path, without a server or socket."""

    def run_child(self, root, line, code, operation):
        program = root / "synthetic-server"
        program.write_text(
            "#!" + sys.executable + "\nimport sys\n"
            + "print(" + repr(line) + ", file=sys.stderr, flush=True)\n"
            + "raise SystemExit(" + str(code) + ")\n")
        program.chmod(0o700)
        node = HA.Node(1, program, root, None, ports=(19001, 19002))
        children = []
        original = HA.owned_process.popen

        def capture(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        try:
            with patch.object(HA.owned_process, "popen", side_effect=capture):
                operation(node)
        finally:
            self.assertEqual(1, len(children))
            self.assertEqual(code, children[0].poll())
            self.assertIsNone(node.process)
            self.assertIsNone(node.log)

    def test_exact_exit_one_rejection_is_reaped_without_sigkill_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_child(Path(directory), HA.MISBOUND_BOOTSTRAP_ERROR, 1,
                           lambda node: node.expect_startup_rejection(HA.MISBOUND_BOOTSTRAP_ERROR))

    def test_wrong_diagnostic_remains_original_rejection_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            def attempt(node):
                with self.assertRaisesRegex(HA.FixtureError, "unexpected_startup_rejection"):
                    node.expect_startup_rejection(HA.MISBOUND_BOOTSTRAP_ERROR)
            self.run_child(Path(directory), "different synthetic failure", 1, attempt)

    def test_exit_zero_never_qualifies_a_startup_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            def attempt(node):
                with self.assertRaisesRegex(HA.FixtureError, "unexpected_startup_rejection"):
                    node.expect_startup_rejection(HA.MISBOUND_BOOTSTRAP_ERROR)
            self.run_child(Path(directory), HA.MISBOUND_BOOTSTRAP_ERROR, 0, attempt)

    def test_ordinary_stop_still_rejects_unexpected_exit_one(self):
        with tempfile.TemporaryDirectory() as directory:
            def attempt(node):
                node.start(wait=False)
                self.assertEqual(1, HA.owned_process.wait(node.process, timeout=5))
                with self.assertRaisesRegex(HA.owned_process.OwnedFailure,
                                           "owned_standalone_shutdown_code"):
                    node.stop()
            self.run_child(Path(directory), "unqualified synthetic exit", 1, attempt)


if __name__ == "__main__":
    unittest.main()
