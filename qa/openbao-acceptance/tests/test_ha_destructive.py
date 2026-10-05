"""Fixture guard tests only; these do not execute or qualify a real HA cluster."""
from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

FIXTURES = Path(__file__).resolve().parents[1]
if str(FIXTURES) not in sys.path:
    sys.path.insert(0, str(FIXTURES))
SPEC = importlib.util.spec_from_file_location("ha_destructive_under_test", FIXTURES / "ha_destructive.py")
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


class StartupRejectionObservationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.node = HA.Node.__new__(HA.Node)
        self.node.root = self.root
        self.node.process = Mock()
        self.node.process.wait.return_value = 1
        self.node.log = Mock()
        self.node._startup_log_offset = 0

    def test_terminal_rejection_reads_only_the_current_launch(self):
        old = (HA.MISBOUND_BOOTSTRAP_ERROR + "\n").encode()
        path = self.root / "process.log"
        path.write_bytes(old + b"different error\n")
        self.node._startup_log_offset = len(old)
        with self.assertRaisesRegex(HA.FixtureError, "unexpected_startup_rejection"):
            self.node.verify_startup_rejection(HA.MISBOUND_BOOTSTRAP_ERROR)
        path.write_bytes(old + old)
        self.node.verify_startup_rejection(HA.MISBOUND_BOOTSTRAP_ERROR)

    def test_missing_launch_identity_and_nonterminal_process_fail(self):
        self.node._startup_log_offset = None
        with self.assertRaises(HA.FixtureError):
            self.node.verify_startup_rejection(HA.MISBOUND_BOOTSTRAP_ERROR)
        self.node._startup_log_offset = 0
        self.node.process.wait.side_effect = subprocess.TimeoutExpired("synthetic", 10)
        with self.assertRaisesRegex(HA.FixtureError, "did_not_exit"):
            self.node.verify_startup_rejection(HA.MISBOUND_BOOTSTRAP_ERROR)

    def test_wrong_exit_oversized_or_nonterminal_diagnostic_fails(self):
        expected = (HA.MISBOUND_BOOTSTRAP_ERROR + "\n").encode()
        for returncode, delta in [(0, expected), (-9, expected),
                                  (1, b"x" * (64 * 1024) + expected),
                                  (1, expected + b"later error\n"), (1, b"\xff")]:
            with self.subTest(returncode=returncode, bytes=len(delta)):
                (self.root / "process.log").write_bytes(delta)
                self.node.process.wait.return_value = returncode
                with self.assertRaises(HA.FixtureError):
                    self.node.verify_startup_rejection(HA.MISBOUND_BOOTSTRAP_ERROR)

    def test_start_captures_existing_log_offset_before_one_launch(self):
        prefix = b"previous launch\n"
        (self.root / "process.log").write_bytes(prefix)
        self.node.process = None
        self.node.binary, self.node.ha_config = Path("/synthetic"), self.root / "ha.json"
        self.node.started_pids = []
        process = Mock(pid=123)
        with patch.object(HA.subprocess, "Popen", return_value=process) as launch:
            self.node.start(wait=False)
        self.addCleanup(self.node.log.close)
        launch.assert_called_once()
        self.assertEqual(self.node._startup_log_offset, len(prefix))
        self.assertEqual(self.node.started_pids, [123])

    def test_real_terminal_process_is_observed_without_another_launch(self):
        self.node.log = (self.root / "process.log").open("ab")
        self.node.process = subprocess.Popen(
            [sys.executable, "-c", "import sys; print(sys.argv[1]); sys.exit(1)",
             HA.MISBOUND_BOOTSTRAP_ERROR],
            stdin=subprocess.DEVNULL, stdout=self.node.log, stderr=self.node.log,
        )
        process = self.node.process
        try:
            with patch.object(self.node, "start") as start:
                self.node.verify_startup_rejection(HA.MISBOUND_BOOTSTRAP_ERROR)
            start.assert_not_called()
            self.assertIs(self.node.process, process)
            self.assertEqual(process.returncode, 1)
        finally:
            self.node.stop()
        self.assertIsNone(self.node.process)
        self.assertIsNone(self.node.log)
        self.assertIsNone(self.node._startup_log_offset)

    def test_expected_refusal_closes_log_when_process_launch_fails(self):
        self.node.process = None
        self.node.log = None
        self.node.binary, self.node.ha_config = Path("/synthetic"), self.root / "ha.json"
        self.node.started_pids = []
        with patch.object(HA.subprocess, "Popen", side_effect=OSError("synthetic launch failure")) as launch, \
                self.assertRaises(OSError):
            self.node.expect_startup_rejection(HA.MISBOUND_BOOTSTRAP_ERROR)
        launch.assert_called_once()
        self.assertIsNone(self.node.process)
        self.assertIsNone(self.node.log)
        self.assertIsNone(self.node._startup_log_offset)


if __name__ == "__main__":
    unittest.main()
