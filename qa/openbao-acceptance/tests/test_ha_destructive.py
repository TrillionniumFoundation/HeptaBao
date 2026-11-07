"""Fixture guard tests only; these do not execute or qualify a real HA cluster."""
from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path
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

    def test_verified_startup_rejection_reaps_exact_observed_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            node = HA.Node.__new__(HA.Node)
            node.root = Path(directory)
            node.process = None
            node.log = None
            expected = HA.MISBOUND_BOOTSTRAP_ERROR
            process = Mock()

            def start_without_wait(instance, *, wait=True):
                self.assertFalse(wait)
                (instance.root / "process.log").write_bytes((expected + "\\n").encode())
                instance.log = (instance.root / "process.log").open("ab")
                instance.process = process

            with patch.object(HA.Node, "start", new=start_without_wait), \\
                    patch.object(HA.owned_process, "wait", return_value=1), \\
                    patch.object(HA.owned_process, "stop", return_value=1) as stop:
                node.expect_startup_rejection(expected)

            stop.assert_called_once_with(
                process, action="KILL", timeout=10, expected_codes=(1,))
            self.assertIsNone(node.process)
            self.assertIsNone(node.log)

    def test_unverified_startup_exit_keeps_strict_sigkill_cleanup_code(self):
        with tempfile.TemporaryDirectory() as directory:
            node = HA.Node.__new__(HA.Node)
            node.root = Path(directory)
            node.process = None
            node.log = None
            expected = HA.MISBOUND_BOOTSTRAP_ERROR
            process = Mock()

            def start_without_wait(instance, *, wait=True):
                self.assertFalse(wait)
                (instance.root / "process.log").write_bytes((expected + "\\n").encode())
                instance.log = (instance.root / "process.log").open("ab")
                instance.process = process

            def reject_wrong_cleanup_code(child, *, action=None, timeout=None, expected_codes=None):
                self.assertIs(child, process)
                self.assertEqual(expected_codes, (-9,))
                raise HA.owned_process.OwnedFailure("owned_standalone_shutdown_code")

            with patch.object(HA.Node, "start", new=start_without_wait), \\
                    patch.object(HA.owned_process, "wait", return_value=2), \\
                    patch.object(HA.owned_process, "stop", side_effect=reject_wrong_cleanup_code) as stop:
                with self.assertRaisesRegex(
                        HA.owned_process.OwnedFailure, "^owned_standalone_shutdown_code$"):
                    node.expect_startup_rejection(expected)

            stop.assert_called_once_with(
                process, action="KILL", timeout=10, expected_codes=(-9,))
            self.assertIsNone(node.process)
            self.assertIsNone(node.log)


if __name__ == "__main__":
    unittest.main()
