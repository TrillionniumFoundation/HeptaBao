"""Exact QA controls: real owned subprocesses, substituted listener observation.

No server is compiled or launched. No network or device operation is permitted.
The same real Node start/stop and rolling method run against tiny exit programs.
"""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ha_rolling_upgrade as upgrade
import owned_process


class TerminalNode(upgrade.Node):
    def wait_ready(self):
        self.wait_ready_calls += 1
        owned_process.wait(self.process, timeout=2)
        self.child = self.process
        raise upgrade.FixtureError("node_exited_during_startup")

    def call(self, *args, **kwargs):
        raise AssertionError("network_forbidden")


class RollingAdmissionActualProcessControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        patcher = patch.object(owned_process, "_CURRENT", None)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.ordinal = 0

    def make(self, payload, exit_code, prior=b"", module=upgrade):
        self.ordinal += 1
        root = self.root / str(self.ordinal)
        root.mkdir(mode=0o700)
        binary = root / "exit-program"
        binary.write_text(
            f"#!{sys.executable}\nimport sys\n"
            f"sys.stderr.buffer.write({payload!r})\n"
            f"raise SystemExit({exit_code!r})\n"
        )
        binary.chmod(0o700)
        if prior:
            (root / "process.log").write_bytes(prior)
        node = TerminalNode(3, binary, root, None, ports=(30131, 30132))
        node.wait_ready_calls = 0
        node.child = None
        cluster = module.RollingUpgradeCluster.__new__(module.RollingUpgradeCluster)
        cluster.base_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        cluster.candidate_digest = "b" * 64
        cluster.candidate_binary = root / "candidate-not-launched"
        cluster.scenarios = []
        cluster.unseal_key = "synthetic-unused"
        return cluster, node

    def assert_reaped(self, node):
        self.assertIsNone(node.process)
        self.assertIsNone(node.log)
        self.assertEqual(node.wait_ready_calls, 1)
        self.assertIsNotNone(node.child)
        self.assertIsNotNone(node.child.poll())
        self.assertEqual(node.child.wait(timeout=0), node.child.returncode)

    def test_exact_modern_base_rejection_is_accepted_and_reaped(self):
        cluster, node = self.make((upgrade.MISBOUND_BOOTSTRAP_ERROR + "\n").encode(), 1)
        cluster.assert_misbound_rejection(node)
        self.assertEqual(cluster.scenarios, ["rolling_upgrade_base_misbound_startup_rejected"])
        self.assert_reaped(node)
        self.assertEqual(node.child.returncode, 1)

    def test_wrong_or_stale_terminal_evidence_never_qualifies(self):
        exact = (upgrade.MISBOUND_BOOTSTRAP_ERROR + "\n").encode()
        for payload, code, prior in [
            (exact, 0, b""), (exact, 2, b""), (b"unrelated failure\n", 1, b""),
            (exact + b"unexpected trailing output\n", 1, b""),
            (b"x" * 65536 + exact, 1, b""), (b"", 1, exact),
        ]:
            with self.subTest(exit_code=code, payload_length=len(payload), prior=bool(prior)):
                cluster, node = self.make(payload, code, prior)
                with self.assertRaisesRegex(upgrade.FixtureError, "unexpected_startup_rejection"):
                    cluster.assert_misbound_rejection(node)
                self.assertEqual(cluster.scenarios, [])
                self.assert_reaped(node)

    def test_unknown_binary_rejected_before_any_launch(self):
        cluster, node = self.make((upgrade.MISBOUND_BOOTSTRAP_ERROR + "\n").encode(), 1)
        cluster.base_digest = "0" * 64
        with self.assertRaisesRegex(upgrade.FixtureError, "binary_digest_mismatch"):
            cluster.assert_misbound_rejection(node)
        self.assertEqual(node.started_pids, [])
        self.assertFalse((node.root / "process.log").exists())

    def test_listener_failure_is_not_reinterpreted_as_startup_rejection(self):
        cluster = upgrade.RollingUpgradeCluster.__new__(upgrade.RollingUpgradeCluster)
        cluster.candidate_binary = Path("/candidate")
        cluster.base_digest = "a" * 64
        node = Mock(binary=Path("/base"), root=self.root)
        node.wait_ready.side_effect = upgrade.FixtureError("node_listener_timeout")
        with patch.object(upgrade, "checked_binary"), self.assertRaisesRegex(upgrade.FixtureError, "node_listener_timeout"):
            cluster.assert_misbound_rejection(node)
        node.start.assert_called_once_with(wait=False)
        node.wait_ready.assert_called_once_with()
        node.call.assert_not_called()
        node.stop.assert_called_once_with()


class MixedSnapshotControls(unittest.TestCase):
    def cluster(self):
        c = upgrade.RollingUpgradeCluster.__new__(upgrade.RollingUpgradeCluster)
        c.root_token, c.scenarios, c.snapshot_downloads = "synthetic-unused", [], []
        return c

    def test_actual_Node_shared_helper_uses_only_status_compact_and_native_download(self):
        c = self.cluster()
        node = upgrade.Node(1, Path("/unused/server"), Path("/unused/node"),
                            None, ports=(19001, 19002))
        node.call = Mock(side_effect=[
            (200, {"data": {"applied_index": 90}}),
            (200, {"data": {"generation": 80, "retained_requests": 9,
                             "journal_bytes_before": 800, "journal_bytes_after": 0}}),
        ])
        node.download_snapshot = Mock(return_value={"http_status": 200,
                                                    "archive_sha256": "a" * 64})
        with patch.object(upgrade.time, "monotonic", side_effect=[100, 101, 102, 103, 104]):
            c.capture_mixed_snapshot(node)
        self.assertEqual(node.call.call_args_list, [
            call("GET", "sys/storage/raft/snapshot-status",
                               token=c.root_token, timeout=19),
            call("POST", "sys/storage/raft/compact", {},
                               token=c.root_token, timeout=18),
        ])
        node.download_snapshot.assert_called_once_with(token=c.root_token, timeout=17)
        self.assertEqual(c.scenarios, ["rolling_upgrade_snapshot_with_one_candidate_voter"])
        self.assertEqual(len(c.snapshot_downloads), 1)
        record = c.snapshot_downloads[0]
        self.assertEqual(record["phase"], "rolling_upgrade_one_candidate_voter")
        self.assertEqual(record["http_status"], 200)
        self.assertEqual(record["raft_compaction"]["target_applied_index"], 90)
        self.assertFalse(record["raft_compaction"]["purge_completion_verified"])

    def test_snapshot_failure_is_not_retried_or_counted_as_success(self):
        c = self.cluster()
        node = upgrade.Node(1, Path("/unused/server"), Path("/unused/node"),
                            None, ports=(19001, 19002))
        node.call = Mock(side_effect=upgrade.FixtureError("snapshot_operation_deadline"))
        node.download_snapshot = Mock()
        with self.assertRaisesRegex(upgrade.FixtureError, "snapshot_operation_deadline"):
            c.capture_mixed_snapshot(node)
        node.call.assert_called_once()
        node.download_snapshot.assert_not_called()
        self.assertEqual(c.scenarios, [])
        self.assertEqual(c.snapshot_downloads, [])


if __name__ == "__main__":
    unittest.main()
