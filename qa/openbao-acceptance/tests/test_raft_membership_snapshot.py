"""Actual membership/Node methods with only HTTP and clock substituted."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ha_destructive as ha
import raft_membership_live as membership


class MembershipSnapshotGuards(unittest.TestCase):
    def setUp(self):
        self.cluster = membership.AdminCluster.__new__(membership.AdminCluster)
        self.cluster.root_token = "synthetic-unused"
        self.cluster.scenarios = []
        self.cluster.snapshot_downloads = []
        self.node = ha.Node(1, Path("/unused/server"), Path("/unused/node"),
                            None, ports=(19001, 19002))
        self.node.call = Mock(side_effect=[
            (200, {"data": {"applied_index": 90}}),
            (200, {"data": {"generation": 80, "retained_requests": 9,
                             "journal_bytes_before": 800, "journal_bytes_after": 0}}),
        ])
        self.node.download_snapshot = Mock(return_value={
            "http_status": 200, "gzip_framing_verified": True,
            "archive_sha256": "a" * 64,
        })

    def test_actual_helper_keeps_twelve_second_budget_and_native_download(self):
        with patch.object(ha.time, "monotonic", side_effect=[100, 101, 102, 103, 104]):
            self.cluster.capture_prejoin_snapshot(self.node)
        self.assertEqual(self.node.call.call_args_list, [
            call("GET", "sys/storage/raft/snapshot-status", token="synthetic-unused", timeout=11),
            call("POST", "sys/storage/raft/compact", {}, token="synthetic-unused", timeout=10),
        ])
        self.node.download_snapshot.assert_called_once_with(token="synthetic-unused", timeout=9)
        self.assertEqual(self.cluster.scenarios, ["snapshot_waits_durable_readback"])
        self.assertEqual(len(self.cluster.snapshot_downloads), 1)
        record = self.cluster.snapshot_downloads[0]
        self.assertEqual(record["phase"], "prejoin")
        self.assertEqual(record["raft_compaction"]["target_applied_index"], 90)
        self.assertFalse(record["raft_compaction"]["purge_completion_verified"])

    def test_late_native_download_is_not_success_or_retried(self):
        with patch.object(ha.time, "monotonic", side_effect=[100, 101, 102, 103, 112.001]):
            with self.assertRaisesRegex(ha.FixtureError, "snapshot_operation_deadline"):
                self.cluster.capture_prejoin_snapshot(self.node)
        self.assertEqual(self.node.call.call_count, 2)
        self.node.download_snapshot.assert_called_once_with(token="synthetic-unused", timeout=9)
        self.assertEqual(self.cluster.scenarios, [])
        self.assertEqual(self.cluster.snapshot_downloads, [])


if __name__ == "__main__":
    unittest.main()
