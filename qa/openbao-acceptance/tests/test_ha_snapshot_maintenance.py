"""Snapshot maintenance guards; substituted HTTP is not real HA evidence."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, call, patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HA = load("ha_snapshot_maintenance_under_test", "ha_destructive.py")
REPLAY = load("replay_snapshot_maintenance_under_test", "replay_epoch_ha.py")


class SnapshotMaintenanceGuards(unittest.TestCase):
    def setUp(self):
        self.node = HA.Node(1, Path("/unused/server"), Path("/unused/node"),
                            None, ports=(19001, 19002))
        self.before = {"data": {"applied_index": 90, "snapshot_index": 12, "purged_index": 12}}
        self.compacted = {"data": {"generation": 80, "retained_requests": 9,
                                    "journal_bytes_before": 800, "journal_bytes_after": 0}}
        self.node.call = Mock(side_effect=[(200, self.before), (200, self.compacted)])
        self.node.download_snapshot = Mock(return_value={"gzip_framing_verified": True})

    def run_snapshot(self):
        return self.node.snapshot_after_compaction(token="synthetic", timeout=20)

    def test_explicit_maintenance_precedes_download_under_one_budget(self):
        events = []

        def request(method, path, *args, **kwargs):
            events.append((method, path))
            return (200, self.before if method == "GET" else self.compacted)

        def download(**kwargs):
            events.append(("GET", "native-download"))
            return {"gzip_framing_verified": True}

        self.node.call.side_effect = request
        self.node.download_snapshot.side_effect = download
        with patch.object(HA.time, "monotonic", side_effect=[100, 101, 102, 103, 104]):
            result = self.run_snapshot()
        self.assertEqual([("GET", "sys/storage/raft/snapshot-status"),
                          ("POST", "sys/storage/raft/compact"),
                          ("GET", "native-download")], events)
        self.assertEqual([call("GET", "sys/storage/raft/snapshot-status", token="synthetic", timeout=19),
                          call("POST", "sys/storage/raft/compact", {}, token="synthetic", timeout=18)],
                         self.node.call.call_args_list)
        self.node.download_snapshot.assert_called_once_with(token="synthetic", timeout=17)
        self.assertEqual(90, result["raft_compaction"]["target_applied_index"])
        self.assertFalse(result["raft_compaction"]["purge_completion_verified"])

    def test_missing_or_invalid_frontier_refuses_before_maintenance(self):
        for status, body in [(503, {}), (200, {}), (200, {"data": []})] + [
                (200, {"data": {"applied_index": value}})
                for value in (None, False, 0, -1, "90", 1.0, 2 ** 64)]:
            with self.subTest(status=status, body=body):
                self.node.call.reset_mock(side_effect=True)
                self.node.call.return_value = status, body
                with self.assertRaisesRegex(HA.FixtureError, "pre_compaction_frontier"):
                    self.run_snapshot()
                self.node.call.assert_called_once()
                self.node.download_snapshot.assert_not_called()

    def test_denied_maintenance_is_not_replayed_or_downloaded(self):
        self.node.call.side_effect = [(200, self.before), (403, {"errors": ["synthetic"]})]
        with self.assertRaisesRegex(HA.FixtureError, "compaction_not_acknowledged"):
            self.run_snapshot()
        self.assertEqual(2, self.node.call.call_count)
        self.node.download_snapshot.assert_not_called()

    def test_invalid_compaction_counters_are_not_success_receipts(self):
        bad = []
        for field in self.compacted["data"]:
            for value in (None, False, -1, "0", 0.0, 2 ** 64):
                data = dict(self.compacted["data"], **{field: value})
                bad.append(data)
        bad.append(dict(self.compacted["data"], journal_bytes_after=801))
        for data in bad:
            with self.subTest(data=data):
                self.node.call.reset_mock(side_effect=True)
                self.node.call.side_effect = [(200, self.before), (200, {"data": data})]
                with self.assertRaisesRegex(HA.FixtureError, "compaction_not_acknowledged"):
                    self.run_snapshot()
                self.assertEqual(2, self.node.call.call_count)
                self.node.download_snapshot.assert_not_called()

    def test_ambiguous_post_is_not_replayed(self):
        self.node.call.side_effect = [(200, self.before), TimeoutError("synthetic")]
        with self.assertRaises(TimeoutError):
            self.run_snapshot()
        self.assertEqual(2, self.node.call.call_count)
        self.node.download_snapshot.assert_not_called()

    def test_exhausted_budget_refuses_before_maintenance(self):
        with patch.object(HA.time, "monotonic", side_effect=[100, 101, 120]):
            with self.assertRaisesRegex(HA.FixtureError, "snapshot_operation_deadline"):
                self.run_snapshot()
        self.node.call.assert_called_once()
        self.node.download_snapshot.assert_not_called()

    def test_completed_download_after_original_budget_still_fails(self):
        with patch.object(HA.time, "monotonic", side_effect=[100, 101, 102, 103, 120.1]):
            with self.assertRaisesRegex(HA.FixtureError, "snapshot_operation_deadline"):
                self.run_snapshot()
        self.assertEqual(2, self.node.call.call_count)
        self.node.download_snapshot.assert_called_once()

    def test_bad_download_never_restarts_maintenance(self):
        self.node.download_snapshot.side_effect = HA.FixtureError("snapshot_download_invalid_gzip")
        with self.assertRaisesRegex(HA.FixtureError, "invalid_gzip"):
            self.run_snapshot()
        self.assertEqual(2, self.node.call.call_count)
        self.node.download_snapshot.assert_called_once()


class ReplaySnapshotFrontierGuards(unittest.TestCase):
    def test_current_epoch_frontier_must_be_covered(self):
        self.assertTrue(REPLAY.snapshot_covers_frontier({"snapshot_index": 90, "purged_index": 90}, 90))
        self.assertTrue(REPLAY.snapshot_covers_frontier({"snapshot_index": 92, "purged_index": 91}, 90))

    def test_positive_old_purge_is_insufficient(self):
        self.assertFalse(REPLAY.snapshot_covers_frontier({"snapshot_index": 12, "purged_index": 12}, 90))
        self.assertFalse(REPLAY.snapshot_covers_frontier({"snapshot_index": 90, "purged_index": 89}, 90))

    def test_inverted_frontier_is_rejected(self):
        self.assertFalse(REPLAY.snapshot_covers_frontier({"snapshot_index": 89, "purged_index": 90}, 90))

    def test_missing_noninteger_or_out_of_range_frontier_is_rejected(self):
        for value in (None, False, True, -1, 0, "90", 90.0, 2 ** 64):
            for field in ("target", "snapshot_index", "purged_index"):
                with self.subTest(field=field, value=value):
                    data = {"snapshot_index": 90, "purged_index": 90}
                    target = value if field == "target" else 90
                    if field != "target":
                        data[field] = value
                    self.assertFalse(REPLAY.snapshot_covers_frontier(data, target))
        self.assertFalse(REPLAY.snapshot_covers_frontier({}, 90))


if __name__ == "__main__":
    unittest.main()
