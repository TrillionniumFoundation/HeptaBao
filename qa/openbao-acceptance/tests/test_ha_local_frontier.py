"""A forwarded business read is not evidence of local voter recovery."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ha_multihost_live as profile


class Clock:
    def __init__(self):
        self.value = 0.0

    def now(self):
        return self.value

    def sleep(self, duration):
        self.value += duration


class LocalRaftFrontierTests(unittest.TestCase):
    def setUp(self):
        self.node = profile.parse_node("fixture,100.64.1.2,/home/fixture/heptabao-test", 1, 46230, 46231)

    def test_frontier_requires_valid_local_metadata_not_a_business_response(self):
        for body in [{}, {"data": {"value": "synthetic"}},
                     {"ha_enabled": True, "raft_committed_index": True, "raft_applied_index": 1},
                     {"ha_enabled": True, "raft_committed_index": 7, "raft_applied_index": False},
                     {"ha_enabled": True, "raft_committed_index": 6, "raft_applied_index": 7},
                     {"ha_enabled": False, "raft_committed_index": 7, "raft_applied_index": 7},
                     {"ha_enabled": True, "raft_committed_index": 1 << 64, "raft_applied_index": 7}]:
            with self.subTest(body=body):
                self.assertIsNone(profile.parsed_local_frontier(body))
        self.assertEqual(profile.parsed_local_frontier({"ha_enabled": True,
                         "raft_committed_index": 8, "raft_applied_index": 7}), (8, 7))

    def test_anchor_must_be_current_leader_not_follower_or_forwarded_read(self):
        for body in [{"data": {}}, {"ha_enabled": True, "raft_committed_index": 8,
                                    "raft_applied_index": 7}]:
            with patch.object(profile, "api", return_value=(200, body)):
                with self.assertRaisesRegex(profile.FixtureError, "leader_frontier_anchor_unavailable"):
                    profile.capture_committed_frontier(None, self.node)
        with patch.object(profile, "api", return_value=(200, {"ha_enabled": True,
                "is_self": True, "raft_committed_index": 8, "raft_applied_index": 7})) as api:
            self.assertEqual(profile.capture_committed_frontier(None, self.node), 8)
            api.assert_called_once_with(None, self.node, "GET", "sys/leader", timeout=4)

    def test_waits_for_local_applied_frontier_using_only_passive_local_endpoint(self):
        clock = Clock()
        replies = [(200, {"ha_enabled": True, "raft_committed_index": 8, "raft_applied_index": 6}),
                   (200, {"ha_enabled": True, "raft_committed_index": 8, "raft_applied_index": 7})]
        with patch.object(profile.time, "monotonic", clock.now), patch.object(profile.time, "sleep", clock.sleep),                 patch.object(profile, "api", side_effect=replies) as api:
            self.assertEqual(profile.wait_local_frontier(None, self.node, 7, seconds=1), (8, 7))
            self.assertEqual(api.call_count, 2)
            for call in api.call_args_list:
                self.assertEqual(call.args, (None, self.node, "GET", "sys/leader"))
                self.assertLessEqual(call.kwargs["timeout"], 1)

    def test_late_ready_reply_cannot_reset_deadline_or_issue_a_pass(self):
        clock = Clock()
        events = []
        def late(*args, **kwargs):
            clock.value += 1.0
            return 200, {"ha_enabled": True, "raft_committed_index": 7, "raft_applied_index": 7}
        with patch.object(profile.time, "monotonic", clock.now), patch.object(profile.time, "sleep", clock.sleep),                 patch.object(profile, "api", side_effect=late) as api:
            with self.assertRaisesRegex(profile.FixtureError, "node_1_raft_frontier_timeout"):
                profile.wait_local_frontier(None, self.node, 7, seconds=0.2,
                                             record=lambda *a, **kw: events.append((a, kw)))
            self.assertEqual(api.call_count, 1)
        self.assertEqual(events, [(("local_raft_frontier_timeout",), {
            "node": 1, "required_index": 7, "committed_index": 7, "applied_index": 7})])

    def test_failed_health_observation_keeps_only_boolean_flags_and_safe_error(self):
        import json
        events = []
        body = {"initialized": True, "sealed": False, "standby": False,
                "ha_active": True, "ha_application_ready": False,
                "recovery_required": True, "errors": ["synthetic-private-error"],
                "cluster_id": "synthetic-private-cluster", "token": "synthetic-private-token"}
        with patch.object(profile, "api", return_value=(503, body)) as request:
            profile.record_health_failure(None, self.node, lambda name, **kw: events.append({"event": name, **kw}))
            request.assert_called_once_with(None, self.node, "GET", "sys/health", timeout=4)
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0]["recovery_required"])
        self.assertFalse(events[0]["ha_application_ready"])
        self.assertEqual(events[0]["failure_code"], "http_503_unclassified")
        self.assertNotIn("synthetic-private", json.dumps(events))
        self.assertNotIn("passed", events[0])
        body.update({"initialized": 1, "sealed": "false", "recovery_required": {"token": "private"}})
        events.clear()
        with patch.object(profile, "api", return_value=(503, body)):
            profile.record_health_failure(None, self.node, lambda name, **kw: events.append(kw))
        for name in ("initialized", "sealed", "recovery_required"):
            self.assertIsNone(events[0][name])

    def test_health_diagnostic_transport_failure_is_not_retried_or_admitted(self):
        events = []
        with patch.object(profile, "api", side_effect=TimeoutError("synthetic-private-error")) as request:
            profile.record_health_failure(None, self.node, lambda name, **kw: events.append({"event": name, **kw}))
            self.assertEqual(request.call_count, 1)
        self.assertEqual(events, [{"event": "failed_transfer_health_observation",
                                  "node": 1, "status": "transport_or_deadline"}])

    def test_stale_or_invalid_observations_never_qualify(self):
        clock = Clock()
        with patch.object(profile.time, "monotonic", clock.now), patch.object(profile.time, "sleep", clock.sleep),                 patch.object(profile, "api", return_value=(200, {"data": {"value": "synthetic-private"}})):
            with self.assertRaisesRegex(profile.FixtureError, "raft_frontier_timeout"):
                profile.wait_local_frontier(None, self.node, 7, seconds=0.2)
        for invalid in [0, -1, True, 1 << 64, "7"]:
            with patch.object(profile, "api") as api:
                with self.assertRaisesRegex(profile.FixtureError, "invalid_required_raft_frontier"):
                    profile.wait_local_frontier(None, self.node, invalid)
                api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
