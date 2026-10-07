"""The step-down profile counts only exact acknowledgements and never retries uncertainty."""
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ha_step_down
from ha_destructive import FixtureError


class FakeNode:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def call(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error
        return self.response


class StepDownContractTests(unittest.TestCase):
    def cluster(self):
        cluster = ha_step_down.StepDownCluster.__new__(ha_step_down.StepDownCluster)
        cluster.root_token = "synthetic-root-token"
        return cluster

    def test_only_exact_version_one_is_acknowledged(self):
        cluster = self.cluster()
        node = FakeNode((200, {"data": {"version": 1}}))
        row = cluster._write_once(node, "unique", "value")
        self.assertEqual(row["outcome"], "acknowledged")
        self.assertEqual(len(node.calls), 1)
        body = node.calls[0][0][2]
        self.assertEqual(body["options"], {"cas": 0})
        self.assertEqual(body["data"], {"value": "value"})
        with self.assertRaisesRegex(FixtureError, "exact_version_one"):
            cluster._write_once(FakeNode((200, {"data": {"version": 2}})), "other", "value")

    def test_refusal_and_transport_uncertainty_are_not_retried_or_admitted(self):
        cluster = self.cluster()
        refused = FakeNode((503, {"errors": ["unavailable"]}))
        row = cluster._write_once(refused, "refused", "value")
        self.assertEqual((row["outcome"], len(refused.calls)), ("refused_no_retry", 1))
        unknown = FakeNode(error=TimeoutError("synthetic timeout"))
        row = cluster._write_once(unknown, "unknown", "value")
        self.assertEqual((row["outcome"], len(unknown.calls)), ("unknown_no_retry", 1))

    def test_required_scenarios_bind_load_interruption_restart_and_readback(self):
        required = ha_step_down.REQUIRED_SCENARIOS
        for name in (
            "step_down.concurrent_requests_overlap_transfer",
            "step_down.acknowledged_load_survives_transfer",
            "step_down.interrupted_request_sent_without_response",
            "step_down.no_blind_admin_retry",
            "step_down.interrupted_phase_acknowledged_values_survive",
            "step_down.old_leader_rejoined_after_interruption",
            "step_down.complete",
        ):
            self.assertIn(name, required)
        self.assertEqual(len(required), len(set(required)))

    def test_interrupted_request_sends_complete_frame_without_reading_response(self):
        cluster = self.cluster()
        observed = {}

        class Stream:
            def settimeout(self, value):
                observed["timeout"] = value
            def sendall(self, value):
                observed["request"] = value
            def shutdown(self, direction):
                observed["shutdown"] = direction
            def close(self):
                observed["closed"] = True

        stream = Stream()
        class Context:
            def wrap_socket(self, raw, server_hostname):
                observed["raw"] = raw
                observed["server_hostname"] = server_hostname
                return stream

        node = type("Node", (), {"http_port": 18200, "context": Context()})()
        with patch.object(ha_step_down.socket, "create_connection", return_value=object()), \
             patch.object(ha_step_down.time, "sleep"):
            cluster._send_step_down_without_read(node)
        request = observed["request"]
        self.assertIn(b"POST /v1/sys/step-down HTTP/1.1\r\n", request)
        self.assertIn(b"X-Vault-Token: synthetic-root-token\r\n", request)
        self.assertTrue(request.endswith(b"\r\n\r\n{}"))
        self.assertEqual(observed["shutdown"], socket.SHUT_WR)
        self.assertTrue(observed["closed"])


if __name__ == "__main__":
    unittest.main()
