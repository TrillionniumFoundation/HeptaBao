"""Guard the real deadline fixture against client-timeout and 503 false claims."""
from __future__ import annotations
import copy
import importlib.util
from pathlib import Path
import queue
import sys
import threading
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / "ha_request_deadline_live.py"
sys.path.insert(0, str(SOURCE.parent))
SPEC = importlib.util.spec_from_file_location("ha_request_deadline_fixture", SOURCE)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def row(ordinal=0, *, status=503, termination="http", elapsed=4100, body=3501):
    return {"ordinal": ordinal, "status": status, "termination": termination,
            "elapsed_ms": elapsed, "body_sent_ms": body, "no_payload": True}


def observations():
    gate = {"request_count": fixture.CONTENDED_READS,
        "all_headers_sent_before_body_release": True,
        "all_bodies_released_before_original_deadlines": True,
        "header_spread_ms": 30, "body_hold_seconds": fixture.BODY_HOLD_SECONDS}
    rows = [row(i) for i in range(fixture.CONTENDED_READS)]
    rows[-1] = row(fixture.CONTENDED_READS - 1, status=None, termination="peer_eof", elapsed=5002)
    return [
        {"phase": "healthy_same_delayed_get", "gate": gate, "elapsed_ms": 3550, "http_status": 200},
        {"phase": "lost_quorum", "requests": [row(body=0, elapsed=202)]},
        {"phase": "contended_read_admission", "gate": gate, "requests": rows,
         "http_503_count": len(rows) - 1, "peer_termination_count": 1,
         "all_requests_returned_http_503": False},
    ]


class DeadlineGuards(unittest.TestCase):
    def test_only_503_or_separately_labeled_peer_termination_is_accepted(self):
        self.assertTrue(fixture.safe_outcome(row()))
        self.assertTrue(fixture.safe_outcome(row(status=None, termination="peer_eof", elapsed=5000)))
        for update in ({"status": 200}, {"status": 429}, {"status": 503.0}, {"status": True},
                       {"no_payload": False}, {"elapsed_ms": 8000}, {"elapsed_ms": float("nan")},
                       {"body_sent_ms": 4900}, {"termination": "client_timeout", "status": None},
                       {"termination": "peer_eof", "status": 503}):
            invalid = row(); invalid.update(update)
            self.assertFalse(fixture.safe_outcome(invalid), update)

    def test_closed_connections_cannot_be_relabelled_as_all_503(self):
        valid = observations()
        self.assertTrue(fixture.complete_observations(valid))
        wrong = copy.deepcopy(valid)
        wrong[-1]["all_requests_returned_http_503"] = True
        self.assertFalse(fixture.complete_observations(wrong))
        wrong = copy.deepcopy(valid)
        for entry in wrong[-1]["requests"]:
            entry.update(status=None, termination="peer_eof")
        wrong[-1].update(http_503_count=0, peer_termination_count=fixture.CONTENDED_READS,
                         all_requests_returned_http_503=False)
        self.assertFalse(fixture.complete_observations(wrong))

    def test_missing_delayed_control_or_early_body_is_not_deadline_evidence(self):
        for change in (lambda o: o.pop(0), lambda o: o[0].update(http_status=503),
                       lambda o: o[-1]["gate"].update(all_headers_sent_before_body_release=False),
                       lambda o: o[-1]["requests"][0].update(body_sent_ms=0),
                       lambda o: o[-1]["requests"].pop()):
            invalid = observations(); change(invalid)
            self.assertFalse(fixture.complete_observations(invalid))

    def test_client_watchdog_and_truncated_response_propagate_failure(self):
        for error in (TimeoutError("private-sentinel"), ConnectionResetError("private-sentinel"),
                      fixture.http.client.IncompleteRead(b"private-sentinel")):
            connection = Mock()
            connection.getresponse.side_effect = error
            released = threading.Event(); released.set()
            with patch.object(fixture.http.client, "HTTPSConnection", return_value=connection):
                with self.assertRaises(type(error)):
                    fixture.delayed_get(Mock(), "private-bearer", 0, queue.Queue(), released)
            connection.getresponse.assert_called_once()
            connection.close.assert_called_once()
            connection.send.assert_called_once_with(b"{}")

    def test_only_http_status_line_eof_is_reported_as_peer_termination(self):
        connection = Mock()
        connection.getresponse.side_effect = fixture.http.client.RemoteDisconnected()
        released = threading.Event(); released.set()
        with patch.object(fixture.http.client, "HTTPSConnection", return_value=connection):
            observed, body = fixture.delayed_get(Mock(), "private-bearer", 0, queue.Queue(), released)
        self.assertEqual(observed["termination"], "peer_eof")
        self.assertIsNone(observed["status"])
        self.assertEqual(body, {})
        self.assertTrue(fixture.safe_outcome(observed))

    def test_get_has_one_fixed_body_and_waits_for_the_shared_release(self):
        connection = Mock()
        response = Mock(status=503)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'{"errors":["unavailable"]}'
        connection.getresponse.return_value = response
        released = threading.Event(); headers = queue.Queue()
        with patch.object(fixture.http.client, "HTTPSConnection", return_value=connection):
            result = []
            worker = threading.Thread(target=lambda: result.append(
                fixture.delayed_get(Mock(), "private-bearer", 0, headers, released)))
            worker.start()
            headers.get(timeout=1)
            connection.send.assert_not_called()
            released.set(); worker.join(timeout=1)
            self.assertFalse(worker.is_alive())
        self.assertEqual(result[0][0]["status"], 503)
        connection.putrequest.assert_called_once_with("GET", "/v1/" + fixture.KEY)
        connection.putheader.assert_any_call("Content-Length", "2")
        connection.send.assert_called_once_with(b"{}")

    def test_ambiguous_recovery_write_is_not_retried(self):
        node = Mock()
        node.call.side_effect = TimeoutError("private-sentinel")
        with self.assertRaises(TimeoutError):
            fixture.write_once(node, "private-bearer", "private-value", 1)
        node.call.assert_called_once()

    def test_receipt_requires_named_completion_no_duplicates_or_false_rows(self):
        valid = [{"case": name, "passed": True} for name in sorted(fixture.REQUIRED - {"complete"})]
        valid.append({"case": "complete", "passed": True})
        self.assertTrue(fixture.complete(valid))
        for invalid in ([], valid[:-1], valid[1:], valid + valid[-1:],
                        [{"case": r["case"], "passed": 1} for r in valid]):
            self.assertFalse(fixture.complete(invalid))

    def test_failure_always_resumes_owned_processes_before_cleanup(self):
        cluster = Mock()
        node = Mock()
        node.process.pid = 12345
        node.process.poll.return_value = None
        cluster.nodes = [node]
        cluster.bootstrap.side_effect = fixture.FixtureError("synthetic_failure")
        with patch.object(fixture, "DeadlineCluster", return_value=cluster), patch.object(fixture.os, "kill") as kill:
            with self.assertRaises(fixture.FixtureError):
                fixture.run(Path("/synthetic/bin"), Path("/synthetic/root"), [], [], [])
        kill.assert_called_once_with(12345, fixture.signal.SIGCONT)
        cluster.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
