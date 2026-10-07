"""Guard the real HA read fixture against stale-success and false-pass receipts."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / "ha_verified_read_live.py"
sys.path.insert(0, str(SOURCE.parent))
SPEC = importlib.util.spec_from_file_location("ha_verified_read_fixture", SOURCE)
assert SPEC is not None and SPEC.loader is not None
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def response(value="latest", version=2):
    return 200, {"data": {"data": {"value": value}, "metadata": {"version": version}}}


class ReadGuards(unittest.TestCase):
    def setUp(self):
        self.node = Mock()

    def test_successful_stale_or_malformed_read_is_never_retried(self):
        for observed in (response("stale"), response(version=1), response(version=True),
                         response(version=3), (200, {}), (200, {"data": None}),
                         (404, {}), (True, {}), (503.0, {})):
            with self.subTest(observed=observed):
                self.node.reset_mock()
                self.node.call.side_effect = [observed, response()]
                with self.assertRaises(fixture.FixtureError):
                    fixture.read_exact(self.node, "synthetic-bearer", "latest", 2, recover=True)
                self.node.call.assert_called_once()

    def test_recovery_may_retry_only_unavailability(self):
        self.node.call.side_effect = [(503, {}), (429, {}), response()]
        with patch.object(fixture.time, "sleep"):
            fixture.read_exact(self.node, "synthetic-bearer", "latest", 2, recover=True)
        self.assertEqual(self.node.call.call_count, 3)

    def test_stable_warm_read_unavailability_is_not_hidden(self):
        self.node.call.side_effect = [(503, {}), response()]
        with self.assertRaises(fixture.FixtureError):
            fixture.read_exact(self.node, "synthetic-bearer", "latest", 2)
        self.node.call.assert_called_once()

    def test_recovery_timeout_cannot_turn_into_pass(self):
        self.node.call.return_value = 503, {}
        with patch.object(fixture.time, "monotonic", side_effect=[0, 31]):
            with self.assertRaises(fixture.FixtureError):
                fixture.read_exact(self.node, "synthetic-bearer", "latest", 2, recover=True)
        self.node.call.assert_called_once()

    def test_transport_failure_is_failure_not_authority_denial(self):
        self.node.call.side_effect = TimeoutError("private-response-sentinel")
        with self.assertRaises(TimeoutError):
            fixture.read_exact(self.node, "synthetic-bearer", "latest", 2, recover=True)
        self.node.call.assert_called_once()

    def test_partition_and_seal_require_503_with_no_released_data(self):
        self.assertTrue(fixture.read_denied(503, {"errors": ["unavailable"]}))
        for observed in (response(), (429, {}), (200, {}), (503, {"data": {"value": "old"}}),
                         (503, {"auth": {"client_token": "private-bearer"}}),
                         (503, {"wrap_info": {"token": "private-wrapper"}}),
                         (503.0, {}), (True, {}), (503, None)):
            with self.subTest(observed=observed):
                self.assertFalse(fixture.read_denied(*observed))


class WriteGuards(unittest.TestCase):
    def test_ambiguous_or_wrong_version_mutation_is_never_replayed(self):
        node = Mock()
        for observed in ((503, {}), (200, {}), (200, {"data": {"version": True}}),
                         (200, {"data": {"version": 1}}), (200, {"data": {"version": 3}})):
            with self.subTest(observed=observed):
                node.reset_mock()
                node.call.return_value = observed
                with self.assertRaises(fixture.FixtureError):
                    fixture.write_once(node, "synthetic-bearer", "latest", 1)
                node.call.assert_called_once()
                self.assertEqual(node.call.call_args.args[2]["options"], {"cas": 1})

    def test_timeout_mutation_is_never_replayed(self):
        node = Mock()
        node.call.side_effect = TimeoutError("private-response-sentinel")
        with self.assertRaises(TimeoutError):
            fixture.write_once(node, "synthetic-bearer", "latest", 1)
        node.call.assert_called_once()


class ReceiptGuards(unittest.TestCase):
    @staticmethod
    def checks():
        return [{"case": name, "passed": True} for name in sorted(fixture.REQUIRED_PHASES - {"complete"})]

    def test_partial_false_duplicate_or_unfinished_evidence_is_rejected(self):
        valid = self.checks() + [{"case": "complete", "passed": True}]
        self.assertTrue(fixture.complete_checks(valid))
        variants = [[], [{"case": "complete", "passed": True}], valid[:-1], valid + valid[-1:],
                    valid + [{"case": "after_complete", "passed": True}],
                    [{"case": row["case"], "passed": 1} for row in valid],
                    [{"case": row["case"], "passed": False} for row in valid],
                    valid + [{"case": "secret-bearing/path", "passed": True}]]
        for rows in variants:
            with self.subTest(rows=rows):
                self.assertFalse(fixture.complete_checks(rows))

    def test_cleanup_failure_cannot_produce_complete_evidence(self):
        cluster = Mock()
        cluster.bootstrap.side_effect = fixture.FixtureError("bootstrap_failed")
        cluster.close.side_effect = fixture.FixtureError("cleanup_failed")
        checks = []
        with patch.object(fixture, "PartitionCluster", return_value=cluster):
            with self.assertRaises(fixture.FixtureError):
                fixture.run(Path("/synthetic/binary"), Path("/synthetic/root"), checks, [], [])
        cluster.close.assert_called_once()
        self.assertFalse(fixture.complete_checks(checks))

    def test_signal_is_classified_as_failure(self):
        with self.assertRaises(fixture.FixtureError):
            fixture.terminate(15, None)


if __name__ == "__main__":
    unittest.main()
