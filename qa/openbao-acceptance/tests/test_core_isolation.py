"""Harness failures preserve partial observations without copying secrets."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core_isolation
from bao_http import Response


class FailingClient:
    def request(self, method, path, payload=None, *, token=None):
        return Response(503, {"errors": ["sentinel-private-response"], "auth": {"client_token": "do-not-log"}})


class CoreIsolationHarnessTests(unittest.TestCase):
    def test_failure_records_only_fixed_case_and_status(self):
        observations = []
        with self.assertRaisesRegex(core_isolation.ScenarioFailure, "^token.alice$"):
            core_isolation.run_scenarios(FailingClient(), observations)
        self.assertEqual(observations, [{"case": "token.alice", "status": 503, "passed": False}])
        self.assertNotIn("sentinel-private-response", json.dumps(observations))
        self.assertNotIn("do-not-log", json.dumps(observations))

    def test_partial_observation_sink_is_not_replaced(self):
        observations = [{"case": "previous", "passed": True}]
        with self.assertRaises(core_isolation.ScenarioFailure):
            core_isolation.run_scenarios(FailingClient(), observations)
        self.assertEqual(len(observations), 2)
        self.assertFalse(observations[-1]["passed"])

    def test_nonprivate_output_parent_is_rejected_before_allocating_a_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o755)
            argv = ['compare', '--binary', sys.executable, '--output', str(parent / 'report.json')]
            with patch.object(sys, 'argv', argv), patch.object(core_isolation.tempfile, 'mkdtemp') as allocate:
                with self.assertRaises(SystemExit) as raised:
                    core_isolation.main()
                self.assertEqual(raised.exception.code, 2)
                allocate.assert_not_called()
            self.assertFalse((parent / 'report.json').exists())

    def test_private_output_parent_passes_admission_before_fixture_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            argv = ['compare', '--binary', sys.executable, '--output', str(parent / 'report.json')]
            with patch.object(sys, 'argv', argv), patch.object(core_isolation.tempfile, 'mkdtemp',
                    side_effect=RuntimeError('fixture-allocation-reached')) as allocate:
                with self.assertRaisesRegex(RuntimeError, '^fixture-allocation-reached$'):
                    core_isolation.main()
                allocate.assert_called_once()
            self.assertFalse((parent / 'report.json').exists())

    def test_invalid_side_contract_configuration_is_rejected_before_fixture(self):
        with patch.object(core_isolation.tempfile, "mkdtemp") as allocate:
            with self.assertRaisesRegex(ValueError, "oracle scenario runner"):
                core_isolation.main(oracle_scenario_runner=object())
            with self.assertRaisesRegex(ValueError, "oracle restart runner requires"):
                core_isolation.main(oracle_restart_runner=lambda *_: None)
            with self.assertRaisesRegex(ValueError, "bounded printable"):
                core_isolation.main(contract_divergences=("invalid\nmetadata",))
            allocate.assert_not_called()

    def test_binary_binding_hashes_file_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic"
            path.write_bytes(b"not-an-executable")
            self.assertEqual(core_isolation.file_hash(path), hashlib.sha256(b"not-an-executable").hexdigest())

    def test_response_write_log_keeps_only_closed_numeric_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            accepted = (b"HBHTTP-RESPONSE-WRITE-FAILURE io_kind=timed_out "
                        b"accepted_plaintext_bytes=11 flush_attempted=false "
                        b"original_deadline_expired=true")
            path.write_bytes(
                b"sentinel-private-response\n"
                b"HBHTTP-RESPONSE-WRITE-FAILURE io_kind=SensitivePeerBytes "
                b"accepted_plaintext_bytes=11 flush_attempted=false original_deadline_expired=true\n"
                + accepted + b" extra-private-bytes\n" + accepted + b"\n"
            )
            result = core_isolation.bounded_response_write_observations(path)
            self.assertEqual(result["rows"], [{
                "io_kind": "timed_out", "accepted_plaintext_bytes": 11,
                "flush_attempted": False, "original_deadline_expired": True,
            }])
            self.assertNotIn("private", json.dumps(result))
            self.assertNotIn("SensitivePeerBytes", json.dumps(result))
            self.assertFalse(result["tail_only"])
            self.assertFalse(result["rows_truncated"])

    def test_response_write_log_tail_and_row_limits_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            row = (b"HBHTTP-RESPONSE-WRITE-FAILURE io_kind=broken_pipe "
                   b"accepted_plaintext_bytes=0 flush_attempted=false "
                   b"original_deadline_expired=false\n")
            path.write_bytes(b"x" * (128 * 1024) + b"\n" + row * 65)
            result = core_isolation.bounded_response_write_observations(path)
            self.assertTrue(result["tail_only"])
            self.assertTrue(result["rows_truncated"])
            self.assertEqual(result["examined_bytes"], 128 * 1024)
            self.assertEqual(len(result["rows"]), 64)


if __name__ == "__main__":
    unittest.main()
