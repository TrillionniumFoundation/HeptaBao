import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import kv_metadata_cas_live as subject


class ReadinessClient:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.timeout = 15
        self.calls = []

    def request(self, method, path):
        self.calls.append((method, path, self.timeout))
        value = next(self.responses)
        if isinstance(value, Exception):
            raise value
        return value


class ReadinessContract(unittest.TestCase):
    def test_only_exact_official_upgrade_error_allows_another_probe(self):
        client = ReadinessClient([
            SimpleNamespace(status=400, body={"errors": [subject._KV_UPGRADE_PENDING]}),
            SimpleNamespace(status=200, body={"data": {}})])
        with patch.object(subject.time, "sleep"):
            subject.wait_for_empty_backend(client)
        self.assertEqual(len(client.calls), 2)
        self.assertTrue(all(method == "GET" and path == "/v1/metadata-cas/config"
                            and 0 < timeout <= 2 for method, path, timeout in client.calls))
        self.assertEqual(client.timeout, 15)

    def test_other_denials_and_extra_body_fields_are_not_readiness(self):
        for status, body in [
            (403, {"errors": ["permission denied"]}),
            (400, {"errors": ["different error"]}),
            (400, {"errors": [subject._KV_UPGRADE_PENDING], "data": {}}),
            (503, {"errors": [subject._KV_UPGRADE_PENDING]})]:
            client = ReadinessClient([SimpleNamespace(status=status, body=body)])
            with self.assertRaises(subject.ScenarioFailure):
                subject.wait_for_empty_backend(client)
            self.assertEqual(len(client.calls), 1)
            self.assertEqual(client.timeout, 15)

    def test_transport_failure_is_not_retried(self):
        client = ReadinessClient([OSError("synthetic transport failure")])
        with self.assertRaises(OSError):
            subject.wait_for_empty_backend(client)
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.timeout, 15)

    def test_readiness_timeout_restores_business_timeout(self):
        client = ReadinessClient([])
        with patch.object(subject.time, "monotonic", side_effect=[100.0, 102.0]):
            with self.assertRaises(subject.ScenarioFailure):
                subject.wait_for_empty_backend(client)
        self.assertEqual(client.calls, [])
        self.assertEqual(client.timeout, 15)


if __name__ == "__main__":
    unittest.main()
