"""The bounded LDAPS fixture must inspect the actual native response contract."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "ldap_bounded.py"
SPEC = importlib.util.spec_from_file_location("ldap_bounded_contract", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LdapBoundedContractTests(unittest.TestCase):
    def test_native_envelope_is_required(self):
        url = "ldaps://localhost:1636"
        self.assertTrue(MODULE.configuration_matches(200, {"data": {"url": url}}, url))
        for body in ({"url": url}, {"data": None}, {"data": []}, None, [],
                     {"url": url, "data": {"url": "ldaps://wrong.invalid"}}):
            with self.subTest(body=body):
                self.assertFalse(MODULE.configuration_matches(200, body, url))

    def test_failure_status_cannot_supply_positive_evidence(self):
        url = "ldaps://localhost:1636"
        for status in (400, 403, 503, 204, True, "200", 200.0):
            with self.subTest(status=status):
                self.assertFalse(MODULE.configuration_matches(status, {"data": {"url": url}}, url))


if __name__ == "__main__":
    unittest.main()
