import json
import unittest

from batch_provider_lease_live import REQUIRED, Trace, FixtureError, no_secret_failure
from batch_provider_ldap_gate import fields, is_issue_readback
from online_evidence import complete_checks


def tlv(tag, data):
    if len(data) >= 128:
        raise ValueError("unit frame too large")
    return bytes((tag, len(data))) + data


RESULT = tlv(0x0a, b"\0") + tlv(4, b"") + tlv(4, b"")


class ProviderLeaseGuards(unittest.TestCase):
    def test_incomplete_lifecycle_and_missing_cleanup_cannot_pass(self):
        rows = [{"case": name, "passed": True} for name in sorted(REQUIRED)]
        self.assertTrue(complete_checks(rows, required_cases=REQUIRED))
        for critical in ("parent_revocation_provider_cleanup", "completion_cleanup_after_restart", "complete"):
            self.assertFalse(complete_checks([r for r in rows if r["case"] != critical], required_cases=REQUIRED))
        self.assertFalse(complete_checks(rows + [rows[0]], required_cases=REQUIRED))
        self.assertFalse(complete_checks([{**r, "passed": 1} for r in rows], required_cases=REQUIRED))

    def test_trace_failure_and_exception_never_add_completion(self):
        trace = Trace()
        trace.secret("synthetic-password-sentinel")
        trace.check("provider_entered", True)
        with self.assertRaises(FixtureError):
            trace.check("provider_cleanup", False)
        self.assertNotIn("synthetic-password-sentinel", json.dumps(trace.checks))
        self.assertFalse(complete_checks(trace.checks, required_cases=REQUIRED))
        with self.assertRaises(FixtureError):
            trace.check("provider_entered", True)
        with self.assertRaises(FixtureError):
            trace.check("wrong_bool", 1)

    def test_late_completion_must_be_explicit_reconciliation_without_secret_or_wrapper(self):
        body = {"lease_id": "ldap/creds/reader/synthetic", "retry_allowed": False, "reconcile_required": True}
        self.assertTrue(no_secret_failure(503, body))
        for altered in ({**body, "data": {"password": "synthetic"}},
                        {**body, "auth": {"client_token": "synthetic"}},
                        {**body, "wrap_info": {"token": "synthetic"}},
                        {**body, "retry_allowed": True}, {**body, "reconcile_required": False},
                        {**body, "lease_id": ""}):
            self.assertFalse(no_secret_failure(503, altered))
        self.assertFalse(no_secret_failure(200, body))

    def test_gate_requires_real_add_and_unique_final_search_result(self):
        self.assertTrue(is_issue_readback(4, 0x65, RESULT, added=True, entries=1))
        for changes in ((3, 0x65, True, 1), (4, 0x69, True, 1),
                        (4, 0x65, False, 1), (4, 0x65, True, 0), (4, 0x65, True, 2)):
            message, op, added, entries = changes
            self.assertFalse(is_issue_readback(message, op, RESULT, added=added, entries=entries))
        denied = tlv(0x0a, b"\x31") + tlv(4, b"") + tlv(4, b"")
        self.assertFalse(is_issue_readback(4, 0x65, denied, added=True, entries=1))

    def test_relay_preserves_request_controls_but_rejects_invalid_envelope(self):
        payload = tlv(2, b"\x05") + tlv(0x66, b"") + tlv(0xa0, b"")
        self.assertEqual(fields(tlv(0x30, payload)), (5, 0x66, b""))
        with self.assertRaises(ValueError):
            fields(tlv(0x30, tlv(2, b"\x80") + tlv(0x66, b"")))
        with self.assertRaises(ValueError):
            fields(tlv(0x30, payload) + b"trailing")


if __name__ == "__main__":
    unittest.main()
