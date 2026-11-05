"""Prevent fake LDAP success or incomplete fault traces qualifying HA receipts."""
import io
import unittest

from ldap_native_renewal_ha import PHASES, MAX_FRAME, complete_checks, envelope, read_frame, successful_done
from radius_renewal_ha import authority_denied


def tlv(tag, body):
    size = bytes([len(body)]) if len(body) < 128 else b"\x82" + len(body).to_bytes(2, "big")
    return bytes([tag]) + size + body


def done(message=5, result=0, operation=0x65):
    return tlv(0x30, tlv(2, bytes([message])) + tlv(operation,
               tlv(0x0a, bytes([result])) + tlv(4, b"") + tlv(4, b"")))


class FragmentedStream:
    def __init__(self, data):
        self.source = io.BytesIO(data)

    def recv(self, count):
        return self.source.read(min(count, 1))


class GatedLdapTests(unittest.TestCase):
    def test_only_final_success_result_can_trigger_gate(self):
        self.assertTrue(successful_done(done()))
        for packet in (done(message=2), done(result=49), done(operation=0x61),
                       tlv(0x30, tlv(2, b"\x05") + tlv(0x64, tlv(4, b"dn")))):
            self.assertFalse(successful_done(packet))

    def test_exact_framing_does_not_consume_next_result(self):
        stream = FragmentedStream(done(message=2) + done())
        self.assertEqual(envelope(read_frame(stream))[:2], (2, 0x65))
        self.assertTrue(successful_done(read_frame(stream)))
        with self.assertRaises(EOFError):
            read_frame(stream)

    def test_rejects_partial_indefinite_oversized_and_trailing_data(self):
        for packet in (b"\x30\x80", b"\x30\x81\x01x", b"\x30\x03x",
                       b"\x30\x83" + (MAX_FRAME + 1).to_bytes(3, "big")):
            with self.assertRaises((EOFError, ValueError)):
                read_frame(FragmentedStream(packet))
        with self.assertRaises(ValueError):
            successful_done(done() + b"ignored")
        with self.assertRaises(ValueError):
            successful_done(tlv(0x30, tlv(2, b"\x05") + tlv(0x65, b"\x0a\x01\0")))

    def test_provider_failure_cannot_count_as_authority_fence(self):
        for phase in PHASES:
            self.assertFalse(authority_denied(400, {"errors": ["LDAP authentication failed"]}, phase))
            self.assertFalse(authority_denied(503, {"errors": ["provider timeout"]}, phase))
            self.assertFalse(authority_denied(200, {"auth": {}}, phase))
        self.assertTrue(authority_denied(None, {}, "leader_killed"))
        self.assertFalse(authority_denied(None, {}, "quorum_lost"))
        self.assertTrue(authority_denied(503, {"errors": ["HA quorum unavailable"]}, "quorum_lost"))

    def test_required_milestones_unique_and_terminal_without_fixed_count(self):
        names = ["healthy_forwarded_provider_once", "acknowledged_renewal_survives_leader_death",
                 "secrets_absent_from_storage_and_logs"]
        for phase in PHASES:
            names.extend(phase + suffix for suffix in ("_real_success_released", "_no_success_or_wrapper",
                "_expiry_not_extended", "_identity_not_partially_changed", "_fresh_provider_once",
                "_fresh_identity_refreshed"))
        rows = [{"case": name, "passed": True} for name in names + ["complete"]]
        self.assertTrue(complete_checks(rows))
        self.assertTrue(complete_checks(rows[:-1] + [{"case": "new_real_observation", "passed": True}] + rows[-1:]))
        self.assertFalse(complete_checks(rows[:-1]))
        self.assertFalse(complete_checks(rows + rows[-1:]))
        self.assertFalse(complete_checks(rows[:4] + rows[5:]))
        failed = [dict(row) for row in rows]
        failed[0]["passed"] = False
        self.assertFalse(complete_checks(failed))


if __name__ == "__main__":
    unittest.main()
