"""Actual TLS attribution: a later protocol failure is not a SAN rejection."""
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ldap_transport_tls_probe import wrong_san_probe, san_rejection_observed, WRONG_DNS_NAME
from official_openbao_launcher import certificates


class LdapTlsProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="ldap-san-guard-", dir=os.environ.get("TMPDIR"))
        cls.root = Path(cls.temporary.name)
        cls.root.chmod(0o700)
        cls.authority = cls.root / "authority"
        cls.authority.mkdir(mode=0o700)
        certificates(cls.authority)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def probe(self, name):
        return wrong_san_probe(self.root / name, self.authority / "ca.crt", self.authority / "ca.key")

    def context(self):
        context = ssl.create_default_context(cafile=str(self.authority / "ca.crt"))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def connect(self, probe, name):
        port = int(probe.origin.rsplit(":", 1)[1])
        raw = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            return self.context().wrap_socket(raw, server_hostname=name)
        except Exception:
            raw.close()
            raise

    def test_wrong_ip_san_is_rejected_with_correct_ca(self):
        with self.probe("rejected") as probe:
            with self.assertRaises(ssl.SSLCertVerificationError) as raised:
                self.connect(probe, "127.0.0.1")
            self.assertIn(raised.exception.verify_code, (62, 64))
            evidence = probe.wait()
            self.assertTrue(san_rejection_observed(evidence))
            self.assertTrue(all(type(value) is bool for value in evidence.values()))
        self.assertFalse(probe._thread.is_alive())

    def test_matching_san_proves_valid_chain_and_detects_application_bytes(self):
        with self.probe("valid-chain") as probe:
            with self.connect(probe, WRONG_DNS_NAME) as connection:
                connection.sendall(b"synthetic-private-ldap-payload")
                evidence = probe.wait()
            self.assertTrue(evidence["handshake_attempted"])
            self.assertTrue(evidence["handshake_completed"])
            self.assertTrue(evidence["application_bytes_seen"])
            self.assertFalse(san_rejection_observed(evidence))
            self.assertNotIn("private", json.dumps(evidence))
        self.assertFalse(probe._thread.is_alive())

    def test_successful_tls_then_eof_cannot_masquerade_as_san_rejection(self):
        with self.probe("eof") as probe:
            connection = self.connect(probe, WRONG_DNS_NAME)
            connection.close()
            evidence = probe.wait()
            self.assertTrue(evidence["handshake_completed"])
            self.assertFalse(evidence["application_bytes_seen"])
            self.assertFalse(san_rejection_observed(evidence))

    def test_cleanup_without_any_client_joins_listener(self):
        with self.probe("unused") as probe:
            pass
        self.assertFalse(probe._thread.is_alive())

    def test_boolean_and_complete_evidence_is_required(self):
        good = {"handshake_attempted": True, "handshake_completed": False, "application_bytes_seen": False}
        self.assertTrue(san_rejection_observed(good))
        for key in good:
            missing = dict(good)
            del missing[key]
            self.assertFalse(san_rejection_observed(missing))
            numeric = dict(good, **{key: int(good[key])})
            self.assertFalse(san_rejection_observed(numeric))
        self.assertFalse(san_rejection_observed(dict(good, raw_response="private")))


if __name__ == "__main__":
    unittest.main()
