import base64
import json
import unittest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from core_isolation import ScenarioFailure
import transit_derived_live as derived


class DerivedFixtureTests(unittest.TestCase):
    def test_trace_failure_does_not_copy_service_body_into_rows(self):
        class Client:
            def request(self, *args):
                class Response:
                    status = 500
                    body = {"synthetic_credential": "fixture-secret-marker", "ciphertext": "fixture-cipher-marker"}
                return Response()
        rows = []
        with self.assertRaises(ScenarioFailure):
            derived.Trace(Client(), rows).call("failure", "POST", "fixture", 200, {})
        report = json.dumps(rows)
        self.assertTrue("fixture-secret-marker" not in report)
        self.assertTrue("fixture-cipher-marker" not in report)
        self.assertEqual(set(rows[0]), {"case", "status", "passed"})

    def test_independent_decrypt_rejects_wrong_context_and_aad(self):
        master, context, message, aad = bytes(range(32)), b"synthetic context", b"synthetic message", b"synthetic AAD"
        key = derived.material("aes256-gcm96", master, context, True, False)
        nonce = bytes(12)
        wire = "vault:v1:" + base64.b64encode(nonce + AESGCM(key).encrypt(nonce, message, aad)).decode()
        self.assertTrue(derived.independent_decrypt("aes256-gcm96", master, context, True, False, wire, aad) == message)
        with self.assertRaises(InvalidTag):
            derived.independent_decrypt("aes256-gcm96", master, b"wrong context", True, False, wire, aad)
        with self.assertRaises(InvalidTag):
            derived.independent_decrypt("aes256-gcm96", master, context, True, False, wire, b"wrong AAD")


if __name__ == "__main__":
    unittest.main()
