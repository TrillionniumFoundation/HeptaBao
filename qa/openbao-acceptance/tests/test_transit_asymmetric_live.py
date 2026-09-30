import base64
import importlib.util
from pathlib import Path
import unittest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

SPEC = importlib.util.spec_from_file_location("transit_asymmetric_live", Path(__file__).resolve().parents[1] / "transit_asymmetric_live.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def wrapped(signature, url=False):
    payload = base64.urlsafe_b64encode(signature).decode().rstrip("=") if url else base64.b64encode(signature).decode()
    return "vault:v1:" + payload


class IndependentSignatureTests(unittest.TestCase):
    def test_ecdsa_p521_real_jws_accepts_message_and_rejects_tamper(self):
        from cryptography.hazmat.primitives.asymmetric import utils
        private = ec.generate_private_key(ec.SECP521R1())
        message = b"synthetic independent P521"
        signature = private.sign(message, ec.ECDSA(hashes.SHA512()))
        r, s = utils.decode_dss_signature(signature)
        raw = r.to_bytes(66, "big") + s.to_bytes(66, "big")
        self.assertTrue(MODULE.independent_verify(private.public_key(), "ecdsa-p521", wrapped(raw, True), message, "sha2-512", False, "jws", "ignored"))
        self.assertFalse(MODULE.independent_verify(private.public_key(), "ecdsa-p521", wrapped(raw, True), b"changed", "sha2-512", False, "jws", "ignored"))
        self.assertFalse(MODULE.independent_verify(private.public_key(), "ecdsa-p521", wrapped(raw[:-1], True), message, "sha2-512", False, "jws", "ignored"))

    def test_rsa_real_pss_uses_explicit_custom_salt(self):
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        message = b"synthetic independent RSA salt"
        signature = private.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=17), hashes.SHA256())
        self.assertTrue(MODULE.independent_verify(private.public_key(), "rsa-2048", wrapped(signature), message, "sha2-256", False, "asn1", "pss", 17))
        self.assertFalse(MODULE.independent_verify(private.public_key(), "rsa-2048", wrapped(signature), message, "sha2-256", False, "asn1", "pss", "hash"))
        self.assertFalse(MODULE.independent_verify(private.public_key(), "rsa-2048", wrapped(signature), b"changed", "sha2-256", False, "asn1", "pss", 17))

    def test_true_prehash_has_the_exact_digest_and_rejects_rehash(self):
        from cryptography.hazmat.primitives.asymmetric import utils
        private = ec.generate_private_key(ec.SECP256R1())
        message = b"synthetic independent prehash"
        digest = MODULE.actual_input(message, "sha3-256", True)
        signature = private.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA3_256())))
        self.assertTrue(MODULE.independent_verify(private.public_key(), "ecdsa-p256", wrapped(signature), digest, "sha3-256", True, "asn1", "ignored"))
        self.assertFalse(MODULE.independent_verify(private.public_key(), "ecdsa-p256", wrapped(signature), digest, "sha3-256", False, "asn1", "ignored"))


if __name__ == "__main__":
    unittest.main()
