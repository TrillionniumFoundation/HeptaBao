import base64
import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "qa/openbao-acceptance/external_transit_consumer_live.py"
sys.path.insert(0, str(RUNNER.parent))
SPEC = importlib.util.spec_from_file_location("external_transit_consumer_contract", RUNNER)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ExternalConsumerContractTests(unittest.TestCase):
    def test_exact_denominator_rejects_empty_missing_reordered_duplicate_and_failed_traces(self):
        self.assertEqual(1982, len(MODULE.EXPECTED_CASES))
        rows = [{"case": case, "passed": True} for case in MODULE.EXPECTED_CASES]
        self.assertEqual(len(MODULE.EXPECTED_CASES), len(set(MODULE.EXPECTED_CASES)))
        self.assertTrue(MODULE.trace_complete(rows))
        failed = copy.deepcopy(rows)
        failed[-1]["passed"] = False
        for invalid in ([], rows[:-1], list(reversed(rows)), rows + [rows[-1]], failed):
            self.assertFalse(MODULE.trace_complete(invalid))

    def test_ca_successor_retains_every_other_original_case_and_order(self):
        cases = MODULE.EXPECTED_CASES
        accepted = cases.index("candidate.api_ca_assertion_accepted")
        self.assertEqual("candidate.api_ca_assertion_remote_readback", cases[accepted + 1])
        self.assertEqual("candidate.restore_enrolled_config", cases[accepted + 2])
        self.assertNotIn("candidate.api_ca_override_refused", cases)
        original = tuple("candidate.api_ca_override_refused" if name == "candidate.api_ca_assertion_accepted" else name
            for name in cases if name != "candidate.api_ca_assertion_remote_readback")
        self.assertEqual("e75fb2460140262b6e3ab67cb9f15f9ebaf62eb703d60796c0d5d5dc1c391c48", hashlib.sha256(json.dumps(original, separators=(",", ":")).encode()).hexdigest())
        rows = [{"case": name, "passed": True} for name in cases]
        self.assertFalse(MODULE.trace_complete([row for row in rows if row["case"] != "candidate.api_ca_assertion_remote_readback"]))

    def test_ca_assertion_requires_framed_crypto_output_and_real_exact_readback(self):
        payload = base64.b64encode(bytes(range(28))).decode()
        good = {"data": {"ciphertext": "vault:v2:" + payload, "key_version": 2}}
        self.assertTrue(MODULE.api_ca_assertion_ciphertext(good) == good["data"]["ciphertext"])
        self.assertTrue(MODULE.api_ca_assertion_readback_matches({"data": {"plaintext": MODULE.PLAIN}}))
        for invalid in ({}, {"data": {"verified": True}}, {"data": {"ciphertext": good["data"]["ciphertext"], "key_version": True}},
                {"data": {"ciphertext": "vault:v1:" + payload, "key_version": 2}},
                {"data": {"ciphertext": "vault:v2:%%%%", "key_version": 2}},
                {"data": {"ciphertext": "vault:v2:AB==", "key_version": 2}},
                {"data": {"ciphertext": "vault:v2:" + base64.b64encode(bytes(29)).decode()[:-2] + "B=", "key_version": 2}},
                {"data": {**good["data"], "private_key": None}}):
            self.assertIsNone(MODULE.api_ca_assertion_ciphertext(invalid))
        for invalid in ({}, {"data": {"verified": True}}, {"data": {"plaintext": False}},
                {"data": {"plaintext": "wrong"}}, {"data": {"plaintext": MODULE.PLAIN, "private_key": None}},
                {"errors": ["failure"]}):
            self.assertFalse(MODULE.api_ca_assertion_readback_matches(invalid))

    def test_raw_remote_payload_retains_exact_bytes_and_selected_local_version(self):
        payload = base64.b64encode(bytes(range(28))).decode()
        self.assertEqual(payload, MODULE.remote_payload("vault:v2:" + payload, 2))
        with self.assertRaises(MODULE.Failure):
            MODULE.remote_payload("vault:v2:" + payload, 1)

    def test_ciphertext_bounds_and_base64_fail_closed(self):
        for invalid in ("", "vault:v1:%%", "vault:v0:AA==", "vault:v1:" + base64.b64encode(b"short").decode(),
                "vault:v1:" + base64.b64encode(bytes(64 * 1024 + 65)).decode()):
            with self.assertRaises(MODULE.Failure):
                MODULE.remote_payload(invalid, 1)

    def test_descriptor_contract_has_only_official_reference_and_algorithm_fields(self):
        self.assertEqual(MODULE.DESCRIPTOR_FIELDS, frozenset(MODULE.INITIAL_DESCRIPTOR))
        self.assertEqual({"1": "provider:fixed1"}, MODULE.INITIAL_DESCRIPTOR["keys"])
        self.assertNotIn("external_key_ref", MODULE.INITIAL_DESCRIPTOR)
        self.assertTrue(MODULE.INITIAL_DESCRIPTOR["supports_signing"])
        self.assertTrue(MODULE.descriptor_matches(MODULE.INITIAL_DESCRIPTOR))
        official = {**MODULE.INITIAL_DESCRIPTOR, "supports_signing": True}
        self.assertTrue(MODULE.descriptor_matches(official, "official"))
        self.assertTrue(MODULE.descriptor_matches(official, "candidate"))
        self.assertTrue(MODULE.descriptor_matches(MODULE.INITIAL_DESCRIPTOR, "official"))
        unsigned = {**MODULE.INITIAL_DESCRIPTOR,"supports_signing":False}
        self.assertFalse(MODULE.descriptor_matches(unsigned,"candidate"))
        self.assertFalse(MODULE.descriptor_matches(unsigned,"official"))
        self.assertFalse(MODULE.descriptor_matches(MODULE.INITIAL_DESCRIPTOR, "unknown"))
        for key, wrong in (("min_available_version", False), ("latest_version", True),
                ("supports_encryption", 1), ("keys", {"1": {"external_key_ref": "provider:fixed1"}})):
            changed = copy.deepcopy(MODULE.INITIAL_DESCRIPTOR)
            changed[key] = wrong
            self.assertFalse(MODULE.descriptor_matches(changed))

    def test_crypto_valid_boolean_and_signature_encoding_are_exact(self):
        self.assertTrue(MODULE.crypto_boolean({"valid":True},True))
        self.assertTrue(MODULE.crypto_boolean({"valid":False},False))
        for invalid in ({"valid":1},{"valid":0},{"valid":"true"},{"valid":True,"extra":0},{},None):
            self.assertFalse(MODULE.crypto_boolean(invalid,True))
        raw = bytes(range(64))
        standard=base64.b64encode(raw).decode()
        jws=base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.assertEqual(standard,MODULE.signature_payload("vault:v1:"+standard,1))
        self.assertEqual(jws,MODULE.signature_payload("vault:v1:"+jws,1,True))
        for payload in ("",jws+"=",standard):
            with self.assertRaises(MODULE.Failure):
                MODULE.signature_payload("vault:v1:"+payload,1,True)

    def test_negative_status_is_not_a_union_or_any_failure(self):
        rows = []
        trace = MODULE.Trace(rows)
        class Response:
            status = 503
            body = {"errors": ["synthetic"]}
        class Client:
            def request(self, *args, **kwargs):
                return Response()
        with self.assertRaises(MODULE.Failure):
            trace.call("candidate.grant_removed_encrypt", Client(), "POST", "consumer/encrypt/local", 400, {})
        self.assertEqual([{"case": "candidate.grant_removed_encrypt", "status": 503, "passed": False}], rows)


if __name__ == "__main__":
    unittest.main()
