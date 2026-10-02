import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import transit_byok_live as subject


class ProfileContracts(unittest.TestCase):
    def response(self, status, data=None, body=None):
        return SimpleNamespace(status=status, body=body if body is not None else {"data": data})

    def descriptor(self):
        return {"allow_plaintext_backup": False, "auto_rotate_period": 0,
                "deletion_allowed": False, "derived": False, "exportable": False,
                "imported_key": True, "keys": {"1": 100}, "latest_version": 1,
                "min_available_version": 0, "min_decryption_version": 1,
                "min_encryption_version": 0, "name": "PUBLIC_FIXTURE",
                "soft_deleted": False, "supports_decryption": True,
                "supports_derivation": True, "supports_encryption": True,
                "supports_signing": False, "type": "aes256-gcm96"}

    def test_fixed_eighty_seven_ids_match_preserved_observations(self):
        self.assertEqual(len(subject.fixed_ids()), 87)
        self.assertEqual(tuple(row["case"] for row in subject._EXPECTED), subject.fixed_ids())
        self.assertEqual(subject.fixed_ids()[-3:],
                         ("restart.wrapping", "restart.aes128.decrypt", "restart.aes256.decrypt"))

    def test_recursive_bool_is_not_integer(self):
        self.assertFalse(subject.typed_equal({"valid": True}, {"valid": 1}))
        self.assertFalse(subject.typed_equal([0], [False]))
        self.assertFalse(subject.typed_equal({"latest": 1}, {"latest": True}))
        self.assertTrue(subject.typed_equal({"valid": True}, {"valid": True}))

    def test_recursive_unknown_or_missing_fields_rejected(self):
        self.assertFalse(subject.typed_equal({"status": 200, "other": True}, {"status": 200}))
        self.assertFalse(subject.typed_equal({}, {"status": 200}))
        self.assertFalse(subject.typed_equal([200, 204], [200]))

    def test_wrapping_has_only_public_key(self):
        self.assertTrue(subject.response_data_shape("wrapping.first", self.response(200, {"public_key": "PUBLIC"})))
        self.assertFalse(subject.response_data_shape("wrapping.first", self.response(200, {"public_key": "PUBLIC", "private_key": "PUBLIC_DUMMY"})))
        self.assertFalse(subject.response_data_shape("wrapping.repeat", self.response(200, {"public_key": 1})))
        self.assertFalse(subject.response_data_shape("restart.wrapping", self.response(400, {"public_key": "PUBLIC"})))

    def test_unknown_top_level_fields_rejected(self):
        self.assertFalse(subject.response_data_shape("wrapping.first", self.response(200, body={"data": {"public_key": "PUBLIC"}, "private_key": "PUBLIC_DUMMY"})))
        self.assertFalse(subject.response_data_shape("negative.invalid_base64", self.response(500, body={"errors": ["FIXED"], "private_key": "PUBLIC_DUMMY"})))

    def test_import_empty_response_does_not_allow_extra_private_fields(self):
        self.assertTrue(subject.response_data_shape("aes256-gcm96.SHA256.import", self.response(204, body={})))
        self.assertFalse(subject.response_data_shape("aes256-gcm96.SHA256.import", self.response(204, {"material": "PUBLIC_DUMMY"})))

    def test_descriptor_is_closed_and_typed(self):
        self.assertTrue(subject.response_data_shape("aes256-gcm96.SHA256.read", self.response(200, self.descriptor())))
        for key, value in (("private_key", "PUBLIC_DUMMY"), ("supports_derivation", 1), ("supports_signing", True)):
            changed = self.descriptor()
            changed[key] = value
            self.assertFalse(subject.response_data_shape("aes256-gcm96.SHA256.read", self.response(200, changed)))
        changed = self.descriptor()
        changed["keys"]["1"] = True
        self.assertFalse(subject.response_data_shape("aes256-gcm96.SHA256.read", self.response(200, changed)))

    def test_successful_rotate_has_same_closed_descriptor(self):
        changed = self.descriptor()
        changed["material"] = "PUBLIC_DUMMY"
        self.assertTrue(subject.response_data_shape("aes256-gcm96.allowed.rotate", self.response(200, self.descriptor())))
        self.assertFalse(subject.response_data_shape("aes256-gcm96.allowed.rotate", self.response(200, changed)))

    def test_encrypt_and_decrypt_closed_fields(self):
        self.assertTrue(subject.response_data_shape("aes256-gcm96.SHA256.encrypt", self.response(200, {"ciphertext": "PUBLIC_DUMMY", "key_version": 1})))
        self.assertFalse(subject.response_data_shape("aes256-gcm96.SHA256.encrypt", self.response(200, {"ciphertext": "PUBLIC_DUMMY", "key_version": True})))
        self.assertTrue(subject.response_data_shape("restart.aes256.decrypt", self.response(200, {"plaintext": "PUBLIC_DUMMY"})))
        self.assertFalse(subject.response_data_shape("restart.aes256.decrypt", self.response(200, {"plaintext": "PUBLIC_DUMMY", "key": "PUBLIC_DUMMY"})))

    def test_error_must_not_publish_data(self):
        self.assertTrue(subject.response_data_shape("negative.wrong_oaep_hash", self.response(500, body={"errors": ["FIXED"]})))
        self.assertFalse(subject.response_data_shape("negative.wrong_oaep_hash", self.response(500, body={"errors": ["FIXED"], "data": {}})))
        self.assertFalse(subject.response_data_shape("negative.wrong_oaep_hash", self.response(500, body={"errors": []})))

    def test_decrypt_requires_status_and_plaintext(self):
        self.assertTrue(subject.successful_plaintext(self.response(200, {"plaintext": "PUBLIC_DUMMY"}), "PUBLIC_DUMMY"))
        self.assertFalse(subject.successful_plaintext(self.response(400, {"plaintext": "PUBLIC_DUMMY"}), "PUBLIC_DUMMY"))
        self.assertFalse(subject.successful_plaintext(self.response(200, {"plaintext": "CHANGED"}), "PUBLIC_DUMMY"))

    def test_false_crypto_predicate_is_not_equal_to_observation(self):
        expected = next(row for row in subject._EXPECTED if "independent_aes_valid" in row)
        changed = copy.deepcopy(expected)
        changed["independent_aes_valid"] = False
        self.assertFalse(subject.typed_equal(changed, expected))
        changed["independent_aes_valid"] = 1
        self.assertFalse(subject.typed_equal(changed, expected))

    def test_record_order_and_metadata_type_do_not_silently_pass(self):
        recorder = subject.Recorder()
        with self.assertRaises(subject.ProbeFailure):
            recorder.record("wrapping.first", self.response(200, {}), 0)
        recorder.record("setup.mount", self.response(204, body={}), 0)
        with self.assertRaises(subject.ProbeFailure):
            recorder.record("wrapping.first", self.response(200, {"latest_version": True}), 0)


if __name__ == "__main__":
    unittest.main()
