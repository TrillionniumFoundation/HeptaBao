import copy
from types import SimpleNamespace
import unittest
from kubernetes_api_tls_upgrade import LEGACY_SOURCE, LEGACY_SHA256, admit_legacy_receipt, complete, legacy_configuration


class KubernetesApiTlsUpgradeGuards(unittest.TestCase):
    def receipt(self):
        return {"status": "passed", "source_and_binary_unchanged": True, "runner_unchanged": True,
                "build_source_commit": LEGACY_SOURCE, "candidate_binary_sha256": LEGACY_SHA256, "cases_match": True,
                "source_identity": {"source_commit": LEGACY_SOURCE, "source_dirty": False, "binary_sha256": LEGACY_SHA256}}

    def test_historical_shape_does_not_borrow_new_configuration_defaults(self):
        config = legacy_configuration(SimpleNamespace(origin="https://localhost:8443", reviewer="synthetic-reviewer"))
        self.assertEqual(set(config), {"kubernetes_host", "token_reviewer_jwt", "disable_local_ca_jwt"})
        self.assertIs(config["disable_local_ca_jwt"], True)

    def test_receipt_requires_observed_clean_source_and_exact_binary(self):
        receipt = self.receipt()
        admit_legacy_receipt(LEGACY_SHA256, receipt)
        for name, value in [("status", "failed"), ("source_and_binary_unchanged", False),
                            ("runner_unchanged", False), ("build_source_commit", "0" * 40),
                            ("candidate_binary_sha256", "0" * 64), ("cases_match", False)]:
            with self.assertRaises(ValueError):
                admit_legacy_receipt(LEGACY_SHA256, dict(receipt, **{name: value}))
        for name, value in [("source_commit", "0" * 40), ("source_dirty", True), ("binary_sha256", "0" * 64)]:
            wrong = copy.deepcopy(receipt)
            wrong["source_identity"][name] = value
            with self.assertRaises(ValueError):
                admit_legacy_receipt(LEGACY_SHA256, wrong)
        with self.assertRaises(ValueError):
            admit_legacy_receipt("0" * 64, receipt)

    def test_preparation_cannot_be_reported_as_upgrade(self):
        row = {"case": "api_tls.upgrade.legacy.complete", "passed": True}
        self.assertTrue(complete([row], True))
        self.assertFalse(complete([row], False))
        self.assertFalse(complete([], True))
        self.assertFalse(complete([row, row], True))
        self.assertFalse(complete([dict(row, passed=1)], True))
        self.assertFalse(complete([dict(row, credential="sentinel")], True))


if __name__ == "__main__":
    unittest.main()
