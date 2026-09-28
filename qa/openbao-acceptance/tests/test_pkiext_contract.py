"""Bounded PKI extension configuration remains versioned and scoped."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
CASES = {
    "pkiext_live.pkiext.mount",
    "pkiext_live.pkiext.unauthorized_denied",
    "pkiext_live.pkiext.cluster_config",
    "pkiext_live.pkiext.acme_config",
    "pkiext_live.pkiext.acme_config_read",
    "pkiext_live.pkiext.invalid_cluster_rejected",
    "pkiext_live.pkiext.unknown_field_ignored_with_warning",
    "pkiext_live.pkiext.known_field_persists_after_unknown",
    "pkiext_live.pkiext.cluster_persists_after_restart",
    "pkiext_live.pkiext.acme_persists_after_restart",
}


class PkiExtensionContractTests(unittest.TestCase):
    def test_registry_corpus_and_surface_mapping_share_exact_cases(self):
        registry = json.loads((ROOT / "qa/openbao-acceptance/external_fixture_case_registry_v1.json").read_text())
        registered = {"pkiext_live." + case for case in registry["cases"]["pkiext_live"]["case_ids"]}
        self.assertEqual(registered, CASES)
        corpus = json.loads((ROOT / "qa/openbao-acceptance/complete_surface_corpus_v1.json").read_text())
        row = next(value for value in corpus["surfaces"] if value["surface_id"] == "HB-SURFACE-SECRET-PKI")
        self.assertTrue(CASES <= set(row["fixture_case_ids"]))
        self.assertEqual(row["minimum_observations"], len(row["fixture_case_ids"]))
        work = json.loads((ROOT / "planning/HEPTABAO_SURFACE_WORK_V1.json").read_text())
        mapped = {value["surface_id"] for value in work["surfaces"]
                  if "pkiext" in value["available_scoped_profiles"]}
        self.assertEqual(mapped, {"HB-SURFACE-SECRET-PKI"})
        self.assertFalse(next(value for value in work["surfaces"]
                              if value["surface_id"] == "HB-SURFACE-SECRET-PKI")["whole_surface_admitted"])

    def test_schema59_is_independent_and_default_shape_is_omitted(self):
        service = (ROOT / "crates/heptabao-server/src/service.rs").read_text()
        self.assertRegex(service, r"CURRENT_STATE_SCHEMA:\s*u32\s*=\s*59;")
        identity = (ROOT / "crates/heptabao-server/src/service_identity.rs").read_text()
        self.assertIn("self.schema < 59 && self.engines.has_pki_extension_state()", identity)
        self.assertIn("PKI cluster or ACME configuration requires schema 59", identity)
        pki = (ROOT / "crates/heptabao-server/src/engines/pki.rs").read_text()
        for marker in (
            'skip_serializing_if = "String::is_empty"',
            'skip_serializing_if = "AcmeConfig::is_default"',
            "pub(super) fn has_extension_state",
        ):
            self.assertIn(marker, pki)
        tests = (ROOT / "crates/heptabao-server/src/pki_service_tests.rs").read_text()
        self.assertIn("pki_default_shape_remains_readable_as_schema57_without_new_fields", tests)
        self.assertIn("pki_extension_state_requires_schema59_independently", tests)

    def test_profile_is_mandatory_but_does_not_claim_acme_protocol(self):
        profile = (ROOT / "qa/openbao-acceptance/pkiext_live.py").read_text()
        self.assertIn("account, order, challenge, certificate and revocation protocol routes remain", profile)
        self.assertIn('profile="pkiext-live"', profile)
        workflow = (ROOT / ".github/workflows/codex-openbao-replacement-ci.yml").read_text()
        self.assertIn("pki_live pkiext_live ssh_otp_live", workflow)
        surface = json.loads((ROOT / "planning/HEPTABAO_SURFACE_WORK_V1.json").read_text())
        profile_row = surface["profile_definitions"]["pkiext"]
        self.assertEqual(profile_row["scope"], "repository_controlled_bounded_profile_not_whole_surface")
        self.assertIn("ACME account/order/challenge protocol", next(value for value in surface["surfaces"]
                      if value["surface_id"] == "HB-SURFACE-SECRET-PKI")["technical_contract"]["remaining_semantics_and_effect_checks"])


if __name__ == "__main__":
    unittest.main()
