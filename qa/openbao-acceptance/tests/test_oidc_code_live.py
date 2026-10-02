"""OIDC completion is evidence of required phases, not a numeric row budget."""
import unittest

from oidc_code_live import REQUIRED_CASES
from online_evidence import complete_checks


class OidcCodeCompletenessGuards(unittest.TestCase):
    def test_every_required_phase_must_be_present_even_when_other_checks_pass(self):
        rows = [{"case": case, "passed": True} for case in sorted(REQUIRED_CASES)]
        self.assertIn("complete", REQUIRED_CASES)
        self.assertTrue(complete_checks(rows, required_cases=REQUIRED_CASES))
        self.assertTrue(complete_checks(rows + [{"case": "additional_tls_check", "passed": True}],
                                        required_cases=REQUIRED_CASES))
        for omitted in REQUIRED_CASES:
            with self.subTest(omitted=omitted):
                self.assertFalse(complete_checks([row for row in rows if row["case"] != omitted],
                                                 required_cases=REQUIRED_CASES))
        self.assertFalse(complete_checks([], required_cases=REQUIRED_CASES))
        self.assertFalse(complete_checks([{"case": "complete", "passed": True}],
                                         required_cases=REQUIRED_CASES))

    def test_failed_or_duplicate_additional_observation_cannot_be_ignored(self):
        rows = [{"case": case, "passed": True} for case in sorted(REQUIRED_CASES)]
        for extra in ({"case": "additional_tls_check", "passed": False},
                      {"case": "additional_tls_check", "passed": 1}, rows[0]):
            self.assertFalse(complete_checks(rows + [extra], required_cases=REQUIRED_CASES))


if __name__ == "__main__":
    unittest.main()
