"""Prevent provider failures or lost HTTP replies from masquerading as HA fencing."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from radius_renewal_ha import authority_denied


class RenewalFaultClassification(unittest.TestCase):
    def test_provider_failure_is_not_a_ha_pass_even_if_leader_died(self):
        for phase in ("leader_killed", "quorum_lost", "sealed"):
            for body in ({"errors": ["RADIUS provider unavailable or response unauthenticated"]},
                         {"errors": []}, {}, {"errors": "HA unavailable"}):
                self.assertFalse(authority_denied(503, body, phase))

    def test_transport_loss_only_qualifies_the_process_kill(self):
        self.assertTrue(authority_denied(None, {}, "leader_killed"))
        self.assertFalse(authority_denied(None, {}, "quorum_lost"))
        self.assertFalse(authority_denied(None, {}, "sealed"))

    def test_sealed_rejection_is_not_quorum_evidence(self):
        body = {"errors": ["online authentication authority changed"]}
        self.assertTrue(authority_denied(503, body, "sealed"))
        self.assertFalse(authority_denied(503, body, "quorum_lost"))
        self.assertTrue(authority_denied(503, {"errors": ["HA linearizable state is unavailable"]}, "quorum_lost"))


if __name__ == "__main__":
    unittest.main()
