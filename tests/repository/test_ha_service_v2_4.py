from pathlib import Path
import unittest


class HaServiceV24Tests(unittest.TestCase):
    def test_service_ha_fail_closed_markers_exist(self):
        source=Path("crates/heptabao-ha-service/src/lib.rs").read_text(encoding="utf-8")
        for marker in ("QuorumUnavailable", "OperationIdConflict", "StaleLeaderResponse", "accept_incoming", "HMAC_SHA256", "SnapshotManifest", "MembershipTransition"):
            self.assertIn(marker,source)

    def test_production_boundaries_are_explicit(self):
        guide=Path("docs/modules/heptabao-ha-service.md").read_text(encoding="utf-8")
        self.assertIn("concrete `heptabao-raft-runtime` adapter",guide)
        self.assertIn("destructive multi-node qualification remain required",guide)


if __name__ == "__main__":
    unittest.main()
