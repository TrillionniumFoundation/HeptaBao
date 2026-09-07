from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE_MAIN = ROOT / "probes/h02/openraft-tokio/src/main.rs"
FAULT_CLUSTER = (
    ROOT
    / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/cluster.rs"
)
FAULT_DURABLE = (
    ROOT
    / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/durable.rs"
)


class OpenRaftStrictLintSourceTests(unittest.TestCase):
    def test_probe_emitters_use_captured_format_arguments(self):
        source = PROBE_MAIN.read_text(encoding="utf-8")
        self.assertIn('\\"candidate_id\\":\\"{CANDIDATE_ID}\\"', source)
        self.assertIn('\\"case_id\\":\\"{case_id}\\"', source)
        self.assertNotIn("CANDIDATE_ID, VERSION, PROFILE_ID, seed", source)
        self.assertNotIn("case_id, status, assertions, detail", source)

    def test_obsolete_hostile_snapshot_implementation_is_removed(self):
        source = FAULT_CLUSTER.read_text(encoding="utf-8")
        self.assertNotIn("pub async fn execute_hostile_snapshot_child(", source)

    def test_durable_fault_path_uses_direct_async_block(self):
        source = FAULT_DURABLE.read_text(encoding="utf-8")
        self.assertIn("let outcome = async {", source)
        self.assertNotIn("let outcome = (|| async {", source)
        self.assertNotIn("    })()\n    .await;", source)


if __name__ == "__main__":
    unittest.main()
