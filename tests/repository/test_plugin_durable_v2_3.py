from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class DurablePluginV23Tests(unittest.TestCase):
    def test_durable_plugin_source_binds_intent_effect_and_plaintext_release(self) -> None:
        source = (ROOT / "crates/heptabao-plugin-host/src/durable.rs").read_text(encoding="utf-8")
        issue = source[source.index("    pub fn issue("):source.index("    pub fn renew(")]
        intent = issue.index("self.publish_intent(context, &intent)?;")
        invoke = issue.index("match self.broker.issue", intent)
        publish = issue.index("self.publish_lease(context, &issue.lease, &intent)", invoke)
        clear = issue.index("self.clear_intent(context, &intent)", publish)
        release = issue.index("self.pending = None;\n                Ok(issue)", clear)
        self.assertEqual([intent, invoke, publish, clear, release], sorted([intent, invoke, publish, clear, release]))
        self.assertIn("HBDI", source)
        self.assertIn("HBDL", source)
        self.assertNotIn("Secret::new(issue.secret", source)

    def test_restart_recovery_is_fenced_by_persisted_intent(self) -> None:
        source = (ROOT / "crates/heptabao-plugin-host/src/durable.rs").read_text(encoding="utf-8")
        self.assertIn("broker.host.state = PluginHostState::ReconciliationRequired", source)
        self.assertIn("PendingPluginInvocation", source)
        self.assertIn("DurableReconciliationDecision", source)
        self.assertIn("authoritative provider readback", source)

    def test_repository_and_external_qualification_are_separated(self) -> None:
        register = yaml.safe_load(
            (ROOT / "planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml").read_text(encoding="utf-8")
        )
        repository = {item["id"]: item for item in register["repository_blockers"]}
        external = {item["id"]: item for item in register["external_blockers"]}
        self.assertEqual("IMPLEMENTED_REVIEW_REQUIRED", repository["HB-V2-REP-015"]["state"])
        self.assertEqual(
            "EXTERNAL_COMPLETION_REQUIRED",
            external["HB-BLK-EXT-008"]["state"],
        )
        self.assertFalse(register["claims"]["production_authority"])


if __name__ == "__main__":
    unittest.main()
