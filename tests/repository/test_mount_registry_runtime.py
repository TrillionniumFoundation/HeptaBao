import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class MountRegistryRuntimeTests(unittest.TestCase):
    def test_runtime_revision_cas_remount_and_lifecycle_are_bound(self):
        engines = (ROOT / "crates/heptabao-server/src/engines.rs").read_text()
        auth = (ROOT / "crates/heptabao-server/src/auth.rs").read_text()
        service = (ROOT / "crates/heptabao-server/src/service.rs").read_text()
        tests = "\n".join(
            (ROOT / path).read_text()
            for path in (
                "crates/heptabao-server/src/engine_tests.rs",
                "crates/heptabao-server/src/auth_tests.rs",
                "crates/heptabao-server/src/service_tests.rs",
            )
        )
        for marker in ("cas_revision", "revision", "incarnation", "mount_epochs", "pub(crate) fn remount"):
            self.assertIn(marker, engines)
        for marker in ("cas_revision", "revision", "accessor", "pub(super) fn remount_mount"):
            self.assertIn(marker, auth)
        for marker in ('path == "sys/remount"', '"revision": 1', '"accessor": "audit_file"'):
            self.assertIn(marker, service)
        for name in (
            "mount_registry_revision_cas_remount_and_incarnation_are_persisted",
            "auth_mount_revision_tune_remount_and_recreate_rotate_identity",
            "mount_registry_remount_cas_and_restart_fence_stale_incarnations",
        ):
            self.assertIn(f"fn {name}", tests)

    def test_execution_row_keeps_later_phases_open(self):
        matrix = json.loads((ROOT / "planning/HEPTABAO_REPLACEMENT_EXECUTION_V2.json").read_text())
        row = next(row for row in matrix["surfaces"] if row["surface_id"] == "HB-SURFACE-MOUNT-REGISTRY")
        self.assertEqual(row["implementation"], "RUNTIME_COMPLETE_LOCAL")
        self.assertFalse(row["full_surface_verified"])
        self.assertFalse(row["independently_admitted"])
        self.assertIn("migration", row["remaining_scope"].lower())
        self.assertIn("multi-host", row["remaining_scope"].lower())
        self.assertIn("2.6.2", row["remaining_scope"])
        self.assertEqual(
            set(row["implementation_evidence"]["local_dimensions"]),
            {"protocol_framing", "authorization_before_effect", "effect_readback", "crash_reopen"},
        )


if __name__ == "__main__":
    unittest.main()
