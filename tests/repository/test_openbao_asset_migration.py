import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import validate_openbao_asset_migration as validator


class OpenBaoAssetMigrationTests(unittest.TestCase):
    def setUp(self): self.doc = validator.load()

    def test_current_closed_world_ledger_passes(self):
        self.assertEqual([], validator.validate(self.doc))

    def test_missing_asset_cannot_disappear_silently(self):
        changed = copy.deepcopy(self.doc); changed["assets"].pop()
        self.assertIn("asset denominator drift", validator.validate(changed))

    def test_bounded_adapter_requires_real_path(self):
        changed = copy.deepcopy(self.doc)
        row = next(row for row in changed["assets"] if row["id"] == "kv_v2_data_history_metadata")
        row["adapter"] = "qa/openbao-acceptance/not-real.py"
        self.assertTrue(any("adapter path missing" in error for error in validator.validate(changed)))

    def test_repository_cannot_self_grant_migration_or_cutover(self):
        for flag in ("full_asset_migration_authority", "cutover_authority", "rollback_authority"):
            changed = copy.deepcopy(self.doc); changed[flag] = True
            self.assertTrue(any(flag in error for error in validator.validate(changed)))

    def test_live_authority_and_ephemeral_state_have_non_transfer_dispositions(self):
        by_id = {row["id"]: row for row in self.doc["assets"]}
        self.assertEqual(by_id["tokens_and_revocation"]["disposition"], "DO_NOT_TRANSFER_LIVE_AUTHORITY")
        self.assertEqual(by_id["wrapping_cubbyhole_ephemeral"]["disposition"], "EPHEMERAL_DO_NOT_MIGRATE")
        self.assertEqual(by_id["storage_ha_metadata"]["disposition"], "DO_NOT_IMPORT_RAW_FORMAT")


if __name__ == "__main__": unittest.main()
