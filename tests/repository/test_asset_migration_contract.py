"""Bind the frozen 18-asset migration denominator to concrete repository evidence."""
from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "planning/HEPTABAO_OPENBAO_ASSET_MIGRATION_V1.json"


class AssetMigrationContractTests(unittest.TestCase):
    def test_frozen_denominator_and_authority_flags(self):
        ledger = json.loads(LEDGER.read_text())
        self.assertEqual(ledger["schema"], "heptabao.openbao-asset-migration.v1")
        self.assertEqual(ledger["source_product"], "OpenBao")
        self.assertEqual(ledger["source_version"], "2.6.2")
        self.assertEqual(ledger["target_product"], "HeptaBao")
        self.assertIs(ledger["full_asset_migration_authority"], False)
        self.assertIs(ledger["cutover_authority"], False)
        self.assertIs(ledger["rollback_authority"], False)
        rows = ledger["assets"]
        self.assertEqual(len(rows), 18)
        ids = [row["id"] for row in rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_bounded_adapters_and_evidence_are_real_files(self):
        ledger = json.loads(LEDGER.read_text())
        bounded = {row["id"]: row for row in ledger["assets"] if row["disposition"] == "BOUNDED_ADAPTER"}
        self.assertTrue(
            {"policies_acl", "kv_v2_data_history_metadata", "transit_keys_ciphertexts"}
            <= set(bounded)
        )
        self.assertGreaterEqual(len(bounded), 3)
        for row in bounded.values():
            self.assertIsInstance(row["adapter"], str)
            self.assertTrue((ROOT / row["adapter"]).is_file(), row["adapter"])
            self.assertTrue(row["evidence"])
            for evidence in row["evidence"]:
                self.assertTrue((ROOT / evidence).is_file(), evidence)
            self.assertGreater(len(row["required_exit"].strip()), 40)

    def test_nontransferable_live_authority_remains_explicit(self):
        ledger = json.loads(LEDGER.read_text())
        rows = {row["id"]: row for row in ledger["assets"]}
        self.assertEqual(rows["tokens_and_revocation"]["disposition"], "DO_NOT_TRANSFER_LIVE_AUTHORITY")
        self.assertEqual(rows["storage_ha_metadata"]["disposition"], "DO_NOT_IMPORT_RAW_FORMAT")
        self.assertEqual(rows["wrapping_cubbyhole_ephemeral"]["disposition"], "EPHEMERAL_DO_NOT_MIGRATE")


if __name__ == "__main__":
    unittest.main()
