"""Fail-closed tests for the complete OpenBao migration asset denominator."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import migration_preflight as preflight
from bao_http import BaoError


class MigrationAssetDenominatorTests(unittest.TestCase):
    def test_current_plan_has_exact_declared_asset_denominator(self):
        assets = preflight.declared_asset_contract()
        self.assertEqual(preflight.EXPECTED_ASSET_IDS, {item["id"] for item in assets})
        self.assertEqual(18, len(assets))

    def test_missing_or_renamed_asset_fails_closed(self):
        document = json.loads(preflight.ASSET_PLAN.read_text(encoding="utf-8"))
        document["assets"] = document["assets"][:-1]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assets.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(BaoError, "asset_plan_denominator_drift"):
                preflight.declared_asset_contract(path)


if __name__ == "__main__":
    unittest.main()
