"""Independent v3 provenance and traversal-bound checks; local public data only."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("authbus_gap_v3_provenance_scanner", HERE / "authbus_migration_gap_inventory_v3.py")
S = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = S
SPEC.loader.exec_module(S)


class ProvenanceAndBoundsTests(unittest.TestCase):
    def test_every_fixed_scope_path_and_old_observation_has_real_receipt_authority(self):
        expected = {
            "main": "a5083d6c99800054eb50155dafe033fd7429fdec48d8b440569eae5678e62452",
            "macbook-pro": "4445db0b874b12f27a11f2f9dab2d9d261dc6457acf827623f840e1705a560fd",
            "rog": "0a10171367de4b7588177f750e65bddef9219a5769615667b356ad0c1602440a",
            "pocket4": "7282f921223de2fb7ea32a7c39298322e65d22350f0a8e871ed87e3f3a8da293",
        }
        # The independent expected values are not read from generated PLAN.
        for host, selected in S.PLAN["hosts"].items():
            with self.subTest(host=host):
                raw = (HERE / "local-r8-evidence" / ("authbus-current-inventory-r1-" + host + ".json")).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), expected[host])
                original = json.loads(raw)
                self.assertEqual(selected["receipt"]["sha256"], expected[host])
                self.assertEqual(selected["receipt"]["bytes"], len(raw))
                self.assertEqual(selected["receipt"]["created_at"], original["created_at"])
                self.assertEqual(selected["expected_home"], original["home"])
                self.assertEqual(selected["expected_uid"], original["config"]["uid"])
                self.assertEqual(selected["expected_platform"], original["platform"])
                self.assertEqual(selected["config"], {k: original["config"][k] for k in ("path", "sha256")})
                self.assertEqual(selected["secretrefs"], [{k: x[k] for k in ("id", "path", "source")} for x in original["secret_providers"]])
                self.assertEqual({x["kind"]: x["path"] for x in selected["binding_files"]},
                                 {k: v["path"] for k, v in original["authbus"]["binding_files"].items()})
                refs = {x["path"]: x for group in original["backup_references"] for x in group["references"]}
                self.assertEqual([x["path"] for x in selected["backup_runtime"]], sorted(refs))
                for item in selected["backup_runtime"]:
                    self.assertEqual(item["baseline"], {k: v for k, v in refs[item["path"]].items() if k != "path"})
                absent = {x["agent_dir"]: x for x in original["client_store_metadata"] if x["directory"].get("exists") is False}
                self.assertEqual({x["agent_dir"] for x in selected["missing_agents"]}, set(absent))
                for item in selected["missing_agents"]:
                    self.assertEqual(item["existing_file_references"], [x["path"] for x in absent[item["agent_dir"]]["files"]])
                    agent = next(x for x in original["agents"] if x.get("agent_dir") == item["agent_dir"])
                    self.assertEqual((item["agent_id"], item["configured_model"]), (agent["id"], agent["model"]))
                startups = {x["path"]: x for x in original["entrypoints"] if "/Library/LaunchAgents/ai.openclaw.authbus-relay." in x.get("path", "")}
                self.assertEqual([x["path"] for x in selected["relay_startups"]], sorted(startups))
                for item in selected["relay_startups"]:
                    self.assertEqual(item["existing_path_references"], startups[item["path"]]["path_references"])
                    self.assertEqual(item["sha256"], startups[item["path"]]["sha256"])
                self.assertEqual({x["path"] for x in selected["relay_dependencies"]},
                                 {p for x in startups.values() for p in x["path_references"] if p.startswith(original["home"] + "/.openclaw/authbus-relay/")})
                self.assertEqual(selected["reused_existing_store_metadata"], original["client_store_metadata"])
                self.assertEqual(len(selected["reused_entrypoint_metadata"]), len(original["entrypoints"]))
                for projected, record in zip(selected["reused_entrypoint_metadata"], original["entrypoints"]):
                    self.assertTrue(all(key in record and record[key] == value for key, value in projected.items()))
        receipt_set = json.dumps(S.PLAN["source_receipt_set"], sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertEqual(hashlib.sha256(receipt_set).hexdigest(), S.PLAN["source_receipt_set_sha256"])
        self.assertNotIn("source_manifest_sha256", S.PLAN)

    def test_depth_directory_and_total_entry_caps_do_not_expand_scope(self):
        with tempfile.TemporaryDirectory(prefix="gap-v3-independent-bounds-") as temporary:
            root = Path(temporary)
            backup = root / "backup"
            (backup / "a" / "b" / "c").mkdir(parents=True)
            (backup / "a" / "b" / "c" / "private.sqlite").write_bytes(b"SQLite format 3\x00PRIVATE_ROWS")
            (backup / "second").touch()
            selected = {"expected_home": str(root), "config": {"path": str(root / "config.json")},
                        "secretrefs": [], "binding_files": [], "missing_agents": [], "relay_startups": [], "relay_dependencies": [],
                        "backup_runtime": [{"path": str(backup), "kind": "backup_reference", "baseline": {}}]}
            for limit, value, expected_hit in (("maximum_depth", 2, "maximum_depth"),
                                                ("total_directories", 1, "total_directories"),
                                                ("total_entries", 1, "total_entries")):
                with self.subTest(limit=limit):
                    bounds = copy.deepcopy(S.PLAN["bounds"])
                    bounds[limit] = value
                    inspector = S.Inspector(selected, bounds)
                    output = inspector.backup_tree(selected["backup_runtime"][0])
                    self.assertIn(expected_hit, inspector.budget.hits)
                    self.assertFalse(output["full_tree_enumerated"])
                    self.assertFalse(output["restore_qualified"])
                    self.assertLessEqual(inspector.budget.directories, bounds["total_directories"])
                    self.assertLessEqual(inspector.budget.entries, bounds["total_entries"])
                    self.assertEqual(inspector.fs.content_reads, [])
                    self.assertNotIn("private.sqlite", json.dumps(output))


if __name__ == "__main__":
    unittest.main(verbosity=2)
