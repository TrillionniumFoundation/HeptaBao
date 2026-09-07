from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class PlanV147Tests(unittest.TestCase):
    def test_previous_repository_blockers_are_closed_without_external_overclaim(self) -> None:
        receipt = yaml.safe_load(
            (ROOT / "planning/evidence/repository/HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual([f"HB-BLK-REPO-{i:03d}" for i in range(49, 59)], receipt["closed_repository_blockers"])
        self.assertEqual([], receipt["external_or_control_blockers_closed"])
        self.assertFalse(receipt["claims"]["qualification"])

    def test_new_repository_blockers_are_source_implemented_review_required(self) -> None:
        value = yaml.safe_load((ROOT / "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_7.yaml").read_text(encoding="utf-8"))
        self.assertEqual([f"HB-BLK-REPO-{i:03d}" for i in range(59, 63)], [item["id"] for item in value["added_blockers"]])
        self.assertTrue(all(item["state"] == "IMPLEMENTED_SOURCE_REVIEW_REQUIRED" for item in value["added_blockers"]))

    def test_external_and_control_blockers_remain_open(self) -> None:
        value = yaml.safe_load((ROOT / "planning/HEPTABAO_V1_4_7_POST_MERGE_TRUTH_STATUS.yaml").read_text(encoding="utf-8"))
        self.assertEqual(
            ["HB-BLK-CTRL-001", *[f"HB-BLK-EXT-{i:03d}" for i in range(1, 8)]],
            value["external_open"],
        )
        self.assertEqual("NONE", value["claims"]["authority_effect"])

    def test_current_workflow_is_read_only_and_pr_only(self) -> None:
        text = (ROOT / ".github/workflows/plan-v1.4.7-post-merge-truth-and-external-admission.yml").read_text(encoding="utf-8")
        self.assertIn("contents: read", text)
        self.assertIn("pull_request:", text)
        self.assertNotIn("push:", text)
        self.assertIn("exact-head", text)
        self.assertIn("prospective-merge", text)


if __name__ == "__main__":
    unittest.main()
