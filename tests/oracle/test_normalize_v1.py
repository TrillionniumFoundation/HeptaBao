from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from scripts.oracle_normalize_v1 import NormalizationError, Normalizer, canonical_bytes, normalize_file

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "oracle/normalization/HEPTABAO_ORACLE_NORMALIZATION_POLICY_V1.yaml"


class OracleNormalizationTests(unittest.TestCase):
    def policy(self) -> tuple[dict, bytes]:
        raw = POLICY_PATH.read_bytes()
        return yaml.safe_load(raw), raw

    def normalize_value(self, value: object) -> dict:
        policy, policy_bytes = self.policy()
        raw = canonical_bytes(value)
        return Normalizer(policy, policy_bytes).normalize(value, raw)

    def test_registered_secret_becomes_typed_placeholder(self) -> None:
        token = "syn" + "thetic-token-value"
        value = {
            "request_id": "random-request",
            "auth": {
                "client_token": token,
                "policies": ["z-policy", "a-policy"],
                "lease_duration": 3600,
            },
        }
        result = self.normalize_value(value)
        self.assertEqual(result["document"]["request_id"], "$REQUEST_ID")
        placeholder = result["document"]["auth"]["client_token"]["$heptabao_secret_placeholder_v1"]
        self.assertEqual(placeholder["kind"], "service_or_batch_token")
        self.assertEqual(placeholder["byte_length"], len(token.encode("utf-8")))
        self.assertEqual(placeholder["value_shape"], "string")
        self.assertNotIn(token, json.dumps(result, sort_keys=True))
        self.assertEqual(result["document"]["auth"]["policies"], ["a-policy", "z-policy"])
        self.assertEqual(result["document"]["auth"]["lease_duration"], 3600)
        self.assertEqual(result["authority_effect"], "NONE")

    def test_unmatched_suspicious_secret_is_rejected(self) -> None:
        value = {"other": {"refresh_token": "synthetic-refresh"}}
        with self.assertRaisesRegex(NormalizationError, "unmatched suspicious secret field"):
            self.normalize_value(value)

    def test_unknown_fields_and_array_order_are_preserved(self) -> None:
        value = {
            "new_future_field": {"nested": [3, 1, 2]},
            "data": {"unregistered_array": ["b", "a"]},
        }
        result = self.normalize_value(value)
        self.assertEqual(result["document"], value)
        self.assertEqual(result["changes"], [])

    def test_nested_wildcard_secret_rule_applies_only_at_registered_shape(self) -> None:
        value = {"data": {"credential": {"password": "synthetic-password", "username": "role-user"}}}
        result = self.normalize_value(value)
        credential = result["document"]["data"]["credential"]
        self.assertEqual(credential["username"], "role-user")
        self.assertIn("$heptabao_secret_placeholder_v1", credential["password"])

    def test_output_is_deterministic_for_equivalent_json_objects(self) -> None:
        left = {"data": {"policies": ["b", "a"], "creation_time": "2026-01-01T00:00:00Z"}, "request_id": "one"}
        right = {"request_id": "two", "data": {"creation_time": "2027-01-01T00:00:00Z", "policies": ["a", "b"]}}
        left_result = self.normalize_value(left)
        right_result = self.normalize_value(right)
        self.assertEqual(left_result["normalized_sha256"], right_result["normalized_sha256"])
        self.assertEqual(left_result["document"], right_result["document"])
        self.assertNotEqual(left_result["input_sha256"], right_result["input_sha256"])

    def test_ambiguous_equal_specificity_rules_are_rejected(self) -> None:
        policy, policy_bytes = self.policy()
        modified = copy.deepcopy(policy)
        modified["rules"].append(
            {
                "path": "/data/credential/*",
                "operation": "replace",
                "replacement": "$AMBIGUOUS",
                "reason": "Synthetic ambiguity test.",
                "security_relevance": "TEST_ONLY",
                "approved_roles": ["compatibility", "security"],
            }
        )
        normalizer = Normalizer(modified, policy_bytes)
        with self.assertRaisesRegex(NormalizationError, "ambiguous normalization rules"):
            normalizer.normalize({"data": {"credential": {"password": "synthetic"}}}, b"{}")

    def test_remove_rule_for_security_relevant_field_is_rejected(self) -> None:
        policy, policy_bytes = self.policy()
        modified = copy.deepcopy(policy)
        modified["rules"].append(
            {
                "path": "/data/policy",
                "operation": "remove",
                "reason": "Synthetic unsafe removal.",
                "security_relevance": "SECURITY_CRITICAL",
                "approved_roles": ["compatibility", "security"],
            }
        )
        with self.assertRaisesRegex(NormalizationError, "security-relevant remove rule is forbidden"):
            Normalizer(modified, policy_bytes)

    def test_file_api_writes_sanitized_output_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "input.json"
            input_path.write_text(json.dumps({"data": {"private_key": "synthetic-private"}}), encoding="utf-8")
            result = normalize_file(input_path, POLICY_PATH)
            encoded = json.dumps(result)
            self.assertNotIn("synthetic-private", encoded)
            self.assertIn("$heptabao_secret_placeholder_v1", encoded)


if __name__ == "__main__":
    unittest.main()
