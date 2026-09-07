from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "oracle_side_effect_diff_v1", ROOT / "scripts" / "oracle_side_effect_diff_v1.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def snapshot(**overrides):
    value = {
        "mount_revision": 1,
        "policy_revision": 2,
        "token_count": 3,
        "lease_count": 4,
        "audit_event_count": 5,
        "plugin_process_count": 0,
        "raft_commit_index": 6,
        "external_effect_receipt_count": 0,
        "sealed": False,
        "active": True,
    }
    value.update(overrides)
    return value


def policy(**overrides):
    value = {
        "allow_mount_revision": False,
        "allow_policy_revision": False,
        "allow_token_count": False,
        "allow_lease_count": False,
        "allow_audit_event_count": False,
        "allow_plugin_process_count": False,
        "allow_raft_commit_index": False,
        "allow_external_effect_receipt_count": False,
        "allow_seal_transition": False,
        "allow_active_transition": False,
    }
    value.update(overrides)
    return value


def document(**overrides):
    value = {
        "baseline_id": "HB-ORACLE-OPENBAO-V2_6_2",
        "observation_id": "HB-OSE-SYNTHETIC-HEALTH-0001",
        "operation_id": "sys.health.read",
        "capture_kind": "SYNTHETIC_CONTRACT",
        "status": "SYNTHETIC_CONTRACT",
        "artifact_signature_verified": False,
        "before": snapshot(),
        "after": snapshot(),
        "declared_policy": policy(),
        "provenance_ref": "synthetic://h01/health",
        "review_status": "PENDING",
    }
    value.update(overrides)
    return value


class SideEffectDiffTests(unittest.TestCase):
    def test_empty_delta_is_deterministic_and_authority_free(self):
        first = MODULE.build_observation(document())
        second = MODULE.build_observation(document())
        self.assertEqual(first, second)
        self.assertEqual(first["authority_effect"], "NONE")
        self.assertFalse(first["secret_material_present"])
        self.assertIsNone(first["raw_capture_digest_sha256"])

    def test_declared_audit_increment_is_allowed(self):
        value = document(
            after=snapshot(audit_event_count=6),
            declared_policy=policy(allow_audit_event_count=True),
        )
        observation = MODULE.build_observation(value)
        self.assertEqual(observation["delta"]["audit_event_count"], 1)

    def test_undeclared_token_increment_is_rejected(self):
        value = document(after=snapshot(token_count=4))
        with self.assertRaisesRegex(MODULE.ObservationError, "unexpected side effect: token_count"):
            MODULE.build_observation(value)

    def test_black_box_capture_requires_verified_artifact(self):
        value = document(
            capture_kind="BLACK_BOX_ORACLE",
            status="SANITIZED",
            raw_capture_digest_sha256="0" * 64,
        )
        with self.assertRaisesRegex(MODULE.ObservationError, "verified artifact signature"):
            MODULE.build_observation(value)

    def test_black_box_capture_requires_raw_digest(self):
        value = document(
            capture_kind="BLACK_BOX_ORACLE",
            status="SANITIZED",
            artifact_signature_verified=True,
        )
        with self.assertRaisesRegex(MODULE.ObservationError, "raw_capture_digest_sha256"):
            MODULE.build_observation(value)

    def test_verified_black_box_capture_binds_raw_digest(self):
        value = document(
            capture_kind="BLACK_BOX_ORACLE",
            status="SANITIZED",
            artifact_signature_verified=True,
            raw_capture_digest_sha256="1" * 64,
        )
        observation = MODULE.build_observation(value)
        self.assertEqual(observation["raw_capture_digest_sha256"], "1" * 64)
        self.assertEqual(observation["authority_effect"], "NONE")

    def test_synthetic_capture_rejects_raw_digest(self):
        value = document(raw_capture_digest_sha256="2" * 64)
        with self.assertRaisesRegex(MODULE.ObservationError, "synthetic contract"):
            MODULE.build_observation(value)

    def test_black_box_capture_cannot_use_synthetic_status(self):
        value = document(
            capture_kind="BLACK_BOX_ORACLE",
            artifact_signature_verified=True,
            raw_capture_digest_sha256="3" * 64,
        )
        with self.assertRaisesRegex(MODULE.ObservationError, "cannot use synthetic status"):
            MODULE.build_observation(value)

    def test_secret_bearing_key_is_rejected(self):
        value = document()
        value["client_token"] = "synthetic-value"
        with self.assertRaisesRegex(MODULE.ObservationError, "forbidden secret-bearing key"):
            MODULE.build_observation(value)

    def test_snapshot_shape_is_closed(self):
        value = document()
        value["after"]["unknown_counter"] = 1
        with self.assertRaisesRegex(MODULE.ObservationError, "shape mismatch"):
            MODULE.build_observation(value)

    def test_transition_requires_explicit_policy(self):
        value = document(after=snapshot(sealed=True, active=False))
        with self.assertRaisesRegex(MODULE.ObservationError, "sealed_changed"):
            MODULE.build_observation(value)


if __name__ == "__main__":
    unittest.main()
