from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "oracle_side_effect_diff_v1",
    ROOT / "scripts" / "oracle_side_effect_diff_v1.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def black_box_document(raw_digest: str) -> dict[str, object]:
    snapshot: dict[str, object] = {
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
    return {
        "baseline_id": "HB-ORACLE-OPENBAO-V2_6_2",
        "observation_id": "HB-OSE-BLACKBOX-BINDING-0001",
        "operation_id": "sys.health.read",
        "capture_kind": "BLACK_BOX_ORACLE",
        "status": "SANITIZED",
        "artifact_signature_verified": True,
        "before": dict(snapshot),
        "after": dict(snapshot),
        "declared_policy": {
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
        },
        "provenance_ref": "synthetic://raw-digest-binding-test",
        "review_status": "PENDING",
        "raw_capture_digest_sha256": raw_digest,
    }


class RawCaptureBindingTests(unittest.TestCase):
    def test_raw_digest_is_part_of_sanitized_digest_preimage(self):
        first = MODULE.build_observation(black_box_document("1" * 64))
        second = MODULE.build_observation(black_box_document("2" * 64))
        self.assertNotEqual(
            first["sanitized_capture_digest_sha256"],
            second["sanitized_capture_digest_sha256"],
        )
        self.assertEqual(first["raw_capture_digest_sha256"], "1" * 64)
        self.assertEqual(second["raw_capture_digest_sha256"], "2" * 64)


if __name__ == "__main__":
    unittest.main()
