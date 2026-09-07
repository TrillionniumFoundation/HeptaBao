from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class V131ResidualHardeningTests(unittest.TestCase):
    def test_response_writer_uses_one_absolute_deadline(self) -> None:
        source = text("crates/heptabao-p0-server/src/main.rs")
        for marker in (
            "fn write_response_until(",
            "checked_duration_since(Instant::now())",
            "stream.write(&bytes[offset..])",
            "response write deadline exceeded",
            "set response flush timeout failed",
        ):
            self.assertIn(marker, source)
        self.assertNotIn("write_all(&bytes)", source)

    def test_state_lock_is_fail_closed_and_dispatch_time_is_fresh(self) -> None:
        source = text("crates/heptabao-p0-server/src/main.rs")
        for marker in (
            "use std::sync::{Arc, Mutex, TryLockError};",
            "let response = match server.try_lock()",
            "Err(TryLockError::WouldBlock)",
            'detail_code: "p0-state-busy"',
            "let now = tick(epoch).map_err(internal_serve_error)?;",
        ):
            self.assertIn(marker, source)
        self.assertLess(
            source.index("let response = match server.try_lock()"),
            source.index("let now = tick(epoch).map_err(internal_serve_error)?;"),
        )
        self.assertNotIn("let mut guard = server.lock()", source)

    def test_operation_body_policy_precedes_dispatch(self) -> None:
        source = text("crates/heptabao-p0-server/src/lib.rs")
        self.assertIn("operation_body_is_valid(operation, &envelope.request.body)", source)
        self.assertIn('"operation-body-forbidden"', source)
        self.assertIn('Operation::SysInit => body == b"{}"', source)
        self.assertIn("Operation::SysUnseal | Operation::KvWrite => !body.is_empty()", source)
        self.assertLess(
            source.index("operation_body_is_valid(operation, &envelope.request.body)"),
            source.index("let request_event = AuditEvent"),
        )

    def test_sensitive_target_and_kv_path_lifetimes_are_controlled(self) -> None:
        protocol = text("crates/heptabao-protocol/src/lib.rs")
        authbus = text("crates/heptabao-authbus-contracts/src/lib.rs")
        server = text("crates/heptabao-p0-server/src/lib.rs")
        self.assertIn("impl Drop for CanonicalTarget", protocol)
        self.assertIn("pub fn matches_canonical(&self, raw: &str) -> bool", protocol)
        self.assertIn("canonical_target.matches_canonical(self.canonical_target)", authbus)
        self.assertNotIn("canonical_target.canonical_string() != self.canonical_target", authbus)
        self.assertIn("struct SecretPath(String);", server)
        self.assertIn("impl Drop for SecretPath", server)
        self.assertIn("BTreeMap<SecretPath, SecretBytes>", server)

    def test_kv_list_builds_directly_into_owned_response_bytes(self) -> None:
        source = text("crates/heptabao-p0-server/src/lib.rs")
        self.assertIn("append_json_string_bytes(key.as_bytes(), &mut body);", source)
        self.assertIn("kv_list_response_is_direct_owned_and_debug_redacted", source)
        self.assertNotIn("let escaped = escape_json(key);", source)
        self.assertNotIn("collect::<Vec<_>>()\n            .join(\",\")", source)

    def test_transport_matrix_names_the_residual_closures(self) -> None:
        matrix = yaml.safe_load(
            text("planning/HEPTABAO_P0_TRANSPORT_TEST_MATRIX_V2.yaml")
        )
        cases = {entry["id"]: entry for entry in matrix["cases"]}
        self.assertEqual(cases["P0-TRANSPORT-011"]["maximum_write_seconds"], 5)
        self.assertEqual(
            cases["P0-TRANSPORT-013"]["expected_detail_code"],
            "operation-body-forbidden",
        )
        self.assertIn("P0-TRANSPORT-014", cases)
        self.assertFalse(matrix["qualification"])
        self.assertFalse(matrix["compatibility_claim"])
        self.assertEqual(matrix["authority_effect"], "NONE")

    def test_normative_manifest_includes_residual_regression_suite(self) -> None:
        manifest = yaml.safe_load(
            text("planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml")
        )
        paths = {entry["path"] for entry in manifest["documents"]}
        self.assertIn("tests/plan/test_v1_3_1_residual_hardening.py", paths)
        self.assertFalse(manifest["qualification"])
        self.assertFalse(manifest["compatibility_claim"])
        self.assertEqual(manifest["authority_effect"], "NONE")


if __name__ == "__main__":
    unittest.main()
