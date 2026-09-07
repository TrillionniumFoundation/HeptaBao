from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATE = ROOT / "crates" / "heptabao-runtime-service"
SOURCE = CRATE / "src" / "lib.rs"
GUIDE = ROOT / "docs" / "modules" / "heptabao-runtime-service.md"
ARCHITECTURE = (
    ROOT
    / "docs"
    / "architecture"
    / "HEPTABAO_V2_1_AUTHORIZED_DURABLE_PIPELINE.md"
)
MATRIX = ROOT / "planning" / "HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml"
REGISTER = ROOT / "planning" / "HEPTABAO_BLOCKER_REGISTER_V2_0.yaml"
WORKFLOW = ROOT / ".github" / "workflows" / "v2-1-main-convergence.yml"


class AuthorizedDurableRuntimeV21Tests(unittest.TestCase):
    def test_manifest_source_docs_truth_and_ci_are_one_tree(self) -> None:
        paths = [
            CRATE / "Cargo.toml",
            SOURCE,
            GUIDE,
            ARCHITECTURE,
            MATRIX,
            REGISTER,
            WORKFLOW,
        ]
        missing = [str(path.relative_to(ROOT)) for path in paths if not path.is_file()]
        self.assertEqual([], missing)

        manifest = (CRATE / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('name = "heptabao-runtime-service"', manifest)
        self.assertIn(
            'heptabao-durable-service = { path = "../heptabao-durable-service" }',
            manifest,
        )
        self.assertIn("publish = false", manifest)

        matrix = MATRIX.read_text(encoding="utf-8")
        self.assertEqual(1, matrix.count("crate: heptabao-runtime-service"))
        self.assertIn("domain: authorized audit-to-durable mutation adapter", matrix)
        self.assertIn("source: crates/heptabao-runtime-service/src/lib.rs", matrix)
        self.assertIn("guide: docs/modules/heptabao-runtime-service.md", matrix)

        register = REGISTER.read_text(encoding="utf-8")
        self.assertEqual(1, register.count("id: HB-V2-REP-009"))
        self.assertIn(
            "id: HB-V2-REP-009, class: REPOSITORY_CONTROLLED, severity: CRITICAL",
            register,
        )
        rep009 = next(
            line for line in register.splitlines() if "id: HB-V2-REP-009" in line
        )
        self.assertIn("state: IMPLEMENTED_REVIEW_REQUIRED", rep009)

    def test_admission_happens_before_durable_dispatch(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("pub fn handle_with_failpoint(")
        end = source.index("pub fn reconcile(", start)
        body = source[start:end]

        ordered = [
            ".authenticate(",
            ".authorize(",
            "AuditStage::AcceptedBeforeEntry",
            "PutRequest::new(",
            ".put_with_failpoint(",
        ]
        positions = [body.index(marker) for marker in ordered]
        self.assertEqual(sorted(positions), positions)

        delete_order = [
            body.index("AuditStage::AcceptedBeforeEntry"),
            body.index("DeleteRequest::new("),
            body.index(".delete_with_failpoint("),
        ]
        self.assertEqual(sorted(delete_order), delete_order)

    def test_inbound_cannot_supply_authenticated_principal_or_authorization_digest(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        inbound_start = source.index("pub struct InboundMutation")
        inbound_end = source.index("impl InboundMutation", inbound_start)
        inbound = source[inbound_start:inbound_end]
        self.assertIn("credential: Credential", inbound)
        self.assertIn("namespace: String", inbound)
        self.assertIn("request_id: String", inbound)
        self.assertIn("resource: String", inbound)
        self.assertIn("operation: InboundOperation", inbound)
        self.assertNotIn("AuthenticatedPrincipal", inbound)
        self.assertNotIn("AuthorizationDigest", inbound)

        service_start = source.index("pub struct RuntimeService")
        service_end = source.index("impl<A, Z, U, B> fmt::Debug", service_start)
        service = source[service_start:service_end]
        self.assertIn("durable: DurableService<B>", service)
        self.assertNotRegex(source, r"pub fn durable(?:_mut)?\(")

    def test_post_entry_uncertainty_is_never_mapped_to_retry(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("RuntimeError::OutcomeUnknown { recovery_reference }", source)
        self.assertIn("AuditStage::OutcomeUnknown", source)
        self.assertNotIn("Retryable", source)
        self.assertNotIn("AutomaticRetry", source)

        architecture = ARCHITECTURE.read_text(encoding="utf-8").lower()
        self.assertIn("never blind retry", architecture)
        self.assertIn("no replay identity allocated", architecture)
        self.assertIn("post-commit audit failure", architecture)

    def test_rejections_do_not_allocate_durable_identity(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        test_names = set(re.findall(r"fn ([a-z0-9_]+)\(\) -> Result<\(\), RuntimeError>", source))
        required = {
            "invalid_credential_cannot_allocate_durable_request_identity",
            "denied_request_does_not_preempt_later_authorized_identity",
            "request_identity_is_scoped_to_authenticated_principal",
            "pre_entry_audit_failure_prevents_durable_dispatch",
            "post_commit_audit_failure_is_reconcile_only",
            "durable_unknown_survives_restart_and_reconciles",
            "debug_output_redacts_credentials_paths_and_secret",
        }
        self.assertTrue(required.issubset(test_names), sorted(required - test_names))

        for function in (
            "invalid_credential_cannot_allocate_durable_request_identity",
            "pre_entry_audit_failure_prevents_durable_dispatch",
        ):
            start = source.index(f"fn {function}")
            next_test = source.find("\n    #[test]", start + 1)
            body = source[start : next_test if next_test != -1 else None]
            self.assertIn("retained_request_count(), 0", body)
            self.assertIn("generation(), 0", body)

    def test_debug_and_error_surfaces_do_not_expose_secrets(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        for marker in (
            "Credential([REDACTED])",
            'field("namespace", &"[REDACTED]")',
            'field("request_id", &"[REDACTED]")',
            'field("resource", &"[REDACTED]")',
            "Put([REDACTED])",
            "AuthorizationDigest([REDACTED])",
        ):
            self.assertIn(marker, source)
        self.assertNotRegex(source, r"formatter\.write_str\([^\n]*(credential|secret|principal)")

    def test_main_targeted_workflow_runs_runtime_tests_read_only(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("branches: [main]", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("persist-credentials: true", workflow)
        self.assertIn("cargo +1.98.0 test --locked --workspace --all-targets", workflow)
        self.assertIn("tests/repository", workflow)

    def test_authority_claims_remain_false(self) -> None:
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (GUIDE, ARCHITECTURE, MATRIX, REGISTER)
        )
        for claim in (
            "qualification: false",
            "compatibility_claim: false",
            "production_authority: false",
            "migration_authority: false",
            "release_authority: false",
        ):
            self.assertIn(claim, combined)
        self.assertIn("authority_effect: NONE", combined)


if __name__ == "__main__":
    unittest.main()
