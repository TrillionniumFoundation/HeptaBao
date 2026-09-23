#!/usr/bin/env python3
"""Repository guard for the transaction-scoped authentication capability."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "crates" / "heptabao-server" / "src"
LIB_RS = SERVER / "lib.rs"
AUTH_RS = SERVER / "auth.rs"
SERVICE_RS = SERVER / "service.rs"
WORKFLOWS_RS = SERVER / "service_workflows.rs"
BOUNDARY_DOC = ROOT / "docs" / "security" / "HEPTABAO_REQUEST_CAPABILITY_BOUNDARY_V1.md"


class AuthenticationCapabilityBoundaryTests(unittest.TestCase):
    def test_raw_auth_module_is_not_public(self) -> None:
        text = LIB_RS.read_text(encoding="utf-8")
        self.assertEqual(1, len(re.findall(r"(?m)^mod auth;$", text)))
        self.assertNotRegex(text, r"(?m)^pub(?:\([^)]*\))?\s+mod\s+auth\s*;")
        self.assertNotRegex(text, r"(?m)^pub\s+use\s+[^;]*auth")

    def test_public_crate_surface_keeps_principal_unnameable(self) -> None:
        text = LIB_RS.read_text(encoding="utf-8")
        self.assertIn("use heptabao_server::auth::Principal;", text)
        self.assertIn("```compile_fail", text)
        self.assertIn("pub use service::{Response, Service};", text)

    def test_service_public_methods_do_not_accept_or_return_principal(self) -> None:
        text = SERVICE_RS.read_text(encoding="utf-8")
        public_signatures = re.findall(
            r"(?ms)^\s*pub\s+fn\s+[^\{;]+(?:\{|;)",
            text,
        )
        self.assertGreater(len(public_signatures), 0)
        for signature in public_signatures:
            self.assertNotIn("Principal", signature, signature)
            self.assertNotIn("AuthState", signature, signature)

    def test_principal_is_affine_and_raw_authority_is_internal(self) -> None:
        text = AUTH_RS.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^pub\(super\) struct Principal \{")
        self.assertNotRegex(
            text,
            r"#\[derive\([^]]*Clone[^]]*\)\]\s*pub\(super\) struct Principal",
        )
        self.assertNotIn("authenticated_at", text)
        self.assertIn("request_time: u64", text)
        self.assertRegex(text, r"(?m)^\s*pub\(super\) fn authenticate\(")
        self.assertNotRegex(text, r"(?m)^\s*pub fn authenticate\(")
        self.assertRegex(text, r"(?m)^\s*pub\(super\) fn authorize_request\(")
        self.assertNotRegex(text, r"(?m)^\s*pub fn authorize\(")
        self.assertNotIn("Ok(principal.clone())", text)

    def test_dispatch_consumes_one_principal_and_forwards_live_time(self) -> None:
        text = SERVICE_RS.read_text(encoding="utf-8")
        compact = re.sub(r"\s+", "", text)
        self.assertRegex(text, r"principal:\s*Option<Principal>")
        self.assertRegex(text, r"Self::dispatch\(\s*&mut transaction,\s*principal,")
        self.assertNotRegex(
            text,
            r"Self::dispatch\(\s*&mut transaction,\s*principal\.as_ref\(\)",
        )
        self.assertIn("letmuttransaction=admitted;", compact)
        self.assertIn("letwrapping_rollback=wrap_ttl_seconds.map(|_|admitted.clone());", compact)
        dispatch_start = compact.index("letwrapping_rollback=wrap_ttl_seconds.map(|_|admitted.clone());")
        dispatch_end = compact.index("if admitted.engines.record_root().is_some()".replace(" ", ""), dispatch_start)
        dispatch_block = compact[dispatch_start:dispatch_end]
        self.assertEqual(1, dispatch_block.count("admitted.clone()"))
        self.assertEqual(1, len(re.findall(r"Self::dispatch\(", text)))
        workflows = WORKFLOWS_RS.read_text(encoding="utf-8")
        self.assertRegex(
            text,
            r"fn dispatch_authorized_subrequest\(\s*state:\s*&mut State,\s*principal:\s*Option<&Principal>",
        )
        self.assertEqual(
            2,
            len(
                re.findall(
                    r"Self::dispatch_authorized_subrequest\(",
                    text + "\n" + workflows,
                )
            ),
        )
        self.assertEqual(
            1,
            len(re.findall(r"Self::dispatch_authorized_subrequest\(", workflows)),
        )
        self.assertGreaterEqual(compact.count(".authorize_request("), 3)
        self.assertIn(",now)", compact)

    def test_wrapping_request_envelope_does_not_carry_authority(self) -> None:
        text = SERVICE_RS.read_text(encoding="utf-8")
        match = re.search(r"pub struct ServiceRequest<'a> \{(.*?)\n\}", text, re.S)
        self.assertIsNotNone(match)
        fields = set(re.findall(r"pub (\w+):", match.group(1)))
        self.assertEqual(
            fields,
            {
                "method",
                "path",
                "namespace",
                "token",
                "body",
                "wrap_ttl_seconds",
                "origin_peer",
            },
        )
        # A verified TLS chain is transport evidence for certificate auth; it
        # is never an authenticated Principal or an authorization decision. It
        # is crate-private so external callers cannot inject an unverified
        # chain through the public ServiceRequest literal.
        self.assertIn("pub(crate) client_certificates", match.group(1))
        self.assertNotIn("Principal", match.group(1))
        self.assertNotIn("AuthState", match.group(1))
        self.assertNotRegex(text, r"#\[derive\([^]]*(?:Clone|Debug)[^]]*\)\]\s*pub struct ServiceRequest")

    def test_request_capability_has_one_documented_owner(self) -> None:
        self.assertTrue(BOUNDARY_DOC.is_file())
        text = BOUNDARY_DOC.read_text(encoding="utf-8")
        for marker in (
            "transaction-scoped",
            "non-exported",
            "non-cloneable",
            "consumed by value",
            "live decision time",
            "finite-use",
            "revocation",
            "exact-head",
        ):
            self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
