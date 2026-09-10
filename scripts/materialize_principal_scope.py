#!/usr/bin/env python3
"""Materialize the affine, current-time-bound request principal repair.

This script is a one-shot source transformer for the exact reviewed V2.4
candidate.  It fails closed if any expected source shape has drifted.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def materialize_auth() -> None:
    path = "crates/heptabao-server/src/auth.rs"
    text = read(path)

    text = replace_once(
        text,
        "//! Every caller must transact a clone and durably commit authentication use-count\n"
        "//! changes before returning either successful data or a handler error.\n",
        "//! Every caller owns one affine request capability and durably commits authentication\n"
        "//! use-count changes before returning either successful data or a handler error.\n",
        "auth module contract",
    )
    text = replace_once(
        text,
        "use std::{\n    collections::{BTreeMap, BTreeSet},\n    num::NonZeroU32,\n};",
        "use std::{\n    cell::Cell,\n    collections::{BTreeMap, BTreeSet},\n    num::NonZeroU32,\n};",
        "Cell import",
    )
    text = replace_once(
        text,
        "/// A capability to act for one authenticated request. Fields cannot be supplied\n"
        "/// by HTTP callers, and authorization rechecks the live authoritative record.\n"
        "#[derive(Clone)]\n"
        "pub struct Principal {\n"
        "    digest: String,\n"
        "    token: Token,\n"
        "    authenticated_at: u64,\n"
        "}\n",
        "/// An affine capability to act for exactly one authenticated service request.\n"
        "/// It is crate-internal, non-cloneable and moved into one dispatcher invocation.\n"
        "pub(super) struct Principal {\n"
        "    digest: String,\n"
        "    token: Token,\n"
        "    request_time: Cell<u64>,\n"
        "}\n",
        "Principal shape",
    )
    text = replace_once(
        text,
        "impl Principal {\n"
        "    pub fn is_root(&self) -> bool {\n"
        "        self.token.root\n"
        "    }\n"
        "    pub fn policies(&self) -> &BTreeSet<String> {\n"
        "        &self.token.policies\n"
        "    }\n"
        "    pub fn consumed_use(&self) -> bool {\n"
        "        self.token.uses_remaining.is_some()\n"
        "    }\n"
        "}\n",
        "impl Principal {\n"
        "    pub(super) fn is_root(&self) -> bool {\n"
        "        self.token.root\n"
        "    }\n"
        "    pub(super) fn policies(&self) -> &BTreeSet<String> {\n"
        "        &self.token.policies\n"
        "    }\n"
        "    pub(super) fn consumed_use(&self) -> bool {\n"
        "        self.token.uses_remaining.is_some()\n"
        "    }\n"
        "    fn bind_request_time(&self, now: u64) -> Result<(), AuthError> {\n"
        "        if now < self.request_time.get() {\n"
        "            return Err(denied());\n"
        "        }\n"
        "        self.request_time.set(now);\n"
        "        Ok(())\n"
        "    }\n"
        "}\n",
        "Principal implementation",
    )
    text = replace_once(text, "    pub fn bootstrap(now: u64)", "    pub(super) fn bootstrap(now: u64)", "bootstrap visibility")
    text = replace_once(
        text,
        "    pub fn authenticate(&mut self, raw: &str, now: u64) -> Result<Principal, AuthError> {",
        "    pub(super) fn authenticate(&mut self, raw: &str, now: u64) -> Result<Principal, AuthError> {",
        "authenticate visibility",
    )
    text = replace_once(
        text,
        "        Ok(Principal {\n"
        "            digest: id,\n"
        "            token: token.clone(),\n"
        "            authenticated_at: now,\n"
        "        })",
        "        Ok(Principal {\n"
        "            digest: id,\n"
        "            token: token.clone(),\n"
        "            request_time: Cell::new(now),\n"
        "        })",
        "principal construction",
    )
    text = replace_once(
        text,
        "        let token = self.active_token(&principal.digest, principal.authenticated_at, false)?;",
        "        let token = self.active_token(&principal.digest, principal.request_time.get(), false)?;",
        "live request time",
    )
    text = replace_once(text, "    pub fn authorize(\n", "    fn authorize(\n", "authorize visibility")
    text = replace_once(
        text,
        "    fn permission(\n"
        "        &self,\n"
        "        principal: Option<&Principal>,\n"
        "        namespace: &str,\n"
        "        path: &str,\n"
        "        cap: &str,\n"
        "    ) -> Result<Principal, AuthError> {\n"
        "        let principal = principal.ok_or_else(denied)?;\n"
        "        self.authorize(principal, namespace, path, cap)?;\n"
        "        Ok(principal.clone())\n"
        "    }\n",
        "    pub(super) fn authorize_request(\n"
        "        &self,\n"
        "        principal: &Principal,\n"
        "        namespace: &str,\n"
        "        path: &str,\n"
        "        capability: &str,\n"
        "        now: u64,\n"
        "    ) -> Result<(), AuthError> {\n"
        "        principal.bind_request_time(now)?;\n"
        "        self.authorize(principal, namespace, path, capability)\n"
        "    }\n"
        "\n"
        "    fn permission<'a>(\n"
        "        &self,\n"
        "        principal: Option<&'a Principal>,\n"
        "        namespace: &str,\n"
        "        path: &str,\n"
        "        cap: &str,\n"
        "    ) -> Result<&'a Principal, AuthError> {\n"
        "        let principal = principal.ok_or_else(denied)?;\n"
        "        self.authorize(principal, namespace, path, cap)?;\n"
        "        Ok(principal)\n"
        "    }\n",
        "affine permission",
    )
    text = replace_once(text, "    pub fn handle(\n", "    pub(super) fn handle(\n", "handle visibility")
    text = replace_once(
        text,
        "        validate_namespace(namespace)?;\n"
        "        validate_path(path, false)?;\n"
        "        if path == \"auth/approle/login\" {",
        "        validate_namespace(namespace)?;\n"
        "        validate_path(path, false)?;\n"
        "        if let Some(principal) = principal {\n"
        "            principal.bind_request_time(now)?;\n"
        "        }\n"
        "        if path == \"auth/approle/login\" {",
        "handle request-time binding",
    )

    text = text.replace("self.authorize(&actor,", "self.authorize(actor,")
    text = text.replace("self.validate_assignment(&actor,", "self.validate_assignment(actor,")
    text = text.replace("self.create_token(\n                &actor,", "self.create_token(\n                actor,")

    for forbidden in (
        "#[derive(Clone)]\npub(super) struct Principal",
        "authenticated_at",
        "Ok(principal.clone())",
        "self.authorize(&actor,",
        "self.validate_assignment(&actor,",
        "self.create_token(\n                &actor,",
    ):
        if forbidden in text:
            raise SystemExit(f"auth repair left forbidden shape: {forbidden!r}")
    for required in (
        "pub(super) struct Principal",
        "request_time: Cell<u64>",
        "pub(super) fn authorize_request(",
        "principal.bind_request_time(now)?;",
        "Result<&'a Principal, AuthError>",
    ):
        if required not in text:
            raise SystemExit(f"auth repair missing required shape: {required!r}")
    write(path, text)


def materialize_service() -> None:
    path = "crates/heptabao-server/src/service.rs"
    text = read(path)
    text = replace_once(
        text,
        "        let response = Self::dispatch(\n"
        "            &mut admitted,\n"
        "            principal.as_ref(),\n"
        "            namespace,\n",
        "        let response = Self::dispatch(\n"
        "            &mut admitted,\n"
        "            principal,\n"
        "            namespace,\n",
        "owned dispatch call",
    )
    text = replace_once(
        text,
        "        principal: Option<&Principal>,\n"
        "        namespace: &str,\n"
        "        method: &str,\n"
        "        path: &str,\n"
        "        body: &Value,\n"
        "        now: u64,\n"
        "    ) -> Response {\n"
        "        // Each subsystem operates on its own candidate.",
        "        principal: Option<Principal>,\n"
        "        namespace: &str,\n"
        "        method: &str,\n"
        "        path: &str,\n"
        "        body: &Value,\n"
        "        now: u64,\n"
        "    ) -> Response {\n"
        "        let principal = principal.as_ref();\n"
        "        // Each subsystem operates on its own candidate.",
        "owned dispatch signature",
    )
    text = replace_once(
        text,
        "            if let Err(error) = state.auth.authorize(principal, namespace, path, \"read\") {",
        "            if let Err(error) = state\n"
        "                .auth\n"
        "                .authorize_request(principal, namespace, path, \"read\", now)\n"
        "            {",
        "leader authorization time",
    )
    text = replace_once(
        text,
        "            && let Err(error) = state.auth.authorize(principal, namespace, path, \"sudo\")",
        "            && let Err(error) = state\n"
        "                .auth\n"
        "                .authorize_request(principal, namespace, path, \"sudo\", now)",
        "mount sudo authorization time",
    )
    text = replace_once(
        text,
        "        if let Err(error) = state.auth.authorize(principal, namespace, path, capability) {",
        "        if let Err(error) = state\n"
        "            .auth\n"
        "            .authorize_request(principal, namespace, path, capability, now)\n"
        "        {",
        "engine authorization time",
    )
    if "Self::dispatch(\n            &mut admitted,\n            principal.as_ref()," in text:
        raise SystemExit("service still borrows the request principal into dispatch")
    if "principal: Option<Principal>" not in text:
        raise SystemExit("service dispatch does not own the request principal")
    write(path, text)


def materialize_rust_regression() -> None:
    path = "crates/heptabao-server/src/auth_tests.rs"
    text = read(path)
    marker = "fn request_principal_rechecks_live_time_after_finite_use_admission()"
    if marker in text:
        raise SystemExit("request principal regression already exists")
    addition = r'''

#[test]
fn request_principal_rechecks_live_time_after_finite_use_admission() {
    let (mut state, _, root) = setup();
    put_policy(
        &mut state,
        &root,
        "",
        "reader",
        json!(r#"path "secret/data/a" { capabilities = ["read"] }"#),
    );
    let raw = token(
        &mut state,
        &root,
        "",
        json!({"policies": ["reader"], "ttl": 2, "num_uses": 1}),
        100,
    );
    let actor = state.authenticate(&raw, 101).unwrap();

    // The admitted request has already paid its one use, so repeated layered
    // checks at the same request time remain valid inside that one dispatch.
    state
        .authorize_request(&actor, "", "secret/data/a", "read", 101)
        .unwrap();
    state
        .authorize_request(&actor, "", "secret/data/a", "read", 101)
        .unwrap();

    // The same affine value cannot be rebound to an earlier clock and cannot
    // authorize after the token expiry boundary. A new request also cannot
    // authenticate because the finite use was consumed.
    assert!(
        state
            .authorize_request(&actor, "", "secret/data/a", "read", 100)
            .is_err()
    );
    assert!(
        state
            .authorize_request(&actor, "", "secret/data/a", "read", 102)
            .is_err()
    );
    assert!(state.authenticate(&raw, 101).is_err());
}
'''
    write(path, text.rstrip() + addition + "\n")


def materialize_repository_guard() -> None:
    path = "tests/repository/test_auth_capability_boundary_v2_6.py"
    text = read(path)
    text = replace_once(
        text,
        "SERVICE_RS = SERVER / \"service.rs\"\n",
        "AUTH_RS = SERVER / \"auth.rs\"\nSERVICE_RS = SERVER / \"service.rs\"\n",
        "auth guard path",
    )
    insertion = '''    def test_request_principal_is_affine_and_dispatch_consumes_it(self) -> None:\n        auth = AUTH_RS.read_text(encoding="utf-8")\n        service = SERVICE_RS.read_text(encoding="utf-8")\n        self.assertRegex(auth, r"(?m)^pub\\(super\\) struct Principal \\{")\n        self.assertNotRegex(\n            auth,\n            r"#\\[derive\\([^]]*Clone[^]]*\\)\\]\\s*pub\\(super\\) struct Principal",\n        )\n        self.assertNotIn("authenticated_at", auth)\n        self.assertIn("request_time: Cell<u64>", auth)\n        self.assertRegex(service, r"principal:\\s*Option<Principal>")\n        self.assertRegex(\n            service,\n            r"Self::dispatch\\(\\s*&mut admitted,\\s*principal,",\n        )\n        self.assertNotRegex(\n            service,\n            r"Self::dispatch\\(\\s*&mut admitted,\\s*principal\\.as_ref\\(\\)",\n        )\n\n    def test_live_authorization_binds_the_service_decision_time(self) -> None:\n        auth = AUTH_RS.read_text(encoding="utf-8")\n        service = SERVICE_RS.read_text(encoding="utf-8")\n        compact_auth = re.sub(r"\\s+", "", auth)\n        compact_service = re.sub(r"\\s+", "", service)\n        self.assertIn("principal.bind_request_time(now)?;", auth)\n        self.assertIn(\n            "self.active_token(&principal.digest,principal.request_time.get(),false)?;",\n            compact_auth,\n        )\n        self.assertIn(\n            ".authorize_request(principal,namespace,path,capability,now)",\n            compact_service,\n        )\n\n'''
    text = replace_once(
        text,
        "    def test_request_capability_has_one_documented_owner(self) -> None:\n",
        insertion + "    def test_request_capability_has_one_documented_owner(self) -> None:\n",
        "repository affine tests",
    )
    text = replace_once(
        text,
        "            \"transaction-scoped\",\n"
        "            \"non-exported\",\n"
        "            \"finite-use\",\n",
        "            \"transaction-scoped\",\n"
        "            \"non-exported\",\n"
        "            \"non-cloneable\",\n"
        "            \"consumed by value\",\n"
        "            \"finite-use\",\n",
        "document markers",
    )
    write(path, text)


def materialize_boundary_document() -> None:
    path = "docs/security/HEPTABAO_REQUEST_CAPABILITY_BOUNDARY_V1.md"
    text = read(path)
    text = replace_once(
        text,
        "The service creates one transaction-scoped principal after request audit and before dispatch. It stores the finite-use decrement durably before the authorized operation proceeds. The principal remains a local value owned by that request invocation, is passed only by shared reference to the internal dispatcher, and is dropped before the public call returns. No public method accepts or returns it.",
        "The service creates one transaction-scoped principal after request audit and before dispatch. It stores the finite-use decrement durably before the authorized operation proceeds. The principal is a crate-internal, non-cloneable local value that is consumed by value by exactly one internal dispatcher invocation. Subsystems may borrow it only inside that invocation for layered checks, and it is dropped before the public call returns. No public method accepts or returns it.",
        "boundary ownership prose",
    )
    text = replace_once(
        text,
        "Internal authorization re-resolves the authoritative token record and parent chain. Revocation, token replacement, parent removal, namespace mismatch, accessor mismatch, and policy denial fail closed. The request time captured during authentication is the service decision time for that synchronous request; a later request must authenticate again against a fresh service time.",
        "Internal authorization re-resolves the authoritative token record and parent chain. Revocation, token replacement, parent removal, namespace mismatch, accessor mismatch, and policy denial fail closed. The dispatcher binds the current service decision time before every authorization path; clock rollback is rejected, expiry is evaluated against that bound time, and a later request must authenticate again to obtain a new affine principal.",
        "live authority prose",
    )
    text = replace_once(
        text,
        "3. No public `Service` method accepts or returns an authentication capability.\n"
        "4. Authentication state is serialized only as part of the encrypted durable service state; the request principal itself is never serialized.\n"
        "5. Public callers receive only `Response` values and cannot recover a principal from a response.",
        "3. No public `Service` method accepts or returns an authentication capability.\n"
        "4. `Principal` is crate-internal, non-cloneable, non-serializable, and the dispatcher consumes it by value.\n"
        "5. Authentication state is serialized only as part of the encrypted durable service state; the request principal itself is never serialized.\n"
        "6. Public callers receive only `Response` values and cannot recover a principal from a response.",
        "public invariant list",
    )
    text = replace_once(
        text,
        "Any future need to expose lower-level authentication must introduce a new affine, non-cloneable, non-serializable request capability that is consumed by one dispatcher call and bound to a fresh request identity and decision time. Re-exporting the current raw module is prohibited. Such a change requires hostile replay tests, an exact-head security review, and an explicit revision of this contract.",
        "The current internal principal is affine, non-cloneable and non-serializable, is consumed by one dispatcher call, and is rebound only to a monotonic service decision time. Any future lower-level authentication surface must preserve those properties and add a fresh request identity without re-exporting the raw module. Such a change requires hostile replay tests, an exact-head security review, and an explicit revision of this contract.",
        "evolution rule",
    )
    write(path, text)


def materialize_module_guide() -> None:
    path = "docs/modules/heptabao-server.md"
    text = read(path)
    heading = "## Affine request-principal closure"
    if heading in text:
        raise SystemExit("module guide already contains affine principal closure")
    addition = f'''\n\n{heading}\n\nThe authenticated request principal is crate-internal, non-cloneable and non-serializable. `Service` moves it into exactly one dispatcher invocation; internal authorization layers borrow it only during that invocation. The dispatcher binds a monotonic service decision time before authorization, so token and parent expiry are re-evaluated at the live request boundary while a finite-use request that has already durably paid its use may still perform layered checks inside that one dispatch. Repository guards and hostile Rust tests reject a borrowed dispatcher signature, a cloneable principal, stale authentication-time authorization and clock rollback. This source-level closure remains subject to exact-head independent review and grants no production authority.\n'''
    write(path, text.rstrip() + addition)


def main() -> int:
    materialize_auth()
    materialize_service()
    materialize_rust_regression()
    materialize_repository_guard()
    materialize_boundary_document()
    materialize_module_guide()
    print("PASS_HEPTABAO_AFFINE_REQUEST_PRINCIPAL_MATERIALIZATION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
