#!/usr/bin/env python3
"""Materialize the affine, live-time request-principal repair.

The transformer is intentionally exact-source and fail-closed.  It is executed
from a detached checkout of the reviewed V2.4 candidate and is not retained in
the resulting product commit.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path.cwd()


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def regex_once(text: str, pattern: str, replacement: str, label: str) -> str:
    result, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE | re.DOTALL)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return result


def append_now_to_calls(text: str, old_name: str, new_name: str, minimum: int) -> str:
    pattern = rf"self\.{re.escape(old_name)}\((?P<args>.*?)\)\?;"

    def replacement(match: re.Match[str]) -> str:
        args = match.group("args").rstrip()
        separator = "\n            " if args.endswith(",") else ", "
        return f"self.{new_name}({args}{separator}now)?;"

    result, count = re.subn(pattern, replacement, text, flags=re.DOTALL)
    if count < minimum:
        raise SystemExit(f"{old_name} call closure: expected at least {minimum}, found {count}")
    return result


def materialize_auth() -> None:
    path = "crates/heptabao-server/src/auth.rs"
    text = read(path)

    text = replace_once(
        text,
        "//! Every caller must transact a clone and durably commit authentication use-count\n"
        "//! changes before returning either successful data or a handler error.\n",
        "//! Every public service request owns one affine principal and durably commits any\n"
        "//! finite-use decrement before dispatch. Raw authorization remains crate-internal.\n",
        "auth module contract",
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
        "/// An affine capability owned by exactly one service dispatcher invocation.\n"
        "/// It is non-cloneable, non-serializable and never crosses the public API.\n"
        "pub(super) struct Principal {\n"
        "    digest: String,\n"
        "    token: Token,\n"
        "    request_time: u64,\n"
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
        "    fn policies(&self) -> &BTreeSet<String> {\n"
        "        &self.token.policies\n"
        "    }\n"
        "    pub(super) fn consumed_use(&self) -> bool {\n"
        "        self.token.uses_remaining.is_some()\n"
        "    }\n"
        "}\n",
        "Principal methods",
    )
    text = replace_once(text, "    pub fn bootstrap(now: u64)", "    pub(super) fn bootstrap(now: u64)", "bootstrap visibility")
    text = replace_once(
        text,
        "    pub fn authenticate(&mut self, raw: &str, now: u64) -> Result<Principal, AuthError> {",
        "    pub(super) fn authenticate(&mut self, raw: &str, now: u64) -> Result<Principal, AuthError> {",
        "authenticate visibility",
    )
    text = replace_once(text, "            authenticated_at: now,", "            request_time: now,", "principal request time")
    text = replace_once(
        text,
        "    fn check_principal<'a>(\n"
        "        &'a self,\n"
        "        principal: &Principal,\n"
        "        namespace: &str,\n"
        "    ) -> Result<&'a Token, AuthError> {",
        "    fn check_principal<'a>(\n"
        "        &'a self,\n"
        "        principal: &Principal,\n"
        "        namespace: &str,\n"
        "        now: u64,\n"
        "    ) -> Result<&'a Token, AuthError> {",
        "live check signature",
    )
    text = replace_once(
        text,
        "        let token = self.active_token(&principal.digest, principal.authenticated_at, false)?;",
        "        let token = self.active_token(&principal.digest, now, false)?;",
        "live check timestamp",
    )
    text = replace_once(
        text,
        "    pub fn authorize(\n"
        "        &self,\n"
        "        principal: &Principal,\n"
        "        namespace: &str,\n"
        "        path: &str,\n"
        "        capability: &str,\n"
        "    ) -> Result<(), AuthError> {",
        "    fn authorize_request(\n"
        "        &self,\n"
        "        principal: &Principal,\n"
        "        namespace: &str,\n"
        "        path: &str,\n"
        "        capability: &str,\n"
        "        now: u64,\n"
        "    ) -> Result<(), AuthError> {",
        "authorization surface",
    )
    text = replace_once(
        text,
        "        let token = self.check_principal(principal, namespace)?;",
        "        let token = self.check_principal(principal, namespace, now)?;",
        "authorization live check",
    )

    test_wrapper = '''    #[cfg(test)]
    fn authorize_for_unit_test(
        &self,
        principal: &Principal,
        namespace: &str,
        path: &str,
        capability: &str,
    ) -> Result<(), AuthError> {
        self.authorize_request(
            principal,
            namespace,
            path,
            capability,
            principal.request_time,
        )
    }

'''
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
        test_wrapper
        + "    fn permission<'principal>(\n"
        "        &self,\n"
        "        principal: Option<&'principal Principal>,\n"
        "        namespace: &str,\n"
        "        path: &str,\n"
        "        cap: &str,\n"
        "        now: u64,\n"
        "    ) -> Result<&'principal Principal, AuthError> {\n"
        "        let principal = principal.ok_or_else(denied)?;\n"
        "        self.authorize_request(principal, namespace, path, cap, now)?;\n"
        "        Ok(principal)\n"
        "    }\n",
        "affine permission",
    )
    text = replace_once(text, "    pub fn handle(\n", "    pub(super) fn handle(\n", "handle visibility")

    text = replace_once(
        text,
        "            return self\n"
        "                .policy_route(principal, namespace, method, path, body)\n"
        "                .map(Some);",
        "            return self\n"
        "                .policy_route(principal, namespace, method, path, body, now)\n"
        "                .map(Some);",
        "policy route call",
    )
    text = replace_once(
        text,
        "            return self\n"
        "                .user_route(principal, namespace, method, path, body)\n"
        "                .map(Some);",
        "            return self\n"
        "                .user_route(principal, namespace, method, path, body, now)\n"
        "                .map(Some);",
        "user route call",
    )
    text = replace_once(
        text,
        "    fn policy_route(\n"
        "        &mut self,\n"
        "        principal: Option<&Principal>,\n"
        "        namespace: &str,\n"
        "        method: &str,\n"
        "        path: &str,\n"
        "        body: &Value,\n"
        "    ) -> Result<AuthResponse, AuthError> {",
        "    fn policy_route(\n"
        "        &mut self,\n"
        "        principal: Option<&Principal>,\n"
        "        namespace: &str,\n"
        "        method: &str,\n"
        "        path: &str,\n"
        "        body: &Value,\n"
        "        now: u64,\n"
        "    ) -> Result<AuthResponse, AuthError> {",
        "policy route time",
    )
    text = replace_once(
        text,
        "    fn user_route(\n"
        "        &mut self,\n"
        "        principal: Option<&Principal>,\n"
        "        namespace: &str,\n"
        "        method: &str,\n"
        "        path: &str,\n"
        "        body: &Value,\n"
        "    ) -> Result<AuthResponse, AuthError> {",
        "    fn user_route(\n"
        "        &mut self,\n"
        "        principal: Option<&Principal>,\n"
        "        namespace: &str,\n"
        "        method: &str,\n"
        "        path: &str,\n"
        "        body: &Value,\n"
        "        now: u64,\n"
        "    ) -> Result<AuthResponse, AuthError> {",
        "user route time",
    )

    # All production authorization and permission decisions now consume the
    # service request's explicit decision time. Calls are intentionally simple
    # and terminate in `?;`, so this transformation remains fail-closed.
    text = append_now_to_calls(text, "authorize", "authorize_request", 4)
    text = append_now_to_calls(text, "permission", "permission", 5)
    text = replace_once(
        text,
        "        let parent = self.check_principal(actor, namespace)?.clone();",
        "        let parent = self.check_principal(actor, namespace, now)?.clone();",
        "token parent live check",
    )
    text = text.replace("self.validate_assignment(&actor,", "self.validate_assignment(actor,")
    text = text.replace("self.create_token(\n                &actor,", "self.create_token(\n                actor,")

    for forbidden in (
        "#[derive(Clone)]\npub(super) struct Principal",
        "authenticated_at",
        "Ok(principal.clone())",
        "pub fn authenticate(",
        "pub fn authorize(",
        "self.authorize(",
        "self.check_principal(actor, namespace)?",
    ):
        if forbidden in text:
            raise SystemExit(f"auth repair left forbidden shape: {forbidden!r}")
    for required in (
        "pub(super) struct Principal",
        "request_time: u64",
        "fn authorize_request(",
        "self.active_token(&principal.digest, now, false)?",
        "Result<&'principal Principal, AuthError>",
        "#[cfg(test)]\n    fn authorize_for_unit_test(",
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
        "        // Ownership of the affine principal is consumed at this single\n"
        "        // dispatcher boundary. Internal layers borrow it only here.\n"
        "        let principal = principal.as_ref();\n"
        "        // Each subsystem operates on its own candidate.",
        "owned dispatch signature",
    )

    pattern = r"state\.auth\.authorize\((?P<args>.*?)\)"

    def replacement(match: re.Match[str]) -> str:
        args = match.group("args").rstrip()
        separator = "\n                    " if args.endswith(",") else ", "
        return f"state.auth.authorize_request({args}{separator}now)"

    text, count = re.subn(pattern, replacement, text, flags=re.DOTALL)
    if count != 3:
        raise SystemExit(f"service live authorization closure: expected 3 calls, found {count}")

    if "Self::dispatch(\n            &mut admitted,\n            principal.as_ref()," in text:
        raise SystemExit("service still borrows the principal into dispatch")
    if "principal: Option<Principal>" not in text:
        raise SystemExit("service dispatcher does not own the principal")
    if text.count("authorize_request(") != 3:
        raise SystemExit("service current-time authorization count changed")
    write(path, text)


def materialize_rust_tests() -> None:
    path = "crates/heptabao-server/src/auth_tests.rs"
    text = read(path)
    text, count = re.subn(r"\.authorize\(", ".authorize_for_unit_test(", text)
    if count < 8:
        raise SystemExit(f"unit authorization call migration: expected at least 8, found {count}")

    marker = "fn affine_request_principal_uses_live_subject_and_parent_time()"
    if marker in text:
        raise SystemExit("affine request regression already exists")
    addition = r'''

#[test]
fn affine_request_principal_uses_live_subject_and_parent_time() {
    let (mut state, _, root) = setup();
    put_policy(
        &mut state,
        &root,
        "",
        "reader",
        json!(r#"path "secret/data/a" { capabilities = ["read"] }"#),
    );
    let one_use = token(
        &mut state,
        &root,
        "",
        json!({"policies": ["reader"], "ttl": 2, "num_uses": 1}),
        100,
    );
    let admitted = state.authenticate(&one_use, 101).unwrap();
    state
        .authorize_request(&admitted, "", "secret/data/a", "read", 101)
        .unwrap();
    assert!(
        state
            .authorize_request(&admitted, "", "secret/data/a", "read", 102)
            .is_err()
    );
    assert!(state.authenticate(&one_use, 101).is_err());

    put_policy(
        &mut state,
        &root,
        "",
        "issuer",
        json!(r#"path "auth/token/create" { capabilities = ["update"] }"#),
    );
    let parent_raw = token(
        &mut state,
        &root,
        "",
        json!({"policies": ["issuer", "reader"], "ttl": 3}),
        200,
    );
    let parent = state.authenticate(&parent_raw, 200).unwrap();
    let child_raw = token(
        &mut state,
        &parent,
        "",
        json!({"policies": ["reader"], "ttl": 100}),
        201,
    );
    let child = state.authenticate(&child_raw, 202).unwrap();
    state
        .authorize_request(&child, "", "secret/data/a", "read", 202)
        .unwrap();
    assert!(
        state
            .authorize_request(&child, "", "secret/data/a", "read", 203)
            .is_err()
    );

    let policy_bound_raw = token(
        &mut state,
        &root,
        "",
        json!({"policies": ["reader"]}),
        300,
    );
    let policy_bound = state.authenticate(&policy_bound_raw, 300).unwrap();
    state
        .authorize_request(&policy_bound, "", "secret/data/a", "read", 300)
        .unwrap();
    call(
        &mut state,
        &root,
        "",
        "PUT",
        "sys/policies/acl/reader",
        json!({"policy": r#"path "secret/data/a" { capabilities = ["deny"] }"#}),
        301,
    );
    assert!(
        state
            .authorize_request(&policy_bound, "", "secret/data/a", "read", 301)
            .is_err()
    );

    put_policy(
        &mut state,
        &root,
        "",
        "fresh-reader",
        json!(r#"path "secret/data/a" { capabilities = ["read"] }"#),
    );
    let fresh_raw = token(
        &mut state,
        &root,
        "",
        json!({"policies": ["fresh-reader"]}),
        302,
    );
    let fresh = state.authenticate(&fresh_raw, 302).unwrap();
    state
        .authorize_request(&fresh, "", "secret/data/a", "read", 302)
        .unwrap();
    state.tokens.get_mut(&hash(&fresh_raw)).unwrap().accessor = "replacement".into();
    assert!(
        state
            .authorize_request(&fresh, "", "secret/data/a", "read", 302)
            .is_err()
    );
}
'''
    write(path, text.rstrip() + addition + "\n")


def materialize_repository_guard() -> None:
    path = "tests/repository/test_auth_capability_boundary_v2_6.py"
    text = read(path)
    text = replace_once(
        text,
        "LIB_RS = SERVER / \"lib.rs\"\nSERVICE_RS = SERVER / \"service.rs\"\n",
        "LIB_RS = SERVER / \"lib.rs\"\nAUTH_RS = SERVER / \"auth.rs\"\nSERVICE_RS = SERVER / \"service.rs\"\n",
        "auth source path",
    )
    insertion = '''    def test_principal_is_affine_and_raw_authority_is_internal(self) -> None:\n        text = AUTH_RS.read_text(encoding="utf-8")\n        self.assertRegex(text, r"(?m)^pub\\(super\\) struct Principal \\{")\n        self.assertNotRegex(\n            text,\n            r"#\\[derive\\([^]]*Clone[^]]*\\)\\]\\s*pub\\(super\\) struct Principal",\n        )\n        self.assertNotIn("authenticated_at", text)\n        self.assertIn("request_time: u64", text)\n        self.assertRegex(text, r"(?m)^\\s*pub\\(super\\) fn authenticate\\(")\n        self.assertNotRegex(text, r"(?m)^\\s*pub fn authenticate\\(")\n        self.assertRegex(text, r"(?m)^\\s*fn authorize_request\\(")\n        self.assertNotRegex(text, r"(?m)^\\s*pub fn authorize\\(")\n        self.assertNotIn("Ok(principal.clone())", text)\n\n    def test_dispatch_consumes_one_principal_and_forwards_live_time(self) -> None:\n        text = SERVICE_RS.read_text(encoding="utf-8")\n        compact = re.sub(r"\\s+", "", text)\n        self.assertRegex(text, r"principal:\\s*Option<Principal>")\n        self.assertRegex(text, r"Self::dispatch\\(\\s*&mut admitted,\\s*principal,")\n        self.assertNotRegex(\n            text,\n            r"Self::dispatch\\(\\s*&mut admitted,\\s*principal\\.as_ref\\(\\)",\n        )\n        self.assertEqual(3, compact.count(".authorize_request("))\n        self.assertIn(",now)", compact)\n\n'''
    text = replace_once(
        text,
        "    def test_request_capability_has_one_documented_owner(self) -> None:\n",
        insertion + "    def test_request_capability_has_one_documented_owner(self) -> None:\n",
        "affine repository guards",
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
        "            \"live decision time\",\n"
        "            \"finite-use\",\n",
        "boundary document markers",
    )
    write(path, text)


def materialize_boundary_document() -> None:
    path = "docs/security/HEPTABAO_REQUEST_CAPABILITY_BOUNDARY_V1.md"
    text = read(path)
    text = replace_once(
        text,
        "The service creates one transaction-scoped principal after request audit and before dispatch. It stores the finite-use decrement durably before the authorized operation proceeds. The principal remains a local value owned by that request invocation, is passed only by shared reference to the internal dispatcher, and is dropped before the public call returns. No public method accepts or returns it.",
        "The service creates one transaction-scoped principal after request audit and before dispatch. It stores the finite-use decrement durably before the authorized operation proceeds. The principal is non-cloneable and is consumed by value by exactly one internal dispatcher invocation; subsystems borrow it only inside that invocation. It is dropped before the public call returns, and no public method accepts or returns it.",
        "boundary ownership",
    )
    text = replace_once(
        text,
        "Internal authorization re-resolves the authoritative token record and parent chain. Revocation, token replacement, parent removal, namespace mismatch, accessor mismatch, and policy denial fail closed. The request time captured during authentication is the service decision time for that synchronous request; a later request must authenticate again against a fresh service time.",
        "Internal authorization re-resolves the authoritative token record and parent chain at the live decision time supplied by the service dispatcher. Revocation, token replacement, parent removal or expiry, namespace mismatch, accessor mismatch, and policy denial fail closed. A later request must authenticate again and cannot recover or replay the consumed principal.",
        "live authority prose",
    )
    text = replace_once(
        text,
        "3. No public `Service` method accepts or returns an authentication capability.\n"
        "4. Authentication state is serialized only as part of the encrypted durable service state; the request principal itself is never serialized.\n"
        "5. Public callers receive only `Response` values and cannot recover a principal from a response.",
        "3. No public `Service` method accepts or returns an authentication capability.\n"
        "4. `Principal` is crate-internal, non-cloneable, non-serializable, and consumed by value by one dispatcher call.\n"
        "5. Every production authorization path receives the current request's live decision time.\n"
        "6. Authentication state is serialized only as part of the encrypted durable service state; the request principal itself is never serialized.\n"
        "7. Public callers receive only `Response` values and cannot recover a principal from a response.",
        "public invariant",
    )
    write(path, text)


def materialize_module_guide() -> None:
    path = "docs/modules/heptabao-server.md"
    text = read(path)
    heading = "## Affine request-principal closure"
    if heading in text:
        raise SystemExit("module guide already contains affine principal closure")
    addition = f'''\n\n{heading}\n\nThe authenticated request principal is crate-internal, non-cloneable and non-serializable. `Service` moves it into exactly one dispatcher invocation; internal authorization layers borrow it only during that invocation. Every production authorization decision receives the current service request's live decision time, so subject and parent expiry, revocation, token replacement and policy replacement are re-evaluated without charging an unrelated fresh token use. Repository guards and hostile Rust tests reject a borrowed dispatcher signature, stale authentication-time authorization and a cloneable principal. This source-level closure remains subject to exact-head independent review and grants no production authority.\n'''
    write(path, text.rstrip() + addition)


def main() -> int:
    materialize_auth()
    materialize_service()
    materialize_rust_tests()
    materialize_repository_guard()
    materialize_boundary_document()
    materialize_module_guide()
    print("PASS_HEPTABAO_AFFINE_REQUEST_PRINCIPAL_MATERIALIZATION_V2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
