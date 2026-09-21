// Test setup failures are assertions; this module is only compiled under cfg(test).
#![allow(clippy::unwrap_used)]
use super::*;
use std::net::IpAddr;

fn peer(last: u8) -> Option<IpAddr> {
    Some(IpAddr::from([127, 0, 0, last]))
}
fn claims() -> batch::BatchClaims {
    batch::BatchClaims {
        namespace: String::new(),
        policies: BTreeSet::from(["default".into()]),
        metadata: BTreeMap::from([("username".into(), "alice".into())]),
        display_name: "userpass-alice".into(),
        path: "auth/userpass/login/alice".into(),
        bound_cidrs: vec!["127.0.0.1".into()],
        issued_at: 100,
        expires_at: 400,
        parent: None,
        entity_id: None,
    }
}
fn seal(state: &mut AuthState, value: batch::BatchClaims) -> batch::BatchToken {
    if state.batch_authority.is_none() {
        state.batch_authority = Some(batch::BatchKeyAuthority::new(100).unwrap());
    }
    state
        .batch_authority
        .as_mut()
        .unwrap()
        .seal(value, 100)
        .unwrap()
}
fn call(
    state: &mut AuthState,
    actor: &Principal,
    path: &str,
    body: Value,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(actor), "", "POST", path, &body, now)?
        .ok_or_else(|| bad("test route missing"))
}
fn all_policy(state: &mut AuthState, root: &Principal) {
    call(state, root, "sys/policies/acl/batch-admin", json!({"policy":"path \"*\" { capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\",\"sudo\"] }"}), 100).unwrap();
}

#[test]
fn batch_authentication_is_read_only_and_requires_the_real_peer_without_service_backing() {
    let (mut state, _) = AuthState::bootstrap(100).unwrap();
    let raw = seal(&mut state, claims());
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let token_count = state.tokens.len();
    for _ in 0..3 {
        let actor = state
            .authenticate_read_only_from(raw.as_str(), 101, peer(1))
            .unwrap()
            .unwrap();
        assert!(!actor.is_root());
        assert!(!actor.consumed_use());
        assert!(actor.service_token().is_none());
        state
            .authorize_request(&actor, "", "auth/token/lookup-self", "read", 101)
            .unwrap();
        let actor = state.authenticate_from(raw.as_str(), 101, peer(1)).unwrap();
        assert!(state.check_principal(&actor, "wrong", 101).is_err());
    }
    assert!(state.authenticate_from(raw.as_str(), 101, peer(2)).is_err());
    assert!(
        state
            .authenticate_read_only_from(raw.as_str(), 101, None)
            .is_err()
    );
    assert!(state.authenticate_from(raw.as_str(), 400, peer(1)).is_err());
    assert!(
        state
            .authenticate_from(&format!("hvb.{}", "x".repeat(16 * 1024)), 101, peer(1))
            .is_err()
    );
    assert!(
        state
            .authenticate_from(&format!("hvs.{}", "x".repeat(253)), 101, peer(1))
            .is_err()
    );
    assert_eq!(state.tokens.len(), token_count);
    assert_eq!(*before, serde_json::to_vec(&state).unwrap());
}

#[test]
fn batch_target_lookup_and_capabilities_do_not_apply_target_cidrs_to_administrator() {
    let (mut state, raw_root) = AuthState::bootstrap(100).unwrap();
    let raw = seal(&mut state, claims());
    let root = state.authenticate_from(&raw_root, 101, peer(2)).unwrap();
    let response = call(
        &mut state,
        &root,
        "auth/token/lookup",
        json!({"token":raw.as_str()}),
        101,
    )
    .unwrap();
    let data = &response.body["data"];
    assert_eq!(data["type"], "batch");
    assert_eq!(data["accessor"], "");
    assert_eq!(data["ttl"], 299);
    assert_eq!(data["renewable"], false);
    assert_eq!(data["meta"], json!({"username":"alice"}));
    assert_eq!(data["display_name"], "userpass-alice");
    assert_eq!(data["path"], "auth/userpass/login/alice");
    assert_eq!(data["num_uses"], 0);
    assert!(data.get("period").is_none());
    let target = state
        .inspection_target(
            &root,
            "",
            "sys/capabilities",
            &json!({"token":raw.as_str()}),
            101,
        )
        .unwrap();
    assert_eq!(
        state
            .inspect_capabilities(
                "",
                "auth/token/lookup-self",
                &target,
                &BTreeSet::new(),
                false
            )
            .unwrap(),
        vec!["read"]
    );
    assert!(
        state
            .inspection_target(
                &root,
                "other",
                "sys/capabilities",
                &json!({"token":raw.as_str()}),
                101
            )
            .is_err()
    );
    all_policy(&mut state, &root);
    let mut allowed = claims();
    allowed.policies = BTreeSet::from(["batch-admin".into()]);
    let fallback = seal(&mut state, allowed);
    let actor = state
        .authenticate_from(fallback.as_str(), 101, peer(1))
        .unwrap();
    let self_lookup = state
        .handle(
            Some(&actor),
            "",
            "GET",
            "auth/token/lookup-self",
            &json!({}),
            101,
        )
        .unwrap()
        .unwrap();
    assert_eq!(self_lookup.body["data"]["type"], "batch");
    let self_target = state
        .inspection_target(&actor, "", "sys/capabilities-self", &json!({}), 101)
        .unwrap();
    assert!(
        state
            .inspect_capabilities("", "secret/a", &self_target, &BTreeSet::new(), false)
            .unwrap()
            .contains(&"read")
    );
    for body in [json!({}), json!({"token":null}), json!({"token":""})] {
        let response = call(&mut state, &actor, "auth/token/lookup", body, 101).unwrap();
        assert_eq!(response.body["data"]["type"], "batch");
    }
}

#[test]
fn batch_acl_denial_precedes_kind_errors_and_provider_renewal_is_never_prepared() {
    let (mut state, raw_root) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate(&raw_root, 100).unwrap();
    all_policy(&mut state, &root);
    let mut empty = claims();
    empty.policies.clear();
    let denied_raw = seal(&mut state, empty);
    let denied_actor = state
        .authenticate_from(denied_raw.as_str(), 101, peer(1))
        .unwrap();
    let mut allowed = claims();
    allowed.policies = BTreeSet::from(["batch-admin".into()]);
    let allowed_raw = seal(&mut state, allowed);
    let allowed_actor = state
        .authenticate_from(allowed_raw.as_str(), 101, peer(1))
        .unwrap();
    for path in [
        "auth/token/renew-self",
        "auth/token/revoke-self",
        "auth/token/create",
        "auth/token/create-orphan",
    ] {
        assert_eq!(
            call(&mut state, &denied_actor, path, json!({}), 101)
                .err()
                .unwrap()
                .status,
            403,
            "{path}"
        );
        assert_eq!(
            call(&mut state, &allowed_actor, path, json!({}), 101)
                .err()
                .unwrap()
                .status,
            400,
            "{path}"
        );
    }
    assert_eq!(
        state
            .prepare_provider_renewal(
                Some(&allowed_actor),
                "",
                "POST",
                "auth/token/renew-self",
                &json!({}),
                101
            )
            .err()
            .unwrap()
            .status,
        400
    );
    for path in ["auth/token/renew", "auth/token/revoke"] {
        assert_eq!(
            call(
                &mut state,
                &root,
                path,
                json!({"token":allowed_raw.as_str()}),
                101
            )
            .err()
            .unwrap()
            .status,
            400
        );
    }
    assert_eq!(
        state
            .prepare_provider_renewal(
                Some(&root),
                "",
                "POST",
                "auth/token/renew",
                &json!({"token":allowed_raw.as_str()}),
                101
            )
            .err()
            .unwrap()
            .status,
        400
    );
    let remaining = state.tokens.len();
    assert_eq!(
        call(
            &mut state,
            &root,
            "auth/token/create",
            json!({"type":"batch"}),
            101
        )
        .err()
        .unwrap()
        .status,
        400
    );
    assert_eq!(state.tokens.len(), remaining); // Root policy cannot be put in a batch grant.
}

#[test]
fn existing_batch_principal_and_lease_projection_recheck_parent_ancestors_and_authority() {
    let (mut state, raw_root) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate(&raw_root, 100).unwrap();
    let parent = call(
        &mut state,
        &root,
        "auth/token/create",
        json!({"policies":["default"],"ttl":150}),
        100,
    )
    .unwrap();
    let parent_raw = parent.body["auth"]["client_token"].as_str().unwrap();
    let mut bound = claims();
    bound.parent = Some(hash(parent_raw));
    let raw = seal(&mut state, bound);
    let actor = state.authenticate_from(raw.as_str(), 101, peer(1)).unwrap();
    let verified = state
        .batch_authority
        .as_ref()
        .unwrap()
        .open(raw.as_str(), "", 101)
        .unwrap();
    let owner = LeaseOwner::from_batch(&verified);
    let resolved = state.resolve_lease_owner(&owner, "", 101).unwrap();
    assert_eq!(resolved.expires_at, Some(400));
    assert!(resolved.owner.same_credential(&owner));
    assert!(resolved.entity_id.is_none());
    let issuer = state.typed_lease_issuer(&actor, "", 101).unwrap();
    assert!(issuer.owner.batch_claims().is_some());
    assert!(issuer.owner.service_digest().is_none());
    state.revoke(&hash(parent_raw));
    assert!(state.check_principal(&actor, "", 102).is_err());
    assert!(state.resolve_lease_owner(&owner, "", 102).is_none());
    assert!(state.authenticate_from(raw.as_str(), 102, peer(1)).is_err());
    let orphan = seal(&mut state, claims());
    let orphan_actor = state
        .authenticate_from(orphan.as_str(), 102, peer(1))
        .unwrap();
    state.batch_authority = Some(batch::BatchKeyAuthority::new(102).unwrap());
    assert!(state.check_principal(&orphan_actor, "", 102).is_err());
}

#[test]
fn batch_entity_requires_request_identity_projection_and_uses_current_acl_documents() {
    let (mut state, raw_root) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate(&raw_root, 100).unwrap();
    all_policy(&mut state, &root);
    let mut value = claims();
    value.entity_id = Some("entity-test".into());
    value.policies.clear();
    let raw = seal(&mut state, value);
    let mut actor = state.authenticate_from(raw.as_str(), 101, peer(1)).unwrap();
    assert!(
        state
            .authorize_request(&actor, "", "secret/a", "read", 101)
            .is_err()
    );
    actor.bind_identity_policies(BTreeSet::from(["batch-admin".into()]));
    state
        .authorize_request(&actor, "", "secret/a", "read", 101)
        .unwrap();
    call(
        &mut state,
        &root,
        "sys/policies/acl/batch-admin",
        json!({"policy":"path \"secret/*\" { capabilities = [\"deny\"] }"}),
        102,
    )
    .unwrap();
    assert!(
        state
            .authorize_request(&actor, "", "secret/a", "read", 102)
            .is_err()
    );
}

#[test]
fn batch_authority_and_credentials_reopen_without_migrating_legacy_or_creating_tokens() {
    let (mut state, _) = AuthState::bootstrap(100).unwrap();
    state.batch_authority = None; // A real pre-batch persisted AuthState shape.
    let old = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert!(
        serde_json::from_slice::<Value>(&old)
            .unwrap()
            .get("batch_authority")
            .is_none()
    );
    let legacy: AuthState = serde_json::from_slice(&old).unwrap();
    assert!(!legacy.has_batch_authority());
    assert_eq!(*old, serde_json::to_vec(&legacy).unwrap());
    let raw = seal(&mut state, claims());
    let bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let reopened: AuthState = serde_json::from_slice(&bytes).unwrap();
    reopened.validate_batch_authority().unwrap();
    assert!(reopened.has_batch_authority());
    let actor = reopened
        .authenticate_read_only_from(raw.as_str(), 101, peer(1))
        .unwrap()
        .unwrap();
    reopened
        .authorize_request(&actor, "", "auth/token/lookup-self", "read", 101)
        .unwrap();
    assert_eq!(state.tokens.len(), reopened.tokens.len());
    assert_eq!(*bytes, serde_json::to_vec(&reopened).unwrap());
}

#[test]
fn batch_actor_can_use_a_service_wrapper_without_ever_becoming_that_wrapper() {
    let (mut state, raw_root) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate(&raw_root, 100).unwrap();
    all_policy(&mut state, &root);
    let mut value = claims();
    value.policies = BTreeSet::from(["batch-admin".into()]);
    let raw = seal(&mut state, value);
    let actor = state.authenticate_from(raw.as_str(), 101, peer(1)).unwrap();
    let wrap = state
        .wrap_response("", "test", 30, &json!({"data":{"value":"test-only"}}), 101)
        .unwrap();
    let wrapper = wrap.body["wrap_info"]["token"].as_str().unwrap();
    let result = call(
        &mut state,
        &actor,
        "sys/wrapping/unwrap",
        json!({"token":wrapper}),
        102,
    )
    .unwrap();
    assert_eq!(result.body["data"]["value"], "test-only");
    assert!(
        call(
            &mut state,
            &actor,
            "sys/wrapping/unwrap",
            json!({"token":wrapper}),
            102
        )
        .is_err()
    );
    state
        .authorize_request(&actor, "", "secret/a", "read", 102)
        .unwrap();
}

#[test]
fn typed_principal_keeps_the_service_final_use_capability_without_reopening_admission() {
    let (mut state, raw_root) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate(&raw_root, 100).unwrap();
    let issued = call(
        &mut state,
        &root,
        "auth/token/create",
        json!({"policies":["default"],"num_uses":1,"ttl":60}),
        100,
    )
    .unwrap();
    let raw = issued.body["auth"]["client_token"].as_str().unwrap();
    assert!(
        state
            .authenticate_read_only_from(raw, 101, peer(1))
            .unwrap()
            .is_none()
    );
    let actor = state.authenticate_from(raw, 101, peer(1)).unwrap();
    assert!(actor.consumed_use());
    assert_eq!(actor.service_token().unwrap().uses_remaining, Some(0));
    state
        .authorize_request(&actor, "", "auth/token/lookup-self", "read", 101)
        .unwrap();
    let response = state
        .handle(
            Some(&actor),
            "",
            "GET",
            "auth/token/lookup-self",
            &json!({}),
            101,
        )
        .unwrap()
        .unwrap();
    assert_eq!(response.body["data"]["type"], "service");
    assert!(state.authenticate_from(raw, 101, peer(1)).is_err());
}

#[test]
fn batch_cubbyhole_existence_checks_precede_write_acl_but_other_operations_keep_acl() {
    let (mut state, root_raw) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate(&root_raw, 100).unwrap();
    for (name, capabilities) in [
        ("create-only", vec!["create"]),
        ("update-only", vec!["update"]),
        ("read-only", vec!["read"]),
        ("unrelated", vec![]),
        ("empty", vec![]),
    ] {
        if !capabilities.is_empty() {
            let source = format!(
                "path \"cubbyhole/*\" {{ capabilities = {} }}",
                serde_json::to_string(&capabilities).unwrap()
            );
            call(
                &mut state,
                &root,
                &format!("sys/policies/acl/{name}"),
                json!({"policy":source}),
                100,
            )
            .unwrap();
        }
        let mut value = claims();
        value.policies = if name == "empty" {
            BTreeSet::new()
        } else {
            BTreeSet::from([name.into()])
        };
        let raw = seal(&mut state, value);
        let actor = state.authenticate_from(raw.as_str(), 101, peer(1)).unwrap();
        for method in ["POST", "PUT", "GET", "LIST", "DELETE"] {
            let result = state.handle(
                Some(&actor),
                "",
                method,
                "cubbyhole/test",
                &json!({"a":1}),
                101,
            );
            let expected =
                if matches!(method, "POST" | "PUT") || method == "GET" && name == "read-only" {
                    400
                } else {
                    403
                };
            assert_eq!(result.err().unwrap().status, expected, "{name}/{method}");
        }
    }
}

#[test]
fn batch_revoke_orphan_and_empty_accessor_keep_token_api_authorization_order() {
    let (mut state, root_raw) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate(&root_raw, 100).unwrap();
    let mut value = claims();
    value.policies.clear();
    let raw = seal(&mut state, value);
    let actor = state.authenticate_from(raw.as_str(), 101, peer(1)).unwrap();
    assert_eq!(
        call(
            &mut state,
            &actor,
            "auth/token/revoke-orphan",
            json!({"token":raw.as_str()}),
            101
        )
        .err()
        .unwrap()
        .status,
        403
    );
    assert_eq!(
        call(
            &mut state,
            &root,
            "auth/token/revoke-orphan",
            json!({"token":raw.as_str()}),
            101
        )
        .err()
        .unwrap()
        .status,
        400
    );
    for route in ["lookup-accessor", "renew-accessor", "revoke-accessor"] {
        assert_eq!(
            call(
                &mut state,
                &root,
                &format!("auth/token/{route}"),
                json!({"accessor":""}),
                101
            )
            .err()
            .unwrap()
            .status,
            400
        );
    }
}
