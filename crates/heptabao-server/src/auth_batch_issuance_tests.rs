// Test setup failures are assertions; this module is only compiled under cfg(test).
#![allow(clippy::unwrap_used)]
use super::*;

fn call(
    state: &mut AuthState,
    root: &Principal,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(root), "", "POST", path, &body, 100)?
        .ok_or_else(|| bad("missing route"))
}
fn setup() -> (AuthState, Principal) {
    let (mut state, raw) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate(&raw, 100).unwrap();
    call(
        &mut state,
        &root,
        "auth/userpass/users/alice",
        json!({"password":"batch password","token_ttl":60}),
    )
    .unwrap();
    (state, root)
}
fn login(state: &mut AuthState) -> AuthResponse {
    state
        .handle(
            None,
            "",
            "POST",
            "auth/userpass/login/alice",
            &json!({"password":"batch password"}),
            100,
        )
        .unwrap()
        .unwrap()
}
fn finish(state: &mut AuthState, response: &mut AuthResponse) {
    if response.login_identity.take().is_some() {
        state
            .bind_issued_entity(response, "", "userpass", "test-entity")
            .unwrap();
    }
    state.finish_pending_batch(response, "", 100).unwrap();
}

#[test]
fn batch_all_twelve_mount_user_combinations_seal_only_after_identity_without_backing_tokens() {
    let (baseline, root) = setup();
    for (mount, user, batch) in [
        ("default-service", "default", false),
        ("default-service", "service", false),
        ("default-service", "batch", true),
        ("default-batch", "default", true),
        ("default-batch", "service", false),
        ("default-batch", "batch", true),
        ("service", "default", false),
        ("service", "service", false),
        ("service", "batch", false),
        ("batch", "default", true),
        ("batch", "service", true),
        ("batch", "batch", true),
    ] {
        let mut state = baseline.clone();
        call(
            &mut state,
            &root,
            "sys/auth/userpass/tune",
            json!({"token_type":mount}),
        )
        .unwrap();
        call(
            &mut state,
            &root,
            "auth/userpass/users/alice",
            json!({"token_type":user}),
        )
        .unwrap();
        let count = state.tokens.len();
        let mut response = login(&mut state);
        assert_eq!(response.pending_batch.is_some(), batch, "{mount}/{user}");
        if batch {
            assert!(response.body["auth"].get("client_token").is_none());
            assert_eq!(state.tokens.len(), count);
        }
        finish(&mut state, &mut response);
        let raw = response.body["auth"]["client_token"].as_str().unwrap();
        assert_eq!(raw.starts_with("hvb."), batch);
        if batch {
            let claims = state
                .batch_authority
                .as_ref()
                .unwrap()
                .open(raw, "", 100)
                .unwrap();
            assert_eq!(claims.entity_id(), Some("test-entity"));
            assert_eq!(
                claims.metadata().get("username").map(String::as_str),
                Some("alice")
            );
            assert_eq!(state.tokens.len(), count);
        }
        state.validate_batch_issuance_state().unwrap();
    }
}

#[test]
fn batch_user_rejects_period_or_uses_atomically_but_forced_mount_discards_service_only_fields() {
    let (mut state, root) = setup();
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    for (body, message) in [
        (
            json!({"token_type":"batch","token_period":30}),
            "'token_type' cannot be 'batch' or 'default_batch' when set to generate periodic tokens",
        ),
        (
            json!({"token_type":"batch","token_num_uses":2}),
            "'token_type' cannot be 'batch' or 'default_batch' when set to generate tokens with limited use count",
        ),
        (
            json!({"token_type":"invalid"}),
            "invalid 'token_type' value",
        ),
    ] {
        let error = call(&mut state, &root, "auth/userpass/users/alice", body)
            .err()
            .unwrap();
        assert_eq!((error.status, error.message.as_str()), (400, message));
        assert_eq!(*before, serde_json::to_vec(&state).unwrap());
    }
    call(
        &mut state,
        &root,
        "auth/userpass/users/alice",
        json!({"token_period":30,"token_num_uses":2,"token_explicit_max_ttl":20}),
    )
    .unwrap();
    call(
        &mut state,
        &root,
        "sys/auth/userpass/tune",
        json!({"token_type":"batch"}),
    )
    .unwrap();
    let mut response = login(&mut state);
    finish(&mut state, &mut response);
    assert_eq!(response.body["auth"]["num_uses"], 0);
    assert_eq!(response.body["auth"]["renewable"], false);
    assert_eq!(response.body["auth"]["lease_duration"], 20);
    call(
        &mut state,
        &root,
        "sys/auth/userpass/tune",
        json!({"description":"kept"}),
    )
    .unwrap();
    assert_eq!(
        state.effective_auth_mounts("")["userpass"]
            .token_type
            .unwrap()
            .name(),
        "batch"
    );
    call(&mut state, &root, "sys/auth/ldap", json!({"type":"ldap"})).unwrap();
    assert_eq!(
        call(
            &mut state,
            &root,
            "sys/auth/ldap/tune",
            json!({"token_type":"batch"})
        )
        .err()
        .unwrap()
        .status,
        400
    );
}

#[test]
fn batch_token_api_child_has_parent_and_cidrs_but_orphan_has_neither_and_no_backing_row() {
    let (mut state, root) = setup();
    let parent_response = call(
        &mut state,
        &root,
        "auth/token/create",
        json!({"policies":["default"],"ttl":60}),
    )
    .unwrap();
    let parent_raw = parent_response.body["auth"]["client_token"]
        .as_str()
        .unwrap();
    let parent_id = hash(parent_raw);
    let parent = state.tokens.get_mut(&parent_id).unwrap();
    parent.bound_cidrs = vec!["127.0.0.1".into()];
    parent.entity_id = Some("test-entity".into());
    parent.policies.insert("batch-parent".into());
    call(
        &mut state,
        &root,
        "sys/policies/acl/batch-parent",
        json!({"policy":"path \"auth/token/*\" { capabilities = [\"read\",\"update\",\"sudo\"] }"}),
    )
    .unwrap();
    let mut actor = state
        .authenticate_from(parent_raw, 100, Some("127.0.0.1".parse().unwrap()))
        .unwrap();
    actor.bind_identity_policies(BTreeSet::new());
    let count = state.tokens.len();
    let mut child = call(
        &mut state,
        &actor,
        "auth/token/create",
        json!({"type":"batch","policies":["default"],"ttl":300}),
    )
    .unwrap();
    let mut orphan = call(
        &mut state,
        &actor,
        "auth/token/create-orphan",
        json!({"type":"batch","policies":["default"],"ttl":300}),
    )
    .unwrap();
    state.finish_pending_batch(&mut child, "", 100).unwrap();
    state.finish_pending_batch(&mut orphan, "", 100).unwrap();
    let c = state
        .batch_authority
        .as_ref()
        .unwrap()
        .open(
            child.body["auth"]["client_token"].as_str().unwrap(),
            "",
            100,
        )
        .unwrap();
    let o = state
        .batch_authority
        .as_ref()
        .unwrap()
        .open(
            orphan.body["auth"]["client_token"].as_str().unwrap(),
            "",
            100,
        )
        .unwrap();
    assert_eq!(c.parent(), Some(parent_id.as_str()));
    assert_eq!(c.entity_id(), Some("test-entity"));
    assert_eq!(c.bound_cidrs(), ["127.0.0.1"]);
    assert_eq!(c.expires_at(), 400);
    assert!(o.parent().is_none());
    assert!(o.entity_id().is_none());
    assert!(o.bound_cidrs().is_empty());
    assert_eq!(state.tokens.len(), count);
    state.revoke(&parent_id);
    assert!(state.check_batch_claims(&c, "", 101).is_err());
    assert!(state.check_batch_claims(&o, "", 101).is_ok());
}

#[test]
fn batch_authority_is_precreated_and_legacy_absence_is_preserved_until_explicit_publication() {
    let (mut state, root) = setup();
    assert!(state.has_batch_authority());
    state.batch_authority = None;
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let reopened: AuthState = serde_json::from_slice(&before).unwrap();
    assert!(!reopened.has_batch_authority());
    assert_eq!(*before, serde_json::to_vec(&reopened).unwrap());
    call(
        &mut state,
        &root,
        "auth/userpass/users/alice",
        json!({"token_type":"batch"}),
    )
    .unwrap();
    assert!(state.has_batch_issuance_state());
    assert!(!state.has_batch_authority());
    let mut response = login(&mut state);
    assert!(!state.has_batch_authority());
    finish(&mut state, &mut response);
    assert!(state.has_batch_authority());
    let reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    reopened.validate_batch_issuance_state().unwrap();
    let raw = response.body["auth"]["client_token"].as_str().unwrap();
    assert!(reopened.authenticate_read_only(raw, 101).unwrap().is_some());
}

#[test]
fn pending_batch_requires_identity_and_keeps_old_archive_key_authority_without_token_map() {
    let (mut state, root) = setup();
    let old_authority = state.batch_authority.clone().unwrap();
    call(
        &mut state,
        &root,
        "auth/userpass/users/alice",
        json!({"token_type":"batch","token_no_default_policy":true}),
    )
    .unwrap();
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut incomplete = login(&mut state);
    assert!(
        state
            .finish_pending_batch(&mut incomplete, "", 100)
            .is_err()
    );
    assert_eq!(*before, serde_json::to_vec(&state).unwrap());
    let mut response = login(&mut state);
    finish(&mut state, &mut response);
    let raw = response.body["auth"]["client_token"].as_str().unwrap();
    let claims = old_authority.open(raw, "", 101).unwrap();
    assert!(claims.policies().is_empty());
    assert!(response.body["auth"].get("token_policies").is_none());
    // Empty policies remain a real batch principal, not an administrative token.
    let mut actor = state.authenticate(raw, 101).unwrap();
    actor.bind_identity_policies(BTreeSet::new());
    assert_eq!(
        state
            .authorize_request(&actor, "", "auth/token/lookup-self", "read", 101)
            .err()
            .unwrap()
            .status,
        403
    );
    call(
        &mut state,
        &root,
        "auth/userpass/users/alice",
        json!({"token_type":null}),
    )
    .unwrap();
    assert_eq!(
        state
            .users_at(AuthScope {
                namespace: "",
                mount: "userpass"
            })
            .unwrap()["alice"]
            .token_type
            .unwrap()
            .name(),
        "default"
    );
    call(
        &mut state,
        &root,
        "sys/auth/userpass/tune",
        json!({"token_type":"batch"}),
    )
    .unwrap();
    call(
        &mut state,
        &root,
        "sys/auth/userpass",
        json!({"type":"userpass"}),
    )
    .unwrap();
    assert_eq!(
        state.effective_auth_mounts("")["userpass"]
            .token_type
            .unwrap()
            .name(),
        "batch"
    );
}

#[test]
fn batch_userpass_mfa_consumes_one_shared_counter_before_grant() {
    let (mut state, root) = setup();
    call(
        &mut state,
        &root,
        "auth/userpass/users/alice",
        json!({"token_type":"batch"}),
    )
    .unwrap();
    call(
        &mut state,
        &root,
        "auth/userpass/users/alice/mfa",
        json!({}),
    )
    .unwrap();
    let scope = AuthScope {
        namespace: "",
        mount: "userpass",
    };
    let secret = state.users_at(scope).unwrap()["alice"]
        .mfa
        .as_ref()
        .unwrap()
        .secret
        .clone();
    let code = String::from_utf8(totp_code(&secret, 100 / MFA_PERIOD_SECONDS).to_vec()).unwrap();
    let body = json!({"password":"batch password","totp_code":code});
    let mut response = state
        .handle(None, "", "POST", "auth/userpass/login/ALICE", &body, 100)
        .unwrap()
        .unwrap();
    finish(&mut state, &mut response);
    assert_eq!(response.body["auth"]["token_type"], "batch");
    assert_eq!(
        state
            .handle(None, "", "POST", "auth/userpass/login/alice", &body, 100)
            .err()
            .unwrap()
            .status,
        403
    );
    assert_eq!(
        state.users_at(scope).unwrap()["alice"]
            .mfa
            .as_ref()
            .unwrap()
            .last_accepted_counter,
        Some(100 / MFA_PERIOD_SECONDS)
    );
}
