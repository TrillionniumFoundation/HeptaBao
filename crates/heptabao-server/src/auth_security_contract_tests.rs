#![allow(clippy::unwrap_used)]
use super::tests::mount_auth;
use super::*;

fn setup() -> (AuthState, Principal) {
    let (mut state, raw) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate(&raw, 100).unwrap();
    mount_auth(&mut state, &root, "", "approle", "approle");
    (state, root)
}

fn call(
    state: &mut AuthState,
    root: &Principal,
    method: &str,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(root), "", method, path, &body, 100)?
        .ok_or_else(denied)
}

fn role(state: &mut AuthState, root: &Principal, body: Value) -> Result<AuthResponse, AuthError> {
    call(state, root, "POST", "auth/approle/role/security141", body)
}

fn credentials(state: &mut AuthState, root: &Principal, body: Value) -> Value {
    let role_id = state.roles[""]["security141"].role_id.clone();
    let response = call(
        state,
        root,
        "POST",
        "auth/approle/role/security141/secret-id",
        body,
    )
    .unwrap();
    json!({"role_id":role_id,"secret_id":response.body["data"]["secret_id"]})
}

fn login(state: &mut AuthState, credentials: &Value, peer: Option<&str>) -> AuthResponse {
    let mut response = state
        .handle_with_connection(
            None,
            "",
            "POST",
            "auth/approle/login",
            credentials,
            100,
            None,
            peer.map(|value| value.parse().unwrap()),
        )
        .unwrap()
        .unwrap();
    if response.status == 200 {
        response.login_identity.take();
        state
            .bind_issued_entity(&mut response, "", "approle", "security141-test-entity")
            .unwrap();
        state.finish_pending_batch(&mut response, "", 100).unwrap();
    }
    response
}

#[test]
fn security141_explicit_role_fields_persist_without_normalizing_the_old_api() {
    let (mut state, root) = setup();
    role(
        &mut state,
        &root,
        json!({"local_secret_ids":false,"token_strictly_bind_ip":false}),
    )
    .unwrap();
    assert!(state.has_security_contract_state());
    state.validate_security_contract_state().unwrap();
    let wire = serde_json::to_vec(&state).unwrap();
    let mut restored: AuthState = serde_json::from_slice(&wire).unwrap();
    restored.validate_security_contract_state().unwrap();
    let data = call(
        &mut restored,
        &root,
        "GET",
        "auth/approle/role/security141",
        json!({}),
    )
    .unwrap()
    .body;
    assert_eq!(data["data"]["local_secret_ids"], false);
    assert_eq!(data["data"]["token_strictly_bind_ip"], false);
}

#[test]
fn security141_strict_ipv4_ipv6_and_mapped_peers_constrain_service_and_batch_tokens() {
    for kind in ["service", "batch"] {
        for (login_peer, accepted_peer, denied_peer) in [
            ("127.0.0.1", "::ffff:127.0.0.1", "127.0.0.2"),
            ("2001:db8::1", "2001:db8::1", "2001:db8::2"),
        ] {
            let (mut state, root) = setup();
            role(
                &mut state,
                &root,
                json!({"token_strictly_bind_ip":true,"token_type":kind,"token_ttl":120}),
            )
            .unwrap();
            let credentials = credentials(&mut state, &root, json!({}));
            let issued = login(&mut state, &credentials, Some(login_peer));
            assert_eq!(issued.status, 200);
            let token = issued.body["auth"]["client_token"].as_str().unwrap();
            assert!(
                state
                    .authenticate_from(token, 101, Some(accepted_peer.parse().unwrap()))
                    .is_ok()
            );
            assert_eq!(
                state
                    .authenticate_from(token, 101, Some(denied_peer.parse().unwrap()))
                    .err()
                    .unwrap()
                    .status,
                403
            );
            assert_eq!(
                state
                    .authenticate_from(token, 101, None)
                    .err()
                    .unwrap()
                    .status,
                403
            );
        }
    }
}

#[test]
fn security141_role_edits_renewal_and_serde_reopen_do_not_rebind_issued_source_ip() {
    let (mut state, root) = setup();
    role(
        &mut state,
        &root,
        json!({"token_strictly_bind_ip":true,"token_ttl":120,"token_max_ttl":600}),
    )
    .unwrap();
    let credentials = credentials(&mut state, &root, json!({}));
    let issued = login(&mut state, &credentials, Some("127.0.0.1"));
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    role(&mut state, &root, json!({"token_strictly_bind_ip":false})).unwrap();
    assert_eq!(
        call(
            &mut state,
            &root,
            "POST",
            "auth/token/renew",
            json!({"token":token,"increment":180})
        )
        .unwrap()
        .status,
        200
    );
    let mut restored: AuthState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    restored.validate_security_contract_state().unwrap();
    assert!(
        restored
            .authenticate_from(&token, 101, Some("127.0.0.1".parse().unwrap()))
            .is_ok()
    );
    assert_eq!(
        restored
            .authenticate_from(&token, 101, Some("127.0.0.2".parse().unwrap()))
            .err()
            .unwrap()
            .status,
        403
    );
}

#[test]
fn security141_strict_ip_and_role_cidrs_conflict_on_whole_and_dedicated_updates() {
    let (mut state, root) = setup();
    role(&mut state, &root, json!({"token_strictly_bind_ip":true})).unwrap();
    let before = serde_json::to_vec(&state).unwrap();
    assert!(
        role(
            &mut state,
            &root,
            json!({"token_bound_cidrs":["127.0.0.1"]})
        )
        .is_err()
    );
    assert!(
        call(
            &mut state,
            &root,
            "POST",
            "auth/approle/role/security141/token-bound-cidrs",
            json!({"token_bound_cidrs":["127.0.0.1"]})
        )
        .is_err()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    role(
        &mut state,
        &root,
        json!({"token_strictly_bind_ip":false,"token_bound_cidrs":["127.0.0.1"]}),
    )
    .unwrap();
    role(
        &mut state,
        &root,
        json!({"token_strictly_bind_ip":true,"token_bound_cidrs":[]}),
    )
    .unwrap();
}

#[test]
fn security141_missing_peer_carries_finite_secret_consumption_but_no_token() {
    let (mut state, root) = setup();
    role(
        &mut state,
        &root,
        json!({"token_strictly_bind_ip":true,"secret_id_num_uses":1}),
    )
    .unwrap();
    let credentials = credentials(&mut state, &root, json!({}));
    let token_count = state.tokens.len();
    let failed = login(&mut state, &credentials, None);
    assert_eq!(failed.status, 500);
    assert!(failed.approle_secret_consumption.is_some());
    assert!(failed.body.get("auth").is_none());
    assert_eq!(state.tokens.len(), token_count);
}

#[test]
fn security141_local_replication_fails_closed_and_sid_cidrs_intersect_strict_ip() {
    let (mut state, root) = setup();
    let before = serde_json::to_vec(&state).unwrap();
    assert!(role(&mut state, &root, json!({"local_secret_ids":true})).is_err());
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    role(&mut state, &root, json!({"token_strictly_bind_ip":true})).unwrap();
    let credentials = credentials(
        &mut state,
        &root,
        json!({"token_bound_cidrs":["127.0.0.0/8"]}),
    );
    let failed = login(&mut state, &credentials, Some("10.0.0.1"));
    assert_eq!(failed.status, 403);
    assert!(failed.body.get("auth").is_none());
    let issued = login(&mut state, &credentials, Some("127.0.0.1"));
    assert_eq!(issued.status, 200);
    let token = issued.body["auth"]["client_token"].as_str().unwrap();
    assert!(
        state
            .authenticate_from(token, 101, Some("127.0.0.1".parse().unwrap()))
            .is_ok()
    );
    assert_eq!(
        state
            .authenticate_from(token, 101, Some("127.0.0.2".parse().unwrap()))
            .err()
            .unwrap()
            .status,
        403
    );
}

#[test]
fn security141_unknown_persisted_security_fields_are_not_discarded() {
    let (mut state, root) = setup();
    role(&mut state, &root, json!({"token_strictly_bind_ip":true})).unwrap();
    let mut value = serde_json::to_value(&state).unwrap();
    value["roles"][""]["security141"]["security"]["unknown_security_option"] = json!(true);
    assert!(serde_json::from_value::<AuthState>(value).is_err());
}

fn policy_read(state: &mut AuthState, root: &Principal) -> Value {
    call(
        state,
        root,
        "GET",
        "sys/policies/acl/security141-policy",
        json!({}),
    )
    .unwrap()
    .body["data"]
        .clone()
}

const POLICY: &str = "path \"secret/*\" { capabilities = [\"read\"] }";

#[test]
fn security141_policy_all_seven_fields_revision_and_restore_are_exact() {
    let (mut state, root) = setup();
    call(
        &mut state,
        &root,
        "POST",
        "sys/policies/acl/security141-policy",
        json!({"policy":POLICY,"cas":0}),
    )
    .unwrap();
    let initial = policy_read(&mut state, &root);
    assert_eq!(initial.as_object().unwrap().len(), 7);
    assert_eq!(initial["version"], 1);
    assert_eq!(initial["modified"], "1970-01-01T00:01:40Z");
    assert_eq!(initial["cas_required"], false);
    assert_eq!(initial["allow_slashes_in_identity_templates"], false);
    assert_eq!(initial["allow_wildcards_in_identity_templates"], false);
    assert!(state.has_security_contract_state());
    state.validate_security_contract_state().unwrap();
    let mut restored: AuthState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    restored.validate_security_contract_state().unwrap();
    assert_eq!(policy_read(&mut restored, &root), initial);
}

#[test]
fn security141_policy_cas_zero_minus_one_and_stale_rejection_are_atomic() {
    let (mut state, root) = setup();
    let path = "sys/policies/acl/security141-policy";
    call(
        &mut state,
        &root,
        "POST",
        path,
        json!({"policy":POLICY,"cas":-1}),
    )
    .unwrap();
    let before = serde_json::to_vec(&state).unwrap();
    for cas in [-2, -1, 0, 2] {
        assert_eq!(
            call(
                &mut state,
                &root,
                "POST",
                path,
                json!({"policy":POLICY,"cas":cas})
            )
            .err()
            .unwrap()
            .status,
            400
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }
    call(
        &mut state,
        &root,
        "POST",
        path,
        json!({"policy":POLICY,"cas":1}),
    )
    .unwrap();
    assert_eq!(policy_read(&mut state, &root)["version"], 2);
}

#[test]
fn security141_policy_cas_required_cannot_be_disabled_without_current_cas() {
    let (mut state, root) = setup();
    let path = "sys/policies/acl/security141-policy";
    assert!(
        call(
            &mut state,
            &root,
            "POST",
            path,
            json!({"policy":POLICY,"cas_required":true})
        )
        .is_err()
    );
    call(
        &mut state,
        &root,
        "POST",
        path,
        json!({"policy":POLICY,"cas_required":true,"cas":0}),
    )
    .unwrap();
    let before = policy_read(&mut state, &root);
    assert!(
        call(
            &mut state,
            &root,
            "POST",
            path,
            json!({"policy":POLICY,"cas_required":false})
        )
        .is_err()
    );
    assert_eq!(policy_read(&mut state, &root), before);
    call(
        &mut state,
        &root,
        "POST",
        path,
        json!({"policy":POLICY,"cas_required":false,"cas":1}),
    )
    .unwrap();
    let updated = policy_read(&mut state, &root);
    assert_eq!(updated["version"], 2);
    assert_eq!(updated["cas_required"], false);
}

#[test]
fn security141_policy_present_null_cas_is_zero_and_not_patch_default() {
    let (mut state, root) = setup();
    let path = "sys/policies/acl/security141-policy";
    call(
        &mut state,
        &root,
        "POST",
        path,
        json!({"policy":POLICY,"cas":null}),
    )
    .unwrap();
    assert_eq!(policy_read(&mut state, &root)["version"], 1);
    let before = serde_json::to_vec(&state).unwrap();
    for method in ["POST", "PATCH"] {
        assert_eq!(
            call(
                &mut state,
                &root,
                method,
                path,
                json!({"policy":POLICY,"cas":null})
            )
            .err()
            .unwrap()
            .status,
            400
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }
    call(&mut state, &root, "PATCH", path, json!({})).unwrap();
    assert_eq!(policy_read(&mut state, &root)["version"], 2);
}

#[test]
fn security141_legacy_policy_null_uses_rules_fallback() {
    let (mut state, root) = setup();
    call(
        &mut state,
        &root,
        "POST",
        "sys/policy/security141-policy",
        json!({"policy":null,"rules":POLICY,"cas":0}),
    )
    .unwrap();
    assert_eq!(policy_read(&mut state, &root)["policy"], POLICY);
    assert_eq!(policy_read(&mut state, &root)["version"], 1);
}

#[test]
fn security141_patch_preserves_omitted_options_and_uses_observed_cas() {
    let (mut state, root) = setup();
    let path = "sys/policies/acl/security141-policy";
    assert_eq!(
        call(&mut state, &root, "PATCH", path, json!({}))
            .err()
            .unwrap()
            .status,
        404
    );
    call(
        &mut state,
        &root,
        "POST",
        path,
        json!({"policy":POLICY,"cas":0,"cas_required":true,
        "allow_slashes_in_identity_templates":true,"allow_wildcards_in_identity_templates":true}),
    )
    .unwrap();
    call(&mut state, &root, "PATCH", path, json!({})).unwrap();
    let preserved = policy_read(&mut state, &root);
    assert_eq!(preserved["version"], 2);
    assert_eq!(preserved["policy"], POLICY);
    for field in [
        "cas_required",
        "allow_slashes_in_identity_templates",
        "allow_wildcards_in_identity_templates",
    ] {
        assert_eq!(preserved[field], true);
    }
    let wire = serde_json::to_vec(&state).unwrap();
    assert!(
        call(
            &mut state,
            &root,
            "PATCH",
            path,
            json!({"cas":1,"cas_required":false})
        )
        .is_err()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), wire);
    call(
        &mut state,
        &root,
        "POST",
        path,
        json!({"policy":POLICY,"cas":2}),
    )
    .unwrap();
    let replaced = policy_read(&mut state, &root);
    assert_eq!(replaced["version"], 3);
    for field in [
        "cas_required",
        "allow_slashes_in_identity_templates",
        "allow_wildcards_in_identity_templates",
    ] {
        assert_eq!(replaced[field], false);
    }
}

#[test]
fn security141_policy_unknown_options_and_unsupported_expiration_are_atomic_errors() {
    let (mut state, root) = setup();
    let before = serde_json::to_vec(&state).unwrap();
    for field in ["unknown_security_flag", "ttl", "expiration"] {
        let mut body = json!({"policy":POLICY,"cas":0});
        body[field] = json!(true);
        assert_eq!(
            call(
                &mut state,
                &root,
                "POST",
                "sys/policies/acl/security141-policy",
                body
            )
            .err()
            .unwrap()
            .status,
            400
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }
}

#[test]
fn security141_legacy_policy_has_no_fabricated_timestamp_and_explicit_zero_version() {
    let (mut state, root) = setup();
    state.policies.entry(String::new()).or_default().insert(
        "security141-policy".into(),
        parse_policy(&json!(POLICY)).unwrap(),
    );
    let before = policy_read(&mut state, &root);
    assert_eq!(before["version"], 0);
    assert!(before.get("modified").is_none());
    assert_eq!(before["allow_slashes_in_identity_templates"], true);
    call(
        &mut state,
        &root,
        "POST",
        "sys/policies/acl/security141-policy",
        json!({"policy":POLICY,"cas":0}),
    )
    .unwrap();
    assert_eq!(policy_read(&mut state, &root)["version"], 1);
}

#[test]
fn security141_acl_actual_authorization_uses_both_template_flags() {
    let (mut state, root) = setup();
    let path = "sys/policies/acl/security141-policy";
    let policy =
        "path \"secret/{{identity.entity.metadata.team}}/*\" { capabilities = [\"read\"] }";
    call(
        &mut state,
        &root,
        "POST",
        path,
        json!({"policy":policy,"cas":0}),
    )
    .unwrap();
    role(
        &mut state,
        &root,
        json!({"token_policies":["security141-policy"],"token_no_default_policy":true}),
    )
    .unwrap();
    let credentials = credentials(&mut state, &root, json!({}));
    let issued = login(&mut state, &credentials, Some("127.0.0.1"));
    let mut actor = state
        .authenticate(issued.body["auth"]["client_token"].as_str().unwrap(), 100)
        .unwrap();
    // AuthState tests supply the same checked Identity projection boundary
    // used by Service::bind_identity_principal. An entity-bearing token must
    // not bypass that production admission gate before ACL evaluation.
    actor.bind_identity_policies(BTreeSet::new());
    assert!(
        state.check_principal(&actor, "", 100).is_ok(),
        "security141_checked_identity_fixture_must_reach_acl"
    );
    actor
        .identity_templates
        .insert("identity.entity.metadata.team", "ops");
    assert!(
        state
            .authorize_request(&actor, "", "secret/ops/value", "read", 100)
            .is_ok(),
        "security141_plain_identity_binding_must_allow_baseline"
    );
    actor
        .identity_templates
        .insert("identity.entity.metadata.team", "ops/service");
    assert_eq!(
        state
            .authorize_request(&actor, "", "secret/ops/service/value", "read", 100)
            .err()
            .unwrap()
            .status,
        403
    );
    call(
        &mut state,
        &root,
        "PATCH",
        path,
        json!({"allow_slashes_in_identity_templates":true}),
    )
    .unwrap();
    assert!(
        state
            .authorize_request(&actor, "", "secret/ops/service/value", "read", 100)
            .is_ok()
    );
    actor
        .identity_templates
        .insert("identity.entity.metadata.team", "+");
    assert_eq!(
        state
            .authorize_request(&actor, "", "secret/ops/value", "read", 100)
            .err()
            .unwrap()
            .status,
        403
    );
    call(
        &mut state,
        &root,
        "PATCH",
        path,
        json!({"allow_wildcards_in_identity_templates":true}),
    )
    .unwrap();
    assert!(
        state
            .authorize_request(&actor, "", "secret/ops/value", "read", 100)
            .is_ok()
    );
}

#[test]
fn security141_forbidden_template_cannot_remove_a_deny_and_leave_a_broad_grant() {
    let (mut state, root) = setup();
    let policy = "path \"secret/*\" { capabilities = [\"read\"] }\npath \"secret/{{identity.entity.metadata.team}}/*\" { capabilities = [\"deny\"] }";
    call(
        &mut state,
        &root,
        "POST",
        "sys/policies/acl/security141-policy",
        json!({"policy":policy}),
    )
    .unwrap();
    role(
        &mut state,
        &root,
        json!({"token_policies":["security141-policy"],"token_no_default_policy":true}),
    )
    .unwrap();
    let credentials = credentials(&mut state, &root, json!({}));
    let issued = login(&mut state, &credentials, Some("127.0.0.1"));
    let mut actor = state
        .authenticate(issued.body["auth"]["client_token"].as_str().unwrap(), 100)
        .unwrap();
    // AuthState tests supply the same checked Identity projection boundary
    // used by Service::bind_identity_principal. An entity-bearing token must
    // not bypass that production admission gate before ACL evaluation.
    actor.bind_identity_policies(BTreeSet::new());
    assert!(
        state.check_principal(&actor, "", 100).is_ok(),
        "security141_checked_identity_fixture_must_reach_acl"
    );
    actor
        .identity_templates
        .insert("identity.entity.metadata.team", "ops");
    assert!(
        state
            .authorize_request(&actor, "", "secret/public/value", "read", 100)
            .is_ok(),
        "security141_plain_identity_binding_must_allow_baseline"
    );
    actor
        .identity_templates
        .insert("identity.entity.metadata.team", "+");
    assert_eq!(
        state
            .authorize_request(&actor, "", "secret/public/value", "read", 100)
            .err()
            .unwrap()
            .status,
        403
    );
}
