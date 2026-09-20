#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

fn scope() -> AuthScope<'static> {
    AuthScope {
        namespace: "",
        mount: "browser",
    }
}
fn update(state: &mut AuthState, root: &Principal, body: Value, now: u64) {
    assert_eq!(
        state
            .handle(Some(root), "", "POST", "auth/browser/role/app", &body, now)
            .unwrap()
            .unwrap()
            .status,
        204
    );
}
fn discovery() -> OidcBeginObservation {
    OidcBeginObservation {
        authorization_endpoint: "https://issuer.example:443/realm/authorize".into(),
        token_endpoint: "https://issuer.example:443/realm/token".into(),
        jwks_uri: "https://issuer.example:443/realm/keys".into(),
    }
}
fn begin_body() -> Value {
    json!({"role":"app","redirect_uri":"http://127.0.0.1:8259/oidc/callback","client_nonce":random_id("").unwrap()})
}
fn callback(state: &mut AuthState, now: u64) -> Value {
    let body = begin_body();
    let plan = state.prepare_oidc_begin("", "browser", &body, now).unwrap();
    let response = state.finish_oidc_begin(plan, discovery()).unwrap();
    let url = response.body["data"]["auth_url"].as_str().unwrap();
    let state_id = url
        .split('&')
        .find_map(|part| part.strip_prefix("state="))
        .unwrap();
    json!({"state":state_id,"code":"synthetic-code","client_nonce":body["client_nonce"]})
}
fn login(state: &mut AuthState, now: u64) -> String {
    let body = callback(state, now);
    let exchange = state
        .consume_oidc("", "browser", &body, now)
        .unwrap()
        .unwrap();
    let response = state
        .finish_oidc_observation(
            "",
            "browser",
            exchange,
            OidcLoginObservation::observed("alice", now),
        )
        .unwrap();
    assert_eq!(response.body["auth"]["renewable"], true);
    response.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .into()
}
fn fixture() -> (AuthState, Principal, String) {
    let (mut state, raw, _) = tests::setup();
    let root = state.authenticate(&raw, 100).unwrap();
    state.handle(Some(&root),"","POST","sys/policies/acl/issuer",&json!({"policy":"path \"auth/token/*\" { capabilities = [\"read\", \"update\", \"sudo\"] }"}),100).unwrap().unwrap();
    update(
        &mut state,
        &root,
        json!({"token_policies":["issuer"],"token_ttl":60,"token_max_ttl":90}),
        100,
    );
    let token = login(&mut state, 100);
    assert_eq!(state.tokens[&hash(&token)].expires_at, Some(160));
    (state, root, token)
}
fn renew(
    state: &mut AuthState,
    root: &Principal,
    raw: &str,
    operation: &str,
    increment: u64,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    let actor = state.authenticate(raw, now)?;
    let body = match operation {
        "renew" => json!({"token":raw,"increment":increment}),
        "renew-accessor" => {
            json!({"accessor":state.tokens[&hash(raw)].accessor,"increment":increment})
        }
        _ => json!({"increment":increment}),
    };
    state
        .handle(
            Some(if operation == "renew-self" {
                &actor
            } else {
                root
            }),
            "",
            "POST",
            &format!("auth/token/{operation}"),
            &body,
            now,
        )?
        .ok_or_else(denied)
}

#[test]
fn oidc_all_renew_routes_use_live_role_limits_without_issuer_or_claim_reauthentication() {
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let (mut state, root, raw) = fixture();
        state.oidc_mut(scope()).config = None;
        update(
            &mut state,
            &root,
            json!({"token_ttl":60,"token_max_ttl":600,"token_policies":["changed"],"bound_subject":"other","bound_groups":["other"]}),
            103,
        );
        let response = renew(&mut state, &root, &raw, operation, 300, 103).unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 300);
        assert!(state.tokens[&hash(&raw)].policies.contains("issuer"));
        assert!(!state.tokens[&hash(&raw)].policies.contains("changed"));
        let role = state.oidc_mut(scope()).roles.remove("app").unwrap();
        state.validate_oidc_renewal_state().unwrap();
        let before = state.tokens[&hash(&raw)].expires_at;
        assert_eq!(
            renew(&mut state, &root, &raw, operation, 400, 104)
                .err()
                .unwrap()
                .status,
            500
        );
        assert_eq!(state.tokens[&hash(&raw)].expires_at, before);
        state.oidc_mut(scope()).roles.insert("app".into(), role);
        assert_eq!(
            renew(&mut state, &root, &raw, operation, 300, 105)
                .unwrap()
                .status,
            200
        );
    }
}

#[test]
fn oidc_current_role_maximum_uses_issue_time_and_period_keeps_only_issued_explicit_cap() {
    let (mut state, root, raw) = fixture();
    update(
        &mut state,
        &root,
        json!({"token_ttl":1,"token_max_ttl":1}),
        104,
    );
    assert_eq!(
        renew(&mut state, &root, &raw, "renew-self", 300, 104)
            .err()
            .unwrap()
            .status,
        500
    );
    assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(160));
    update(
        &mut state,
        &root,
        json!({"token_ttl":60,"token_max_ttl":600}),
        105,
    );
    assert_eq!(
        renew(&mut state, &root, &raw, "renew-self", 300, 105)
            .unwrap()
            .body["auth"]["lease_duration"],
        300
    );
    update(
        &mut state,
        &root,
        json!({"token_ttl":60,"token_max_ttl":90,"token_period":20,"token_explicit_max_ttl":120}),
        110,
    );
    let raw = login(&mut state, 110);
    assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(130));
    assert_eq!(state.tokens[&hash(&raw)].max_expires_at, Some(230));
    update(
        &mut state,
        &root,
        json!({"token_ttl":3,"token_max_ttl":3,"token_explicit_max_ttl":1}),
        114,
    );
    assert_eq!(
        renew(&mut state, &root, &raw, "renew-self", 300, 114)
            .unwrap()
            .body["auth"]["lease_duration"],
        3
    );
    update(
        &mut state,
        &root,
        json!({"token_ttl":60,"token_max_ttl":600,"token_period":120}),
        115,
    );
    assert_eq!(
        renew(&mut state, &root, &raw, "renew-self", 300, 115)
            .unwrap()
            .body["auth"]["lease_duration"],
        115
    );
    assert_eq!(state.tokens[&hash(&raw)].max_expires_at, Some(230));
}

#[test]
fn oidc_zero_defaults_and_partial_role_updates_preserve_bindings() {
    let (mut state, root, _) = fixture();
    state
        .handle(
            Some(&root),
            "",
            "POST",
            "sys/auth/browser/tune",
            &json!({"default_lease_ttl":45,"max_lease_ttl":600}),
            101,
        )
        .unwrap()
        .unwrap();
    update(
        &mut state,
        &root,
        json!({"token_ttl":0,"token_max_ttl":0,"bound_subject":"alice","bound_groups":["engineering"]}),
        101,
    );
    update(
        &mut state,
        &root,
        json!({"token_policies":["changed"],"bound_subject":null,"token_ttl":null}),
        102,
    );
    let role = &state.oidc_at(scope()).unwrap().roles["app"];
    assert_eq!(role.bound_subject.as_deref(), Some("alice"));
    assert_eq!(role.bound_groups, BTreeSet::from(["engineering".into()]));
    assert!(
        role.allowed_redirect_uris
            .contains("http://127.0.0.1:8259/oidc/callback")
    );
    let data = state
        .handle(
            Some(&root),
            "",
            "GET",
            "auth/browser/role/app",
            &json!({}),
            102,
        )
        .unwrap()
        .unwrap()
        .body["data"]
        .clone();
    for field in [
        "token_ttl",
        "token_max_ttl",
        "token_period",
        "token_explicit_max_ttl",
    ] {
        assert_eq!(data[field], 0);
    }
    assert_eq!(data["token_policies"], json!(["changed"]));
    let raw = login(&mut state, 103);
    assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(148));
    assert_eq!(
        state.tokens[&hash(&raw)].policies,
        BTreeSet::from(["changed".into(), "default".into()])
    );
    update(
        &mut state,
        &root,
        json!({"bound_subject":"","bound_groups":[]}),
        104,
    );
    assert!(
        state.oidc_at(scope()).unwrap().roles["app"]
            .bound_subject
            .is_none()
    );
    for field in [
        "token_ttl",
        "token_max_ttl",
        "token_period",
        "token_explicit_max_ttl",
    ] {
        let mut body = json!({});
        body[field] = json!(MAX_TTL + 1);
        assert_eq!(
            state
                .handle(Some(&root), "", "POST", "auth/browser/role/app", &body, 104)
                .err()
                .unwrap()
                .status,
            400
        );
    }
}

#[test]
fn oidc_role_policy_defaults_are_not_persisted_until_login() {
    let (mut state, root, _) = fixture();
    assert_eq!(
        state
            .handle(
                Some(&root),
                "",
                "DELETE",
                "auth/browser/role/app",
                &json!({}),
                101
            )
            .unwrap()
            .unwrap()
            .status,
        204
    );
    update(
        &mut state,
        &root,
        json!({"allowed_redirect_uris":["http://127.0.0.1:8259/oidc/callback"]}),
        101,
    );
    let read = state
        .handle(
            Some(&root),
            "",
            "GET",
            "auth/browser/role/app",
            &json!({}),
            101,
        )
        .unwrap()
        .unwrap();
    assert_eq!(read.body["data"]["token_policies"], json!([]));
    let raw = login(&mut state, 102);
    assert_eq!(
        state.tokens[&hash(&raw)].policies,
        BTreeSet::from(["default".into()])
    );
    update(
        &mut state,
        &root,
        json!({"token_ttl":60,"token_policies":["issuer"]}),
        103,
    );
    update(&mut state, &root, json!({"token_policies":[]}), 104);
    assert!(
        state.oidc_at(scope()).unwrap().roles["app"]
            .token_policies
            .is_empty()
    );
    let raw = login(&mut state, 105);
    assert_eq!(
        state.tokens[&hash(&raw)].policies,
        BTreeSet::from(["default".into()])
    );
}

#[test]
fn oidc_tokenapi_children_are_independent_of_role_and_legacy_direct_tokens_stay_nonrenewable() {
    let (mut state, root, raw) = fixture();
    let actor = state.authenticate(&raw, 100).unwrap();
    let mut children = Vec::new();
    for op in ["create", "create-orphan"] {
        let response = state
            .handle(
                Some(&actor),
                "",
                "POST",
                &format!("auth/token/{op}"),
                &json!({"policies":["issuer"],"ttl":60}),
                100,
            )
            .unwrap()
            .unwrap();
        let child = response.body["auth"]["client_token"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(matches!(
            state.tokens[&hash(&child)].auth_provenance,
            Some(TokenAuthProvenance::TokenApi)
        ));
        children.push(child);
    }
    state.oidc_mut(scope()).roles.remove("app");
    for child in children {
        assert_eq!(
            renew(&mut state, &root, &child, "renew-self", 30, 101)
                .unwrap()
                .status,
            200
        );
    }
    let token = state.tokens.get_mut(&hash(&raw)).unwrap();
    token.auth_provenance = None;
    token.renewable = false;
    token.max_expires_at = token.expires_at;
    assert_eq!(
        renew(&mut state, &root, &raw, "renew-self", 30, 101)
            .err()
            .unwrap()
            .status,
        400
    );
    state.tokens.get_mut(&hash(&raw)).unwrap().renewable = true;
    assert_eq!(
        renew(&mut state, &root, &raw, "renew-self", 30, 101)
            .err()
            .unwrap()
            .status,
        400
    );
}

fn remount_same(state: &mut AuthState, root: &Principal, now: u64) {
    let old = state.oidc_at(scope()).unwrap().clone();
    state
        .handle(
            Some(root),
            "",
            "DELETE",
            "sys/auth/browser",
            &json!({}),
            now,
        )
        .unwrap()
        .unwrap();
    state
        .handle(
            Some(root),
            "",
            "POST",
            "sys/auth/browser",
            &json!({"type":"oidc"}),
            now,
        )
        .unwrap()
        .unwrap();
    let new = state.oidc_mut(scope());
    new.config = old.config;
    new.roles = old.roles;
}

#[test]
fn oidc_discovery_and_consumed_exchange_cannot_complete_in_recreated_mount() {
    let (mut state, root, _) = fixture();
    let plan = state
        .prepare_oidc_begin("", "browser", &begin_body(), 101)
        .unwrap();
    remount_same(&mut state, &root, 101);
    let before = provider_renewal::state_revision(&state).unwrap();
    assert_eq!(
        state
            .finish_oidc_begin(plan, discovery())
            .err()
            .unwrap()
            .status,
        409
    );
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    let body = callback(&mut state, 102);
    let exchange = state
        .consume_oidc("", "browser", &body, 102)
        .unwrap()
        .unwrap();
    remount_same(&mut state, &root, 102);
    let before = provider_renewal::state_revision(&state).unwrap();
    assert_eq!(
        state
            .finish_oidc_observation(
                "",
                "browser",
                exchange,
                OidcLoginObservation::observed("alice", 102)
            )
            .err()
            .unwrap()
            .status,
        409
    );
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    assert!(state.consume_oidc("", "browser", &body, 102).is_err());
}

#[test]
fn oidc_schema_twenty_binding_is_byte_identical_and_pending_session_survives_decode() {
    #[derive(Serialize)]
    struct LegacyRole<'a> {
        allowed_redirect_uris: &'a BTreeSet<String>,
        bound_subject: &'a Option<String>,
        bound_groups: &'a BTreeSet<String>,
        token_policies: &'a BTreeSet<String>,
        token_ttl: u64,
        token_num_uses: u64,
    }
    let (state, _, body) = tests::setup();
    let mount = state.oidc_at(scope()).unwrap();
    let role = &mount.roles["app"];
    let config = mount.config.as_ref().unwrap();
    let legacy = LegacyRole {
        allowed_redirect_uris: &role.allowed_redirect_uris,
        bound_subject: &role.bound_subject,
        bound_groups: &role.bound_groups,
        token_policies: &role.token_policies,
        token_ttl: role.token_ttl,
        token_num_uses: role.token_num_uses,
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&(config, legacy)).unwrap());
    let old_binding = URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, &bytes).as_ref());
    assert_eq!(binding(config, role).unwrap(), old_binding);
    let mut value = serde_json::to_value(&state).unwrap();
    let role = value["oidc_mounts"][""]["browser"]["roles"]["app"]
        .as_object_mut()
        .unwrap();
    for field in ["token_max_ttl", "token_period", "token_explicit_max_ttl"] {
        assert!(!role.contains_key(field));
    }
    let mut decoded: AuthState = serde_json::from_value(value).unwrap();
    decoded.validate_online_auth().unwrap();
    let exchange = decoded
        .consume_oidc("", "browser", &body, 110)
        .unwrap()
        .unwrap();
    assert_eq!(exchange.session.binding, old_binding);
    let login = decoded
        .finish_oidc_observation(
            "",
            "browser",
            exchange,
            OidcLoginObservation::observed("alice", 110),
        )
        .unwrap();
    assert_eq!(login.body["auth"]["lease_duration"], 300);
    assert_eq!(login.body["auth"]["renewable"], true);
    assert!(decoded.consume_oidc("", "browser", &body, 111).is_err());
}
