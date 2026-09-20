#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

fn config() -> Value {
    json!({"url":"ldaps://directory.example.test:636","binddn":"cn=manager,dc=example,dc=test",
        "bindpass":"synthetic-manager-secret","userdn":"ou=people,dc=example,dc=test",
        "userattr":"uid","groupdn":"ou=groups,dc=example,dc=test","token_ttl":120,"token_max_ttl":600})
}
fn fixture() -> (AuthState, String) {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    update(
        &mut state,
        &root,
        "sys/auth/directory",
        json!({"type":"ldap"}),
    );
    update(&mut state, &root, "auth/directory/config", config());
    (state, root)
}
fn update(state: &mut AuthState, root: &str, path: &str, body: Value) {
    let actor = state.authenticate(root, 100).unwrap();
    assert_eq!(
        state
            .handle(Some(&actor), "", "POST", path, &body, 100)
            .unwrap()
            .unwrap()
            .status,
        204
    );
}
fn read(state: &mut AuthState, root: &str, path: &str) -> Value {
    let actor = state.authenticate(root, 100).unwrap();
    state
        .handle(Some(&actor), "", "GET", path, &json!({}), 100)
        .unwrap()
        .unwrap()
        .body["data"]
        .clone()
}
fn login(state: &mut AuthState, name: &str, alias: &str, groups: &[&str]) -> AuthResponse {
    let plan = state
        .prepare_ldap_login(
            "",
            "directory",
            name,
            "POST",
            &json!({"password":"synthetic-user-secret"}),
            100,
        )
        .unwrap();
    state
        .finish_ldap_login(
            plan,
            LdapLoginObservation::native(alias, groups.iter().map(|s| s.to_string()).collect()),
        )
        .unwrap()
}
fn bearer(response: &AuthResponse) -> String {
    response.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn renewal(
    state: &mut AuthState,
    root: &str,
    raw: &str,
    endpoint: &str,
    now: u64,
) -> (Principal, ProviderRenewalPlan) {
    assert!(matches!(
        endpoint,
        "renew-self" | "renew" | "renew-accessor"
    ));
    let caller = if endpoint == "renew-self" { raw } else { root };
    let actor = state.authenticate(caller, now).unwrap();
    let body = match endpoint {
        "renew-self" => json!({"increment":300}),
        "renew" => json!({"token":raw,"increment":300}),
        _ => json!({"accessor":state.tokens[&hash(raw)].accessor,"increment":300}),
    };
    let plan = state
        .prepare_provider_renewal(
            Some(&actor),
            "",
            "POST",
            &format!("auth/token/{endpoint}"),
            &body,
            now,
        )
        .unwrap()
        .unwrap();
    (actor, plan)
}
fn accepted(
    state: &mut AuthState,
    plan: ProviderRenewalPlan,
    actor: &Principal,
    groups: &[&str],
    now: u64,
) -> Result<AuthResponse, AuthError> {
    state.finish_provider_renewal(
        plan,
        actor,
        ProviderRenewalObservation::Ldap(LdapRenewalObservation::observed(
            groups.iter().map(|s| s.to_string()).collect(),
        )),
        now,
    )
}

#[test]
fn native_ldap_no_local_user_defaults_secret_redaction_and_alias_case() {
    let (mut state, root) = fixture();
    let config = read(&mut state, &root, "auth/directory/config");
    assert_eq!(config["groupattr"], "cn");
    assert_eq!(config["token_policies"], json!([]));
    assert!(config.get("bindpass").is_none());
    assert!(!config.to_string().contains("synthetic-manager-secret"));
    let actor = state.authenticate(&root, 100).unwrap();
    for mapping in ["users", "groups"] {
        let listed = state.handle(
            Some(&actor),
            "",
            "LIST",
            &format!("auth/directory/{mapping}"),
            &json!({}),
            100,
        );
        assert!(matches!(listed, Err(AuthError { status: 404, .. })));
    }
    let response = login(&mut state, "MIXEDUID", "Case Person", &["Engineering"]);
    assert_eq!(response.body["auth"]["metadata"]["username"], "mixeduid");
    assert_eq!(
        response.login_identity.as_ref().unwrap().alias,
        "Case Person"
    );
    assert_eq!(response.body["auth"]["token_policies"], json!(["default"]));
    assert!(
        state
            .users_at(AuthScope {
                namespace: "",
                mount: "directory"
            })
            .is_none_or(BTreeMap::is_empty)
    );
    assert!(state.ldap_native_users.is_empty());
    let raw = bearer(&response);
    let token = &state.tokens[&hash(&raw)];
    assert!(token.renewable);
    assert!(token.max_expires_at.is_none());
    assert!(
        matches!(&token.auth_provenance,Some(TokenAuthProvenance::LdapNative{username,alias,..}) if username=="mixeduid"&&alias=="Case Person")
    );
    state.validate_online_auth().unwrap();
    assert!(state.has_native_ldap_state());
}

#[test]
fn native_ldap_partial_null_config_and_profile_boundary() {
    let (mut state, root) = fixture();
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_period":30,"token_explicit_max_ttl":90,"token_num_uses":4,"token_policies":["alpha"],"case_sensitive_names":true}),
    );
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_ttl":null,"token_period":null,"token_num_uses":null,"token_policies":null,"case_sensitive_names":null,"userfilter":null}),
    );
    let data = read(&mut state, &root, "auth/directory/config");
    assert_eq!(data["token_ttl"], 120);
    assert_eq!(data["token_period"], 30);
    assert_eq!(data["token_explicit_max_ttl"], 90);
    assert_eq!(data["token_num_uses"], 0);
    assert_eq!(data["token_policies"], json!([]));
    assert_eq!(data["case_sensitive_names"], false);
    assert_eq!(data["userfilter"], "");
    let actor = state.authenticate(&root, 100).unwrap();
    for body in [
        json!({"bind_dn":"cn=legacy","binddn":"cn=mixed"}),
        json!({"starttls":true}),
        json!({"insecure_tls":true}),
        json!({"bindpass":""}),
        json!({"bindpass":null}),
    ] {
        let before = state_revision(&state).unwrap();
        assert_eq!(
            state
                .handle(
                    Some(&actor),
                    "",
                    "POST",
                    "auth/directory/config",
                    &body,
                    100
                )
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(state_revision(&state).unwrap(), before);
    }
    assert_eq!(
        state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/directory/config",
                &json!({"bind_dn":"cn=legacy","user_dn_template":"uid={{username}},dc=test"}),
                100
            )
            .err()
            .unwrap()
            .status,
        409
    );
    update(&mut state, &root, "sys/auth/legacy", json!({"type":"ldap"}));
    update(
        &mut state,
        &root,
        "auth/legacy/config",
        json!({"url":"ldaps://directory.example.test","bind_dn":"cn=legacy","user_dn_template":"uid={{username}},dc=test"}),
    );
    assert_eq!(
        state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/legacy/config",
                &config(),
                100
            )
            .err()
            .unwrap()
            .status,
        409
    );
    let legacy = &state.ldap_mounts[""]["legacy"];
    assert!(legacy.native.is_none());
    assert!(
        serde_json::to_value(legacy)
            .unwrap()
            .get("native")
            .is_none()
    );
}

#[test]
fn native_ldap_optional_user_maps_replace_fold_and_delete_literal_key() {
    let (mut state, root) = fixture();
    update(
        &mut state,
        &root,
        "auth/directory/groups/AUX",
        json!({"policies":["aux-policy"]}),
    );
    update(
        &mut state,
        &root,
        "auth/directory/groups/Engineering",
        json!({"policies":["directory-policy"]}),
    );
    update(
        &mut state,
        &root,
        "auth/directory/users/ALICE",
        json!({"groups":["AUX"],"policies":["direct"]}),
    );
    assert_eq!(
        read(&mut state, &root, "auth/directory/users/ALICE"),
        json!({"groups":"aux","policies":["direct"]})
    );
    let initial = login(&mut state, "ALICE", "alice", &["Engineering"]);
    assert_eq!(
        initial.body["auth"]["token_policies"],
        json!(["aux-policy", "default", "direct", "directory-policy"])
    );
    assert_eq!(
        initial.external_groups.unwrap().names,
        BTreeSet::from(["Engineering".into(), "aux".into()])
    );
    update(
        &mut state,
        &root,
        "auth/directory/users/alice",
        json!({"policies":["direct"]}),
    );
    assert_eq!(
        read(&mut state, &root, "auth/directory/users/alice")["groups"],
        ""
    );
    let actor = state.authenticate(&root, 100).unwrap();
    assert_eq!(
        state
            .handle(
                Some(&actor),
                "",
                "DELETE",
                "auth/directory/users/ALICE",
                &json!({}),
                100
            )
            .unwrap()
            .unwrap()
            .status,
        204
    );
    assert_eq!(
        read(&mut state, &root, "auth/directory/users/alice")["policies"],
        json!(["direct"])
    );
    state
        .handle(
            Some(&actor),
            "",
            "DELETE",
            "auth/directory/users/alice",
            &json!({}),
            100,
        )
        .unwrap();
    let response = login(&mut state, "alice", "alice", &[]);
    assert_eq!(response.body["auth"]["token_policies"], json!(["default"]));
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"case_sensitive_names":true}),
    );
    update(
        &mut state,
        &root,
        "auth/directory/users/ALICE",
        json!({"policies":["exact"]}),
    );
    assert_eq!(
        login(&mut state, "ALICE", "ALICE", &[]).body["auth"]["token_policies"],
        json!(["default", "exact"])
    );
    assert_eq!(
        login(&mut state, "alice", "alice", &[]).body["auth"]["token_policies"],
        json!(["default"])
    );
}

#[test]
fn native_ldap_login_mapping_absence_and_mount_config_are_fenced() {
    for mutation in ["new-user", "new-group", "config", "mount"] {
        let (mut state, root) = fixture();
        let plan = state
            .prepare_ldap_login(
                "",
                "directory",
                "alice",
                "POST",
                &json!({"password":"secret"}),
                100,
            )
            .unwrap();
        match mutation {
            "new-user" => update(
                &mut state,
                &root,
                "auth/directory/users/alice",
                json!({"policies":["added"]}),
            ),
            "new-group" => update(
                &mut state,
                &root,
                "auth/directory/groups/engineering",
                json!({"policies":["added"]}),
            ),
            "config" => update(
                &mut state,
                &root,
                "auth/directory/config",
                json!({"token_ttl":60}),
            ),
            "mount" => {
                let actor = state.authenticate(&root, 100).unwrap();
                state
                    .handle(
                        Some(&actor),
                        "",
                        "DELETE",
                        "sys/auth/directory",
                        &json!({}),
                        100,
                    )
                    .unwrap();
                update(
                    &mut state,
                    &root,
                    "sys/auth/directory",
                    json!({"type":"ldap"}),
                );
                update(&mut state, &root, "auth/directory/config", config());
            }
            _ => unreachable!(),
        }
        let before = state_revision(&state).unwrap();
        let error = state
            .finish_ldap_login(plan, LdapLoginObservation::native("alice", BTreeSet::new()))
            .err()
            .unwrap();
        assert_eq!(error.status, 409, "{mutation}");
        assert_eq!(state_revision(&state).unwrap(), before, "{mutation}");
    }
}

#[test]
fn native_ldap_provider_renewal_all_entries_keep_issued_alias_and_dynamic_limits() {
    for endpoint in ["renew-self", "renew", "renew-accessor"] {
        let (mut state, root) = fixture();
        let response = login(&mut state, "ALICE", "Case Person", &[]);
        let raw = bearer(&response);
        let (actor, plan) = renewal(&mut state, &root, &raw, endpoint, 110);
        let renewed = accepted(&mut state, plan, &actor, &[], 110).unwrap();
        assert_eq!(renewed.body["auth"]["lease_duration"], 300);
        assert_eq!(renewed.external_groups.unwrap().alias, "Case Person");
        update(
            &mut state,
            &root,
            "auth/directory/config",
            json!({"token_period":30,"token_explicit_max_ttl":1}),
        );
        let (actor, plan) = renewal(&mut state, &root, &raw, endpoint, 115);
        assert_eq!(
            accepted(&mut state, plan, &actor, &[], 115).unwrap().body["auth"]["lease_duration"],
            30
        );
        assert_eq!(state.tokens[&hash(&raw)].period, 0);
        assert!(state.tokens[&hash(&raw)].max_expires_at.is_none());
        let actor = state.authenticate(&root, 116).unwrap();
        assert_eq!(
            state
                .handle(
                    Some(&actor),
                    "",
                    "POST",
                    "auth/token/renew",
                    &json!({"token":raw}),
                    116
                )
                .err()
                .unwrap()
                .status,
            503
        );
    }
}

#[test]
fn native_ldap_policies_compare_after_provider_and_failed_renewal_is_atomic() {
    let (mut state, root) = fixture();
    update(
        &mut state,
        &root,
        "auth/directory/users/alice",
        json!({"policies":["mapped"]}),
    );
    let raw = bearer(&login(&mut state, "alice", "alice", &[]));
    let actor = state.authenticate(&root, 110).unwrap();
    state
        .handle(
            Some(&actor),
            "",
            "DELETE",
            "auth/directory/users/alice",
            &json!({}),
            110,
        )
        .unwrap();
    let (actor, plan) = renewal(&mut state, &root, &raw, "renew", 110);
    let before = state_revision(&state).unwrap();
    assert_eq!(
        accepted(&mut state, plan, &actor, &[], 110)
            .err()
            .unwrap()
            .status,
        500
    );
    assert_eq!(state_revision(&state).unwrap(), before);
    assert_eq!(
        login(&mut state, "alice", "alice", &[]).body["auth"]["token_policies"],
        json!(["default"])
    );
    let (actor, plan) = renewal(&mut state, &root, &raw, "renew", 115);
    update(
        &mut state,
        &root,
        "auth/directory/users/alice",
        json!({"policies":["mapped"]}),
    );
    let before = state_revision(&state).unwrap();
    assert_eq!(
        accepted(&mut state, plan, &actor, &[], 115)
            .err()
            .unwrap()
            .status,
        409
    );
    assert_eq!(state_revision(&state).unwrap(), before);
}

#[test]
fn native_ldap_issue_explicit_cap_persisted_and_token_api_children_have_no_credentials() {
    let (mut state, root) = fixture();
    update(
        &mut state,
        &root,
        "sys/policies/acl/issuer",
        json!({"policy":"path \"auth/token/create\" { capabilities = [\"update\"] }"}),
    );
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_ttl":0,"token_period":30,"token_explicit_max_ttl":90,"token_policies":["issuer"]}),
    );
    let raw = bearer(&login(&mut state, "alice", "alice", &[]));
    let issued = state.tokens[&hash(&raw)].created_at;
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_period":60,"token_explicit_max_ttl":0}),
    );
    let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut state: AuthState = serde_json::from_slice(&encoded).unwrap();
    state.validate_online_auth().unwrap();
    let (actor, plan) = renewal(&mut state, &root, &raw, "renew", issued + 20);
    assert_eq!(
        accepted(&mut state, plan, &actor, &[], issued + 20)
            .unwrap()
            .body["auth"]["lease_duration"],
        60
    );
    let (actor, plan) = renewal(&mut state, &root, &raw, "renew", issued + 70);
    assert_eq!(
        accepted(&mut state, plan, &actor, &[], issued + 70)
            .unwrap()
            .body["auth"]["lease_duration"],
        20
    );
    assert_eq!(state.tokens[&hash(&raw)].period, 30);
    let actor = state.authenticate(&raw, issued + 70).unwrap();
    // A child created by this direct LDAP token remains generic TokenApi.
    let child = state
        .handle(
            Some(&actor),
            "",
            "POST",
            "auth/token/create",
            &json!({"policies":["default"]}),
            issued + 70,
        )
        .unwrap()
        .unwrap();
    let token = &state.tokens[&hash(&bearer(&child))];
    assert!(matches!(
        token.auth_provenance,
        Some(TokenAuthProvenance::TokenApi)
    ));
    assert!(
        !serde_json::to_string(token)
            .unwrap()
            .contains("synthetic-user-secret")
    );
}
