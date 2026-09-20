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
        json!({"url":"LDAPS://DIRECTORY.EXAMPLE.TEST:636","userattr":"UID"}),
    );
    let canonical = read(&mut state, &root, "auth/directory/config");
    assert_eq!(canonical["url"], "ldaps://directory.example.test:636");
    assert_eq!(canonical["userattr"], "uid");
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

#[test]
fn native_ldap_transport_preserves_legacy_authority_until_explicit_configuration() {
    let (state, root) = fixture();
    assert!(state.has_native_ldap_transport());
    let mut encoded = serde_json::to_value(&state).unwrap();
    encoded["ldap_mounts"][""]["directory"]["native"]
        .as_object_mut()
        .unwrap()
        .remove("transport");
    let mut legacy: AuthState = serde_json::from_value(encoded.clone()).unwrap();
    assert!(!legacy.has_native_ldap_transport());
    assert_eq!(serde_json::to_value(&legacy).unwrap(), encoded);
    let config = read(&mut legacy, &root, "auth/directory/config");
    assert!(config.get("certificate").is_none());
    update(
        &mut legacy,
        &root,
        "auth/directory/config",
        json!({"token_ttl":90}),
    );
    assert!(!legacy.has_native_ldap_transport());
    legacy.validate_native_ldap_state().unwrap();
    update(
        &mut legacy,
        &root,
        "auth/directory/config",
        json!({"certificate":""}),
    );
    assert!(legacy.has_native_ldap_transport());
    let config = read(&mut legacy, &root, "auth/directory/config");
    assert_eq!(config["certificate"], "");
    assert_eq!(config["connection_timeout"], 30);
    assert_eq!(config["request_timeout"], 90);
    let persisted: AuthState =
        serde_json::from_value(serde_json::to_value(&legacy).unwrap()).unwrap();
    assert!(persisted.has_native_ldap_transport());
    persisted.validate_native_ldap_state().unwrap();
}

#[test]
fn native_ldap_transport_validation_is_atomic_and_url_defaults_are_persisted() {
    let (mut state, root) = fixture();
    for url in [
        "ldaps://localhost",
        "ldaps://[::1]",
        "ldaps://[::1]:636/",
        "ldaps://127.0.0.1",
    ] {
        update(
            &mut state,
            &root,
            "auth/directory/config",
            json!({"url":url}),
        );
        state.validate_native_ldap_state().unwrap();
        assert_eq!(read(&mut state, &root, "auth/directory/config")["url"], url);
    }
    let actor = state.authenticate(&root, 100).unwrap();
    for body in [
        json!({"certificate":"garbage"}),
        json!({"connection_timeout":0}),
        json!({"request_timeout":301}),
        json!({"request_timeout":-1}),
        json!({"url":"ldaps://localhost/private"}),
        json!({"url":"ldaps://user@localhost"}),
    ] {
        let before = state_revision(&state).unwrap();
        let error = state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/directory/config",
                &body,
                100,
            )
            .err()
            .unwrap();
        assert_eq!(error.status, 400);
        assert_eq!(state_revision(&state).unwrap(), before);
    }
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"connection_timeout":4,"request_timeout":7}),
    );
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"request_timeout":null}),
    );
    let data = read(&mut state, &root, "auth/directory/config");
    assert_eq!(data["connection_timeout"], 4);
    assert_eq!(data["request_timeout"], 90);
}

fn cidr_login(
    state: &mut AuthState,
    peer: Option<std::net::IpAddr>,
) -> Result<AuthResponse, AuthError> {
    let plan = state.prepare_ldap_login_from(
        "",
        "directory",
        "alice",
        "POST",
        &json!({"password":"synthetic-user-secret"}),
        100,
        peer,
    )?;
    state.finish_ldap_login(plan, LdapLoginObservation::native("alice", BTreeSet::new()))
}

#[test]
fn native_ldap_cidr_configuration_preserves_legacy_bytes_and_partial_updates() {
    let (mut state, root) = fixture();
    let old = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert!(!state.has_ldap_token_bound_cidrs());
    assert_eq!(
        read(&mut state, &root, "auth/directory/config")["token_bound_cidrs"],
        json!([])
    );
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_bound_cidrs":"127.0.0.1/32,::1/128"}),
    );
    assert_eq!(
        read(&mut state, &root, "auth/directory/config")["token_bound_cidrs"],
        json!(["127.0.0.1", "::1"])
    );
    assert!(state.has_token_bound_cidrs() && state.has_ldap_token_bound_cidrs());
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_ttl":120}),
    );
    assert_eq!(
        read(&mut state, &root, "auth/directory/config")["token_bound_cidrs"],
        json!(["127.0.0.1", "::1"])
    );
    let actor = state.authenticate(&root, 100).unwrap();
    assert_eq!(
        state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/directory/config",
                &json!({"token_bound_cidrs":["hostname.invalid"]}),
                100
            )
            .err()
            .unwrap()
            .status,
        400
    );
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_bound_cidrs":null}),
    );
    assert!(!state.has_ldap_token_bound_cidrs());
    assert!(
        old.as_slice() == serde_json::to_vec(&state).unwrap(),
        "cleared CIDRs preserve prior serialized representation"
    );
}

#[test]
fn native_ldap_cidrs_reject_missing_or_wrong_origin_before_issue_and_token_use() {
    let (mut state, root) = fixture();
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_bound_cidrs":["127.0.0.1"],"token_num_uses":2}),
    );
    let good = Some("127.0.0.1".parse().unwrap());
    let other = Some("127.0.0.2".parse().unwrap());
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    for peer in [None, other, Some("::1".parse().unwrap())] {
        assert_eq!(cidr_login(&mut state, peer).err().unwrap().status, 403);
    }
    assert!(before.as_slice() == serde_json::to_vec(&state).unwrap());
    let raw = bearer(&cidr_login(&mut state, good).unwrap());
    assert_eq!(state.tokens[&hash(&raw)].bound_cidrs, ["127.0.0.1"]);
    for peer in [None, other] {
        assert_eq!(
            state
                .authenticate_from(&raw, 100, peer)
                .err()
                .unwrap()
                .status,
            403
        );
        assert_eq!(
            state
                .authenticate_read_only_from(&raw, 100, peer)
                .err()
                .unwrap()
                .status,
            403
        );
    }
    assert_eq!(state.tokens[&hash(&raw)].uses_remaining, Some(2));
    assert!(state.authenticate_from(&raw, 100, good).is_ok());
    assert_eq!(state.tokens[&hash(&raw)].uses_remaining, Some(1));
}

#[test]
fn native_ldap_cidr_snapshot_survives_all_renewal_entries_config_clear_and_reopen() {
    let (mut state, root) = fixture();
    let good = Some("127.0.0.1".parse().unwrap());
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_bound_cidrs":["127.0.0.1"]}),
    );
    let raw = bearer(&cidr_login(&mut state, good).unwrap());
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_bound_cidrs":["192.0.2.0/24"]}),
    );
    assert_eq!(cidr_login(&mut state, good).err().unwrap().status, 403);
    for via in ["renew-self", "renew", "renew-accessor"] {
        let peer = if via == "renew-self" {
            good
        } else {
            Some("127.0.0.2".parse().unwrap())
        };
        let actor = state
            .authenticate_from(if via == "renew-self" { &raw } else { &root }, 110, peer)
            .unwrap();
        let body = match via {
            "renew" => json!({"token":raw,"increment":300}),
            "renew-accessor" => {
                json!({"accessor":state.tokens[&hash(&raw)].accessor,"increment":300})
            }
            _ => json!({"increment":300}),
        };
        let plan = state
            .prepare_provider_renewal(
                Some(&actor),
                "",
                "POST",
                &format!("auth/token/{via}"),
                &body,
                110,
            )
            .unwrap()
            .unwrap();
        accepted(&mut state, plan, &actor, &[], 110).unwrap();
        assert_eq!(
            token_info(&state.tokens[&hash(&raw)], 110)["bound_cidrs"],
            json!(["127.0.0.1"])
        );
    }
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_bound_cidrs":[]}),
    );
    assert!(
        state.has_ldap_token_bound_cidrs(),
        "issued native LDAP token preserves the format fence"
    );
    let bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut reopened: AuthState = serde_json::from_slice(&bytes).unwrap();
    reopened.validate_online_auth().unwrap();
    assert!(reopened.authenticate(&raw, 110).is_err());
    assert!(reopened.authenticate_from(&raw, 110, good).is_ok());
    let fresh = bearer(&cidr_login(&mut reopened, None).unwrap());
    assert!(reopened.authenticate(&fresh, 110).is_ok());
}

#[test]
fn native_ldap_child_inherits_cidr_but_orphan_does_not() {
    let (mut state, root) = fixture();
    update(
        &mut state,
        &root,
        "sys/policies/acl/cidr-issuer",
        json!({"policy":
        "path \"auth/token/create\" { capabilities = [\"update\",\"sudo\"] } path \"auth/token/create-orphan\" { capabilities = [\"update\",\"sudo\"] }"}),
    );
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_bound_cidrs":["127.0.0.1"],"token_policies":["cidr-issuer"]}),
    );
    let good = Some("127.0.0.1".parse().unwrap());
    let parent = bearer(&cidr_login(&mut state, good).unwrap());
    for (path, bound) in [
        ("auth/token/create", true),
        ("auth/token/create-orphan", false),
    ] {
        let actor = state.authenticate_from(&parent, 100, good).unwrap();
        let response = state
            .handle(
                Some(&actor),
                "",
                "POST",
                path,
                &json!({"policies":["default"]}),
                100,
            )
            .unwrap()
            .unwrap();
        let child = bearer(&response);
        assert_eq!(
            state
                .authenticate_from(&child, 101, Some("127.0.0.2".parse().unwrap()))
                .is_err(),
            bound
        );
        assert_eq!(state.tokens[&hash(&child)].bound_cidrs.is_empty(), !bound);
        assert!(matches!(
            state.tokens[&hash(&child)].auth_provenance,
            Some(TokenAuthProvenance::TokenApi)
        ));
    }
}

#[test]
fn native_ldap_no_default_preserves_old_config_bytes_and_partial_null_semantics() {
    let (mut state, root) = fixture();
    let scope = AuthScope {
        namespace: "",
        mount: "directory",
    };
    let mut legacy = serde_json::to_value(state.ldap_native_at(scope).unwrap()).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("token_policies_configured");
    assert!(legacy.get("token_no_default_policy").is_none());
    let old: LdapNativeConfig = serde_json::from_value(legacy.clone()).unwrap();
    assert!(!old.token_no_default_policy);
    assert_eq!(old.token_policies_configured, None);
    assert!(serde_json::to_value(old).unwrap() == legacy);
    assert!(state.has_ldap_no_default_policy());
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_no_default_policy":true}),
    );
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_ttl":121}),
    );
    assert_eq!(
        read(&mut state, &root, "auth/directory/config")["token_no_default_policy"],
        true
    );
    assert_eq!(
        state
            .ldap_native_at(scope)
            .unwrap()
            .token_policies_configured,
        Some(false)
    );
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_no_default_policy":null,"token_policies":null}),
    );
    let config = read(&mut state, &root, "auth/directory/config");
    assert_eq!(config["token_no_default_policy"], false);
    assert_eq!(config["token_policies"], json!([]));
    assert!(config.get("token_policies_configured").is_none());
    assert_eq!(
        state
            .ldap_native_at(scope)
            .unwrap()
            .token_policies_configured,
        Some(true)
    );
}

#[test]
fn native_ldap_no_default_nil_empty_and_empty_mappings_match_provider_renewal() {
    for mapping in [None, Some("users/alice"), Some("groups/engineering")] {
        let (mut state, root) = fixture();
        update(
            &mut state,
            &root,
            "auth/directory/config",
            json!({"token_no_default_policy":true}),
        );
        if let Some(path) = mapping {
            update(
                &mut state,
                &root,
                &format!("auth/directory/{path}"),
                json!({"policies":[]}),
            );
        }
        let issued = login(&mut state, "alice", "alice", &["engineering"]);
        assert_eq!(issued.body["auth"]["policies"], json!([]));
        assert!(issued.body["auth"].get("token_policies").is_none());
        let raw = bearer(&issued);
        let actor = state.authenticate(&raw, 110).unwrap();
        assert_eq!(
            state
                .prepare_provider_renewal(
                    Some(&actor),
                    "",
                    "POST",
                    "auth/token/renew-self",
                    &json!({}),
                    110
                )
                .err()
                .unwrap()
                .status,
            403
        );
        for via in ["renew", "renew-accessor"] {
            let (actor, plan) = renewal(&mut state, &root, &raw, via, 110);
            let before = state_revision(&state).unwrap();
            assert_eq!(
                accepted(&mut state, plan, &actor, &["engineering"], 110)
                    .err()
                    .unwrap()
                    .status,
                500
            );
            assert_eq!(state_revision(&state).unwrap(), before);
        }
        for value in [json!([]), Value::Null] {
            update(
                &mut state,
                &root,
                "auth/directory/config",
                json!({"token_policies":value}),
            );
            for via in ["renew", "renew-accessor"] {
                let (actor, plan) = renewal(&mut state, &root, &raw, via, 115);
                let response = accepted(&mut state, plan, &actor, &["engineering"], 115).unwrap();
                assert_eq!(response.body["auth"]["policies"], json!([]));
                assert!(response.body["auth"].get("token_policies").is_none());
            }
        }
        // Older native configs had already lost nil/empty provenance. Do not
        // retroactively infer nil when an old normalized config is reopened.
        state
            .ldap_mounts
            .get_mut("")
            .unwrap()
            .get_mut("directory")
            .unwrap()
            .native
            .as_mut()
            .unwrap()
            .token_policies_configured = None;
        let (actor, plan) = renewal(&mut state, &root, &raw, "renew", 120);
        assert_eq!(
            accepted(&mut state, plan, &actor, &["engineering"], 120)
                .unwrap()
                .status,
            200
        );
    }
}

#[test]
fn native_ldap_no_default_keeps_explicit_default_from_config_user_and_group() {
    for owner in ["config", "users/alice", "groups/engineering"] {
        let (mut state, root) = fixture();
        update(
            &mut state,
            &root,
            "auth/directory/config",
            json!({"token_no_default_policy":true}),
        );
        let body = if owner == "config" {
            json!({"token_policies":["default"]})
        } else {
            json!({"policies":["default"]})
        };
        update(&mut state, &root, &format!("auth/directory/{owner}"), body);
        let issued = login(&mut state, "alice", "alice", &["engineering"]);
        assert_eq!(issued.body["auth"]["token_policies"], json!(["default"]));
        let raw = bearer(&issued);
        for via in ["renew-self", "renew", "renew-accessor"] {
            let (actor, plan) = renewal(&mut state, &root, &raw, via, 110);
            assert_eq!(
                accepted(&mut state, plan, &actor, &["engineering"], 110)
                    .unwrap()
                    .body["auth"]["token_policies"],
                json!(["default"])
            );
        }
    }
}

#[test]
fn native_ldap_no_default_toggles_only_future_tokens_and_policy_change_still_fails() {
    let (mut state, root) = fixture();
    update(
        &mut state,
        &root,
        "sys/policies/acl/ldap-renewer",
        json!({"policy":"path \"auth/token/renew-self\" { capabilities = [\"update\"] }"}),
    );
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_policies":["ldap-renewer"]}),
    );
    let original = bearer(&login(&mut state, "alice", "alice", &[]));
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_no_default_policy":true}),
    );
    let bare = bearer(&login(&mut state, "alice", "alice", &[]));
    for enabled in [true, false] {
        update(
            &mut state,
            &root,
            "auth/directory/config",
            json!({"token_no_default_policy":enabled}),
        );
        for (raw, expected) in [
            (&original, json!(["default", "ldap-renewer"])),
            (&bare, json!(["ldap-renewer"])),
        ] {
            for via in ["renew-self", "renew", "renew-accessor"] {
                let (actor, plan) = renewal(&mut state, &root, raw, via, 110);
                assert_eq!(
                    accepted(&mut state, plan, &actor, &[], 110).unwrap().body["auth"]["token_policies"],
                    expected
                );
            }
        }
    }
    update(
        &mut state,
        &root,
        "auth/directory/config",
        json!({"token_policies":["default"]}),
    );
    for via in ["renew-self", "renew", "renew-accessor"] {
        let (actor, plan) = renewal(&mut state, &root, &bare, via, 115);
        let before = state_revision(&state).unwrap();
        assert_eq!(
            accepted(&mut state, plan, &actor, &[], 115)
                .err()
                .unwrap()
                .status,
            500
        );
        assert_eq!(state_revision(&state).unwrap(), before);
    }
    // A retained no-default direct token remains a format discriminator even
    // after its mount configuration is absent.
    state.ldap_mounts.get_mut("").unwrap().remove("directory");
    assert!(state.has_ldap_no_default_policy());
}
