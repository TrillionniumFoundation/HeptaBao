#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

#[path = "auth_approle_renewal_tests.rs"]
mod approle_renewal_tests;
#[path = "auth_cert_renewal_tests.rs"]
mod certificate_renewal_tests;
#[path = "auth_token_lifetime_tests.rs"]
mod token_lifetime_tests;

#[path = "auth_jwt_renewal_tests.rs"]
mod jwt_renewal_tests;

#[path = "auth_jwt_login_tests.rs"]
mod jwt_login_tests;

fn setup() -> (AuthState, String, Principal) {
    let (mut state, raw) = AuthState::bootstrap(100).unwrap();
    let principal = state.authenticate(&raw, 100).unwrap();
    (state, raw, principal)
}

#[test]
fn ldap_bounded_profile_config_login_and_injection_rejection() {
    let (mut state, _raw, root) = setup();
    call(
        &mut state,
        &root,
        "",
        "POST",
        "sys/auth/ldap",
        json!({"type":"ldap"}),
        100,
    );
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/ldap/config",
        json!({
            "url":"ldaps://directory.example.test",
            "bind_dn":"cn=heptabao,dc=example,dc=test",
            "user_dn_template":"uid={{username}},ou=people,dc=example,dc=test",
            "starttls":false
        }),
        100,
    );
    let cfg = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/ldap/config",
        json!({}),
        100,
    );
    assert_eq!(cfg.body["data"]["url"], "ldaps://directory.example.test");
    call(
        &mut state,
        &root,
        "",
        "PUT",
        "auth/ldap/users/alice",
        json!({"password":"correct horse battery staple"}),
        100,
    );
    let before = state.tokens.len();
    let offline = state.handle(
        Some(&root),
        "",
        "POST",
        "auth/ldap/login/alice",
        &json!({"password":"correct horse battery staple"}),
        101,
    );
    assert_eq!(offline.err().unwrap().status, 503);
    assert_eq!(
        state.tokens.len(),
        before,
        "local password must not replace LDAP bind"
    );
    let plan = state
        .prepare_ldap_login(
            "",
            "ldap",
            "alice",
            "POST",
            &json!({"password":"directory-password"}),
            101,
        )
        .unwrap();
    // This unit observation exercises local mapping only. Real LDAPS bind and
    // directory-group readback are exercised by ldap_openldap_live.py.
    let login = state
        .finish_ldap_login(
            plan,
            LdapLoginObservation {
                alias: None,
                groups: BTreeSet::new(),
            },
        )
        .unwrap();
    let issued = login.body["auth"]["client_token"].as_str().unwrap();
    assert!(state.authenticate(issued, 102).is_ok());
    assert!(
        state
            .handle(
                Some(&root),
                "",
                "PUT",
                "auth/ldap/config",
                &json!({
                    "url":"ldap://directory.example.test/??(|(uid=*))"
                }),
                100
            )
            .is_err()
    );
}

#[test]
fn radius_bounded_profile_config_login_and_policy_projection() {
    let (mut state, _raw, root) = setup();
    call(
        &mut state,
        &root,
        "",
        "POST",
        "sys/auth/radius",
        json!({"type":"radius"}),
        100,
    );
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/radius/config",
        json!({
            "url":"radius://radius.example.test:1812",
            "token_policies":["default","operator"],
            "token_ttl":120,
            "token_max_ttl":240,
            "token_num_uses":2
        }),
        100,
    );
    let cfg = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/radius/config",
        json!({}),
        100,
    );
    assert_eq!(cfg.body["data"]["url"], "radius://radius.example.test:1812");
    let plan = state
        .prepare_radius_login(
            "",
            "radius",
            "POST",
            &json!({"username":"alice","password":"radius-password"}),
            101,
        )
        .unwrap();
    let login = state
        .finish_radius_login(plan, RadiusLoginObservation)
        .unwrap();
    assert_eq!(
        login.body["auth"]["token_policies"],
        json!(["default", "operator"])
    );
    let issued = login.body["auth"]["client_token"].as_str().unwrap();
    assert!(state.authenticate(issued, 102).is_ok());
    assert!(
        state
            .prepare_radius_login(
                "",
                "radius",
                "POST",
                &json!({"username":"alice","password":""}),
                101,
            )
            .is_err()
    );
    assert!(
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "auth/radius/config",
                &json!({"url":"radius://radius.example.test:1812/path"}),
                100,
            )
            .is_err()
    );
}
fn call(
    state: &mut AuthState,
    actor: &Principal,
    namespace: &str,
    method: &str,
    path: &str,
    body: Value,
    now: u64,
) -> AuthResponse {
    state
        .handle(Some(actor), namespace, method, path, &body, now)
        .unwrap()
        .unwrap()
}
fn token(
    state: &mut AuthState,
    root: &Principal,
    namespace: &str,
    body: Value,
    now: u64,
) -> String {
    call(
        state,
        root,
        namespace,
        "POST",
        "auth/token/create",
        body,
        now,
    )
    .body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .into()
}
fn put_policy(state: &mut AuthState, root: &Principal, namespace: &str, name: &str, source: Value) {
    call(
        state,
        root,
        namespace,
        "PUT",
        &format!("sys/policies/acl/{name}"),
        json!({"policy": source}),
        100,
    );
}

#[test]
fn no_cleartext_credentials_in_restart_state() {
    let (mut state, root_raw, root) = setup();
    let raw = token(
        &mut state,
        &root,
        "",
        json!({"policies": ["default"], "ttl": 30, "num_uses": 2}),
        100,
    );
    let first = state.authenticate(&raw, 101).unwrap();
    assert!(first.consumed_use());
    let saved = serde_json::to_string(&state).unwrap();
    assert!(!saved.contains(&raw));
    assert!(!saved.contains(&root_raw));
    let mut restarted: AuthState = serde_json::from_str(&saved).unwrap();
    let second = restarted.authenticate(&raw, 102).unwrap();
    restarted
        .authorize_for_unit_test(&second, "", "auth/token/lookup-self", "read")
        .unwrap();
    assert!(restarted.authenticate(&raw, 103).is_err());
    assert!(restarted.authenticate(&root_raw, 103).is_ok());
}

#[test]
fn namespace_collision_and_cross_namespace_grants_are_rejected() {
    let (mut state, _, root) = setup();
    put_policy(
        &mut state,
        &root,
        "a",
        "reader",
        json!(r#"path "b/c" { capabilities = ["read"] }"#),
    );
    put_policy(
        &mut state,
        &root,
        "a/b",
        "reader",
        json!(r#"path "c" { capabilities = ["read"] }"#),
    );
    let raw = token(&mut state, &root, "a", json!({"policies": ["reader"]}), 100);
    let actor = state.authenticate(&raw, 101).unwrap();
    state
        .authorize_for_unit_test(&actor, "a", "b/c", "read")
        .unwrap();
    assert!(
        state
            .authorize_for_unit_test(&actor, "a/b", "c", "read")
            .is_err()
    );
    assert!(
        state
            .authorize_for_unit_test(&actor, "", "b/c", "read")
            .is_err()
    );
    assert!(
        state
            .handle(
                Some(&actor),
                "a/b",
                "GET",
                "auth/token/lookup-self",
                &json!({}),
                101
            )
            .is_err()
    );
    assert!(
        state
            .authorize_for_unit_test(&root, "../a", "b/c", "read")
            .is_err()
    );
}

#[test]
fn policy_deny_overrides_grants_and_sudo_never_implies_read() {
    let (mut state, _, root) = setup();
    put_policy(
        &mut state,
        &root,
        "",
        "reader",
        json!({"path": {
            "secret/data/*": {"capabilities": ["read"]},
            "secret/data/private/*": {"capabilities": ["deny"]},
            "sys/control": {"capabilities": ["sudo"]}
        }}),
    );
    let raw = token(&mut state, &root, "", json!({"policies": ["reader"]}), 100);
    let actor = state.authenticate(&raw, 101).unwrap();
    state
        .authorize_for_unit_test(&actor, "", "secret/data/public/a", "read")
        .unwrap();
    assert!(
        state
            .authorize_for_unit_test(&actor, "", "secret/data/private/a", "read")
            .is_err()
    );
    assert!(
        state
            .authorize_for_unit_test(&actor, "", "secret/data/public/a", "update")
            .is_err()
    );
    state
        .authorize_for_unit_test(&actor, "", "sys/control", "sudo")
        .unwrap();
    assert!(
        state
            .authorize_for_unit_test(&actor, "", "sys/control", "read")
            .is_err()
    );
    assert!(
        state
            .authorize_for_unit_test(&actor, "", "unlisted", "read")
            .is_err()
    );
}

#[test]
fn acl_glob_boundaries_and_strict_hcl_parsing() {
    assert_eq!(parse_strict_json(br#"{"null":null,"bool":true,"number":1.5,"neg":-2,"large":18446744073709551615,"list":[1,"x"]}"#).unwrap(), json!({"null":null,"bool":true,"number":1.5,"neg":-2,"large":u64::MAX,"list":[1,"x"]}));
    assert!(parse_strict_json(br#"{"data":{"a":1,"a":2}}"#).is_err());
    assert!(parse_strict_json(br#"{"password":"secret-before-error","broken":[true,}"#).is_err());
    assert!(path_matches("secret/+/data/*", "secret/one/data/a/b"));
    assert!(!path_matches("secret/+/data/*", "secret/one/two/data/a"));
    assert!(!path_matches("secret/+/data/*", "secret//data/a"));
    assert!(path_matches("secret/data/team*", "secret/data/teams/a"));
    assert!(!path_matches(
        "secret/data/team/*",
        "secret/data/team-other/a"
    ));
    assert!(!path_matches("secret/+/data", "secret/a/data/b"));
    assert!(!path_matches("secret/+/data", "secret/a/data-other"));
    assert!(path_matches("*", "any/path"));
    assert!(
        parse_policy(&json!(
            "# comment\npath \"secret/+/*\" {\n capabilities = [\"read\", \"list\",]\n}\n/* end */"
        ))
        .is_ok()
    );
    for source in [
        r#"path "secret/*/bad" { capabilities = ["read"] }"#,
        r#"path "secret/a+" { capabilities = ["read"] }"#,
        r#"path "secret/*" { capabilities = ["read"] allowed_parameters = {} }"#,
        r#"path "secret/*" { capabilities = ["superuser"] }"#,
        r#"path "secret/*" { capabilities = ["read"] } junk"#,
        r#"path "secret/*" { capabilities = ["read"] } path "secret/*" { capabilities = ["deny"] }"#,
        r#"path "secret/${identity}" { capabilities = ["read"] }"#,
        "/* unterminated",
    ] {
        assert!(parse_policy(&json!(source)).is_err(), "{source}");
    }
    assert!(
        parse_policy(&json!({"path": {"*": {"capabilities": ["read"], "denied_parameters": {}}}}))
            .is_err()
    );
    assert!(
        parse_policy(&json!(
            r#"{"path":{"*":{"capabilities":["deny"],"capabilities":["read"]}}}"#
        ))
        .is_err()
    );
    assert!(
        parse_policy(&json!(
            r#"{"path":{"*":{"capabilities":["deny"]},"*":{"capabilities":["read"]}}}"#
        ))
        .is_err()
    );
}

#[test]
fn token_parent_expiry_revoke_cascade_and_orphan_survival() {
    let (mut state, _, root) = setup();
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
        json!({"policies": ["issuer"], "ttl": 30}),
        100,
    );
    let parent = state.authenticate(&parent_raw, 101).unwrap();
    let child_raw = token(
        &mut state,
        &parent,
        "",
        json!({"policies": ["default"], "ttl": 300}),
        101,
    );
    assert!(state.authenticate(&child_raw, 129).is_ok());
    assert!(state.authenticate(&child_raw, 130).is_err());
    let parent2_raw = token(&mut state, &root, "", json!({"policies": ["issuer"]}), 100);
    let parent2 = state.authenticate(&parent2_raw, 101).unwrap();
    let child2_raw = token(
        &mut state,
        &parent2,
        "",
        json!({"policies": ["default"]}),
        101,
    );
    let orphan = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/create-orphan",
        json!({"policies": ["default"]}),
        101,
    )
    .body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/revoke",
        json!({"token": parent2_raw}),
        102,
    );
    assert!(state.authenticate(&parent2_raw, 103).is_err());
    assert!(state.authenticate(&child2_raw, 103).is_err());
    assert!(state.authenticate(&orphan, 103).is_ok());
    // A principal obtained before revocation cannot bypass authoritative state.
    assert!(
        state
            .authorize_for_unit_test(&parent2, "", "auth/token/create", "update")
            .is_err()
    );
}

#[test]
fn token_creation_cannot_escalate_policies_or_skip_parent_without_sudo() {
    let (mut state, _, root) = setup();
    put_policy(
        &mut state,
        &root,
        "",
        "issuer",
        json!(r#"path "auth/token/create*" { capabilities = ["update"] }"#),
    );
    let raw = token(&mut state, &root, "", json!({"policies": ["issuer"]}), 100);
    let actor = state.authenticate(&raw, 101).unwrap();
    for body in [
        json!({"policies": ["root"]}),
        json!({"policies": ["other"]}),
        json!({"no_parent": true}),
        json!({"period": 30}),
    ] {
        assert!(
            state
                .handle(Some(&actor), "", "POST", "auth/token/create", &body, 102)
                .is_err()
        );
    }
    let raw = token(
        &mut state,
        &root,
        "",
        json!({"policies": ["issuer"], "num_uses": 2}),
        100,
    );
    let actor = state.authenticate(&raw, 101).unwrap();
    assert!(
        state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/token/create",
                &json!({}),
                102
            )
            .is_err()
    );
}

#[test]
fn periodic_and_finite_tokens_renew_without_exceeding_explicit_maximum() {
    let (mut state, _, root) = setup();
    let raw = token(
        &mut state,
        &root,
        "",
        json!({"policies": ["default"], "period": 30, "explicit_max_ttl": 70}),
        100,
    );
    let actor = state.authenticate(&raw, 120).unwrap();
    let renewed = call(
        &mut state,
        &actor,
        "",
        "POST",
        "auth/token/renew-self",
        json!({"increment": 99999}),
        120,
    );
    assert_eq!(renewed.body["auth"]["lease_duration"], 30);
    let actor = state.authenticate(&raw, 140).unwrap();
    call(
        &mut state,
        &actor,
        "",
        "POST",
        "auth/token/renew-self",
        json!({}),
        140,
    );
    let actor = state.authenticate(&raw, 160).unwrap();
    let renewed = call(
        &mut state,
        &actor,
        "",
        "POST",
        "auth/token/renew-self",
        json!({}),
        160,
    );
    assert_eq!(renewed.body["auth"]["lease_duration"], 10);
    assert!(state.authenticate(&raw, 170).is_err());
    let raw = token(
        &mut state,
        &root,
        "",
        json!({"policies": ["default"], "ttl": 20, "renewable": false}),
        100,
    );
    let actor = state.authenticate(&raw, 110).unwrap();
    assert!(
        state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/token/renew-self",
                &json!({}),
                110
            )
            .is_err()
    );
}

#[test]
fn actual_userpass_login_rotation_and_serde_restart() {
    let (mut state, _, root) = setup();
    let password = "correct-horse-battery-staple";
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/userpass/users/alice",
        json!({"password": password, "token_ttl": 15, "token_num_uses": 1}),
        100,
    );
    let saved = serde_json::to_string(&state).unwrap();
    assert!(!saved.contains(password));
    state = serde_json::from_str(&saved).unwrap();
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/userpass/login/alice",
                &json!({"password": "wrong-password"}),
                101
            )
            .is_err()
    );
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/userpass/login/unknown",
                &json!({"password": password}),
                101
            )
            .is_err()
    );
    assert!(
        state
            .handle(
                None,
                "",
                "POST",
                "auth/userpass/login/alice",
                &json!({"password": password}),
                101
            )
            .is_err()
    );
    let login = state
        .handle(
            None,
            "team",
            "POST",
            "auth/userpass/login/alice",
            &json!({"password": password}),
            101,
        )
        .unwrap()
        .unwrap();
    let raw = login.body["auth"]["client_token"].as_str().unwrap();
    let actor = state.authenticate(raw, 102).unwrap();
    state
        .authorize_for_unit_test(&actor, "team", "auth/token/lookup-self", "read")
        .unwrap();
    assert!(state.authenticate(raw, 103).is_err());
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/userpass/users/alice/password",
        json!({"password": "rotated-correct-password"}),
        104,
    );
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/userpass/login/alice",
                &json!({"password": password}),
                105
            )
            .is_err()
    );
    let new_login = state
        .handle(
            None,
            "team",
            "POST",
            "auth/userpass/login/alice",
            &json!({"password": "rotated-correct-password"}),
            105,
        )
        .unwrap()
        .unwrap();
    assert!(
        state
            .authenticate(
                new_login.body["auth"]["client_token"].as_str().unwrap(),
                120
            )
            .is_err()
    );
}

#[test]
fn approle_secret_ids_are_hashed_consumable_and_expiring() {
    let (mut state, _, root) = setup();
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/approle/role/hepta",
        json!({"secret_id_ttl": 10, "secret_id_num_uses": 2, "token_ttl": 20}),
        100,
    );
    let role_id = call(
        &mut state,
        &root,
        "team",
        "GET",
        "auth/approle/role/hepta/role-id",
        json!({}),
        100,
    )
    .body["data"]["role_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let secret = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/approle/role/hepta/secret-id",
        json!({}),
        100,
    )
    .body["data"]["secret_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let serialized = serde_json::to_string(&state).unwrap();
    assert!(!serialized.contains(&secret));
    state = serde_json::from_str(&serialized).unwrap();
    let body = json!({"role_id": role_id, "secret_id": secret});
    assert!(
        state
            .handle(None, "", "POST", "auth/approle/login", &body, 101)
            .is_err()
    );
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/approle/login",
                &json!({"role_id": role_id, "secret_id": "wrong"}),
                101
            )
            .is_err()
    );
    let login = state
        .handle(None, "team", "POST", "auth/approle/login", &body, 101)
        .unwrap()
        .unwrap();
    let raw = login.body["auth"]["client_token"].as_str().unwrap();
    assert!(state.authenticate(raw, 102).is_ok());
    assert!(
        state
            .handle(None, "team", "POST", "auth/approle/login", &body, 102)
            .is_ok()
    );
    assert!(
        state
            .handle(None, "team", "POST", "auth/approle/login", &body, 103)
            .is_err()
    );
    let secret2 = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/approle/role/hepta/secret-id",
        json!({}),
        100,
    )
    .body["data"]["secret_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/approle/login",
                &json!({"role_id": role_id, "secret_id": secret2}),
                110
            )
            .is_err()
    );
}

#[test]
fn approle_custom_secret_id_is_bounded_hashed_and_consumable() {
    let (mut state, _, root) = setup();
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/approle/role/custom",
        json!({"secret_id_ttl": 30, "secret_id_num_uses": 2}),
        100,
    );
    let role_id = call(
        &mut state,
        &root,
        "team",
        "GET",
        "auth/approle/role/custom/role-id",
        json!({}),
        100,
    )
    .body["data"]["role_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let secret_id = "operator-issued-secret";
    let issued = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/approle/role/custom/custom-secret-id",
        json!({"secret_id": secret_id}),
        100,
    );
    assert_eq!(issued.body["data"]["secret_id"], secret_id);
    assert_eq!(issued.body["data"]["secret_id_num_uses"], 2);
    assert_eq!(issued.body["data"]["secret_id_ttl"], 30);
    let serialized = serde_json::to_string(&state).unwrap();
    assert!(!serialized.contains(secret_id));

    let login_body = json!({"role_id": role_id, "secret_id": secret_id});
    assert!(
        state
            .handle(None, "team", "POST", "auth/approle/login", &login_body, 101)
            .is_ok()
    );
    assert!(
        state
            .handle(None, "team", "POST", "auth/approle/login", &login_body, 102)
            .is_ok()
    );
    assert!(
        state
            .handle(None, "team", "POST", "auth/approle/login", &login_body, 103)
            .is_err()
    );

    let duplicate = state.handle(
        Some(&root),
        "team",
        "POST",
        "auth/approle/role/custom/custom-secret-id",
        &json!({"secret_id": secret_id}),
        104,
    );
    assert_eq!(
        duplicate
            .err()
            .expect("duplicate custom secret ID must fail")
            .status,
        400
    );
    let invalid = state.handle(
        Some(&root),
        "team",
        "POST",
        "auth/approle/role/custom/custom-secret-id",
        &json!({"secret_id": "", "unexpected": true}),
        104,
    );
    assert_eq!(
        invalid
            .err()
            .expect("invalid custom secret ID must fail")
            .status,
        400
    );
}

#[test]
fn approle_periodic_role_issues_fixed_period_tokens() {
    let (mut state, _, root) = setup();
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/approle/role/periodic",
        json!({"token_period": 15, "token_ttl": 5, "secret_id_num_uses": 0}),
        100,
    );
    let role = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/approle/role/periodic",
        json!({}),
        100,
    );
    assert_eq!(role.body["data"]["token_period"], 15);
    let role_id = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/approle/role/periodic/role-id",
        json!({}),
        100,
    )
    .body["data"]["role_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let secret = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/approle/role/periodic/secret-id",
        json!({"num_uses": 0}),
        100,
    )
    .body["data"]["secret_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let login = state
        .handle(
            None,
            "",
            "POST",
            "auth/approle/login",
            &json!({"role_id": role_id, "secret_id": secret}),
            100,
        )
        .unwrap()
        .unwrap();
    assert_eq!(login.body["auth"]["lease_duration"], 15);
    assert_eq!(login.body["auth"]["renewable"], true);
    let token = login.body["auth"]["client_token"].as_str().unwrap();
    let actor = state.authenticate(token, 110).unwrap();
    let renewed = call(
        &mut state,
        &actor,
        "",
        "POST",
        "auth/token/renew-self",
        json!({"increment": 999}),
        110,
    );
    assert_eq!(renewed.body["auth"]["lease_duration"], 15);
    let actor = state.authenticate(token, 111).unwrap();
    let lookup = call(
        &mut state,
        &actor,
        "",
        "GET",
        "auth/token/lookup-self",
        json!({}),
        111,
    );
    assert_eq!(lookup.body["data"]["period"], 15);
    assert_eq!(lookup.body["data"]["explicit_max_ttl"], 0);
}

#[test]
fn approle_explicit_max_ttl_clamps_periodic_and_finite_tokens() {
    let (mut state, _, root) = setup();
    let configured = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/approle/role/capped",
        json!({
            "token_ttl": 30,
            "token_max_ttl": 60,
            "token_period": 15,
            "token_explicit_max_ttl": 20,
            "secret_id_num_uses": 0
        }),
        100,
    );
    assert_eq!(configured.status, 204);
    let role = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/approle/role/capped",
        json!({}),
        100,
    );
    assert_eq!(role.body["data"]["token_explicit_max_ttl"], 20);
    assert_eq!(role.body["data"]["period"], 15);
    let role_id = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/approle/role/capped/role-id",
        json!({}),
        100,
    )
    .body["data"]["role_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let secret = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/approle/role/capped/secret-id",
        json!({"num_uses": 0}),
        100,
    )
    .body["data"]["secret_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let login = state
        .handle(
            None,
            "",
            "POST",
            "auth/approle/login",
            &json!({"role_id": role_id, "secret_id": secret}),
            100,
        )
        .unwrap()
        .unwrap();
    assert_eq!(login.body["auth"]["lease_duration"], 15);
    let token = login.body["auth"]["client_token"].as_str().unwrap();

    let actor = state.authenticate(token, 110).unwrap();
    let renewed = call(
        &mut state,
        &actor,
        "",
        "POST",
        "auth/token/renew-self",
        json!({"increment": 999}),
        110,
    );
    assert_eq!(renewed.body["auth"]["lease_duration"], 10);
    assert!(state.authenticate(token, 120).is_err());

    let finite = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/approle/role/finite-capped",
        json!({
            "token_ttl": 30,
            "token_max_ttl": 60,
            "token_explicit_max_ttl": 20,
            "secret_id_num_uses": 0
        }),
        100,
    );
    assert_eq!(finite.status, 204);
    let finite_role_id = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/approle/role/finite-capped/role-id",
        json!({}),
        100,
    )
    .body["data"]["role_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let finite_secret = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/approle/role/finite-capped/secret-id",
        json!({"num_uses": 0}),
        100,
    )
    .body["data"]["secret_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let finite_login = state
        .handle(
            None,
            "",
            "POST",
            "auth/approle/login",
            &json!({"role_id": finite_role_id, "secret_id": finite_secret}),
            100,
        )
        .unwrap()
        .unwrap();
    assert_eq!(finite_login.body["auth"]["lease_duration"], 20);
    let finite_token = finite_login.body["auth"]["client_token"].as_str().unwrap();
    assert!(state.authenticate(finite_token, 120).is_err());

    let rejected = state.handle(
        Some(&root),
        "",
        "POST",
        "auth/approle/role/too-large",
        &json!({"token_explicit_max_ttl": 32 * 24 * 3600 + 1}),
        100,
    );
    assert_eq!(rejected.err().unwrap().status, 400);
}

#[test]
fn approle_renewal_reloads_live_role_mount_and_survives_restart() {
    let (mut state, root_raw, root) = setup();
    mount_auth(&mut state, &root, "team", "build", "approle");
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/build/role/service",
        json!({
            "token_ttl": 30,
            "token_max_ttl": 90,
            "secret_id_num_uses": 0,
            "policies": ["default"]
        }),
        100,
    );
    let role_id = call(
        &mut state,
        &root,
        "team",
        "GET",
        "auth/build/role/service/role-id",
        json!({}),
        100,
    )
    .body["data"]["role_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let secret_id = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/build/role/service/secret-id",
        json!({"num_uses": 0}),
        100,
    )
    .body["data"]["secret_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let login = state
        .handle(
            None,
            "team",
            "POST",
            "auth/build/login",
            &json!({"role_id": role_id, "secret_id": secret_id}),
            100,
        )
        .unwrap()
        .unwrap();
    let raw = login.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let id = hash(&raw);
    assert!(matches!(
        state.tokens[&id].auth_provenance.as_ref(),
        Some(TokenAuthProvenance::AppRole { role_name }) if role_name == "service"
    ));

    // A restart must preserve the issuer binding without ever persisting the
    // bearer or allowing display_name to stand in for role identity.
    let saved = serde_json::to_string(&state).unwrap();
    assert!(!saved.contains(&raw));
    assert!(saved.contains("auth_provenance"));
    let mut restarted: AuthState = serde_json::from_str(&saved).unwrap();
    let restarted_root = restarted.authenticate(&root_raw, 105).unwrap();
    put_policy(
        &mut restarted,
        &restarted_root,
        "team",
        "changed",
        json!(r#"path "secret/data/*" { capabilities = ["read"] }"#),
    );
    // Change the role's policies and finite bounds after issuance. Renewal
    // keeps the token's original policies, but uses current TTL/max settings.
    call(
        &mut restarted,
        &restarted_root,
        "team",
        "POST",
        "auth/build/role/service",
        json!({"token_ttl": 10, "token_max_ttl": 20, "policies": ["changed"]}),
        110,
    );
    let actor = restarted.authenticate(&raw, 110).unwrap();
    let renewed = call(
        &mut restarted,
        &actor,
        "team",
        "POST",
        "auth/token/renew-self",
        json!({"increment": 0}),
        110,
    );
    assert_eq!(renewed.body["auth"]["lease_duration"], 10);
    assert_eq!(renewed.body["auth"]["policies"], json!(["default"]));

    // A current role max is an absolute lifetime from issue, not a new window
    // beginning at each renewal. The 20-second cap therefore leaves 10 seconds.
    let actor = restarted.authenticate(&raw, 115).unwrap();
    let renewed = call(
        &mut restarted,
        &actor,
        "team",
        "POST",
        "auth/token/renew-self",
        json!({"increment": 999}),
        115,
    );
    assert_eq!(renewed.body["auth"]["lease_duration"], 5);

    // Deleting the live role fences an already-issued token at renewal.
    call(
        &mut restarted,
        &restarted_root,
        "team",
        "DELETE",
        "auth/build/role/service",
        json!({}),
        116,
    );
    let actor = restarted.authenticate(&raw, 116).unwrap();
    let denied = restarted.handle(
        Some(&actor),
        "team",
        "POST",
        "auth/token/renew-self",
        &json!({"increment": 1}),
        116,
    );
    assert!(matches!(denied, Err(error) if error.status == 500));
}

#[test]
fn approle_periodic_renewal_uses_current_mount_bound_and_children_are_ordinary() {
    let (mut state, _, root) = setup();
    mount_auth(&mut state, &root, "team", "build", "approle");
    put_policy(
        &mut state,
        &root,
        "team",
        "issuer",
        json!(r#"path "auth/token/create*" { capabilities = ["update"] }"#),
    );
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/build/role/periodic",
        json!({"token_period": 50, "token_ttl": 5, "secret_id_num_uses": 0, "policies": ["issuer"]}),
        100,
    );
    let role_id = call(
        &mut state,
        &root,
        "team",
        "GET",
        "auth/build/role/periodic/role-id",
        json!({}),
        100,
    )
    .body["data"]["role_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let secret_id = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/build/role/periodic/secret-id",
        json!({"num_uses": 0}),
        100,
    )
    .body["data"]["secret_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let login = state
        .handle(
            None,
            "team",
            "POST",
            "auth/build/login",
            &json!({"role_id": role_id, "secret_id": secret_id}),
            100,
        )
        .unwrap()
        .unwrap();
    let raw = login.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let actor = state.authenticate(&raw, 101).unwrap();
    let child = token(
        &mut state,
        &actor,
        "team",
        json!({"policies": ["default"]}),
        101,
    );
    assert!(matches!(
        state.tokens[&hash(&child)].auth_provenance,
        Some(TokenAuthProvenance::TokenApi)
    ));

    // The role's period is 50, but tuning the issuing mount to 20 clamps the
    // next renewal without changing the already-issued token's policies.
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "sys/auth/build/tune",
        json!({"default_lease_ttl": 10, "max_lease_ttl": 20}),
        105,
    );
    let actor = state.authenticate(&raw, 110).unwrap();
    let renewed = call(
        &mut state,
        &actor,
        "team",
        "POST",
        "auth/token/renew-self",
        json!({"increment": 999}),
        110,
    );
    assert_eq!(renewed.body["auth"]["lease_duration"], 20);

    // The token API child follows ordinary token renewal and is not coupled to
    // the AppRole's current period or role deletion.
    let child_actor = state.authenticate(&child, 110).unwrap();
    let child_renewed = call(
        &mut state,
        &child_actor,
        "team",
        "POST",
        "auth/token/renew-self",
        json!({"increment": 7}),
        110,
    );
    assert_eq!(child_renewed.body["auth"]["lease_duration"], 7);
}

#[test]
fn approle_destroy_and_policy_assignment_fail_closed() {
    let (mut state, _, root) = setup();
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/approle/role/no-secret",
        json!({"bind_secret_id": false}),
        100,
    );
    let no_secret_role_id = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/approle/role/no-secret/role-id",
        json!({}),
        100,
    )
    .body["data"]["role_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let no_secret_role = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/approle/role/no-secret",
        json!({}),
        100,
    );
    assert_eq!(no_secret_role.body["data"]["bind_secret_id"], false);
    let no_secret_login = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/approle/login",
        json!({"role_id": no_secret_role_id}),
        101,
    );
    assert!(
        no_secret_login.body["auth"]["client_token"]
            .as_str()
            .is_some()
    );
    assert!(
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "auth/approle/role/bad",
                &json!({"token_policies": ["root"]}),
                100
            )
            .is_err()
    );
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/approle/role/hepta",
        json!({}),
        100,
    );
    let role_id = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/approle/role/hepta/role-id",
        json!({}),
        100,
    )
    .body["data"]["role_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let created = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/approle/role/hepta/secret-id",
        json!({}),
        100,
    );
    let accessor = created.body["data"]["secret_id_accessor"].as_str().unwrap();
    let raw = created.body["data"]["secret_id"].as_str().unwrap();
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/approle/role/hepta/secret-id-accessor/destroy",
        json!({"secret_id_accessor": accessor}),
        101,
    );
    assert!(
        state
            .handle(
                None,
                "",
                "POST",
                "auth/approle/login",
                &json!({"role_id": role_id, "secret_id": raw}),
                102
            )
            .is_err()
    );
    assert!(
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "auth/approle/role/hepta/secret-id",
                &json!({"num_uses": 0}),
                102
            )
            .is_err()
    );
}

#[test]
fn transaction_clone_failure_does_not_consume_source_state() {
    let (mut state, _, root) = setup();
    let raw = token(
        &mut state,
        &root,
        "",
        json!({"policies": ["default"], "num_uses": 1}),
        100,
    );
    let persisted = serde_json::to_vec(&state).unwrap();
    let mut candidate = state.clone();
    candidate.authenticate(&raw, 101).unwrap();
    assert!(candidate.authenticate(&raw, 102).is_err());
    // Model failed durable commit: discard the candidate, retain old state.
    assert_eq!(serde_json::to_vec(&state).unwrap(), persisted);
    assert!(state.authenticate(&raw, 102).is_ok());
}

#[test]
fn accessors_allow_revocation_without_revealing_token() {
    let (mut state, _, root) = setup();
    let raw = token(&mut state, &root, "", json!({"policies": ["default"]}), 100);
    let actor = state.authenticate(&raw, 101).unwrap();
    let lookup = call(
        &mut state,
        &actor,
        "",
        "GET",
        "auth/token/lookup-self",
        json!({}),
        101,
    );
    assert!(!lookup.body.to_string().contains(&raw));
    let accessor = lookup.body["data"]["accessor"].as_str().unwrap();
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/revoke-accessor",
        json!({"accessor": accessor}),
        102,
    );
    assert!(state.authenticate(&raw, 103).is_err());
}

#[test]
fn userpass_totp_mfa_is_required_replay_safe_and_restart_persistent() {
    let (mut state, _, root) = setup();
    let password = "correct-horse-battery-staple";
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/userpass/users/alice",
        json!({"password": password, "token_ttl": 60}),
        100,
    );
    let enrollment = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/userpass/users/alice/mfa",
        json!({}),
        100,
    );
    let exported_secret = enrollment.body["data"]["secret_base32"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(enrollment.body["data"]["algorithm"], "SHA256");
    assert_eq!(enrollment.body["data"]["digits"], 6);
    assert_eq!(enrollment.body["data"]["period"], 30);
    let secret = state.users["team"]["alice"]
        .mfa
        .as_ref()
        .unwrap()
        .secret
        .clone();
    assert_eq!(exported_secret, base32_no_padding(&secret));

    for body in [
        json!({"password": password}),
        json!({"password": password, "totp_code": "000000"}),
        json!({"password": password, "totp_code": 123456}),
    ] {
        assert!(
            state
                .handle(
                    None,
                    "team",
                    "POST",
                    "auth/userpass/login/alice",
                    &body,
                    120,
                )
                .is_err()
        );
    }

    let code = std::str::from_utf8(&totp_code(&secret, 120 / MFA_PERIOD_SECONDS))
        .unwrap()
        .to_owned();
    let login = state
        .handle(
            None,
            "team",
            "POST",
            "auth/userpass/login/alice",
            &json!({"password": password, "totp_code": code}),
            120,
        )
        .unwrap()
        .unwrap();
    assert!(login.body["auth"]["client_token"].as_str().is_some());

    let saved = serde_json::to_string(&state).unwrap();
    assert!(!saved.contains(&exported_secret));
    let mut restarted: AuthState = serde_json::from_str(&saved).unwrap();
    assert!(
        restarted
            .handle(
                None,
                "team",
                "POST",
                "auth/userpass/login/alice",
                &json!({"password": password, "totp_code": code}),
                121,
            )
            .is_err()
    );
    let next = std::str::from_utf8(&totp_code(&secret, 150 / MFA_PERIOD_SECONDS))
        .unwrap()
        .to_owned();
    assert!(
        restarted
            .handle(
                None,
                "team",
                "POST",
                "auth/userpass/login/alice",
                &json!({"password": password, "totp_code": next}),
                150,
            )
            .is_ok()
    );
}

#[test]
fn totp_mfa_reset_is_explicit_sudo_only_and_status_never_returns_seed() {
    let (mut state, _, root) = setup();
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/userpass/users/alice",
        json!({"password": "correct-horse-battery-staple"}),
        100,
    );
    let first = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/userpass/users/alice/mfa",
        json!({}),
        100,
    );
    let first_seed = first.body["data"]["secret_base32"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        state
            .handle(
                Some(&root),
                "team",
                "POST",
                "auth/userpass/users/alice/mfa",
                &json!({}),
                101,
            )
            .is_err()
    );
    let status = call(
        &mut state,
        &root,
        "team",
        "GET",
        "auth/userpass/users/alice/mfa",
        json!({}),
        101,
    );
    assert_eq!(status.body["data"]["enabled"], true);
    assert!(status.body["data"].get("secret_base32").is_none());

    put_policy(
        &mut state,
        &root,
        "team",
        "mfa-manager",
        json!(
            r#"path "auth/userpass/users/+/mfa" { capabilities = ["read", "update", "delete"] }"#
        ),
    );
    let manager_raw = token(
        &mut state,
        &root,
        "team",
        json!({"policies": ["mfa-manager"]}),
        101,
    );
    let manager = state.authenticate(&manager_raw, 102).unwrap();
    for (method, body) in [("POST", json!({"regenerate": true})), ("DELETE", json!({}))] {
        assert!(
            state
                .handle(
                    Some(&manager),
                    "team",
                    method,
                    "auth/userpass/users/alice/mfa",
                    &body,
                    102,
                )
                .is_err()
        );
    }

    let replacement = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/userpass/users/alice/mfa",
        json!({"regenerate": true}),
        103,
    );
    let replacement_seed = replacement.body["data"]["secret_base32"].as_str().unwrap();
    assert_ne!(first_seed, replacement_seed);
    call(
        &mut state,
        &root,
        "team",
        "DELETE",
        "auth/userpass/users/alice/mfa",
        json!({}),
        104,
    );
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/userpass/login/alice",
                &json!({"password": "correct-horse-battery-staple"}),
                105,
            )
            .is_ok()
    );
}

#[test]
fn totp_mfa_rejects_clock_rollback_after_future_window_acceptance() {
    let (mut state, _, root) = setup();
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/userpass/users/alice",
        json!({"password": "correct-horse-battery-staple"}),
        100,
    );
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/userpass/users/alice/mfa",
        json!({}),
        100,
    );
    let secret = state.users["team"]["alice"]
        .mfa
        .as_ref()
        .unwrap()
        .secret
        .clone();
    let future_counter = 151 / MFA_PERIOD_SECONDS;
    let future = std::str::from_utf8(&totp_code(&secret, future_counter))
        .unwrap()
        .to_owned();
    state
        .handle(
            None,
            "team",
            "POST",
            "auth/userpass/login/alice",
            &json!({"password": "correct-horse-battery-staple", "totp_code": future}),
            121,
        )
        .unwrap();
    let current = std::str::from_utf8(&totp_code(&secret, 121 / MFA_PERIOD_SECONDS))
        .unwrap()
        .to_owned();
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/userpass/login/alice",
                &json!({"password": "correct-horse-battery-staple", "totp_code": current}),
                121,
            )
            .is_err()
    );
}

#[test]
fn administrative_tidy_frees_only_inactive_credentials_in_its_namespace() {
    let (mut state, _, root) = setup();
    let expired = token(
        &mut state,
        &root,
        "team",
        json!({"policies": ["default"], "ttl": 5}),
        100,
    );
    let exhausted = token(
        &mut state,
        &root,
        "team",
        json!({"policies": ["default"], "num_uses": 1}),
        100,
    );
    state.authenticate(&exhausted, 101).unwrap();
    let active = token(
        &mut state,
        &root,
        "team",
        json!({"policies": ["default"]}),
        100,
    );
    let other = token(
        &mut state,
        &root,
        "other",
        json!({"policies": ["default"], "ttl": 5}),
        100,
    );
    let result = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/token/tidy",
        json!({}),
        110,
    );
    assert_eq!(result.body["data"]["removed_tokens"], 2);
    assert!(!state.tokens.contains_key(&hash(&expired)));
    assert!(!state.tokens.contains_key(&hash(&exhausted)));
    assert!(state.tokens.contains_key(&hash(&other)));
    assert!(state.authenticate(&active, 111).is_ok());
    let actor = state.authenticate(&active, 111).unwrap();
    assert!(
        state
            .handle(
                Some(&actor),
                "team",
                "POST",
                "auth/token/tidy",
                &json!({}),
                111
            )
            .is_err()
    );
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/approle/role/hepta",
        json!({"secret_id_ttl": 5}),
        100,
    );
    let expired_secret = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/approle/role/hepta/secret-id",
        json!({}),
        100,
    )
    .body["data"]["secret_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let active_secret = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/approle/role/hepta/secret-id",
        json!({}),
        110,
    )
    .body["data"]["secret_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let result = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/approle/tidy/secret-id",
        json!({}),
        111,
    );
    assert_eq!(result.body["data"]["removed_secret_ids"], 1);
    let stored = &state.roles["team"]["hepta"].secret_ids;
    assert!(!stored.contains_key(&hash(&expired_secret)));
    assert!(stored.contains_key(&hash(&active_secret)));
}

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

    let policy_bound_raw = token(&mut state, &root, "", json!({"policies": ["reader"]}), 300);
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

#[test]
fn auth_mount_registry_is_persistent_sudo_gated_and_fail_closed() {
    let (mut state, _, root) = setup();
    let listed = call(&mut state, &root, "", "GET", "sys/auth", json!({}), 100);
    assert_eq!(listed.status, 200);
    assert_eq!(listed.body["data"]["token/"]["type"], "token");
    assert_eq!(listed.body["data"]["userpass/"]["type"], "userpass");
    assert_eq!(listed.body["data"]["approle/"]["type"], "approle");

    let disabled = call(
        &mut state,
        &root,
        "",
        "DELETE",
        "sys/auth/userpass",
        json!({}),
        100,
    );
    assert_eq!(disabled.status, 204);
    assert!(
        state
            .handle(
                None,
                "",
                "POST",
                "auth/userpass/login/alice",
                &json!({"password":"x"}),
                101
            )
            .is_err_and(|error| error.status == 404)
    );

    let saved = serde_json::to_string(&state).unwrap();
    let mut restarted: AuthState = serde_json::from_str(&saved).unwrap();
    assert!(
        restarted
            .handle(
                None,
                "",
                "POST",
                "auth/userpass/login/alice",
                &json!({"password":"x"}),
                101
            )
            .is_err_and(|error| error.status == 404)
    );

    let enabled = call(
        &mut restarted,
        &root,
        "",
        "POST",
        "sys/auth/userpass",
        json!({"type":"userpass","description":"synthetic userpass"}),
        102,
    );
    assert_eq!(enabled.status, 204);
    let descriptor = call(
        &mut restarted,
        &root,
        "",
        "GET",
        "sys/auth/userpass",
        json!({}),
        102,
    );
    assert_eq!(descriptor.body["data"]["type"], "userpass");
    assert_eq!(descriptor.body["data"]["description"], "synthetic userpass");

    assert!(
        restarted
            .handle(
                Some(&root),
                "",
                "POST",
                "sys/auth/team-login",
                &json!({"type":"userpass"}),
                103,
            )
            .is_ok_and(|response| response.is_some_and(|response| response.status == 204))
    );
    assert!(
        restarted
            .handle(Some(&root), "", "DELETE", "sys/auth/token", &json!({}), 103,)
            .is_err()
    );
}

#[test]
fn auth_mount_registry_requires_sudo_for_mutation() {
    let (mut state, _, root) = setup();
    let raw = token(&mut state, &root, "", json!({"policies":["default"]}), 100);
    let actor = state.authenticate(&raw, 101).unwrap();
    assert!(
        state
            .handle(
                Some(&actor),
                "",
                "DELETE",
                "sys/auth/userpass",
                &json!({}),
                101,
            )
            .is_err()
    );
    assert!(state.auth_mount_enabled("", "userpass", "userpass"));
}

#[test]
fn certificate_role_login_requires_the_verified_leaf_digest() {
    let (mut state, _raw, root) = setup();
    mount_auth(&mut state, &root, "", "cert", "cert");
    let leaf = vec![1_u8, 2, 3, 4];
    let digest = certificate_sha256(&leaf);
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/cert/certs/operator",
        json!({
            "certificate_sha256": digest,
            "token_policies": ["default"],
        }),
        100,
    );

    let no_peer = state.handle_with_client_certificates(
        None,
        "",
        "POST",
        "auth/cert/login",
        &json!({}),
        101,
        None,
    );
    assert!(matches!(no_peer, Err(error) if error.status == 403));

    let wrong_leaf = vec![9_u8, 8, 7, 6];
    let wrong = state.handle_with_client_certificates(
        None,
        "",
        "POST",
        "auth/cert/login",
        &json!({}),
        101,
        Some(std::slice::from_ref(&wrong_leaf)),
    );
    assert!(matches!(wrong, Err(error) if error.status == 403));

    let login = state
        .handle_with_client_certificates(
            None,
            "",
            "POST",
            "auth/cert/login",
            &json!({}),
            101,
            Some(std::slice::from_ref(&leaf)),
        )
        .unwrap()
        .unwrap();
    assert_eq!(login.status, 200);
    assert_eq!(login.login_identity.unwrap().alias, "operator");
    assert!(
        login.body["auth"]["metadata"]
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    );
}

#[test]
fn certificate_role_login_name_selects_the_requested_matching_role() {
    let (mut state, _raw, root) = setup();
    mount_auth(&mut state, &root, "", "cert", "cert");
    let leaf = vec![11_u8, 12, 13, 14];
    let digest = certificate_sha256(&leaf);
    for role in ["operator", "reader"] {
        call(
            &mut state,
            &root,
            "",
            "POST",
            &format!("auth/cert/certs/{role}"),
            json!({
                "certificate_sha256": digest,
                "token_policies": ["default"],
            }),
            100,
        );
    }

    let selected = state
        .handle_with_client_certificates(
            None,
            "",
            "POST",
            "auth/cert/login",
            &json!({"name": "reader"}),
            101,
            Some(std::slice::from_ref(&leaf)),
        )
        .unwrap()
        .unwrap();
    assert_eq!(selected.status, 200);
    assert_eq!(selected.login_identity.unwrap().alias, "reader");

    let unknown = state.handle_with_client_certificates(
        None,
        "",
        "POST",
        "auth/cert/login",
        &json!({"name": "missing"}),
        101,
        Some(std::slice::from_ref(&leaf)),
    );
    assert!(matches!(unknown, Err(error) if error.status == 403));

    let malformed = state.handle_with_client_certificates(
        None,
        "",
        "POST",
        "auth/cert/login",
        &json!({"name": "bad/name"}),
        101,
        Some(std::slice::from_ref(&leaf)),
    );
    assert!(matches!(malformed, Err(error) if error.status == 400));
}

#[test]
fn certificate_role_selectors_match_sans_subject_and_metadata() {
    let (mut state, _raw, root) = setup();
    mount_auth(&mut state, &root, "", "cert", "cert");
    let leaf = include_bytes!("../testdata/cert-selector.der").to_vec();
    let digest = certificate_sha256(&leaf);
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/cert/certs/operator",
        json!({
            "certificate_sha256": digest,
            "allowed_names": ["client.*"],
            "allowed_common_names": ["client.example.test"],
            "allowed_dns_sans": ["client.example.test"],
            "allowed_email_sans": ["user@*example.test"],
            "allowed_uri_sans": ["spiffe://example/*"],
            "allowed_organizational_units": ["Eng*"],
            "required_extensions": ["1.2.3.4.5:tenant-*"],
            "allowed_metadata_extensions": ["1.2.3.4.5"],
            "token_policies": ["default"],
        }),
        100,
    );
    let login = state
        .handle_with_client_certificates(
            None,
            "",
            "POST",
            "auth/cert/login",
            &json!({}),
            101,
            Some(std::slice::from_ref(&leaf)),
        )
        .unwrap()
        .unwrap();
    assert_eq!(login.login_identity.unwrap().alias, "client.example.test");
    assert_eq!(login.body["auth"]["metadata"]["1-2-3-4-5"], "tenant-a");
    assert_eq!(login.body["auth"]["metadata"]["cert_name"], "operator");
    assert_eq!(
        login.body["auth"]["metadata"]["common_name"],
        "client.example.test"
    );
    assert_eq!(
        login.body["auth"]["metadata"]["serial_number"],
        "604808306919950594911996544712097931612123050017"
    );
    assert_eq!(
        login.body["auth"]["metadata"]["subject_key_id"],
        "42:90:9c:3f:b0:be:cd:25:b9:7d:58:c7:f6:1e:a9:46:85:9d:66:5b"
    );
    assert_eq!(login.body["auth"]["metadata"]["authority_key_id"], "");
    let raw = login.body["auth"]["client_token"]
        .as_str()
        .expect("certificate login returns a token")
        .to_owned();
    let actor = state.authenticate(&raw, 101).unwrap();
    let renewal_without_certificate = state.handle(
        Some(&actor),
        "",
        "POST",
        "auth/token/renew-self",
        &json!({}),
        102,
    );
    assert!(matches!(renewal_without_certificate, Err(error) if error.status == 400));
    let wrong_leaf = vec![91_u8, 92, 93];
    let renewal_with_wrong_certificate = state.handle_with_client_certificates(
        Some(&actor),
        "",
        "POST",
        "auth/token/renew-self",
        &json!({}),
        102,
        Some(std::slice::from_ref(&wrong_leaf)),
    );
    assert!(matches!(renewal_with_wrong_certificate, Err(error) if error.status == 403));
    let renewal = state
        .handle_with_client_certificates(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({}),
            102,
            Some(std::slice::from_ref(&leaf)),
        )
        .unwrap()
        .unwrap();
    assert_eq!(renewal.status, 200);

    call(
        &mut state,
        &root,
        "",
        "PUT",
        "auth/cert/certs/operator",
        json!({
            "certificate_sha256": certificate_sha256(&leaf),
            "allowed_names": ["client?.example.test"],
            "token_policies": ["default"],
        }),
        102,
    );
    let literal_question_mark = state.handle_with_client_certificates(
        None,
        "",
        "POST",
        "auth/cert/login",
        &json!({}),
        103,
        Some(std::slice::from_ref(&leaf)),
    );
    assert!(matches!(literal_question_mark, Err(error) if error.status == 403));
    let renewal_after_selector_change = state.handle_with_client_certificates(
        Some(&actor),
        "",
        "POST",
        "auth/token/renew-self",
        &json!({}),
        104,
        Some(std::slice::from_ref(&leaf)),
    );
    assert!(matches!(renewal_after_selector_change, Err(error) if error.status == 403));

    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "DELETE",
            "auth/cert/certs/operator",
            json!({}),
            104,
        )
        .status,
        204
    );
    let renewal_after_role_delete = state.handle(
        Some(&actor),
        "",
        "POST",
        "auth/token/renew-self",
        &json!({}),
        105,
    );
    assert!(matches!(renewal_after_role_delete, Err(error) if error.status == 403));
}

fn mount_auth(state: &mut AuthState, root: &Principal, namespace: &str, mount: &str, kind: &str) {
    assert_eq!(
        call(
            state,
            root,
            namespace,
            "POST",
            &format!("sys/auth/{mount}"),
            json!({"type":kind}),
            100
        )
        .status,
        204
    );
}

fn userpass_login(
    state: &mut AuthState,
    namespace: &str,
    mount: &str,
    password: &str,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(
            None,
            namespace,
            "POST",
            &format!("auth/{mount}/login/alice"),
            &json!({"password":password}),
            101,
        )?
        .ok_or_else(denied)
}

#[test]
fn custom_userpass_mounts_isolate_credentials_namespaces_and_real_acl_paths() {
    let (mut state, _, root) = setup();
    for (ns, mount, password) in [
        ("team", "staff", "synthetic-staff-password"),
        ("team", "external/users", "synthetic-external-password"),
        ("other", "staff", "synthetic-other-password"),
    ] {
        mount_auth(&mut state, &root, ns, mount, "userpass");
        call(
            &mut state,
            &root,
            ns,
            "POST",
            &format!("auth/{mount}/users/alice"),
            json!({"password":password}),
            100,
        );
    }
    assert!(userpass_login(&mut state, "team", "staff", "synthetic-staff-password").is_ok());
    assert!(userpass_login(&mut state, "team", "staff", "synthetic-external-password").is_err());
    assert!(userpass_login(&mut state, "other", "staff", "synthetic-staff-password").is_err());
    assert!(
        userpass_login(
            &mut state,
            "team",
            "external/users",
            "synthetic-external-password"
        )
        .is_ok()
    );
    assert!(userpass_login(&mut state, "team", "userpass", "synthetic-staff-password").is_err());

    put_policy(
        &mut state,
        &root,
        "team",
        "staff-admin",
        json!(r#"path "auth/staff/users/*" { capabilities = ["read"] }"#),
    );
    let raw = token(
        &mut state,
        &root,
        "team",
        json!({"policies":["staff-admin"]}),
        100,
    );
    let admin = state.authenticate(&raw, 101).unwrap();
    assert!(
        state
            .handle(
                Some(&admin),
                "team",
                "GET",
                "auth/staff/users/alice",
                &json!({}),
                101
            )
            .is_ok()
    );
    assert!(
        state
            .handle(
                Some(&admin),
                "team",
                "GET",
                "auth/external/users/users/alice",
                &json!({}),
                101
            )
            .is_err()
    );
    assert!(
        state
            .handle(
                Some(&admin),
                "team",
                "GET",
                "auth/userpass/users/alice",
                &json!({}),
                101
            )
            .is_err()
    );

    let persisted = serde_json::to_vec(&state).unwrap();
    assert!(!String::from_utf8_lossy(&persisted).contains("synthetic-staff-password"));
    let mut state: AuthState = serde_json::from_slice(&persisted).unwrap();
    assert!(userpass_login(&mut state, "team", "staff", "synthetic-staff-password").is_ok());
    assert!(userpass_login(&mut state, "other", "staff", "synthetic-staff-password").is_err());
}

#[test]
fn disabling_auth_mount_revokes_its_tokens_and_children_and_erases_credentials() {
    let (mut state, root_raw, root) = setup();
    put_policy(
        &mut state,
        &root,
        "team",
        "issuer",
        json!(r#"path "auth/token/create" { capabilities = ["update"] }"#),
    );
    for mount in ["staff", "other"] {
        mount_auth(&mut state, &root, "team", mount, "userpass");
        call(
            &mut state,
            &root,
            "team",
            "POST",
            &format!("auth/{mount}/users/alice"),
            json!({"password":"synthetic-shared-password","token_policies":["issuer"]}),
            100,
        );
    }
    let raw = userpass_login(&mut state, "team", "staff", "synthetic-shared-password")
        .unwrap()
        .body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let other = userpass_login(&mut state, "team", "other", "synthetic-shared-password")
        .unwrap()
        .body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let actor = state.authenticate(&raw, 101).unwrap();
    let child = token(
        &mut state,
        &actor,
        "team",
        json!({"policies":["default"]}),
        101,
    );
    call(
        &mut state,
        &root,
        "team",
        "DELETE",
        "sys/auth/staff",
        json!({}),
        102,
    );
    assert!(state.authenticate(&raw, 103).is_err());
    assert!(state.authenticate(&child, 103).is_err());
    assert!(state.authenticate(&other, 103).is_ok());
    assert!(state.authenticate(&root_raw, 103).is_ok());
    mount_auth(&mut state, &root, "team", "staff", "userpass");
    assert!(userpass_login(&mut state, "team", "staff", "synthetic-shared-password").is_err());
    assert!(userpass_login(&mut state, "team", "other", "synthetic-shared-password").is_ok());
}

#[test]
fn custom_approle_mounts_isolate_role_ids_secret_ids_and_tidy() {
    let (mut state, _, root) = setup();
    let mut credentials = Vec::new();
    for mount in ["build", "deploy"] {
        mount_auth(&mut state, &root, "team", mount, "approle");
        call(
            &mut state,
            &root,
            "team",
            "POST",
            &format!("auth/{mount}/role/service"),
            json!({}),
            100,
        );
        call(
            &mut state,
            &root,
            "team",
            "POST",
            &format!("auth/{mount}/role/service/role-id"),
            json!({"role_id":"same-role-id-in-isolated-mounts"}),
            100,
        );
        credentials.push(
            call(
                &mut state,
                &root,
                "team",
                "POST",
                &format!("auth/{mount}/role/service/secret-id"),
                json!({}),
                100,
            )
            .body["data"]["secret_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/build/login",
                &json!({
        "role_id":"same-role-id-in-isolated-mounts", "secret_id":credentials[1]}),
                101
            )
            .is_err()
    );
    let result = state
        .handle(
            None,
            "team",
            "POST",
            "auth/build/login",
            &json!({
        "role_id":"same-role-id-in-isolated-mounts", "secret_id":credentials[0]}),
            101,
        )
        .unwrap()
        .unwrap();
    let raw = result.body["auth"]["client_token"].as_str().unwrap();
    assert_eq!(
        state.tokens[&hash(raw)].auth_mount.as_deref(),
        Some("build")
    );
    let tidied = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/build/tidy/secret-id",
        json!({}),
        101,
    );
    assert_eq!(tidied.body["data"]["removed_secret_ids"], 1);
    let mut state: AuthState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/deploy/login",
                &json!({
        "role_id":"same-role-id-in-isolated-mounts", "secret_id":credentials[1]}),
                101
            )
            .is_ok()
    );
    assert!(
        state
            .handle(
                None,
                "other",
                "POST",
                "auth/deploy/login",
                &json!({
        "role_id":"same-role-id-in-isolated-mounts", "secret_id":credentials[1]}),
                101
            )
            .is_err()
    );
}

#[test]
fn legacy_fixed_auth_state_survives_upgrade_and_unmount_fences_unattributed_tokens() {
    let (mut state, root_raw, root) = setup();
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/userpass/users/alice",
        json!({"password":"synthetic-legacy-password"}),
        100,
    );
    let legacy_raw = userpass_login(&mut state, "team", "userpass", "synthetic-legacy-password")
        .unwrap()
        .body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut old = serde_json::to_value(&state).unwrap();
    let object = old.as_object_mut().unwrap();
    object.remove("mounted_users");
    object.remove("mounted_roles");
    for token in object["tokens"].as_object_mut().unwrap().values_mut() {
        token.as_object_mut().unwrap().remove("auth_mount");
        token.as_object_mut().unwrap().remove("auth_origin_known");
    }
    let mut state: AuthState = serde_json::from_value(old).unwrap();
    assert!(state.authenticate(&legacy_raw, 101).is_ok());
    assert!(userpass_login(&mut state, "team", "userpass", "synthetic-legacy-password").is_ok());
    let directly_issued = token(
        &mut state,
        &root,
        "team",
        json!({"policies":["default"]}),
        101,
    );
    call(
        &mut state,
        &root,
        "team",
        "DELETE",
        "sys/auth/userpass",
        json!({}),
        102,
    );
    assert!(state.authenticate(&legacy_raw, 103).is_err());
    assert!(state.authenticate(&root_raw, 103).is_ok());
    assert!(state.authenticate(&directly_issued, 103).is_ok());
    mount_auth(&mut state, &root, "team", "userpass", "userpass");
    assert!(userpass_login(&mut state, "team", "userpass", "synthetic-legacy-password").is_err());
}

#[test]
fn auth_mount_replacement_and_overlapping_routes_fail_without_mutation() {
    let (mut state, _, root) = setup();
    mount_auth(&mut state, &root, "", "external/users", "userpass");
    let saved = serde_json::to_vec(&state).unwrap();
    for mount in ["token", "external", "external/users/sub", "external/users"] {
        assert!(
            state
                .handle(
                    Some(&root),
                    "",
                    "POST",
                    &format!("sys/auth/{mount}"),
                    &json!({"type":"approle"}),
                    101
                )
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), saved);
    }
}

fn jwt_config(public_key: &[u8], algorithm: &str) -> Value {
    json!({"issuer":"https://issuer.example", "audiences":["https://service.example/bao"],
        "required_namespace":"team", "clock_skew_seconds":0,
        "maximum_token_lifetime_seconds":3600,
        "keys":[{"kid":"key-1","algorithm":algorithm,"key_base64":URL_SAFE_NO_PAD.encode(public_key)}]})
}

fn jwt_claims(id: &str) -> Value {
    json!({"iss":"https://issuer.example", "sub":"alice", "aud":"https://service.example/bao",
        "iat":1000,"nbf":1000,"exp":1300,"jti":id,"heptabao_namespace":"team",
        "groups":["team/developers"]})
}

fn signed_jwt(pair: &ring::signature::Ed25519KeyPair, header: &Value, claims: &Value) -> String {
    let body = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    );
    format!(
        "{body}.{}",
        URL_SAFE_NO_PAD.encode(pair.sign(body.as_bytes()).as_ref())
    )
}

fn configured_jwt_mount(
    state: &mut AuthState,
    root: &Principal,
    mount: &str,
    public_key: &[u8],
    algorithm: &str,
) {
    mount_auth(state, root, "team", mount, "jwt");
    call(
        state,
        root,
        "team",
        "POST",
        &format!("auth/{mount}/config"),
        jwt_config(public_key, algorithm),
        1000,
    );
    call(
        state,
        root,
        "team",
        "POST",
        &format!("auth/{mount}/role/app"),
        json!({"token_policies":["reader"],"bound_subject":"alice","bound_groups":["team/developers"],
            "bound_audiences":["https://service.example/bao"],"token_ttl":600,"token_max_ttl":900}),
        1000,
    );
}

#[test]
fn jwt_login_composes_pinned_signature_policy_and_reusable_bearer_tokens() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let pair = Ed25519KeyPair::from_seed_unchecked(&[47; 32]).unwrap();
    let (mut state, _, root) = setup();
    put_policy(
        &mut state,
        &root,
        "team",
        "reader",
        json!(r#"path "secret/data/app" { capabilities = ["read"] }"#),
    );
    for mount in ["workload/ci", "workload/deploy"] {
        configured_jwt_mount(
            &mut state,
            &root,
            mount,
            pair.public_key().as_ref(),
            "EdDSA",
        );
    }
    let jwt = signed_jwt(
        &pair,
        &json!({"alg":"EdDSA","kid":"key-1","typ":"JWT"}),
        &jwt_claims("first"),
    );
    let request = json!({"role":"app","jwt":jwt});
    let result = state
        .handle(
            None,
            "team",
            "POST",
            "auth/workload/ci/login",
            &request,
            1050,
        )
        .unwrap()
        .unwrap();
    assert_eq!(result.body["auth"]["lease_duration"], 600);
    let raw = result.body["auth"]["client_token"].as_str().unwrap();
    let actor = state.authenticate(raw, 1051).unwrap();
    assert!(
        state
            .authorize_request(&actor, "team", "secret/data/app", "read", 1051)
            .is_ok()
    );
    assert!(
        state
            .authorize_request(&actor, "team", "secret/data/app", "update", 1051)
            .is_err()
    );
    assert!(
        state
            .authorize_request(&actor, "other", "secret/data/app", "read", 1051)
            .is_err()
    );
    assert!(
        state
            .authorize_request(&actor, "team", "secret/data/app", "read", 1300)
            .is_ok()
    );
    assert!(
        state
            .authorize_request(&actor, "team", "secret/data/app", "read", 1650)
            .is_err()
    );
    let saved = serde_json::to_vec(&state).unwrap();
    assert!(!String::from_utf8_lossy(&saved).contains(&jwt));
    let mut state: AuthState = serde_json::from_slice(&saved).unwrap();
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/workload/ci/login",
                &request,
                1051
            )
            .is_ok()
    );
    assert_ne!(serde_json::to_vec(&state).unwrap(), saved);
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/workload/deploy/login",
                &request,
                1051
            )
            .is_ok()
    );
    call(
        &mut state,
        &root,
        "team",
        "DELETE",
        "sys/auth/workload/ci",
        json!({}),
        1052,
    );
    assert!(state.authenticate(raw, 1053).is_err());
    mount_auth(&mut state, &root, "team", "workload/ci", "jwt");
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/workload/ci/login",
                &request,
                1053
            )
            .is_err_and(|error| error.status == 503)
    );
}

#[test]
fn jwt_login_denies_invalid_trust_claims_headers_and_roles_without_mutation() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let pair = Ed25519KeyPair::from_seed_unchecked(&[48; 32]).unwrap();
    let wrong_pair = Ed25519KeyPair::from_seed_unchecked(&[49; 32]).unwrap();
    let (mut state, _, root) = setup();
    configured_jwt_mount(
        &mut state,
        &root,
        "workload",
        pair.public_key().as_ref(),
        "EdDSA",
    );
    let header = json!({"alg":"EdDSA","kid":"key-1"});
    let valid = jwt_claims("same-id");
    let mut invalid = Vec::new();
    for (field, value) in [
        ("iss", json!("https://evil.example")),
        ("aud", json!("wrong-service")),
        ("sub", json!("mallory")),
        ("groups", json!(["others"])),
        ("heptabao_namespace", json!("other")),
        ("exp", json!(1049)),
        ("exp", json!(100000)),
        ("nbf", json!(1100)),
        ("iat", json!(1100)),
    ] {
        let mut claims = valid.clone();
        claims[field] = value;
        invalid.push(signed_jwt(&pair, &header, &claims));
    }
    for header in [
        json!({"alg":"none","kid":"key-1"}),
        json!({"alg":"ES256","kid":"key-1"}),
        json!({"alg":"EdDSA","kid":"unknown"}),
        json!({"alg":"EdDSA","kid":"key-1","jku":"https://evil.example/keys"}),
    ] {
        invalid.push(signed_jwt(&pair, &header, &valid));
    }
    invalid.push(signed_jwt(&wrong_pair, &header, &valid));
    let duplicate_payload=URL_SAFE_NO_PAD.encode(br#"{"iss":"https://issuer.example","iss":"https://evil.example","sub":"alice","aud":"https://service.example/bao","iat":1000,"exp":1300,"jti":"duplicate","heptabao_namespace":"team","groups":["team/developers"]}"#);
    let input = format!(
        "{}.{duplicate_payload}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap())
    );
    invalid.push(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(pair.sign(input.as_bytes()).as_ref())
    ));
    let saved = serde_json::to_vec(&state).unwrap();
    for jwt in invalid {
        assert!(
            state
                .handle(
                    None,
                    "team",
                    "POST",
                    "auth/workload/login",
                    &json!({"role":"app","jwt":jwt}),
                    1050
                )
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), saved);
    }
    let jwt = signed_jwt(&pair, &header, &valid);
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/workload/login",
                &json!({"role":"unknown","jwt":jwt}),
                1050
            )
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), saved);
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/workload/login",
                &json!({"role":"app","jwt":jwt}),
                1050
            )
            .is_ok()
    );
}

#[test]
fn jwt_successful_native_login_retires_legacy_replay_without_rejecting_reuse() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let pair = Ed25519KeyPair::from_seed_unchecked(&[50; 32]).unwrap();
    let (mut state, _, root) = setup();
    configured_jwt_mount(
        &mut state,
        &root,
        "workload",
        pair.public_key().as_ref(),
        "EdDSA",
    );
    let header = json!({"alg":"EdDSA","kid":"key-1"});
    let mut old_claims = jwt_claims("old");
    old_claims["exp"] = json!(1100);
    let old = signed_jwt(&pair, &header, &old_claims);
    let scope = AuthScope {
        namespace: "team",
        mount: "workload",
    };
    let fingerprint = state
        .jwt_at(scope)
        .unwrap()
        .config
        .as_ref()
        .unwrap()
        .verifier()
        .unwrap()
        .verify(&old, 1050)
        .unwrap()
        .replay_fingerprint();
    state
        .jwt_at_mut(scope)
        .replay
        .insert(URL_SAFE_NO_PAD.encode(fingerprint), 1100);
    state.jwt_at_mut(scope).last_admission_time = 1150;
    let saved = serde_json::to_vec(&state).unwrap();
    let mut state: AuthState = serde_json::from_slice(&saved).unwrap();
    assert!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/workload/login",
                &json!({"role":"app","jwt":"invalid"}),
                1050
            )
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), saved);
    let first = state
        .handle(
            None,
            "team",
            "POST",
            "auth/workload/login",
            &json!({"role":"app","jwt":old}),
            1050,
        )
        .unwrap()
        .unwrap();
    let second = state
        .handle(
            None,
            "team",
            "POST",
            "auth/workload/login",
            &json!({"role":"app","jwt":old}),
            1051,
        )
        .unwrap()
        .unwrap();
    assert_ne!(
        first.body["auth"]["client_token"],
        second.body["auth"]["client_token"]
    );
    assert!(state.jwt_at(scope).unwrap().native_claims);
    assert!(state.jwt_at(scope).unwrap().replay.is_empty());
    assert_eq!(state.jwt_at(scope).unwrap().last_admission_time, 0);
    state.validate_native_jwt_state().unwrap();
}

#[test]
fn jwt_configuration_rejects_bad_keys_namespace_and_privilege_escalation() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let pair = Ed25519KeyPair::from_seed_unchecked(&[51; 32]).unwrap();
    let (mut state, _, root) = setup();
    configured_jwt_mount(
        &mut state,
        &root,
        "workload",
        pair.public_key().as_ref(),
        "EdDSA",
    );
    let saved = serde_json::to_vec(&state).unwrap();
    for change in 0..5 {
        let mut config = jwt_config(pair.public_key().as_ref(), "EdDSA");
        match change {
            0 => config["keys"][0]["algorithm"] = json!("HS256"),
            1 => config["keys"][0]["key_base64"] = json!(URL_SAFE_NO_PAD.encode([0; 31])),
            2 => config["required_namespace"] = json!("other"),
            3 => config["audiences"] = json!([]),
            _ => config["clock_skew_seconds"] = json!(301),
        }
        assert!(
            state
                .handle(
                    Some(&root),
                    "team",
                    "POST",
                    "auth/workload/config",
                    &config,
                    1000
                )
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), saved);
    }
    put_policy(
        &mut state,
        &root,
        "team",
        "jwt-manager",
        json!(r#"path "auth/workload/role/*" { capabilities = ["update", "sudo"] }"#),
    );
    let raw = token(
        &mut state,
        &root,
        "team",
        json!({"policies":["jwt-manager"]}),
        1000,
    );
    let actor = state.authenticate(&raw, 1001).unwrap();
    for requested in ["root", "unowned-policy"] {
        assert!(
            state
                .handle(
                    Some(&actor),
                    "team",
                    "POST",
                    "auth/workload/role/escalate",
                    &json!({"policies":[requested]}),
                    1001
                )
                .is_err()
        );
    }
}

#[test]
fn jwt_config_and_role_readback_preserve_openbao_aliases() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let pair = Ed25519KeyPair::from_seed_unchecked(&[53; 32]).unwrap();
    let (mut state, _, root) = setup();
    configured_jwt_mount(
        &mut state,
        &root,
        "workload",
        pair.public_key().as_ref(),
        "EdDSA",
    );

    let config = call(
        &mut state,
        &root,
        "team",
        "GET",
        "auth/workload/config",
        json!({}),
        1001,
    );
    assert_eq!(
        config.body["data"]["issuer"],
        config.body["data"]["bound_issuer"]
    );
    assert_eq!(
        config.body["data"]["bound_issuer"],
        "https://issuer.example"
    );

    let role = call(
        &mut state,
        &root,
        "team",
        "GET",
        "auth/workload/role/app",
        json!({}),
        1001,
    );
    assert_eq!(
        role.body["data"]["policies"],
        role.body["data"]["token_policies"]
    );
    assert_eq!(
        role.body["data"]["token_policies"],
        json!(["default", "reader"])
    );
}

#[test]
fn jwt_es256_login_uses_real_p256_signature_and_rejects_algorithm_confusion() {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let (mut state, _, root) = setup();
    configured_jwt_mount(
        &mut state,
        &root,
        "workload",
        pair.public_key().as_ref(),
        "ES256",
    );
    for algorithm in ["EdDSA", "ES256"] {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&json!({"alg":algorithm,"kid":"key-1"})).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&jwt_claims("p256")).unwrap())
        );
        let jwt = format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(pair.sign(&rng, input.as_bytes()).unwrap().as_ref())
        );
        let result = state.handle(
            None,
            "team",
            "POST",
            "auth/workload/login",
            &json!({"role":"app","jwt":jwt}),
            1050,
        );
        assert_eq!(result.is_ok(), algorithm == "ES256");
    }
}

#[test]
fn jwt_service_persists_tokens_and_allows_assertion_reuse_across_reopen() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    struct SyntheticRoot(std::path::PathBuf);
    impl Drop for SyntheticRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = SyntheticRoot(std::env::temp_dir().join(format!(
        "heptabao-auth-service-{}-{}",
        std::process::id(),
        random_id("fixture.").unwrap()
    )));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory.0).unwrap();
    let make_service =
        || crate::Service::new(directory.0.join("data"), &directory.0.join("audit.jsonl")).unwrap();
    let mut service = make_service();
    let initialized = service.handle_at(
        "PUT",
        "sys/init",
        "",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
        1000,
    );
    assert_eq!(initialized.status, 200);
    let key = initialized.body["keys_base64"][0]
        .as_str()
        .unwrap()
        .to_owned();
    let root = initialized.body["root_token"].as_str().unwrap().to_owned();
    assert_eq!(
        service
            .handle_at("PUT", "sys/unseal", "", "", json!({"key":key}), 1000)
            .status,
        200
    );
    let pair = Ed25519KeyPair::from_seed_unchecked(&[52; 32]).unwrap();
    for (path, body) in [
        (
            "sys/policies/acl/reader",
            json!({"policy":r#"path "secret/data/app" { capabilities = ["read"] }"#}),
        ),
        (
            "secret/data/app",
            json!({"data":{"value":"synthetic-jwt-secret"}}),
        ),
        ("sys/auth/workload", json!({"type":"jwt"})),
        (
            "auth/workload/config",
            jwt_config(pair.public_key().as_ref(), "EdDSA"),
        ),
        (
            "auth/workload/role/app",
            json!({"policies":["reader"],"token_ttl":600}),
        ),
    ] {
        assert!(
            service
                .handle_at("POST", path, "team", &root, body, 1000)
                .status
                < 300,
            "route {path}"
        );
    }
    let jwt = signed_jwt(
        &pair,
        &json!({"alg":"EdDSA","kid":"key-1"}),
        &jwt_claims("durable"),
    );
    let login = service.handle_at(
        "POST",
        "auth/workload/login",
        "team",
        "",
        json!({"role":"app","jwt":jwt}),
        1050,
    );
    assert_eq!(login.status, 200);
    let raw = login.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        service
            .handle_at("GET", "secret/data/app", "team", &raw, json!({}), 1051)
            .body["data"]["data"]["value"],
        "synthetic-jwt-secret"
    );
    drop(service);
    let mut service = make_service();
    assert_eq!(
        service
            .handle_at("PUT", "sys/unseal", "", "", json!({"key":key}), 1052)
            .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "auth/workload/login",
                "team",
                "",
                json!({"role":"app","jwt":jwt}),
                1053
            )
            .status,
        200
    );
    assert_eq!(
        service
            .handle_at("GET", "secret/data/app", "team", &raw, json!({}), 1054)
            .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "DELETE",
                "sys/auth/workload",
                "team",
                &root,
                json!({}),
                1055
            )
            .status,
        204
    );
    drop(service);
    let mut service = make_service();
    assert_eq!(
        service
            .handle_at("PUT", "sys/unseal", "", "", json!({"key":key}), 1056)
            .status,
        200
    );
    assert_eq!(
        service
            .handle_at("GET", "secret/data/app", "team", &raw, json!({}), 1057)
            .status,
        403
    );
}

#[test]
fn jwt_jwks_config_accepts_public_ed25519_and_drives_login() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let pair = Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
    let (mut state, _, root) = setup();
    put_policy(
        &mut state,
        &root,
        "team",
        "reader",
        json!(r#"path "secret/data/app" { capabilities = ["read"] }"#),
    );
    mount_auth(&mut state, &root, "team", "federated", "jwt");
    let config = json!({
        "issuer":"https://issuer.example",
        "audiences":["https://service.example/bao"],
        "required_namespace":"team",
        "clock_skew_seconds":0,
        "maximum_token_lifetime_seconds":3600,
        "jwks":{"keys":[{
            "kid":"key-1","kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","key_ops":["verify"],
            "x":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
        }]}
    });
    let response = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/federated/config",
        config,
        1000,
    );
    assert_eq!(response.status, 204);
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/federated/role/app",
        json!({"token_policies":["reader"],"bound_subject":"alice","bound_groups":["team/developers"],
            "bound_audiences":["https://service.example/bao"],"token_ttl":120,"token_max_ttl":240}),
        1000,
    );
    let token = signed_jwt(
        &pair,
        &json!({"alg":"EdDSA","kid":"key-1","typ":"JWT"}),
        &jwt_claims("jwks-login"),
    );
    let login = state
        .handle(
            None,
            "team",
            "POST",
            "auth/federated/login",
            &json!({"role":"app","jwt":token}),
            1001,
        )
        .unwrap()
        .unwrap();
    assert_eq!(login.status, 200);
    assert_eq!(
        login.body["auth"]["token_policies"],
        json!(["default", "reader"])
    );
}

#[test]
fn jwt_jwks_rejects_private_symmetric_duplicate_and_mixed_key_material_without_mutation() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let pair = Ed25519KeyPair::from_seed_unchecked(&[92; 32]).unwrap();
    let (mut state, _, root) = setup();
    mount_auth(&mut state, &root, "team", "federated", "jwt");
    let base = serde_json::to_vec(&state).unwrap();
    let x = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    let bad_jwks = [
        json!({"keys":[{"kid":"k","kty":"oct","crv":"Ed25519","alg":"EdDSA","x":x}]}),
        json!({"keys":[{"kid":"k","kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":x,"d":"private"}]}),
        json!({"keys":[
            {"kid":"k","kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":x},
            {"kid":"k","kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":x}
        ]}),
    ];
    for jwks in bad_jwks {
        let result = state.handle(
            Some(&root),
            "team",
            "POST",
            "auth/federated/config",
            &json!({"issuer":"https://issuer.example","audiences":["https://service.example/bao"],
                "required_namespace":"team","clock_skew_seconds":0,"maximum_token_lifetime_seconds":3600,
                "jwks":jwks}),
            1000,
        );
        assert!(result.is_err());
        assert_eq!(serde_json::to_vec(&state).unwrap(), base);
    }
    let mixed = state.handle(
        Some(&root),
        "team",
        "POST",
        "auth/federated/config",
        &json!({"issuer":"https://issuer.example","audiences":["https://service.example/bao"],
            "required_namespace":"team","clock_skew_seconds":0,"maximum_token_lifetime_seconds":3600,
            "keys":[{"kid":"legacy","algorithm":"EdDSA","key_base64":x}],
            "jwks":{"keys":[{"kid":"k","kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":x}]}}),
        1000,
    );
    assert!(mixed.is_err());
    assert_eq!(serde_json::to_vec(&state).unwrap(), base);
}

#[test]
fn auth_mount_revision_tune_remount_and_recreate_rotate_identity() {
    let (mut state, _raw, root) = setup();
    call(
        &mut state,
        &root,
        "",
        "POST",
        "sys/auth/team",
        json!({"type":"userpass","cas_revision":0}),
        100,
    );
    let created = call(
        &mut state,
        &root,
        "",
        "GET",
        "sys/auth/team",
        json!({}),
        100,
    );
    let accessor = created.body["data"]["accessor"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(created.body["data"]["revision"], 1);
    call(
        &mut state,
        &root,
        "",
        "PUT",
        "sys/auth/team/tune",
        json!({"description":"team-v2","cas_revision":1}),
        100,
    );
    call(
        &mut state,
        &root,
        "",
        "PUT",
        "auth/team/users/alice",
        json!({"password":"correct horse battery staple"}),
        100,
    );
    let issued = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/team/login/alice",
        json!({"password":"correct horse battery staple"}),
        101,
    )
    .body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let moved = state.remount_mount("", "team", "moved", Some(2)).unwrap();
    assert_eq!(moved.body["data"]["revision"], 3);
    assert_eq!(moved.body["data"]["accessor"], accessor);
    assert_eq!(
        state
            .handle(
                None,
                "",
                "POST",
                "auth/team/login/alice",
                &json!({"password":"correct horse battery staple"}),
                102,
            )
            .err()
            .map(|error| error.status),
        Some(404)
    );
    assert_eq!(
        state
            .handle(
                None,
                "",
                "POST",
                "auth/moved/login/alice",
                &json!({"password":"correct horse battery staple"}),
                102,
            )
            .unwrap()
            .unwrap()
            .status,
        200
    );
    assert!(state.authenticate(&issued, 102).is_ok());
    let before_stale = serde_json::to_vec(&state).unwrap();
    assert_eq!(
        state
            .remount_mount("", "moved", "other", Some(1))
            .err()
            .map(|error| error.status),
        Some(409)
    );
    assert_eq!(before_stale, serde_json::to_vec(&state).unwrap());
    call(
        &mut state,
        &root,
        "",
        "DELETE",
        "sys/auth/moved",
        json!({"cas_revision":3}),
        103,
    );
    assert!(state.authenticate(&issued, 103).is_err());
    call(
        &mut state,
        &root,
        "",
        "POST",
        "sys/auth/moved",
        json!({"type":"userpass","cas_revision":0}),
        104,
    );
    let recreated = call(
        &mut state,
        &root,
        "",
        "GET",
        "sys/auth/moved",
        json!({}),
        104,
    );
    assert_eq!(recreated.body["data"]["revision"], 1);
    assert_ne!(recreated.body["data"]["accessor"], accessor);
}
