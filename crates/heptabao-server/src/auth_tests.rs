#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

fn setup() -> (AuthState, String, Principal) {
    let (mut state, raw) = AuthState::bootstrap(100).unwrap();
    let principal = state.authenticate(&raw, 100).unwrap();
    (state, raw, principal)
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
fn approle_destroy_and_policy_assignment_fail_closed() {
    let (mut state, _, root) = setup();
    assert!(
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "auth/approle/role/bad",
                &json!({"bind_secret_id": false}),
                100
            )
            .is_err()
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
