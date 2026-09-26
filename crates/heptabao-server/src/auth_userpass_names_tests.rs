use super::*;

fn request(
    state: &mut AuthState,
    actor: Option<&Principal>,
    method: &str,
    path: &str,
    body: Value,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(actor, "", method, path, &body, now)?
        .ok_or_else(denied)
}
fn login(state: &mut AuthState, name: &str, password: &str) -> Result<AuthResponse, AuthError> {
    request(
        state,
        None,
        "POST",
        &format!("auth/userpass/login/{name}"),
        json!({"password":password}),
        100,
    )
}

#[test]
fn fresh_userpass_has_one_canonical_account_for_crud_reset_policy_and_login() {
    let (mut state, _, root) = setup();
    assert!(state.has_userpass_name_modes());
    let before = serde_json::to_vec(&state).unwrap();
    let missing = request(
        &mut state,
        Some(&root),
        "LIST",
        "auth/userpass/users",
        json!({}),
        100,
    )
    .unwrap();
    assert_eq!(missing.status, 404);
    assert_eq!(missing.body, json!({"errors": []}));
    assert!(!missing.mutated);
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    request(
        &mut state,
        Some(&root),
        "POST",
        "auth/userpass/users/MiXeD",
        json!({"username":"ignored","password":"original"}),
        100,
    )
    .unwrap();
    for name in ["mixed", "MIXED", "mIxEd"] {
        let result = login(&mut state, name, "original").unwrap();
        assert_eq!(result.body["auth"]["metadata"]["username"], "mixed");
        assert_eq!(result.login_identity.unwrap().alias, "mixed");
        let raw = result.body["auth"]["client_token"].as_str().unwrap();
        assert!(matches!(&state.tokens[&hash(raw)].auth_provenance,
            Some(TokenAuthProvenance::Userpass { username }) if username == "mixed"));
    }
    assert_eq!(
        request(
            &mut state,
            Some(&root),
            "LIST",
            "auth/userpass/users",
            json!({}),
            100
        )
        .unwrap()
        .body["data"]["keys"],
        json!(["mixed"])
    );
    request(
        &mut state,
        Some(&root),
        "POST",
        "auth/userpass/users/MIXED/password",
        json!({"password":"replacement"}),
        100,
    )
    .unwrap();
    assert_eq!(
        login(&mut state, "mixed", "original").err().unwrap().status,
        400
    );
    assert!(login(&mut state, "MiXeD", "replacement").is_ok());
    request(
        &mut state,
        Some(&root),
        "POST",
        "auth/userpass/users/MIXED/policies",
        json!({"token_policies":["named"]}),
        100,
    )
    .unwrap();
    assert_eq!(
        login(&mut state, "mixed", "replacement").unwrap().body["auth"]["policies"],
        json!(["default", "named"])
    );
    assert_eq!(state.users[""].len(), 1);
    request(
        &mut state,
        Some(&root),
        "DELETE",
        "auth/userpass/users/mIxEd",
        json!({}),
        100,
    )
    .unwrap();
    assert!(state.users[""].is_empty());
    let missing = request(
        &mut state,
        Some(&root),
        "LIST",
        "auth/userpass/users",
        json!({}),
        100,
    )
    .unwrap();
    assert_eq!(missing.status, 404);
    assert_eq!(missing.body, json!({"errors": []}));
    assert!(!missing.mutated);
    assert_eq!(
        login(&mut state, "mixed", "replacement")
            .err()
            .unwrap()
            .status,
        400
    );
}

#[test]
fn fresh_userpass_mfa_replay_counter_is_shared_across_case_variants() {
    let (mut state, _, root) = setup();
    request(
        &mut state,
        Some(&root),
        "POST",
        "auth/userpass/users/Alice",
        json!({"password":"password"}),
        100,
    )
    .unwrap();
    request(
        &mut state,
        Some(&root),
        "POST",
        "auth/userpass/users/ALICE/mfa",
        json!({}),
        100,
    )
    .unwrap();
    let secret = Zeroizing::new(
        state.users[""]["alice"]
            .mfa
            .as_ref()
            .unwrap()
            .secret
            .clone(),
    );
    let code = String::from_utf8(totp_code(&secret, 100 / MFA_PERIOD_SECONDS).to_vec()).unwrap();
    let first = request(
        &mut state,
        None,
        "POST",
        "auth/userpass/login/ALICE",
        json!({"password":"password","totp_code":code}),
        100,
    )
    .unwrap();
    assert_eq!(first.body["auth"]["metadata"]["username"], "alice");
    let before = state.tokens.len();
    assert_eq!(
        request(
            &mut state,
            None,
            "POST",
            "auth/userpass/login/Alice",
            json!({"password":"password","totp_code":code}),
            100
        )
        .err()
        .unwrap()
        .status,
        403
    );
    assert_eq!(state.tokens.len(), before);
    assert_eq!(state.users[""].len(), 1);
    request(
        &mut state,
        Some(&root),
        "DELETE",
        "auth/userpass/users/aLiCe/mfa",
        json!({}),
        100,
    )
    .unwrap();
    assert!(login(&mut state, "Alice", "password").is_ok());
}

#[test]
fn absent_mode_preserves_case_distinct_credentials_and_exact_issued_renewal_source() {
    let (mut state, _, root) = setup();
    // Format-unit legacy shape only; the actual upgrade QA uses an old binary.
    state
        .auth_mounts
        .get_mut("")
        .unwrap()
        .get_mut("userpass")
        .unwrap()
        .userpass_name_mode = None;
    for (name, password) in [("Alice", "upper password"), ("alice", "lower password")] {
        request(
            &mut state,
            Some(&root),
            "POST",
            &format!("auth/userpass/users/{name}"),
            json!({"password":password}),
            100,
        )
        .unwrap();
    }
    let issued = login(&mut state, "Alice", "upper password").unwrap();
    let raw = issued.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(issued.body["auth"]["metadata"]["username"], "Alice");
    assert_eq!(
        login(&mut state, "Alice", "lower password")
            .err()
            .unwrap()
            .status,
        400
    );
    assert_eq!(state.users[""].len(), 2);
    let wire = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    state = serde_json::from_slice(&wire).unwrap();
    assert!(!state.has_userpass_name_modes());
    assert!(login(&mut state, "Alice", "upper password").is_ok());
    let prior = state.tokens[&hash(&raw)].expires_at;
    request(
        &mut state,
        Some(&root),
        "DELETE",
        "auth/userpass/users/Alice",
        json!({}),
        100,
    )
    .unwrap();
    let result = request(
        &mut state,
        Some(&root),
        "POST",
        "auth/token/renew",
        json!({"token":raw,"increment":600}),
        100,
    )
    .unwrap();
    assert_eq!(result.status, 204);
    assert_eq!(state.tokens[&hash(&raw)].expires_at, prior);
    assert!(login(&mut state, "alice", "lower password").is_ok());
    state.validate_userpass_name_modes().unwrap();
}

#[test]
fn name_mode_is_preserved_by_mount_reconfiguration_and_remount_and_validated_on_load() {
    let (mut state, _, root) = setup();
    mount_auth(&mut state, &root, "", "staff", "userpass");
    for (path, body) in [
        (
            "sys/auth/staff",
            json!({"type":"userpass","description":"updated"}),
        ),
        ("sys/auth/staff/tune", json!({"default_lease_ttl":60})),
    ] {
        request(&mut state, Some(&root), "POST", path, body, 100).unwrap();
    }
    request(
        &mut state,
        Some(&root),
        "POST",
        "auth/staff/users/Mixed",
        json!({"password":"password"}),
        100,
    )
    .unwrap();
    state.remount_mount("", "staff", "moved", None).unwrap();
    assert!(
        state.userpass_account_key(
            AuthScope {
                namespace: "",
                mount: "moved"
            },
            "MIXED"
        ) == "mixed"
    );
    state.validate_userpass_name_modes().unwrap();
    let mut wrong = state.clone();
    wrong
        .auth_mounts
        .get_mut("")
        .unwrap()
        .get_mut("token")
        .unwrap()
        .userpass_name_mode = Some(userpass_names::UserpassNameMode::AsciiLowerV1);
    assert!(wrong.validate_userpass_name_modes().is_err());
    let mut wrong = state.clone();
    let users = wrong
        .mounted_users
        .get_mut("")
        .unwrap()
        .get_mut("moved")
        .unwrap();
    let user = users.remove("mixed").unwrap();
    users.insert("Mixed".into(), user);
    assert!(wrong.validate_userpass_name_modes().is_err());
    let mut value = serde_json::to_value(&state).unwrap();
    value["auth_mounts"][""]["moved"]["userpass_name_mode"] = json!("future_unknown");
    assert!(serde_json::from_value::<AuthState>(value).is_err());
    let legacy = AuthScope {
        namespace: "",
        mount: "ldap",
    };
    assert_eq!(state.userpass_account_key(legacy, "Mixed"), "Mixed");
}
