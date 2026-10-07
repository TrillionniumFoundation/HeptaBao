use super::*;

fn issuer(options: Value) -> (AuthState, Principal, String) {
    let (mut state, _, root) = setup();
    mount_auth(&mut state, &root, "", "build", "approle");
    call(
        &mut state,
        &root,
        "",
        "POST",
        "sys/policies/acl/issuer",
        json!({"policy": "path \"auth/token/create*\" { capabilities = [\"update\", \"sudo\"] }"}),
        100,
    );
    let mut role = json!({"token_ttl": 120, "token_max_ttl": 300, "token_period": 0,
                         "token_explicit_max_ttl": 0, "secret_id_num_uses": 0, "token_policies": ["issuer"]});
    for (key, value) in options.as_object().unwrap() {
        role[key] = value.clone();
    }
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/build/role/service",
        role,
        100,
    );
    let role_id = call(
        &mut state,
        &root,
        "",
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
        "",
        "POST",
        "auth/build/role/service/secret-id",
        json!({}),
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
            "auth/build/login",
            &json!({"role_id": role_id, "secret_id": secret_id}),
            100,
        )
        .unwrap()
        .unwrap();
    (
        state,
        root,
        login.body["auth"]["client_token"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}

fn renew(
    state: &mut AuthState,
    root: &Principal,
    raw: &str,
    operation: &str,
    body: Value,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    let actor = state.authenticate(raw, now)?;
    let mut body = body;
    match operation {
        "renew" => body["token"] = json!(raw),
        "renew-accessor" => body["accessor"] = json!(state.tokens[&hash(raw)].accessor),
        _ => (),
    }
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
fn approle_live_ordinary_limits_missing_increment_and_errors_on_all_renewal_paths() {
    let (baseline, root, raw) = issuer(json!({}));
    assert!(baseline.tokens[&hash(&raw)].max_expires_at.is_none());
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let mut state = baseline.clone();
        call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/build/role/service",
            json!({"token_ttl": 40, "token_max_ttl": 600}),
            105,
        );
        let mut state: AuthState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        let response = renew(
            &mut state,
            &root,
            &raw,
            operation,
            json!({"increment": 500}),
            110,
        )
        .unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 500);
        assert_eq!(response.body["auth"]["orphan"], true);
        assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(610));
        for body in [json!({}), json!({"increment": 0})] {
            let mut attempt = state.clone();
            let response = renew(&mut attempt, &root, &raw, operation, body, 115).unwrap();
            assert_eq!(response.body["auth"]["lease_duration"], 40);
        }
        call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/build/role/service",
            json!({"token_ttl": 10, "token_max_ttl": 20}),
            120,
        );
        let before = state.tokens[&hash(&raw)].expires_at;
        assert_eq!(
            renew(&mut state, &root, &raw, operation, json!({}), 120)
                .err()
                .unwrap()
                .status,
            500
        );
        assert_eq!(state.tokens[&hash(&raw)].expires_at, before);
        call(
            &mut state,
            &root,
            "",
            "DELETE",
            "auth/build/role/service",
            json!({}),
            121,
        );
        assert_eq!(
            renew(&mut state, &root, &raw, operation, json!({}), 121)
                .err()
                .unwrap()
                .status,
            500
        );
        assert_eq!(state.tokens[&hash(&raw)].expires_at, before);
        assert_eq!(
            renew(&mut state, &root, &raw, operation, json!({}), 610)
                .err()
                .unwrap()
                .status,
            403
        );
    }
}

#[test]
fn approle_explicit_caps_are_frozen_at_issue_and_legacy_caps_are_conservative() {
    for (initial, current, expected_expiry) in
        [(0, 20, 230), (200, 20, 230), (20, 600, 120), (20, 0, 120)]
    {
        let (mut state, root, raw) = issuer(json!({"token_explicit_max_ttl": initial}));
        call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/build/role/service",
            json!({"token_explicit_max_ttl": current}),
            105,
        );
        let mut state: AuthState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        let response = renew(
            &mut state,
            &root,
            &raw,
            "renew-self",
            json!({"increment": 120}),
            110,
        )
        .unwrap();
        assert_eq!(
            response.body["auth"]["lease_duration"],
            expected_expiry - 110
        );
        assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(expected_expiry));
    }
    let (mut state, root, raw) = issuer(json!({}));
    state.tokens.get_mut(&hash(&raw)).unwrap().max_expires_at = Some(400);
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/build/role/service",
        json!({"token_max_ttl": 600}),
        105,
    );
    let mut state: AuthState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    let response = renew(
        &mut state,
        &root,
        &raw,
        "renew-self",
        json!({"increment": 500}),
        110,
    )
    .unwrap();
    assert_eq!(response.body["auth"]["lease_duration"], 290);
    assert_eq!(state.tokens[&hash(&raw)].max_expires_at, Some(400));
}

#[test]
fn approle_period_transitions_and_role_mount_explicit_bounds_match_login_and_renewal() {
    for (initial, changes, expected) in [
        (
            json!({"token_ttl": 10, "token_max_ttl": 15}),
            json!({"token_period": 30, "token_max_ttl": 300}),
            30,
        ),
        (
            json!({"token_period": 30}),
            json!({"token_period": 0, "token_max_ttl": 600}),
            500,
        ),
        (
            json!({"token_ttl": 5, "token_max_ttl": 10, "token_period": 30}),
            json!({}),
            10,
        ),
        (
            json!({"token_period": 30}),
            json!({"token_explicit_max_ttl": 5}),
            30,
        ),
        (
            json!({"token_period": 30, "token_explicit_max_ttl": 20}),
            json!({"token_explicit_max_ttl": 60}),
            19,
        ),
    ] {
        let (mut state, root, raw) = issuer(initial);
        call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/build/role/service",
            changes,
            100,
        );
        let response = renew(
            &mut state,
            &root,
            &raw,
            "renew-self",
            json!({"increment": 500}),
            101,
        )
        .unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], expected);
    }
    let (mut state, root, raw) =
        issuer(json!({"token_ttl": 5, "token_max_ttl": 10, "token_period": 30}));
    assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(110));
    call(
        &mut state,
        &root,
        "",
        "POST",
        "sys/auth/build/tune",
        json!({"default_lease_ttl": 5, "max_lease_ttl": 7}),
        101,
    );
    let response = renew(
        &mut state,
        &root,
        &raw,
        "renew-self",
        json!({"increment": 500}),
        102,
    )
    .unwrap();
    assert_eq!(response.body["auth"]["lease_duration"], 7);
}

#[test]
fn approle_token_api_children_keep_their_own_issuer_and_explicit_cap() {
    let (mut state, root, raw) = issuer(json!({}));
    let actor = state.authenticate(&raw, 100).unwrap();
    let children: Vec<_> = [false, true]
        .into_iter()
        .map(|orphan| {
            let child = token(
                &mut state,
                &actor,
                "",
                json!({"policies": ["default"], "ttl": 60,
                          "explicit_max_ttl": 90, "no_parent": orphan}),
                101,
            );
            assert!(matches!(
                state.tokens[&hash(&child)].auth_provenance,
                Some(TokenAuthProvenance::TokenApi { .. })
            ));
            (child, orphan)
        })
        .collect();
    call(
        &mut state,
        &root,
        "",
        "DELETE",
        "auth/build/role/service",
        json!({}),
        105,
    );
    for (child, _) in &children {
        let response = renew(
            &mut state,
            &root,
            child,
            "renew-self",
            json!({"increment": 500}),
            110,
        )
        .unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 81);
    }
    call(
        &mut state,
        &root,
        "",
        "DELETE",
        "sys/auth/build",
        json!({}),
        111,
    );
    for (child, orphan) in children {
        assert_eq!(state.authenticate(&child, 112).is_ok(), orphan);
    }
}
