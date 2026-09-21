use super::*;

fn configured() -> (AuthState, Principal) {
    let (mut state, _, root) = setup();
    mount_auth(&mut state, &root, "", "staff", "userpass");
    (state, root)
}
fn write(
    state: &mut AuthState,
    root: &Principal,
    suffix: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(
            Some(root),
            "",
            "POST",
            &format!("auth/staff/users/{suffix}"),
            &body,
            100,
        )?
        .ok_or_else(denied)
}
fn login(state: &mut AuthState, name: &str, body: Value) -> Result<AuthResponse, AuthError> {
    state
        .handle(
            None,
            "",
            "POST",
            &format!("auth/staff/login/{name}"),
            &body,
            100,
        )?
        .ok_or_else(denied)
}
fn user<'a>(state: &'a AuthState, name: &str) -> &'a User {
    &state
        .users_at(AuthScope {
            namespace: "",
            mount: "staff",
        })
        .unwrap()[name]
}

#[test]
fn userpass_native_aliases_prefer_new_values_and_null_duration_falls_back_to_legacy() {
    let (mut state, root) = configured();
    write(&mut state, &root, "alice", json!({"password":"credential", "ttl":40, "token_ttl":70,
        "max_ttl":100, "token_max_ttl":300, "policies":["old-policy"], "token_policies":["new-policy"]})).unwrap();
    assert_eq!(
        (
            user(&state, "alice").token_ttl,
            user(&state, "alice").token_max_ttl
        ),
        (70, 300)
    );
    assert_eq!(
        user(&state, "alice").policies,
        BTreeSet::from(["new-policy".into()])
    );
    write(
        &mut state,
        &root,
        "alice",
        json!({"ttl":80,"token_ttl":null,"max_ttl":400,
        "token_max_ttl":null,"policies":["old-policy"],"token_policies":null}),
    )
    .unwrap();
    assert_eq!(
        (
            user(&state, "alice").token_ttl,
            user(&state, "alice").token_max_ttl
        ),
        (80, 400)
    );
    assert!(user(&state, "alice").policies.is_empty());
    let issued = login(&mut state, "alice", json!({"password":"credential"})).unwrap();
    assert_eq!(issued.body["auth"]["lease_duration"], 80);
    assert_eq!(issued.body["auth"]["token_policies"], json!(["default"]));
    write(
        &mut state,
        &root,
        "alice",
        json!({"token_ttl":null,"token_max_ttl":null}),
    )
    .unwrap();
    assert_eq!(
        (
            user(&state, "alice").token_ttl,
            user(&state, "alice").token_max_ttl
        ),
        (80, 400)
    );
    write(
        &mut state,
        &root,
        "alice",
        json!({"ttl":90,"token_ttl":0,"max_ttl":500,"token_max_ttl":0}),
    )
    .unwrap();
    assert_eq!(
        (
            user(&state, "alice").token_ttl,
            user(&state, "alice").token_max_ttl
        ),
        (0, 0)
    );
    let bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let restored: AuthState = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(user(&restored, "alice").token_ttl, 0);
    assert!(user(&restored, "alice").policies.is_empty());
}

#[test]
fn userpass_path_capture_overrides_body_username_without_redirecting_login_or_reset() {
    let (mut state, root) = configured();
    write(
        &mut state,
        &root,
        "alice",
        json!({"password":"alice credential", "username":"bob"}),
    )
    .unwrap();
    assert!(
        !state
            .users_at(AuthScope {
                namespace: "",
                mount: "staff"
            })
            .unwrap()
            .contains_key("bob")
    );
    write(
        &mut state,
        &root,
        "bob",
        json!({"password":"bob credential"}),
    )
    .unwrap();
    for username in [
        json!("bob"),
        Value::Null,
        json!(""),
        json!(123),
        json!(false),
        json!({"username":"bob"}),
    ] {
        write(
            &mut state,
            &root,
            "alice",
            json!({"username":username,"token_ttl":90}),
        )
        .unwrap();
        let issued = login(
            &mut state,
            "alice",
            json!({"username":username,"password":"alice credential"}),
        )
        .unwrap();
        assert_eq!(issued.body["auth"]["metadata"], json!({"username":"alice"}));
        assert_eq!(
            login(
                &mut state,
                "alice",
                json!({"username":username,"password":"bob credential"})
            )
            .err()
            .unwrap()
            .status,
            400
        );
    }
    write(
        &mut state,
        &root,
        "alice/password",
        json!({"username":"bob","password":"replacement"}),
    )
    .unwrap();
    assert!(login(&mut state, "alice", json!({"password":"replacement"})).is_ok());
    assert!(login(&mut state, "bob", json!({"password":"bob credential"})).is_ok());
    write(&mut state, &root, "alice/policies", json!({"username":{"target":"bob"},"policies":["old-policy"],"token_policies":["new-policy"]})).unwrap();
    assert_eq!(
        user(&state, "alice").policies,
        BTreeSet::from(["new-policy".into()])
    );
    assert!(user(&state, "bob").policies.is_empty());
    write(
        &mut state,
        &root,
        "alice/policies",
        json!({"username":null,"policies":["old-policy"],"token_policies":null}),
    )
    .unwrap();
    assert!(user(&state, "alice").policies.is_empty());
}

#[test]
fn userpass_alias_errors_do_not_change_password_policy_or_issue_tokens() {
    let (mut state, root) = configured();
    write(
        &mut state,
        &root,
        "alice",
        json!({"password":"original credential","token_ttl":50,"token_max_ttl":300}),
    )
    .unwrap();
    for body in [
        json!({"password":"changed", "ttl":40,"token_ttl":"bad-duration"}),
        json!({"password":"changed","max_ttl":200,"token_max_ttl":20}),
        json!({"password":"changed","policies":["default"],"token_policies":["root"]}),
    ] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert!(write(&mut state, &root, "alice", body).is_err());
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
        assert!(
            login(
                &mut state,
                "alice",
                json!({"password":"original credential"})
            )
            .is_ok()
        );
        assert_eq!(
            login(&mut state, "alice", json!({"password":"changed"}))
                .err()
                .unwrap()
                .status,
            400
        );
    }
    for (path, body) in [
        ("alice/password", json!({"username":"bob"})),
        (
            "alice/password",
            json!({"username":"bob","password":"new","token_ttl":80}),
        ),
        (
            "alice/policies",
            json!({"username":"bob","token_policies":[],"password":"new"}),
        ),
    ] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            write(&mut state, &root, path, body).err().unwrap().status,
            400
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    }
}

#[test]
fn userpass_alias_compatibility_does_not_change_bounded_ldap_or_account_case() {
    let (mut state, root) = configured();
    mount_auth(&mut state, &root, "", "directory", "ldap");
    for body in [
        json!({"password":"bounded credential", "username":"other"}),
        json!({"password":"bounded credential", "ttl":40,"token_ttl":70}),
        json!({"password":"bounded credential", "policies":["old"],"token_policies":["new"]}),
    ] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            state
                .handle(
                    Some(&root),
                    "",
                    "POST",
                    "auth/directory/users/alice",
                    &body,
                    100
                )
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    }
    // Existing mixed-case accounts must not be silently merged by this input-only change.
    write(
        &mut state,
        &root,
        "Alice",
        json!({"password":"upper credential"}),
    )
    .unwrap();
    write(
        &mut state,
        &root,
        "alice",
        json!({"password":"lower credential"}),
    )
    .unwrap();
    assert!(
        login(
            &mut state,
            "Alice",
            json!({"password":"upper credential","username":"alice"})
        )
        .is_ok()
    );
    assert!(
        login(
            &mut state,
            "alice",
            json!({"password":"lower credential","username":"Alice"})
        )
        .is_ok()
    );
    assert_eq!(
        login(
            &mut state,
            "Alice",
            json!({"password":"lower credential","username":"alice"})
        )
        .err()
        .unwrap()
        .status,
        400
    );
}
