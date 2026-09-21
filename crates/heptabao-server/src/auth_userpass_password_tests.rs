use super::*;

fn account_write(
    state: &mut AuthState,
    actor: &Principal,
    suffix: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(
            Some(actor),
            "",
            "POST",
            &format!("auth/staff/users/{suffix}"),
            &body,
            100,
        )?
        .ok_or_else(denied)
}
fn account_login(
    state: &mut AuthState,
    name: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
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
fn configured() -> (AuthState, Principal) {
    let (mut state, _, root) = setup();
    mount_auth(&mut state, &root, "", "staff", "userpass");
    (state, root)
}
fn credential(state: &AuthState) -> (Vec<u8>, Vec<u8>, u32) {
    let user = &state
        .users_at(AuthScope {
            namespace: "",
            mount: "staff",
        })
        .unwrap()["alice"];
    (user.salt.clone(), user.verifier.clone(), user.rounds)
}

#[test]
fn userpass_short_ascii_and_unicode_passwords_keep_existing_kdf_strength_and_exact_bytes() {
    let (mut state, root) = configured();
    for password in ["a", "短", "🔐", "e\u{301}", " ", "a\0b"] {
        account_write(&mut state, &root, "alice", json!({"password":password})).unwrap();
        let (salt, verifier, rounds) = credential(&state);
        assert_eq!(salt.len(), 32);
        assert_eq!(verifier.len(), digest::SHA256_OUTPUT_LEN);
        assert_eq!(rounds, PASSWORD_ROUNDS);
        assert!(account_login(&mut state, "alice", json!({"password":password})).is_ok());
        assert_eq!(
            account_login(
                &mut state,
                "alice",
                json!({"password":format!("{password}x")})
            )
            .err()
            .unwrap()
            .status,
            400
        );
    }
    account_write(&mut state, &root, "alice", json!({"password":"e\u{301}"})).unwrap();
    assert_eq!(
        account_login(&mut state, "alice", json!({"password":"é"}))
            .err()
            .unwrap()
            .status,
        400
    );
    let serialized = serde_json::to_vec(&state).unwrap();
    let mut reopened: AuthState = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(credential(&state), credential(&reopened));
    assert!(account_login(&mut reopened, "alice", json!({"password":"e\u{301}"})).is_ok());
}

#[test]
fn userpass_empty_or_null_general_update_preserves_verifier_and_can_update_other_fields() {
    let (mut state, root) = configured();
    account_write(
        &mut state,
        &root,
        "alice",
        json!({"password":"old compatible credential"}),
    )
    .unwrap();
    let before = credential(&state);
    for body in [
        json!({"token_ttl":15}),
        json!({"password":"","token_ttl":20}),
        json!({"password":null,"token_ttl":25}),
    ] {
        let ttl = body["token_ttl"].as_u64().unwrap();
        account_write(&mut state, &root, "alice", body).unwrap();
        assert_eq!(credential(&state), before);
        let response = account_login(
            &mut state,
            "alice",
            json!({"password":"old compatible credential"}),
        )
        .unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], ttl);
    }
    for body in [json!({}), json!({"password":""}), json!({"password":null})] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            account_write(&mut state, &root, "new-user", body)
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    }
}

#[test]
fn userpass_dedicated_reset_requires_existing_user_and_nonempty_replacement() {
    let (mut state, root) = configured();
    let before = provider_renewal::state_revision(&state).unwrap();
    assert_eq!(
        account_write(
            &mut state,
            &root,
            "unknown/password",
            json!({"password":"x"})
        )
        .err()
        .unwrap()
        .status,
        500
    );
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    account_write(
        &mut state,
        &root,
        "alice",
        json!({"password":"old compatible credential"}),
    )
    .unwrap();
    let login = account_login(
        &mut state,
        "alice",
        json!({"password":"old compatible credential"}),
    )
    .unwrap();
    let issued = login.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    for body in [json!({}), json!({"password":""}), json!({"password":null})] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            account_write(&mut state, &root, "alice/password", body)
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    }
    account_write(
        &mut state,
        &root,
        "alice/password",
        json!({"password":"新"}),
    )
    .unwrap();
    assert_eq!(
        account_login(
            &mut state,
            "alice",
            json!({"password":"old compatible credential"})
        )
        .err()
        .unwrap()
        .status,
        400
    );
    assert!(account_login(&mut state, "alice", json!({"password":"新"})).is_ok());
    assert!(state.authenticate(&issued, 100).is_ok());
}

#[test]
fn userpass_login_empty_and_invalid_credentials_have_endpoint_specific_statuses() {
    let (mut state, root) = configured();
    account_write(
        &mut state,
        &root,
        "alice",
        json!({"password":"correct credential"}),
    )
    .unwrap();
    for name in ["alice", "unknown"] {
        for body in [json!({}), json!({"password":null}), json!({"password":""})] {
            let before = provider_renewal::state_revision(&state).unwrap();
            assert_eq!(
                account_login(&mut state, name, body).err().unwrap().status,
                500
            );
            assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
        }
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            account_login(&mut state, name, json!({"password":"incorrect"}))
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    }
}

#[test]
fn userpass_old_long_credentials_survive_restart_and_bounded_ldap_policy_is_unchanged() {
    let (mut state, root) = configured();
    // Recreate the historical PBKDF2 record shape; old binaries accepted this
    // 840-byte credential. This is a format unit test, not a binary upgrade.
    let old_password = "long-password-".repeat(60);
    account_write(&mut state, &root, "alice", json!({"password":"initial"})).unwrap();
    let user = state
        .users_at_mut(AuthScope {
            namespace: "",
            mount: "staff",
        })
        .get_mut("alice")
        .unwrap();
    user.password_semantics = None; // Historical records had no comparison marker.
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(user.rounds).unwrap(),
        &user.salt,
        old_password.as_bytes(),
        &mut user.verifier,
    );
    let before_credential = credential(&state);
    for body in [
        json!({"token_ttl":120}),
        json!({"password":""}),
        json!({"password":null}),
    ] {
        account_write(&mut state, &root, "alice", body).unwrap();
        assert_eq!(credential(&state), before_credential);
    }
    let saved = serde_json::to_vec(&state).unwrap();
    let mut reopened: AuthState = serde_json::from_slice(&saved).unwrap();
    assert_eq!(credential(&state), credential(&reopened));
    assert!(account_login(&mut reopened, "alice", json!({"password":old_password})).is_ok());
    mount_auth(&mut state, &root, "", "directory", "ldap");
    let before = provider_renewal::state_revision(&state).unwrap();
    assert_eq!(
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "auth/directory/users/alice",
                &json!({"password":"short"}),
                100
            )
            .err()
            .unwrap()
            .status,
        400
    );
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    let before = provider_renewal::state_revision(&state).unwrap();
    assert_eq!(
        account_write(
            &mut state,
            &root,
            "alice",
            json!({"password":"x".repeat(1025)})
        )
        .err()
        .unwrap()
        .status,
        500
    );
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
}

#[test]
fn userpass_new_password_boundary_is_utf8_bytes_and_rejected_replacements_are_atomic() {
    let (mut state, root) = configured();
    account_write(&mut state, &root, "alice", json!({"password":"initial"})).unwrap();
    let login = account_login(&mut state, "alice", json!({"password":"initial"})).unwrap();
    let issued = login.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    for (prefix, accepted) in [
        ("a".repeat(71), "a".repeat(72)),
        ("短".repeat(23) + "ab", "短".repeat(24)),
    ] {
        assert_eq!(prefix.len(), 71);
        account_write(&mut state, &root, "alice", json!({"password":prefix})).unwrap();
        assert!(account_login(&mut state, "alice", json!({"password":prefix})).is_ok());
        assert_eq!(accepted.len(), 72);
        account_write(
            &mut state,
            &root,
            "alice/password",
            json!({"password":accepted}),
        )
        .unwrap();
        assert!(account_login(&mut state, "alice", json!({"password":accepted})).is_ok());
        let too_long = accepted.clone() + "x";
        assert_eq!(too_long.len(), 73);
        for route in ["new-account", "alice", "alice/password"] {
            let before = provider_renewal::state_revision(&state).unwrap();
            assert_eq!(
                account_write(&mut state, &root, route, json!({"password":too_long}))
                    .err()
                    .unwrap()
                    .status,
                500
            );
            assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
        }
        assert!(account_login(&mut state, "alice", json!({"password":accepted})).is_ok());
        assert!(state.authenticate(&issued, 100).is_ok());
    }
}
