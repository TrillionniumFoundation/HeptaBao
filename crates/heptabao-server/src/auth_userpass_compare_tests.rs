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
fn login(state: &mut AuthState, password: &str) -> Result<AuthResponse, AuthError> {
    state
        .handle(
            None,
            "",
            "POST",
            "auth/staff/login/alice",
            &json!({"password":password}),
            100,
        )?
        .ok_or_else(denied)
}
fn old_credential(state: &mut AuthState, password: &str) {
    // Faithful old PBKDF2 shape, not an assertion of a real binary upgrade.
    let user = state
        .users_at_mut(AuthScope {
            namespace: "",
            mount: "staff",
        })
        .get_mut("alice")
        .unwrap();
    user.password_semantics = None;
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(user.rounds).unwrap(),
        &user.salt,
        password.as_bytes(),
        &mut user.verifier,
    );
}

#[test]
fn newly_written_userpass_passwords_compare_first_72_bytes_without_reducing_kdf_strength() {
    let (mut state, root) = configured();
    for password in ["a".repeat(72), "短".repeat(24)] {
        write(&mut state, &root, "alice", json!({"password":password})).unwrap();
        let user = &state
            .users_at(AuthScope {
                namespace: "",
                mount: "staff",
            })
            .unwrap()["alice"];
        assert!(matches!(
            user.password_semantics,
            Some(PasswordSemantics::Bcrypt72)
        ));
        assert_eq!(user.rounds, PASSWORD_ROUNDS);
        assert_eq!(user.salt.len(), 32);
        assert_eq!(user.verifier.len(), digest::SHA256_OUTPUT_LEN);
        for length in [72, 73, 80, 1025] {
            let supplied = password.clone() + &"x".repeat(length - 72);
            assert!(login(&mut state, &supplied).is_ok());
            let wrong = if password.is_ascii() {
                "b".to_owned() + &supplied[1..]
            } else {
                "长".to_owned() + &supplied[3..]
            };
            assert_eq!(login(&mut state, &wrong).err().unwrap().status, 400);
        }
        let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        state = serde_json::from_slice(&encoded).unwrap();
        state.validate_userpass_password_semantics().unwrap();
        assert!(login(&mut state, &(password + &"x".repeat(1000))).is_ok());
    }
    write(
        &mut state,
        &root,
        "alice",
        json!({"password":"a".repeat(71)}),
    )
    .unwrap();
    assert_eq!(
        login(&mut state, &"a".repeat(72)).err().unwrap().status,
        400
    );
}

#[test]
fn comparison_prefix_is_bytes_even_when_72_cuts_a_utf8_codepoint() {
    let (mut state, root) = configured();
    write(&mut state, &root, "alice", json!({"password":"initial"})).unwrap();
    let user = &state
        .users_at(AuthScope {
            namespace: "",
            mount: "staff",
        })
        .unwrap()["alice"];
    let supplied = "a".repeat(71) + "短";
    let prefix = userpass_password_semantics::password_bytes(Some(user), &supplied).unwrap();
    assert_eq!(prefix.len(), 72);
    assert_eq!(prefix, &supplied.as_bytes()[..72]);
    assert!(std::str::from_utf8(prefix).is_err());
    assert_eq!(login(&mut state, &supplied).err().unwrap().status, 400);
    // Unknown users still reach the dummy KDF for a bounded long HTTP input.
    assert_eq!(
        userpass_password_semantics::password_bytes(None, &"a".repeat(1025))
            .unwrap()
            .len(),
        72
    );
}

#[test]
fn historical_long_and_72_byte_passwords_remain_exact_until_explicit_replacement() {
    let (mut state, root) = configured();
    write(&mut state, &root, "alice", json!({"password":"initial"})).unwrap();
    for password in ["a".repeat(72), "b".repeat(73), "c".repeat(1024)] {
        old_credential(&mut state, &password);
        let user_before = Zeroizing::new(
            serde_json::to_vec(
                &state
                    .users_at(AuthScope {
                        namespace: "",
                        mount: "staff",
                    })
                    .unwrap()["alice"],
            )
            .unwrap(),
        );
        assert!(!state.has_userpass_password_semantics());
        let token = login(&mut state, &password).unwrap().body["auth"]["client_token"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(!state.has_userpass_password_semantics());
        assert_eq!(
            login(&mut state, &(password.clone() + "x"))
                .err()
                .unwrap()
                .status,
            400
        );
        for body in [json!({}), json!({"password":""}), json!({"password":null})] {
            write(&mut state, &root, "alice", body).unwrap();
            assert!(!state.has_userpass_password_semantics());
        }
        let user_after = Zeroizing::new(
            serde_json::to_vec(
                &state
                    .users_at(AuthScope {
                        namespace: "",
                        mount: "staff",
                    })
                    .unwrap()["alice"],
            )
            .unwrap(),
        );
        assert_eq!(user_before.as_slice(), user_after.as_slice());
        let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        state = serde_json::from_slice(&encoded).unwrap();
        assert!(login(&mut state, &password).is_ok());
        assert!(state.authenticate(&token, 100).is_ok());
    }
    write(
        &mut state,
        &root,
        "alice/password",
        json!({"password":"x".repeat(72)}),
    )
    .unwrap();
    assert!(state.has_userpass_password_semantics());
    assert!(login(&mut state, &"x".repeat(1025)).is_ok());
}

#[test]
fn rejected_replacement_preserves_legacy_and_marked_credentials_and_unknown_tags_fail() {
    let (mut state, root) = configured();
    write(&mut state, &root, "alice", json!({"password":"initial"})).unwrap();
    for legacy in [true, false] {
        if legacy {
            old_credential(&mut state, &"a".repeat(73));
        } else {
            write(
                &mut state,
                &root,
                "alice/password",
                json!({"password":"a".repeat(72)}),
            )
            .unwrap();
        }
        for body in [
            json!({"password":"b".repeat(73)}),
            json!({"password":"replacement","token_ttl":"invalid"}),
        ] {
            let before = provider_renewal::state_revision(&state).unwrap();
            assert!(write(&mut state, &root, "alice", body).is_err());
            assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
        }
    }
    let mut serialized = serde_json::to_value(&state).unwrap();
    serialized["mounted_users"][""]["staff"]["alice"]["password_semantics"] =
        json!("unknown_version");
    assert!(serde_json::from_value::<AuthState>(serialized).is_err());
    mount_auth(&mut state, &root, "", "directory", "ldap");
    state
        .handle(
            Some(&root),
            "",
            "POST",
            "auth/directory/users/bob",
            &json!({"password":"bounded credential"}),
            100,
        )
        .unwrap();
    assert!(
        state
            .users_at(AuthScope {
                namespace: "",
                mount: "directory"
            })
            .unwrap()["bob"]
            .password_semantics
            .is_none()
    );
    state
        .users_at_mut(AuthScope {
            namespace: "",
            mount: "directory",
        })
        .get_mut("bob")
        .unwrap()
        .password_semantics = Some(PasswordSemantics::Bcrypt72);
    assert!(state.validate_userpass_password_semantics().is_err());
}
