use super::*;
use userpass_bcrypt::ImportedBcrypt;

fn hash(password: &str) -> Zeroizing<String> {
    Zeroizing::new(
        bcrypt::hash_with_salt(password, 5, [7; 16])
            .unwrap()
            .format_for_version(bcrypt::Version::TwoB),
    )
}
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
fn login(state: &mut AuthState, name: &str, password: &str) -> Result<AuthResponse, AuthError> {
    state
        .handle(
            None,
            "",
            "POST",
            &format!("auth/staff/login/{name}"),
            &json!({"password":password}),
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
fn bcrypt_import_go_header_variants_are_verified_by_library_and_bad_tails_cannot_authenticate() {
    let h = hash("imported credential");
    let alphabet = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let salt_last = alphabet
        .iter()
        .position(|b| *b == h.as_bytes()[28])
        .unwrap();
    let salt_variant = format!(
        "{}{}{}",
        &h[..28],
        char::from(alphabet[salt_last + 1]),
        &h[29..]
    );
    for value in [
        format!("{}{}", &h[..2], &h[3..]),
        format!("$2a{}", &h[3..]),
        format!("$2y{}", &h[3..]),
        format!("$2x{}", &h[3..]),
        format!("$2z{}", &h[3..]),
        format!("$1a{}", &h[3..]),
        format!("{}+5{}", &h[..4], &h[6..]),
        format!("{}!{}", &h[..3], &h[4..]),
        format!("{}!{}", &h[..6], &h[7..]),
        format!("{}EXTRA", h.as_str()),
        format!("{}短", h.as_str()),
        salt_variant,
    ] {
        let imported = ImportedBcrypt::new(&value).unwrap();
        assert!(imported.verify(b"imported credential"));
        assert!(!imported.verify(b"incorrect credential"));
    }
    for value in [
        h[..59].to_owned(),
        format!("{}!{}", &h[..7], &h[8..]),
        format!("{}!", &h[..59]),
        format!("{}短", &h[..59]),
    ] {
        let imported = ImportedBcrypt::new(&value).unwrap();
        assert!(!imported.verify(b"imported credential"));
        assert!(!imported.verify(b"incorrect credential"));
    }
    for value in [
        format!("$3a{}", &h[3..]),
        format!("{}04{}", &h[..4], &h[6..]),
        format!("{}13{}", &h[..4], &h[6..]),
        "not-bcrypt".into(),
    ] {
        assert_eq!(ImportedBcrypt::new(&value).err().unwrap().status, 400);
    }
    assert!(ImportedBcrypt::new(&format!("{}12{}", &h[..4], &h[6..])).is_ok());
}

#[test]
fn imported_and_pbkdf_credentials_switch_explicitly_without_fallback_and_preserve_issued_tokens() {
    let (mut state, root) = configured();
    let password = "a".repeat(72);
    let h = hash(&password);
    write(
        &mut state,
        &root,
        "alice",
        json!({"password_hash":h.as_str()}),
    )
    .unwrap();
    assert!(user(&state, "alice").salt.is_empty());
    assert!(user(&state, "alice").verifier.is_empty());
    assert_eq!(user(&state, "alice").rounds, 0);
    assert!(user(&state, "alice").password_semantics.is_none());
    assert!(state.has_userpass_password_semantics());
    state.validate_userpass_password_semantics().unwrap();
    let issued =
        login(&mut state, "alice", &"a".repeat(1025)).unwrap().body["auth"]["client_token"]
            .as_str()
            .unwrap()
            .to_owned();
    assert_eq!(
        login(&mut state, "alice", "wrong").err().unwrap().status,
        400
    );
    let before = Zeroizing::new(serde_json::to_vec(user(&state, "alice")).unwrap());
    for body in [
        json!({}),
        json!({"password_hash":""}),
        json!({"password_hash":null}),
        json!({"password":"","password_hash":null}),
    ] {
        write(&mut state, &root, "alice", body).unwrap();
        assert_eq!(
            serde_json::to_vec(user(&state, "alice")).unwrap(),
            before.as_slice()
        );
    }
    let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    state = serde_json::from_slice(&encoded).unwrap();
    assert!(login(&mut state, "alice", &password).is_ok());
    write(
        &mut state,
        &root,
        "alice/password",
        json!({"password":"new plaintext"}),
    )
    .unwrap();
    assert!(user(&state, "alice").imported_bcrypt.is_none());
    assert!(matches!(
        user(&state, "alice").password_semantics,
        Some(PasswordSemantics::Bcrypt72)
    ));
    assert_eq!(user(&state, "alice").rounds, PASSWORD_ROUNDS);
    assert_eq!(
        login(&mut state, "alice", &password).err().unwrap().status,
        400
    );
    assert!(login(&mut state, "alice", "new plaintext").is_ok());
    assert!(state.authenticate(&issued, 100).is_ok());
    write(
        &mut state,
        &root,
        "alice/password",
        json!({"password_hash":h.as_str(),"password":"","username":"other"}),
    )
    .unwrap();
    assert!(login(&mut state, "alice", &password).is_ok());
    assert_eq!(
        login(&mut state, "alice", "new plaintext")
            .err()
            .unwrap()
            .status,
        400
    );
}

#[test]
fn bcrypt_input_combinations_and_invalid_replacements_are_atomic() {
    let (mut state, root) = configured();
    let h = hash("imported credential");
    for (name, body) in [
        ("one", json!({"password":"","password_hash":h.as_str()})),
        ("two", json!({"password":null,"password_hash":h.as_str()})),
        ("three", json!({"password":"plaintext","password_hash":""})),
        ("four", json!({"password":"plaintext","password_hash":null})),
    ] {
        write(&mut state, &root, name, body).unwrap();
        assert!(
            login(
                &mut state,
                name,
                if matches!(name, "one" | "two") {
                    "imported credential"
                } else {
                    "plaintext"
                }
            )
            .is_ok()
        );
    }
    write(&mut state, &root, "alice", json!({"password":"original"})).unwrap();
    for body in [
        json!({"password":"replacement","password_hash":h.as_str()}),
        json!({"password_hash":"invalid"}),
        json!({"password_hash":h.as_str(),"token_ttl":"invalid"}),
    ] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            write(&mut state, &root, "alice", body)
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
        assert!(login(&mut state, "alice", "original").is_ok());
    }
    for body in [
        json!({}),
        json!({"password_hash":null}),
        json!({"password":"","password_hash":""}),
    ] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            write(&mut state, &root, "alice/password", body)
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    }
    assert_eq!(
        write(
            &mut state,
            &root,
            "missing/password",
            json!({"password_hash":h.as_str()})
        )
        .err()
        .unwrap()
        .status,
        500
    );
}

#[test]
fn legacy_long_pbkdf_and_bounded_ldap_do_not_adopt_hash_import_implicitly() {
    let (mut state, root) = configured();
    write(&mut state, &root, "alice", json!({"password":"initial"})).unwrap();
    let long = "l".repeat(1000);
    let account = state
        .users_at_mut(AuthScope {
            namespace: "",
            mount: "staff",
        })
        .get_mut("alice")
        .unwrap();
    account.password_semantics = None;
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(account.rounds).unwrap(),
        &account.salt,
        long.as_bytes(),
        &mut account.verifier,
    );
    let before = Zeroizing::new(serde_json::to_vec(user(&state, "alice")).unwrap());
    for body in [json!({"password_hash":null}), json!({"password_hash":""})] {
        write(&mut state, &root, "alice", body).unwrap();
        assert_eq!(
            serde_json::to_vec(user(&state, "alice")).unwrap(),
            before.as_slice()
        );
        assert!(login(&mut state, "alice", &long).is_ok());
        assert_eq!(
            login(&mut state, "alice", &(long.clone() + "x"))
                .err()
                .unwrap()
                .status,
            400
        );
    }
    mount_auth(&mut state, &root, "", "directory", "ldap");
    let h = hash("imported credential");
    let before = provider_renewal::state_revision(&state).unwrap();
    assert_eq!(
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "auth/directory/users/alice",
                &json!({"password_hash":h.as_str()}),
                100
            )
            .err()
            .unwrap()
            .status,
        400
    );
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
}

#[test]
fn imported_credentials_are_redacted_zeroized_and_reject_ambiguous_storage() {
    let (mut state, root) = configured();
    let h = hash("imported credential");
    let mut imported = ImportedBcrypt::new(&h).unwrap();
    assert_eq!(format!("{imported:?}"), "ImportedBcrypt([REDACTED])");
    imported.zeroize();
    assert_eq!(serde_json::to_value(&imported).unwrap(), json!(""));
    write(
        &mut state,
        &root,
        "alice",
        json!({"password_hash":h.as_str()}),
    )
    .unwrap();
    for (field, value) in [
        ("rounds", json!(600000)),
        ("salt", json!([1])),
        ("verifier", json!([2])),
        ("password_semantics", json!("bcrypt_72")),
        ("imported_bcrypt", json!("not-bcrypt")),
    ] {
        let mut encoded = serde_json::to_value(&state).unwrap();
        encoded["mounted_users"][""]["staff"]["alice"][field] = value;
        let invalid: AuthState = serde_json::from_value(encoded).unwrap();
        assert!(invalid.validate_userpass_password_semantics().is_err());
    }
}

#[test]
fn imported_go_variable_salts_use_the_existing_bcrypt_kernel_and_survive_serialization() {
    let password = b"synthetic-variable-salt-password";
    let standard = bcrypt::hash_with_salt(password, 5, [b'4'; 16])
        .unwrap()
        .format_for_version(bcrypt::Version::TwoB);
    for length in [1, 4, 7, 10, 13, 16] {
        // A constant periodic salt presents exactly the same byte stream to
        // Blowfish at all these lengths. Official OpenBao confirms this case.
        let encoded = base64::engine::general_purpose::GeneralPurpose::new(
            &base64::alphabet::BCRYPT,
            base64::engine::general_purpose::NO_PAD,
        )
        .encode(vec![b'4'; length]);
        let salt = format!("{encoded}{}", "\r\n".repeat((22 - encoded.len()) / 2));
        assert_eq!(salt.len(), 22);
        let value = format!("{}{}{}", &standard[..7], salt, &standard[29..]);
        let imported = ImportedBcrypt::new(&value).unwrap();
        assert!(imported.verify(password));
        assert!(!imported.verify(b"different credential"));
        let encoded = Zeroizing::new(serde_json::to_vec(&imported).unwrap());
        let reopened: ImportedBcrypt = serde_json::from_slice(&encoded).unwrap();
        assert!(reopened.verify(password));
    }
}

#[test]
fn decoded_salt_adapter_matches_normal_library_for_periodic_salts_and_password_boundaries() {
    for length in [1, 2, 4, 8, 16] {
        let salt: Vec<u8> = (0..length).map(|i| i as u8).collect();
        let mut expanded = [0u8; 16];
        for (position, value) in expanded.iter_mut().enumerate() {
            *value = salt[position % length];
        }
        for password in [
            b"short".to_vec(),
            vec![b'x'; 71],
            vec![b'x'; 72],
            vec![b'x'; 1025],
        ] {
            let standard = bcrypt::hash_with_salt(&password, 5, expanded)
                .unwrap()
                .format_for_version(bcrypt::Version::TwoB);
            assert!(
                bcrypt::verify_with_decoded_salt(&password, 5, &salt, &standard.as_bytes()[29..])
                    .unwrap()
            );
            assert!(
                !bcrypt::verify_with_decoded_salt(
                    b"incorrect",
                    5,
                    &salt,
                    &standard.as_bytes()[29..]
                )
                .unwrap()
            );
        }
    }
}

#[test]
fn decoded_salt_bounds_and_go_padding_reject_before_verification_without_pbkdf_fallback() {
    let h = hash("imported credential");
    for cost in [0, 4, 13, 31, u32::MAX] {
        assert!(
            bcrypt::verify_with_decoded_salt(b"password", cost, &[1; 16], &[b'.'; 31]).is_err()
        );
    }
    for salt in [&[][..], &[0u8; 17][..]] {
        assert!(bcrypt::verify_with_decoded_salt(b"password", 5, salt, &[b'.'; 31]).is_err());
    }
    for expected in [&[][..], &[b'.'; 30][..], &[b'.'; 32][..]] {
        assert!(bcrypt::verify_with_decoded_salt(b"password", 5, &[1; 16], expected).is_err());
    }
    for salt in [
        "\r\n".repeat(11),
        format!("{}\n", ".".repeat(21)),
        format!("{}\t\t", ".".repeat(20)),
    ] {
        let value = format!("{}{}{}", &h[..7], salt, &h[29..]);
        assert!(
            !ImportedBcrypt::new(&value)
                .unwrap()
                .verify(b"imported credential")
        );
    }
}
