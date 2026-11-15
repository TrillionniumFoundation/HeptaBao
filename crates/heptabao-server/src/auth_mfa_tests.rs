use super::*;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn mfa129_rfc6238_all_hashes_digits_and_counter_vectors_are_exact() -> TestResult {
    let cases = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000u64, "65353130", "77737706", "47863826"),
    ];
    let secrets = [
        ("SHA1", b"12345678901234567890".as_slice()),
        ("SHA256", b"12345678901234567890123456789012".as_slice()),
        (
            "SHA512",
            b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
        ),
    ];
    for (seconds, sha1, sha256, sha512) in cases {
        for ((algorithm, secret), expected) in secrets.into_iter().zip([sha1, sha256, sha512]) {
            assert_eq!(
                crate::engines::rfc6238_code(secret, algorithm, 8, seconds / 30)
                    .map_err(|_| "native RFC6238")?,
                expected
            );
            assert_eq!(
                crate::engines::rfc6238_code(secret, algorithm, 6, seconds / 30)
                    .map_err(|_| "native RFC6238")?,
                &expected[2..]
            );
        }
    }
    assert!(crate::engines::rfc6238_code(b"", "SHA1", 6, 1).is_err());
    assert!(crate::engines::rfc6238_code(b"public-rfc-fixture", "MD5", 6, 1).is_err());
    assert!(crate::engines::rfc6238_code(b"public-rfc-fixture", "SHA1", 7, 1).is_err());
    Ok(())
}

#[test]
fn mfa129_configuration_is_strict_and_ordinary_auth_bytes_keep_the_absent_floor() -> TestResult {
    let (mut auth, _) = AuthState::bootstrap(100)?;
    assert!(!auth.has_identity_mfa_state());
    let original =
        crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024).map_err(|_| "Auth encoding")?;
    let original_value: Value = heptabao_domain::json::decode(&original)?;
    assert!(original_value.get("identity_mfa").is_none());
    for invalid in [
        json!({}),
        json!({"issuer":"native","digits":7}),
        json!({"issuer":"native","algorithm":"MD5"}),
        json!({"issuer":"native","skew":2}),
        json!({"issuer":"native","period":-1}),
        json!({"issuer":"native","unknown":true}),
    ] {
        assert!(
            auth.mfa_method_route("", "root", 0, "POST", "identity/mfa/method/totp", &invalid)
                .is_err()
        );
        assert!(
            crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024)
                .map_err(|_| "Auth encoding")?
                .as_slice()
                == original.as_slice(),
            "invalid configuration must preserve private Auth state"
        );
    }
    let created = auth.mfa_method_route(
        "",
        "root",
        0,
        "POST",
        "identity/mfa/method/totp",
        &json!({"issuer":"native"}),
    )?;
    let id = created.body["data"]["method_id"]
        .as_str()
        .ok_or("native method ID")?;
    let read = auth.mfa_method_route(
        "",
        "root",
        0,
        "GET",
        &format!("identity/mfa/method/{id}"),
        &json!({}),
    )?;
    assert_eq!(read.status, 200);
    for (name, expected) in [
        ("digits", 6),
        ("key_size", 20),
        ("max_validation_attempts", 5),
        ("period", 30),
        ("qr_size", 200),
        ("skew", 1),
    ] {
        assert_eq!(read.body["data"][name].as_u64(), Some(expected));
    }
    assert_eq!(read.body["data"]["algorithm"], "SHA1");
    assert!(read.body["data"].get("secret").is_none());
    auth.validate_identity_mfa_state(None)?;
    let mut stripped = auth.clone();
    stripped.identity_mfa = None;
    assert!(stripped.validate_identity_mfa_state(Some(&auth)).is_err());
    let checkpoint = auth.clone();
    assert_eq!(
        auth.mfa_method_route(
            "",
            "root",
            0,
            "POST",
            &format!("identity/mfa/method/totp/{id}"),
            &json!({"method_name":"changed"})
        )?
        .status,
        204
    );
    assert!(checkpoint.validate_identity_mfa_state(Some(&auth)).is_err());
    let mut torn = auth.clone();
    torn.identity_mfa
        .as_mut()
        .ok_or("MFA")?
        .namespaces
        .get_mut("")
        .ok_or("owner")?
        .methods
        .get_mut(id)
        .ok_or("method")?
        .name = "forged without native mutation".into();
    assert!(torn.validate_identity_mfa_state(Some(&auth)).is_err());
    Ok(())
}

#[test]
fn mfa129_ancestor_method_parcel_and_reference_deletion_use_the_real_private_owner() -> TestResult {
    let (mut auth, _) = AuthState::bootstrap(100)?;
    let created = auth.mfa_method_route(
        "",
        "root",
        0,
        "POST",
        "identity/mfa/method/totp",
        &json!({"issuer":"parent","qr_size":0}),
    )?;
    let id = created.body["data"]["method_id"]
        .as_str()
        .ok_or("method")?
        .to_owned();
    assert_eq!(
        auth.mfa_method_route(
            "child",
            "actual-child",
            7,
            "GET",
            &format!("identity/mfa/method/{id}"),
            &json!({})
        )?
        .status,
        200
    );
    let enrolled = auth.mfa_generate("child", "actual-child", 7, "actual-entity", &id, false)?;
    assert_eq!(enrolled.status, 200);
    let encoded =
        crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024).map_err(|_| "Auth encoding")?;
    let mut reopened: AuthState = serde_json::from_slice(&encoded)?;
    let duplicate =
        reopened.mfa_generate("child", "actual-child", 7, "actual-entity", &id, false)?;
    assert!(duplicate.body["data"].is_null());
    assert!(!duplicate.mutated);
    assert!(
        crate::secret_serde::to_vec(&reopened, 16 * 1024 * 1024)
            .map_err(|_| "Auth encoding")?
            .as_slice()
            == encoded.as_slice(),
        "duplicate enrollment must preserve all private state"
    );
    let loaded_digest = reopened
        .identity_mfa
        .as_ref()
        .ok_or("MFA")?
        .semantic_digest()?;
    let parcel = reopened
        .detach_mfa_namespace("child")?
        .ok_or("actual parcel")?;
    assert!(
        reopened
            .identity_mfa
            .as_ref()
            .ok_or("MFA")?
            .semantic_digest()?
            == loaded_digest
    );
    reopened.validate_identity_mfa_state(Some(&auth))?;
    assert!(!reopened.mfa_namespace_has_assets("child"));
    assert_eq!(
        reopened
            .mfa_method_route(
                "",
                "root",
                0,
                "DELETE",
                &format!("identity/mfa/method/totp/{id}"),
                &json!({})
            )
            .err()
            .ok_or("closed reference guard")?
            .status,
        500
    );
    let closed =
        crate::secret_serde::to_vec(&reopened, 16 * 1024 * 1024).map_err(|_| "Auth encoding")?;
    let mut loaded: AuthState = serde_json::from_slice(&closed)?;
    loaded.attach_mfa_namespace("child", Some(parcel))?;
    loaded.validate_identity_mfa_state(None)?;
    assert!(loaded.mfa_namespace_has_assets("child"));
    assert_eq!(
        loaded
            .mfa_generate("child", "actual-child", 7, "actual-entity", &id, true)?
            .status,
        204
    );
    loaded.retire_mfa_namespace("child", 7)?;
    assert!(
        loaded
            .mfa_generate("child", "actual-child", 7, "actual-entity", &id, false)
            .is_err()
    );
    assert_eq!(
        loaded
            .mfa_generate(
                "child",
                "different-child",
                8,
                "different-entity",
                &id,
                false
            )?
            .status,
        200
    );
    loaded.validate_identity_mfa_state(Some(&reopened))?;
    Ok(())
}

#[test]
fn mfa129_closed_reference_successors_reject_erasure_and_forged_parcels_after_encrypted_reopen()
-> TestResult {
    let (mut auth, _) = AuthState::bootstrap(100)?;
    let created = auth.mfa_method_route(
        "",
        "root",
        0,
        "POST",
        "identity/mfa/method/totp",
        &json!({"issuer":"closed-reference-fixture","qr_size":0}),
    )?;
    let id = created.body["data"]["method_id"]
        .as_str()
        .ok_or("native method")?
        .to_owned();
    auth.mfa_generate("child", "original-child", 7, "actual-entity", &id, false)?;
    let open = auth.clone();
    let parcel = auth.detach_mfa_namespace("child")?.ok_or("native parcel")?;
    auth.validate_identity_mfa_state(Some(&open))?;
    let encoded = crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024)
        .map_err(|_| "private Auth encoding")?;
    let closed: AuthState = serde_json::from_slice(&encoded)?;
    closed.validate_identity_mfa_state(Some(&auth))?;
    for kind in ["erase", "id", "incarnation", "methods", "digest"] {
        let mut torn = closed.clone();
        let registry = torn.identity_mfa.as_mut().ok_or("registry")?;
        registry.advance_mutation()?;
        if kind == "erase" {
            registry.closed_references.remove("child");
        } else {
            let index = registry.closed_references.get_mut("child").ok_or("index")?;
            match kind {
                "id" => index.namespace_id = "different-child".into(),
                "incarnation" => index.incarnation += 1,
                "methods" => index.method_ids.clear(),
                "digest" => index.owner_digest[0] ^= 1,
                _ => return Err("unknown fixed mutation".into()),
            }
        }
        torn.validate_identity_mfa_state(None)?;
        assert!(torn.validate_identity_mfa_state(Some(&closed)).is_err());
    }
    let mut forged_open = closed.clone();
    let mut changed_owner = open
        .identity_mfa
        .as_ref()
        .ok_or("open registry")?
        .namespaces
        .get("child")
        .ok_or("open owner")?
        .clone();
    changed_owner
        .enrollments
        .get_mut("actual-entity")
        .ok_or("enrollment")?
        .get_mut(&id)
        .ok_or("method enrollment")?
        .generation += 1;
    let registry = forged_open.identity_mfa.as_mut().ok_or("registry")?;
    registry.closed_references.remove("child");
    registry.namespaces.insert("child".into(), changed_owner);
    registry.advance_mutation()?;
    forged_open.validate_identity_mfa_state(None)?;
    assert!(
        forged_open
            .validate_identity_mfa_state(Some(&closed))
            .is_err()
    );

    let mut forged_closed = open.clone();
    forged_closed
        .detach_mfa_namespace("child")?
        .ok_or("parcel")?;
    let registry = forged_closed.identity_mfa.as_mut().ok_or("registry")?;
    registry
        .closed_references
        .get_mut("child")
        .ok_or("index")?
        .owner_digest[0] ^= 1;
    registry.advance_mutation()?;
    forged_closed.validate_identity_mfa_state(None)?;
    assert!(
        forged_closed
            .validate_identity_mfa_state(Some(&open))
            .is_err()
    );

    let mut attached = closed.clone();
    attached.attach_mfa_namespace("child", Some(parcel))?;
    attached.validate_identity_mfa_state(Some(&closed))?;
    let binding = crate::namespace_custody::Binding::new(
        "actual-cluster".into(),
        "child".into(),
        "original-child".into(),
        7,
    )
    .map_err(|_| "native closed binding")?;
    let wrong = crate::namespace_custody::Binding::new(
        "actual-cluster".into(),
        "child".into(),
        "different-child".into(),
        7,
    )
    .map_err(|_| "negative closed binding")?;
    let mut retired = closed.clone();
    assert!(
        retired
            .retire_closed_mfa_namespace(&wrong, "actual-cluster")
            .is_err()
    );
    assert!(
        crate::secret_serde::to_vec(&retired, 16 * 1024 * 1024)
            .map_err(|_| "private Auth encoding")?
            .as_slice()
            == encoded.as_slice()
    );
    retired.retire_closed_mfa_namespace(&binding, "actual-cluster")?;
    retired.validate_identity_mfa_state(Some(&closed))?;
    assert!(
        !retired
            .identity_mfa
            .as_ref()
            .ok_or("registry")?
            .closed_references
            .contains_key("child")
    );
    assert_eq!(
        retired
            .identity_mfa
            .as_ref()
            .ok_or("registry")?
            .retired
            .get("child"),
        Some(&7)
    );
    retired.mfa_generate("child", "new-child", 8, "new-entity", &id, false)?;
    retired.validate_identity_mfa_state(Some(&closed))?;
    Ok(())
}

#[test]
fn mfa129_validation_issuer_mount_retirement_never_transfers_the_original_accessor() -> TestResult {
    let (mut auth, raw) = AuthState::bootstrap(100)?;
    let actor = auth.authenticate(&raw, 100)?;
    assert_eq!(
        auth.handle(
            Some(&actor),
            "",
            "POST",
            "sys/auth/mfa_native",
            &json!({"type":"userpass"}),
            100
        )?
        .ok_or("native mount")?
        .status,
        204
    );
    let scope = AuthScope {
        namespace: "",
        mount: "mfa_native",
    };
    let original = auth
        .effective_auth_mounts("")
        .get("mfa_native")
        .ok_or("native original mount")?
        .clone();
    assert!(auth.mfa_validation_mount(scope, &original).is_ok());
    assert_eq!(
        auth.handle(
            Some(&actor),
            "",
            "DELETE",
            "sys/auth/mfa_native",
            &json!({}),
            101
        )?
        .ok_or("native mount deletion")?
        .status,
        204
    );
    let retired_bytes = crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024)
        .map_err(|_| "private Auth encoding")?;
    let failure = auth
        .mfa_validation_mount(scope, &original)
        .err()
        .ok_or("retired gate")?;
    assert_eq!(failure.status, 500);
    assert_eq!(
        failure.message,
        "failed to find MFAEnforcement configuration"
    );
    assert!(
        crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024)
            .map_err(|_| "private Auth encoding")?
            .as_slice()
            == retired_bytes.as_slice()
    );
    let mut reopened: AuthState = serde_json::from_slice(&retired_bytes)?;
    let failure = reopened
        .mfa_validation_mount(scope, &original)
        .err()
        .ok_or("reopened retired gate")?;
    assert_eq!(failure.status, 500);
    assert_eq!(
        failure.message,
        "failed to find MFAEnforcement configuration"
    );
    let actor = reopened.authenticate(&raw, 102)?;
    assert_eq!(
        reopened
            .handle(
                Some(&actor),
                "",
                "POST",
                "sys/auth/mfa_native",
                &json!({"type":"userpass"}),
                102
            )?
            .ok_or("native remount")?
            .status,
        204
    );
    let replacement = reopened
        .effective_auth_mounts("")
        .get("mfa_native")
        .ok_or("native replacement mount")?
        .clone();
    assert_ne!(original.accessor, replacement.accessor);
    let before = crate::secret_serde::to_vec(&reopened, 16 * 1024 * 1024)
        .map_err(|_| "private Auth encoding")?;
    let failure = reopened
        .mfa_validation_mount(scope, &original)
        .err()
        .ok_or("remount old issuer gate")?;
    assert_eq!(failure.status, 500);
    assert_eq!(
        failure.message,
        "failed to find MFAEnforcement configuration"
    );
    assert!(reopened.mfa_validation_mount(scope, &replacement).is_ok());
    assert!(
        crate::secret_serde::to_vec(&reopened, 16 * 1024 * 1024)
            .map_err(|_| "private Auth encoding")?
            .as_slice()
            == before.as_slice()
    );
    Ok(())
}
