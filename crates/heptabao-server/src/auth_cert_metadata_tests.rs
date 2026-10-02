use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ROLE: &str = "auth/cert/certs/operator";
fn call(
    state: &mut AuthState,
    actor: &Principal,
    method: &str,
    path: &str,
    body: Value,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(actor), "", method, path, &body, now)?
        .ok_or_else(denied)
}
fn setup() -> TestResult<(AuthState, Principal, Vec<u8>)> {
    let (mut state, raw) = AuthState::bootstrap(100)?;
    let root = state.authenticate(&raw, 100)?;
    call(
        &mut state,
        &root,
        "POST",
        "sys/auth/cert",
        json!({"type":"cert"}),
        100,
    )?;
    call(
        &mut state,
        &root,
        "POST",
        "sys/policies/acl/cert-parent",
        json!({"policy":"path \"auth/token/create\" { capabilities=[\"update\",\"sudo\"] } path \"auth/token/create-orphan\" { capabilities=[\"update\",\"sudo\"] }"}),
        100,
    )?;
    let leaf = include_bytes!("../testdata/cert-selector.der").to_vec();
    call(
        &mut state,
        &root,
        "POST",
        ROLE,
        json!({"certificate_sha256":certificate_sha256(&leaf),
        "token_policies":["default","cert-parent"],"token_ttl":300,"token_max_ttl":600,
        "allowed_metadata_extensions":["1.2.3.4.5"]}),
        100,
    )?;
    Ok((state, root, leaf))
}
fn login(state: &mut AuthState, leaf: &[u8]) -> Result<AuthResponse, AuthError> {
    state
        .handle_with_client_certificates(
            None,
            "",
            "POST",
            "auth/cert/login",
            &json!({"name":"operator"}),
            100,
            Some(&[leaf.to_vec()]),
        )?
        .ok_or_else(denied)
}
fn token_text(response: &AuthResponse) -> TestResult<String> {
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned())
}
fn bytes(state: &AuthState) -> TestResult<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(serde_json::to_vec(state)?))
}

#[test]
fn cert_issued_metadata_lookup_and_three_renewals_ignore_current_extension_configuration()
-> TestResult {
    let (mut state, root, leaf) = setup()?;
    let issued = login(&mut state, &leaf)?;
    let original = issued.body["auth"]["metadata"].clone();
    assert_eq!(original["cert_name"], "operator");
    assert!(original.get("1-2-3-4-5").is_some());
    let raw = token_text(&issued)?;
    let actor = state.authenticate(&raw, 100)?;
    let accessor = state.tokens[&hash(&raw)].accessor.clone();
    call(
        &mut state,
        &root,
        "POST",
        ROLE,
        json!({"token_ttl":60,"allowed_metadata_extensions":[]}),
        101,
    )?;
    let newer = login(&mut state, &leaf)?;
    assert!(newer.body["auth"]["metadata"].get("1-2-3-4-5").is_none());
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let body = match operation {
            "renew-self" => json!({}),
            "renew" => json!({"token":raw}),
            _ => json!({"accessor":accessor}),
        };
        let principal = if operation == "renew-self" {
            &actor
        } else {
            &root
        };
        let response = state
            .handle_with_client_certificates(
                Some(principal),
                "",
                "POST",
                &format!("auth/token/{operation}"),
                &body,
                102,
                Some(std::slice::from_ref(&leaf)),
            )?
            .ok_or("renew")?;
        assert_eq!(response.body["auth"]["metadata"], original);
        assert_eq!(response.body["auth"]["lease_duration"], 60);
        assert_eq!(response.body["auth"]["orphan"], true);
        assert_eq!(response.body["auth"]["num_uses"], 0);
    }
    let mut reopened: AuthState = serde_json::from_slice(&bytes(&state)?)?;
    reopened.validate_cert_batch_state()?;
    let before = bytes(&reopened)?;
    for (actor, path, body) in [
        (&actor, "auth/token/lookup-self", json!({})),
        (&root, "auth/token/lookup", json!({"token":raw})),
        (
            &root,
            "auth/token/lookup-accessor",
            json!({"accessor":accessor}),
        ),
    ] {
        let response = call(&mut reopened, actor, "POST", path, body, 103)?;
        assert_eq!(response.body["data"]["meta"], original);
        assert_eq!(response.body["data"]["creation_ttl"], 300);
    }
    assert!(before.as_slice() == bytes(&reopened)?.as_slice());
    Ok(())
}

#[test]
fn cert_retained_metadata_alone_requires_new_reader_after_role_deletion() -> TestResult {
    let (mut state, root, leaf) = setup()?;
    let issued = login(&mut state, &leaf)?;
    let raw = token_text(&issued)?;
    let metadata = issued.body["auth"]["metadata"].clone();
    call(&mut state, &root, "DELETE", ROLE, json!({}), 101)?;
    assert!(state.has_cert_issued_metadata());
    assert!(state.has_cert_batch_state());
    let mut reopened: AuthState = serde_json::from_slice(&bytes(&state)?)?;
    reopened.validate_cert_batch_state()?;
    assert_eq!(
        call(
            &mut reopened,
            &root,
            "POST",
            "auth/token/lookup",
            json!({"token":raw}),
            102
        )?
        .body["data"]["meta"],
        metadata
    );
    call(
        &mut reopened,
        &root,
        "DELETE",
        "sys/auth/cert",
        json!({}),
        103,
    )?;
    assert!(!reopened.has_cert_issued_metadata());
    assert!(!reopened.tokens.contains_key(&hash(&raw)));
    Ok(())
}

#[test]
fn cert_token_api_child_and_orphan_do_not_inherit_certificate_snapshot() -> TestResult {
    let (mut state, root, leaf) = setup()?;
    let issued = login(&mut state, &leaf)?;
    let raw = token_text(&issued)?;
    let parent = state.authenticate(&raw, 100)?;
    for orphan in [false, true] {
        let created = call(
            &mut state,
            &parent,
            "POST",
            if orphan {
                "auth/token/create-orphan"
            } else {
                "auth/token/create"
            },
            json!({"policies":["default"],"ttl":120}),
            100,
        )?;
        let child = token_text(&created)?;
        let child_token = &state.tokens[&hash(&child)];
        assert!(matches!(
            child_token.auth_provenance,
            Some(TokenAuthProvenance::TokenApi { .. })
        ));
        assert!(child_token.auth_cert_role.is_none());
        assert!(cert_metadata::snapshot(child_token).is_none());
        let lookup = call(
            &mut state,
            &root,
            "POST",
            "auth/token/lookup",
            json!({"token":child}),
            101,
        )?;
        assert!(lookup.body["data"].get("meta").is_none());
        let actor = state.authenticate(&child, 101)?;
        let renewal = call(
            &mut state,
            &actor,
            "POST",
            "auth/token/renew-self",
            json!({"increment":120}),
            101,
        )?;
        assert!(renewal.body["auth"].get("metadata").is_none());
    }
    Ok(())
}

#[test]
fn cert_old_none_tokens_never_infer_or_backfill_metadata_on_read_or_renewal() -> TestResult {
    let (mut state, root, leaf) = setup()?;
    let issued = login(&mut state, &leaf)?;
    let raw = token_text(&issued)?;
    let id = hash(&raw);
    let token = state.tokens.get_mut(&id).ok_or("token")?;
    if let Some(TokenAuthProvenance::Cert {
        issued_metadata, ..
    }) = &mut token.auth_provenance
    {
        approle_metadata::erase(issued_metadata);
    }
    token.auth_provenance = None;
    let legacy = bytes(&state)?;
    let mut reopened: AuthState = serde_json::from_slice(&legacy)?;
    assert!(legacy.as_slice() == bytes(&reopened)?.as_slice());
    assert!(!reopened.has_cert_issued_metadata());
    let lookup = call(
        &mut reopened,
        &root,
        "POST",
        "auth/token/lookup",
        json!({"token":raw}),
        100,
    )?;
    assert!(lookup.body["data"].get("meta").is_none());
    assert!(lookup.body["data"].get("creation_ttl").is_none());
    assert!(legacy.as_slice() == bytes(&reopened)?.as_slice());
    let actor = reopened.authenticate(&raw, 100)?;
    let accessor = reopened.tokens[&id].accessor.clone();
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let body = match operation {
            "renew-self" => json!({}),
            "renew" => json!({"token":raw}),
            _ => json!({"accessor":accessor}),
        };
        let principal = if operation == "renew-self" {
            &actor
        } else {
            &root
        };
        let response = reopened
            .handle_with_client_certificates(
                Some(principal),
                "",
                "POST",
                &format!("auth/token/{operation}"),
                &body,
                101,
                Some(std::slice::from_ref(&leaf)),
            )?
            .ok_or("renew")?;
        assert!(response.body["auth"].get("metadata").is_none());
    }
    assert!(reopened.tokens[&id].auth_provenance.is_none());
    assert!(!reopened.has_cert_issued_metadata());
    Ok(())
}

#[test]
fn cert_metadata_validation_allows_empty_certificate_attributes_but_rejects_wrong_origin()
-> TestResult {
    let (mut state, _, leaf) = setup()?;
    let issued = login(&mut state, &leaf)?;
    let id = hash(&token_text(&issued)?);
    let token = state.tokens.get_mut(&id).ok_or("token")?;
    let Some(TokenAuthProvenance::Cert {
        issued_metadata, ..
    }) = &mut token.auth_provenance
    else {
        return Err("snapshot".into());
    };
    for key in ["common_name", "subject_key_id", "authority_key_id"] {
        issued_metadata.insert(key.into(), String::new());
    }
    state.validate_cert_issued_metadata()?;
    for change in 0..5 {
        let mut altered = state.clone();
        let token = altered.tokens.get_mut(&id).ok_or("token")?;
        match change {
            0 => token.parent = Some("0".repeat(64)),
            1 => token.auth_mount = Some("userpass".into()),
            2 => token.auth_cert_sha256 = Some("wrong".into()),
            3 => {
                if let Some(TokenAuthProvenance::Cert {
                    issued_metadata, ..
                }) = &mut token.auth_provenance
                {
                    issued_metadata.insert("cert_name".into(), "different".into());
                }
            }
            _ => {
                if let Some(TokenAuthProvenance::Cert {
                    issued_metadata, ..
                }) = &mut token.auth_provenance
                {
                    issued_metadata.insert(
                        "common_name".into(),
                        "x".repeat(crate::login_metadata::MAX_BYTES),
                    );
                }
            }
        }
        assert!(altered.validate_cert_issued_metadata().is_err());
    }
    Ok(())
}

#[test]
fn cert_opaque_leaf_test_profile_records_empty_metadata_without_claiming_x509_attributes()
-> TestResult {
    let (mut state, root, _) = setup()?;
    let opaque = b"synthetic opaque leaf, not a TLS certificate".to_vec();
    call(
        &mut state,
        &root,
        "POST",
        ROLE,
        json!({"certificate_sha256":certificate_sha256(&opaque),"allowed_metadata_extensions":[]}),
        100,
    )?;
    let issued = login(&mut state, &opaque)?;
    assert_eq!(issued.body["auth"]["metadata"], json!({}));
    let raw = token_text(&issued)?;
    state.validate_cert_issued_metadata()?;
    assert_eq!(
        call(
            &mut state,
            &root,
            "POST",
            "auth/token/lookup",
            json!({"token":raw}),
            100
        )?
        .body["data"]["meta"],
        json!({})
    );
    Ok(())
}

#[test]
fn cert_creation_grant_is_issued_ttl_not_role_ttl_or_renewed_remaining() -> TestResult {
    let (mut state, root, leaf) = setup()?;
    call(
        &mut state,
        &root,
        "POST",
        ROLE,
        json!({"token_ttl":60,"token_period":20,"token_explicit_max_ttl":120}),
        100,
    )?;
    let issued = login(&mut state, &leaf)?;
    assert_eq!(issued.body["auth"]["lease_duration"], 20);
    let raw = token_text(&issued)?;
    let id = hash(&raw);
    assert_eq!(cert_metadata::creation_ttl(&state.tokens[&id]), Some(20));
    call(
        &mut state,
        &root,
        "POST",
        ROLE,
        json!({"token_period":10,"token_explicit_max_ttl":1}),
        101,
    )?;
    let actor = state.authenticate(&raw, 102)?;
    let renewed = state
        .handle_with_client_certificates(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({"increment":300}),
            102,
            Some(std::slice::from_ref(&leaf)),
        )?
        .ok_or("renew")?;
    assert_eq!(renewed.body["auth"]["lease_duration"], 10);
    state.validate_cert_batch_state()?;
    call(&mut state, &root, "DELETE", ROLE, json!({}), 103)?;
    let mut reopened: AuthState = serde_json::from_slice(&bytes(&state)?)?;
    reopened.validate_cert_batch_state()?;
    let response = call(
        &mut reopened,
        &root,
        "POST",
        "auth/token/lookup",
        json!({"token":raw}),
        104,
    )?;
    assert_eq!(response.body["data"]["creation_ttl"], 20);
    assert_eq!(response.body["data"]["ttl"], 8);
    assert_eq!(response.body["data"]["period"], 20);
    assert_eq!(response.body["data"]["explicit_max_ttl"], 120);
    Ok(())
}

#[test]
fn cert_missing_creation_snapshot_stays_absent_through_reopen_and_renew() -> TestResult {
    let (mut state, root, leaf) = setup()?;
    let raw = token_text(&login(&mut state, &leaf)?)?;
    let id = hash(&raw);
    let Some(TokenAuthProvenance::Cert {
        issued_creation_ttl,
        ..
    }) = &mut state.tokens.get_mut(&id).ok_or("token")?.auth_provenance
    else {
        return Err("origin".into());
    };
    *issued_creation_ttl = None;
    let original = bytes(&state)?;
    let mut reopened: AuthState = serde_json::from_slice(&original)?;
    reopened.validate_cert_batch_state()?;
    assert!(
        original.as_slice() == bytes(&reopened)?.as_slice(),
        "old cert owner changed"
    );
    let before = call(
        &mut reopened,
        &root,
        "POST",
        "auth/token/lookup",
        json!({"token":raw}),
        100,
    )?;
    assert!(before.body["data"].get("creation_ttl").is_none());
    let actor = reopened.authenticate(&raw, 101)?;
    reopened
        .handle_with_client_certificates(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({"increment":60}),
            101,
            Some(std::slice::from_ref(&leaf)),
        )?
        .ok_or("renew")?;
    assert_eq!(cert_metadata::creation_ttl(&reopened.tokens[&id]), None);
    let after = call(
        &mut reopened,
        &root,
        "POST",
        "auth/token/lookup",
        json!({"token":raw}),
        102,
    )?;
    assert!(after.body["data"].get("creation_ttl").is_none());
    Ok(())
}

#[test]
fn cert_creation_snapshot_validates_even_with_empty_metadata_and_deleted_role() -> TestResult {
    let (mut state, root, leaf) = setup()?;
    let raw = token_text(&login(&mut state, &leaf)?)?;
    let id = hash(&raw);
    let Some(TokenAuthProvenance::Cert {
        issued_metadata, ..
    }) = &mut state.tokens.get_mut(&id).ok_or("token")?.auth_provenance
    else {
        return Err("origin".into());
    };
    approle_metadata::erase(issued_metadata);
    call(&mut state, &root, "DELETE", ROLE, json!({}), 101)?;
    assert!(state.has_cert_batch_state());
    state.validate_cert_batch_state()?;
    for ttl in [0, MAX_TTL + 1] {
        let mut invalid = state.clone();
        let Some(TokenAuthProvenance::Cert {
            issued_creation_ttl,
            ..
        }) = &mut invalid.tokens.get_mut(&id).ok_or("token")?.auth_provenance
        else {
            return Err("origin".into());
        };
        *issued_creation_ttl = Some(ttl);
        assert!(invalid.validate_cert_batch_state().is_err());
    }
    Ok(())
}

#[test]
fn cert_admin_renewal_reports_target_remaining_uses_not_actor_or_role_defaults() -> TestResult {
    let (mut state, root, leaf) = setup()?;
    call(
        &mut state,
        &root,
        "POST",
        ROLE,
        json!({"token_num_uses":2}),
        100,
    )?;
    let issued = login(&mut state, &leaf)?;
    let raw = token_text(&issued)?;
    let id = hash(&raw);
    let accessor = state.tokens[&id].accessor.clone();
    call(
        &mut state,
        &root,
        "POST",
        ROLE,
        json!({"token_num_uses":7}),
        101,
    )?;
    for (route, body) in [
        ("renew", json!({"token":raw,"increment":60})),
        (
            "renew-accessor",
            json!({"accessor":accessor,"increment":60}),
        ),
    ] {
        let response = state
            .handle_with_client_certificates(
                Some(&root),
                "",
                "POST",
                &format!("auth/token/{route}"),
                &body,
                102,
                Some(std::slice::from_ref(&leaf)),
            )?
            .ok_or("renew")?;
        assert_eq!(response.body["auth"]["num_uses"], 2);
        assert_eq!(response.body["auth"]["orphan"], true);
    }
    Ok(())
}

#[test]
fn cert_missing_role_read_is_empty_404_after_acl_without_changing_renewal_failure() -> TestResult {
    let (mut state, root, leaf) = setup()?;
    let raw = token_text(&login(&mut state, &leaf)?)?;
    let actor = state.authenticate(&raw, 100)?;
    call(&mut state, &root, "DELETE", ROLE, json!({}), 101)?;
    let before = bytes(&state)?;
    let missing = call(&mut state, &root, "GET", ROLE, json!({}), 102)?;
    assert_eq!(missing.status, 404);
    assert_eq!(missing.body, json!({}));
    assert!(!missing.mutated);
    for principal in [None, Some(&actor)] {
        let denied = state.handle(principal, "", "GET", ROLE, &json!({}), 102);
        assert!(matches!(denied, Err(AuthError { status: 403, .. })));
    }
    let renewal = state.handle_with_client_certificates(
        Some(&actor),
        "",
        "POST",
        "auth/token/renew-self",
        &json!({}),
        102,
        Some(std::slice::from_ref(&leaf)),
    );
    assert!(matches!(renewal, Err(AuthError { status: 403, .. })));
    assert!(
        before.as_slice() == bytes(&state)?.as_slice(),
        "missing role operation changed auth state"
    );
    Ok(())
}
