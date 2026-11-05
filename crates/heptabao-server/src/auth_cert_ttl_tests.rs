use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ROLE: &str = "auth/cert/certs/operator";
fn write(
    state: &mut AuthState,
    root: &Principal,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(root), "", "POST", path, &body, 100)?
        .ok_or_else(denied)
}
fn setup() -> TestResult<(AuthState, Principal, Vec<u8>)> {
    let (mut state, raw) = AuthState::bootstrap(100)?;
    let root = state.authenticate(&raw, 100)?;
    write(&mut state, &root, "sys/auth/cert", json!({"type":"cert"}))?;
    write(
        &mut state,
        &root,
        "sys/auth/cert/tune",
        json!({"default_lease_ttl":75,"max_lease_ttl":600}),
    )?;
    let leaf = include_bytes!("../testdata/cert-selector.der").to_vec();
    write(
        &mut state,
        &root,
        ROLE,
        json!({"certificate_sha256":certificate_sha256(&leaf)}),
    )?;
    Ok((state, root, leaf))
}
fn login(state: &mut AuthState, leaf: &[u8], now: u64) -> Result<AuthResponse, AuthError> {
    state
        .handle_with_client_certificates(
            None,
            "",
            "POST",
            "auth/cert/login",
            &json!({"name":"operator"}),
            now,
            Some(&[leaf.to_vec()]),
        )?
        .ok_or_else(denied)
}
fn read(state: &mut AuthState, root: &Principal) -> Result<Value, AuthError> {
    let response = state
        .handle(Some(root), "", "GET", ROLE, &json!({}), 100)?
        .ok_or_else(denied)?;
    Ok(response.body["data"].clone())
}
fn saved(state: &AuthState) -> TestResult<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(serde_json::to_vec(state)?))
}

#[test]
fn cert_native_zero_defaults_null_preservation_and_explicit_reset() -> TestResult {
    let (mut state, root, leaf) = setup()?;
    let role = read(&mut state, &root)?;
    for field in [
        "token_ttl",
        "token_max_ttl",
        "token_period",
        "token_explicit_max_ttl",
    ] {
        assert_eq!(role[field], 0);
    }
    assert!(state.has_cert_batch_state());
    assert_eq!(
        login(&mut state, &leaf, 100)?.body["auth"]["lease_duration"],
        75
    );
    write(
        &mut state,
        &root,
        ROLE,
        json!({"token_ttl":40,"token_max_ttl":300,"token_period":20,"token_explicit_max_ttl":180,"token_num_uses":2}),
    )?;
    let before = read(&mut state, &root)?;
    write(
        &mut state,
        &root,
        ROLE,
        json!({"token_ttl":null,"token_max_ttl":null,"token_period":null,"token_explicit_max_ttl":null}),
    )?;
    assert_eq!(read(&mut state, &root)?, before);
    write(
        &mut state,
        &root,
        ROLE,
        json!({"token_ttl":0,"token_max_ttl":0,"token_period":0,"token_explicit_max_ttl":0,"token_num_uses":null}),
    )?;
    write(
        &mut state,
        &root,
        "sys/auth/cert/tune",
        json!({"default_lease_ttl":95}),
    )?;
    assert_eq!(
        login(&mut state, &leaf, 100)?.body["auth"]["lease_duration"],
        95
    );
    assert_eq!(read(&mut state, &root)?["token_num_uses"], 0);
    write(
        &mut state,
        &root,
        "sys/auth/cert/tune",
        json!({"default_lease_ttl":0,"max_lease_ttl":60}),
    )?;
    assert_eq!(
        login(&mut state, &leaf, 100)?.body["auth"]["lease_duration"],
        60
    );
    state.validate_cert_batch_state()?;
    Ok(())
}

#[test]
fn cert_legacy_duration_aliases_keep_native_precedence_and_readback_shadows() -> TestResult {
    let (mut state, root, _) = setup()?;
    write(
        &mut state,
        &root,
        ROLE,
        json!({"ttl":40,"max_ttl":300,"period":20}),
    )?;
    let data = read(&mut state, &root)?;
    for (old, new) in [
        ("ttl", "token_ttl"),
        ("max_ttl", "token_max_ttl"),
        ("period", "token_period"),
    ] {
        assert_eq!(data[old], data[new]);
    }
    write(
        &mut state,
        &root,
        ROLE,
        json!({"token_ttl":null,"ttl":50,"token_period":null,"period":10}),
    )?;
    assert_eq!(read(&mut state, &root)?["ttl"], 50);
    write(
        &mut state,
        &root,
        ROLE,
        json!({"token_ttl":60,"ttl":55,"token_period":15}),
    )?;
    let data = read(&mut state, &root)?;
    assert_eq!(data["ttl"], 60);
    assert_eq!(data["token_period"], 15);
    assert!(data.get("period").is_none());
    write(
        &mut state,
        &root,
        ROLE,
        json!({"token_ttl":0,"ttl":99,"lease":88}),
    )?;
    let data = read(&mut state, &root)?;
    assert_eq!(data["token_ttl"], 0);
    assert!(data.get("ttl").is_none());
    write(
        &mut state,
        &root,
        ROLE,
        json!({"token_ttl":null,"ttl":null,"lease":35}),
    )?;
    assert_eq!(read(&mut state, &root)?["ttl"], 35);
    write(&mut state, &root, ROLE, json!({"lease":null}))?;
    assert_eq!(read(&mut state, &root)?["token_ttl"], 0);
    assert!(read(&mut state, &root)?.get("ttl").is_none());
    let bytes = saved(&state)?;
    let mut reopened: AuthState = serde_json::from_slice(&bytes)?;
    reopened.validate_cert_batch_state()?;
    assert_eq!(read(&mut reopened, &root)?, read(&mut state, &root)?);
    Ok(())
}

#[test]
fn cert_native_validation_precedes_alias_upgrade_and_rejects_atomically() -> TestResult {
    let (mut state, root, _) = setup()?;
    write(
        &mut state,
        &root,
        ROLE,
        json!({"token_ttl":300,"token_max_ttl":600}),
    )?;
    let before = saved(&state)?;
    for body in [
        json!({"ttl":30,"token_max_ttl":60}),
        json!({"token_type":"batch","token_period":30}),
        json!({"token_type":"batch","token_num_uses":2}),
        json!({"token_explicit_max_ttl":-1}),
        json!({"lease":"1m"}),
    ] {
        assert_eq!(
            write(&mut state, &root, ROLE, body)
                .err()
                .ok_or("expected error")?
                .status,
            400
        );
        assert!(before.as_slice() == saved(&state)?.as_slice());
    }
    write(
        &mut state,
        &root,
        ROLE,
        json!({"token_ttl":30,"token_max_ttl":60}),
    )?;
    Ok(())
}

#[test]
fn cert_period_and_explicit_cap_drive_initial_service_and_forced_batch_expiry() -> TestResult {
    for batch in [false, true] {
        let (mut state, root, leaf) = setup()?;
        if batch {
            write(
                &mut state,
                &root,
                "sys/auth/cert/tune",
                json!({"token_type":"batch"}),
            )?;
        }
        write(
            &mut state,
            &root,
            ROLE,
            json!({"token_type":"service","token_ttl":300,"token_period":30,"token_explicit_max_ttl":20,"token_num_uses":2}),
        )?;
        let before = state.tokens.len();
        let mut response = login(&mut state, &leaf, 100)?;
        assert_eq!(response.body["auth"]["lease_duration"], 20);
        state.bind_issued_entity(&mut response, "", "cert", "entity")?;
        state.finish_pending_batch(&mut response, "", 100)?;
        let raw = response.body["auth"]["client_token"]
            .as_str()
            .ok_or("token")?;
        let mut actor = state.authenticate(raw, 100)?;
        actor.bind_identity_policies(BTreeSet::new());
        let lookup = state
            .handle(
                Some(&actor),
                "",
                "GET",
                "auth/token/lookup-self",
                &json!({}),
                100,
            )?
            .ok_or("lookup")?;
        if batch {
            assert_eq!(state.tokens.len(), before);
            assert_eq!(response.body["auth"]["num_uses"], 2);
            assert_eq!(lookup.body["data"]["explicit_max_ttl"], 0);
            assert!(lookup.body["data"].get("period").is_none());
        } else {
            let token = state.tokens.get(&hash(raw)).ok_or("stored token")?;
            assert_eq!(token.period, 30);
            assert_eq!(token.max_expires_at, Some(120));
            assert_eq!(lookup.body["data"]["explicit_max_ttl"], 20);
        }
    }
    Ok(())
}

#[test]
fn cert_three_renew_routes_use_live_period_but_keep_issued_period_and_cap() -> TestResult {
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let (mut state, root, leaf) = setup()?;
        write(
            &mut state,
            &root,
            ROLE,
            json!({"token_period":20,"token_explicit_max_ttl":120}),
        )?;
        let issued = login(&mut state, &leaf, 100)?;
        let raw = issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("token")?
            .to_owned();
        let id = hash(&raw);
        let accessor = state.tokens[&id].accessor.clone();
        let actor = state.authenticate(&raw, 100)?;
        write(
            &mut state,
            &root,
            ROLE,
            json!({"token_period":10,"token_explicit_max_ttl":1}),
        )?;
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
        let path = format!("auth/token/{operation}");
        let response = state
            .handle_with_client_certificates(
                Some(principal),
                "",
                "POST",
                &path,
                &body,
                110,
                Some(std::slice::from_ref(&leaf)),
            )?
            .ok_or("renew")?;
        assert_eq!(response.body["auth"]["lease_duration"], 10);
        assert_eq!(state.tokens[&id].period, 20);
        assert_eq!(state.tokens[&id].max_expires_at, Some(220));
        write(
            &mut state,
            &root,
            "sys/auth/cert/tune",
            json!({"default_lease_ttl":0,"max_lease_ttl":3}),
        )?;
        let response = state
            .handle_with_client_certificates(
                Some(principal),
                "",
                "POST",
                &path,
                &body,
                111,
                Some(std::slice::from_ref(&leaf)),
            )?
            .ok_or("renew")?;
        assert_eq!(response.body["auth"]["lease_duration"], 3);
        // Ordinary age is already 11 > mount maximum 3. A current period must
        // still renew; switching current period off reinstates the age bound.
        write(&mut state, &root, ROLE, json!({"token_period":0}))?;
        let before = saved(&state)?;
        assert_eq!(
            state
                .handle_with_client_certificates(
                    Some(principal),
                    "",
                    "POST",
                    &path,
                    &body,
                    112,
                    Some(std::slice::from_ref(&leaf))
                )
                .err()
                .ok_or("past max")?
                .status,
            500
        );
        assert!(before.as_slice() == saved(&state)?.as_slice());
    }
    Ok(())
}

#[test]
fn cert_native_default_renewal_follows_mount_and_never_loses_certificate_binding() -> TestResult {
    let (mut state, root, leaf) = setup()?;
    let issued = login(&mut state, &leaf, 100)?;
    let raw = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    let actor = state.authenticate(&raw, 100)?;
    write(
        &mut state,
        &root,
        "sys/auth/cert/tune",
        json!({"default_lease_ttl":95}),
    )?;
    let before = saved(&state)?;
    assert_eq!(
        state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/token/renew-self",
                &json!({}),
                101
            )
            .err()
            .ok_or("binding error")?
            .status,
        400
    );
    assert!(before.as_slice() == saved(&state)?.as_slice());
    for body in [json!({}), json!({"increment":0})] {
        let response = state
            .handle_with_client_certificates(
                Some(&actor),
                "",
                "POST",
                "auth/token/renew-self",
                &body,
                101,
                Some(std::slice::from_ref(&leaf)),
            )?
            .ok_or("renew")?;
        assert_eq!(response.body["auth"]["lease_duration"], 95);
    }
    // A historical absolute cap remains authoritative, even though fresh
    // ordinary cert tokens no longer record one.
    state
        .tokens
        .get_mut(&hash(&raw))
        .ok_or("token")?
        .max_expires_at = Some(120);
    let response = state
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
    assert_eq!(response.body["auth"]["lease_duration"], 18);
    Ok(())
}

#[test]
fn cert_legacy_positive_role_bytes_and_new_native_state_admission_are_separate() -> TestResult {
    let (mut state, root, leaf) = setup()?;
    write(
        &mut state,
        &root,
        ROLE,
        json!({"token_ttl":120,"token_max_ttl":600}),
    )?;
    let bytes = serde_json::to_vec(&state.cert_roles[""]["cert"]["operator"])?;
    let legacy: CertRole = serde_json::from_slice(&bytes)?;
    assert_eq!(serde_json::to_vec(&legacy)?, bytes);
    assert!(!cert_ttl::has_native_shape(&legacy));
    write(&mut state, &root, ROLE, json!({"token_period":30}))?;
    let token = login(&mut state, &leaf, 100)?;
    assert!(token.body["auth"]["client_token"].as_str().is_some());
    state
        .cert_roles
        .get_mut("")
        .ok_or("namespace")?
        .get_mut("cert")
        .ok_or("mount")?
        .clear();
    assert!(
        state.has_cert_batch_state(),
        "issued periodic cert still needs the reader gate"
    );
    let mut invalid: AuthState = serde_json::from_slice(&saved(&state)?)?;
    invalid
        .cert_roles
        .entry("".into())
        .or_default()
        .entry("missing".into())
        .or_default()
        .insert(
            "operator".into(),
            CertRole {
                token_ttl: 0,
                ..legacy
            },
        );
    assert!(invalid.validate_cert_batch_state().is_err());
    Ok(())
}
