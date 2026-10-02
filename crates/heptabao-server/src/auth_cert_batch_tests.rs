use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const MOUNT: &str = "nested/cert";
const ROLE: &str = "auth/nested/cert/certs/operator";
fn write(
    state: &mut AuthState,
    admin: &Principal,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(admin), "", "POST", path, &body, 100)?
        .ok_or_else(|| bad("missing route"))
}
fn fixture() -> TestResult<(AuthState, Principal, Vec<u8>)> {
    let (mut state, raw) = AuthState::bootstrap(100)?;
    let admin = state.authenticate(&raw, 100)?;
    let leaf = include_bytes!("../testdata/cert-selector.der").to_vec();
    write(
        &mut state,
        &admin,
        "sys/auth/nested/cert",
        json!({"type":"cert"}),
    )?;
    write(
        &mut state,
        &admin,
        ROLE,
        json!({"certificate_sha256":certificate_sha256(&leaf),
        "token_ttl":120,"token_max_ttl":600,"allowed_common_names":["client.example.test"],
        "allowed_metadata_extensions":["1.2.3.4.5"]}),
    )?;
    Ok((state, admin, leaf))
}
fn login(state: &mut AuthState, leaf: &[u8]) -> Result<AuthResponse, AuthError> {
    state
        .handle_with_client_certificates(
            None,
            "",
            "POST",
            "auth/nested/cert/login",
            &json!({}),
            100,
            Some(&[leaf.to_vec()]),
        )?
        .ok_or_else(|| bad("missing login"))
}
fn finish(state: &mut AuthState, response: &mut AuthResponse) -> Result<(), AuthError> {
    let identity = response
        .login_identity
        .take()
        .ok_or_else(|| bad("missing identity"))?;
    assert_eq!(identity.alias, "client.example.test");
    assert!(identity.metadata.is_none());
    state.bind_issued_entity(response, "", MOUNT, "fixture-entity")?;
    state.finish_pending_batch(response, "", 100)
}

#[test]
fn cert_batch_mount_precedence_uses_signed_certificate_metadata_without_backing_rows() -> TestResult
{
    for mount in ["default-service", "default-batch", "service", "batch"] {
        for kind in ["default", "service", "batch"] {
            let (mut state, admin, leaf) = fixture()?;
            write(
                &mut state,
                &admin,
                "sys/auth/nested/cert/tune",
                json!({"token_type":mount}),
            )?;
            write(&mut state, &admin, ROLE, json!({"token_type":kind}))?;
            let is_batch = mount == "batch"
                || (mount == "default-batch" && kind != "service")
                || (mount == "default-service" && kind == "batch");
            let count = state.tokens.len();
            let mut issued = login(&mut state, &leaf)?;
            assert_eq!(issued.pending_batch.is_some(), is_batch);
            assert_eq!(state.tokens.len(), count + usize::from(!is_batch));
            finish(&mut state, &mut issued)?;
            assert_eq!(
                issued.body["auth"]["token_type"],
                if is_batch { "batch" } else { "service" }
            );
            assert_eq!(issued.body["auth"]["renewable"], !is_batch);
            assert_eq!(
                issued.body["auth"]["metadata"]["common_name"],
                "client.example.test"
            );
            assert_eq!(issued.body["auth"]["metadata"]["1-2-3-4-5"], "tenant-a");
            let raw = issued.body["auth"]["client_token"]
                .as_str()
                .ok_or("token")?;
            let mut actor = state.authenticate(raw, 100)?;
            actor.bind_identity_policies(BTreeSet::new());
            let looked = state
                .handle(
                    Some(&actor),
                    "",
                    "GET",
                    "auth/token/lookup-self",
                    &json!({}),
                    100,
                )?
                .ok_or("lookup")?;
            if is_batch {
                assert_eq!(state.tokens.len(), count);
                assert_eq!(looked.body["data"]["type"], "batch");
                assert_eq!(looked.body["data"]["num_uses"], 0);
                assert!(
                    looked.body["data"]
                        .get("period")
                        .is_none_or(|value| value == &json!(0))
                );
                assert_eq!(looked.body["data"]["meta"], issued.body["auth"]["metadata"]);
                assert!(
                    issued.body["auth"]["accessor"]
                        .as_str()
                        .is_some_and(str::is_empty)
                );
                assert!(
                    state
                        .handle(
                            Some(&actor),
                            "",
                            "POST",
                            "auth/token/renew-self",
                            &json!({}),
                            100
                        )
                        .is_err()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn cert_role_partial_type_null_reset_and_failed_explicit_batch_are_atomic() -> TestResult {
    let (mut state, admin, leaf) = fixture()?;
    let initial = state.cert_roles[""][MOUNT]["operator"].clone();
    assert!(!state.has_cert_batch_state());
    for value in [json!("batch"), Value::Null, json!(""), json!("service")] {
        write(&mut state, &admin, ROLE, json!({"token_type":value}))?;
        let mut expected = initial.clone();
        expected.token_type = Some(batch_issuance::UserTokenType::parse(&value)?);
        assert_eq!(state.cert_roles[""][MOUNT]["operator"], expected);
        assert!(state.has_cert_batch_state());
        state.validate_cert_batch_state()?;
    }
    write(&mut state, &admin, ROLE, json!({"token_type":"batch"}))?;
    write(&mut state, &admin, ROLE, json!({"token_ttl":90}))?;
    assert_eq!(
        state.cert_roles[""][MOUNT]["operator"].token_type,
        Some(batch_issuance::UserTokenType::Batch)
    );
    assert_eq!(
        state.cert_roles[""][MOUNT]["operator"].certificate_sha256,
        certificate_sha256(&leaf)
    );
    for body in [
        json!({"token_type":"default-batch"}),
        json!({"token_type":"default-service"}),
        json!({"token_type":"batch","token_num_uses":2}),
    ] {
        let before = serde_json::to_vec(&state)?;
        assert_eq!(
            write(&mut state, &admin, ROLE, body)
                .err()
                .ok_or("invalid type accepted")?
                .status,
            400
        );
        assert!(
            serde_json::to_vec(&state)? == before,
            "rejected role update changed auth"
        );
    }
    write(
        &mut state,
        &admin,
        ROLE,
        json!({"token_type":"service","token_num_uses":2}),
    )?;
    write(
        &mut state,
        &admin,
        "sys/auth/nested/cert/tune",
        json!({"token_type":"batch"}),
    )?;
    let mut issued = login(&mut state, &leaf)?;
    finish(&mut state, &mut issued)?;
    assert_eq!(issued.body["auth"]["num_uses"], 2);
    let mut actor = state.authenticate(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("token")?,
        100,
    )?;
    actor.bind_identity_policies(BTreeSet::new());
    let looked = state
        .handle(
            Some(&actor),
            "",
            "GET",
            "auth/token/lookup-self",
            &json!({}),
            100,
        )?
        .ok_or("lookup")?;
    assert_eq!(looked.body["data"]["num_uses"], 0);
    Ok(())
}

#[test]
fn cert_legacy_role_none_bytes_and_existing_service_renewal_are_preserved() -> TestResult {
    // Exact pre-feature encoding: no new optional field is materialized on read.
    let old = br#"{"certificate_sha256":"0000000000000000000000000000000000000000000000000000000000000000","policies":["default"],"token_ttl":120,"token_max_ttl":600,"token_num_uses":0}"#;
    let role: CertRole = serde_json::from_slice(old)?;
    assert!(role.token_type.is_none());
    assert!(
        serde_json::to_vec(&role)?.as_slice() == old,
        "legacy CertRole bytes changed"
    );
    let (mut state, admin, leaf) = fixture()?;
    let mut issued = login(&mut state, &leaf)?;
    finish(&mut state, &mut issued)?;
    let raw = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?;
    write(&mut state, &admin, ROLE, json!({"token_type":"batch"}))?;
    let mut actor = state.authenticate(raw, 100)?;
    actor.bind_identity_policies(BTreeSet::new());
    let renewed = state
        .handle_with_client_certificates(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({"increment":60}),
            100,
            Some(&[leaf]),
        )?
        .ok_or("renew")?;
    assert_eq!(renewed.status, 200);
    assert_eq!(renewed.body["auth"]["token_type"], "service");
    let restored: AuthState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    restored.validate_cert_batch_state()?;
    assert!(restored.has_cert_batch_state());
    Ok(())
}

#[test]
fn cert_batch_issued_bearer_survives_role_mount_removal_and_restored_authority() -> TestResult {
    let (mut state, admin, leaf) = fixture()?;
    write(&mut state, &admin, ROLE, json!({"token_type":"batch"}))?;
    let mut issued = login(&mut state, &leaf)?;
    finish(&mut state, &mut issued)?;
    let raw = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?;
    state
        .handle(
            Some(&admin),
            "",
            "DELETE",
            "sys/auth/nested/cert",
            &json!({}),
            100,
        )?
        .ok_or("disable")?;
    let mut restored: AuthState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    assert!(restored.authenticate(raw, 101).is_ok());
    assert!(restored.authenticate(raw, 220).is_err());
    assert!(
        restored
            .handle_with_client_certificates(
                None,
                "",
                "POST",
                "auth/nested/cert/login",
                &json!({}),
                101,
                Some(&[leaf])
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn cert_batch_format_predicate_covers_mount_only_and_rejects_invalid_persisted_roles() -> TestResult
{
    let (mut state, admin, _) = fixture()?;
    write(
        &mut state,
        &admin,
        "sys/auth/nested/cert/tune",
        json!({"token_type":"service"}),
    )?;
    assert!(state.has_cert_batch_state());
    let mut reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    reopened.validate_batch_issuance_state()?;
    let role = reopened
        .cert_roles
        .get_mut("")
        .and_then(|mounts| mounts.get_mut(MOUNT))
        .and_then(|roles| roles.get_mut("operator"))
        .ok_or("role")?;
    role.token_type = Some(batch_issuance::UserTokenType::Batch);
    role.token_num_uses = 1;
    assert!(reopened.validate_batch_issuance_state().is_err());
    role_reset(&mut reopened)?;
    reopened
        .auth_mounts
        .get_mut("")
        .and_then(|mounts| mounts.get_mut(MOUNT))
        .ok_or("mount")?
        .kind = "userpass".into();
    assert!(reopened.validate_cert_batch_state().is_err());
    Ok(())
}
fn role_reset(state: &mut AuthState) -> TestResult {
    state
        .cert_roles
        .get_mut("")
        .and_then(|mounts| mounts.get_mut(MOUNT))
        .and_then(|roles| roles.get_mut("operator"))
        .ok_or("role")?
        .token_num_uses = 0;
    Ok(())
}
