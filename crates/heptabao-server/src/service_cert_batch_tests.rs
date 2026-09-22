use super::tests::{Root, bootstrap, call};
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn setup(service: &mut Service, admin: &str) -> TestResult<Vec<Vec<u8>>> {
    let leaf = include_bytes!("../testdata/cert-selector.der").to_vec();
    let digest: String = ring::digest::digest(&ring::digest::SHA256, &leaf)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        call(
            service,
            "POST",
            "sys/auth/cert",
            admin,
            json!({"type":"cert"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            service,
            "POST",
            "auth/cert/certs/operator",
            admin,
            json!({
        "certificate_sha256":digest,"token_type":"batch","token_ttl":120,"token_max_ttl":600,
        "allowed_metadata_extensions":["1.2.3.4.5"]})
        )
        .status,
        204
    );
    Ok(vec![leaf])
}
fn login(service: &mut Service, chain: &[Vec<u8>], wrap: Option<u64>) -> Response {
    service.handle_at_mode(RequestDispatch {
        method: "POST",
        path: "auth/cert/login",
        namespace: "",
        token: "",
        body: json!({"name":"operator"}),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: wrap,
        origin_peer: None,
        client_certificates: Some(chain.to_vec()),
    })
}
fn owners(
    service: &Service,
) -> TestResult<(zeroize::Zeroizing<Vec<u8>>, zeroize::Zeroizing<Vec<u8>>)> {
    let state = service.state.as_ref().ok_or("state")?;
    Ok((
        owner_store::serialize_owner(&state.auth).map_err(|_| "auth")?,
        owner_store::serialize_owner(&state.engines).map_err(|_| "engines")?,
    ))
}

#[test]
fn cert_batch_identity_denial_and_wrapper_failure_do_not_publish_candidate_owners() -> TestResult {
    for disabled in [false, true] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, admin) = bootstrap(&mut service)?;
        let chain = setup(&mut service, &admin)?;
        if disabled {
            let first = login(&mut service, &chain, None);
            assert_eq!(first.status, 200);
            let entity = first.body["auth"]["entity_id"].as_str().ok_or("entity")?;
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    &format!("identity/entity/id/{entity}"),
                    &admin,
                    json!({"disabled":true})
                )
                .status,
                204
            );
        } else {
            let mut state = service.state.clone().ok_or("state")?;
            for _ in 0..256 {
                state
                    .auth
                    .wrap_response("", "fixture", 60, &json!({"data":{"ok":true}}), 100)?;
            }
            service.commit_state(&state).map_err(|_| "fixture commit")?;
            service.state = Some(state);
        }
        let before = owners(&service)?;
        let denied = login(&mut service, &chain, Some(60));
        assert_eq!(denied.status, if disabled { 403 } else { 503 });
        assert!(denied.body.get("auth").is_none_or(Value::is_null));
        assert!(denied.body.get("wrap_info").is_none_or(Value::is_null));
        let after = owners(&service)?;
        assert!(
            before.0.as_slice() == after.0.as_slice(),
            "denial published Auth/key/wrapper"
        );
        assert!(
            before.1.as_slice() == after.1.as_slice(),
            "denial published Identity"
        );
        drop(service);
        let mut reopened = root.service()?;
        assert_eq!(
            call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        let after = owners(&reopened)?;
        assert!(
            before.0.as_slice() == after.0.as_slice(),
            "reopen changed denied Auth"
        );
        assert!(
            before.1.as_slice() == after.1.as_slice(),
            "reopen changed denied Identity"
        );
    }
    Ok(())
}

#[test]
fn cert_batch_wrapped_success_binds_certificate_metadata_and_unwraps_once() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let chain = setup(&mut service, &admin)?;
    let issued = login(&mut service, &chain, Some(60));
    assert_eq!(issued.status, 200);
    assert!(issued.body.get("auth").is_none_or(Value::is_null));
    let wrapper = issued.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?;
    let unwrapped = call(
        &mut service,
        "POST",
        "sys/wrapping/unwrap",
        wrapper,
        json!({}),
    );
    assert_eq!(unwrapped.status, 200);
    let auth = &unwrapped.body["auth"];
    assert_eq!(auth["token_type"], "batch");
    assert_eq!(auth["renewable"], false);
    assert_eq!(auth["metadata"]["common_name"], "client.example.test");
    assert_eq!(auth["metadata"]["1-2-3-4-5"], "tenant-a");
    assert!(auth["entity_id"].as_str().is_some_and(|id| !id.is_empty()));
    let raw = auth["client_token"].as_str().ok_or("token")?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            raw,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/renew-self",
            raw,
            json!({})
        )
        .status,
        400
    );
    assert_ne!(
        call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            wrapper,
            json!({})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn schema48_cert_role_and_mount_each_reject_false_legacy_schema() -> TestResult {
    for mount_only in [false, true] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        let mut legacy = service.state.clone().ok_or("state")?;
        legacy.schema = 47;
        assert!(!legacy.auth.has_cert_batch_state());
        assert!(!legacy.auth.has_token_api_creation_ttl());
        assert!(legacy.validate_format().is_ok());
        if mount_only {
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/auth/cert",
                    &admin,
                    json!({"type":"cert"})
                )
                .status,
                204
            );
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/auth/cert/tune",
                    &admin,
                    json!({"token_type":"default-service"})
                )
                .status,
                204
            );
        } else {
            setup(&mut service, &admin)?;
        }
        let mut state = service.state.clone().ok_or("state")?;
        assert_eq!(state.schema, 48);
        assert!(state.auth.has_cert_batch_state());
        assert!(!state.auth.has_token_api_creation_ttl());
        assert!(state.validate_format().is_ok());
        state.schema = 47;
        let rejected = state
            .validate_format()
            .err()
            .ok_or("schema downgrade admitted")?;
        assert_eq!(rejected.status, 503);
        assert_eq!(
            rejected.body["errors"][0],
            "native certificate token state requires schema 48"
        );
    }
    Ok(())
}

#[test]
fn schema48_token_api_creation_ttl_has_an_independent_reader_fence() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["default"],"ttl":60}),
    );
    assert_eq!(issued.status, 200);
    let mut state = service.state.clone().ok_or("state")?;
    assert_eq!(state.schema, 48);
    assert!(state.auth.has_token_api_creation_ttl());
    assert!(!state.auth.has_cert_batch_state());
    assert!(state.validate_format().is_ok());
    state.schema = 47;
    let rejected = state
        .validate_format()
        .err()
        .ok_or("schema downgrade admitted")?;
    assert_eq!(rejected.status, 503);
    assert_eq!(
        rejected.body["errors"][0],
        "Token API creation TTL requires schema 48"
    );
    Ok(())
}
