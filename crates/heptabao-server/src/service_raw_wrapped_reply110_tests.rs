//! Actual encrypted Service owner/record and snapshot checks; synthetic payloads.
use super::tests::{Root, bootstrap, call};
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn issue(
    service: &mut Service,
    admin: &str,
    attempt: [u8; 16],
) -> Result<String, Box<dyn std::error::Error>> {
    let _ingress = crate::auth::IngressReplyScope::listener(&attempt);
    let mut request = ServiceRequest::new(
        "POST",
        "sys/wrapping/wrap",
        "",
        admin,
        json!({"value":"original <>& payload"}),
    );
    request.wrap_ttl_seconds = Some(60);
    let response = service.handle_request_at(request, 100);
    assert_eq!(response.status, 200);
    Ok(response.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?
        .to_owned())
}
#[test]
fn raw110_encrypted_reopen_original_id_and_retired_snapshot_floor() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let old_backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let bearer = issue(&mut service, &admin, [0xa1; 16])?;
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        RAW_WRAPPED_REPLY_STATE_SCHEMA
    );
    assert!(service.record_root.is_some());
    assert!(service.prepare_snapshot_restore(&old_backup).is_err());
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        RAW_WRAPPED_REPLY_STATE_SCHEMA
    );
    let _later = crate::auth::IngressReplyScope::listener(&[0xb2; 16]);
    let response = call(
        &mut service,
        "POST",
        "sys/wrapping/unwrap",
        &admin,
        json!({"token":bearer}),
    );
    assert_eq!(response.status, 200);
    let bytes = response
        .unwrapped_json
        .as_ref()
        .ok_or("trusted unwrap")?
        .raw_bytes(&response.body)?
        .ok_or("stored bytes")?;
    let mut decoded: Value = serde_json::from_slice(bytes)?;
    assert_eq!(
        decoded["request_id"],
        crate::crypto::uuid_from_bytes(&[0xa1; 16])
    );
    assert_eq!(decoded["data"]["value"], "original <>& payload");
    erase_json(&mut decoded);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            &admin,
            json!({"token":bearer})
        )
        .status,
        400
    );
    let retired = service.state.as_ref().ok_or("state")?.clone();
    assert!(retired.auth.has_raw_wrapped_reply_state());
    assert!(service.prepare_snapshot_restore(&old_backup).is_err());
    let mut lower = retired.clone();
    lower.schema = PKI_RSA8192_STATE_SCHEMA;
    assert!(lower.validate_format().is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &lower).is_err());
    let mut owner = serde_json::to_value(&retired.auth)?;
    owner
        .as_object_mut()
        .ok_or("auth owner")?
        .remove("raw_wrapped_reply_floor");
    let mut stripped = retired.clone();
    stripped.auth = serde_json::from_value(owner)?;
    assert!(stripped.validate_format().is_err());
    assert!(
        stripped
            .validate_publication_schema(Some(&retired))
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&retired, &stripped).is_err());
    drop(response);
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        RAW_WRAPPED_REPLY_STATE_SCHEMA
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_raw_wrapped_reply_state()
    );
    Ok(())
}
#[test]
fn raw110_stale_cow_auth_record_plan_cannot_publish_actual_new_custody() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let mut before = service.state.as_ref().ok_or("state")?.clone();
    let plan = service
        .prepare_record_plan(&mut before)
        .map_err(|_| "old actual record plan")?;
    let _bearer = issue(&mut service, &admin, [0xc3; 16])?;
    let current = service.state.as_ref().ok_or("state")?.clone();
    let identity = service
        .current_state_identity()
        .map_err(|_| "current identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert!(service.commit_record_plan(&current, plan).is_err());
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "current identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(current.auth.has_raw_wrapped_reply_state());
    Ok(())
}

#[test]
fn raw110_actual_service_terminal_vetoes_current_publication_snapshot_and_cow() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let bearer = issue(&mut service, &admin, [0xd4; 16])?;
    let live = service.state.as_ref().ok_or("live")?.clone();
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    for case in [0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12] {
        let mut forged = live.clone();
        forged.auth = live.auth.raw110_token_countercandidate(case)?.into();
        if case != 11 {
            assert!(forged.validate_format().is_err());
        }
        assert!(forged.validate_publication_schema(Some(&live)).is_err());
        assert!(Service::validate_snapshot_protected_floor(&live, &forged).is_err());
        assert!(service.prepare_record_plan(&mut forged).is_err());
        let mut healthy = live.clone();
        let plan = service
            .prepare_record_plan(&mut healthy)
            .map_err(|_| "healthy COW plan")?;
        assert!(service.commit_record_plan(&forged, plan).is_err());
        assert_eq!(
            service.current_state_identity().map_err(|_| "identity")?,
            identity
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
    }
    // The actual listener-style self bearer consumes through Service admission,
    // retaining only the original affine final-use view for this one reply.
    let response = call(
        &mut service,
        "POST",
        "sys/wrapping/unwrap",
        &bearer,
        json!({}),
    );
    assert_eq!(response.status, 200);
    assert!(
        response
            .unwrapped_json
            .as_ref()
            .ok_or("origin")?
            .raw_bytes(&response.body)?
            .is_some()
    );
    let terminal = service.state.as_ref().ok_or("terminal")?.clone();
    assert!(terminal.validate_publication_schema(Some(&live)).is_ok());
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    for case in [4, 5, 6, 7, 8, 9, 10, 11] {
        let mut forged = terminal.clone();
        forged.auth = terminal.auth.raw110_token_countercandidate(case)?.into();
        if ![5, 11].contains(&case) {
            assert!(forged.validate_format().is_err());
        }
        assert!(forged.validate_publication_schema(Some(&terminal)).is_err());
        assert!(Service::validate_snapshot_protected_floor(&terminal, &forged).is_err());
        assert!(service.prepare_record_plan(&mut forged).is_err());
        let mut healthy = terminal.clone();
        let plan = service
            .prepare_record_plan(&mut healthy)
            .map_err(|_| "healthy COW plan")?;
        assert!(service.commit_record_plan(&forged, plan).is_err());
        assert_eq!(
            service.current_state_identity().map_err(|_| "identity")?,
            identity
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
    }
    let mut rearmed = terminal.clone();
    rearmed.auth = live.auth.clone();
    assert!(rearmed.auth.validate_raw_wrapped_reply_state().is_ok());
    assert!(
        rearmed
            .validate_publication_schema(Some(&terminal))
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&terminal, &rearmed).is_err());
    assert!(service.prepare_record_plan(&mut rearmed).is_err());
    let mut healthy = terminal.clone();
    let plan = service
        .prepare_record_plan(&mut healthy)
        .map_err(|_| "healthy COW plan")?;
    assert!(service.commit_record_plan(&rearmed, plan).is_err());
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}

#[test]
fn raw110_actual_service_historical_consume_promotion_vetoes_publication_snapshot_and_cow()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    // Actual direct Service producer has no ingress and retains historical None.
    let mut request = ServiceRequest::new(
        "POST",
        "sys/wrapping/wrap",
        "",
        &admin,
        json!({"legacy":true}),
    );
    request.wrap_ttl_seconds = Some(60);
    let issued = service.handle_request_at(request, 100);
    assert_eq!(issued.status, 200);
    let historical = issued.body["wrap_info"]["token"]
        .as_str()
        .ok_or("historical bearer")?
        .to_owned();
    let consumed = call(
        &mut service,
        "POST",
        "sys/wrapping/unwrap",
        &admin,
        json!({"token":historical}),
    );
    assert_eq!(consumed.status, 200);
    assert!(
        consumed
            .unwrapped_json
            .as_ref()
            .ok_or("historical origin")?
            .raw_bytes(&consumed.body)?
            .is_none()
    );
    let old = service.state.as_ref().ok_or("historical terminal")?.clone();
    let raw = issue(&mut service, &admin, [0xe5; 16])?;
    let current = service.state.as_ref().ok_or("actual new raw")?.clone();
    assert!(current.validate_publication_schema(Some(&old)).is_ok());
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    for consumed in [false, true] {
        let mut candidate = current.clone();
        candidate.auth = current
            .auth
            .raw110_promote_historical_countercandidate(&historical, &raw, consumed)?
            .into();
        assert!(candidate.validate_format().is_ok()); // Canonical current shape alone cannot establish history.
        assert!(
            candidate
                .validate_publication_schema(Some(&current))
                .is_err()
        );
        assert!(Service::validate_snapshot_protected_floor(&current, &candidate).is_err());
        assert!(service.prepare_record_plan(&mut candidate).is_err());
        let mut healthy = current.clone();
        let plan = service
            .prepare_record_plan(&mut healthy)
            .map_err(|_| "healthy COW plan")?;
        assert!(service.commit_record_plan(&candidate, plan).is_err());
        assert_eq!(
            service.current_state_identity().map_err(|_| "identity")?,
            identity
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
    }
    Ok(())
}

fn raw110_pki_install(service: &mut Service, admin: &str, generate: bool) -> TestResult {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/mounts/rawpki",
            admin,
            json!({"type":"pki"})
        )
        .status,
        204
    );
    if generate {
        assert_eq!(
            call(
                service, "POST", "rawpki/root/generate/internal", admin,
                json!({"common_name":"raw110.example.test","key_type":"ec","key_bits":256,"ttl":"48h"}),
            ).status,
            200
        );
    }
    Ok(())
}
fn raw110_pki_issue(
    service: &mut Service,
    admin: &str,
    method: &str,
    path: &str,
    body: Value,
    attempt: [u8; 16],
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let _ingress = crate::auth::IngressReplyScope::listener(&attempt);
    let mut request = ServiceRequest::new(method, path, "", admin, body);
    request.wrap_ttl_seconds = Some(60);
    let response = service.handle_request_at(request, 100);
    assert_eq!(response.status, 200);
    Ok(Zeroizing::new(
        response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("PKI wrapper")?
            .to_owned(),
    ))
}
fn raw110_pki_unwrap(
    service: &mut Service,
    admin: &str,
    bearer: &str,
) -> Result<(Response, Zeroizing<Vec<u8>>), Box<dyn std::error::Error>> {
    let _later = crate::auth::IngressReplyScope::listener(&[0xfe; 16]);
    let response = call(
        service,
        "POST",
        "sys/wrapping/unwrap",
        admin,
        json!({"token":bearer}),
    );
    assert_eq!(response.status, 200);
    let bytes = Zeroizing::new(
        response
            .unwrapped_json
            .as_ref()
            .ok_or("PKI unwrap origin")?
            .raw_bytes(&response.body)?
            .ok_or("PKI stored JSON")?
            .to_vec(),
    );
    Ok((response, bytes))
}

#[test]
fn raw110_actual_pki_certificate_chain_issuer_and_crl_preserve_special_data_and_original_id()
-> TestResult {
    use base64::Engine as _;
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    raw110_pki_install(&mut service, &admin, true)?;
    for (index, (path, marker, mime)) in [
        (
            "rawpki/ca",
            "__heptabao_pki_certificate",
            "application/pkix-cert",
        ),
        (
            "rawpki/ca/pem",
            "__heptabao_pki_certificate",
            "application/pem-certificate-chain",
        ),
        (
            "rawpki/ca_chain",
            "__heptabao_pki_certificate",
            "application/pkix-cert",
        ),
        (
            "rawpki/issuer/default/der",
            "__heptabao_pki_certificate",
            "application/pkix-cert",
        ),
        (
            "rawpki/issuer/default/pem",
            "__heptabao_pki_certificate",
            "application/pem-certificate-chain",
        ),
        ("rawpki/crl", "__heptabao_pki_crl", "application/pkix-crl"),
        (
            "rawpki/crl/pem",
            "__heptabao_pki_crl",
            "application/x-pem-file",
        ),
        (
            "rawpki/issuer/default/crl/der",
            "__heptabao_pki_crl",
            "application/pkix-crl",
        ),
        (
            "rawpki/issuer/default/crl/pem",
            "__heptabao_pki_crl",
            "application/x-pem-file",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let original = call(&mut service, "GET", path, &admin, json!({}));
        assert_eq!(original.status, 200);
        let encoded = original.body[marker].as_str().ok_or("actual PKI bytes")?;
        let actual = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        if path == "rawpki/ca" {
            assert!(openssl::x509::X509::from_der(&actual).is_ok());
        } else if path == "rawpki/crl" {
            assert!(openssl::x509::X509Crl::from_der(&actual).is_ok());
        }
        let attempt = [0x41 + u8::try_from(index)?; 16];
        let bearer = raw110_pki_issue(&mut service, &admin, "GET", path, json!({}), attempt)?;
        let (response, bytes) = raw110_pki_unwrap(&mut service, &admin, &bearer)?;
        let mut envelope: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(envelope.as_object().ok_or("envelope")?.len(), 8);
        assert_eq!(
            envelope["request_id"],
            crate::crypto::uuid_from_bytes(&attempt)
        );
        assert_eq!(
            envelope["data"],
            json!({
                "http_content_type":mime,"http_raw_body":encoded,"http_status_code":200
            })
        );
        assert_eq!(envelope["auth"], Value::Null);
        assert_eq!(envelope["wrap_info"], Value::Null);
        assert_eq!(response.body["data"], envelope["data"]);
        assert!(bytes.starts_with(b"{\"request_id\":"));
        assert!(!bytes.ends_with(b"\n"));
        assert_ne!(bytes.as_slice(), actual.as_slice());
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/wrapping/unwrap",
                &admin,
                json!({"token":bearer.as_str()})
            )
            .status,
            400
        );
        erase_json(&mut envelope);
    }
    Ok(())
}
#[test]
fn raw110_actual_rootless_pki_crl_preserves_nil_body_204_and_historical_none() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    raw110_pki_install(&mut service, &admin, false)?;
    for (path, mime, attempt) in [
        ("rawpki/crl", "application/pkix-crl", [0x71; 16]),
        ("rawpki/crl/pem", "application/x-pem-file", [0x72; 16]),
    ] {
        let actual = call(&mut service, "GET", path, &admin, json!({}));
        assert_eq!(actual.status, 204);
        let bearer = raw110_pki_issue(&mut service, &admin, "GET", path, json!({}), attempt)?;
        let (_, bytes) = raw110_pki_unwrap(&mut service, &admin, &bearer)?;
        let mut envelope: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(
            envelope["data"],
            json!({
                "http_content_type":mime,"http_raw_body":null,"http_status_code":204
            })
        );
        assert_eq!(
            envelope["request_id"],
            crate::crypto::uuid_from_bytes(&attempt)
        );
        erase_json(&mut envelope);
    }
    // A real legacy producer remains None even for the newly supported raw route.
    let mut request = ServiceRequest::new("GET", "rawpki/crl", "", &admin, json!({}));
    request.wrap_ttl_seconds = Some(60);
    let issued = service.handle_request_at(request, 100);
    assert_eq!(issued.status, 200);
    let bearer = Zeroizing::new(
        issued.body["wrap_info"]["token"]
            .as_str()
            .ok_or("legacy raw wrapper")?
            .to_owned(),
    );
    let response = call(
        &mut service,
        "POST",
        "sys/wrapping/unwrap",
        &admin,
        json!({"token":bearer.as_str()}),
    );
    assert_eq!(response.status, 200);
    let origin = response.unwrapped_json.as_ref().ok_or("legacy unwrap")?;
    assert!(!origin.has_stored_reply());
    assert!(origin.raw_bytes(&response.body)?.is_none());
    assert_eq!(response.body, json!({"__heptabao_pki_crl":"","pem":false}));
    Ok(())
}
#[test]
fn raw110_actual_ocsp_malformed_reply_wraps_protocol_data_without_granting_arbitrary_errors()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    raw110_pki_install(&mut service, &admin, true)?;
    let body = json!({"__heptabao_pki_ocsp_request":"bm90LWFuLU9DU1AtcmVxdWVzdA=="});
    let original = call(&mut service, "POST", "rawpki/ocsp", &admin, body.clone());
    assert_eq!(original.status, 400);
    let bytes = crate::engines::raw_ocsp_response(original.status, &original.body)
        .ok_or("actual malformed OCSP")?;
    assert_eq!(bytes, [0x30, 3, 0x0a, 1, 1]);
    let bearer = raw110_pki_issue(
        &mut service,
        &admin,
        "POST",
        "rawpki/ocsp",
        body,
        [0x81; 16],
    )?;
    let (_, stored) = raw110_pki_unwrap(&mut service, &admin, &bearer)?;
    let mut envelope: Value = serde_json::from_slice(&stored)?;
    assert_eq!(
        envelope["data"],
        json!({
            "http_content_type":"application/ocsp-response","http_raw_body":"MAMKAQE=","http_status_code":400
        })
    );
    assert_eq!(
        envelope["request_id"],
        crate::crypto::uuid_from_bytes(&[0x81; 16])
    );
    erase_json(&mut envelope);
    let mut request = ServiceRequest::new("GET", "rawpki/unknown", "", &admin, json!({}));
    request.wrap_ttl_seconds = Some(60);
    let error = service.handle_request_at(request, 100);
    assert!(error.status >= 400);
    assert!(error.body.get("wrap_info").is_none());
    Ok(())
}
#[test]
fn raw110_actual_pki_rewrap_and_encrypted_reopen_keep_original_complete_reply() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    raw110_pki_install(&mut service, &admin, true)?;
    let bearer = raw110_pki_issue(
        &mut service,
        &admin,
        "GET",
        "rawpki/ca",
        json!({}),
        [0x91; 16],
    )?;
    let original_state = service.state.as_ref().ok_or("original state")?;
    assert!(original_state.auth.has_raw_wrapped_reply_state());
    let mut original_owner = serde_json::to_value(&original_state.auth)?;
    let original_wrapper = original_owner["tokens"]
        .as_object()
        .ok_or("token owner")?
        .values()
        .find(|token| token["wrapping"]["creation_path"] == "rawpki/ca")
        .ok_or("actual original wrapper")?;
    let original_stored = Zeroizing::new(serde_json::from_value::<Vec<u8>>(
        original_wrapper["wrapping"]["stored_reply"]["bytes"].clone(),
    )?);
    let original_digest = original_wrapper["wrapping"]["stored_reply"]["digest"].clone();
    erase_json(&mut original_owner);
    let rewrapped = {
        let _later = crate::auth::IngressReplyScope::listener(&[0x92; 16]);
        call(
            &mut service,
            "POST",
            "sys/wrapping/rewrap",
            &admin,
            json!({"token":bearer.as_str()}),
        )
    };
    assert_eq!(rewrapped.status, 200);
    let next = Zeroizing::new(
        rewrapped.body["wrap_info"]["token"]
            .as_str()
            .ok_or("rewrap")?
            .to_owned(),
    );
    assert_ne!(next.as_str(), bearer.as_str());
    let mut transferred_owner =
        serde_json::to_value(&service.state.as_ref().ok_or("transferred state")?.auth)?;
    let transferred = transferred_owner["tokens"]
        .as_object()
        .ok_or("transferred token owner")?
        .values()
        .find(|token| token["wrapping"]["creation_path"] == "rawpki/ca")
        .ok_or("actual transferred wrapper")?;
    let transferred_stored = Zeroizing::new(serde_json::from_value::<Vec<u8>>(
        transferred["wrapping"]["stored_reply"]["bytes"].clone(),
    )?);
    assert_eq!(transferred_stored.as_slice(), original_stored.as_slice());
    assert_eq!(
        transferred["wrapping"]["stored_reply"]["digest"],
        original_digest
    );
    erase_json(&mut transferred_owner);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            &admin,
            json!({"token":bearer.as_str()})
        )
        .status,
        400
    );
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let (_, bytes) = raw110_pki_unwrap(&mut service, &admin, &next)?;
    assert_eq!(bytes.as_slice(), original_stored.as_slice());
    let mut envelope: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        envelope["request_id"],
        crate::crypto::uuid_from_bytes(&[0x91; 16])
    );
    assert_eq!(
        envelope["data"]["http_content_type"],
        "application/pkix-cert"
    );
    assert_eq!(envelope["data"]["http_status_code"], 200);
    assert!(
        envelope["data"]["http_raw_body"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    erase_json(&mut envelope);
    Ok(())
}
#[test]
fn raw110_actual_pki_owner_rejects_forged_body_wrong_format_namespace_and_shadow_mount()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    raw110_pki_install(&mut service, &admin, true)?;
    let genuine = call(&mut service, "GET", "rawpki/ca", &admin, json!({}));
    let state = service.state.as_ref().ok_or("state")?;
    assert!(
        state
            .engines
            .wrapping_raw_pki_reply("", "GET", "rawpki/ca", 200, &genuine.body)
            .is_some()
    );
    for (namespace, method, path) in [
        ("missing", "GET", "rawpki/ca"),
        ("", "POST", "rawpki/ca"),
        ("", "GET", "secret/ca"),
        ("", "GET", "rawpki/cert/ca"),
        ("", "GET", "rawpki/cert/ca_chain"),
        ("", "GET", "rawpki/ca?owner=other"),
    ] {
        assert!(
            state
                .engines
                .wrapping_raw_pki_reply(namespace, method, path, 200, &genuine.body)
                .is_none()
        );
    }
    let mut altered = genuine.body.clone();
    altered["format"] = json!("pem");
    assert!(
        state
            .engines
            .wrapping_raw_pki_reply("", "GET", "rawpki/ca", 200, &altered)
            .is_none()
    );
    altered = genuine.body.clone();
    altered["extra"] = json!(true);
    assert!(
        state
            .engines
            .wrapping_raw_pki_reply("", "GET", "rawpki/ca", 200, &altered)
            .is_none()
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/rawpki/shadow",
            &admin,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        204
    );
    let state = service.state.as_ref().ok_or("shadow state")?;
    assert!(
        state
            .engines
            .wrapping_raw_pki_reply("", "GET", "rawpki/shadow/ca", 200, &genuine.body)
            .is_none()
    );
    erase_json(&mut altered);
    Ok(())
}

#[test]
fn raw110_actual_ocsp_signed_success_retains_protocol_body_inside_complete_json() -> TestResult {
    use base64::Engine as _;
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    raw110_pki_install(&mut service, &admin, true)?;
    assert_eq!(
        call(&mut service, "POST", "rawpki/roles/leaf", &admin,
            json!({"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec","max_ttl":"2h"})).status,
        200
    );
    let issued = call(
        &mut service,
        "POST",
        "rawpki/issue/leaf",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"1h"}),
    );
    assert_eq!(issued.status, 200);
    let leaf = openssl::x509::X509::from_pem(
        issued.body["data"]["certificate"]
            .as_str()
            .ok_or("actual leaf")?
            .as_bytes(),
    )?;
    let issuer = openssl::x509::X509::from_pem(
        issued.body["data"]["issuing_ca"]
            .as_str()
            .ok_or("actual issuer")?
            .as_bytes(),
    )?;
    let mut request = openssl::ocsp::OcspRequest::new()?;
    request.add_id(openssl::ocsp::OcspCertId::from_cert(
        openssl::hash::MessageDigest::sha256(),
        &leaf,
        &issuer,
    )?)?;
    let body = json!({"__heptabao_pki_ocsp_request":
        base64::engine::general_purpose::STANDARD.encode(request.to_der()?)});
    let original = call(&mut service, "POST", "rawpki/ocsp", &admin, body.clone());
    assert_eq!(original.status, 200);
    let original_raw =
        crate::engines::raw_ocsp_response(200, &original.body).ok_or("actual signed OCSP")?;
    let parsed = openssl::ocsp::OcspResponse::from_der(&original_raw)?;
    assert_eq!(
        parsed.status(),
        openssl::ocsp::OcspResponseStatus::SUCCESSFUL
    );
    let mut issuers = openssl::stack::Stack::new()?;
    issuers.push(issuer.clone())?;
    let mut trust = openssl::x509::store::X509StoreBuilder::new()?;
    trust.add_cert(issuer)?;
    let mut clock = openssl::x509::verify::X509VerifyParam::new()?;
    clock.set_time(100);
    trust.set_param(&clock)?;
    parsed
        .basic()?
        .verify(&issuers, &trust.build(), openssl::ocsp::OcspFlag::empty())?;
    let bearer = raw110_pki_issue(
        &mut service,
        &admin,
        "POST",
        "rawpki/ocsp",
        body,
        [0xa8; 16],
    )?;
    let (_, bytes) = raw110_pki_unwrap(&mut service, &admin, &bearer)?;
    let mut envelope: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        envelope["request_id"],
        crate::crypto::uuid_from_bytes(&[0xa8; 16])
    );
    assert_eq!(envelope["data"]["http_status_code"], 200);
    assert_eq!(
        envelope["data"]["http_content_type"],
        "application/ocsp-response"
    );
    let wrapped_raw = base64::engine::general_purpose::STANDARD.decode(
        envelope["data"]["http_raw_body"]
            .as_str()
            .ok_or("stored OCSP bytes")?,
    )?;
    let wrapped_parsed = openssl::ocsp::OcspResponse::from_der(&wrapped_raw)?;
    assert_eq!(
        wrapped_parsed.status(),
        openssl::ocsp::OcspResponseStatus::SUCCESSFUL
    );
    wrapped_parsed.basic()?;
    assert_eq!(envelope.as_object().ok_or("complete envelope")?.len(), 8);
    erase_json(&mut envelope);
    Ok(())
}
