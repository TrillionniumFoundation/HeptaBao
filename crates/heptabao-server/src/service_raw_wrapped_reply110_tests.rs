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
type RawPkiUnwrap = (Response, Zeroizing<Vec<u8>>);
fn raw110_pki_unwrap(
    service: &mut Service,
    admin: &str,
    bearer: &str,
) -> Result<RawPkiUnwrap, Box<dyn std::error::Error>> {
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
            .ok_or("PKI stored raw HTTP")?
            .to_vec(),
    );
    Ok((response, bytes))
}

#[test]
fn raw110_actual_pki_certificate_chain_issuer_and_crl_preserve_raw_http_and_private_original_id()
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
        let origin = response
            .unwrapped_json
            .as_ref()
            .ok_or("actual PKI origin")?;
        assert_eq!(
            origin.raw_http_transport(&response.body)?,
            Some((200, mime))
        );
        assert_eq!(
            response.body["data"],
            json!({
                "http_content_type":mime,"http_raw_body":encoded,"http_status_code":200
            })
        );
        assert_eq!(bytes.as_slice(), actual.as_slice());
        let mut owner = serde_json::to_value(origin.stored_reply().ok_or("stored PKI")?)?;
        assert_eq!(
            owner["request_id"],
            crate::crypto::uuid_from_bytes(&attempt)
        );
        assert_eq!(owner["kind"]["pki-raw-http-v1"]["status"], 200);
        erase_json(&mut owner);
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
        raw110_assert_http_terminal(response, 200, mime, &actual)?;
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
        let (response, bytes) = raw110_pki_unwrap(&mut service, &admin, &bearer)?;
        assert!(bytes.is_empty());
        let origin = response.unwrapped_json.as_ref().ok_or("rootless origin")?;
        assert_eq!(
            origin.raw_http_transport(&response.body)?,
            Some((204, mime))
        );
        assert_eq!(
            response.body["data"],
            json!({
                "http_content_type":mime,"http_raw_body":null,"http_status_code":204
            })
        );
        let mut owner = serde_json::to_value(origin.stored_reply().ok_or("nil stored PKI")?)?;
        assert_eq!(
            owner["request_id"],
            crate::crypto::uuid_from_bytes(&attempt)
        );
        assert_eq!(owner["kind"]["pki-raw-http-v1"]["nil_body"], true);
        erase_json(&mut owner);
        raw110_assert_http_terminal(response, 204, mime, &[])?;
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
    let (response, stored) = raw110_pki_unwrap(&mut service, &admin, &bearer)?;
    assert_eq!(stored.as_slice(), bytes.as_slice());
    let origin = response
        .unwrapped_json
        .as_ref()
        .ok_or("OCSP protocol origin")?;
    assert_eq!(
        origin.raw_http_transport(&response.body)?,
        Some((400, "application/ocsp-response"))
    );
    let mut owner = serde_json::to_value(origin.stored_reply().ok_or("stored OCSP")?)?;
    assert_eq!(
        owner["request_id"],
        crate::crypto::uuid_from_bytes(&[0x81; 16])
    );
    erase_json(&mut owner);
    raw110_assert_http_terminal(response, 400, "application/ocsp-response", &bytes)?;
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
    let mut original_metadata = original_wrapper["wrapping"]["stored_reply"].clone();
    assert_eq!(original_metadata["kind"]["pki-raw-http-v1"]["status"], 200);
    assert_eq!(
        original_metadata["request_id"],
        crate::crypto::uuid_from_bytes(&[0x91; 16])
    );
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
    assert_eq!(transferred["wrapping"]["stored_reply"], original_metadata);
    erase_json(&mut original_metadata);
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
    let (response, bytes) = raw110_pki_unwrap(&mut service, &admin, &next)?;
    assert_eq!(bytes.as_slice(), original_stored.as_slice());
    assert!(openssl::x509::X509::from_der(&bytes).is_ok());
    let origin = response
        .unwrapped_json
        .as_ref()
        .ok_or("reopened PKI origin")?;
    assert_eq!(
        origin.raw_http_transport(&response.body)?,
        Some((200, "application/pkix-cert"))
    );
    let mut owner = serde_json::to_value(origin.stored_reply().ok_or("reopened stored PKI")?)?;
    assert_eq!(
        owner["request_id"],
        crate::crypto::uuid_from_bytes(&[0x91; 16])
    );
    erase_json(&mut owner);
    raw110_assert_http_terminal(response, 200, "application/pkix-cert", &bytes)?;
    Ok(())
}
#[test]
fn raw110_actual_pki_owner_rejects_forged_body_wrong_format_namespace_and_retired_remount()
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
    // Real catalogs reject overlapping mounts. Retire the actual PKI and
    // remount its allowed path as KV; its old producer body cannot mint proof.
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/rawpki",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/rawpki",
            &admin,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        204
    );
    let state = service.state.as_ref().ok_or("retired PKI remount state")?;
    assert!(
        state
            .engines
            .wrapping_raw_pki_reply("", "GET", "rawpki/ca", 200, &genuine.body)
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
    let (response, bytes) = raw110_pki_unwrap(&mut service, &admin, &bearer)?;
    let origin = response
        .unwrapped_json
        .as_ref()
        .ok_or("signed OCSP origin")?;
    assert_eq!(
        origin.raw_http_transport(&response.body)?,
        Some((200, "application/ocsp-response"))
    );
    let mut owner = serde_json::to_value(origin.stored_reply().ok_or("stored signed OCSP")?)?;
    assert_eq!(
        owner["request_id"],
        crate::crypto::uuid_from_bytes(&[0xa8; 16])
    );
    erase_json(&mut owner);
    let wrapped_parsed = openssl::ocsp::OcspResponse::from_der(&bytes)?;
    assert_eq!(
        wrapped_parsed.status(),
        openssl::ocsp::OcspResponseStatus::SUCCESSFUL
    );
    wrapped_parsed.basic()?;
    raw110_assert_http_terminal(response, 200, "application/ocsp-response", &bytes)?;
    Ok(())
}

fn raw110_assert_http_terminal(
    response: Response,
    status: u16,
    mime: &str,
    expected: &[u8],
) -> TestResult {
    let mut wire = Zeroizing::new(Vec::new());
    crate::http::write_raw110_reply_for_test(&mut *wire, response, false)?;
    let split = wire
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .ok_or("HTTP boundary")?;
    let header = std::str::from_utf8(&wire[..split])?;
    assert!(header.starts_with(&format!("HTTP/1.1 {status} ")));
    assert!(
        header
            .lines()
            .any(|line| line == format!("Content-Type: {mime}"))
    );
    assert_eq!(&wire[split + 4..], expected);
    Ok(())
}

#[test]
fn raw112_actual_sticky_floor_consume_retire_reopen_and_snapshot_cow_veto() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    raw110_pki_install(&mut service, &admin, true)?;
    let old_backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut old_state = service.state.as_ref().ok_or("old state")?.clone();
    let old_plan = service
        .prepare_record_plan(&mut old_state)
        .map_err(|_| "old COW plan")?;
    let bearer = raw110_pki_issue(
        &mut service,
        &admin,
        "GET",
        "rawpki/ca",
        json!({}),
        [0xd1; 16],
    )?;
    let live = service.state.as_ref().ok_or("live")?.clone();
    assert_eq!(live.schema, RAW_PKI_HTTP_REPLY_STATE_SCHEMA);
    assert_eq!(live.writer_schema(), RAW_PKI_HTTP_REPLY_STATE_SCHEMA);
    assert!(live.auth.has_pki_raw_http_reply_state());
    assert!(supported_reader_schema(RAW_PKI_HTTP_REPLY_STATE_SCHEMA));
    assert!(!supported_reader_schema(111));
    let encoded = Zeroizing::new(serde_json::to_vec(&live.auth)?);
    for schema in [108, 110, 111] {
        assert!(AuthState::predecode_raw_reply_owner(&encoded, schema).is_err());
        let mut lower = live.clone();
        lower.schema = schema;
        assert!(lower.validate_format().is_err());
        assert!(lower.validate_publication_schema(Some(&live)).is_err());
        assert!(Service::validate_snapshot_protected_floor(&live, &lower).is_err());
    }
    assert!(AuthState::predecode_raw_reply_owner(&encoded, 112).is_ok());
    // This is the literal known R13 bool decoder, not a new-reader mock.
    #[derive(Deserialize)]
    struct R13Floor {
        #[serde(default)]
        raw_wrapped_reply_floor: bool,
    }
    assert!(serde_json::from_slice::<R13Floor>(&encoded).is_err());
    assert!(
        serde_json::from_value::<R13Floor>(json!({"raw_wrapped_reply_floor":true}))?
            .raw_wrapped_reply_floor
    );
    let (response, bytes) = raw110_pki_unwrap(&mut service, &admin, &bearer)?;
    raw110_assert_http_terminal(response, 200, "application/pkix-cert", &bytes)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke",
            &admin,
            json!({"token":bearer.as_str()})
        )
        .status,
        204
    );
    let retired = service.state.as_ref().ok_or("retired")?.clone();
    assert!(retired.auth.has_pki_raw_http_reply_state());
    assert_eq!(retired.schema, 112);
    let mut owner = serde_json::to_value(&retired.auth)?;
    assert_eq!(owner["raw_wrapped_reply_floor"], "pki-raw-http-v1");
    assert!(serde_json::from_value::<R13Floor>(owner.clone()).is_err());
    for marker in [None, Some(json!(false)), Some(json!(true))] {
        let mut changed = owner.clone();
        let fields = changed.as_object_mut().ok_or("owner")?;
        match marker {
            None => {
                fields.remove("raw_wrapped_reply_floor");
            }
            Some(value) => {
                fields.insert("raw_wrapped_reply_floor".into(), value);
            }
        }
        let mut stripped = retired.clone();
        stripped.auth = serde_json::from_value(changed)?;
        assert!(stripped.validate_format().is_err());
        assert!(
            stripped
                .validate_publication_schema(Some(&retired))
                .is_err()
        );
        assert!(Service::validate_snapshot_protected_floor(&retired, &stripped).is_err());
    }
    erase_json(&mut owner);
    assert!(service.prepare_snapshot_restore(&old_backup).is_err());
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert!(service.commit_record_plan(&retired, old_plan).is_err());
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    // A labelled empty successor cannot substitute the genuine permanent fact.
    let mut empty = old_state;
    empty.schema = 112;
    assert!(!empty.auth.has_pki_raw_http_reply_state());
    assert!(empty.validate_format().is_err());
    assert!(empty.validate_publication_schema(Some(&retired)).is_err());
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let reopened = service.state.as_ref().ok_or("reopened")?;
    assert_eq!(reopened.schema, 112);
    assert!(reopened.auth.has_pki_raw_http_reply_state());
    Ok(())
}

#[test]
fn raw113_actual_pki_kind_metadata_veto_and_client_special_fields_choose_separate_presentation()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    raw110_pki_install(&mut service, &admin, true)?;
    let bearer = raw110_pki_issue(
        &mut service,
        &admin,
        "GET",
        "rawpki/ca",
        json!({}),
        [0xd2; 16],
    )?;
    let (response, bytes) = raw110_pki_unwrap(&mut service, &admin, &bearer)?;
    let origin = response.unwrapped_json.as_ref().ok_or("origin")?;
    let stored = origin.stored_reply().ok_or("stored")?;
    let mut original = serde_json::to_value(stored)?;
    for (name, value) in [
        ("media_type", json!("application/pkix-crl")),
        ("media_type", json!("application/pkix-cert\r\nInjected: no")),
        (
            "kind",
            json!({"pki-raw-http-v1":{"status":400,"nil_body":false}}),
        ),
        (
            "kind",
            json!({"pki-raw-http-v1":{"status":200,"nil_body":true}}),
        ),
        ("kind", json!("json-envelope-v1")),
        ("byte_count", json!(1)),
    ] {
        let mut altered = original.clone();
        altered[name] = value;
        let decoded: crate::auth::StoredWrappedReply = serde_json::from_value(altered)?;
        assert!(decoded.validate(&response.body).is_err());
    }
    let mut unknown = original.clone();
    unknown["kind"] = json!({"pki-raw-http-v2":{"status":200}});
    assert!(serde_json::from_value::<crate::auth::StoredWrappedReply>(unknown).is_err());
    let mut extra = original.clone();
    extra["kind"]["pki-raw-http-v1"]["untrusted"] = json!(true);
    assert!(serde_json::from_value::<crate::auth::StoredWrappedReply>(extra).is_err());
    erase_json(&mut original);
    raw110_assert_http_terminal(response, 200, "application/pkix-cert", &bytes)?;
    // Legitimate client presentation follows the primary special-Data branch.
    // Its private generic origin cannot mint the independent sealed PKI history.
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xd3; 16]);
    let mut request = ServiceRequest::new(
        "POST",
        "sys/wrapping/wrap",
        "",
        &admin,
        json!({"http_content_type":"application/pkix-cert","http_raw_body":"MAMKAQE=","http_status_code":200,"kind":"pki-raw-http-v1"}),
    );
    request.wrap_ttl_seconds = Some(60);
    let issued = service.handle_request_at(request, 100);
    assert_eq!(issued.status, 200);
    let token = Zeroizing::new(
        issued.body["wrap_info"]["token"]
            .as_str()
            .ok_or("client wrapper")?
            .to_owned(),
    );
    let response = call(
        &mut service,
        "POST",
        "sys/wrapping/unwrap",
        &admin,
        json!({"token":token.as_str()}),
    );
    let origin = response.unwrapped_json.as_ref().ok_or("client origin")?;
    assert_eq!(
        origin.raw_http_transport(&response.body)?,
        Some((200, "application/pkix-cert"))
    );
    let raw = origin
        .raw_bytes(&response.body)?
        .ok_or("client presentation")?;
    assert_eq!(raw, &[0x30, 0x03, 0x0a, 0x01, 0x01]);
    let mut client_stored =
        serde_json::to_value(origin.stored_reply().ok_or("private presentation")?)?;
    assert!(client_stored["kind"].get("general-raw-http-v1").is_some());
    assert!(client_stored["kind"].get("pki-raw-http-v1").is_none());
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, GENERAL_WRAPPED_REPLY_STATE_SCHEMA);
    assert!(state.auth.has_pki_raw_http_reply_state()); // Prior genuine PKI history is retained.
    assert!(state.auth.has_general_wrapped_reply_state());
    erase_json(&mut client_stored);
    Ok(())
}

#[test]
fn raw113_actual_pki_q8_oldq7_refuses_before_token_consume_and_s6_raw_custody() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    raw110_pki_install(&mut service, &admin, true)?;
    let token = raw110_pki_issue(
        &mut service,
        &admin,
        "GET",
        "rawpki/ca",
        json!({}),
        [0xd4; 16],
    )?;
    let body = json!({"token":token.as_str()});
    let context = crate::ha_forward::ForwardContext {
        method: "POST",
        path: "sys/wrapping/unwrap",
        namespace: "",
        token: &admin,
        body: &body,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
        caller_deadline: None,
    };
    let frame = crate::ha_forward::encode_completed_index_request_for_cluster(
        "pki112-ha",
        (1, 2),
        &context,
        Some([5; 32]),
    )?;
    assert!(frame.starts_with(b"HBFQ8"));
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    for magic in [b"HBFQ5", b"HBFQ6", b"HBFQ7"] {
        let mut old = frame.clone();
        old[..5].copy_from_slice(magic);
        assert!(crate::ha_forward::decode_request_for_cluster(&old, "pki112-ha").is_err());
        assert!(
            service
                .state
                .as_ref()
                .ok_or("state")?
                .auth
                .is_wrapping_token(&token)
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
    }
    let (response, bytes) = raw110_pki_unwrap(&mut service, &admin, &token)?;
    let frame = crate::ha_forward::encode_completed_unwrap_response_for_cluster(
        "pki112-ha",
        2,
        1,
        &response,
        None,
    )?;
    assert!(frame.starts_with(b"HBFS6"));
    let received = crate::ha_forward::decode_unwrap_response_for_cluster(&frame, "pki112-ha")?;
    let stored = received
        .raw_wrapped_reply
        .as_ref()
        .ok_or("received raw custody")?;
    assert_eq!(stored.bytes(&received.body)?, bytes.as_slice());
    assert_eq!(
        stored.raw_http_transport(&received.body)?,
        Some((200, "application/pkix-cert"))
    );
    assert_eq!(
        crate::ha_forward_completion::response_digest(&response)?,
        crate::ha_forward_completion::wire_response_digest(&received)?
    );
    for magic in [b"HBFS3", b"HBFS4"] {
        let mut old = frame.clone();
        old[..5].copy_from_slice(magic);
        assert!(crate::ha_forward::decode_unwrap_response_for_cluster(&old, "pki112-ha").is_err());
    }
    Ok(())
}

#[test]
fn raw112_actual_explicit_csr_is_400_without_engine_publication_and_keeps_pki_sticky() -> TestResult
{
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    raw110_pki_install(&mut service, &admin, true)?;
    let bearer = raw110_pki_issue(
        &mut service,
        &admin,
        "GET",
        "rawpki/ca",
        json!({}),
        [0xd1; 16],
    )?;
    let _consumed = raw110_pki_unwrap(&mut service, &admin, &bearer)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "rawpki/roles/raw110",
            &admin,
            json!({"allow_any_name":true,"key_type":"ec","key_bits":256,"ttl":"1h","max_ttl":"1h"})
        )
        .status,
        200
    );
    let before = Zeroizing::new(serde_json::to_vec(
        &service.state.as_ref().ok_or("state")?.engines,
    )?);
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xd2; 16]);
    let mut request = ServiceRequest::new(
        "POST",
        "rawpki/sign/raw110",
        "",
        &admin,
        json!({"csr":include_str!("../fixtures/raw112-actual-mac-explicit-p256.csr"),
               "common_name":"raw110.example","ttl":"1h"}),
    );
    request.wrap_ttl_seconds = Some(60);
    let rejected = service.handle_request_at(request, 100);
    assert_eq!(rejected.status, 400);
    assert!(
        rejected.body["errors"]
            == json!(["certificate request could not be parsed: x509: invalid ECDSA parameters"]),
        "fixed public CSR classification"
    );
    assert!(rejected.body.get("wrap_info").is_none());
    let state = service.state.as_ref().ok_or("state")?;
    let after = Zeroizing::new(serde_json::to_vec(&state.engines)?);
    assert!(
        before.as_slice() == after.as_slice(),
        "rejected CSR must not publish PKI state"
    );
    assert_eq!(state.schema, RAW_PKI_HTTP_REPLY_STATE_SCHEMA);
    assert!(state.auth.has_pki_raw_http_reply_state());
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
    Ok(())
}

#[test]
fn raw112_actual_shared_official_named_curve_csr_signs_its_public_key_and_verifies_issuer()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    raw110_pki_install(&mut service, &admin, true)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "rawpki/roles/raw110",
            &admin,
            json!({"allow_any_name":true,"key_type":"ec","key_bits":256,"ttl":"1h","max_ttl":"1h"})
        )
        .status,
        200
    );
    let csr = include_str!("../fixtures/raw112-actual-official-named-p256.csr");
    let request = openssl::x509::X509Req::from_pem(csr.as_bytes())?;
    let subject = request.public_key()?;
    assert!(request.verify(&subject)?);
    let signed = call(
        &mut service,
        "POST",
        "rawpki/sign/raw110",
        &admin,
        json!({"csr":csr,"common_name":"raw110.example","ttl":"1h"}),
    );
    assert_eq!(signed.status, 200);
    assert!(signed.body["data"].get("private_key").is_none());
    let certificate = openssl::x509::X509::from_pem(
        signed.body["data"]["certificate"]
            .as_str()
            .ok_or("actual signed certificate")?
            .as_bytes(),
    )?;
    assert!(certificate.public_key()?.public_key_to_der()? == subject.public_key_to_der()?);
    let original = call(&mut service, "GET", "rawpki/ca", &admin, json!({}));
    assert_eq!(original.status, 200);
    let ca_der = base64::engine::general_purpose::STANDARD.decode(
        original.body["__heptabao_pki_certificate"]
            .as_str()
            .ok_or("actual issuer DER")?,
    )?;
    let ca = openssl::x509::X509::from_der(&ca_der)?;
    let issuer = ca.public_key()?;
    assert!(certificate.verify(&issuer)?);
    let mut tampered = certificate.to_der()?;
    *tampered.last_mut().ok_or("actual certificate signature")? ^= 1;
    assert!(!openssl::x509::X509::from_der(&tampered)?.verify(&issuer)?);
    Ok(())
}

#[test]
fn raw113_actual_generic_floor_cow_snapshot_consume_revoke_encrypted_reopen() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let old_backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut old_state = service.state.as_ref().ok_or("old state")?.clone();
    let old_plan = service
        .prepare_record_plan(&mut old_state)
        .map_err(|_| "old COW")?;
    let body = crate::auth::LexicalJson::parse_listener(
        br#"{"number":1.0,"large":1e309,"string":"1.0"}"#,
    )?;
    let view = body.wrapping_view()?;
    let _ingress = crate::auth::IngressReplyScope::listener_wrapping(&[0xe1; 16], Some(body));
    let mut request = ServiceRequest::new("POST", "sys/wrapping/wrap", "", &admin, view);
    request.wrap_ttl_seconds = Some(60);
    let issued = service.handle_request_at(request, 100);
    assert_eq!(issued.status, 200);
    let token = Zeroizing::new(
        issued.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper")?
            .to_owned(),
    );
    let live = service.state.as_ref().ok_or("live")?.clone();
    assert_eq!(live.schema, GENERAL_WRAPPED_REPLY_STATE_SCHEMA);
    assert_eq!(live.writer_schema(), GENERAL_WRAPPED_REPLY_STATE_SCHEMA);
    assert!(
        live.auth.has_general_wrapped_reply_state() && !live.auth.has_pki_raw_http_reply_state()
    );
    assert!(supported_reader_schema(113) && !supported_reader_schema(111));
    for schema in [108, 110, 111, 112] {
        let mut lower = live.clone();
        lower.schema = schema;
        assert!(lower.validate_format().is_err());
        assert!(lower.validate_publication_schema(Some(&live)).is_err());
        assert!(Service::validate_snapshot_protected_floor(&live, &lower).is_err());
        assert!(
            AuthState::predecode_raw_reply_owner(&serde_json::to_vec(&live.auth)?, schema).is_err()
        );
    }
    let _later = crate::auth::IngressReplyScope::listener(&[0xe2; 16]);
    let response = call(
        &mut service,
        "POST",
        "sys/wrapping/unwrap",
        &admin,
        json!({"token":token.as_str()}),
    );
    assert_eq!(response.status, 200);
    let bytes = response
        .unwrapped_json
        .as_ref()
        .ok_or("origin")?
        .raw_bytes(&response.body)?
        .ok_or("typed bytes")?;
    let expected = b"\"number\":1.0";
    assert!(bytes.windows(expected.len()).any(|b| b == expected));
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            &admin,
            json!({"token":token.as_str()})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke",
            &admin,
            json!({"token":token.as_str()})
        )
        .status,
        204
    );
    let retired = service.state.as_ref().ok_or("retired")?.clone();
    assert_eq!(retired.schema, 113);
    assert!(
        retired.auth.has_general_wrapped_reply_state()
            && !retired.auth.has_pki_raw_http_reply_state()
    );
    let mut owner = serde_json::to_value(&retired.auth)?;
    assert_eq!(owner["raw_wrapped_reply_floor"], "general-wrapped-reply-v1");
    for marker in [
        None,
        Some(json!(false)),
        Some(json!(true)),
        Some(json!("pki-raw-http-v1")),
    ] {
        let mut changed = owner.clone();
        let fields = changed.as_object_mut().ok_or("owner")?;
        match marker {
            None => {
                fields.remove("raw_wrapped_reply_floor");
            }
            Some(marker) => {
                fields.insert("raw_wrapped_reply_floor".into(), marker);
            }
        }
        let mut stripped = retired.clone();
        stripped.auth = serde_json::from_value(changed)?;
        assert!(stripped.validate_format().is_err());
        assert!(
            stripped
                .validate_publication_schema(Some(&retired))
                .is_err()
        );
        assert!(Service::validate_snapshot_protected_floor(&retired, &stripped).is_err());
    }
    erase_json(&mut owner);
    assert!(service.prepare_snapshot_restore(&old_backup).is_err());
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert!(service.commit_record_plan(&retired, old_plan).is_err());
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    old_state.schema = 113;
    assert!(old_state.validate_format().is_err());
    assert!(
        old_state
            .validate_publication_schema(Some(&retired))
            .is_err()
    );
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let reopened = service.state.as_ref().ok_or("reopen")?;
    assert_eq!(reopened.schema, 113);
    assert!(reopened.auth.has_general_wrapped_reply_state());
    assert!(!reopened.auth.has_pki_raw_http_reply_state());
    Ok(())
}

#[test]
fn raw113_actual_opaque_number_and_string_shadow_require_distinct_mandatory_audit() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_key, admin) = bootstrap(&mut service)?;
    let number = crate::auth::LexicalJson::parse_listener(br#"{"number":1e309}"#)?;
    let string = crate::auth::LexicalJson::parse_listener(br#"{"number":"1e309"}"#)?;
    assert!(number.wrapping_view()? == string.wrapping_view()?);
    let mut credentials = Vec::new();
    for (index, lexical) in [number, string].into_iter().enumerate() {
        let view = lexical.wrapping_view()?;
        let _ingress = crate::auth::IngressReplyScope::listener_wrapping(
            &[0xe8 + index as u8; 16],
            Some(lexical),
        );
        let mut request = ServiceRequest::new("POST", "sys/wrapping/wrap", "", &admin, view);
        request.wrap_ttl_seconds = Some(60);
        let response = service.handle_request_at(request, 100);
        assert_eq!(response.status, 200);
        credentials.push(Zeroizing::new(
            response.body["wrap_info"]["token"]
                .as_str()
                .ok_or("actual opaque wrapper")?
                .to_owned(),
        ));
    }
    let mut audit = Zeroizing::new(std::fs::read(directory.path.join("audit.jsonl"))?);
    let mut request_digests = Vec::new();
    for line in audit
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let mut record: Value = serde_json::from_slice(line)?;
        if record["event"]["kind"] == "request" {
            request_digests.push(
                record["event"]["path_digest"]
                    .as_str()
                    .ok_or("mandatory audit digest")?
                    .to_owned(),
            );
        }
        erase_json(&mut record);
    }
    assert!(request_digests.len() >= 2);
    let last = request_digests.len();
    assert_ne!(request_digests[last - 2], request_digests[last - 1]);
    audit.zeroize();
    for (index, token) in credentials.iter().enumerate() {
        let _ingress = crate::auth::IngressReplyScope::listener(&[0xea; 16]);
        let response = call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            &admin,
            json!({"token":token.as_str()}),
        );
        assert_eq!(response.status, 200);
        let bytes = response
            .unwrapped_json
            .as_ref()
            .ok_or("origin")?
            .raw_bytes(&response.body)?
            .ok_or("complete stored bytes")?;
        let tree = crate::auth::LexicalJson::parse_listener(bytes)?;
        let crate::auth::LexicalJson::Object(root) = &tree else {
            return Err("envelope".into());
        };
        let crate::auth::LexicalJson::Object(data) = &root["data"] else {
            return Err("data".into());
        };
        if index == 0 {
            assert!(matches!(&data["number"], crate::auth::LexicalJson::Number(n) if n == "1e309"));
        } else {
            assert!(matches!(&data["number"], crate::auth::LexicalJson::String(n) if n == "1e309"));
        }
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/wrapping/unwrap",
                &admin,
                json!({"token":token.as_str()})
            )
            .status,
            400
        );
    }
    let current = service.state.as_ref().ok_or("current")?;
    assert_eq!(current.schema, 113);
    assert!(
        current.auth.has_general_wrapped_reply_state()
            && !current.auth.has_pki_raw_http_reply_state()
    );
    Ok(())
}

#[test]
fn raw113_actual_selected_json_consume_needs_real_http_ingress_and_stays_permanent_without_pki_authority()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_key, admin) = bootstrap(&mut service)?;
    let lexical = crate::auth::LexicalJson::parse_listener(
        br#"{"http_status_code":null,"http_content_type":1.0,"http_raw_body":"1.0","request_id":"client-cannot-mint","extra":1e309}"#,
    )?;
    let _issued_ingress =
        crate::auth::IngressReplyScope::listener_wrapping(&[0x91; 16], Some(lexical.clone()));
    let mut request = ServiceRequest::new(
        "POST",
        "sys/wrapping/wrap",
        "",
        &admin,
        lexical.wrapping_view()?,
    );
    request.wrap_ttl_seconds = Some(60);
    let issued = service.handle_request_at(request, 100);
    assert_eq!(issued.status, 200);
    let token = Zeroizing::new(
        issued.body["wrap_info"]["token"]
            .as_str()
            .ok_or("actual wrapper")?
            .to_owned(),
    );
    let _later_ingress = crate::auth::IngressReplyScope::listener(&[0x92; 16]);
    let request = ServiceRequest::new(
        "POST",
        "sys/wrapping/unwrap",
        "",
        &admin,
        json!({"token":&*token}),
    );
    let mut response = service.handle_request_at(request, 101);
    assert_eq!(response.status, 200);
    let origin = response
        .unwrapped_json
        .as_mut()
        .ok_or("actual consumed private origin")?;
    let stored = origin.stored_reply().ok_or("actual selected original")?;
    let original = Zeroizing::new(stored.bytes(&response.body)?.to_vec());
    // Read the complete original with the same typed lexical decoder as its
    // custody. A valid JSON Number such as 1e309 is not an f64 Value.
    let original_envelope = crate::auth::LexicalJson::parse_listener(&original)?;
    let crate::auth::LexicalJson::Object(original_fields) = &original_envelope else {
        return Err("original envelope object".into());
    };
    let Some(crate::auth::LexicalJson::String(original_id)) = original_fields.get("request_id")
    else {
        return Err("original ID".into());
    };
    let original_id = original_id.clone();
    let Some(crate::auth::LexicalJson::Object(original_data)) = original_fields.get("data") else {
        return Err("original Data object".into());
    };
    assert!(
        matches!(original_data.get("extra"), Some(crate::auth::LexicalJson::Number(value)) if value == "1e309")
    );
    assert_eq!(original_id, crate::crypto::uuid_from_bytes(&[0x91; 16]));
    // No response writer may accidentally release the original envelope for this kind.
    assert!(origin.raw_bytes(&response.body).is_err());
    origin.bind_selected_http_ingress(&response.body, &[0x92; 16])?;
    let wire = origin
        .raw_bytes(&response.body)?
        .ok_or("actual selected final ingress")?;
    assert!(wire.ends_with(b"\n"));
    let text = std::str::from_utf8(wire)?;
    assert!(
        text.contains("\"http_content_type\":1.0") && text.contains("\"http_raw_body\":\"1.0\"")
    );
    assert!(!text.contains("client-cannot-mint") && !text.contains("1e309"));
    let mut public: Value = serde_json::from_slice(wire)?;
    assert_eq!(
        public["request_id"],
        crate::crypto::uuid_from_bytes(&[0x92; 16])
    );
    assert!(
        public["data"]
            .get("http_raw_body_already_json_decoded")
            .is_none()
    );
    assert!(public["data"].get("http_status_code").is_none());
    assert!(origin.raw_http_transport(&response.body)?.is_none());
    assert_eq!(
        origin
            .stored_reply()
            .ok_or("retained private original")?
            .bytes(&response.body)?,
        original.as_slice()
    );
    assert!(
        origin
            .bind_selected_http_ingress(&response.body, &[0x93; 16])
            .is_err()
    );
    let replay = service.handle_request_at(
        ServiceRequest::new(
            "POST",
            "sys/wrapping/unwrap",
            "",
            &admin,
            json!({"token":&*token}),
        ),
        102,
    );
    assert_eq!(replay.status, 400);
    let retired = service.state.as_ref().ok_or("retired actual state")?;
    assert_eq!(retired.schema, GENERAL_WRAPPED_REPLY_STATE_SCHEMA);
    assert!(
        retired.auth.has_general_wrapped_reply_state()
            && !retired.auth.has_pki_raw_http_reply_state()
    );
    erase_json(&mut public);
    erase_json(&mut response.body);
    Ok(())
}

fn raw112_assert_chain_rewrap_reopen_terminal(
    directory: &Root,
    mut service: Service,
    key: &str,
    admin: &str,
    expected: &[u8],
) -> TestResult {
    assert!(!expected.ends_with(b"\n"));
    let plain = call(&mut service, "GET", "rawpki/ca_chain", admin, json!({}));
    assert_eq!(plain.status, 200);
    let actual = base64::engine::general_purpose::STANDARD.decode(
        plain.body["__heptabao_pki_certificate"]
            .as_str()
            .ok_or("chain bytes")?,
    )?;
    assert_eq!(actual.as_slice(), expected);
    let ordinary = call(
        &mut service,
        "GET",
        "rawpki/cert/ca_chain",
        admin,
        json!({}),
    );
    assert_eq!(ordinary.status, 200);
    let text = std::str::from_utf8(expected)?;
    assert_eq!(ordinary.body["data"]["certificate"].as_str(), Some(text));
    assert_eq!(ordinary.body["data"]["ca_chain"].as_str(), Some(text));
    let first = raw110_pki_issue(
        &mut service,
        admin,
        "GET",
        "rawpki/ca_chain",
        json!({}),
        [0xa4; 16],
    )?;
    let (response, bytes) = raw110_pki_unwrap(&mut service, admin, &first)?;
    assert_eq!(bytes.as_slice(), expected);
    raw110_assert_http_terminal(response, 200, "application/pkix-cert", expected)?;
    let second = raw110_pki_issue(
        &mut service,
        admin,
        "GET",
        "rawpki/ca_chain",
        json!({}),
        [0xa5; 16],
    )?;
    let rewrapped = {
        let _ingress = crate::auth::IngressReplyScope::listener(&[0xa6; 16]);
        call(
            &mut service,
            "POST",
            "sys/wrapping/rewrap",
            admin,
            json!({"token":second.as_str()}),
        )
    };
    assert_eq!(rewrapped.status, 200);
    let next = Zeroizing::new(
        rewrapped.body["wrap_info"]["token"]
            .as_str()
            .ok_or("rewrapped chain")?
            .to_owned(),
    );
    assert_ne!(next.as_str(), second.as_str());
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            admin,
            json!({"token":second.as_str()})
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
    let (response, bytes) = raw110_pki_unwrap(&mut service, admin, &next)?;
    assert_eq!(bytes.as_slice(), expected);
    let origin = response
        .unwrapped_json
        .as_ref()
        .ok_or("reopened chain origin")?;
    let mut stored = serde_json::to_value(origin.stored_reply().ok_or("stored chain")?)?;
    assert_eq!(
        stored["request_id"],
        crate::crypto::uuid_from_bytes(&[0xa5; 16])
    );
    assert_eq!(stored["kind"]["pki-raw-http-v1"]["status"], 200);
    erase_json(&mut stored);
    raw110_assert_http_terminal(response, 200, "application/pkix-cert", expected)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            admin,
            json!({"token":next.as_str()})
        )
        .status,
        400
    );
    let state = service.state.as_ref().ok_or("retired chain state")?;
    assert!(state.auth.has_pki_raw_http_reply_state());
    assert_eq!(state.writer_schema(), RAW_PKI_HTTP_REPLY_STATE_SCHEMA);
    Ok(())
}

#[test]
fn raw112_actual_imported_single_ca_chain_has_no_terminal_lf_through_rewrap_reopen() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/chainparent",
            &admin,
            json!({"type":"pki"})
        )
        .status,
        204
    );
    let mut generated = call(
        &mut service,
        "POST",
        "chainparent/root/generate/exported",
        &admin,
        json!({"common_name":"chainparent.example.test","key_type":"ed25519","ttl":"48h","format":"pem"}),
    );
    assert_eq!(generated.status, 200);
    let certificate = generated.body["data"]["certificate"]
        .as_str()
        .ok_or("actual public parent")?
        .to_owned();
    let private = Zeroizing::new(
        generated.body["data"]["private_key"]
            .as_str()
            .ok_or("actual transient key")?
            .to_owned(),
    );
    erase_json(&mut generated.body);
    let parsed = openssl::x509::X509::from_pem(certificate.as_bytes())?;
    let public_key = parsed.public_key()?;
    assert!(parsed.verify(&public_key)?);
    let canonical = parsed.to_pem()?;
    let expected = canonical.strip_suffix(b"\n").ok_or("OpenSSL PEM LF")?;
    raw110_pki_install(&mut service, &admin, false)?;
    let imported = call(
        &mut service,
        "POST",
        "rawpki/keys/import",
        &admin,
        json!({"pem_bundle":&*private,"key_name":"chain-parent-key"}),
    );
    assert_eq!(imported.status, 200);
    drop(private);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "rawpki/intermediate/set-signed",
            &admin,
            json!({"certificate":format!("\r\n\t{certificate}\n ")}),
        )
        .status,
        200
    );
    raw112_assert_chain_rewrap_reopen_terminal(&directory, service, &key, &admin, expected)
}

#[test]
fn raw112_actual_two_certificate_ca_chain_has_one_separator_and_no_terminal_lf() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/chainparent",
            &admin,
            json!({"type":"pki"})
        )
        .status,
        204
    );
    let parent = call(
        &mut service,
        "POST",
        "chainparent/root/generate/internal",
        &admin,
        json!({"common_name":"chainparent.example.test","key_type":"ed25519","ttl":"48h"}),
    );
    assert_eq!(parent.status, 200);
    let parent_pem = parent.body["data"]["certificate"]
        .as_str()
        .ok_or("parent certificate")?;
    let parent_cert = openssl::x509::X509::from_pem(parent_pem.as_bytes())?;
    raw110_pki_install(&mut service, &admin, false)?;
    let csr = call(
        &mut service,
        "POST",
        "rawpki/intermediate/generate/internal",
        &admin,
        json!({"common_name":"child.example.test","key_type":"ec","key_bits":256}),
    );
    assert_eq!(csr.status, 200);
    let signed = call(
        &mut service,
        "POST",
        "chainparent/root/sign-intermediate",
        &admin,
        json!({"csr":csr.body["data"]["csr"],"use_csr_values":true,"ttl":"24h","max_path_length":0}),
    );
    assert_eq!(signed.status, 200);
    let child_pem = signed.body["data"]["certificate"]
        .as_str()
        .ok_or("child certificate")?;
    let child_cert = openssl::x509::X509::from_pem(child_pem.as_bytes())?;
    let parent_key = parent_cert.public_key()?;
    assert!(child_cert.verify(&parent_key)?);
    assert!(parent_cert.verify(&parent_key)?);
    let child_bytes = child_cert.to_pem()?;
    let parent_bytes = parent_cert.to_pem()?;
    let mut expected = child_bytes
        .strip_suffix(b"\n")
        .ok_or("child PEM LF")?
        .to_vec();
    expected.push(b'\n');
    expected.extend_from_slice(parent_bytes.strip_suffix(b"\n").ok_or("parent PEM LF")?);
    assert_eq!(openssl::x509::X509::stack_from_pem(&expected)?.len(), 2);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "rawpki/intermediate/set-signed",
            &admin,
            json!({"certificate":format!(" \r\n{child_pem}\r\n\n{parent_pem}\n\t")}),
        )
        .status,
        200
    );
    raw112_assert_chain_rewrap_reopen_terminal(&directory, service, &key, &admin, &expected)
}

#[test]
fn raw113_actual_selected_byte_string_drop_projection_reaches_mandatory_audit_before_http()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_key, admin) = bootstrap(&mut service)?;
    let mut response_bindings = std::collections::BTreeSet::new();
    for (index, raw) in [json!("/wBh"), json!("1.0"), json!(123), json!("")]
        .into_iter()
        .enumerate()
    {
        let lexical = crate::auth::LexicalJson::from_backend(
            &json!({"http_raw_body":raw,"extra":"must-not-leak","http_raw_body_already_json_decoded":true}),
        )?;
        let _ingress = crate::auth::IngressReplyScope::listener_wrapping(
            &[0x96 + index as u8; 16],
            Some(lexical.clone()),
        );
        let mut request = ServiceRequest::new(
            "POST",
            "sys/wrapping/wrap",
            "",
            &admin,
            lexical.wrapping_view()?,
        );
        request.wrap_ttl_seconds = Some(60);
        let issued = service.handle_request_at(request, 100);
        assert_eq!(issued.status, 200);
        let token = Zeroizing::new(
            issued.body["wrap_info"]["token"]
                .as_str()
                .ok_or("wrapper")?
                .to_owned(),
        );
        let _later = crate::auth::IngressReplyScope::listener(&[0x9b; 16]);
        let mut response = service.handle_request_at(
            ServiceRequest::new(
                "POST",
                "sys/wrapping/unwrap",
                "",
                &admin,
                json!({"token":&*token}),
            ),
            101,
        );
        assert_eq!(response.status, 200);
        let audit = Zeroizing::new(std::fs::read(directory.path.join("audit.jsonl"))?);
        let rows = audit
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        assert!(rows.len() >= 2);
        let mut request_record: Value = serde_json::from_slice(rows[rows.len() - 2])?;
        let mut response_record: Value = serde_json::from_slice(rows[rows.len() - 1])?;
        assert_eq!(request_record["event"]["kind"], "request");
        assert_eq!(response_record["event"]["kind"], "response");
        assert!(request_record["event"]["path_digest"] != response_record["event"]["path_digest"]);
        let binding = response_record["event"]["path_digest"]
            .as_str()
            .ok_or("mandatory response binding")?
            .to_owned();
        assert!(response_bindings.insert(binding));
        erase_json(&mut request_record);
        erase_json(&mut response_record);
        let origin = response
            .unwrapped_json
            .as_mut()
            .ok_or("actual consumed owner")?;
        assert!(origin.raw_bytes(&response.body).is_err());
        // The actual Service boundary has prepared this projection exactly once.
        assert!(
            origin
                .selected_response_audit_binding(&response.body)
                .is_err()
        );
        origin.bind_selected_http_ingress(&response.body, &[0x9b; 16])?;
        let wire = origin
            .raw_bytes(&response.body)?
            .ok_or("actual selected HTTP")?;
        let mut public: Value = serde_json::from_slice(wire)?;
        assert!(
            !wire
                .windows(b"must-not-leak".len())
                .any(|w| w == b"must-not-leak")
        );
        if index == 2 {
            assert_eq!(public["data"]["http_raw_body_already_json_decoded"], true);
            assert!(public["data"].get("http_raw_body").is_none());
        } else {
            assert!(
                public["data"]
                    .get("http_raw_body_already_json_decoded")
                    .is_none()
            );
            assert!(public["data"]["http_raw_body"] == raw);
        }
        assert_eq!(
            public["request_id"],
            crate::crypto::uuid_from_bytes(&[0x9b; 16])
        );
        erase_json(&mut public);
        erase_json(&mut response.body);
    }
    assert_eq!(response_bindings.len(), 4);
    Ok(())
}

#[test]
fn raw113_actual_selected_mandatory_response_audit_failure_erases_owner_and_retains_consumption()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let lexical =
        crate::auth::LexicalJson::parse_listener(br#"{"http_raw_body":"do-not-release!"}"#)?;
    let _issue =
        crate::auth::IngressReplyScope::listener_wrapping(&[0x9c; 16], Some(lexical.clone()));
    let mut request = ServiceRequest::new(
        "POST",
        "sys/wrapping/wrap",
        "",
        &admin,
        lexical.wrapping_view()?,
    );
    request.wrap_ttl_seconds = Some(60);
    let issued = service.handle_request_at(request, 100);
    assert_eq!(issued.status, 200);
    let token = Zeroizing::new(
        issued.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper")?
            .to_owned(),
    );
    let _later = crate::auth::IngressReplyScope::listener(&[0x9d; 16]);
    let old_sequence = service.audit_sequence;
    let event = AuditUnsigned {
        schema: 2,
        sequence: old_sequence + 1,
        previous: STANDARD.encode(service.audit_previous),
        time: 101,
        kind: "request".into(),
        path_digest: service.request_fingerprint("POST", "sys/wrapping/unwrap", "", &admin),
        status: None,
    };
    let payload = Zeroizing::new(serde_json::to_vec(&event)?);
    let mac = STANDARD.encode(hmac::sign(&service.audit_key, &payload).as_ref());
    let request_bytes = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
    service.audit_capacity = service.audit.metadata()?.len() + request_bytes as u64;
    let response = service.handle_request_at(
        ServiceRequest::new(
            "POST",
            "sys/wrapping/unwrap",
            "",
            &admin,
            json!({"token":&*token}),
        ),
        101,
    );
    assert_eq!(response.status, 503);
    assert!(response.unwrapped_json.is_none());
    assert!(!response.body.to_string().contains("do-not-release!"));
    assert!(service.recovery_required && service.audit_sequence == old_sequence + 1);
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            &admin,
            json!({"token":&*token})
        )
        .status,
        400
    );
    let retired = service.state.as_ref().ok_or("retired state")?;
    assert_eq!(retired.schema, GENERAL_WRAPPED_REPLY_STATE_SCHEMA);
    assert!(retired.auth.has_general_wrapped_reply_state());
    Ok(())
}

fn raw113_issue_media(
    service: &mut Service,
    admin: &str,
    media: &str,
    attempt: [u8; 16],
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let lexical = crate::auth::LexicalJson::from_backend(&json!({
        "http_status_code":200,"http_content_type":media,"http_raw_body":"YQ==",
        "extra":"must-not-be-a-header"
    }))?;
    let _ingress =
        crate::auth::IngressReplyScope::listener_wrapping(&attempt, Some(lexical.clone()));
    let mut request = ServiceRequest::new(
        "POST",
        "sys/wrapping/wrap",
        "",
        admin,
        lexical.wrapping_view()?,
    );
    request.wrap_ttl_seconds = Some(60);
    let response = service.handle_request_at(request, 100);
    assert_eq!(response.status, 200);
    Ok(Zeroizing::new(
        response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("media wrapper")?
            .to_owned(),
    ))
}

#[test]
fn raw113_actual_wrapped_raw_media_sanitizes_only_terminal_header_through_rewrap_reopen()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let original = " \ttext/plain\r\nInjected: cannot-be-a-header\t ";
    let expected = "text/plain  Injected: cannot-be-a-header";
    let first = raw113_issue_media(&mut service, &admin, original, [0xb9; 16])?;
    let (response, bytes) = raw110_pki_unwrap(&mut service, &admin, &first)?;
    assert_eq!(bytes.as_slice(), b"a");
    let mut stored = serde_json::to_value(
        response
            .unwrapped_json
            .as_ref()
            .ok_or("origin")?
            .stored_reply()
            .ok_or("stored")?,
    )?;
    assert_eq!(stored["media_type"], original);
    assert_eq!(
        stored["request_id"],
        crate::crypto::uuid_from_bytes(&[0xb9; 16])
    );
    assert!(stored["kind"].get("general-raw-http-v1").is_some());
    erase_json(&mut stored);
    raw110_assert_http_terminal(response, 200, expected, b"a")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            &admin,
            json!({"token":first.as_str()})
        )
        .status,
        400
    );

    let second = raw113_issue_media(&mut service, &admin, original, [0xba; 16])?;
    let response = {
        let _rewrap = crate::auth::IngressReplyScope::listener(&[0xbb; 16]);
        call(
            &mut service,
            "POST",
            "sys/wrapping/rewrap",
            &admin,
            json!({"token":second.as_str()}),
        )
    };
    assert_eq!(response.status, 200);
    let next = Zeroizing::new(
        response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("rewrapped media")?
            .to_owned(),
    );
    assert!(next.as_str() != second.as_str());
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            &admin,
            json!({"token":second.as_str()})
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
    let (response, bytes) = raw110_pki_unwrap(&mut service, &admin, &next)?;
    assert_eq!(bytes.as_slice(), b"a");
    let mut stored = serde_json::to_value(
        response
            .unwrapped_json
            .as_ref()
            .ok_or("origin")?
            .stored_reply()
            .ok_or("stored")?,
    )?;
    assert_eq!(stored["media_type"], original);
    assert_eq!(
        stored["request_id"],
        crate::crypto::uuid_from_bytes(&[0xba; 16])
    );
    erase_json(&mut stored);
    let mut wire = Zeroizing::new(Vec::new());
    crate::http::write_raw110_reply_for_test(&mut *wire, response, false)?;
    let split = wire
        .windows(4)
        .position(|p| p == b"\r\n\r\n")
        .ok_or("HTTP boundary")?;
    let header = std::str::from_utf8(&wire[..split])?;
    assert!(
        header
            .lines()
            .any(|line| line == format!("Content-Type: {expected}"))
    );
    assert!(!header.lines().any(|line| line.starts_with("Injected:")));
    assert!(
        !wire
            .windows(b"must-not-be-a-header".len())
            .any(|p| p == b"must-not-be-a-header")
    );
    assert_eq!(&wire[split + 4..], b"a");
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            &admin,
            json!({"token":next.as_str()})
        )
        .status,
        400
    );
    let state = service.state.as_ref().ok_or("retired state")?;
    assert_eq!(state.writer_schema(), GENERAL_WRAPPED_REPLY_STATE_SCHEMA);
    assert!(
        state.auth.has_general_wrapped_reply_state() && !state.auth.has_pki_raw_http_reply_state()
    );
    Ok(())
}
