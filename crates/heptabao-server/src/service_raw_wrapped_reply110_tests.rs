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
