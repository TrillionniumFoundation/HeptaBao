//! Original SDK control admission, durable prepublication and mandatory audit.
use super::super::tests::{Root, bootstrap, call};
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn clock() -> TestResult<RequestClock> {
    Ok(RequestClock::anchored(
        Duration::new(100, 200_000_000),
        Instant::now(),
    )?)
}
fn issue(service: &mut Service, root: &str) -> TestResult<String> {
    assert_eq!(
        call(
            service,
            "PUT",
            "sys/policies/acl/sdk-authority",
            root,
            json!({"policy":r#"path "sys/plugins/catalog" { capabilities=["read", "sudo"] }"#})
        )
        .status,
        204
    );
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method: "POST",
            path: "auth/token/create",
            namespace: "",
            token: root,
            body: json!({"ttl":"1s","policies":["sdk-authority"],"no_default_policy":true}),
            now: 100,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        clock()?,
    );
    let response = service.finish_synchronous_request(execution);
    assert_eq!(response.status, 200, "{}", response.body);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("issued token")?
        .into())
}
fn admitted(
    service: &mut Service,
    actor: &str,
) -> TestResult<(plugin::PluginResponseAuthority, Response, RequestClock)> {
    assert!(service.pending_sdk_control_authority.is_none());
    let clock = clock()?;
    let body = json!({});
    let response = service.handle_inner(RequestView {
        method: "GET",
        path: "sys/plugins/catalog",
        namespace: "",
        token: actor,
        body: &body,
        now: 100,
        admission_started: Instant::now(),
        token_clock: Some(clock),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    });
    assert_eq!(response.status, 200, "{}", response.body);
    Ok((
        service
            .pending_sdk_control_authority
            .take()
            .ok_or("actual SDK control capsule")?,
        response,
        clock,
    ))
}
#[test]
fn sdk_authority_control_expired_before_publication_changes_no_durable_generation() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let actor = issue(&mut service, &root)?;
    let (mut authority, response, _) = admitted(&mut service, &actor)?;
    let before = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let mut candidate = service.state.clone().ok_or("state")?;
    std::thread::sleep(Duration::from_millis(1100));
    let error = match service.commit_sdk_control(&mut candidate, &mut authority, &before) {
        Err(error) => error,
        Ok(()) => return Err("expired original capsule published a clock candidate".into()),
    };
    assert_eq!(error.status, 403, "{}", error.body);
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "identity after")?,
        before
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(response.status, 200);
    Ok(())
}
#[test]
fn sdk_authority_control_expired_during_actual_audit_erases_and_records_veto() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let actor = issue(&mut service, &root)?;
    let (authority, mut response, clock) = admitted(&mut service, &actor)?;
    response.response_headers = ResponseHeaders::from_sdk(
        Some(&json!({"X-SDK-Secret":["original-header-secret"]})),
        &["X-SDK-Secret".into()],
    )
    .map_err(|()| "header metadata")?;
    assert!(!response.response_headers.is_empty());
    service.pending_sdk_control_authority = Some(authority);
    let response = service.audit_completed_response_with_receipt(
        "sdk-real-audit-expiry",
        100,
        Some(clock),
        response,
        || std::thread::sleep(Duration::from_millis(1100)),
    );
    assert_eq!(response.status, 200);
    let response =
        service.complete_pending_sdk_control_delivery(true, response, "sdk-real-audit-expiry");
    assert_eq!(response.status, 403, "{}", response.body);
    assert!(response.body.get("data").is_none());
    assert!(response.response_headers.is_empty());
    assert!(response.consistency_index.is_none());
    let forwarded = crate::ha_forward::encode_index_response_for_cluster(
        "sdk-headers95-audit",
        1,
        2,
        &response,
    )?;
    let received =
        crate::ha_forward::decode_index_response_for_cluster(&forwarded, "sdk-headers95-audit")?;
    assert_eq!(received.status, 403);
    assert!(received.response_headers.is_empty());
    assert!(received.body.get("data").is_none());
    let records = fs::read_to_string(files.path.join("audit.jsonl"))?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let last = records.last().ok_or("veto audit")?;
    let prior = records.iter().rev().nth(1).ok_or("response audit")?;
    assert_eq!(last["event"]["kind"], "sdk-delivery-veto");
    assert_eq!(last["event"]["status"], 403);
    assert_eq!(prior["event"]["kind"], "response");
    assert_eq!(prior["event"]["status"], 200);
    assert_eq!(last["event"]["path_digest"], prior["event"]["path_digest"]);
    assert!(!service.recovery_required);
    Ok(())
}
#[test]
fn sdk_authority_missing_control_capsule_fences_original_service() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let (authority, response, _) = admitted(&mut service, &root)?;
    drop(authority);
    let response =
        service.complete_pending_sdk_control_delivery(true, response, "sdk-real-capsule-loss");
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.response_headers.is_empty());
    assert!(response.consistency_index.is_none());
    assert!(service.recovery_required);
    assert!(service.ha_activation.is_none());
    Ok(())
}

fn precise_call(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> TestResult<Response> {
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method,
            path,
            namespace: "",
            token,
            body,
            now: 100,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        clock()?,
    );
    Ok(service.finish_synchronous_request(execution))
}

fn data_admission(
    service: &mut Service,
    actor: &str,
    deadline: Instant,
) -> TestResult<expiry::Authority> {
    let (client, _, clock) = admitted(service, actor)?;
    let state = service.state.as_ref().ok_or("state")?;
    let body = json!({});
    let request = RequestView {
        method: "GET",
        path: "sys/plugins/catalog",
        namespace: "",
        token: actor,
        body: &body,
        now: 100,
        admission_started: clock.started(),
        token_clock: Some(clock),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    Ok(expiry::Authority::Admitted(Box::new(
        expiry::AdmittedAuthority::capture(
            Box::new(client),
            state,
            &request,
            &service.unseal_nonce,
            service.ha.clone(),
            deadline,
        )
        .map_err(|_| "capture")?,
    )))
}
#[test]
fn sdk_admitted_original_expiry_retains_data_but_secret_requires_same_live_client() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let actor = issue(&mut service, &root)?;
    let mut authority = data_admission(
        &mut service,
        &actor,
        Instant::now() + Duration::from_secs(4),
    )?;
    std::thread::sleep(Duration::from_millis(1100));
    service
        .validate_sdk_authority(&mut authority)
        .map_err(|_| "Data original snapshot")?;
    authority
        .validate_live_auth(&service.state.as_ref().ok_or("state")?.auth)
        .map_err(|_| "Data prepublication")?;
    authority.require_secret_authority();
    assert_eq!(
        service
            .validate_sdk_authority(&mut authority)
            .err()
            .ok_or("late Secret must retain existing guard")?
            .status,
        403
    );
    Ok(())
}
#[test]
fn sdk_admitted_revoke_is_retained_and_original_deadline_seal_veto_data() -> TestResult {
    {
        let coarse_files = Root::new();
        let mut coarse = coarse_files.service()?;
        let (_, coarse_root) = bootstrap(&mut coarse)?;
        let coarse_actor = issue(&mut coarse, &coarse_root)?;
        let _held = data_admission(
            &mut coarse,
            &coarse_actor,
            Instant::now() + Duration::from_secs(4),
        )?;
        let response = call(
            &mut coarse,
            "POST",
            "auth/token/revoke",
            &coarse_root,
            json!({"token":coarse_actor}),
        );
        assert_eq!(response.status, 503, "{}", response.body);
        eprintln!("sdk-admitted-original-coarse-revoke={}", response.body);
        assert_eq!(
            response.body,
            json!({"errors":["trusted token clock is required"]})
        );
    }
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let actor = issue(&mut service, &root)?;
    let mut authority = data_admission(
        &mut service,
        &actor,
        Instant::now() + Duration::from_secs(4),
    )?;
    assert_eq!(
        precise_call(
            &mut service,
            "POST",
            "auth/token/revoke",
            &root,
            json!({"token":actor})
        )?
        .status,
        204
    );
    service
        .validate_sdk_authority(&mut authority)
        .map_err(|_| "Data revoke snapshot")?;
    assert_eq!(
        precise_call(
            &mut service,
            "GET",
            "sys/plugins/catalog",
            &actor,
            json!({})
        )?
        .status,
        403
    );
    let mut deadline = data_admission(
        &mut service,
        &root,
        Instant::now() + Duration::from_millis(20),
    )?;
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(
        service
            .validate_sdk_authority(&mut deadline)
            .err()
            .ok_or("deadline veto")?
            .status,
        503
    );
    assert_eq!(
        precise_call(&mut service, "PUT", "sys/seal", &root, json!({}))?.status,
        204
    );
    assert_eq!(
        service
            .validate_sdk_authority(&mut authority)
            .err()
            .ok_or("seal veto")?
            .status,
        503
    );
    Ok(())
}
