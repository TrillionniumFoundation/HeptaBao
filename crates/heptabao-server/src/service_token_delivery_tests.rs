//! Real Service issuance/admission, durable publication and mandatory audit.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use std::time::{Duration, Instant};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn clock() -> TestResult<RequestClock> {
    Ok(RequestClock::anchored(
        Duration::new(100, 200_000_000),
        Instant::now(),
    )?)
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

fn issue(service: &mut Service, root: &str, ttl: &str, uses: u64) -> TestResult<String> {
    let response = precise_call(
        service,
        "POST",
        "auth/token/create",
        root,
        json!({"ttl":ttl,"num_uses":uses,"policies":["token-delivery"],"no_default_policy":true}),
    )?;
    assert_eq!(response.status, 200, "{}", response.body);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("issued token")?
        .into())
}

fn fixture(service: &mut Service, root: &str) {
    assert_eq!(
        call(
            service,
            "PUT",
            "sys/policies/acl/token-delivery",
            root,
            json!({"policy":r#"path "auth/token/lookup-self" { capabilities=["read"] }
path "auth/token/create" { capabilities=["update"] }"#})
        )
        .status,
        204
    );
}

fn admitted(
    service: &mut Service,
    actor: &str,
    path: &str,
    body: &Value,
) -> TestResult<(plugin::PluginResponseAuthority, Response, RequestClock)> {
    assert!(service.pending_token_api_authority.is_none());
    let clock = clock()?;
    let response = service.handle_inner(RequestView {
        method: "POST",
        path,
        namespace: "",
        token: actor,
        body,
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
    let authority = service
        .pending_token_api_authority
        .take()
        .ok_or("actual admission capsule")?;
    Ok((authority, response, clock))
}

fn audit_veto(files: &Root, status: u16) -> TestResult {
    let records = std::fs::read_to_string(files.path.join("audit.jsonl"))?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let last = records.last().ok_or("veto record")?;
    assert_eq!(last["event"]["kind"], "token-delivery-veto");
    assert_eq!(last["event"]["status"], status);
    let before = records.iter().rev().nth(1).ok_or("actual response audit")?;
    assert_eq!(before["event"]["kind"], "response");
    assert_eq!(before["event"]["status"], 200);
    assert_eq!(last["event"]["path_digest"], before["event"]["path_digest"]);
    Ok(())
}

#[test]
fn token_delivery_retains_actual_final_use_and_rejects_reauthentication() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    fixture(&mut service, &root);
    let token = issue(&mut service, &root, "10m", 1)?;
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .has_token_api_precision_state()
    );
    let (authority, response, clock) =
        admitted(&mut service, &token, "auth/token/lookup-self", &json!({}))?;
    assert_eq!(response.body["data"]["num_uses"], 0);
    let response = service.audit_completed_response("token-last-use", 100, Some(clock), response);
    let response = service.complete_token_api_delivery(authority, response, "token-last-use");
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body["data"]["id"], token);
    // Only the durable clock may advance during audit. A second authentication
    // must fail because the one real finite use was already consumed.
    assert_eq!(
        precise_call(
            &mut service,
            "POST",
            "auth/token/lookup-self",
            &token,
            json!({})
        )?
        .status,
        403
    );
    assert!(service.pending_token_api_authority.is_none());
    Ok(())
}

#[test]
fn token_delivery_withholds_actor_or_actual_target_expired_during_audit() -> TestResult {
    for actor_expiry in [true, false] {
        let files = Root::new();
        let mut service = files.service()?;
        let (_, root) = bootstrap(&mut service)?;
        fixture(&mut service, &root);
        let token = issue(&mut service, &root, "1s", 0)?;
        let (actor, path, body) = if actor_expiry {
            (token.as_str(), "auth/token/lookup-self", json!({}))
        } else {
            (root.as_str(), "auth/token/lookup", json!({"token":token}))
        };
        let (authority, response, clock) = admitted(&mut service, actor, path, &body)?;
        assert_eq!(response.body["data"]["id"], token);
        let response = service.audit_completed_response_with_receipt(
            "token-audit-expiry",
            100,
            Some(clock),
            response,
            || std::thread::sleep(Duration::from_millis(1100)),
        );
        assert_eq!(
            response.status, 200,
            "actual audit completed before the late observation"
        );
        let response =
            service.complete_token_api_delivery(authority, response, "token-audit-expiry");
        assert!(response.status >= 300, "{}", response.body);
        assert!(response.body.get("data").is_none());
        assert!(response.body.get("auth").is_none());
        assert!(response.consistency_index.is_none());
        audit_veto(&files, response.status)?;
    }
    Ok(())
}

#[test]
fn token_delivery_late_veto_keeps_the_actual_published_child() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    fixture(&mut service, &root);
    let actor = issue(&mut service, &root, "1s", 0)?;
    let (authority, response, clock) = admitted(
        &mut service,
        &actor,
        "auth/token/create",
        &json!({"ttl":"10m"}),
    )?;
    let child = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("published child")?
        .to_owned();
    let response = service.audit_completed_response_with_receipt(
        "token-create-veto",
        100,
        Some(clock),
        response,
        || std::thread::sleep(Duration::from_millis(1100)),
    );
    let before = serde_json::to_vec(&service.state.as_ref().ok_or("state")?.auth)?;
    let response = service.complete_token_api_delivery(authority, response, "token-create-veto");
    assert_eq!(response.status, 403, "{}", response.body);
    assert!(response.body.get("auth").is_none());
    let state = service.state.as_ref().ok_or("state")?;
    // This is the committed AuthState from actual publication; final veto does
    // not restore an earlier state or remove the already-created child.
    let after = serde_json::to_vec(&state.auth)?;
    assert_eq!(after, before);
    let child_digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(ring::digest::digest(&ring::digest::SHA256, child.as_bytes()).as_ref());
    assert!(String::from_utf8(after)?.contains(&child_digest));
    Ok(())
}

#[test]
fn token_delivery_missing_capsule_fences_an_actual_success_body() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let (authority, response, _) =
        admitted(&mut service, &root, "auth/token/lookup-self", &json!({}))?;
    drop(authority);
    let response =
        service.complete_pending_token_api_delivery(true, response, "missing-token-capsule");
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.consistency_index.is_none());
    assert!(service.recovery_required);
    Ok(())
}
