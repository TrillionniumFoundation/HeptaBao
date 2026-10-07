use super::*;
use crate::service::tests::{Root, bootstrap};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn request(
    service: &mut Service,
    clock: RequestClock,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
) -> Response {
    let started = Instant::now();
    let _deadline =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(4));
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
        clock,
    );
    service.finish_synchronous_request(execution)
}
// Original legacy assertions can observe the actual completed task explicitly,
// while the separately tested public request still returns only a queued ACK.
pub(in crate::service) fn call_and_complete(
    service: &mut Service,
    clock: RequestClock,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> Response {
    let response = request(service, clock, token, method, path, body);
    if path == "sys/remount" && matches!(method, "POST" | "PUT") && response.status < 300 {
        let result = migration(&response);
        assert!(result.is_ok(), "actual queued migration missing");
        let id = match result {
            Ok(id) => id,
            Err(_) => return Response::error(500, "actual queued migration missing"),
        };
        assert!(service.maintain_native_remounts());
        let status = request(
            service,
            clock,
            token,
            "GET",
            &format!("sys/remount/status/{id}"),
            json!({}),
        );
        assert_eq!(
            status.body["data"]["migration_info"]["status"], "success",
            "{}",
            status.body
        );
    }
    response
}
fn clock() -> TestResult<RequestClock> {
    Ok(RequestClock::anchored(
        Duration::new(100, 1),
        Instant::now(),
    )?)
}
fn migration(response: &Response) -> TestResult<String> {
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body["warnings"], json!([QUEUED_WARNING]));
    let id = response.body["data"]["migration_id"]
        .as_str()
        .ok_or("migration id")?;
    assert_eq!(
        id.split('-').map(str::len).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12]
    );
    Ok(id.into())
}
fn mount(service: &mut Service, clock: RequestClock, root: &str) {
    let response = request(
        service,
        clock,
        root,
        "POST",
        "sys/mounts/from-native",
        json!({"type":"kv"}),
    );
    assert_eq!(response.status, 204, "{}", response.body);
    let response = request(
        service,
        clock,
        root,
        "PUT",
        "from-native/record",
        json!({"value":"original"}),
    );
    assert_eq!(response.status, 204, "{}", response.body);
}
#[test]
fn native_remount_ack_is_queued_then_real_move_and_encrypted_reopen() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, root) = bootstrap(&mut service)?;
    let clock = clock()?;
    mount(&mut service, clock, &root);
    let id = migration(&request(
        &mut service,
        clock,
        &root,
        "POST",
        "sys/remount",
        json!({"from":"from-native","to":"to-native"}),
    ))?;
    assert_eq!(service.native_remount_jobs.len(), 1);
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            "from-native/record",
            json!({})
        )
        .status,
        200
    );
    let status = request(
        &mut service,
        clock,
        &root,
        "GET",
        &format!("sys/remount/status/{id}"),
        json!({}),
    );
    assert_eq!(
        status.body["data"]["migration_info"]["status"],
        "in-progress"
    );
    assert!(service.maintain_native_remounts());
    assert!(!service.maintain_native_remounts());
    let status = request(
        &mut service,
        clock,
        &root,
        "GET",
        &format!("sys/remount/status/{id}"),
        json!({}),
    );
    assert_eq!(
        status.body["data"]["migration_info"]["status"], "success",
        "{}",
        status.body
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            "from-native/record",
            json!({})
        )
        .status,
        404
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            "to-native/record",
            json!({})
        )
        .body["data"]["value"],
        "original"
    );
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        request(
            &mut service,
            clock,
            "",
            "POST",
            "sys/unseal",
            json!({"key":key})
        )
        .status,
        200
    );
    let response = request(
        &mut service,
        clock,
        &root,
        "GET",
        &format!("sys/remount/status/{id}"),
        json!({}),
    );
    assert_eq!(response.status, 404);
    assert_eq!(response.body, json!({"errors":[]}));
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            "to-native/record",
            json!({})
        )
        .body["data"]["value"],
        "original"
    );
    Ok(())
}
#[test]
fn native_auth_remount_revokes_original_token_and_preserves_current_policy_and_users() -> TestResult
{
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let clock = clock()?;
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "POST",
            "sys/auth/from-auth",
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "PUT",
            "auth/from-auth/users/alice",
            json!({"password":"native-password"})
        )
        .status,
        204
    );
    let login = request(
        &mut service,
        clock,
        "",
        "POST",
        "auth/from-auth/login/alice",
        json!({"password":"native-password"}),
    );
    assert_eq!(login.status, 200, "{}", login.body);
    let token = zeroize::Zeroizing::new(
        login.body["auth"]["client_token"]
            .as_str()
            .ok_or("token")?
            .to_owned(),
    );
    let id = migration(&request(
        &mut service,
        clock,
        &root,
        "POST",
        "sys/remount",
        json!({"from":"auth/from-auth","to":"auth/to-auth"}),
    ))?;
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "PUT",
            "sys/policies/acl/current-policy",
            json!({"policy":"path \"secret/*\" { capabilities=[\"read\"] }"})
        )
        .status,
        204
    );
    assert!(service.maintain_native_remounts());
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            &format!("sys/remount/status/{id}"),
            json!({})
        )
        .body["data"]["migration_info"]["status"],
        "success"
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &token,
            "GET",
            "auth/token/lookup-self",
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            "sys/policies/acl/current-policy",
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            "",
            "POST",
            "auth/to-auth/login/alice",
            json!({"password":"native-password"})
        )
        .status,
        200
    );
    Ok(())
}
#[test]
fn native_remount_destination_change_and_original_deadline_fail_once_without_move() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let clock = clock()?;
    mount(&mut service, clock, &root);
    let id = migration(&request(
        &mut service,
        clock,
        &root,
        "POST",
        "sys/remount",
        json!({"from":"from-native","to":"to-native"}),
    ))?;
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "POST",
            "sys/mounts/to-native",
            json!({"type":"kv"})
        )
        .status,
        204
    );
    assert!(service.maintain_native_remounts());
    assert!(!service.maintain_native_remounts());
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            &format!("sys/remount/status/{id}"),
            json!({})
        )
        .body["data"]["migration_info"]["status"],
        "failure"
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            "from-native/record",
            json!({})
        )
        .status,
        200
    );
    let id = migration(&request(
        &mut service,
        clock,
        &root,
        "POST",
        "sys/remount",
        json!({"from":"from-native","to":"another-native"}),
    ))?;
    // This is the exact already-admitted task's original deadline, never a new scope.
    let deadline = service.native_remount_jobs.front().ok_or("task")?.deadline;
    std::thread::sleep(
        deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
    );
    assert!(service.maintain_native_remounts());
    assert!(!service.maintain_native_remounts());
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            &format!("sys/remount/status/{id}"),
            json!({})
        )
        .body["data"]["migration_info"]["status"],
        "failure"
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            "from-native/record",
            json!({})
        )
        .status,
        200
    );
    Ok(())
}
#[test]
fn native_remount_ack_veto_does_not_arm_and_source_aba_task_does_not_move() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let clock = clock()?;
    mount(&mut service, clock, &root);
    let body = json!({"from":"from-native","to":"to-native"});
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(4),
    );
    let response = service.handle_inner(RequestView {
        method: "POST",
        path: "sys/remount",
        namespace: "",
        token: &root,
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
    assert!(service.native_remount_jobs.is_empty());
    let original_nonce = service.unseal_nonce.clone();
    service.unseal_nonce.push_str("-changed");
    let response =
        service.complete_native_remount_delivery(true, response, "fixed-public-fingerprint");
    assert_eq!(response.status, 503);
    assert!(service.native_remount_jobs.is_empty());
    service.unseal_nonce = original_nonce;
    let id = migration(&request(
        &mut service,
        clock,
        &root,
        "POST",
        "sys/remount",
        json!({"from":"from-native","to":"to-native"}),
    ))?;
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "DELETE",
            "sys/mounts/from-native",
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "POST",
            "sys/mounts/from-native",
            json!({"type":"kv"})
        )
        .status,
        204
    );
    assert!(service.maintain_native_remounts());
    assert!(!service.maintain_native_remounts());
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            &format!("sys/remount/status/{id}"),
            json!({})
        )
        .body["data"]["migration_info"]["status"],
        "failure"
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            "to-native/record",
            json!({})
        )
        .status,
        404
    );
    Ok(())
}

#[test]
fn native_auth_remount_destination_enable_disable_aba_fails_once_without_move() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let clock = clock()?;
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "POST",
            "sys/auth/from-auth",
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    let id = migration(&request(
        &mut service,
        clock,
        &root,
        "POST",
        "sys/remount",
        json!({"from":"auth/from-auth","to":"auth/to-auth"}),
    ))?;
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "POST",
            "sys/auth/to-auth",
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "DELETE",
            "sys/auth/to-auth",
            json!({})
        )
        .status,
        204
    );
    assert!(service.maintain_native_remounts());
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            &format!("sys/remount/status/{id}"),
            json!({})
        )
        .body["data"]["migration_info"]["status"],
        "failure"
    );
    assert!(!service.maintain_native_remounts());
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            "sys/auth/from-auth",
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            "sys/auth/to-auth",
            json!({})
        )
        .status,
        404
    );
    Ok(())
}

#[test]
fn native_auth_remount_auth_decode_after_destination_aba_rejects_original_task() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let clock = clock()?;
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "POST",
            "sys/auth/from-auth",
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    let id = migration(&request(
        &mut service,
        clock,
        &root,
        "POST",
        "sys/remount",
        json!({"from":"auth/from-auth","to":"auth/to-auth"}),
    ))?;
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "POST",
            "sys/auth/to-auth",
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "DELETE",
            "sys/auth/to-auth",
            json!({})
        )
        .status,
        204
    );
    // Rebuild the actual published Auth bytes as a reload does; no epoch or control
    // is supplied in JSON, and the old RAM task must fail instead of matching epoch0.
    let state = service.state.as_mut().ok_or("state")?;
    let bytes = zeroize::Zeroizing::new(
        crate::secret_serde::to_vec(&state.auth, MAX_STATE_BYTES)
            .map_err(|_| "actual Auth encode unavailable")?,
    );
    let rebuilt: AuthState = serde_json::from_slice(&bytes)?;
    let after = zeroize::Zeroizing::new(
        crate::secret_serde::to_vec(&rebuilt, MAX_STATE_BYTES)
            .map_err(|_| "rebuilt Auth encode unavailable")?,
    );
    assert!(
        bytes.as_slice() == after.as_slice(),
        "actual Auth persisted bytes changed"
    );
    state.auth = rebuilt.into();
    assert!(service.maintain_native_remounts());
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            &format!("sys/remount/status/{id}"),
            json!({})
        )
        .body["data"]["migration_info"]["status"],
        "failure"
    );
    assert!(!service.maintain_native_remounts());
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            "sys/auth/from-auth",
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            &root,
            "GET",
            "sys/auth/to-auth",
            json!({})
        )
        .status,
        404
    );
    Ok(())
}
