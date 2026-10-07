use super::*;
use crate::service::tests::{Root, bootstrap};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn clock(now: u64) -> TestResult<RequestClock> {
    Ok(RequestClock::anchored(
        Duration::new(now, 1),
        Instant::now(),
    )?)
}
#[allow(clippy::too_many_arguments)]
fn request(
    service: &mut Service,
    clock: RequestClock,
    namespace: &str,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
    wrap: Option<u64>,
) -> Response {
    let started = Instant::now();
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(4));
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method,
            path,
            namespace,
            token,
            body,
            now: clock.admitted_at().seconds(),
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: wrap,
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    );
    service.finish_synchronous_request(execution)
}
fn mount(service: &mut Service, clock: RequestClock, namespace: &str, admin: &str, name: &str) {
    assert_eq!(
        request(
            service,
            clock,
            namespace,
            admin,
            "POST",
            &format!("sys/auth/{name}"),
            json!({"type":"approle"}),
            None
        )
        .status,
        204
    );
    assert_eq!(
        request(
            service,
            clock,
            namespace,
            admin,
            "POST",
            &format!("auth/{name}/role/work"),
            json!({"secret_id_ttl":0}),
            None
        )
        .status,
        204
    );
}
fn issue(
    service: &mut Service,
    clock: RequestClock,
    namespace: &str,
    admin: &str,
    name: &str,
    ttl: u64,
) -> TestResult<String> {
    let response = request(
        service,
        clock,
        namespace,
        admin,
        "POST",
        &format!("auth/{name}/role/work/secret-id"),
        json!({"ttl":ttl}),
        None,
    );
    assert_eq!(response.status, 200);
    Ok(response.body["data"]["secret_id_accessor"]
        .as_str()
        .ok_or("actual accessor")?
        .into())
}
fn lookup(
    service: &mut Service,
    clock: RequestClock,
    namespace: &str,
    admin: &str,
    name: &str,
    accessor: &str,
) -> u16 {
    request(
        service,
        clock,
        namespace,
        admin,
        "POST",
        &format!("auth/{name}/role/work/secret-id-accessor/lookup"),
        json!({"secret_id_accessor":accessor}),
        None,
    )
    .status
}
fn tidy(
    service: &mut Service,
    clock: RequestClock,
    namespace: &str,
    actor: &str,
    name: &str,
    wrap: Option<u64>,
) -> Response {
    request(
        service,
        clock,
        namespace,
        actor,
        "POST",
        &format!("auth/{name}/tidy/secret-id"),
        json!({}),
        wrap,
    )
}
fn updater(service: &mut Service, clock: RequestClock, admin: &str) -> TestResult<String> {
    assert_eq!(
        request(
            service,
            clock,
            "",
            admin,
            "PUT",
            "sys/policies/acl/tidy-updater",
            json!({"policy":r#"path "auth/build/tidy/secret-id" { capabilities = ["update"] }"#}),
            None
        )
        .status,
        204
    );
    let response = request(
        service,
        clock,
        "",
        admin,
        "POST",
        "auth/token/create",
        json!({"policies":["tidy-updater"],"no_default_policy":true,"ttl":300}),
        None,
    );
    assert_eq!(response.status, 200);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("actual actor")?
        .into())
}
fn reserve_next_request_audit(service: &mut Service, now: u64, actor: &str) -> TestResult {
    let event = AuditUnsigned {
        schema: 2,
        sequence: service.audit_sequence + 1,
        previous: STANDARD.encode(service.audit_previous),
        time: now,
        kind: "request".into(),
        path_digest: service.request_fingerprint("POST", "auth/build/tidy/secret-id", "", actor),
        status: None,
    };
    let payload = serde_json::to_vec(&event)?;
    let mac = STANDARD.encode(hmac::sign(&service.audit_key, &payload).as_ref());
    let bytes = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
    service.audit_capacity = service.audit.metadata()?.len() + bytes as u64;
    Ok(())
}
#[test]
fn native_approle_tidy_ack_busy_update_actor_revoke_and_real_cleanup_reopen() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let initial = clock(100)?;
    mount(&mut service, initial, "", &admin, "build");
    mount(&mut service, initial, "", &admin, "deploy");
    let expired = issue(&mut service, initial, "", &admin, "build", 1)?;
    let active = issue(&mut service, initial, "", &admin, "build", 0)?;
    let other = issue(&mut service, initial, "", &admin, "deploy", 1)?;
    let actor = updater(&mut service, initial, &admin)?;
    let later = clock(200)?;
    assert_eq!(tidy(&mut service, later, "", "", "build", None).status, 403);
    let accepted = tidy(&mut service, later, "", &actor, "build", None);
    assert_eq!(accepted.status, 202);
    assert_eq!(accepted.body["warnings"], json!([STARTED]));
    assert_eq!(service.approle_tidy_jobs.len(), 1);
    assert_eq!(
        lookup(&mut service, later, "", &admin, "build", &expired),
        200
    );
    assert_eq!(
        request(
            &mut service,
            later,
            "",
            &admin,
            "POST",
            "sys/auth/build/tune",
            json!({"description":"same backend after tune"}),
            None
        )
        .status,
        204
    );
    // Mutable tuning keeps the same actual backend incarnation and shared CAS.
    let busy = tidy(&mut service, later, "", &actor, "build", None);
    assert_eq!(busy.status, 200);
    assert_eq!(busy.body["warnings"], json!([BUSY]));
    assert_eq!(service.approle_tidy_jobs.len(), 1);
    assert_eq!(
        request(
            &mut service,
            later,
            "",
            &admin,
            "POST",
            "auth/token/revoke",
            json!({"token":actor}),
            None
        )
        .status,
        204
    );
    // HTTP scopes above have ended and the original actor is revoked. The
    // accepted native task has no Caller and retains its own original clock.
    assert!(service.maintain_approle_tidies());
    assert!(service.approle_tidy_jobs.is_empty());
    assert_eq!(
        lookup(&mut service, later, "", &admin, "build", &expired),
        404
    );
    assert_eq!(
        lookup(&mut service, later, "", &admin, "build", &active),
        200
    );
    assert_eq!(
        lookup(&mut service, later, "", &admin, "deploy", &other),
        200
    );
    drop(service);
    let mut service = files.service()?;
    assert_eq!(
        request(
            &mut service,
            later,
            "",
            "",
            "POST",
            "sys/unseal",
            json!({"key":key}),
            None
        )
        .status,
        200
    );
    assert_eq!(
        lookup(&mut service, later, "", &admin, "build", &expired),
        404
    );
    assert_eq!(
        lookup(&mut service, later, "", &admin, "build", &active),
        200
    );
    assert!(service.approle_tidy_jobs.is_empty());
    Ok(())
}
#[test]
fn native_approle_tidy_wrapped_ack_retains_same_owned_task() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    mount(&mut service, clock(100)?, "", &admin, "build");
    let expired = issue(&mut service, clock(100)?, "", &admin, "build", 1)?;
    let accepted = tidy(&mut service, clock(200)?, "", &admin, "build", Some(30));
    assert_eq!(accepted.status, 200);
    let bearer = accepted.body["wrap_info"]["token"]
        .as_str()
        .ok_or("actual wrapping bearer")?;
    assert_eq!(service.approle_tidy_jobs.len(), 1);
    let unwrapped = request(
        &mut service,
        clock(200)?,
        "",
        &admin,
        "POST",
        "sys/wrapping/unwrap",
        json!({"token":bearer}),
        None,
    );
    assert_eq!(unwrapped.status, 200);
    assert_eq!(unwrapped.body["warnings"], json!([STARTED]));
    assert!(service.maintain_approle_tidies());
    assert_eq!(
        lookup(&mut service, clock(200)?, "", &admin, "build", &expired),
        404
    );
    Ok(())
}
#[test]
fn native_approle_tidy_response_audit_failure_never_activates_or_leaks_guard() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    mount(&mut service, clock(100)?, "", &admin, "build");
    let expired = issue(&mut service, clock(100)?, "", &admin, "build", 1)?;
    reserve_next_request_audit(&mut service, 200, &admin)?;
    assert_eq!(
        tidy(&mut service, clock(200)?, "", &admin, "build", None).status,
        503
    );
    assert!(service.recovery_required);
    assert!(service.approle_tidy_jobs.is_empty());
    assert!(service.pending_approle_tidy.is_none());
    assert!(
        service
            .approle_tidy_slots
            .values()
            .all(|slot| slot.busy.upgrade().is_none())
    );
    drop(service);
    let mut service = files.service()?;
    assert_eq!(
        request(
            &mut service,
            clock(200)?,
            "",
            "",
            "POST",
            "sys/unseal",
            json!({"key":key}),
            None
        )
        .status,
        200
    );
    assert_eq!(
        lookup(&mut service, clock(200)?, "", &admin, "build", &expired),
        200
    );
    assert_eq!(
        tidy(&mut service, clock(200)?, "", &admin, "build", None).status,
        202
    );
    assert!(service.maintain_approle_tidies());
    assert_eq!(
        lookup(&mut service, clock(200)?, "", &admin, "build", &expired),
        404
    );
    Ok(())
}
#[test]
fn native_approle_tidy_terminal_audit_failure_retains_actual_commit_without_completion()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    mount(&mut service, clock(100)?, "", &admin, "build");
    let expired = issue(&mut service, clock(100)?, "", &admin, "build", 1)?;
    assert_eq!(
        tidy(&mut service, clock(200)?, "", &admin, "build", None).status,
        202
    );
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let task = service.approle_tidy_jobs.front().ok_or("actual task")?;
    let event = AuditUnsigned {
        schema: 2,
        sequence: service.audit_sequence + 1,
        previous: STANDARD.encode(service.audit_previous),
        time: task.clock.observed_at()?.seconds(),
        kind: "approle-tidy-task-request".into(),
        path_digest: task.fingerprint.clone(),
        status: None,
    };
    let payload = serde_json::to_vec(&event)?;
    let mac = STANDARD.encode(hmac::sign(&service.audit_key, &payload).as_ref());
    let bytes = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
    service.audit_capacity = service.audit.metadata()?.len() + bytes as u64;
    assert!(service.maintain_approle_tidies());
    assert!(service.recovery_required && service.approle_tidy_jobs.is_empty());
    assert_ne!(
        service
            .current_state_identity()
            .map_err(|_| "committed identity")?,
        identity
    );
    assert!(service.durable.as_ref().ok_or("durable")?.generation() > generation);
    assert!(
        service
            .approle_tidy_slots
            .values()
            .all(|slot| slot.busy.upgrade().is_none())
    );
    drop(service);
    let mut service = files.service()?;
    assert_eq!(
        request(
            &mut service,
            clock(200)?,
            "",
            "",
            "POST",
            "sys/unseal",
            json!({"key":key}),
            None
        )
        .status,
        200
    );
    assert_eq!(
        lookup(&mut service, clock(200)?, "", &admin, "build", &expired),
        404
    );
    assert!(service.approle_tidy_jobs.is_empty());
    Ok(())
}
#[test]
fn native_approle_tidy_ack_veto_and_actual_mount_aba_release_only_owned_guard() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    mount(&mut service, clock(100)?, "", &admin, "build");
    let body = json!({});
    let clock = clock(200)?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(4),
    );
    let response = service.handle_inner(RequestView {
        method: "POST",
        path: "auth/build/tidy/secret-id",
        namespace: "",
        token: &admin,
        body: &body,
        now: 200,
        admission_started: Instant::now(),
        token_clock: Some(clock),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    });
    assert_eq!(response.status, 202);
    assert!(service.approle_tidy_jobs.is_empty());
    let original = service.unseal_nonce.clone();
    service.unseal_nonce.push_str("-changed");
    assert_eq!(
        service
            .complete_approle_tidy_delivery(true, response, "fixed-public-fingerprint")
            .status,
        503
    );
    service.unseal_nonce = original;
    assert!(service.approle_tidy_jobs.is_empty());
    assert_eq!(
        tidy(&mut service, clock, "", &admin, "build", None).status,
        202
    );
    assert_eq!(
        request(
            &mut service,
            clock,
            "",
            &admin,
            "DELETE",
            "sys/auth/build",
            json!({}),
            None
        )
        .status,
        204
    );
    mount(&mut service, clock, "", &admin, "build");
    let replacement = issue(&mut service, clock, "", &admin, "build", 1)?;
    let before = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert!(service.maintain_approle_tidies());
    assert!(service.approle_tidy_jobs.is_empty());
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        before
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        lookup(&mut service, clock, "", &admin, "build", &replacement),
        200
    );
    assert_eq!(
        tidy(&mut service, clock, "", &admin, "build", None).status,
        202
    );
    Ok(())
}
#[test]
fn native_approle_tidy_real_namespace_seal_vetoes_original_loaded_task() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        request(
            &mut service,
            clock(100)?,
            "",
            &admin,
            "POST",
            "sys/namespaces/team",
            json!({}),
            None
        )
        .status,
        200
    );
    mount(&mut service, clock(100)?, "team", &admin, "build");
    let _expired = issue(&mut service, clock(100)?, "team", &admin, "build", 1)?;
    assert_eq!(
        tidy(&mut service, clock(200)?, "team", &admin, "build", None).status,
        202
    );
    assert!(
        service.namespace_runtime.is_loaded("team")
            || service
                .state
                .as_ref()
                .ok_or("state")?
                .namespaces
                .inherited_owner("team")
                .is_none()
    );
    assert_eq!(
        request(
            &mut service,
            clock(200)?,
            "",
            &admin,
            "POST",
            "sys/namespaces/team/seal",
            json!({}),
            None
        )
        .status,
        204
    );
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert!(service.maintain_approle_tidies());
    assert!(service.approle_tidy_jobs.is_empty());
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
fn native_approle_tidy_worker_runs_with_lifecycle_zero_and_periodic_shares_actual_cas() -> TestResult
{
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    mount(&mut service, clock(100)?, "", &admin, "build");
    let expired = issue(&mut service, clock(100)?, "", &admin, "build", 1)?;
    assert_eq!(
        tidy(&mut service, clock(200)?, "", &admin, "build", None).status,
        202
    );
    assert_eq!(
        service
            .queue_periodic_approle_tidies(clock(200)?)
            .map_err(|_| "periodic admission")?,
        0
    );
    assert_eq!(service.approle_tidy_jobs.len(), 1);
    assert_eq!(PERIOD, Duration::from_secs(60));
    let shared = Arc::new(Mutex::new(service));
    assert!(crate::service::start_lifecycle_worker(&shared, Duration::ZERO)?.is_none());
    let worker = start_worker(&shared)?;
    let until = Instant::now() + Duration::from_secs(4);
    loop {
        let mut service = shared.lock().map_err(|_| "writer")?;
        if service.approle_tidy_jobs.is_empty() {
            assert_eq!(
                lookup(&mut service, clock(200)?, "", &admin, "build", &expired),
                404
            );
            break;
        }
        drop(service);
        assert!(
            Instant::now() < until,
            "actual owned background worker did not finish"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(worker);
    let mut service = shared.lock().map_err(|_| "writer")?;
    assert_eq!(
        service
            .queue_periodic_approle_tidies(clock(200)?)
            .map_err(|_| "fresh periodic admission")?,
        1
    );
    assert_eq!(
        tidy(&mut service, clock(200)?, "", &admin, "build", None).status,
        200
    );
    assert!(service.maintain_approle_tidies());
    Ok(())
}
#[test]
fn native_approle_tidy_real_two_batch_cleanup_keeps_original_clock_and_busy_guard() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    mount(&mut service, clock(100)?, "", &admin, "build");
    let initial = clock(100)?;
    for _ in 0..257 {
        let _ = issue(&mut service, initial, "", &admin, "build", 1)?;
    }
    let active = issue(&mut service, initial, "", &admin, "build", 0)?;
    assert_eq!(
        tidy(&mut service, clock(200)?, "", &admin, "build", None).status,
        202
    );
    let task = service.approle_tidy_jobs.front().ok_or("task")?;
    let started = task.clock.started();
    let deadline = task.admission_deadline;
    assert!(service.maintain_approle_tidies());
    let task = service.approle_tidy_jobs.front().ok_or("second batch")?;
    assert_eq!(task.checked, 256);
    assert!((255..=256).contains(&task.removed));
    assert_eq!(task.clock.started(), started);
    assert_eq!(task.admission_deadline, deadline);
    assert_eq!(
        tidy(&mut service, clock(200)?, "", &admin, "build", None).status,
        200
    );
    let mut task = service
        .approle_tidy_jobs
        .pop_front()
        .ok_or("actual final batch")?;
    assert!(
        task.step(&mut service)
            .map_err(|_| "actual final publication")?
    );
    assert_eq!(task.checked, 258);
    assert_eq!(task.removed, 257);
    assert_eq!(task.clock.started(), started);
    assert_eq!(task.admission_deadline, deadline);
    drop(task);
    assert!(service.approle_tidy_jobs.is_empty());
    assert!(
        service
            .approle_tidy_slots
            .values()
            .all(|slot| slot.busy.upgrade().is_none())
    );
    assert_eq!(
        lookup(&mut service, clock(200)?, "", &admin, "build", &active),
        200
    );
    Ok(())
}
#[test]
fn native_approle_tidy_expired_original_native_producer_cannot_reset_clock_or_queue() -> TestResult
{
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    mount(&mut service, clock(100)?, "", &admin, "build");
    let expired = issue(&mut service, clock(100)?, "", &admin, "build", 1)?;
    let started = Instant::now() - ADMISSION_BUDGET - Duration::from_secs(1);
    let old = RequestClock::anchored(Duration::new(100, 1), started)?;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert!(service.queue_periodic_approle_tidies(old).is_err());
    assert!(service.approle_tidy_jobs.is_empty());
    assert!(
        service
            .approle_tidy_slots
            .values()
            .all(|slot| slot.busy.upgrade().is_none())
    );
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        lookup(&mut service, clock(200)?, "", &admin, "build", &expired),
        200
    );
    assert_eq!(
        tidy(&mut service, clock(200)?, "", &admin, "build", None).status,
        202
    );
    Ok(())
}
#[test]
fn native_approle_tidy_actual_ha_term_change_after_stage_cannot_publish_cleanup() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    mount(&mut service, clock(100)?, "", &admin, "build");
    let expired = issue(&mut service, clock(100)?, "", &admin, "build", 1)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&files.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service.sync_from_ha().map_err(|_| "actual HA prefix")?;
    assert_eq!(
        tidy(&mut service, clock(200)?, "", &admin, "build", None).status,
        202
    );
    let expected = service
        .approle_tidy_jobs
        .front()
        .ok_or("captured task")?
        .role
        .ok_or("role")?;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let ran = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&ran);
    service.native_record_role_hook = Some(Box::new(move |process| {
        let successor = process.step_down();
        assert!(successor.is_ok(), "actual three-node leader handoff failed");
        observed.store(true, Ordering::Release);
    }));
    assert!(service.maintain_approle_tidies());
    assert!(
        ran.load(Ordering::Acquire),
        "actual post-Stage pre-Publish boundary not reached"
    );
    let role = cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .leader_status()?;
    assert!(!role.local_is_leader || (role.local_id, role.term) != expected);
    assert!(service.approle_tidy_jobs.is_empty());
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    // Staging/GC may already be replicated. This asserts no candidate root Publish.
    drop(service);
    let mut service = files.service()?;
    assert_eq!(
        request(
            &mut service,
            clock(200)?,
            "",
            "",
            "POST",
            "sys/unseal",
            json!({"key":key}),
            None
        )
        .status,
        200
    );
    assert_eq!(
        lookup(&mut service, clock(200)?, "", &admin, "build", &expired),
        200
    );
    Ok(())
}

#[test]
fn native_approle_tidy_original_http_deadline_expiry_does_not_cancel_accepted_task() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    mount(&mut service, clock(100)?, "", &admin, "build");
    let expired = issue(&mut service, clock(100)?, "", &admin, "build", 1)?;
    let started = Instant::now();
    let original_http_deadline = started + Duration::from_secs(1);
    let execution = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(original_http_deadline);
        service.begin_at_mode_precise(
            RequestDispatch {
                method: "POST",
                path: "auth/build/tidy/secret-id",
                namespace: "",
                token: &admin,
                body: json!({}),
                now: 200,
                allow_forward: true,
                enforce_namespace: true,
                wrap_ttl_seconds: None,
                origin_peer: None,
                client_certificates: None,
            },
            clock(200)?,
        )
    };
    let response = service.finish_synchronous_request(execution);
    assert_eq!(response.status, 202);
    let task = service
        .approle_tidy_jobs
        .front()
        .ok_or("actual accepted task")?;
    let native_admission_deadline = task.admission_deadline;
    assert!(native_admission_deadline > original_http_deadline);
    std::thread::sleep(
        original_http_deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
    );
    assert!(Instant::now() >= original_http_deadline && Instant::now() < native_admission_deadline);
    assert!(service.maintain_approle_tidies());
    assert!(service.approle_tidy_jobs.is_empty());
    assert_eq!(
        lookup(&mut service, clock(200)?, "", &admin, "build", &expired),
        404
    );
    Ok(())
}

#[test]
fn native_approle_tidy_same_path_two_namespaces_have_distinct_cas_and_actual_cleanup() -> TestResult
{
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let initial = clock(100)?;
    assert_eq!(
        request(
            &mut service,
            initial,
            "",
            &admin,
            "POST",
            "sys/namespaces/team",
            json!({}),
            None
        )
        .status,
        200
    );
    mount(&mut service, initial, "", &admin, "build");
    mount(&mut service, initial, "team", &admin, "build");
    let root_expired = issue(&mut service, initial, "", &admin, "build", 1)?;
    let team_expired = issue(&mut service, initial, "team", &admin, "build", 1)?;
    let team_active = issue(&mut service, initial, "team", &admin, "build", 0)?;
    let later = clock(200)?;
    assert_eq!(
        tidy(&mut service, later, "", &admin, "build", None).status,
        202
    );
    assert_eq!(
        tidy(&mut service, later, "team", &admin, "build", None).status,
        202
    );
    assert_eq!(service.approle_tidy_jobs.len(), 2);
    assert_eq!(
        tidy(&mut service, later, "team", &admin, "build", None).status,
        200
    );
    assert!(service.maintain_approle_tidies());
    assert_eq!(
        lookup(&mut service, later, "", &admin, "build", &root_expired),
        404
    );
    assert_eq!(
        lookup(&mut service, later, "team", &admin, "build", &team_expired),
        200
    );
    assert!(service.maintain_approle_tidies());
    assert_eq!(
        lookup(&mut service, later, "team", &admin, "build", &team_expired),
        404
    );
    assert_eq!(
        lookup(&mut service, later, "team", &admin, "build", &team_active),
        200
    );
    assert!(service.approle_tidy_jobs.is_empty());
    Ok(())
}

#[test]
fn native_approle_tidy_actual_accepted_owner_survives_original_sixty_seconds_without_clock_rearm()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    mount(&mut service, clock(100)?, "", &admin, "build");
    let expired = issue(&mut service, clock(100)?, "", &admin, "build", 1)?;
    let active = issue(&mut service, clock(100)?, "", &admin, "build", 0)?;
    assert_eq!(
        tidy(&mut service, clock(200)?, "", &admin, "build", None).status,
        202
    );
    let task = service
        .approle_tidy_jobs
        .front()
        .ok_or("actual accepted task")?;
    let original_started = task.clock.started();
    let original_admission_deadline = task.admission_deadline;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();

    // Age the real accepted clock. No test clock, deadline field or task owner
    // is rewritten to manufacture an old task.
    std::thread::sleep(
        original_admission_deadline.saturating_duration_since(Instant::now())
            + Duration::from_millis(20),
    );
    assert!(Instant::now() >= original_admission_deadline);
    assert_eq!(
        tidy(&mut service, clock(270)?, "", &admin, "build", None).status,
        200
    );
    assert_eq!(service.approle_tidy_jobs.len(), 1);
    let same = service
        .approle_tidy_jobs
        .front()
        .ok_or("same accepted task")?;
    assert_eq!(same.clock.started(), original_started);
    assert_eq!(same.admission_deadline, original_admission_deadline);
    assert_eq!(same.checked, 0);
    assert!(service.maintain_approle_tidies());
    assert!(service.approle_tidy_jobs.is_empty());
    assert!(service.current_state_identity().map_err(|_| "identity")? != identity);
    assert!(service.durable.as_ref().ok_or("durable")?.generation() > generation);
    assert_eq!(
        lookup(&mut service, clock(270)?, "", &admin, "build", &expired),
        404
    );
    assert_eq!(
        lookup(&mut service, clock(270)?, "", &admin, "build", &active),
        200
    );
    assert!(
        service
            .approle_tidy_slots
            .values()
            .all(|slot| slot.busy.upgrade().is_none())
    );
    Ok(())
}

#[test]
fn native_approle_tidy_expired_attempt_scope_cannot_extend_wait_or_publish_and_drops_only_owned_task()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    mount(&mut service, clock(100)?, "", &admin, "build");
    let expired = issue(&mut service, clock(100)?, "", &admin, "build", 1)?;
    assert_eq!(
        tidy(&mut service, clock(200)?, "", &admin, "build", None).status,
        202
    );
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let expired_attempt = Instant::now() - Duration::from_secs(1);
    {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(expired_attempt);
        assert_eq!(crate::request_deadline::current(), Some(expired_attempt));
        assert!(service.maintain_approle_tidies());
        assert_eq!(crate::request_deadline::current(), Some(expired_attempt));
    }
    assert!(service.approle_tidy_jobs.is_empty());
    assert!(service.pending_approle_tidy.is_none());
    assert!(
        service
            .approle_tidy_slots
            .values()
            .all(|slot| slot.busy.upgrade().is_none())
    );
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        lookup(&mut service, clock(270)?, "", &admin, "build", &expired),
        200
    );
    // The failed task was not re-armed. A distinct real foreground admission
    // after the prepublication veto is still permitted by the released CAS.
    assert_eq!(
        tidy(&mut service, clock(270)?, "", &admin, "build", None).status,
        202
    );
    assert!(service.maintain_approle_tidies());
    assert!(service.approle_tidy_jobs.is_empty());
    assert_eq!(
        lookup(&mut service, clock(270)?, "", &admin, "build", &expired),
        404
    );
    Ok(())
}
