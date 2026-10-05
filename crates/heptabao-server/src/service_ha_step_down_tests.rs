//! Real loopback Raft handoff under the original Service admission and clock.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type TestCluster = (
    Service,
    crate::ha::snapshot_test_support::Cluster,
    String,
    String,
);

fn clock() -> TestResult<RequestClock> {
    Ok(RequestClock::anchored(
        Duration::new(100, 200_000_000),
        Instant::now(),
    )?)
}

fn precise(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> TestResult<Response> {
    let request = service.begin_at_mode_precise(
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
    Ok(service.finish_synchronous_request(request))
}

fn cluster(root: &Root) -> TestResult<TestCluster> {
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/step-down-test",
            &token,
            json!({"policy":r#"path "sys/step-down" { capabilities=["update","sudo"] }"#}),
        )
        .status,
        204
    );
    let id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service.sync_from_ha().map_err(|_| "initial HA state")?;
    Ok((service, cluster, key, token))
}

fn issue(
    service: &mut Service,
    root: &str,
    ttl: &str,
    requested_uses: u64,
) -> TestResult<(String, String)> {
    let response = precise(
        service,
        "POST",
        "auth/token/create",
        root,
        json!({"ttl":ttl,"num_uses":requested_uses,"policies":["step-down-test"],"no_default_policy":true}),
    )?;
    assert_eq!(response.status, 200, "{}", response.body);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .has_token_api_precision_state()
    );
    let actor = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    let accessor = response.body["auth"]["accessor"]
        .as_str()
        .ok_or("accessor")?
        .to_owned();
    assert_eq!(uses(service, &accessor)?, Some(requested_uses));
    Ok((actor, accessor))
}

fn uses(service: &Service, accessor: &str) -> TestResult<Option<u64>> {
    let auth = serde_json::to_value(&service.state.as_ref().ok_or("state")?.auth)?;
    Ok(auth["tokens"]
        .as_object()
        .ok_or("tokens")?
        .values()
        .find(|token| token["accessor"] == accessor)
        .and_then(|token| token["uses_remaining"].as_u64()))
}

fn floor(service: &Service) -> TestResult<Value> {
    Ok(serde_json::to_value(&service.state.as_ref().ok_or("state")?.auth)?["token_api_observed_at"].clone())
}

fn admitted(
    service: &mut Service,
    actor: &str,
) -> TestResult<(StepDownPlan, Response, RequestClock)> {
    let clock = clock()?;
    let body = json!({});
    let response = service.handle_inner(RequestView {
        method: "POST",
        path: "sys/step-down",
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
    });
    assert_eq!(response.status, 204, "{}", response.body);
    Ok((
        service
            .pending_ha_step_down
            .take()
            .ok_or("original capsule")?,
        response,
        clock,
    ))
}

#[test]
fn precise_step_down_commits_floor_before_real_transfer_and_retains_final_use() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, key, root) = cluster(&files)?;
    assert_eq!(
        precise(
            &mut service,
            "PUT",
            "secret/data/handoff",
            &root,
            json!({"data":{"value":"retained"}})
        )?
        .status,
        200
    );
    let (actor, accessor) = issue(&mut service, &root, "10m", 1)?;
    let response = precise(&mut service, "POST", "sys/step-down", &actor, json!({}))?;
    assert_eq!(response.status, 204, "{}", response.body);
    assert_eq!(response.body, Value::Null);
    assert!(response.consistency_index.is_none());
    assert_eq!(
        uses(&service, &accessor)?,
        Some(0),
        "final use must remain exhausted"
    );
    let saved_floor = floor(&service)?;
    assert!(saved_floor.is_object());
    let successor = cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .leader()?
        .ok_or("leader")?;
    assert_ne!(successor, 1);
    service.ha = Some(Arc::clone(&cluster.processes[(successor - 1) as usize]));
    let repeated = precise(&mut service, "POST", "sys/step-down", &actor, json!({}))?;
    assert_eq!(repeated.status, 403, "{}", repeated.body);
    assert_eq!(uses(&service, &accessor)?, Some(0));
    assert_eq!(
        cluster.processes[(successor - 1) as usize]
            .lock()
            .map_err(|_| "HA")?
            .leader()?,
        Some(successor),
        "an exhausted actor cannot initiate another handoff"
    );
    let response = precise(&mut service, "GET", "secret/data/handoff", &root, json!({}))?;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body["data"]["data"]["value"], "retained");
    let durable_floor = floor(&service)?;
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(
        precise(&mut reopened, "POST", "sys/unseal", "", json!({"key":key}))?.status,
        200
    );
    assert_eq!(floor(&reopened)?, durable_floor);
    assert_eq!(uses(&reopened, &accessor)?, Some(0));
    let repeated = precise(&mut reopened, "POST", "sys/step-down", &actor, json!({}))?;
    assert_eq!(repeated.status, 403, "{}", repeated.body);
    assert_eq!(uses(&reopened, &accessor)?, Some(0));
    println!(
        "STEP_DOWN_REAL transfer=true empty204=true final_use_consumed=true durable_precise_floor=true successor_secret=true exhausted_readmission403=true reopened_readmission403=true"
    );
    Ok(())
}

#[test]
fn precise_step_down_response_audit_failure_does_not_transfer_or_refund() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, _, root) = cluster(&files)?;
    let (actor, accessor) = issue(&mut service, &root, "10m", 2)?;
    let (plan, response, clock) = admitted(&mut service, &actor)?;
    assert_eq!(uses(&service, &accessor)?, Some(1));
    let fingerprint = service.request_fingerprint("POST", "sys/step-down", "", &actor);
    service.audit_capacity = 0;
    let response = service.audit_completed_response(&fingerprint, 100, Some(clock), response);
    assert_eq!(response.status, 503);
    let response = service.complete_ha_step_down(true, Some(plan), response, &fingerprint);
    assert_eq!(response.status, 503);
    assert!(service.recovery_required);
    assert_eq!(
        cluster.processes[0].lock().map_err(|_| "HA")?.leader()?,
        Some(1)
    );
    assert_eq!(uses(&service, &accessor)?, Some(1));
    assert!(floor(&service)?.is_object());
    println!(
        "STEP_DOWN_REAL response_audit_failure=true transfer=false consumed_use_not_refunded=true committed_floor_retained=true"
    );
    Ok(())
}

#[test]
fn precise_step_down_actor_expired_during_response_audit_does_not_transfer() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, _, root) = cluster(&files)?;
    let (actor, accessor) = issue(&mut service, &root, "1s", 2)?;
    let (plan, response, clock) = admitted(&mut service, &actor)?;
    assert_eq!(uses(&service, &accessor)?, Some(1));
    let fingerprint = service.request_fingerprint("POST", "sys/step-down", "", &actor);
    let response = service.audit_completed_response_with_receipt(
        &fingerprint,
        100,
        Some(clock),
        response,
        || {
            std::thread::sleep(Duration::from_millis(1100));
        },
    );
    assert_eq!(response.status, 204);
    let response = service.complete_ha_step_down(true, Some(plan), response, &fingerprint);
    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(
        cluster.processes[0].lock().map_err(|_| "HA")?.leader()?,
        Some(1)
    );
    assert_eq!(uses(&service, &accessor)?, Some(1));
    let audit = fs::read_to_string(files.path.join("audit.jsonl"))?;
    let last: Value = serde_json::from_str(audit.lines().last().ok_or("audit")?)?;
    assert_eq!(last["event"]["kind"], "ha-step-down-veto");
    assert_eq!(last["event"]["status"], 403);
    println!(
        "STEP_DOWN_REAL actual_audit_delay_ms=1100 actor_expired=true transfer=false consumed_use_not_refunded=true"
    );
    Ok(())
}

#[test]
fn precise_step_down_original_deadline_elapsed_during_audit_does_not_transfer() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, _, root) = cluster(&files)?;
    let (actor, accessor) = issue(&mut service, &root, "10m", 2)?;
    let _original = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(1),
    );
    let (plan, response, clock) = admitted(&mut service, &actor)?;
    assert_eq!(uses(&service, &accessor)?, Some(1));
    let fingerprint = service.request_fingerprint("POST", "sys/step-down", "", &actor);
    let response = service.audit_completed_response_with_receipt(
        &fingerprint,
        100,
        Some(clock),
        response,
        || {
            std::thread::sleep(Duration::from_millis(1100));
        },
    );
    assert_eq!(response.status, 204);
    let response = service.complete_ha_step_down(true, Some(plan), response, &fingerprint);
    assert_eq!(response.status, 503, "{}", response.body);
    assert_eq!(
        cluster.processes[0].lock().map_err(|_| "HA")?.leader()?,
        Some(1)
    );
    assert_eq!(uses(&service, &accessor)?, Some(1));
    println!(
        "STEP_DOWN_REAL actual_original_budget_ms=1000 actual_audit_delay_ms=1100 original_deadline_expired=true transfer=false consumed_use_not_refunded=true"
    );
    Ok(())
}

#[test]
fn precise_step_down_actor_expired_after_real_transfer_withholds_success() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, _, root) = cluster(&files)?;
    let (actor, accessor) = issue(&mut service, &root, "1s", 2)?;
    let (plan, response, clock) = admitted(&mut service, &actor)?;
    assert_eq!(uses(&service, &accessor)?, Some(1));
    let fingerprint = service.request_fingerprint("POST", "sys/step-down", "", &actor);
    let response = service.audit_completed_response(&fingerprint, 100, Some(clock), response);
    assert_eq!(response.status, 204);
    let response =
        service.complete_ha_step_down_observed(true, Some(plan), response, &fingerprint, || {
            std::thread::sleep(Duration::from_millis(1100))
        });
    assert_eq!(response.status, 403, "{}", response.body);
    assert_ne!(
        cluster.processes[0].lock().map_err(|_| "HA")?.leader()?,
        Some(1),
        "the rejected response must not undo an actual transfer"
    );
    assert!(service.ha_activation.is_none());
    assert_eq!(uses(&service, &accessor)?, Some(1));
    let audit = fs::read_to_string(files.path.join("audit.jsonl"))?;
    let last: Value = serde_json::from_str(audit.lines().last().ok_or("audit")?)?;
    assert_eq!(last["event"]["kind"], "ha-step-down-veto");
    assert_eq!(last["event"]["status"], 403);
    println!(
        "STEP_DOWN_REAL transfer=true after_transfer_delay_ms=1100 actor_expired=true success_withheld=true stale_activation_cleared=true consumed_use_not_refunded=true"
    );
    Ok(())
}

#[test]
fn precise_step_down_original_deadline_elapsed_after_real_transfer_withholds_success() -> TestResult
{
    let files = Root::new();
    let (mut service, cluster, _, root) = cluster(&files)?;
    let (actor, accessor) = issue(&mut service, &root, "10m", 2)?;
    let original_started = Instant::now();
    let _original = crate::request_deadline::RequestDeadlineScope::enter(
        original_started + Duration::from_secs(1),
    );
    let hook_entered = std::cell::Cell::new(false);
    let hook_entry_leader = std::cell::Cell::new(None);
    let (plan, response, clock) = admitted(&mut service, &actor)?;
    assert_eq!(uses(&service, &accessor)?, Some(1));
    let fingerprint = service.request_fingerprint("POST", "sys/step-down", "", &actor);
    let response = service.audit_completed_response(&fingerprint, 100, Some(clock), response);
    assert_eq!(response.status, 204);
    println!(
        "STEP_DOWN_OBSERVER before_complete_elapsed_ms={}",
        original_started.elapsed().as_millis()
    );
    let response =
        service.complete_ha_step_down_observed(true, Some(plan), response, &fingerprint, || {
            hook_entered.set(true);
            let leader = cluster.processes[0]
                .lock()
                .ok()
                .and_then(|process| process.leader().ok())
                .flatten();
            hook_entry_leader.set(leader);
            println!(
                "STEP_DOWN_OBSERVER hook_entered=true entry_leader={leader:?} entry_elapsed_ms={}",
                original_started.elapsed().as_millis()
            );
            std::thread::sleep(Duration::from_millis(1100))
        });
    let terminal_leader = cluster.processes[0]
        .lock()
        .ok()
        .and_then(|process| process.leader().ok())
        .flatten();
    println!(
        "STEP_DOWN_OBSERVER hook_entered={} hook_entry_leader={:?} terminal_leader={terminal_leader:?} terminal_elapsed_ms={} response_status={}",
        hook_entered.get(),
        hook_entry_leader.get(),
        original_started.elapsed().as_millis(),
        response.status
    );
    assert_eq!(response.status, 503, "{}", response.body);
    assert_ne!(
        cluster.processes[0].lock().map_err(|_| "HA")?.leader()?,
        Some(1),
        "the rejected response must not undo an actual transfer"
    );
    assert!(service.ha_activation.is_none());
    assert_eq!(uses(&service, &accessor)?, Some(1));
    let audit = fs::read_to_string(files.path.join("audit.jsonl"))?;
    let last: Value = serde_json::from_str(audit.lines().last().ok_or("audit")?)?;
    assert_eq!(last["event"]["kind"], "ha-step-down-veto");
    assert_eq!(last["event"]["status"], 503);
    println!(
        "STEP_DOWN_REAL transfer=true original_budget_ms=1000 after_transfer_delay_ms=1100 original_deadline_expired=true success_withheld=true stale_activation_cleared=true consumed_use_not_refunded=true"
    );
    Ok(())
}
