use super::*;
use crate::service::tests::{Root, bootstrap, call};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn key(term: u64) -> ActivationKey {
    ActivationKey { local_id: 1, term }
}

#[test]
fn activation_requires_real_leader_role_as_well_as_remembered_local_leader_id() {
    let observation = LocalLeaderObservation {
        local_id: 1,
        term: 3,
        local_is_leader: true,
        leader: Some(1),
        committed_index: Some(10),
        applied_index: Some(10),
    };
    assert_eq!(ActivationKey::from_observation(observation), Some(key(3)));
    assert!(
        ActivationKey::from_observation(LocalLeaderObservation {
            local_is_leader: false,
            ..observation
        })
        .is_none()
    );
    assert!(
        ActivationKey::from_observation(LocalLeaderObservation {
            leader: Some(2),
            ..observation
        })
        .is_none()
    );
}

#[test]
fn publication_clock_runs_only_after_same_term_application_gate_and_is_stable() {
    let mut event = None;
    let invalid_clock_calls = std::cell::Cell::new(0);
    let first = UNIX_EPOCH + Duration::new(1_700_000_000, 120_000_000);
    publish(&mut event, Some(key(1)), Some(key(1)), false, || {
        invalid_clock_calls.set(invalid_clock_calls.get() + 1);
        UNIX_EPOCH
    });
    assert!(event.is_none());
    publish(&mut event, Some(key(1)), Some(key(2)), true, || {
        invalid_clock_calls.set(invalid_clock_calls.get() + 1);
        UNIX_EPOCH
    });
    assert!(event.is_none());
    publish(&mut event, None, Some(key(1)), true, || {
        invalid_clock_calls.set(invalid_clock_calls.get() + 1);
        UNIX_EPOCH
    });
    assert!(event.is_none());
    publish(&mut event, Some(key(1)), Some(key(1)), true, || first);
    assert_eq!(
        event.as_ref().and_then(|event| event.active_time(key(1))),
        Some("2023-11-14T22:13:20.12Z")
    );
    publish(&mut event, Some(key(1)), Some(key(1)), true, || {
        invalid_clock_calls.set(invalid_clock_calls.get() + 1);
        UNIX_EPOCH
    });
    assert_eq!(
        event.as_ref().and_then(|event| event.active_time(key(1))),
        Some("2023-11-14T22:13:20.12Z")
    );
    publish(&mut event, Some(key(2)), Some(key(2)), true, || {
        first + Duration::from_secs(1)
    });
    assert_eq!(
        event.as_ref().and_then(|event| event.active_time(key(2))),
        Some("2023-11-14T22:13:21.12Z")
    );
    assert!(
        event
            .as_ref()
            .and_then(|event| event.active_time(key(1)))
            .is_none()
    );
    publish(&mut event, Some(key(2)), None, true, || {
        invalid_clock_calls.set(invalid_clock_calls.get() + 1);
        UNIX_EPOCH
    });
    assert!(event.is_none());
    assert_eq!(invalid_clock_calls.get(), 0);
}

#[test]
fn invalid_clock_preserves_event_without_inventing_or_retiming_timestamp() {
    let mut event = None;
    let invalid_clock_calls = std::cell::Cell::new(0);
    publish(&mut event, Some(key(1)), Some(key(1)), true, || {
        UNIX_EPOCH - Duration::from_secs(1)
    });
    assert!(event.as_ref().is_some_and(|event| event.matches(key(1))));
    assert!(
        event
            .as_ref()
            .and_then(|event| event.active_time(key(1)))
            .is_none()
    );
    publish(&mut event, Some(key(1)), Some(key(1)), true, || {
        invalid_clock_calls.set(invalid_clock_calls.get() + 1);
        UNIX_EPOCH
    });
    assert_eq!(invalid_clock_calls.get(), 0);
    assert!(activation_time(UNIX_EPOCH + Duration::from_secs(253_402_300_800)).is_none());
    assert_eq!(
        activation_time(UNIX_EPOCH),
        Some("1970-01-01T00:00:00Z".into())
    );
}

fn diagnostic(service: &mut Service) -> Response {
    call(service, "GET", "sys/leader", "", json!({}))
}

#[test]
fn real_gate_activation_is_stable_and_invalidated_by_seal_fence_handoff_and_restart() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal_key, token) = bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    // Passive diagnosis cannot bootstrap an anchor, perform ReadIndex or clock an election.
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let audit = fs::read(root.path.join("audit.jsonl"))?;
    assert!(diagnostic(&mut service).body.get("active_time").is_none());
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(fs::read(root.path.join("audit.jsonl"))?, audit);
    service.sync_from_ha().map_err(|_| "initial sync")?;
    let first = diagnostic(&mut service).body["active_time"]
        .as_str()
        .ok_or("activation missing")?
        .to_owned();
    assert!(
        !first.starts_with("1970-01-01"),
        "caller request time must not become activation"
    );
    for _ in 0..3 {
        assert_eq!(diagnostic(&mut service).body["active_time"], first);
    }
    service.sync_from_ha().map_err(|_| "repeat sync")?;
    assert_eq!(diagnostic(&mut service).body["active_time"], first);
    service.recovery_required = true;
    assert!(diagnostic(&mut service).body.get("active_time").is_none());
    service.recovery_required = false;
    assert!(diagnostic(&mut service).body.get("active_time").is_none());
    service.sync_from_ha().map_err(|_| "recovery sync")?;
    let recovered = diagnostic(&mut service).body["active_time"]
        .as_str()
        .ok_or("recovery activation")?
        .to_owned();
    assert_ne!(first, recovered);
    service.audit_failed = true;
    assert!(diagnostic(&mut service).body.get("active_time").is_none());
    service.audit_failed = false;
    service.sync_from_ha().map_err(|_| "audit recovery sync")?;
    assert_eq!(
        call(&mut service, "POST", "sys/seal", &token, json!({})).status,
        204
    );
    assert!(service.ha_activation.is_none());
    assert_eq!(diagnostic(&mut service).status, 503);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal_key})
        )
        .status,
        200
    );
    let reunsealed = diagnostic(&mut service).body["active_time"]
        .as_str()
        .ok_or("unseal activation")?
        .to_owned();
    assert_ne!(recovered, reunsealed);
    let old_term = service.local_activation_key().ok_or("old key")?.term;
    let successor = cluster.processes[0].lock().map_err(|_| "HA")?.step_down()?;
    assert!(diagnostic(&mut service).body.get("active_time").is_none());
    service.ha = Some(Arc::clone(&cluster.processes[(successor - 1) as usize]));
    assert!(diagnostic(&mut service).body.get("active_time").is_none());
    service.sync_from_ha().map_err(|_| "successor sync")?;
    let after = service.local_activation_key().ok_or("successor key")?;
    assert!(after.term > old_term);
    assert!(diagnostic(&mut service).body.get("active_time").is_some());
    // A process restart creates no event from persisted state or Raft metrics.
    drop(service);
    let mut restarted = root.service()?;
    restarted.ha = Some(Arc::clone(&cluster.processes[(successor - 1) as usize]));
    assert!(restarted.ha_activation.is_none());
    assert_eq!(diagnostic(&mut restarted).status, 503);
    Ok(())
}

#[test]
fn idle_worker_activates_without_diagnostic_requests_and_stops_on_drop() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, _) = bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service.sync_from_ha().map_err(|_| "initial anchor")?;
    service.ha_activation = None;
    let service = Arc::new(Mutex::new(service));
    assert!(crate::service::lifecycle::start_lifecycle_worker(&service, Duration::ZERO)?.is_none());
    let worker = start_ha_activation_worker(&service)?.ok_or("worker missing")?;
    let end = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if service
            .lock()
            .map_err(|_| "writer")?
            .ha_activation
            .is_some()
        {
            break;
        }
        if std::time::Instant::now() >= end {
            return Err("idle activation missing".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(worker);
    {
        let mut writer = service.lock().map_err(|_| "writer")?;
        writer.ha_activation = None;
    }
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        service
            .lock()
            .map_err(|_| "writer")?
            .ha_activation
            .is_none()
    );
    Ok(())
}

#[test]
fn idle_activation_quorum_loss_keeps_existing_one_second_read_budget() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service.sync_from_ha().map_err(|_| "initial anchor")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    service.ha_activation = None;
    let service = Arc::new(Mutex::new(service));
    cluster.isolate_all_peers(true);
    let worker = start_ha_activation_worker(&service)?.ok_or("worker missing")?;
    let began = std::time::Instant::now();
    let entered = loop {
        if service.try_lock().is_err() {
            break true;
        }
        if began.elapsed() >= Duration::from_secs(3) {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let acquired = crate::request_deadline::lock_until(
        &service,
        std::time::Instant::now() + Duration::from_secs(2),
    )
    .is_ok();
    cluster.isolate_all_peers(false);
    drop(worker);
    assert!(entered, "real activation ReadIndex must have run");
    assert!(
        acquired,
        "activation must release the writer within its read budget"
    );
    assert_eq!(
        service
            .lock()
            .map_err(|_| "writer")?
            .durable
            .as_ref()
            .ok_or("durable")?
            .generation(),
        generation
    );
    Ok(())
}

#[test]
fn health_role_gate_rejects_real_handoff_between_role_and_readindex() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let _ = bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service.sync_from_ha().map_err(|_| "initial sync")?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        std::time::Instant::now() + Duration::from_secs(10),
    );
    let initial = service.ha_observation();
    assert!(initial.2 && initial.3);
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let audit = fs::read(root.path.join("audit.jsonl"))?;
    let transferred = std::cell::RefCell::new(None);
    let observed = service.ha_observation_with(|process| {
        // This is the same actual process whose original role was just sampled.
        // A real RPC transfer happens before its original ReadIndex operation.
        transferred.replace(Some(process.step_down()));
    });
    let next = transferred
        .into_inner()
        .ok_or("handoff hook was not entered")?
        .map_err(|_| "actual handoff failed")?;
    assert_ne!(next, 1);
    assert!(observed.1, "the terminal role must project actual standby");
    assert!(
        !observed.2 && !observed.3,
        "old local role cannot carry ReadIndex success"
    );
    assert_eq!(observed.4, Some(next));
    assert_eq!(observed.5, Some(1));
    assert!(service.ha_activation.is_none());
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "final identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(fs::read(root.path.join("audit.jsonl"))?, audit);
    Ok(())
}

#[test]
fn health_role_gate_rejects_real_return_to_same_node_in_a_new_term() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let _ = bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service.sync_from_ha().map_err(|_| "initial sync")?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        std::time::Instant::now() + Duration::from_secs(10),
    );
    assert!(service.ha_observation().3);
    let original_term = service.local_activation_key().ok_or("initial role")?.term;
    let transfers = std::cell::RefCell::new(None);
    let observed = service.ha_observation_with(|process| {
        let actual = (|| -> Result<u64, String> {
            let next = process.step_down()?;
            let successor = cluster.processes[(next - 1) as usize]
                .lock()
                .map_err(|_| "successor process lock")?;
            successor.step_down()
        })();
        transfers.replace(Some(actual));
    });
    let returned = transfers
        .into_inner()
        .ok_or("two actual handoffs were not entered")?
        .map_err(|_| "actual return handoff failed")?;
    assert_eq!(returned, 1);
    assert_eq!(observed.4, Some(1));
    assert!(!observed.1);
    assert!(
        !observed.2 && !observed.3,
        "same node in a new term needs a fresh gate"
    );
    assert!(service.ha_activation.is_none());
    let current_term = service.local_activation_key().ok_or("returned role")?.term;
    assert!(current_term > original_term);
    // A new independent probe observes the current role and completes its own gates.
    let fresh = service.ha_observation();
    assert!(fresh.2 && fresh.3);
    assert!(service.ha_activation.is_some());
    Ok(())
}
