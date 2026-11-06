//! Real Service restore, real three-node mTLS, actual quorum epoch and cold reopen.
//! These four gates are separate from the23 lower-level snapshot components.
//! Fault injection changes only activation nonce and the existing audit I/O cap;
//! it never creates a completion, publication receipt, root or replay epoch.
use super::*;
use crate::service::snapshot_transfer::forward::{SnapshotForwardPlan, test_faults};
use std::sync::atomic::{AtomicUsize, Ordering};

fn register_snapshot_handlers(
    pipeline: &Pipeline, forged_leader: Option<usize>,
) -> TestResult<Vec<Arc<AtomicUsize>>> {
    let mut counts = Vec::new();
    for index in 0..3 {
        let service = pipeline.services[index].as_ref().ok_or("snapshot fixture Service")?;
        let weak = Arc::downgrade(service);
        let count = Arc::new(AtomicUsize::new(0));
        counts.push(Arc::clone(&count));
        pipeline.processes[index].as_ref().ok_or("snapshot fixture process")?
            .lock_for_request().map_err(|_| "snapshot fixture handler lock")?
            .register_snapshot_forward_handler(Arc::new(move |ingress| {
                count.fetch_add(1, Ordering::SeqCst);
                if forged_leader == Some(index) {
                    return test_faults::reject_unverified_root_fields(ingress);
                }
                let service = weak.upgrade()
                    .ok_or(heptabao_ha_service::HaError::Transport)?;
                Service::serve_native_snapshot_peer(&service, ingress, REQUEST_BUDGET)
            }))?;
    }
    Ok(counts)
}

fn count_calls(counts: &[Arc<AtomicUsize>]) -> usize {
    counts.iter().map(|count| count.load(Ordering::SeqCst)).sum()
}

fn prepare_archive(
    pipeline: &Pipeline, leader: usize,
) -> TestResult<(StateIdentity, Zeroizing<Vec<u8>>)> {
    let migration_source = activate(pipeline, leader)?;
    expect(pipeline.call(
        leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":1},"data":{"value":"forward-archive-A"}}),
    )?, 200, "forward-audit-archive-A")?;
    let archive = Zeroizing::new(export(pipeline, leader, pipeline.admin())?);
    expect(pipeline.call(
        leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":2},"data":{"value":"forward-later-B"}}),
    )?, 200, "forward-audit-later-B")?;
    for index in 0..3 {
        pipeline.assert_history(index, &[
            (1, "seed-v5"), (2, "forward-archive-A"), (3, "forward-later-B"),
        ])?;
        pipeline.with_service(index, |service| {
            assert!(service.native_root.is_some());
            assert!(service.native_candidate_profile.is_none());
            assert!(!service.recovery_required);
            Ok(())
        })?;
    }
    Ok((migration_source, archive))
}

fn finite_original_token(pipeline: &Pipeline, leader: usize) -> TestResult<Zeroizing<String>> {
    // Created AFTER the archive. The restored Auth graph does not contain it.
    // One final use is enough only if the original Actor is retained; a second
    // authentication or validation against restored Auth must not pass.
    let mut response = expect(pipeline.call(
        leader, "POST", "auth/token/create", pipeline.admin(),
        json!({"policies":["root"],"ttl":"60s","num_uses":1,
            "no_default_policy":true,"no_parent":true}),
    )?, 200, "forward-audit-one-use-original-token")?;
    assert_eq!(response.body["auth"]["num_uses"], 1);
    secret_field(&mut response, "/auth/client_token")
}

fn admit_forward(
    service: &mut Service, token: &str, until: Instant,
) -> TestResult<Box<SnapshotForwardPlan>> {
    match service.begin_native_snapshot_before(
        ServiceRequest::new("POST", SNAPSHOT, "", token, json!({})), until,
    ) {
        NativeSnapshotAdmission::Forward(plan) => Ok(plan),
        NativeSnapshotAdmission::Execute(_) => Err("standby snapshot did not select forwarding".into()),
        NativeSnapshotAdmission::Redirect(_) => Err("standby snapshot used legacy redirect".into()),
    }
}

fn assert_private_lease_released(pipeline: &Pipeline, index: usize) -> TestResult {
    pipeline.with_service(index, |service| {
        let spool = service.snapshot_spool.as_ref().ok_or("actual private snapshot spool")?;
        // The real spool's exclusive transfer lease is available only after
        // every actual plan and private file from the completed request drops.
        let lease = spool.lease()?;
        drop(lease);
        assert!(service.pending_snapshot_transfer.is_none());
        assert!(service.native_request_binding.is_none());
        Ok(())
    })
}

fn run_published_audit_veto(point: test_faults::Point) -> TestResult {
    let mut pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let (migration_source, archive) = prepare_archive(&pipeline, leader)?;
    let token = finite_original_token(&pipeline, leader)?;
    assert_eq!(pipeline.ready_leader()?, leader);
    let ingress = (leader + 1) % 3;
    let counts = register_snapshot_handlers(&pipeline, None)?;
    let before = selection(&pipeline, leader, migration_source)?;
    assert_eq!(before.0, 0);
    assert!(before.1.epoch_transitions().is_empty());
    let fault_node = if point == test_faults::Point::SourceAfterFinalizer { leader } else { ingress };

    let began = Instant::now();
    let until = began + REQUEST_BUDGET;
    let scope = RequestDeadlineScope::enter(until);
    let service = Arc::clone(pipeline.services[ingress].as_ref().ok_or("forward ingress Service")?);
    let mut writer = lock_until(&service, until).map_err(|_| "forward original admission lock")?;
    let plan = admit_forward(&mut writer, &token, until)?;
    let (nonce, original_peer_deadline) = plan.fixture_request_context();
    assert!(original_peer_deadline <= until);
    drop(writer);
    {
        let target = pipeline.services[fault_node].as_ref().ok_or("forward fault Service")?;
        let mut target = lock_until(target, until).map_err(|_| "forward one-shot fault arm lock")?;
        target.snapshot_forward_test.arm(point, nonce)?;
    }
    // Exactly one real exchange, with the original plan and original archive.
    let (denied, private_output) = plan.execute(&service, &mut &archive[..]).into_parts();
    assert!(private_output.is_none());
    assert_eq!(denied.status, 503);
    assert_eq!(denied.body["outcome_unknown"], true);
    assert_eq!(denied.body["retry_allowed"], false);
    assert_eq!(denied.body["root_attempted"], true);
    assert!(denied.body.get("data").is_none());
    assert!(denied.unwrapped_json.is_none());
    assert!(denied.consistency_index.is_none());
    assert!(denied.response_headers.is_empty());
    assert!(denied.body.get("wrap_info").is_none());
    let reference = denied.body["recovery_reference"].as_str()
        .ok_or("real committed restore recovery reference")?.to_owned();
    assert_ne!(reference, "native-v6-restore-forged-untrusted-fixture");
    assert!(Instant::now() < until, "original15 second request bound");
    assert_eq!(count_calls(&counts), 1);
    assert_eq!(counts[leader].load(Ordering::SeqCst), 1);
    let observation = {
        let target = pipeline.services[fault_node].as_ref().ok_or("faulted Service")?;
        let target = lock_until(target, until).map_err(|_| "fault observation lock")?;
        let observed = target.snapshot_forward_test.observed().ok_or("fault boundary not reached")?;
        assert_eq!(target.snapshot_forward_test.hits(), 1);
        assert!(!target.snapshot_forward_test.pending());
        assert!(observed.injected);
        assert_eq!(observed.point, point);
        assert_eq!(observed.nonce, nonce);
        assert!(observed.deadline <= until);
        if point != test_faults::Point::SourceAfterFinalizer {
            assert_eq!(observed.deadline, original_peer_deadline);
        }
        assert_eq!(observed.original_epoch, 0);
        assert_eq!(observed.installed_epoch, Some(1));
        assert!(observed.installed_identity.is_some());
        assert!(observed.installed_auth.is_some());
        assert_ne!(observed.installed_auth, Some(observed.original_auth));
        assert_eq!(target.audit_sequence, observed.audit_sequence);
        assert_eq!(target.audit.metadata()?.len(), observed.audit_bytes.ok_or("actual audit metadata")?);
        assert!(target.recovery_required);
        assert!(target.ha_activation.is_none());
        assert!(target.native_request_binding.is_none());
        assert_eq!(target.state.as_ref().ok_or("faulted State")?.replay_epoch, 1);
        observed.clone()
    };
    drop(service);
    drop(scope);
    assert_private_lease_released(&pipeline, ingress)?;
    assert_private_lease_released(&pipeline, leader)?;

    // Read the actual quorum-selected transition. Finite-use admission can
    // advance the source root, so compare with actual admitted identity from
    // the authenticated path, not a stale root sampled before admission.
    let committed = selection(&pipeline, leader, migration_source)?;
    assert_eq!(committed.0, 1);
    assert_eq!(committed.1.epoch_transitions().len(), 1);
    let transition = committed.1.epoch_transitions().last().ok_or("actual restore transition")?;
    assert_eq!(transition.source_root_digest(), observation.original_identity.digest());
    assert_eq!(transition.source_enrollment().epoch(), 0);
    assert_eq!(transition.target_enrollment().epoch(), 1);
    assert_eq!(transition.operation_digest(), committed.1.intent().operation_digest);
    let operation = transition.operation_digest();
    let expected_reference = format!(
        "native-v6-restore-{}",
        operation.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    );
    assert_eq!(reference, expected_reference);
    assert_ne!(committed.1.root_digest(), observation.original_identity.digest());

    // Drop/reopen the actual faulted Service and Raft owner, without resubmitting
    // an archive or reseeding its files. This is not a physical SIGKILL claim.
    pipeline.stop_process(fault_node)?;
    let successor = pipeline.ready_leader()?;
    if fault_node == leader {
        assert_ne!(successor, leader);
    }
    rejoin_for_unseal(&mut pipeline, fault_node, migration_source)?;
    let reopened = selection(&pipeline, fault_node, migration_source)?;
    assert_eq!(reopened, committed);
    pipeline.with_service(fault_node, |service| {
        assert!(!service.recovery_required);
        assert!(!service.audit_failed);
        assert_eq!(service.state.as_ref().ok_or("cold State")?.replay_epoch, 1);
        assert_eq!(service.durable.as_ref().ok_or("cold Durable")?.replay_epoch(), 1);
        Ok(())
    })?;
    pipeline.assert_history(fault_node, &[(1, "seed-v5"), (2, "forward-archive-A")])?;
    expect(pipeline.call(
        fault_node, "GET", "secret/data/pipeline/history", pipeline.admin(), json!({"version":3}),
    )?, 404, "forward-audit-cold-future-absent")?;
    assert_eq!(selection(&pipeline, fault_node, migration_source)?.1.epoch_transitions().len(), 1);
    assert_eq!(count_calls(&counts), 1);
    Ok(())
}

#[test]
fn native_ha_snapshot_forward_source_publication_audit_veto_keeps_real_restore_after_cold_reopen()
-> TestResult {
    run_published_audit_veto(test_faults::Point::SourceAfterFinalizer)
}

#[test]
fn native_ha_snapshot_forward_first_delivery_audit_veto_keeps_authenticated_restore_after_cold_reopen()
-> TestResult {
    run_published_audit_veto(test_faults::Point::IngressFirstDelivery)
}

#[test]
fn native_ha_snapshot_forward_second_delivery_audit_veto_keeps_authenticated_restore_after_cold_reopen()
-> TestResult {
    run_published_audit_veto(test_faults::Point::IngressSecondDelivery)
}

fn run_unverified_attempt(attempt: bool) -> TestResult {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let (migration_source, archive) = prepare_archive(&pipeline, leader)?;
    let ingress = (leader + 1) % 3;
    let counts = register_snapshot_handlers(&pipeline, Some(leader))?;
    assert_eq!(pipeline.ready_leader()?, leader);
    let before = selection(&pipeline, leader, migration_source)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let scope = RequestDeadlineScope::enter(until);
    let service = Arc::clone(pipeline.services[ingress].as_ref().ok_or("unverified ingress Service")?);
    let mut writer = lock_until(&service, until).map_err(|_| "unverified original admission lock")?;
    let plan = admit_forward(&mut writer, pipeline.admin(), until)?;
    let audit_sequence = writer.audit_sequence;
    let audit_bytes = writer.audit.metadata()?.len();
    writer.audit_capacity = audit_bytes;
    drop(writer);
    let result = if attempt {
        plan.execute(&service, &mut &archive[..])
    } else {
        plan.reject_before_exchange(&service, test_faults::forged_root_response())
    };
    let (denied, output) = result.into_parts();
    assert!(output.is_none());
    assert_eq!(denied.status, 503);
    assert!(denied.body.get("root_attempted").is_none());
    assert!(denied.body.get("recovery_reference").is_none());
    assert!(denied.body.get("data").is_none());
    assert!(denied.unwrapped_json.is_none());
    assert!(denied.consistency_index.is_none());
    assert!(denied.response_headers.is_empty());
    assert!(denied.body.get("wrap_info").is_none());
    if attempt {
        assert_eq!(denied.body["outcome_unknown"], true);
        assert_eq!(denied.body["retry_allowed"], false);
        assert_eq!(counts[leader].load(Ordering::SeqCst), 1);
        assert_eq!(count_calls(&counts), 1);
    } else {
        assert!(denied.body.get("outcome_unknown").is_none());
        assert_eq!(count_calls(&counts), 0);
    }
    {
        let writer = lock_until(&service, until).map_err(|_| "unverified audit closure lock")?;
        assert_eq!(writer.audit_sequence, audit_sequence);
        assert_eq!(writer.audit.metadata()?.len(), audit_bytes);
        assert!(writer.recovery_required);
        assert!(writer.ha_activation.is_none());
        assert!(writer.snapshot_forward_test.observed().is_none());
        assert_eq!(writer.snapshot_forward_test.hits(), 0);
    }
    assert!(Instant::now() < until);
    drop(service);
    drop(scope);
    assert_private_lease_released(&pipeline, ingress)?;
    // No source Actor was admitted, no archive parsed, and no restore submitted.
    // The enrolled peer was actually reached only in the attempt=true branch.
    let after = selection(&pipeline, leader, migration_source)?;
    assert_eq!(after, before);
    assert_eq!(after.0, 0);
    assert!(after.1.epoch_transitions().is_empty());
    Ok(())
}

#[test]
fn native_ha_snapshot_forward_unverified_attempt_audit_failure_cannot_mint_root_authority()
-> TestResult {
    run_unverified_attempt(false)?;
    run_unverified_attempt(true)
}
