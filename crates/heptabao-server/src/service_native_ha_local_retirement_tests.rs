//! Actual Service/Actor, pinned three-node retention and real local .hbo
//! effects. These are process-owner tests, not physical-host SIGKILL evidence.
use super::local_marks::{activate_roots, current_cipher_references};
use super::*;
use crate::service::native_storage::ha_gc::{LOCAL_MARK_PATH, LOCAL_PATH, LOCAL_RECONCILE_PATH};
use heptabao_durable_service::{
    BlobLocator, ImmutableSourceSession, NativeHaLocalRetirementBoundary, PutRequest, Secret,
    ServiceError,
};

/// Produce disposable unreachable DATA through the real local barrier and
/// authenticated catalog. This does not create a typed root, Actor, quorum,
/// retention receipt or deletion owner. Every tested retirement uses the real
/// Service route and independently reacquires all production authorities.
fn local_candidate(pipeline: &Pipeline, owner: usize, registered: bool) -> TestResult<PathBuf> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let actual = pipeline.services[owner]
        .as_ref()
        .ok_or("actual Service owner")?;
    let mut service = lock_until(actual, until).map_err(|_| "actual Service writer")?;
    let identity = service
        .current_state_identity()
        .map_err(|_| "actual root identity")?;
    let root = service
        .native_root
        .as_ref()
        .ok_or("actual native root")?
        .encode()
        .map_err(|_| "actual root bytes")?;
    let directory = service.data_dir.clone();
    let deadline = OriginalDeadline::capture()?;
    let durable = service
        .durable
        .as_mut()
        .ok_or("actual local durable owner")?;
    let session = crate::service::native_blob_source::session(durable, root.as_slice())?;
    let address = crypto::random::<32>().map_err(|_| "disposable random locator")?;
    let resource = format!("state-records/v6/kv2/{}", hex(&address));
    assert!(durable.get("system", &resource)?.is_none());
    let locator = BlobLocator::new(session.store_id(), address)?;
    let path = directory.join(format!(
        "nv6.{}.{}.hbo",
        hex(&session.store_id()),
        hex(&address)
    ));
    let mut aad = b"HeptaBao/native-v6/typed-object-file/v1\0".to_vec();
    aad.extend_from_slice(resource.as_bytes());
    let data = vec![0xb7; 4096];
    let pin = durable.stage_immutable_object_before_publish(
        &session,
        locator,
        &aad,
        &data,
        &mut || deadline.check().map_err(|_| ServiceError::BarrierFailure),
    )?;
    let ciphertext_len = u32::try_from(fs::metadata(&path)?.len())?;
    if registered {
        let mut marker = b"HBV6BLOBREF0001\0".to_vec();
        marker.extend_from_slice(&session.store_id());
        marker.extend_from_slice(&address);
        marker.extend_from_slice(&ciphertext_len.to_be_bytes());
        marker.extend_from_slice(&u32::try_from(data.len())?.to_be_bytes());
        durable.put(PutRequest::new(
            "ha-local-disposable-data",
            "system",
            format!("gc-data-{}", hex(&address)),
            resource,
            identity.digest(),
            Secret::new(marker)?,
        )?)?;
    }
    drop(pin);
    drop(session);
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "unchanged root")?,
        identity
    );
    assert!(path.is_file());
    assert!(Instant::now() < until);
    Ok(path)
}

fn local_source_holder(pipeline: &Pipeline, owner: usize) -> TestResult<ImmutableSourceSession> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let actual = pipeline.services[owner]
        .as_ref()
        .ok_or("actual Service owner")?;
    let mut service = lock_until(actual, until).map_err(|_| "actual local source lock")?;
    let root = service
        .native_root
        .as_ref()
        .ok_or("actual native root")?
        .encode()
        .map_err(|_| "actual root encoding")?;
    let durable = service
        .durable
        .as_mut()
        .ok_or("actual local durable source")?;
    Ok(crate::service::native_blob_source::session(
        durable,
        root.as_slice(),
    )?)
}

fn prepared() -> TestResult<(Pipeline, usize)> {
    let (pipeline, leader) = configured()?;
    prepare(&pipeline, leader)?;
    activate_roots(&pipeline, leader)?;
    Ok((pipeline, leader))
}

fn local_status(pipeline: &Pipeline, leader: usize) -> TestResult<Response> {
    expect(
        pipeline.call(leader, "GET", LOCAL_PATH, pipeline.admin(), json!({}))?,
        200,
        "actual-local-retirement-status",
    )
}

#[test]
fn native_ha_local_retirement_actual_service_removes_only_registered_unreferenced_hbo_and_cold_reopens()
-> TestResult {
    let (mut pipeline, leader) = prepared()?;
    let candidate = local_candidate(&pipeline, leader, true)?;
    let unregistered = local_candidate(&pipeline, leader, false)?;
    let unregistered_bytes = fs::read(&unregistered)?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "sys/storage/native-v6/gc",
            pipeline.admin(),
            json!({}),
        )?,
        501,
        "standalone-File-HA-refusal-stays-exact",
    )?;
    expect(
        pipeline.call(leader, "POST", LOCAL_PATH, "", json!({}))?,
        403,
        "actual-original-root-Actor-required",
    )?;
    assert!(candidate.is_file());
    let mark = expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        200,
        "independent-read-only-mark-does-not-mint-retirement",
    )?;
    let unseen = mark.body["data"]["unreferenced_registered_resources_observed"]
        .as_u64()
        .ok_or("actual unused registered count")?;
    assert!(
        (1..=32).contains(&unseen),
        "fixture fits one original bounded retirement batch"
    );
    assert_eq!(mark.body["data"]["physical_deletion_authorized"], false);
    let response = expect(
        pipeline.call(leader, "POST", LOCAL_PATH, pipeline.admin(), json!({}))?,
        200,
        "real-held-local-retirement",
    )?;
    assert_eq!(
        response.body["data"]["removed_objects"].as_u64(),
        Some(unseen)
    );
    assert_eq!(
        response.body["data"]["retirement"]["phase"],
        "original-completed"
    );
    assert_eq!(response.body["data"]["scope"], "local-barrier-ciphertext");
    assert_eq!(
        response.body["data"]["historical_request_outcome_reclassified"],
        false
    );
    assert!(!candidate.exists());
    assert_eq!(fs::read(&unregistered)?, unregistered_bytes);
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5")])?;
    }
    cold_reopen(&mut pipeline, leader)?;
    lead_with_same_owner(&mut pipeline, leader)?;
    assert!(!candidate.exists());
    assert_eq!(fs::read(&unregistered)?, unregistered_bytes);
    assert_eq!(
        local_status(&pipeline, leader)?.body["data"]["retirement"]["pending"],
        false
    );
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5")])?;
    }

    // A successful physical effect does not grant a later HTTP delivery. The
    // original audit/activation chain still vetoes and erases that response.
    let late_candidate = local_candidate(&pipeline, leader, true)?;
    crate::service::native_storage::ha_gc::invalidate_activation_after_audit_once();
    let late = expect(
        pipeline.call(leader, "POST", LOCAL_PATH, pipeline.admin(), json!({}))?,
        503,
        "original-audit-activation-veto-after-real-local-retirement",
    )?;
    assert!(late.body.get("data").is_none());
    assert!(!late_candidate.exists());
    assert_eq!(fs::read(&unregistered)?, unregistered_bytes);
    Ok(())
}

#[test]
fn native_ha_local_retirement_actual_members_shared_readers_and_local_sessions_hold() -> TestResult
{
    let (mut pipeline, leader) = prepared()?;
    let candidate = local_candidate(&pipeline, leader, true)?;
    let original = fs::read(&candidate)?;
    let missing = (0..3).find(|member| *member != leader).ok_or("standby")?;
    pipeline.stop_process(missing)?;
    assert_eq!(pipeline.ready_leader()?, leader);
    expect(
        pipeline.call(leader, "POST", LOCAL_PATH, pipeline.admin(), json!({}))?,
        503,
        "majority-is-not-every-enrolled-retention-reader",
    )?;
    assert_eq!(fs::read(&candidate)?, original);
    pipeline.start_process(missing)?;
    pipeline.wait_cold_native_readindex_ready(missing)?;
    pipeline.unseal(missing)?;
    let store = {
        let _scope = scope();
        pipeline.processes[leader]
            .as_ref()
            .ok_or("actual HA owner")?
            .lock_for_request()
            .map_err(|_| "actual HA lock")?
            .native_install_test_store()?
    };
    let reading = store.begin_native_operation()?;
    expect(
        pipeline.call(leader, "POST", LOCAL_PATH, pipeline.admin(), json!({}))?,
        503,
        "real-shared-reader-blocks-exclusive-retirement",
    )?;
    assert_eq!(fs::read(&candidate)?, original);
    drop(reading);
    drop(store);
    let local = local_source_holder(&pipeline, leader)?;
    expect(
        pipeline.call(leader, "POST", LOCAL_PATH, pipeline.admin(), json!({}))?,
        503,
        "real-local-source-holder-blocks-physical-unlink",
    )?;
    assert_eq!(fs::read(&candidate)?, original);
    assert!(local_status(&pipeline, leader)?.body["data"]["retirement"].is_null());
    drop(local);
    expect(
        pipeline.call(leader, "POST", LOCAL_PATH, pipeline.admin(), json!({}))?,
        200,
        "new-request-after-real-owners-release",
    )?;
    assert!(!candidate.exists());
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5")])?;
    }
    Ok(())
}

fn cold_pending(boundary: NativeHaLocalRetirementBoundary) -> TestResult {
    let (mut pipeline, leader) = prepared()?;
    let candidate = local_candidate(&pipeline, leader, true)?;
    let original_bytes = fs::read(&candidate)?;
    {
        let _scope = scope();
        let process = pipeline.processes[leader]
            .as_ref()
            .ok_or("original HA process")?
            .lock_for_request()
            .map_err(|_| "original HA process lock")?;
        process.fail_native_v6_local_retirement_once(boundary);
    }
    let original = expect(
        pipeline.call(leader, "POST", LOCAL_PATH, pipeline.admin(), json!({}))?,
        503,
        "real-local-pending-completion-unknown",
    )?;
    assert!(original.body.get("data").is_none());
    if boundary == NativeHaLocalRetirementBoundary::KnownPending {
        assert_eq!(fs::read(&candidate)?, original_bytes);
    } else {
        assert!(!candidate.exists());
    }
    cold_reopen(&mut pipeline, leader)?;
    lead_with_same_owner(&mut pipeline, leader)?;
    let pending = local_status(&pipeline, leader)?;
    assert_eq!(pending.body["data"]["retirement"]["pending"], true);
    assert_eq!(
        pending.body["data"]["retirement"]["original_completion_recorded"],
        false
    );
    let digest = pending.body["data"]["retirement"]["record_sha256"]
        .as_str()
        .ok_or("actual cold pending digest")?
        .to_owned();
    let original_digest = pending.body["data"]["retirement"]["original_pending_sha256"].clone();
    expect(
        pipeline.call(leader, "POST", LOCAL_PATH, pipeline.admin(), json!({}))?,
        409,
        "ordinary-local-operation-cannot-replay-pending",
    )?;
    expect(
        pipeline.call(
            leader,
            "POST",
            LOCAL_RECONCILE_PATH,
            pipeline.admin(),
            json!({"expected_pending_sha256":"00".repeat(32)}),
        )?,
        409,
        "wrong-cold-selector-does-not-authorize-unlink",
    )?;
    let missing = (0..3)
        .find(|member| *member != leader)
        .ok_or("retention peer")?;
    pipeline.stop_process(missing)?;
    assert_eq!(pipeline.ready_leader()?, leader);
    expect(
        pipeline.call(
            leader,
            "POST",
            LOCAL_RECONCILE_PATH,
            pipeline.admin(),
            json!({"expected_pending_sha256":digest}),
        )?,
        503,
        "old-pending-data-cannot-reconstruct-lost-reader-authority",
    )?;
    assert_eq!(
        local_status(&pipeline, leader)?.body["data"]["retirement"]["record_sha256"],
        digest
    );
    pipeline.start_process(missing)?;
    pipeline.wait_cold_native_readindex_ready(missing)?;
    pipeline.unseal(missing)?;
    let completed = expect(
        pipeline.call(
            leader,
            "POST",
            LOCAL_RECONCILE_PATH,
            pipeline.admin(),
            json!({"expected_pending_sha256":digest}),
        )?,
        200,
        "fresh-cold-owner-explicit-local-reconciliation",
    )?;
    assert_eq!(completed.body["data"]["retirement"]["pending"], false);
    assert_eq!(
        completed.body["data"]["retirement"]["original_completion_recorded"],
        false
    );
    assert_eq!(
        completed.body["data"]["retirement"]["original_pending_sha256"],
        original_digest
    );
    assert_eq!(
        completed.body["data"]["historical_request_outcome_reclassified"],
        false
    );
    assert!(!candidate.exists());
    assert_eq!(original.status, 503);
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5")])?;
    }
    cold_reopen(&mut pipeline, leader)?;
    lead_with_same_owner(&mut pipeline, leader)?;
    let cold = local_status(&pipeline, leader)?;
    assert_eq!(cold.body["data"]["retirement"]["pending"], false);
    assert_eq!(
        cold.body["data"]["retirement"]["original_pending_sha256"],
        original_digest
    );
    assert_eq!(
        cold.body["data"]["retirement"]["original_completion_recorded"],
        false
    );
    Ok(())
}

#[test]
fn native_ha_local_retirement_actual_cold_pending_requires_new_held_owner() -> TestResult {
    cold_pending(NativeHaLocalRetirementBoundary::KnownPending)
}

#[test]
fn native_ha_local_retirement_actual_cold_absence_preserves_unknown_original() -> TestResult {
    cold_pending(NativeHaLocalRetirementBoundary::PhysicalCompleted)
}

#[test]
fn native_ha_local_retirement_actual_historical_payload_corruption_holds_unrelated_candidate()
-> TestResult {
    let (pipeline, leader) = prepared()?;
    let value = "full-retained-payload".repeat(16_384);
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({"options":{"cas":1},"data":{"value":value}}),
        )?,
        200,
        "actual-historical-large-version",
    )?;
    let old = current_cipher_references(&pipeline, leader)?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/destroy/pipeline/history",
            pipeline.admin(),
            json!({"versions":[2]}),
        )?,
        204,
        "removed-only-from-current-view",
    )?;
    let current = current_cipher_references(&pipeline, leader)?;
    let selected = old
        .iter()
        .find(|old| old.payload_bytes > 128 * 1024 && !current.iter().any(|live| live.id == old.id))
        .ok_or("historical-only payload")?;
    let historical_path = pipeline.configs[leader]
        .raft_dir
        .join("native-v6-ciphertext")
        .join(format!("v6-{}.blob", hex(&selected.id)));
    let original = fs::read(&historical_path)?;
    let candidate = local_candidate(&pipeline, leader, true)?;
    let candidate_bytes = fs::read(&candidate)?;
    let mut damaged = original.clone();
    *damaged.last_mut().ok_or("historical ciphertext bytes")? ^= 1;
    fs::write(&historical_path, &damaged)?;
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5")])?;
    }
    expect(
        pipeline.call(leader, "POST", LOCAL_PATH, pipeline.admin(), json!({}))?,
        503,
        "unread-current-success-cannot-replace-complete-history-authentication",
    )?;
    assert_eq!(fs::read(&candidate)?, candidate_bytes);
    assert_eq!(fs::read(&historical_path)?, damaged);
    assert!(local_status(&pipeline, leader)?.body["data"]["retirement"].is_null());
    // Exact fixture repair only; the failed mark/owner is never resumed.
    fs::write(&historical_path, &original)?;
    expect(
        pipeline.call(leader, "POST", LOCAL_PATH, pipeline.admin(), json!({}))?,
        200,
        "new-live-owner-after-explicit-exact-history-repair",
    )?;
    assert!(!candidate.exists());
    assert_eq!(fs::read(&historical_path)?, original);
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5")])?;
    }
    Ok(())
}
