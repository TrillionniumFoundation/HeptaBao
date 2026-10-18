//! Actual Service snapshot transport plus real pinned three-node TLS/Raft.
//! Host power loss is separately measured by the physical acceptance runner.
use super::*;
use heptabao_raft_runtime::NativeV6PublishedRoot;
use std::io::Read;

const SNAPSHOT: &str = "sys/storage/raft/snapshot";
fn admit(service: &mut Service, method: &str, token: &str, until: Instant)
    -> TestResult<Box<PendingExternalRequest>>
{
    match service.begin_native_snapshot_before(
        ServiceRequest::new(method, SNAPSHOT, "", token, json!({})), until,
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(pending)) => Ok(pending),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            errors_only("historical-snapshot-admission", &response);
            Err(format!("historical snapshot admission HTTP {}", response.status).into())
        }
        NativeSnapshotAdmission::Redirect(_) => Err("selected historical restore leader redirected".into()),
    }
}
fn activate(pipeline: &Pipeline, leader: usize) -> TestResult {
    expect(pipeline.call(leader, "POST", "sys/internal/native-v6/activate",
        pipeline.admin(), json!({}))?, 204, "historical-native-activation")?;
    Ok(())
}
fn selection(pipeline: &Pipeline, leader: usize) -> TestResult<(u64, NativeV6PublishedRoot)> {
    let _scope = scope();
    let process = pipeline.processes[leader].as_ref().ok_or("restore process")?
        .lock_for_request().map_err(|_| "restore selection lock")?;
    let read = process.native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("restore committed root")?;
    process.verify_native_v6_committed_read(&read)?;
    assert_eq!(read.published().migration_source().0, pipeline.seed_identity.digest());
    Ok((read.enrollment().epoch(), read.published().clone()))
}
fn export(pipeline: &Pipeline, leader: usize, token: &str) -> TestResult<Vec<u8>> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader].as_ref().ok_or("export Service")?;
    let mut writer = lock_until(service, until).map_err(|_| "export writer")?;
    let mut pending = admit(&mut writer, "GET", token, until)?;
    let (observed, archive) = pending.execute_snapshot_transfer(&mut io::empty());
    expect(writer.finish_external_request(*pending, observed), 200, "historical-archive-export")?;
    assert!(writer.native_request_binding.is_none());
    drop(writer);
    let mut archive = archive.ok_or("exported archive")?;
    let mut bytes = Vec::new();
    archive.read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn restore(pipeline: &Pipeline, leader: usize, token: &str, bytes: &[u8]) -> TestResult<Response> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader].as_ref().ok_or("restore Service")?;
    let mut writer = lock_until(service, until).map_err(|_| "restore writer")?;
    let mut pending = admit(&mut writer, "POST", token, until)?;
    drop(writer);
    let (observed, output) = pending.execute_snapshot_transfer(&mut &bytes[..]);
    assert!(output.is_none());
    let mut writer = lock_until(service, until).map_err(|_| "restore completion writer")?;
    let response = writer.finish_external_request(*pending, observed);
    errors_only("historical-restore-complete", &response);
    assert!(writer.native_request_binding.is_none());
    assert!(Instant::now() < until, "restore cannot extend the original 15-second contract");
    Ok(response)
}
fn root_token(pipeline: &Pipeline, leader: usize, ttl: &str) -> TestResult<Zeroizing<String>> {
    let mut issued = expect(pipeline.call(leader, "POST", "auth/token/create", pipeline.admin(),
        json!({"policies":["root"],"ttl":ttl,"no_default_policy":true,"no_parent":true}))?,
        200, "historical-root-token")?;
    secret_field(&mut issued, "/auth/client_token")
}

#[test]
fn native_ha_historical_restore_two_epochs_cold_stale_replica_keeps_original_lineage() -> TestResult {
    let mut pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    activate(&pipeline, leader)?;
    let value = "historical-native-retained-block".repeat(8192);
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":1},"data":{"value":value}}))?, 200, "historical-A-write")?;
    let a = selection(&pipeline, leader)?;
    let archive = export(&pipeline, leader, pipeline.admin())?;
    let stale = (leader + 1) % 3;
    // This Service and Raft owner miss BOTH committed epoch transitions. Its
    // authenticated old local graph must not be rebadged with an epoch integer.
    pipeline.stop_process(stale)?;
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":2},"data":{"value":"later-B-not-in-archive"}}))?,
        200, "historical-B-write")?;
    let b = selection(&pipeline, leader)?;
    assert_eq!(a.0, 0);
    assert_eq!(b.0, 0);
    assert_ne!(a.1.root_digest(), b.1.root_digest());
    for epoch in 1..=2 {
        let response = expect(restore(&pipeline, leader, pipeline.admin(), &archive)?, 200,
            "actual-historical-epoch-restore")?;
        assert_eq!(response.body["data"]["replay_epoch"], epoch);
        let now = selection(&pipeline, leader)?;
        assert_eq!(now.0, epoch);
        assert_eq!(now.1.epoch_transitions().len(), epoch as usize);
        assert_eq!(now.1.native_origin_epoch(), 0);
        assert_ne!(now.1.root_digest(), a.1.root_digest());
        assert_ne!(now.1.root_digest(), b.1.root_digest());
        let transition = now.1.epoch_transitions().last().ok_or("restore lineage")?;
        assert_eq!(transition.source_enrollment().epoch(), epoch - 1);
        assert_eq!(transition.target_enrollment().epoch(), epoch);
        pipeline.assert_history(leader, &[(1, "seed-v5"), (2, &value)])?;
        expect(pipeline.call(leader, "GET", "secret/data/pipeline/history", pipeline.admin(),
            json!({"version":3}))?, 404, "historical-future-version-absent")?;
    }
    pipeline.start_process(stale)?;
    pipeline.unseal(stale)?;
    for voter in 0..3 {
        pipeline.assert_history(voter, &[(1, "seed-v5"), (2, &value)])?;
        assert_eq!(selection(&pipeline, voter)?.0, 2);
        pipeline.with_service(voter, |service| {
            let durable = service.durable.as_ref().ok_or("recovered Durable")?;
            assert_eq!(durable.replay_epoch(), 2);
            assert_eq!(service.state.as_ref().ok_or("recovered State")?.replay_epoch, 2);
            assert!(!service.recovery_required);
            Ok(())
        })?;
    }
    let installed = selection(&pipeline, leader)?;
    pipeline.stop_process(leader)?;
    let successor = pipeline.ready_leader()?;
    assert_ne!(successor, leader);
    pipeline.start_process(leader)?;
    pipeline.unseal(leader)?;
    assert_eq!(selection(&pipeline, leader)?, installed);
    pipeline.assert_history(leader, &[(1, "seed-v5"), (2, &value)])?;
    Ok(())
}

#[test]
fn native_ha_historical_restore_inherits_live_clock_and_uses_original_actor_after_auth_replacement() -> TestResult {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let _existing = root_token(&pipeline, leader, "120s")?;
    activate(&pipeline, leader)?;
    let archive = export(&pipeline, leader, pipeline.admin())?;
    // This original live Actor did not exist in archive A. A real authorized
    // restore may remove it; final delivery must retain its admitted Auth
    // owner rather than fabricate or re-authenticate it from archived Auth.
    let actor = root_token(&pipeline, leader, "120s")?;
    let old_floor = pipeline.with_service(leader, |service| {
        Ok(service.state.as_ref().ok_or("before clock state")?.auth.token_api_observed_time(
            AuthorityTime::Precise(crate::auth::Timestamp::whole(0)?)).exact())
    })?;
    let before = selection(&pipeline, leader)?;
    let response = expect(restore(&pipeline, leader, &actor, &archive)?, 200,
        "historical-restore-original-Actor-delivery")?;
    assert_eq!(response.body["data"]["replay_epoch"], 1);
    let after = selection(&pipeline, leader)?;
    assert_eq!(after.0, 1);
    assert_eq!(after.1.epoch_transitions().len(), 1);
    assert_eq!(after.1.epoch_transitions().next().ok_or("restore transition")?.source_root_digest(),
        before.1.root_digest());
    pipeline.with_service(leader, |service| {
        let state = service.state.as_ref().ok_or("restored clock state")?;
        assert!(state.auth.token_api_observed_time(
            AuthorityTime::Precise(crate::auth::Timestamp::whole(0)?)).exact() >= old_floor);
        assert!(!service.recovery_required);
        assert!(service.native_request_binding.is_none());
        Ok(())
    })?;
    expect(pipeline.call(leader, "GET", "secret/data/pipeline/history", &actor, json!({}))?,
        403, "restored-Auth-does-not-contain-later-Actor")?;
    pipeline.assert_history(leader, &[(1, "seed-v5")])?;
    Ok(())
}

#[test]
fn native_ha_historical_restore_tamper_revocation_and_expiry_never_begin_epoch() -> TestResult {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    activate(&pipeline, leader)?;
    let archive = export(&pipeline, leader, pipeline.admin())?;
    let mut damaged = archive.clone();
    let index = damaged.len().checked_sub(8).ok_or("archive CRC")?;
    damaged[index] ^= 1;
    let rejected = restore(&pipeline, leader, pipeline.admin(), &damaged)?;
    assert!(rejected.status >= 400 && rejected.body.get("data").is_none());
    assert_eq!(selection(&pipeline, leader)?.0, 0);
    for expire in [false, true] {
        let token = root_token(&pipeline, leader, if expire { "1s" } else { "120s" })?;
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let service = pipeline.services[leader].as_ref().ok_or("denial Service")?;
        let mut writer = lock_until(service, until).map_err(|_| "denial writer")?;
        let mut pending = admit(&mut writer, "POST", &token, until)?;
        drop(writer);
        let (observed, output) = pending.execute_snapshot_transfer(&mut &archive[..]);
        assert!(output.is_none());
        if expire {
            thread::sleep(Duration::from_millis(1100));
        } else {
            expect(pipeline.call(leader, "POST", "auth/token/revoke", pipeline.admin(),
                json!({"token":token.as_str()}))?, 204, "historical-revoke-before-finalize")?;
        }
        let mut writer = lock_until(service, until).map_err(|_| "denial finalizer")?;
        let denied = writer.finish_external_request(*pending, observed);
        assert!(denied.status >= 400 && denied.body.get("data").is_none());
        if expire { assert_eq!(denied.status, 403); }
        assert!(writer.native_request_binding.is_none());
        drop(writer);
        let current = selection(&pipeline, leader)?;
        assert_eq!(current.0, 0);
        assert_eq!(current.1.epoch_transitions().len(), 0);
    }
    pipeline.assert_history(leader, &[(1, "seed-v5")])?;
    Ok(())
}
