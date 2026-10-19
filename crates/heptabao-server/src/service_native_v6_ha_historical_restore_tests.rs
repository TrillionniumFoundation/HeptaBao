//! Actual Service snapshot transport plus real pinned three-node TLS/Raft.
//! Host power loss is separately measured by the physical acceptance runner.
use super::*;
use heptabao_raft_runtime::NativeV6PublishedRoot;
use crate::state_record_root::StateIdentity;
use std::io::Read;

const SNAPSHOT: &str = "sys/storage/raft/snapshot";
fn admit(service: &mut Service, method: &str, token: &str, until: Instant)
    -> TestResult<Box<PendingExternalRequest>>
{
    admit_with_query(service, method, token, json!({}), until)
}
fn admit_with_query(service: &mut Service, method: &str, token: &str, query: Value, until: Instant)
    -> TestResult<Box<PendingExternalRequest>>
{
    match service.begin_native_snapshot_before(
        ServiceRequest::new(method, SNAPSHOT, "", token, query), until,
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(pending)) => Ok(pending),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            errors_only("historical-snapshot-admission", &response);
            Err(format!("historical snapshot admission HTTP {}", response.status).into())
        }
        NativeSnapshotAdmission::Redirect(_) => Err("selected historical restore leader redirected".into()),
    }
}
fn activate(pipeline: &Pipeline, leader: usize) -> TestResult<StateIdentity> {
    // Real ordinary admission can publish a precise clock floor after the
    // caller's pre-activation observation. Observe the actual source at the
    // migration boundary, independently of the later published native root.
    pipeline.with_service(leader, |service| {
        assert!(matches!(service.current_state_identity().map_err(|_| "pre-activation source")?,
            StateIdentity::RecordsV5(_)));
        assert!(service.native_root.is_none());
        Ok(())
    })?;
    let observation = crate::service::native_v6_writer::activation_source_observation::arm()?;
    expect(pipeline.call(leader, "POST", "sys/internal/native-v6/activate",
        pipeline.admin(), json!({}))?, 204, "historical-native-activation")?;
    let source = observation.take()?;
    assert_eq!(selection(pipeline, leader, source)?.0, 0);
    Ok(source)
}

// Cold Raft readiness is a separate read-only setup observation, before the
// single real unseal request receives its original 15-second deadline. A newly
// reopened peer may still carry an obsolete leader hint; that must not cause a
// transient refused ReadIndex to be mistaken for a failed historical install.
// No archive, unseal or other mutation is retried by this readiness loop.
fn rejoin_for_unseal(pipeline: &mut Pipeline, index: usize, migration_source: StateIdentity)
    -> TestResult
{
    pipeline.start_process(index)?;
    let until = Instant::now() + Duration::from_secs(8);
    let _scope = RequestDeadlineScope::enter(until);
    loop {
        let ready = {
            let process = pipeline.processes[index].as_ref().ok_or("cold rejoin process")?
                .lock_for_request().map_err(|_| "cold rejoin observation lock")?;
            match process.native_v6_committed_read(OriginalDeadline::capture()?) {
                Ok(Some(read)) => {
                    process.verify_native_v6_committed_read(&read)?;
                    assert_eq!(read.published().migration_source().0, migration_source.digest());
                    true
                }
                Ok(None) | Err(_) => false,
            }
        };
        if ready { break; }
        if Instant::now() >= until {
            return Err("cold rejoin actual ReadIndex readiness exceeded original setup budget".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
    drop(_scope);
    pipeline.unseal(index)
}
fn selection(pipeline: &Pipeline, leader: usize, migration_source: StateIdentity)
    -> TestResult<(u64, NativeV6PublishedRoot)>
{
    let _scope = scope();
    let process = pipeline.processes[leader].as_ref().ok_or("restore process")?
        .lock_for_request().map_err(|_| "restore selection lock")?;
    let read = process.native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("restore committed root")?;
    process.verify_native_v6_committed_read(&read)?;
    assert!(matches!(migration_source, StateIdentity::RecordsV5(_)));
    assert_eq!(read.published().migration_source().0, migration_source.digest());
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

fn observed_pending_reference(pipeline: &Pipeline, leader: usize) -> TestResult<Option<String>> {
    let _scope = scope();
    let process = pipeline.processes[leader].as_ref().ok_or("pending restore process")?
        .lock_for_request().map_err(|_| "pending restore selection lock")?;
    let read = process.native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("pending restore committed root")?;
    let operation = process.pending_native_v6_restore_for_test(&read)?;
    Ok(operation.map(|operation| format!("native-v6-restore-{}", operation
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>())))
}

fn cancel_pending_restore(pipeline: &Pipeline, leader: usize, reference: &str, body: &[u8])
    -> TestResult<Response>
{
    pending_restore_control(pipeline, leader, json!({"cancel_pending_restore":reference}), body)
}

fn inspect_pending_restore(pipeline: &Pipeline, leader: usize, body: &[u8]) -> TestResult<Response> {
    pending_restore_control(pipeline, leader, json!({"inspect_pending_restore":true}), body)
}

fn pending_restore_control(pipeline: &Pipeline, leader: usize, query: Value, body: &[u8])
    -> TestResult<Response>
{
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader].as_ref().ok_or("pending cancellation Service")?;
    let mut writer = lock_until(service, until).map_err(|_| "pending cancellation writer")?;
    let mut pending = admit_with_query(&mut writer, "POST", pipeline.admin(), query, until)?;
    drop(writer);
    let (observed, output) = pending.execute_snapshot_transfer(&mut &body[..]);
    assert!(output.is_none(), "cancellation does not download or upload an archive");
    let mut writer = lock_until(service, until).map_err(|_| "pending cancellation finalizer")?;
    let response = writer.finish_external_request(*pending, observed);
    errors_only("historical-pending-cancellation", &response);
    assert!(writer.native_request_binding.is_none());
    assert!(Instant::now() < until, "cancellation retains its original deadline");
    Ok(response)
}

fn lose_pending_restore_failure_response(pipeline: &Pipeline, leader: usize, archive: &[u8]) -> TestResult {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader].as_ref().ok_or("lost-reference Service")?;
    let mut writer = lock_until(service, until).map_err(|_| "lost-reference admission")?;
    assert!(!writer.state.as_ref().ok_or("lost-reference State")?.has_token_api_precision_state());
    let mut pending = admit(&mut writer, "POST", pipeline.admin(), until)?;
    drop(writer);
    let (observed, output) = pending.execute_snapshot_transfer(&mut &archive[..]);
    assert!(output.is_none());
    let cipher_root = pipeline.configs[leader].raft_dir.join("native-v6-ciphertext");
    let saved_root = pipeline.configs[leader].raft_dir.join("inspect-test-saved-ciphertext");
    private_directory(&saved_root)?;
    let files = fs::read_dir(&cipher_root)?.map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(!files.is_empty());
    for name in &files { fs::rename(cipher_root.join(name), saved_root.join(name))?; }
    fs::remove_dir(&cipher_root)?;
    let mut writer = lock_until(service, until).map_err(|_| "lost-reference completion")?;
    let mut undelivered = writer.finish_external_request(*pending, observed);
    private_directory(&cipher_root)?;
    for name in &files { fs::rename(saved_root.join(name), cipher_root.join(name))?; }
    fs::remove_dir(&saved_root)?;
    assert_eq!(undelivered.status, 503);
    assert_eq!(undelivered.body["root_attempted"], false);
    assert_eq!(writer.durable.as_ref().ok_or("lost-reference Durable")?.replay_epoch(), 0);
    assert!(writer.native_request_binding.is_none());
    // Deliberately destroy the entire undelivered reply without reading or
    // retaining its operation reference. The post-restart caller receives no
    // ID from this helper; it must discover the current operation through a
    // newly admitted root request and an actual fresh quorum observation.
    erase_json(&mut undelivered.body);
    drop(undelivered);
    Ok(())
}

#[test]
fn native_ha_historical_restore_two_epochs_cold_stale_replica_keeps_original_lineage() -> TestResult {
    let mut pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let migration_source = activate(&pipeline, leader)?;
    let value = "historical-native-retained-block".repeat(8192);
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":1},"data":{"value":value}}))?, 200, "historical-A-write")?;
    let a = selection(&pipeline, leader, migration_source)?;
    let archive = export(&pipeline, leader, pipeline.admin())?;
    let stale = (leader + 1) % 3;
    let running_stale = (leader + 2) % 3;
    let running_nonce = pipeline.with_service(running_stale, |service| {
        assert_eq!(service.state.as_ref().ok_or("running stale State")?.replay_epoch, 0);
        Ok(Zeroizing::new(service.unseal_nonce.clone()))
    })?;
    // This Service and Raft owner miss BOTH committed epoch transitions. Its
    // authenticated old local graph must not be rebadged with an epoch integer.
    pipeline.stop_process(stale)?;
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":2},"data":{"value":"later-B-not-in-archive"}}))?,
        200, "historical-B-write")?;
    let b = selection(&pipeline, leader, migration_source)?;
    assert_eq!(a.0, 0);
    assert_eq!(b.0, 0);
    assert_ne!(a.1.root_digest(), b.1.root_digest());
    for epoch in 1..=2 {
        let response = expect(restore(&pipeline, leader, pipeline.admin(), &archive)?, 200,
            "actual-historical-epoch-restore")?;
        assert_eq!(response.body["data"]["replay_epoch"], epoch);
        let now = selection(&pipeline, leader, migration_source)?;
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
    // The other follower's Raft stayed live, but no request or maintenance
    // pre-materialized its Service. Its first real forwarded read must catch
    // up across both committed epochs and bind the resulting activation.
    pipeline.with_service(running_stale, |service| {
        assert_eq!(service.state.as_ref().ok_or("running stale State")?.replay_epoch, 0);
        assert_eq!(service.unseal_nonce, *running_nonce);
        Ok(())
    })?;
    pipeline.assert_history(running_stale, &[(1, "seed-v5"), (2, &value)])?;
    pipeline.with_service(running_stale, |service| {
        assert_eq!(service.state.as_ref().ok_or("caught-up State")?.replay_epoch, 2);
        assert_ne!(service.unseal_nonce, *running_nonce,
            "a real historical install must invalidate the earlier local activation");
        Ok(())
    })?;
    rejoin_for_unseal(&mut pipeline, stale, migration_source)?;
    for voter in 0..3 {
        pipeline.assert_history(voter, &[(1, "seed-v5"), (2, &value)])?;
        assert_eq!(selection(&pipeline, voter, migration_source)?.0, 2);
        pipeline.with_service(voter, |service| {
            let durable = service.durable.as_ref().ok_or("recovered Durable")?;
            assert_eq!(durable.replay_epoch(), 2);
            assert_eq!(service.state.as_ref().ok_or("recovered State")?.replay_epoch, 2);
            assert!(!service.recovery_required);
            Ok(())
        })?;
    }
    let installed = selection(&pipeline, leader, migration_source)?;
    pipeline.stop_process(leader)?;
    let successor = pipeline.ready_leader()?;
    assert_ne!(successor, leader);
    rejoin_for_unseal(&mut pipeline, leader, migration_source)?;
    assert_eq!(selection(&pipeline, leader, migration_source)?, installed);
    pipeline.assert_history(leader, &[(1, "seed-v5"), (2, &value)])?;
    Ok(())
}

#[test]
fn native_ha_historical_restore_inherits_live_clock_and_uses_original_actor_after_auth_replacement() -> TestResult {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let _existing = root_token(&pipeline, leader, "120s")?;
    let migration_source = activate(&pipeline, leader)?;
    assert_ne!(migration_source, pipeline.seed_identity,
        "the migration must include the actual pre-existing token publication");
    let archive = export(&pipeline, leader, pipeline.admin())?;
    // This original live Actor did not exist in archive A. A real authorized
    // restore may remove it; final delivery must retain its admitted Auth
    // owner rather than fabricate or re-authenticate it from archived Auth.
    let actor = root_token(&pipeline, leader, "120s")?;
    let old_floor = pipeline.with_service(leader, |service| {
        Ok(service.state.as_ref().ok_or("before clock state")?.auth.token_api_observed_time(
            AuthorityTime::Precise(crate::auth::Timestamp::whole(0)?)).exact())
    })?;
    let before = selection(&pipeline, leader, migration_source)?;
    let response = expect(restore(&pipeline, leader, &actor, &archive)?, 200,
        "historical-restore-original-Actor-delivery")?;
    assert_eq!(response.body["data"]["replay_epoch"], 1);
    let after = selection(&pipeline, leader, migration_source)?;
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
    let migration_source = activate(&pipeline, leader)?;
    let archive = export(&pipeline, leader, pipeline.admin())?;
    let mut damaged = archive.clone();
    let index = damaged.len().checked_sub(8).ok_or("archive CRC")?;
    damaged[index] ^= 1;
    let rejected = restore(&pipeline, leader, pipeline.admin(), &damaged)?;
    assert!(rejected.status >= 400 && rejected.body.get("data").is_none());
    assert_eq!(selection(&pipeline, leader, migration_source)?.0, 0);
    for expire in [false, true] {
        // A one-second fixture credential can expire during real Raft-backed
        // admission. The expiry branch must first retain an admitted original
        // Actor, then expire that Actor before finalization, inside the same
        // unchanged 15-second request budget.
        let token = root_token(&pipeline, leader, if expire { "6s" } else { "120s" })?;
        let issued_response = Instant::now();
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let service = pipeline.services[leader].as_ref().ok_or("denial Service")?;
        let mut writer = lock_until(service, until).map_err(|_| "denial writer")?;
        let mut pending = admit(&mut writer, "POST", &token, until)?;
        drop(writer);
        let (observed, output) = pending.execute_snapshot_transfer(&mut &archive[..]);
        assert!(output.is_none());
        if expire {
            // Issuance precedes its HTTP response. This real elapsed bound is
            // therefore beyond the actual TTL without changing any Auth state
            // or minting another clock/Actor after successful admission.
            let expired_at = issued_response + Duration::from_millis(6100);
            assert!(expired_at < until);
            thread::sleep(expired_at.saturating_duration_since(Instant::now()));
        } else {
            expect(pipeline.call(leader, "POST", "auth/token/revoke", pipeline.admin(),
                json!({"token":token.as_str()}))?, 204, "historical-revoke-before-finalize")?;
        }
        let mut writer = lock_until(service, until).map_err(|_| "denial finalizer")?;
        let denied = writer.finish_external_request(*pending, observed);
        assert!(denied.status >= 400 && denied.body.get("data").is_none());
        if expire { assert_eq!(denied.status, 403); }
        assert!(Instant::now() < until, "denial must not be explained by request expiry");
        assert!(writer.native_request_binding.is_none());
        drop(writer);
        let current = selection(&pipeline, leader, migration_source)?;
        assert_eq!(current.0, 0);
        assert_eq!(current.1.epoch_transitions().len(), 0);
    }
    pipeline.assert_history(leader, &[(1, "seed-v5")])?;
    Ok(())
}

#[test]
fn native_ha_historical_restore_audit_failure_retains_exact_operation_after_cold_reopen() -> TestResult {
    let mut pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let migration_source = activate(&pipeline, leader)?;
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":1},"data":{"value":"archive-A"}}))?,
        200, "audit-fault-archive-A-write")?;
    let archive = export(&pipeline, leader, pipeline.admin())?;
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":2},"data":{"value":"later-B"}}))?,
        200, "audit-fault-later-B-write")?;
    let before = selection(&pipeline, leader, migration_source)?;

    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader].as_ref().ok_or("audit-fault Service")?;
    let mut writer = lock_until(service, until).map_err(|_| "audit-fault admission writer")?;
    let mut pending = admit(&mut writer, "POST", pipeline.admin(), until)?;
    drop(writer);
    let (observed, output) = pending.execute_snapshot_transfer(&mut &archive[..]);
    assert!(output.is_none());
    let mut writer = lock_until(service, until).map_err(|_| "audit-fault completion writer")?;
    // Admission and archive transport completed normally. Exhaust the existing
    // test-only audit I/O budget before finalization: the real restore CAS and
    // local epoch installation run, then the mandatory response audit fails.
    // No root, receipt, Raft entry or recovery flag is manufactured by this test.
    let audit_sequence = writer.audit_sequence;
    let audit_bytes = writer.audit.metadata()?.len();
    writer.audit_capacity = audit_bytes;
    let denied = writer.finish_external_request(*pending, observed);
    assert_eq!(denied.status, 503);
    assert_eq!(denied.body["errors"][0], "historical restore delivery requires reconciliation");
    assert_eq!(denied.body["recovery_required"], true);
    assert_eq!(denied.body["retry_allowed"], false);
    assert_eq!(denied.body["root_attempted"], true);
    assert!(denied.body.get("data").is_none());
    assert!(denied.consistency_index.is_none());
    let reference = denied.body["recovery_reference"].as_str()
        .ok_or("committed restore recovery reference absent")?.to_owned();
    assert_eq!(writer.audit_sequence, audit_sequence);
    assert_eq!(writer.audit.metadata()?.len(), audit_bytes);
    assert!(writer.recovery_required);
    assert!(writer.ha_activation.is_none());
    assert!(writer.native_request_binding.is_none());
    assert_eq!(writer.durable.as_ref().ok_or("audit-fault Durable")?.replay_epoch(), 1);
    assert_eq!(writer.state.as_ref().ok_or("audit-fault State")?.replay_epoch, 1);
    drop(writer);

    // Read the real quorum-selected transition despite failed delivery. Its
    // operation, source root and epoch prove exactly what committed; HTTP 503
    // must not be interpreted as permission to submit the archive again.
    let committed = selection(&pipeline, leader, migration_source)?;
    assert_eq!(committed.0, 1);
    assert_ne!(committed.1.root_digest(), before.1.root_digest());
    assert_eq!(committed.1.epoch_transitions().len(), 1);
    let transition = committed.1.epoch_transitions().last().ok_or("audit-fault transition")?;
    assert_eq!(transition.source_root_digest(), before.1.root_digest());
    assert_eq!(transition.source_enrollment().epoch(), 0);
    assert_eq!(transition.target_enrollment().epoch(), 1);
    assert_eq!(transition.operation_digest(), committed.1.intent().operation_digest);
    let expected_reference = format!("native-v6-restore-{}", transition.operation_digest()
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>());
    assert_eq!(reference, expected_reference);
    drop(_scope);

    // Replace the actual failed Service, disk owner and Raft process. The
    // reopened owner uses its original barrier key and existing audit chain;
    // it does not retry the restore or reseed from the archive.
    pipeline.stop_process(leader)?;
    let successor = pipeline.ready_leader()?;
    assert_ne!(successor, leader);
    rejoin_for_unseal(&mut pipeline, leader, migration_source)?;
    let reopened = selection(&pipeline, leader, migration_source)?;
    assert_eq!(reopened, committed);
    let recovered_transition = reopened.1.epoch_transitions().last()
        .ok_or("cold recovered restore transition")?;
    assert_eq!(recovered_transition.operation_digest(), transition.operation_digest());
    pipeline.with_service(leader, |service| {
        assert!(!service.recovery_required);
        assert!(!service.audit_failed);
        assert_eq!(service.durable.as_ref().ok_or("cold recovered Durable")?.replay_epoch(), 1);
        Ok(())
    })?;
    pipeline.assert_history(leader, &[(1, "seed-v5"), (2, "archive-A")])?;
    expect(pipeline.call(leader, "GET", "secret/data/pipeline/history", pipeline.admin(),
        json!({"version":3}))?, 404, "cold-recovered-future-version-absent")?;
    assert_eq!(selection(&pipeline, leader, migration_source)?.1.epoch_transitions().len(), 1);
    Ok(())
}

#[test]
fn native_ha_historical_restore_pending_stage_failure_cold_reconcile_never_replays_committed_operation() -> TestResult {
    let mut pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let migration_source = activate(&pipeline, leader)?;
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":1},"data":{"value":"pending-archive-A"}}))?,
        200, "pending-archive-A-write")?;
    let archive = export(&pipeline, leader, pipeline.admin())?;
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":2},"data":{"value":"pending-later-B"}}))?,
        200, "pending-later-B-write")?;
    let before = selection(&pipeline, leader, migration_source)?;
    assert_eq!(before.0, 0);

    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader].as_ref().ok_or("pending staging Service")?;
    let mut writer = lock_until(service, until).map_err(|_| "pending staging admission")?;
    // The bootstrap Actor has no precise-token state or finite-use debit.
    // Thus no unrelated observation-only root publication can legitimately
    // retire this pending source while this regression measures its survival.
    assert!(!writer.state.as_ref().ok_or("pending staging State")?.has_token_api_precision_state());
    let mut pending = admit(&mut writer, "POST", pipeline.admin(), until)?;
    drop(writer);
    let (observed, output) = pending.execute_snapshot_transfer(&mut &archive[..]);
    assert!(output.is_none());

    // Break actual ciphertext staging only after admission and complete body
    // authentication transport. The directory guard intentionally survives a
    // rename, so merely renaming the path would not exercise this failure.
    // Keep every existing file byte, then unlink the emptied directory while
    // the real runtime still holds its FD: the subsequent openat(CreateNew)
    // fails after a real Raft Begin and before any historical root CAS.
    let cipher_root = pipeline.configs[leader].raft_dir.join("native-v6-ciphertext");
    let saved_root = pipeline.configs[leader].raft_dir.join("pending-test-saved-ciphertext");
    private_directory(&saved_root)?;
    let files = fs::read_dir(&cipher_root)?.map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(!files.is_empty(), "real native source ciphertext must exist before the fault");
    for name in &files { fs::rename(cipher_root.join(name), saved_root.join(name))?; }
    fs::remove_dir(&cipher_root)?;
    let mut writer = lock_until(service, until).map_err(|_| "pending staging finalizer")?;
    let denied = writer.finish_external_request(*pending, observed);
    // Restore exactly the old fixture files before dropping the failed owner.
    // Only a new process can acquire this new directory; the old held FD is
    // still unlinked and cannot be silently rebound to the replacement path.
    private_directory(&cipher_root)?;
    for name in &files { fs::rename(saved_root.join(name), cipher_root.join(name))?; }
    fs::remove_dir(&saved_root)?;
    assert_eq!(denied.status, 503);
    assert_eq!(denied.body["root_attempted"], false);
    assert_eq!(denied.body["retry_allowed"], false);
    assert!(denied.body.get("data").is_none());
    let reference = denied.body["recovery_reference"].as_str()
        .ok_or("Begin failure must retain its exact recovery reference")?.to_owned();
    assert_eq!(writer.state.as_ref().ok_or("pending failed State")?.replay_epoch, 0);
    assert_eq!(writer.durable.as_ref().ok_or("pending failed Durable")?.replay_epoch(), 0);
    assert_eq!(writer.current_state_identity().map_err(|_| "pending failed identity")?.digest(),
        before.1.root_digest());
    assert!(writer.native_request_binding.is_none());
    drop(writer);
    drop(_scope);

    // Reopen the actual disk owner and TLS/Raft process without resubmitting
    // any archive. A fresh real quorum observation must still name that Begin.
    pipeline.stop_process(leader)?;
    let successor = pipeline.ready_leader()?;
    assert_ne!(successor, leader);
    rejoin_for_unseal(&mut pipeline, leader, migration_source)?;
    pipeline.assert_history(successor,
        &[(1, "seed-v5"), (2, "pending-archive-A"), (3, "pending-later-B")])?;
    assert_eq!(selection(&pipeline, successor, migration_source)?, before);
    assert_eq!(observed_pending_reference(&pipeline, successor)?, Some(reference.clone()));

    // A syntactically valid selector grants no Actor authority.
    {
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let service = pipeline.services[successor].as_ref().ok_or("pending denial Service")?;
        let mut writer = lock_until(service, until).map_err(|_| "pending denial writer")?;
        match writer.begin_native_snapshot_before(ServiceRequest::new("POST", SNAPSHOT, "",
            "synthetic-invalid-pending-token", json!({"cancel_pending_restore":reference})), until)
        {
            NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
                assert_eq!(response.status, 403);
                assert!(response.body.get("data").is_none());
            }
            _ => return Err("invalid pending Actor reached a transfer or redirect".into()),
        }
    }
    assert_eq!(observed_pending_reference(&pipeline, successor)?, Some(reference.clone()));
    let nonempty = expect(cancel_pending_restore(&pipeline, successor, &reference, b"x")?,
        400, "pending-cancellation-body-rejected")?;
    assert_eq!(nonempty.body["recovery_reference"], reference);
    assert_eq!(observed_pending_reference(&pipeline, successor)?, Some(reference.clone()));
    let raw = reference.strip_prefix("native-v6-restore-").ok_or("pending reference prefix")?;
    let other = format!("native-v6-restore-{}{}", if raw.starts_with('1') { "2" } else { "1" }, &raw[1..]);
    let different = expect(cancel_pending_restore(&pipeline, successor, &other, &[])?,
        200, "different-pending-operation-is-not-cancelled")?;
    assert_eq!(different.body["data"]["state"], "different_pending");
    assert_eq!(different.body["data"]["cancelled"], false);
    assert_eq!(observed_pending_reference(&pipeline, successor)?, Some(reference.clone()));
    assert_eq!(selection(&pipeline, successor, migration_source)?, before);

    let cancelled = expect(cancel_pending_restore(&pipeline, successor, &reference, &[])?,
        200, "matching-pending-operation-cancelled")?;
    assert_eq!(cancelled.body["data"]["state"], "cancelled");
    assert_eq!(cancelled.body["data"]["cancelled"], true);
    assert_eq!(cancelled.body["restore_performed"], false);
    assert_eq!(cancelled.body["retry_allowed"], false);
    assert_eq!(observed_pending_reference(&pipeline, successor)?, None);
    assert_eq!(selection(&pipeline, successor, migration_source)?, before);

    // A lost cancellation reply is reconciled by a NEW explicit request after
    // another cold owner reopen. Verified absence never starts a replacement.
    pipeline.stop_process(successor)?;
    let active = pipeline.ready_leader()?;
    rejoin_for_unseal(&mut pipeline, successor, migration_source)?;
    pipeline.assert_history(active,
        &[(1, "seed-v5"), (2, "pending-archive-A"), (3, "pending-later-B")])?;
    let absent = expect(cancel_pending_restore(&pipeline, active, &reference, &[])?,
        200, "cancelled-operation-remains-absent-after-cold-reopen")?;
    assert_eq!(absent.body["data"]["state"], "not_pending");
    assert_eq!(absent.body["restore_performed"], false);
    assert_eq!(observed_pending_reference(&pipeline, active)?, None);
    assert_eq!(selection(&pipeline, active, migration_source)?, before);

    // Only this separate, explicitly admitted archive request may Begin a NEW
    // operation. Reconciliation of its committed ID cannot replay its epoch.
    expect(restore(&pipeline, active, pipeline.admin(), &archive)?, 200,
        "new-explicit-restore-after-pending-cancellation")?;
    let installed = selection(&pipeline, active, migration_source)?;
    assert_eq!(installed.0, 1);
    assert_eq!(installed.1.epoch_transitions().len(), 1);
    let operation = installed.1.epoch_transitions().last().ok_or("new committed transition")?
        .operation_digest();
    let committed_reference = format!("native-v6-restore-{}", operation
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>());
    assert_ne!(committed_reference, reference);
    let committed = expect(cancel_pending_restore(&pipeline, active, &committed_reference, &[])?,
        200, "committed-operation-is-observed-not-replayed")?;
    assert_eq!(committed.body["data"]["state"], "committed");
    assert_eq!(committed.body["data"]["cancelled"], false);
    assert_eq!(committed.body["restore_performed"], false);
    assert_eq!(selection(&pipeline, active, migration_source)?, installed);
    pipeline.assert_history(active, &[(1, "seed-v5"), (2, "pending-archive-A")])?;
    expect(pipeline.call(active, "GET", "secret/data/pipeline/history", pipeline.admin(),
        json!({"version":3}))?, 404, "pending-recovery-future-B-version-absent")?;
    Ok(())
}

#[test]
fn native_ha_historical_restore_lost_reference_cold_inspection_requires_separate_exact_cancel() -> TestResult {
    let mut pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let migration_source = activate(&pipeline, leader)?;
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":1},"data":{"value":"inspect-archive-A"}}))?,
        200, "inspect-archive-A-write")?;
    let archive = export(&pipeline, leader, pipeline.admin())?;
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":2},"data":{"value":"inspect-later-B"}}))?,
        200, "inspect-later-B-write")?;
    let before = selection(&pipeline, leader, migration_source)?;
    lose_pending_restore_failure_response(&pipeline, leader, &archive)?;

    pipeline.stop_process(leader)?;
    let successor = pipeline.ready_leader()?;
    assert_ne!(successor, leader);
    rejoin_for_unseal(&mut pipeline, leader, migration_source)?;
    pipeline.assert_history(successor,
        &[(1, "seed-v5"), (2, "inspect-archive-A"), (3, "inspect-later-B")])?;
    assert_eq!(selection(&pipeline, successor, migration_source)?, before);

    // Discovery is not an unauthenticated status endpoint. Neither a bad
    // Actor nor extra/ambiguous fields can obtain a pending reference.
    for (token, query, status) in [
        ("synthetic-invalid-inspection-token", json!({"inspect_pending_restore":true}), 403),
        (pipeline.admin(), json!({"inspect_pending_restore":false}), 400),
        (pipeline.admin(), json!({"inspect_pending_restore":[true,true]}), 400),
        (pipeline.admin(), json!({"inspect_pending_restore":true,"force":true}), 400),
        (pipeline.admin(), json!({"inspect_pending_restore":true,
            "cancel_pending_restore":format!("native-v6-restore-{}", "1".repeat(64))}), 400),
    ] {
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let service = pipeline.services[successor].as_ref().ok_or("inspection refusal Service")?;
        let mut writer = lock_until(service, until).map_err(|_| "inspection refusal writer")?;
        match writer.begin_native_snapshot_before(
            ServiceRequest::new("POST", SNAPSHOT, "", token, query), until,
        ) {
            NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
                assert_eq!(response.status, status);
                assert!(response.body.get("data").is_none());
                assert!(response.body.get("recovery_reference").is_none());
            }
            _ => return Err("rejected inspection acquired a transfer or redirect".into()),
        }
    }
    let discovered = expect(inspect_pending_restore(&pipeline, successor, &[])?,
        200, "cold-root-inspection-recovers-lost-operation-reference")?;
    assert_eq!(discovered.body["data"]["state"], "pending");
    assert_eq!(discovered.body["data"]["cancelled"], false);
    assert_eq!(discovered.body["restore_performed"], false);
    let reference = discovered.body["data"]["recovery_reference"].as_str()
        .ok_or("new root inspection must return the actual pending reference")?.to_owned();
    assert_eq!(observed_pending_reference(&pipeline, successor)?, Some(reference.clone()));
    assert_eq!(selection(&pipeline, successor, migration_source)?, before);
    let nonempty = expect(inspect_pending_restore(&pipeline, successor, b"x")?,
        400, "inspection-requires-empty-body")?;
    assert!(nonempty.body.get("data").is_none());
    assert_eq!(observed_pending_reference(&pipeline, successor)?, Some(reference.clone()));

    // The inspection above cannot cancel even though it now knows the exact
    // pending operation. Only this separate explicitly selected request may
    // acquire the existing actual Cancel capability.
    let cancelled = expect(cancel_pending_restore(&pipeline, successor, &reference, &[])?,
        200, "discovered-pending-operation-requires-separate-exact-cancel")?;
    assert_eq!(cancelled.body["data"]["state"], "cancelled");
    assert_eq!(selection(&pipeline, successor, migration_source)?, before);
    let absent = expect(inspect_pending_restore(&pipeline, successor, &[])?,
        200, "inspection-reports-verified-absence-after-cancel")?;
    assert_eq!(absent.body["data"]["state"], "not_pending");
    assert!(absent.body["data"]["recovery_reference"].is_null());
    assert_eq!(observed_pending_reference(&pipeline, successor)?, None);
    assert_eq!(selection(&pipeline, successor, migration_source)?, before);

    expect(restore(&pipeline, successor, pipeline.admin(), &archive)?, 200,
        "inspection-does-not-replay-restore-without-a-new-archive-request")?;
    let installed = selection(&pipeline, successor, migration_source)?;
    assert_eq!(installed.0, 1);
    let no_pending = expect(inspect_pending_restore(&pipeline, successor, &[])?,
        200, "inspection-does-not-return-a-historical-committed-reference")?;
    assert_eq!(no_pending.body["data"]["state"], "not_pending");
    assert!(no_pending.body["data"]["recovery_reference"].is_null());
    assert_eq!(no_pending.body["restore_performed"], false);
    assert_eq!(selection(&pipeline, successor, migration_source)?, installed);
    assert_eq!(installed.1.epoch_transitions().len(), 1);

    // A real authenticated non-root principal remains ineligible even with
    // update/sudo on this exact route. Mint it after the pending-flow checks:
    // token creation legitimately adds precision state and a new ordinary root.
    expect(pipeline.call(successor, "PUT", "sys/policies/acl/inspect-not-root", pipeline.admin(),
        json!({"policy":"path \"sys/storage/raft/snapshot\" { capabilities = [\"update\",\"sudo\"] }"}))?,
        204, "inspection-non-root-policy")?;
    let mut issued = expect(pipeline.call(successor, "POST", "auth/token/create", pipeline.admin(),
        json!({"policies":["inspect-not-root"],"ttl":"300s","no_default_policy":true,"no_parent":true}))?,
        200, "inspection-authenticated-non-root-token")?;
    let limited = secret_field(&mut issued, "/auth/client_token")?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[successor].as_ref().ok_or("non-root inspection Service")?;
    let mut writer = lock_until(service, until).map_err(|_| "non-root inspection writer")?;
    match writer.begin_native_snapshot_before(
        ServiceRequest::new("POST", SNAPSHOT, "", limited.as_str(),
            json!({"inspect_pending_restore":true})), until,
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            assert_eq!(response.status, 403);
            assert!(response.body.get("data").is_none());
            assert!(response.body.get("recovery_reference").is_none());
        }
        _ => return Err("non-root inspection acquired a transfer or redirect".into()),
    }
    Ok(())
}
