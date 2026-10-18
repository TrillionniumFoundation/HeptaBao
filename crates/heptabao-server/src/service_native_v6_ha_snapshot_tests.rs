//! Existing Service admission/finalization over the real three-voter mTLS
//! pipeline. This is an export test, not a restore or physical-host claim.
use super::*;
use crate::crypto::AeadBarrier;
use crate::ha::native_v6_backup::{NativeV6ArchiveSelection, validate_native_v6_archive};
use crate::snapshot_archive::{self, Metadata};
use crate::snapshot_file::SnapshotSpool;
use heptabao_durable_service::Barrier;
use std::io::Read;

fn pending(
    service: &mut Service,
    token: &str,
    deadline: Instant,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_native_snapshot_before(
        ServiceRequest::new("GET", "sys/storage/raft/snapshot", "", token, json!({})),
        deadline,
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(pending)) => Ok(pending),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            errors_only("native-HA-snapshot-admission", &response);
            Err(format!("snapshot admission HTTP {}", response.status).into())
        }
        NativeSnapshotAdmission::Redirect(_) => Err("selected leader redirected snapshot".into()),
    }
}

#[test]
fn native_ha_snapshot_service_export_binds_both_closures_and_rejects_changed_root() -> TestResult {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "sys/internal/native-v6/activate",
            pipeline.admin(),
            json!({}),
        )?,
        204,
        "native-snapshot-activation",
    )?;
    let value = "native-ha-snapshot-history-block".repeat(8192);
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({"options":{"cas":1},"data":{"value":value}}),
        )?,
        200,
        "native-snapshot-history",
    )?;
    let original = pipeline.native_selection(leader)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader].as_ref().ok_or("Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "snapshot writer lock")?;
    assert!(writer.native_candidate_profile.is_none());
    let denied = writer.begin_native_snapshot_before(
        ServiceRequest::new("GET", "sys/storage/raft/snapshot", "", "", json!({})),
        until,
    );
    assert!(matches!(
        denied,
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(ref response))
            if response.status == 403
    ));
    assert!(writer.snapshot_spool.is_none());
    let generation = writer
        .durable
        .as_ref()
        .ok_or("durable absent")?
        .generation();
    let barrier = AeadBarrier::new(**writer.barrier_key.as_ref().ok_or("barrier absent")?)?;
    let mut request = pending(&mut writer, pipeline.admin(), until)?;
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    expect(
        writer.finish_external_request(*request, result),
        200,
        "native-snapshot-finalization",
    )?;
    assert_eq!(
        writer
            .durable
            .as_ref()
            .ok_or("durable absent")?
            .generation(),
        generation
    );
    drop(writer);
    let output = file.ok_or("snapshot output absent")?;
    let verify_dir = pipeline.files.path.join("snapshot-verifier");
    private_directory(&verify_dir)?;
    let spool = SnapshotSpool::open(&verify_dir)?;
    let lease = spool.lease()?;
    let imported = snapshot_archive::import(output, &lease, until)?;
    assert!(imported.metadata.is_v6_ha());
    assert_eq!(imported.metadata.generation(), generation);
    let plain_sums = barrier.open(snapshot_archive::CHECKSUM_CONTEXT, &imported.sealed_sums)?;
    assert_eq!(plain_sums.as_slice(), imported.sums.as_slice());
    let json = serde_json::to_value(&imported.metadata)?;
    assert_eq!(json["format"], "heptabao-native-ha-object-snapshot-v1");
    let hex_digest = json["seal_identity"]["sha256"]
        .as_str()
        .ok_or("seal digest")?;
    let mut seal_digest = [0u8; 32];
    for (slot, pair) in seal_digest
        .iter_mut()
        .zip(hex_digest.as_bytes().chunks_exact(2))
    {
        *slot = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    let process = pipeline.processes[leader]
        .as_ref()
        .ok_or("process absent")?
        .lock_for_request()
        .map_err(|_| "snapshot validation process lock")?;
    let selected = process
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("committed root absent")?;
    let selection =
        NativeV6ArchiveSelection::from_committed(selected.enrollment(), selected.published())?;
    let mut verified = validate_native_v6_archive(
        imported.state,
        &selection,
        seal_digest,
        &barrier,
        OriginalDeadline::capture()?,
        &mut || Ok(()),
    )?;
    assert_eq!(verified.report().local.generation, generation);
    assert!(verified.report().shared_ciphertext_bytes > value.len() as u64);
    let mut leaves = 0;
    verified.visit_shared_ciphertext(&mut || Ok(()), &mut |_, _| {
        leaves += 1;
        Ok(())
    })?;
    assert_eq!(leaves, verified.report().shared_object_count);
    let mut local = lease.file(crate::snapshot_file::MAX_V6_SNAPSHOT_STATE, until)?;
    verified.copy_local_pack_to(&mut local, &mut || Ok(()))?;
    local.rewind_checked()?;
    let mut magic = [0; 8];
    local.read_exact(&mut magic)?;
    assert_eq!(&magic, b"HBV6PK01");
    process.verify_native_v6_committed_read(&selected)?;
    drop((process, local, verified, lease, spool, scope));
    assert_eq!(pipeline.native_selection(leader)?, original);

    // Exercise the actual affine transfer across a later live root publication.
    // The output may exist privately; it must never finalize successfully.
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let mut writer = lock_until(service, until).map_err(|_| "second snapshot writer")?;
    let mut request = pending(&mut writer, pipeline.admin(), until)?;
    let (result, private_file) = request.execute_snapshot_transfer(&mut io::empty());
    drop(writer);
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({"options":{"cas":2},"data":{"value":"changed-after-export"}}),
        )?,
        200,
        "snapshot-racing-root-publication",
    )?;
    let changed = pipeline.native_selection(leader)?;
    assert_ne!(changed, original);
    let mut writer = lock_until(service, until).map_err(|_| "stale snapshot finalizer")?;
    let response = writer.finish_external_request(*request, result);
    assert!(response.status == 409 || response.status == 503);
    assert!(response.body.get("data").is_none());
    drop((writer, private_file));
    assert_eq!(pipeline.native_selection(leader)?, changed);
    Ok(())
}

#[test]
fn native_ha_snapshot_metadata_does_not_change_local_or_legacy_limits() -> TestResult {
    let seal = [7; 32];
    let beyond_local = crate::snapshot_file::MAX_V6_SNAPSHOT_STATE + 1;
    let ha = Metadata::new_v6_ha(1, beyond_local, &seal);
    assert!(ha.valid() && ha.is_v6() && ha.is_v6_ha());
    assert!(!Metadata::new_v6(1, beyond_local, &seal).valid());
    assert!(!Metadata::new(1, beyond_local, &seal).valid());
    assert!(!Metadata::new_v6_ha(0, beyond_local, &seal).valid());
    assert!(
        !Metadata::new_v6_ha(1, crate::snapshot_file::MAX_V6_HA_SNAPSHOT_STATE + 1, &seal).valid()
    );
    assert!(crate::snapshot_file::MAX_V6_HA_SNAPSHOT_STATE < 1 << 33);
    let mut encoded = serde_json::to_value(ha)?;
    encoded["state_format"] = json!("heptabao-encrypted-object-backup/HBV6PK01");
    assert!(!serde_json::from_value::<Metadata>(encoded)?.valid());
    Ok(())
}

#[test]
fn native_ha_snapshot_terminal_clock_keeps_archive_a_and_checks_actual_successor_b() -> TestResult {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let mut issued = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/create",
            pipeline.admin(),
            json!({"policies":["root"],"ttl":"60s","no_default_policy":true,"no_parent":true}),
        )?,
        200,
        "snapshot-precision-token-setup",
    )?;
    let token = secret_field(&mut issued, "/auth/client_token")?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "sys/internal/native-v6/activate",
            pipeline.admin(),
            json!({}),
        )?,
        204,
        "snapshot-precision-activation",
    )?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader].as_ref().ok_or("Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "snapshot precision writer")?;
    assert!(
        writer
            .state
            .as_ref()
            .ok_or("state absent")?
            .has_token_api_precision_state()
    );
    let barrier = AeadBarrier::new(**writer.barrier_key.as_ref().ok_or("barrier absent")?)?;
    let mut request = pending(&mut writer, &token, until)?;
    let archive_generation = writer
        .durable
        .as_ref()
        .ok_or("durable absent")?
        .generation();
    let process = pipeline.processes[leader]
        .as_ref()
        .ok_or("process absent")?;
    let process_guard = process
        .lock_for_request()
        .map_err(|_| "original selection lock")?;
    let original = process_guard
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("original root absent")?;
    let archive_selection =
        NativeV6ArchiveSelection::from_committed(original.enrollment(), original.published())?;
    let a = original.published().clone();
    drop(process_guard);
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    // The precise terminal observation must be strictly later than admission.
    thread::sleep(Duration::from_millis(2));
    expect(
        writer.finish_external_request(*request, result),
        200,
        "snapshot-precision-after-audit",
    )?;
    assert!(writer.native_request_binding.is_none());
    assert!(!writer.recovery_required);
    let final_generation = writer
        .durable
        .as_ref()
        .ok_or("durable absent")?
        .generation();
    assert!(final_generation > archive_generation);
    drop(writer);
    let process_guard = process
        .lock_for_request()
        .map_err(|_| "terminal selection lock")?;
    let current = process_guard
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("terminal root absent")?;
    let b = current.published();
    assert_eq!(b.intent().prior_root_digest, a.root_digest());
    assert_eq!(b.intent().prior_generation, a.generation());
    assert_eq!(
        b.intent().expected_previous_commit_index,
        a.publication_log_id().index
    );
    assert_eq!(b.intent().epoch, a.intent().epoch);
    assert_eq!(b.generation(), a.generation() + 1);
    assert_ne!(b.root_digest(), a.root_digest());
    let verify_dir = pipeline.files.path.join("snapshot-terminal-verifier");
    private_directory(&verify_dir)?;
    let spool = SnapshotSpool::open(&verify_dir)?;
    let lease = spool.lease()?;
    let imported = snapshot_archive::import(file.ok_or("archive absent")?, &lease, until)?;
    assert_eq!(imported.metadata.generation(), archive_generation);
    assert_ne!(imported.metadata.generation(), final_generation);
    let metadata = serde_json::to_value(&imported.metadata)?;
    let digest = metadata["seal_identity"]["sha256"]
        .as_str()
        .ok_or("archive seal digest")?;
    let mut expected_seal = [0u8; 32];
    for (slot, pair) in expected_seal
        .iter_mut()
        .zip(digest.as_bytes().chunks_exact(2))
    {
        *slot = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    let verified = validate_native_v6_archive(
        imported.state,
        &archive_selection,
        expected_seal,
        &barrier,
        OriginalDeadline::capture()?,
        &mut || Ok(()),
    )?;
    assert_eq!(verified.report().local.generation, archive_generation);
    process_guard.verify_native_v6_committed_read(&current)?;
    Ok(())
}
