//! Actual three-voter/mTLS Service export -> bounded upload -> warm repair.
//! These are Service transport-owner regressions, not physical-host claims.
use super::*;
use heptabao_raft_runtime::{LocalV6BlobError, RecordObjectRef};
use sha2::{Digest, Sha256};
use std::io::Read;

const REPAIR: &str = "sys/storage/raft/snapshot-repair";
type LocalAnchor = (u64, u64, Vec<Option<Vec<u8>>>);

fn activate(pipeline: &Pipeline, leader: usize) -> TestResult {
    expect(pipeline.call(leader, "POST", "sys/internal/native-v6/activate",
        pipeline.admin(), json!({}))?, 204, "repair-native-activation")?;
    Ok(())
}

fn local_anchor(service: &Service) -> TestResult<LocalAnchor> {
    let durable = service.durable.as_ref().ok_or("repair durable absent")?;
    let resources = [
        "state", native_v6_reader::ACTIVE_CURSOR_RESOURCE,
        native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE,
        native_v6_ha_install::HA_CURSOR_RESOURCE,
    ].into_iter().map(|resource| {
        durable.get("system", resource).map(|secret| secret.map(|value| value.expose().to_vec()))
    }).collect::<Result<Vec<_>, _>>()?;
    Ok((durable.generation(), durable.replay_epoch(), resources))
}

fn admitted(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    until: Instant,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_native_snapshot_before(
        ServiceRequest::new(method, path, "", token, json!({})), until,
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(pending)) => Ok(pending),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            errors_only("repair-admission", &response);
            Err(format!("repair admission HTTP {}", response.status).into())
        }
        NativeSnapshotAdmission::Redirect(_) => Err("repair leader unexpectedly redirected".into()),
    }
}

fn export(pipeline: &Pipeline, leader: usize) -> TestResult<Vec<u8>> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader].as_ref().ok_or("repair Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "export writer")?;
    let mut pending = admitted(&mut writer, "GET", "sys/storage/raft/snapshot", pipeline.admin(), until)?;
    let (result, file) = pending.execute_snapshot_transfer(&mut io::empty());
    expect(writer.finish_external_request(*pending, result), 200, "repair-source-export")?;
    drop(writer);
    let mut file = file.ok_or("repair-source archive absent")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn selected_shared(pipeline: &Pipeline, leader: usize) -> TestResult<Vec<(RecordObjectRef, Vec<u8>)>> {
    let _scope = scope();
    let process = pipeline.processes[leader].as_ref().ok_or("repair process absent")?
        .lock_for_request().map_err(|_| "repair selection lock")?;
    let read = process.native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("repair selected root absent")?;
    let files = process.with_native_v6_source(&read, |_, store| {
        let (_, refs) = store.reopen_root_closure_archive(read.published(), &mut || Ok(()))?;
        refs.into_iter().map(|reference| {
            let bytes = store.read_local_checked(&reference, &mut || Ok(()))?;
            Ok((reference, bytes))
        }).collect::<Result<Vec<_>, LocalV6BlobError>>()
    })??;
    assert!(!files.is_empty());
    Ok(files)
}

fn leaf(pipeline: &Pipeline, voter: usize, reference: &RecordObjectRef) -> PathBuf {
    pipeline.configs[voter].raft_dir.join("native-v6-ciphertext")
        .join(format!("v6-{}.blob", hex(&reference.id)))
}

fn lose_all_shared(pipeline: &Pipeline, files: &[(RecordObjectRef, Vec<u8>)]) -> TestResult {
    // Exact selected ciphertext in this fresh synthetic Root only. Raft logs,
    // local-barrier files, Auth, epochs and cursors remain physically intact.
    for voter in 0..3 {
        for (reference, _) in files {
            let path = leaf(pipeline, voter, reference);
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        File::open(pipeline.configs[voter].raft_dir.join("native-v6-ciphertext"))?.sync_all()?;
    }
    assert_missing(pipeline, files);
    Ok(())
}

fn assert_missing(pipeline: &Pipeline, files: &[(RecordObjectRef, Vec<u8>)]) {
    for voter in 0..3 {
        for (reference, _) in files {
            assert!(!leaf(pipeline, voter, reference).exists());
        }
    }
}

fn repair(pipeline: &Pipeline, leader: usize, archive: &[u8]) -> TestResult<Response> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader].as_ref().ok_or("repair Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "repair writer")?;
    let mut pending = admitted(&mut writer, "POST", REPAIR, pipeline.admin(), until)?;
    assert!(writer.native_request_binding.is_none());
    drop(writer);
    let (result, file) = pending.execute_snapshot_transfer(&mut &archive[..]);
    assert!(file.is_none());
    let mut writer = lock_until(service, until).map_err(|_| "repair finalizer")?;
    let response = writer.finish_external_request(*pending, result);
    assert!(writer.native_request_binding.is_none());
    Ok(response)
}

fn inflate_transport(archive: &[u8]) -> io::Result<Vec<u8>> {
    let mut plain = Vec::new();
    flate2::read::GzDecoder::new(archive).read_to_end(&mut plain)?;
    Ok(plain)
}

fn entry_extent(tar: &[u8], at: usize, name: &[u8]) -> TestResult<(usize, usize)> {
    let header = tar.get(at..at.checked_add(512).ok_or("tar header overflow")?)
        .ok_or("tar header missing")?;
    if header.get(..name.len()) != Some(name) || header.get(name.len()) != Some(&0) {
        return Err("unexpected synthetic tar entry".into());
    }
    let length = usize::from_str_radix(std::str::from_utf8(&header[124..135])?, 8)?;
    let start = at.checked_add(512).ok_or("tar start overflow")?;
    let end = start.checked_add(length).ok_or("tar end overflow")?;
    tar.get(start..end).ok_or("tar entry data missing")?;
    Ok((start, end))
}

fn corrupt_authenticated_transport_state(archive: &[u8], rehash_unkeyed: bool)
-> TestResult<Vec<u8>> {
    let mut tar = inflate_transport(archive)?;
    let metadata = entry_extent(&tar, 0, b"meta.json")?;
    let state_header = metadata.1.checked_add(511).ok_or("tar alignment overflow")? / 512 * 512;
    let state = entry_extent(&tar, state_header, b"state.bin")?;
    if state.1 - state.0 < 32 {
        return Err("synthetic native state too short".into());
    }
    // Change an actual SHA/AEAD-bound pack byte, retaining the pack magic.
    // A compressed-stream middle bit can instead be unused DEFLATE padding.
    let target = state.0 + (state.1 - state.0) / 2;
    tar[target] ^= 1;
    if rehash_unkeyed {
        let sums_header = state.1.checked_add(511).ok_or("tar sums overflow")? / 512 * 512;
        let checksums = entry_extent(&tar, sums_header, b"SHA256SUMS")?;
        let digest: [u8; 32] = Sha256::digest(&tar[state.0..state.1]).into();
        let sums = crate::snapshot_archive::sums(&tar[metadata.0..metadata.1], &digest);
        if checksums.1 - checksums.0 != sums.len() {
            return Err("synthetic checksum length changed".into());
        }
        tar[checksums.0..checksums.1].copy_from_slice(&sums);
        // The sealed checksum is deliberately unchanged: recomputing public
        // hashes can never mint the actual barrier owner's authentication.
    }
    let mut encoded = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoded.write_all(&tar)?;
    let encoded = encoded.finish()?;
    assert_ne!(inflate_transport(&encoded)?, inflate_transport(archive)?);
    Ok(encoded)
}

#[test]
fn native_ha_snapshot_repair_all_donors_missing_preserves_four_conditions_and_cold_reopens() -> TestResult {
    let mut pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    activate(&pipeline, leader)?;
    let value = "archive-repair-retained-history".repeat(4096);
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":1},"data":{"value":value}}))?, 200, "repair-history-write")?;
    let before = pipeline.native_selection(leader)?;
    let local = pipeline.with_service(leader, local_anchor)?;
    let archive = export(&pipeline, leader)?;
    let files = selected_shared(&pipeline, leader)?;
    lose_all_shared(&pipeline, &files)?;
    // Admission must still deny anonymous callers before it allocates a lease.
    {
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let service = pipeline.services[leader].as_ref().ok_or("repair Service")?;
        let mut writer = lock_until(service, until).map_err(|_| "anonymous repair writer")?;
        let denied = writer.begin_native_snapshot_before(
            ServiceRequest::new("POST", REPAIR, "", "", json!({})), until,
        );
        assert!(matches!(denied, NativeSnapshotAdmission::Execute(RequestExecution::Complete(ref response))
            if response.status == 403));
        assert!(writer.snapshot_spool.as_ref().ok_or("export spool")?.lease().is_ok());
    }
    assert_missing(&pipeline, &files);
    let response = expect(repair(&pipeline, leader, &archive)?, 200, "actual-warm-archive-repair")?;
    assert_eq!(response.body["data"]["shared_object_count"], files.len() as u64);
    for (reference, bytes) in &files {
        assert!(fs::read(leaf(&pipeline, leader, reference))? == *bytes);
    }
    assert_eq!(pipeline.native_selection(leader)?, before);
    assert!(pipeline.with_service(leader, local_anchor)? == local);
    for voter in 0..3 {
        pipeline.assert_history(voter, &[(1, "seed-v5"), (2, &value)])?;
    }
    pipeline.stop_process(leader)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, leader);
    pipeline.start_process(leader)?;
    pipeline.unseal(leader)?;
    assert_eq!(pipeline.native_selection(leader)?, before);
    pipeline.assert_history(leader, &[(1, "seed-v5"), (2, &value)])?;
    Ok(())
}

#[test]
fn native_ha_snapshot_repair_rejects_historical_archive_and_preserves_corrupt_registered_leaf() -> TestResult {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    activate(&pipeline, leader)?;
    let old = export(&pipeline, leader)?;
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":1},"data":{"value":"later-current-root"}}))?,
        200, "repair-later-current-root")?;
    let current = export(&pipeline, leader)?;
    let local = pipeline.with_service(leader, local_anchor)?;
    let before = pipeline.native_selection(leader)?;
    let files = selected_shared(&pipeline, leader)?;
    lose_all_shared(&pipeline, &files)?;
    let stale = repair(&pipeline, leader, &old)?;
    assert_eq!(stale.status, 409);
    assert!(stale.body.get("data").is_none());
    assert_missing(&pipeline, &files);
    // Preserve the original R2 middle-bit experiment as a semantic diagnostic.
    // Valid alternate DEFLATE padding is not an authenticated-content change.
    let mut middle_flip = current.clone();
    let middle = middle_flip.len() / 2;
    middle_flip[middle] ^= 1;
    let original_tar = inflate_transport(&current)?;
    let changed_tar = inflate_transport(&middle_flip);
    let same_payload = changed_tar.as_ref().is_ok_and(|bytes| bytes == &original_tar);
    eprintln!("HBV6-ARCHIVE-MIDDLE-FLIP same_decoded_payload={same_payload} compressed_bytes={} decoded_bytes={}",
        current.len(), original_tar.len());
    if !same_payload {
        let rejected = repair(&pipeline, leader, &middle_flip)?;
        assert!(rejected.status >= 400 && rejected.body.get("data").is_none(),
            "changed/invalid decoded transport accepted: HTTP {}", rejected.status);
        assert_missing(&pipeline, &files);
    }
    // Deterministically altered authenticated content, including a forged
    // unkeyed SHA256SUMS, must never reach a shared staging operation.
    for rehash_unkeyed in [false, true] {
        let damaged = corrupt_authenticated_transport_state(&current, rehash_unkeyed)?;
        let rejected = repair(&pipeline, leader, &damaged)?;
        assert!(rejected.status >= 400 && rejected.body.get("data").is_none(),
            "changed authenticated pack accepted: rehash={rehash_unkeyed} HTTP {}", rejected.status);
        assert_missing(&pipeline, &files);
    }
    let mut bad_crc = current.clone();
    let crc_at = bad_crc.len().checked_sub(8).ok_or("gzip trailer missing")?;
    bad_crc[crc_at] ^= 1;
    assert!(inflate_transport(&bad_crc).is_err());
    let rejected = repair(&pipeline, leader, &bad_crc)?;
    assert!(rejected.status >= 400 && rejected.body.get("data").is_none(),
        "corrupt gzip CRC accepted: HTTP {}", rejected.status);
    assert_missing(&pipeline, &files);
    let (reference, bytes) = files.first().ok_or("repair selected leaf")?;
    let path = leaf(&pipeline, leader, reference);
    let mut corrupt = bytes.clone();
    *corrupt.last_mut().ok_or("repair nonempty ciphertext")? ^= 1;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut bad = options.open(&path)?;
    bad.write_all(&corrupt)?;
    bad.sync_all()?;
    drop(bad);
    let rejected = repair(&pipeline, leader, &current)?;
    assert!(rejected.status >= 400 && rejected.body.get("data").is_none());
    assert!(fs::read(&path)? == corrupt);
    assert!(pipeline.with_service(leader, local_anchor)? == local);
    // Explicit fixture quarantine, never an automatic repair overwrite.
    fs::rename(&path, path.with_extension("corrupt-repair-fixture"))?;
    expect(repair(&pipeline, leader, &current)?, 200, "repair-after-explicit-fixture-quarantine")?;
    assert_eq!(pipeline.native_selection(leader)?, before);
    Ok(())
}

#[test]
fn native_ha_snapshot_repair_rejects_changed_source_after_upload_and_cancel_drops_custody() -> TestResult {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    activate(&pipeline, leader)?;
    let archive = export(&pipeline, leader)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader].as_ref().ok_or("repair Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "repair original writer")?;
    let cancelled = admitted(&mut writer, "POST", REPAIR, pipeline.admin(), until)?;
    drop(cancelled);
    assert!(!writer.recovery_required && writer.native_request_binding.is_none());
    let mut pending = admitted(&mut writer, "POST", REPAIR, pipeline.admin(), until)?;
    drop(writer);
    let (result, _) = pending.execute_snapshot_transfer(&mut archive.as_slice());
    // Publish through the actual Service and actual TLS majority while the
    // original archive owner is outside the writer receiving its body.
    expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
        json!({"options":{"cas":1},"data":{"value":"changed-during-upload"}}))?,
        200, "repair-concurrent-root")?;
    let changed = pipeline.native_selection(leader)?;
    let files = selected_shared(&pipeline, leader)?;
    lose_all_shared(&pipeline, &files)?;
    let mut writer = lock_until(service, until).map_err(|_| "repair changed-source writer")?;
    let response = writer.finish_external_request(*pending, result);
    assert!(response.status >= 400 && response.body.get("data").is_none());
    assert!(writer.native_request_binding.is_none());
    assert_eq!(writer.current_state_identity().map_err(|_| "repair current identity")?.digest(), changed.1);
    drop((writer, scope));
    assert_missing(&pipeline, &files);
    Ok(())
}

#[test]
fn native_ha_snapshot_repair_mandatory_response_audit_failure_fences_completed_physical_repair() -> TestResult {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    activate(&pipeline, leader)?;
    let archive = export(&pipeline, leader)?;
    let files = selected_shared(&pipeline, leader)?;
    lose_all_shared(&pipeline, &files)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader].as_ref().ok_or("repair Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "repair audit writer")?;
    let before = local_anchor(&writer)?;
    let mut pending = admitted(&mut writer, "POST", REPAIR, pipeline.admin(), until)?;
    let (result, _) = pending.execute_snapshot_transfer(&mut archive.as_slice());
    // Existing mandatory-audit I/O fault, after successful request audit. No
    // early audit_failed flag prevents the physical path from being exercised.
    writer.audit_capacity = 0;
    let response = writer.finish_external_request(*pending, result);
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(writer.recovery_required && writer.ha_activation.is_none());
    assert!(local_anchor(&writer)? == before);
    for (reference, bytes) in &files {
        assert!(fs::read(leaf(&pipeline, leader, reference))? == *bytes);
    }
    Ok(())
}
