//! Additional refusal probes through the actual historical POST admission,
//! upload, preparation and finalization path. The archive is exported by this
//! same live three-voter fixture before a real later business publication.
//! Neither observation can return a result or replace an authority gate.
use super::*;

// A real client receives the complete encrypted download before it starts a
// separate upload. SnapshotFile is a live transfer capability, not detached
// client bytes: retaining it retains the Service's exclusive SnapshotLease.
fn receive_completed_archive(
    mut output: crate::snapshot_file::SnapshotFile,
    deadline: Instant,
) -> TestResult<Zeroizing<Vec<u8>>> {
    let expected = output.len();
    assert!(expected > 0 && expected <= crate::snapshot_file::MAX_NATIVE_ARCHIVE);
    output.rewind_checked()?;
    let mut bytes = Zeroizing::new(Vec::new());
    // Observe EOF rather than accepting a truncated prefix. One byte beyond
    // the actual bounded length also detects an unexpected longer file.
    (&mut output).take(expected + 1).read_to_end(&mut bytes)?;
    assert_eq!(bytes.len() as u64, expected);
    assert!(
        Instant::now() < deadline,
        "download retains its original request budget"
    );
    drop(output);
    Ok(bytes)
}

fn archive_then_advance(pipeline: &Pipeline, leader: usize) -> TestResult<Zeroizing<Vec<u8>>> {
    let archived = pipeline.native_selection(leader)?;
    let archive = {
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let service = pipeline.services[leader].as_ref().ok_or("Service absent")?;
        let mut writer = lock_until(service, until).map_err(|_| "historical export writer")?;
        let mut request = pending(&mut writer, pipeline.admin(), until)?;
        let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
        expect(
            writer.finish_external_request(*request, result),
            200,
            "borrowed-historical-real-archive",
        )?;
        receive_completed_archive(file.ok_or("historical archive absent")?, until)?
    };
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({"options":{"cas":1},"data":{"value":"after-real-historical-archive"}}),
        )?,
        200,
        "borrowed-historical-later-business-root",
    )?;
    assert_ne!(pipeline.native_selection(leader)?, archived);
    Ok(archive)
}

fn pending_restore(
    service: &mut Service,
    token: &str,
    deadline: Instant,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_native_snapshot_before(
        ServiceRequest::new("POST", SNAPSHOT_PATH, "", token, json!({})),
        deadline,
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(pending)) => Ok(pending),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            errors_only("borrowed-historical-admission", &response);
            Err(format!("historical admission HTTP {}", response.status).into())
        }
        NativeSnapshotAdmission::Redirect(_) => Err("selected leader redirected restore".into()),
        #[cfg(feature = "native-v6-ha")]
        NativeSnapshotAdmission::Forward(_) => Err("selected leader forwarded restore".into()),
    }
}

fn authorize_restore(
    service: &Service,
    actor: &Principal,
    clock: RequestClock,
) -> Result<(), Response> {
    let observed = clock
        .observed_at()
        .map_err(|_| Response::error(503, "historical test original clock unavailable"))?;
    service
        .state
        .as_ref()
        .ok_or_else(|| Response::error(503, "historical test state unavailable"))?
        .auth
        .authorize_request_observed(
            actor,
            "",
            SNAPSHOT_PATH,
            "update",
            AuthorityTime::Precise(observed),
        )
        .map_err(|error| Response::error(error.status, &error.message))
}

#[test]
fn borrowed_historical_prepare_rejects_live_seal_change_at_original_source_gate() -> TestResult {
    let (pipeline, leader) = activated()?;
    let archive = archive_then_advance(&pipeline, leader)?;
    let selected = pipeline.native_selection(leader)?;
    let began = Instant::now();
    let until = began + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, began)?;
    let service = pipeline.services[leader].as_ref().ok_or("Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "historical seal writer")?;
    let mut request = pending_restore(&mut writer, pipeline.admin(), until)?;
    let identity = writer
        .current_state_identity()
        .map_err(|_| "identity absent")?;
    let epoch = writer.state.as_ref().ok_or("state absent")?.replay_epoch;
    let generation = writer
        .durable
        .as_ref()
        .ok_or("durable absent")?
        .generation();
    let flags = (writer.recovery_required, writer.audit_failed);
    let moved = Rc::new(Cell::new(false));
    let seal = RestoreSeal {
        original: writer.data_dir.join(SEAL_METADATA_FILE),
        held: writer.data_dir.join("borrowed-historical-owned-seal-held"),
        moved: Rc::clone(&moved),
    };
    assert!(fs::symlink_metadata(&seal.original)?.file_type().is_file());
    assert!(!seal.held.try_exists()?);
    let original = seal.original.clone();
    let held = seal.held.clone();
    let observed = Rc::new(Cell::new(false));
    let seen = Rc::clone(&observed);
    let observation = writer
        .observe_historical_prepare_original_source_once(
            until,
            move |service, actual_actor, actual_identity, original_until| {
                assert_eq!(actual_identity, identity);
                assert_eq!(original_until, until);
                assert_eq!(service.current_state_identity().ok(), Some(identity));
                assert!(actual_actor.is_root());
                assert!(authorize_restore(service, actual_actor, clock).is_ok());
                assert!(Instant::now() < until);
                assert!(
                    !seen.replace(true),
                    "one actual original source boundary only"
                );
                assert!(
                    fs::rename(&original, &held).is_ok(),
                    "move only this fixture's actual seal inode"
                );
                moved.set(true);
            },
        )
        .map_err(|_| "historical observation refused")?;
    let mut reader = archive.as_slice();
    let (result, output) = request.execute_snapshot_transfer(&mut reader);
    assert!(output.is_none());
    let response = writer.finish_external_request(*request, result);
    drop(observation);
    // Restore that same inode even if the product unexpectedly accepted it.
    seal.restore()?;
    assert!(
        observed.get(),
        "the actual borrowed prepare boundary must run"
    );
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.unwrapped_json.is_none() && response.consistency_index.is_none());
    assert!(
        Instant::now() < until,
        "the original 15-second budget remains live"
    );
    assert_eq!(writer.current_state_identity().ok(), Some(identity));
    assert_eq!(
        writer.state.as_ref().ok_or("state absent")?.replay_epoch,
        epoch
    );
    let durable = writer
        .durable
        .as_ref()
        .ok_or("same durable owner not returned")?;
    assert_eq!(durable.generation(), generation);
    assert_eq!(durable.replay_epoch(), epoch);
    assert!(!durable.recovery_required());
    assert_eq!((writer.recovery_required, writer.audit_failed), flags);
    drop(writer);
    assert_eq!(pipeline.native_selection(leader)?, selected);
    Ok(())
}

#[test]
fn borrowed_historical_prepare_rejects_live_seal_change_after_actual_archive_object_read()
-> TestResult {
    let (pipeline, leader) = activated()?;
    let archive = archive_then_advance(&pipeline, leader)?;
    let selected = pipeline.native_selection(leader)?;
    let began = Instant::now();
    let until = began + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, began)?;
    let service = pipeline.services[leader].as_ref().ok_or("Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "historical seal writer")?;
    let mut request = pending_restore(&mut writer, pipeline.admin(), until)?;
    let identity = writer
        .current_state_identity()
        .map_err(|_| "identity absent")?;
    let epoch = writer.state.as_ref().ok_or("state absent")?.replay_epoch;
    let generation = writer
        .durable
        .as_ref()
        .ok_or("durable absent")?
        .generation();
    let flags = (writer.recovery_required, writer.audit_failed);
    let moved = Rc::new(Cell::new(false));
    let seal = RestoreSeal {
        original: writer.data_dir.join(SEAL_METADATA_FILE),
        held: writer
            .data_dir
            .join("borrowed-historical-after-object-read-seal-held"),
        moved: Rc::clone(&moved),
    };
    assert!(fs::symlink_metadata(&seal.original)?.file_type().is_file());
    assert!(!seal.held.try_exists()?);
    let original = seal.original.clone();
    let held = seal.held.clone();
    let observed = Rc::new(Cell::new(false));
    let seen = Rc::clone(&observed);
    let observation = writer
        .observe_historical_prepare_archive_read_once(
            until,
            move |service, actual_actor, actual_identity, original_until| {
                assert_eq!(actual_identity, identity);
                assert_eq!(original_until, until);
                assert_eq!(service.current_state_identity().ok(), Some(identity));
                assert!(actual_actor.is_root());
                assert!(authorize_restore(service, actual_actor, clock).is_ok());
                assert!(Instant::now() < until);
                assert!(
                    !seen.replace(true),
                    "one actual nonempty archive object read only"
                );
                assert!(
                    fs::rename(&original, &held).is_ok(),
                    "move only this fixture's actual seal inode"
                );
                moved.set(true);
            },
        )
        .map_err(|_| "historical observation refused")?;
    let mut reader = archive.as_slice();
    let (result, output) = request.execute_snapshot_transfer(&mut reader);
    assert!(output.is_none());
    let response = writer.finish_external_request(*request, result);
    drop(observation);
    // Restore that same inode even if the product unexpectedly accepted it.
    seal.restore()?;
    assert!(
        observed.get(),
        "a real nonempty archive object read must complete before seal removal"
    );
    assert_eq!(response.status, 400);
    assert!(response.body.get("data").is_none());
    assert!(response.unwrapped_json.is_none() && response.consistency_index.is_none());
    assert!(
        Instant::now() < until,
        "the original 15-second budget remains live"
    );
    assert_eq!(writer.current_state_identity().ok(), Some(identity));
    assert_eq!(
        writer.state.as_ref().ok_or("state absent")?.replay_epoch,
        epoch
    );
    let durable = writer
        .durable
        .as_ref()
        .ok_or("same durable owner not returned")?;
    assert_eq!(durable.generation(), generation);
    assert_eq!(durable.replay_epoch(), epoch);
    assert!(!durable.recovery_required());
    assert_eq!((writer.recovery_required, writer.audit_failed), flags);
    drop(writer);
    assert_eq!(pipeline.native_selection(leader)?, selected);
    Ok(())
}

#[test]
fn borrowed_historical_prepare_rejects_real_actor_expiry_at_original_source_gate() -> TestResult {
    let (pipeline, leader) = activated()?;
    let archive = archive_then_advance(&pipeline, leader)?;
    let mut issued = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/create",
            pipeline.admin(),
            json!({"policies":["root"],"ttl":"2s","no_default_policy":true,"no_parent":true}),
        )?,
        200,
        "borrowed-historical-real-two-second-actor",
    )?;
    let issued_finished = Instant::now();
    let token = secret_field(&mut issued, "/auth/client_token")?;
    let began = Instant::now();
    let until = began + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, began)?;
    let service = pipeline.services[leader].as_ref().ok_or("Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "historical actor writer")?;
    let mut request = pending_restore(&mut writer, &token, until)?;
    let identity = writer
        .current_state_identity()
        .map_err(|_| "identity absent")?;
    let epoch = writer.state.as_ref().ok_or("state absent")?.replay_epoch;
    let observed = Rc::new(Cell::new(false));
    let seen = Rc::clone(&observed);
    let expired = Rc::new(Cell::new(false));
    let denied = Rc::clone(&expired);
    let observation = writer
        .observe_historical_prepare_original_source_once(
            until,
            move |service, actual_actor, actual_identity, original_until| {
                assert_eq!(actual_identity, identity);
                assert_eq!(original_until, until);
                assert_eq!(service.current_state_identity().ok(), Some(identity));
                assert!(actual_actor.is_root());
                assert!(
                    authorize_restore(service, actual_actor, clock).is_ok(),
                    "the actual plan Actor must still be live at the borrowed boundary"
                );
                assert!(
                    !seen.replace(true),
                    "one actual original source boundary only"
                );
                // This is a real wait on the originally issued two-second
                // grant. No clock, grant, request deadline or gate is replaced.
                let expired_after = issued_finished + Duration::from_millis(2100);
                thread::sleep(expired_after.saturating_duration_since(Instant::now()));
                assert!(
                    Instant::now() < until,
                    "the original request is not extended"
                );
                let refusal = authorize_restore(service, actual_actor, clock).err();
                assert!(
                    refusal.is_some(),
                    "the same actual plan Actor must have expired"
                );
                if let Some(refusal) = refusal {
                    assert_eq!(refusal.status, 403);
                    denied.set(true);
                }
            },
        )
        .map_err(|_| "historical observation refused")?;
    let mut reader = archive.as_slice();
    let (result, output) = request.execute_snapshot_transfer(&mut reader);
    assert!(output.is_none());
    let response = writer.finish_external_request(*request, result);
    drop(observation);
    assert!(
        observed.get(),
        "the actual borrowed prepare boundary must run"
    );
    assert!(
        expired.get(),
        "the original actual Actor must fail precise authorization"
    );
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.unwrapped_json.is_none() && response.consistency_index.is_none());
    assert!(
        Instant::now() < until,
        "the original 15-second budget remains live"
    );
    // A refused precise token request may persist its terminal clock. That
    // publication cannot restore the archive or advance the replay epoch.
    assert_eq!(
        writer.state.as_ref().ok_or("state absent")?.replay_epoch,
        epoch
    );
    let durable = writer
        .durable
        .as_ref()
        .ok_or("same durable owner not returned")?;
    assert_eq!(durable.replay_epoch(), epoch);
    assert!(!durable.recovery_required());
    assert!(!writer.recovery_required);
    Ok(())
}

#[test]
fn borrowed_historical_fixture_releases_completed_download_before_restore() -> TestResult {
    let (pipeline, leader) = activated()?;
    let archive = {
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let service = pipeline.services[leader].as_ref().ok_or("Service absent")?;
        let mut writer = lock_until(service, until).map_err(|_| "lease control export writer")?;
        let mut request = pending(&mut writer, pipeline.admin(), until)?;
        let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
        expect(
            writer.finish_external_request(*request, result),
            200,
            "historical-lease-control-real-download",
        )?;
        let output = file.ok_or("lease control archive absent")?;
        // Finishing the plan must not release a still-live download file.
        // This is the actual admission path that refused the original R32
        // fixture, with the real Service spool and no injected error.
        match writer.begin_native_snapshot_before(
            ServiceRequest::new("POST", SNAPSHOT_PATH, "", pipeline.admin(), json!({})),
            until,
        ) {
            NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
                expect(
                    response,
                    429,
                    "historical-lease-control-live-download-refused",
                )?;
            }
            _ => return Err("live download did not retain exclusive transfer custody".into()),
        }
        receive_completed_archive(output, until)?
    };
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({"options":{"cas":1},"data":{"value":"after-lease-control-download"}}),
        )?,
        200,
        "historical-lease-control-later-business-root",
    )?;
    let began = Instant::now();
    let until = began + REQUEST_BUDGET;
    let scope = RequestDeadlineScope::enter(until);
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, began)?;
    let service = pipeline.services[leader].as_ref().ok_or("Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "lease control restore writer")?;
    let mut request = pending_restore(&mut writer, pipeline.admin(), until)?;
    let identity = writer
        .current_state_identity()
        .map_err(|_| "identity absent")?;
    let epoch = writer.state.as_ref().ok_or("state absent")?.replay_epoch;
    let observed = Rc::new(Cell::new(false));
    let seen = Rc::clone(&observed);
    let observation = writer
        .observe_historical_prepare_original_source_once(
            until,
            move |service, actual_actor, actual_identity, original_until| {
                assert_eq!(actual_identity, identity);
                assert_eq!(original_until, until);
                assert!(actual_actor.is_root());
                assert!(authorize_restore(service, actual_actor, clock).is_ok());
                assert!(Instant::now() < until);
                assert!(
                    !seen.replace(true),
                    "one actual original source boundary only"
                );
            },
        )
        .map_err(|_| "lease control observation refused")?;
    let mut reader = archive.as_slice();
    let (result, output) = request.execute_snapshot_transfer(&mut reader);
    assert!(output.is_none());
    let response = expect(
        writer.finish_external_request(*request, result),
        200,
        "historical-lease-control-real-restore",
    )?;
    drop(observation);
    assert!(
        observed.get(),
        "the actual borrowed prepare boundary must run"
    );
    assert!(
        Instant::now() < until,
        "the original 15-second budget remains live"
    );
    assert_eq!(
        response.body.pointer("/data/cluster_coordinated"),
        Some(&json!(true))
    );
    assert_eq!(
        response.body.pointer("/data/replay_epoch"),
        Some(&json!(epoch + 1))
    );
    assert_eq!(
        writer.state.as_ref().ok_or("state absent")?.replay_epoch,
        epoch + 1
    );
    assert!(!writer.recovery_required);
    drop(writer);
    drop(scope);
    let restored = expect(
        pipeline.call(
            leader,
            "GET",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "historical-lease-control-restored-archive-readback",
    )?;
    assert_eq!(
        restored.body.pointer("/data/data/value"),
        Some(&json!("seed-v5"))
    );
    assert_eq!(
        restored.body.pointer("/data/metadata/version"),
        Some(&json!(1))
    );
    Ok(())
}
