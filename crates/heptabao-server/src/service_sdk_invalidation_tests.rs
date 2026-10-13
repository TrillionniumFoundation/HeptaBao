//! Exact record-owner and epoch tests. These are native owner tests, not a
//! substitute for the genuine companion or physical HA acceptance receipts.
use super::*;
use crate::service::tests::{Root, bootstrap};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn mount(state: &mut State, name: &str) -> Result<MountOwner, Box<dyn std::error::Error>> {
    let descriptor = state.engines.register_sdk_descriptor(Descriptor {
        name: name.into(),
        version: "v1".into(),
        command: "fixture".into(),
        args: Vec::new(),
        sha256: "a".repeat(64),
        generation: 1,
    })?;
    state.engines.handle(
        "",
        "POST",
        &format!("sys/mounts/{name}"),
        &json!({"type":"plugin","config":{"plugin_id":name}}),
        100,
    )?;
    Ok(state
        .engines
        .bind_sdk_mount("", &format!("{name}/"), &descriptor)?)
}
fn entry(key: &str, value: &[u8]) -> StorageEntry {
    StorageEntry {
        key: key.into(),
        value: Zeroizing::new(value.to_vec()),
        seal_wrap: true,
    }
}
fn fixture() -> Result<(Root, Service, MountOwner, String), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let owner = mount(&mut candidate, "sdk_notify")?;
    candidate
        .engines
        .sdk_storage_put("", "sdk_notify/", &owner, entry("item", b"old"))?;
    candidate.schema = candidate.writer_schema();
    service
        .commit_state(&mut candidate)
        .map_err(|_| "initial real publication")?;
    service.state = Some(candidate);
    Ok((root, service, owner, token))
}

#[test]
fn committed_sdk_actual_keys_and_resource_hashes_bind_insert_update_delete() -> TestResult {
    let (_root, service, owner, _token) = fixture()?;
    let previous = service.state.as_ref().ok_or("state")?;
    let mut next = previous.clone();
    next.engines
        .sdk_storage_put("", "sdk_notify/", &owner, entry("item", b"new"))?;
    next.engines
        .sdk_storage_put("", "sdk_notify/", &owner, entry("nested/child", b"opaque"))?;
    let delta = next
        .engines
        .sdk_committed_storage_invalidation(&previous.engines, "", "sdk_notify/", &owner)?
        .ok_or("delta")?;
    assert_eq!(delta.keys, ["item", "nested/child"]);
    assert_ne!(delta.old_resource_owner, delta.new_resource_owner);
    let mut deleted = next.clone();
    deleted
        .engines
        .sdk_storage_delete("", "sdk_notify/", &owner, "item")?;
    let removed = deleted
        .engines
        .sdk_committed_storage_invalidation(&next.engines, "", "sdk_notify/", &owner)?
        .ok_or("deleted delta")?;
    assert_eq!(removed.keys, ["item"]);
    assert_eq!(removed.old_resource_owner, delta.new_resource_owner);
    assert_ne!(removed.old_resource_owner, removed.new_resource_owner);
    Ok(())
}

#[test]
fn committed_sdk_same_bytes_and_other_mount_never_fanout() -> TestResult {
    let (_root, service, owner, _token) = fixture()?;
    let previous = service.state.as_ref().ok_or("state")?;
    let mut next = previous.clone();
    next.engines
        .sdk_storage_put("", "sdk_notify/", &owner, entry("item", b"old"))?;
    let sibling = mount(&mut next, "sdk_sibling")?;
    next.engines
        .sdk_storage_put("", "sdk_sibling/", &sibling, entry("item", b"sibling"))?;
    assert!(
        next.engines
            .sdk_committed_storage_invalidation(&previous.engines, "", "sdk_notify/", &owner)?
            .is_none()
    );
    Ok(())
}

#[test]
fn committed_sdk_mount_recreation_rejects_held_owner() -> TestResult {
    let (_root, service, owner, _token) = fixture()?;
    let previous = service.state.as_ref().ok_or("state")?;
    let mut next = previous.clone();
    next.engines
        .handle("", "DELETE", "sys/mounts/sdk_notify", &json!({}), 100)?;
    next.engines.handle(
        "",
        "POST",
        "sys/mounts/sdk_notify",
        &json!({"type":"plugin","config":{"plugin_id":"sdk_notify"}}),
        100,
    )?;
    let descriptor = next
        .engines
        .sdk_descriptor("sdk_notify", "v1")
        .ok_or("descriptor")?;
    let replacement = next
        .engines
        .bind_sdk_mount("", "sdk_notify/", &descriptor)?;
    assert_ne!(replacement.mount_incarnation, owner.mount_incarnation);
    assert!(
        next.engines
            .sdk_committed_storage_invalidation(&previous.engines, "", "sdk_notify/", &owner)
            .is_err()
    );
    Ok(())
}

#[test]
fn committed_sdk_changed_key_bound_has_no_partial_notification() -> TestResult {
    let (_root, service, owner, _token) = fixture()?;
    let previous = service.state.as_ref().ok_or("state")?;
    let mut next = previous.clone();
    for index in 0..257 {
        next.engines.sdk_storage_put(
            "",
            "sdk_notify/",
            &owner,
            entry(&format!("key/{index:03}"), b"new"),
        )?;
    }
    assert!(
        next.engines
            .sdk_committed_storage_invalidation(&previous.engines, "", "sdk_notify/", &owner)
            .is_err()
    );
    Ok(())
}

fn install_control(service: &mut Service, owner: &MountOwner) -> Arc<Control> {
    let (control, _queue) = model_revoke_queue();
    let key = service.sdk_host_key("", "sdk_notify/", owner);
    service.sdk_hosts.insert(key, Arc::clone(&control));
    control
}

#[test]
fn committed_sdk_reserved_epoch_changes_and_drop_retires() -> TestResult {
    let (_root, mut service, owner, _token) = fixture()?;
    let control = install_control(&mut service, &owner);
    let identity = service
        .current_state_identity()
        .map_err(|_| "previous identity")?;
    let mut next = service.state.clone().ok_or("state")?;
    next.engines
        .sdk_storage_put("", "sdk_notify/", &owner, entry("item", b"new"))?;
    let before = control.storage_epoch.load(Ordering::Acquire);
    let batch = service
        .reserve_committed_sdk_invalidations(
            &next,
            identity,
            identity,
            Some(Instant::now() + Duration::from_secs(10)),
        )
        .map_err(|_| "reservation")?;
    assert_eq!(batch.owners.len(), 1);
    assert_eq!(control.storage_epoch.load(Ordering::Acquire), before + 1);
    assert!(control.busy.load(Ordering::Acquire));
    drop(batch); // A failed/superseded install must discard the held cache.
    assert!(control.fenced.load(Ordering::Acquire));
    assert!(!control.busy.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn committed_sdk_busy_owner_keeps_original_busy_until_worker_completion() -> TestResult {
    let (_root, mut service, owner, _token) = fixture()?;
    let control = install_control(&mut service, &owner);
    control.busy.store(true, Ordering::Release);
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let mut next = service.state.clone().ok_or("state")?;
    next.engines
        .sdk_storage_put("", "sdk_notify/", &owner, entry("item", b"new"))?;
    let batch = service
        .reserve_committed_sdk_invalidations(
            &next,
            identity,
            identity,
            Some(Instant::now() + Duration::from_secs(10)),
        )
        .map_err(|_| "reservation")?;
    assert!(batch.owners.is_empty());
    assert!(control.fenced.load(Ordering::Acquire));
    assert!(control.busy.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn committed_sdk_missing_original_clock_fences_without_new_budget() -> TestResult {
    let (_root, mut service, owner, _token) = fixture()?;
    let control = install_control(&mut service, &owner);
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let next = service.state.clone().ok_or("state")?;
    let batch = service
        .reserve_committed_sdk_invalidations(&next, identity, identity, None)
        .map_err(|_| "reservation")?;
    assert!(batch.owners.is_empty());
    assert!(control.fenced.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn committed_sdk_wrong_previous_identity_cannot_admit_notification() -> TestResult {
    let (_root, mut service, owner, _token) = fixture()?;
    let control = install_control(&mut service, &owner);
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let mut next = service.state.clone().ok_or("state")?;
    next.engines
        .sdk_storage_put("", "sdk_notify/", &owner, entry("item", b"new"))?;
    assert!(
        service
            .reserve_committed_sdk_invalidations(
                &next,
                crate::state_record_root::StateIdentity::Legacy([0; 32]),
                identity,
                Some(Instant::now() + Duration::from_secs(10))
            )
            .is_err()
    );
    assert!(control.fenced.load(Ordering::Acquire));
    assert!(!control.busy.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn committed_sdk_shorter_scope_is_preserved_in_worker_capsule() -> TestResult {
    let (_root, mut service, owner, _token) = fixture()?;
    let control = install_control(&mut service, &owner);
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let mut next = service.state.clone().ok_or("state")?;
    next.engines
        .sdk_storage_put("", "sdk_notify/", &owner, entry("item", b"new"))?;
    let shorter = Instant::now() + Duration::from_secs(1);
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(shorter);
    let batch = service
        .reserve_committed_sdk_invalidations(
            &next,
            identity,
            identity,
            Some(shorter + Duration::from_secs(10)),
        )
        .map_err(|_| "reservation")?;
    assert_eq!(batch.deadline, Some(shorter));
    drop(batch);
    assert!(control.fenced.load(Ordering::Acquire));
    Ok(())
}

// These queue peers deliberately model an acknowledgement transport. They do
// not implement or impersonate an SDK hook; the separate genuine SDK and LAN
// receipts must establish the provider/process boundary.
fn queue_control(
    service: &mut Service,
    owner: &MountOwner,
) -> (Arc<Control>, Receiver<WorkerCommand>) {
    let (sender, commands) = mpsc::sync_channel(1);
    let control = Arc::new(Control {
        sender,
        busy: Arc::new(AtomicBool::new(false)),
        fenced: Arc::new(AtomicBool::new(false)),
        storage_epoch: Arc::new(AtomicU64::new(1)),
        retiring: AtomicBool::new(false),
    });
    service.sdk_hosts.insert(
        service.sdk_host_key("", "sdk_notify/", owner),
        Arc::clone(&control),
    );
    (control, commands)
}

fn installed_delta(
    service: &mut Service,
    owner: &MountOwner,
    deadline: Instant,
) -> Result<CommittedInvalidations, Box<dyn std::error::Error>> {
    let previous = service
        .current_state_identity()
        .map_err(|_| "previous identity")?;
    let mut next = service.state.clone().ok_or("state")?;
    next.engines
        .sdk_storage_put("", "sdk_notify/", owner, entry("item", b"new"))?;
    next.schema = next.writer_schema();
    let plan = service
        .prepare_record_plan(&mut next)
        .map_err(|_| "real candidate plan")?;
    let installed = plan.identity;
    let batch = service
        .reserve_committed_sdk_invalidations(&next, previous, installed, Some(deadline))
        .map_err(|_| "reserve exact real record delta")?;
    service
        .commit_record_plan(&next, plan)
        .map_err(|_| "actual encrypted record publication")?;
    service.state = Some(next);
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "installed identity")?,
        installed
    );
    Ok(batch)
}

#[test]
fn committed_sdk_finisher_model_ack_preserves_exact_key_epoch_and_shorter_clock() -> TestResult {
    let (_root, mut service, owner, _token) = fixture()?;
    let (control, commands) = queue_control(&mut service, &owner);
    let original = Instant::now() + Duration::from_secs(10);
    let batch = installed_delta(&mut service, &owner, original)?;
    let shorter = Instant::now() + Duration::from_secs(1);
    let peer = Arc::clone(&control);
    let worker = std::thread::spawn(move || {
        let command = commands
            .recv_timeout(Duration::from_secs(2))
            .expect("original notification");
        let WorkerCommand::Invalidate(job) = command else {
            panic!("not an invalidate command");
        };
        assert_eq!(job.keys, ["item"]);
        assert_eq!(job.epoch, 2);
        assert_eq!(job.deadline, shorter);
        peer.busy.store(false, Ordering::Release);
        job.reply
            .send(Ok(InvalidationAck::Hook))
            .expect("original reply receiver");
    });
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(shorter);
    service
        .finish_committed_sdk_invalidations(batch)
        .map_err(|_| "original modeled ack")?;
    worker.join().map_err(|_| "queue peer panicked")?;
    assert!(!control.fenced.load(Ordering::Acquire));
    assert!(!control.busy.load(Ordering::Acquire));
    assert_eq!(control.storage_epoch.load(Ordering::Acquire), 2);
    Ok(())
}

#[test]
fn committed_sdk_finisher_model_missing_ack_keeps_busy_and_late_ack_cannot_revive() -> TestResult {
    let (_root, mut service, owner, _token) = fixture()?;
    let (control, commands) = queue_control(&mut service, &owner);
    let batch = installed_delta(
        &mut service,
        &owner,
        Instant::now() + Duration::from_secs(10),
    )?;
    let (entered, observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let peer = Arc::clone(&control);
    let worker = std::thread::spawn(move || {
        let WorkerCommand::Invalidate(job) = commands.recv().expect("original notification") else {
            panic!("not invalidate");
        };
        entered.send(()).expect("observer");
        released.recv().expect("owned late completion");
        let _ = job.reply.send(Ok(InvalidationAck::Hook));
        peer.busy.store(false, Ordering::Release);
    });
    let shorter = Instant::now() + Duration::from_millis(60);
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(shorter);
    assert!(service.finish_committed_sdk_invalidations(batch).is_err());
    observed
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| "worker never entered")?;
    assert!(control.fenced.load(Ordering::Acquire));
    assert!(control.busy.load(Ordering::Acquire));
    release
        .send(())
        .map_err(|_| "late completion peer absent")?;
    worker.join().map_err(|_| "queue peer panicked")?;
    assert!(control.fenced.load(Ordering::Acquire));
    assert!(!control.busy.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn committed_sdk_finisher_model_error_ack_discards_cache_without_claiming_hook_ack() -> TestResult {
    let (_root, mut service, owner, _token) = fixture()?;
    let (control, commands) = queue_control(&mut service, &owner);
    let batch = installed_delta(
        &mut service,
        &owner,
        Instant::now() + Duration::from_secs(10),
    )?;
    let peer = Arc::clone(&control);
    let worker = std::thread::spawn(move || {
        let WorkerCommand::Invalidate(job) = commands.recv().expect("notification") else {
            panic!("not invalidate");
        };
        peer.fenced.store(true, Ordering::Release);
        peer.busy.store(false, Ordering::Release);
        job.reply
            .send(Err(SdkBridgeError::Backend))
            .expect("original receiver");
    });
    service
        .finish_committed_sdk_invalidations(batch)
        .map_err(|_| "safe discarded cache")?;
    worker.join().map_err(|_| "queue peer panicked")?;
    assert!(control.fenced.load(Ordering::Acquire));
    assert!(!control.busy.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn committed_sdk_finisher_namespace_or_catalog_capsule_change_cannot_enqueue() -> TestResult {
    for namespace_change in [true, false] {
        let (_root, mut service, owner, _token) = fixture()?;
        let (control, commands) = queue_control(&mut service, &owner);
        let mut batch = installed_delta(
            &mut service,
            &owner,
            Instant::now() + Duration::from_secs(10),
        )?;
        if namespace_change {
            batch.owners[0].namespace_incarnation = Some(1);
        } else {
            batch.owners[0].descriptor.generation += 1;
        }
        assert!(service.finish_committed_sdk_invalidations(batch).is_err());
        assert!(control.fenced.load(Ordering::Acquire));
        assert!(!control.busy.load(Ordering::Acquire));
        // A Stop is disposal only; no invalidate may enter the old owner.
        assert!(
            commands
                .try_iter()
                .all(|command| matches!(command, WorkerCommand::Stop))
        );
    }
    Ok(())
}

#[test]
fn committed_sdk_finisher_changed_actual_record_hash_cannot_enqueue() -> TestResult {
    let (_root, mut service, owner, _token) = fixture()?;
    let (control, commands) = queue_control(&mut service, &owner);
    let mut batch = installed_delta(
        &mut service,
        &owner,
        Instant::now() + Duration::from_secs(10),
    )?;
    batch.owners[0].new_resource_owner[0] ^= 1;
    assert!(service.finish_committed_sdk_invalidations(batch).is_err());
    assert!(control.fenced.load(Ordering::Acquire));
    assert!(!control.busy.load(Ordering::Acquire));
    assert!(
        commands
            .try_iter()
            .all(|command| matches!(command, WorkerCommand::Stop))
    );
    Ok(())
}

#[test]
fn committed_sdk_actual_held_plan_execute_and_terminal_response_rejected_after_epoch() -> TestResult
{
    let (root, mut service, owner, token) = fixture()?;
    let (control, commands) = queue_control(&mut service, &owner);
    let clock = RequestClock::anchored(Duration::new(100, 200_000_000), Instant::now())?;
    let mut state = service.state.clone().ok_or("state")?;
    let body = json!({});
    let request = RequestView {
        method: "GET",
        path: "sdk_notify/cached-item",
        namespace: "",
        token: &token,
        body: &body,
        now: 100,
        admission_started: Instant::now(),
        token_clock: Some(clock),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let principal = state.auth.authenticate_from_observed(
        &token,
        AuthorityTime::Precise(clock.observed_at()?),
        None,
    )?;
    let authority = plugin::PluginResponseAuthority::new(
        principal,
        &state,
        &request,
        "read",
        false,
        &service.unseal_nonce,
    )
    .with_sdk_clock();
    service.sdk_configuration = Some(SdkBackendConfig {
        plugin_directory: root.path.join("plugins"),
        companion: root.path.join("companion"),
        companion_sha256: "a".repeat(64),
        runtime_directory: root.path.join("runtime"),
        timeout_ms: 5000,
    });
    service.stage_sdk_plan(
        &state,
        authority.into(),
        &request,
        StageTarget {
            mount: "sdk_notify/".into(),
            owner: owner.clone(),
            operation: "read",
            path: "cached-item",
            lease: None,
        },
    );
    let mut plan = service
        .pending_sdk_request
        .take()
        .ok_or("actual staged Plan")?;
    assert_eq!(plan.storage_epoch, 1);
    let batch = installed_delta(
        &mut service,
        &owner,
        Instant::now() + Duration::from_secs(10),
    )?;
    let peer = Arc::clone(&control);
    let worker = std::thread::spawn(move || {
        let WorkerCommand::Invalidate(job) = commands.recv().expect("notification") else {
            panic!("not invalidate");
        };
        peer.busy.store(false, Ordering::Release);
        job.reply
            .send(Ok(InvalidationAck::Hook))
            .expect("original receiver");
        commands
    });
    service
        .finish_committed_sdk_invalidations(batch)
        .map_err(|_| "modeled ack")?;
    let commands = worker.join().map_err(|_| "queue peer panicked")?;
    let shared = Arc::new(Mutex::new(service));
    let error = plan
        .execute(&shared, plan.deadline)
        .expect_err("stale original Plan entered worker");
    assert_eq!(error.status, 503);
    assert!(matches!(
        commands.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let mut writer = shared.lock().map_err(|_| "writer poisoned")?;
    let response = writer.complete_sdk_delivery(
        &mut plan,
        Response::ok(json!({"data":{"value":"held old cache"}})),
        "sdk-epoch-held-response",
    );
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("wrap_info").is_none());
    assert!(response.response_headers.is_empty());
    Ok(())
}
