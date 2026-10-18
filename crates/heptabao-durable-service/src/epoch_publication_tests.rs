//! Local authenticated transaction tests only. These values are synthetic;
//! an epoch integer here does not exercise Raft, TLS quorum or Service Auth.
use super::*;

const RESOURCES: [&str; 4] = ["state", "active-cursor", "retained-source", "ha-cursor"];

fn seed<B: Barrier, P: DurableBackend>(service: &mut DurableService<B, P>)
-> Result<(), ServiceError> {
    service.apply_batch(
        "server", "system", "seed-four", [3; 32],
        RESOURCES.iter().map(|resource| {
            Ok(((*resource).into(), Some(Secret::new(format!("old-{resource}").into_bytes())?)))
        }).collect::<Result<Vec<_>, ServiceError>>()?,
    )?;
    service.apply_batch(
        "server", "system", "stage-unreferenced", [3; 32],
        vec![("objects/staged-target".into(), Some(Secret::new(b"staged-object".to_vec())?))],
    )?;
    service.put(put_request("old-client-identity", b"unrelated-current-value")?)?;
    Ok(())
}

fn conditions<B: Barrier, P: DurableBackend>(service: &DurableService<B, P>)
-> Result<Vec<PublicationCondition>, ServiceError> {
    RESOURCES.iter().map(|resource| Ok(PublicationCondition {
        resource: (*resource).into(), expected: service.get("system", resource)?,
    })).collect()
}

fn publication(epoch: u64) -> Result<BatchPublication, ServiceError> {
    Ok(BatchPublication {
        replay_epoch: epoch, principal: "server".into(), namespace: "system".into(),
        request_id: "actual-root-install".into(), authorization_digest: [9; 32],
        mutations: RESOURCES.iter().map(|resource| {
            Ok(((*resource).into(), Some(Secret::new(format!("new-{resource}").into_bytes())?)))
        }).collect::<Result<Vec<_>, ServiceError>>()?,
    })
}

fn assert_four<B: Barrier, P: DurableBackend>(service: &DurableService<B, P>, prefix: &str)
-> Result<(), ServiceError> {
    for resource in RESOURCES {
        assert_eq!(service.get("system", resource)?.ok_or(ServiceError::CorruptState)?.expose(),
            format!("{prefix}-{resource}").as_bytes());
    }
    assert_eq!(service.get("system", "objects/staged-target")?
        .ok_or(ServiceError::CorruptState)?.expose(), b"staged-object");
    assert_eq!(service.get("root/team-a", "secret/application")?
        .ok_or(ServiceError::CorruptState)?.expose(), b"unrelated-current-value");
    Ok(())
}

#[test]
fn epoch_publication_installs_all_four_and_retires_only_current_ledger_across_reopen()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    for target_epoch in [1, 3] {
        let root = TestRoot::new("epoch-publication-cold")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
        seed(&mut service)?;
        let prior = service.generation();
        let old_conditions = conditions(&service)?;
        let result = service.publish_epoch_batch_conditionally_before_publish(
            prior, 0, publication(target_epoch)?, old_conditions, || Ok(()),
        )?;
        let MutationOutcome::Committed { generation, recovery_reference } = result else {
            return Err(ServiceError::CorruptState);
        };
        assert_eq!(generation, prior + 1);
        assert_eq!(service.replay_epoch(), target_epoch);
        assert_eq!(service.retired_through_generation, prior);
        assert_eq!(service.retained_request_count(), 1);
        assert_eq!(service.reconcile(&recovery_reference), ReconciliationStatus::Committed { generation });
        assert_four(&service, "new")?;
        drop(service);
        let mut reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
        assert_eq!(reopened.replay_epoch(), target_epoch);
        assert_eq!(reopened.generation(), prior + 1);
        assert_eq!(reopened.retired_through_generation, prior);
        assert_eq!(reopened.retained_request_count(), 1);
        assert_eq!(reopened.reconcile(&recovery_reference), ReconciliationStatus::Committed { generation });
        assert_four(&reopened, "new")?;
        assert!(matches!(reopened.put(put_request("old-client-identity", b"must-not-replay")?),
            Err(ServiceError::ReplayEpochMismatch)));
        reopened.put_in_replay_epoch(target_epoch, put_request("new-epoch-client", b"new-value")?)?;
    }
    Ok(())
}

#[test]
fn epoch_publication_rejects_changed_frontier_conditions_and_nonincreasing_epoch_before_write()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("epoch-publication-rejected")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    seed(&mut service)?;
    let prior = service.generation();
    let before = service.backend.load().map_err(map_backend_error)?;
    for changed in 0..RESOURCES.len() {
        let mut selected = conditions(&service)?;
        selected[changed].expected = Some(Secret::new(b"wrong-condition".to_vec())?);
        assert!(matches!(service.publish_epoch_batch_conditionally_before_publish(
            prior, 0, publication(1)?, selected, || Ok(())),
            Err(ServiceError::PublicationConditionConflict)));
        assert!(!service.recovery_required());
        assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
        assert_eq!(service.replay_epoch(), 0);
    }
    for (generation, epoch, target) in [(prior + 1, 0, 1), (prior, 1, 2), (prior, 0, 0)] {
        let selected = conditions(&service)?;
        assert!(service.publish_epoch_batch_conditionally_before_publish(
            generation, epoch, publication(target)?, selected, || Ok(())).is_err());
        assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
        assert!(!service.recovery_required());
    }
    let selected = conditions(&service)?;
    assert!(matches!(service.publish_epoch_batch_conditionally_before_publish(
        prior, 0, publication(1)?, selected, || Err(ServiceError::BarrierFailure)),
        Err(ServiceError::BarrierFailure)));
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    assert_four(&service, "old")?;
    Ok(())
}

#[test]
fn epoch_publication_lost_real_file_commit_ack_fences_and_reopens_complete_new_bundle()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("epoch-publication-lost-ack")?;
    let lose_ack = Arc::new(AtomicBool::new(false));
    let lose_writer = Arc::new(AtomicBool::new(false));
    let backend = PublicationBackend {
        inner: FileBackend::create_new(&root.0).map_err(map_backend_error)?,
        lose_ack: Arc::clone(&lose_ack), lose_writer: Arc::clone(&lose_writer),
    };
    let mut service = DurableService::create_new_with_backend(backend, TestBarrier::new(), 16)?;
    seed(&mut service)?;
    let prior = service.generation();
    let selected = conditions(&service)?;
    lose_ack.store(true, Ordering::SeqCst);
    let error = service.publish_epoch_batch_conditionally_before_publish(
        prior, 0, publication(1)?, selected, || Ok(()),
    );
    let Err(ServiceError::OutcomeUnknown { recovery_reference }) = error else {
        return Err(ServiceError::CorruptState);
    };
    assert!(service.recovery_required());
    drop(service);
    let reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
    assert_eq!(reopened.replay_epoch(), 1);
    assert_eq!(reopened.generation(), prior + 1);
    assert_eq!(reopened.retired_through_generation, prior);
    assert_eq!(reopened.reconcile(&recovery_reference),
        ReconciliationStatus::Committed { generation: prior + 1 });
    assert_four(&reopened, "new")?;
    Ok(())
}

#[test]
fn epoch_publication_original_owner_loss_after_physical_commit_is_unknown_and_fenced()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("epoch-publication-final-owner")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    seed(&mut service)?;
    let prior = service.generation();
    let selected = conditions(&service)?;
    let error = service.publish_epoch_batch_conditionally_before_publish(
        prior, 0, publication(1)?, selected, || {
            // Observe the actual published local file, not a mocked callback
            // count. Its outer generation is public framing, not authority.
            let bytes = fs::read(root.0.join("ledger.hbl"))?;
            if bytes.get(4..12) == Some((prior + 1).to_le_bytes().as_slice()) {
                return Err(ServiceError::BarrierFailure);
            }
            Ok(())
        },
    );
    assert!(matches!(error, Err(ServiceError::OutcomeUnknown { .. })));
    assert!(service.recovery_required());
    drop(service);
    let reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
    assert_eq!(reopened.replay_epoch(), 1);
    assert_eq!(reopened.generation(), prior + 1);
    assert_four(&reopened, "new")?;
    Ok(())
}
