use super::*;
use crate::tests::{TestBarrier, TestRoot, serial_test};
fn request<'a>(
    epoch: u64,
    op: &'a str,
    objects: &'a [(String, &'a [u8])],
    root: &'a [u8],
) -> ImmutablePublication<'a> {
    ImmutablePublication {
        replay_epoch: epoch,
        principal: "server",
        namespace: "system",
        operation_id: op,
        authorization_digest: [7; 32],
        objects,
        root_resource: "state",
        root_bytes: root,
    }
}
fn counters<B: Barrier, P: DurableBackend>(
    s: &DurableService<B, P>,
) -> (u64, u64, usize, usize, usize) {
    (
        s.snapshot.generation,
        s.journal_sequence,
        s.snapshot_plaintext_bytes,
        s.ledger_plaintext_bytes,
        s.ledger.len(),
    )
}
fn check_caches<B: Barrier, P: DurableBackend>(
    s: &DurableService<B, P>,
) -> Result<(), ServiceError> {
    assert_eq!(
        s.snapshot_plaintext_bytes,
        snapshot_plaintext_len(&s.snapshot)?
    );
    assert_eq!(s.ledger_plaintext_bytes, ledger_plaintext_len(&s.ledger)?);
    Ok(())
}
#[test]
fn reuses_only_identical_objects_and_preflight_preserves_all_artifacts() -> Result<(), ServiceError>
{
    let _serial = serial_test();
    let root = TestRoot::new("immutable-reuse")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
    service.apply_batch(
        "server",
        "system",
        "seed",
        [7; 32],
        vec![
            ("objects/a".into(), Some(Secret::new(b"existing".to_vec())?)),
            ("state".into(), Some(Secret::new(b"root0".to_vec())?)),
        ],
    )?;
    let before = service.backend.load().map_err(map_backend_error)?;
    let before_counters = counters(&service);
    let objects = vec![
        ("objects/a".into(), &b"existing"[..]),
        ("objects/b".into(), &b"new"[..]),
        ("objects/b".into(), &b"new"[..]),
    ];
    let result = service.preflight_immutable_publication(request(0, "next", &objects, b"root1"))?;
    assert_eq!(result.new_objects, 1);
    assert_eq!(result.batches, 1);
    assert_eq!(result.retained_requests_after, 2);
    let conflicts = vec![("objects/a".into(), &b"different"[..])];
    assert!(matches!(
        service.preflight_immutable_publication(request(0, "next", &conflicts, b"root1")),
        Err(ServiceError::RequestBindingConflict)
    ));
    let duplicates = vec![
        ("objects/b".into(), &b"new"[..]),
        ("objects/b".into(), &b"different"[..]),
    ];
    assert!(matches!(
        service.preflight_immutable_publication(request(0, "next", &duplicates, b"root1")),
        Err(ServiceError::RequestBindingConflict)
    ));
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    assert_eq!(counters(&service), before_counters);
    check_caches(&service)
}
#[test]
fn reserves_all_batches_and_old_full_ledger_before_epoch_retirement() -> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-reserve")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 2)?;
    service.apply_batch(
        "server",
        "system",
        "seed",
        [7; 32],
        vec![("state".into(), Some(Secret::new(b"old".to_vec())?))],
    )?;
    let objects = (0..96)
        .map(|n| (format!("objects/{n}"), &b"v"[..]))
        .collect::<Vec<_>>();
    let before = service.backend.load().map_err(map_backend_error)?;
    assert!(matches!(
        service.preflight_immutable_publication(request(0, "next", &objects, b"new")),
        Err(ServiceError::RequestCapacityExhausted)
    ));
    let plan = service.preflight_immutable_publication(request(1, "next", &objects, b"new"))?;
    assert_eq!(plan.batches, 2);
    assert_eq!(plan.retained_requests_after, 2);
    assert_eq!(plan.replay_epoch_transitions, 1);
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    assert_eq!(service.replay_epoch(), 0);
    service.retire_replay_epoch()?;
    service.apply_batch_with_compaction_in_replay_epoch(
        1,
        "server",
        "system",
        "next-objects-0",
        [7; 32],
        objects
            .iter()
            .map(|(resource, value)| Ok((resource.clone(), Some(Secret::new(value.to_vec())?))))
            .collect::<Result<_, ServiceError>>()?,
    )?;
    service.apply_batch_with_compaction_in_replay_epoch(
        1,
        "server",
        "system",
        "next-root",
        [7; 32],
        vec![("state".into(), Some(Secret::new(b"new".to_vec())?))],
    )?;
    check_caches(&service)?;
    assert_eq!(service.ledger.len(), 2);
    drop(service);
    let mut service = DurableService::reopen(&root.0, TestBarrier::new(), 2)?;
    check_caches(&service)?;
    // Full old ledger cannot reserve even a root-only request in its epoch.
    assert!(matches!(
        service.preflight_immutable_publication(request(1, "other", &[], b"other")),
        Err(ServiceError::RequestCapacityExhausted)
    ));
    let before = service.backend.load().map_err(map_backend_error)?;
    let next = service.preflight_immutable_publication(request(2, "other", &[], b"other"))?;
    assert_eq!(next.retained_requests_after, 1);
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    Ok(())
}
#[test]
fn partial_stage_request_identity_cannot_be_rebound_or_skip_missing_objects()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-binding")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    service.apply_batch(
        "server",
        "system",
        "same-root",
        [7; 32],
        vec![("state".into(), Some(Secret::new(b"old".to_vec())?))],
    )?;
    let before = service.backend.load().map_err(map_backend_error)?;
    assert!(matches!(
        service.preflight_immutable_publication(request(0, "same", &[], b"changed")),
        Err(ServiceError::RequestBindingConflict)
    ));
    let duplicate = service.preflight_immutable_publication(request(0, "same", &[], b"old"))?;
    assert_eq!(duplicate.retained_requests_after, 1);
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    Ok(())
}
#[test]
fn insufficient_single_batch_journal_includes_terminal_and_never_compacts_on_preflight()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-journal")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
    let objects = vec![("objects/a".into(), &b"payload"[..])];
    let plan = service.preflight_immutable_publication(request(0, "op", &objects, b"root"))?;
    let before = service.backend.load().map_err(map_backend_error)?;
    service.journal_limit = plan.journal_peak_bound - 1;
    assert!(matches!(
        service.preflight_immutable_publication(request(0, "op", &objects, b"root")),
        Err(ServiceError::JournalCapacityExhausted)
    ));
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    assert_eq!(service.generation(), 0);
    assert!(!service.recovery_required());
    service.journal_limit = plan.journal_peak_bound;
    service.preflight_immutable_publication(request(0, "op", &objects, b"root"))?;
    Ok(())
}
#[test]
fn actual_near_64mib_state_admits_exact_bound_and_rejects_one_more_byte_before_mutation()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-64mib")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
    let mut initial = (0..63)
        .map(|n| {
            Ok((
                format!("objects/base-{n}"),
                Some(Secret::new(vec![b'x'; MAX_SECRET_BYTES])?),
            ))
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    initial.push(("state".into(), Some(Secret::new(b"root".to_vec())?)));
    service.apply_batch("server", "system", "seed", [7; 32], initial)?;
    check_caches(&service)?;
    let tiny = vec![("objects/tail".into(), &b"x"[..])];
    let small = service.preflight_immutable_publication(request(0, "next", &tiny, b"next"))?;
    let fit = MAX_FILE_BYTES - small.snapshot_peak_bound + 1;
    assert!(fit <= MAX_SECRET_BYTES);
    let value = vec![b'y'; fit];
    let objects = vec![("objects/tail".into(), value.as_slice())];
    let admitted =
        service.preflight_immutable_publication(request(0, "next", &objects, b"next"))?;
    assert_eq!(admitted.snapshot_peak_bound, MAX_FILE_BYTES);
    assert_eq!(admitted.final_snapshot_bound, MAX_FILE_BYTES);
    let before = service.backend.load().map_err(map_backend_error)?;
    let before_counters = counters(&service);
    let too_large = vec![b'y'; fit + 1];
    let rejected = vec![("objects/tail".into(), too_large.as_slice())];
    assert!(matches!(
        service.preflight_immutable_publication(request(0, "next", &rejected, b"next")),
        Err(ServiceError::RequestCapacityExhausted)
    ));
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    assert_eq!(counters(&service), before_counters);
    drop(before);
    service.apply_batch_with_compaction(
        "server",
        "system",
        "next-root",
        [7; 32],
        vec![
            ("objects/tail".into(), Some(Secret::new(value)?)),
            ("state".into(), Some(Secret::new(b"next".to_vec())?)),
        ],
    )?;
    check_caches(&service)?;
    assert_eq!(
        sealed_snapshot(&service.barrier, &service.snapshot)?.len(),
        MAX_FILE_BYTES
    );
    Ok(())
}
struct NoBound(TestBarrier);
impl Barrier for NoBound {
    fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BarrierError> {
        self.0.seal(context, plaintext)
    }
    fn open(&self, context: &[u8], protected: &[u8]) -> Result<Vec<u8>, BarrierError> {
        self.0.open(context, protected)
    }
}
#[test]
fn unknown_barrier_and_unresolved_mutation_are_read_only_refusals() -> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-no-bound")?;
    let mut service = DurableService::create_new(&root.0, NoBound(TestBarrier::new()), 8)?;
    let before = service.backend.load().map_err(map_backend_error)?;
    assert!(matches!(
        service.preflight_immutable_publication(request(0, "op", &[], b"root")),
        Err(ServiceError::UnsupportedProfile)
    ));
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    drop(service);
    let root = TestRoot::new("immutable-unknown")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
    let old_ledger = service.ledger_plaintext_bytes;
    assert!(matches!(
        service.put_with_failpoint(
            PutRequest::new(
                "server",
                "system",
                "unknown",
                "state",
                [7; 32],
                Secret::new(b"root".to_vec())?
            )?,
            Failpoint::AfterSnapshotPublication,
        ),
        Err(ServiceError::OutcomeUnknown { .. })
    ));
    assert_eq!(service.ledger_plaintext_bytes, old_ledger);
    let before = service.backend.load().map_err(map_backend_error)?;
    assert!(matches!(
        service.preflight_immutable_publication(request(0, "op", &[], b"root")),
        Err(ServiceError::RecoveryRequired)
    ));
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    drop(service);
    let service = DurableService::reopen(&root.0, TestBarrier::new(), 8)?;
    check_caches(&service)
}
#[test]
fn cache_rebuild_after_backup_restore_and_overflow_refuse_before_write() -> Result<(), ServiceError>
{
    let _serial = serial_test();
    let root = TestRoot::new("immutable-restore")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
    service.apply_batch(
        "server",
        "system",
        "seed",
        [7; 32],
        vec![("state".into(), Some(Secret::new(b"old".to_vec())?))],
    )?;
    let backup = service.export_backup()?;
    service.apply_batch(
        "server",
        "system",
        "later",
        [7; 32],
        vec![("state".into(), Some(Secret::new(b"new".to_vec())?))],
    )?;
    service.restore_backup(&backup, true)?;
    check_caches(&service)?;
    let before = service.backend.load().map_err(map_backend_error)?;
    let generation = service.snapshot.generation;
    service.snapshot.generation = u64::MAX;
    assert!(matches!(
        service.preflight_immutable_publication(request(0, "overflow", &[], b"next")),
        Err(ServiceError::GenerationOverflow)
    ));
    service.snapshot.generation = generation;
    service.journal_sequence = u64::MAX;
    assert!(matches!(
        service.preflight_immutable_publication(request(0, "overflow", &[], b"next")),
        Err(ServiceError::GenerationOverflow)
    ));
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    Ok(())
}
