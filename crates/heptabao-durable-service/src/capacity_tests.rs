use super::tests::{TestBarrier, TestRoot, put_request, recovery_from_result, serial_test};
use super::*;

#[test]
fn capacity_observation_is_nonmutating_and_reopen_exact() -> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("capacity-read")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
    service.put(put_request("one", b"not-printed")?)?;
    let before = service.capacity()?;
    let bytes = fs::read(journal_path(&root.0))?;
    assert_eq!(before.logical_payload_bytes, 11);
    assert_eq!(before.retained_requests, 1);
    assert_eq!(before.max_retained_requests, 8);
    assert_eq!(before.max_value_bytes, 1024 * 1024);
    assert_eq!(service.capacity()?, before);
    assert_eq!(fs::read(journal_path(&root.0))?, bytes);
    drop(service);
    let reopened = DurableService::reopen(&root.0, TestBarrier::new(), 8)?;
    assert_eq!(reopened.capacity()?, before);
    Ok(())
}

#[test]
fn bounded_compaction_allows_longer_journal_without_evicting_identities() -> Result<(), ServiceError>
{
    let _serial = serial_test();
    let root = TestRoot::new("capacity-compact")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 64)?;
    service.journal_limit = 1500;
    let first = put_request("request-0", b"synthetic")?;
    for number in 0..40 {
        service.put_with_compaction(put_request(&format!("request-{number}"), b"synthetic")?)?;
        assert!(service.capacity()?.journal_bytes <= 1500);
    }
    assert_eq!(service.retained_request_count(), 40);
    assert_eq!(service.generation(), 40);
    assert!(matches!(
        service.put_with_compaction(first.clone())?,
        MutationOutcome::Duplicate { generation: 1, .. }
    ));
    drop(service);
    let mut service = DurableService::reopen(&root.0, TestBarrier::new(), 64)?;
    assert_eq!(service.retained_request_count(), 40);
    assert!(matches!(
        service.put_with_compaction(first)?,
        MutationOutcome::Duplicate { generation: 1, .. }
    ));
    Ok(())
}

#[test]
fn full_identity_budget_never_compacts_or_replays_a_new_operation() -> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("capacity-full")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 1)?;
    let request = put_request("first", b"synthetic")?;
    service.put(request.clone())?;
    let before = service.capacity()?;
    let journal = fs::read(journal_path(&root.0))?;
    assert!(matches!(
        service.preflight_new_identity(),
        Err(ServiceError::RequestCapacityExhausted)
    ));
    assert!(matches!(
        service.put_with_compaction(put_request("second", b"other")?),
        Err(ServiceError::RequestCapacityExhausted)
    ));
    assert_eq!(service.capacity()?, before);
    assert_eq!(fs::read(journal_path(&root.0))?, journal);
    assert!(matches!(
        service.put_with_compaction(request)?,
        MutationOutcome::Duplicate { .. }
    ));
    Ok(())
}

#[test]
fn unknown_outcome_cannot_enter_capacity_or_automatic_retry() -> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("capacity-unknown")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
    let request = put_request("first", b"synthetic")?;
    let reference = recovery_from_result(
        service.put_with_failpoint(request.clone(), Failpoint::AfterSnapshotPublication),
    )?;
    let bytes = fs::read(journal_path(&root.0))?;
    assert!(matches!(
        service.capacity(),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(matches!(
        service.put_with_compaction(request.clone()),
        Err(ServiceError::RecoveryRequired)
    ));
    assert_eq!(fs::read(journal_path(&root.0))?, bytes);
    drop(service);
    let mut reopened = DurableService::reopen(&root.0, TestBarrier::new(), 8)?;
    assert_eq!(
        reopened.reconcile(&reference),
        ReconciliationStatus::Committed { generation: 1 }
    );
    assert!(matches!(
        reopened.put_with_compaction(request)?,
        MutationOutcome::Duplicate { generation: 1, .. }
    ));
    Ok(())
}

#[test]
fn binding_conflict_does_not_trigger_compaction() -> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("capacity-conflict")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
    service.put(put_request("same", b"first")?)?;
    let before = fs::read(journal_path(&root.0))?;
    assert!(matches!(
        service.put_with_compaction(put_request("same", b"second")?),
        Err(ServiceError::RequestBindingConflict)
    ));
    assert_eq!(fs::read(journal_path(&root.0))?, before);
    Ok(())
}

#[test]
fn too_small_checkpoint_budget_terminates_without_new_intent() -> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("capacity-impossible")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
    service.journal_limit = 4;
    let before = fs::read(journal_path(&root.0))?;
    assert!(matches!(
        service.put_with_compaction(put_request("first", b"synthetic")?),
        Err(ServiceError::JournalCapacityExhausted)
    ));
    assert_eq!(service.generation(), 0);
    assert_eq!(service.retained_request_count(), 0);
    assert_eq!(fs::read(journal_path(&root.0))?, before);
    assert!(!service.recovery_required());
    Ok(())
}

#[test]
fn compaction_io_failure_fences_without_retry_or_new_intent() -> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("capacity-io")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 64)?;
    service.put(put_request("first", b"synthetic")?)?;
    let before = fs::read(journal_path(&root.0))?;
    // Force the next put to need compaction, but leave room for a checkpoint.
    service.journal_limit = before.len() + 1;
    let temporary = journal_path(&root.0).with_extension("tmp");
    fs::create_dir(&temporary)?;
    assert!(matches!(
        service.put_with_compaction(put_request("second", b"other")?),
        Err(ServiceError::Io(_))
    ));
    assert!(service.recovery_required());
    assert_eq!(service.generation(), 1);
    assert_eq!(service.retained_request_count(), 1);
    assert_eq!(fs::read(journal_path(&root.0))?, before);
    assert!(matches!(
        service.put_with_compaction(put_request("second", b"other")?),
        Err(ServiceError::RecoveryRequired)
    ));
    fs::remove_dir(temporary)?;
    drop(service);
    let mut reopened = DurableService::reopen(&root.0, TestBarrier::new(), 64)?;
    assert_eq!(reopened.generation(), 1);
    assert_eq!(reopened.retained_request_count(), 1);
    assert!(matches!(
        reopened.put_with_compaction(put_request("first", b"synthetic")?)?,
        MutationOutcome::Duplicate { generation: 1, .. }
    ));
    Ok(())
}
