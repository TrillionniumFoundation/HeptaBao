use super::*;
use crate::tests::{TestBarrier, TestRoot, put_request, serial_test};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Clone)]
struct CountingBarrier {
    inner: TestBarrier,
    opens: Arc<AtomicUsize>,
    reject_open: Arc<AtomicBool>,
}

impl CountingBarrier {
    fn new() -> Self {
        Self {
            inner: TestBarrier::new(),
            opens: Arc::new(AtomicUsize::new(0)),
            reject_open: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Barrier for CountingBarrier {
    fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BarrierError> {
        self.inner.seal(context, plaintext)
    }
    fn open(&self, context: &[u8], protected: &[u8]) -> Result<Vec<u8>, BarrierError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        if self.reject_open.load(Ordering::SeqCst) {
            return Err(BarrierError);
        }
        self.inner.open(context, protected)
    }
    fn sealed_len_bound(&self, length: usize) -> Option<usize> {
        self.inner.sealed_len_bound(length)
    }
}

#[test]
fn inspect_and_commit_share_one_authenticated_backup_without_plaintext_copy()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("prepared-once")?;
    let barrier = CountingBarrier::new();
    let mut service = DurableService::create_new(&root.0, barrier.clone(), 16)?;
    service.put(put_request("prepared-secret-id", b"prepared-secret-value")?)?;
    let backup = service.export_backup()?;
    let before = service.backend.load().map_err(map_backend_error)?;
    let opens = barrier.opens.load(Ordering::SeqCst);
    let prepared = service.prepare_restore(&backup)?;
    assert_eq!(barrier.opens.load(Ordering::SeqCst) - opens, 3);
    assert_eq!(prepared.metadata().generation, 1);
    assert_eq!(prepared.metadata().entry_count, 1);
    let borrowed = prepared
        .get("root/team-a", "secret/application")?
        .ok_or(ServiceError::CorruptState)?;
    assert_eq!(borrowed, b"prepared-secret-value");
    let mut visits = 0;
    prepared.inspect(|namespace, resource, value| {
        assert_eq!(namespace, "root/team-a");
        assert_eq!(resource, "secret/application");
        assert!(std::ptr::eq(value.as_ptr(), borrowed.as_ptr()));
        visits += 1;
    });
    assert_eq!(visits, 1);
    let debug = format!("{prepared:?}");
    for secret in [
        "prepared-secret",
        "root/team-a",
        "secret/application",
        "principal-a",
    ] {
        assert!(!debug.contains(secret));
    }
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    let unused = service.prepare_restore(&backup)?;
    drop(unused);
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    let opens = barrier.opens.load(Ordering::SeqCst);
    // A second decrypt would now fail. Publication must use the validated plan.
    barrier.reject_open.store(true, Ordering::SeqCst);
    assert_eq!(
        service
            .restore_prepared(prepared, false)?
            .restored_generation,
        1
    );
    assert_eq!(barrier.opens.load(Ordering::SeqCst), opens);
    barrier.reject_open.store(false, Ordering::SeqCst);
    drop(service);
    let reopened = DurableService::reopen(&root.0, barrier, 16)?;
    assert_eq!(
        reopened
            .get("root/team-a", "secret/application")?
            .ok_or(ServiceError::CorruptState)?
            .expose(),
        b"prepared-secret-value"
    );
    Ok(())
}

#[test]
fn changed_state_rejects_plan_before_publication_and_reprepare_preserves_rollback_policy()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("prepared-stale")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    service.put(put_request("first", b"first")?)?;
    let backup = service.export_backup()?;
    let prepared = service.prepare_restore(&backup)?;
    service.put(put_request("second", b"second")?)?;
    let live = service.backend.load().map_err(map_backend_error)?;
    assert!(matches!(
        service.restore_prepared(prepared, true),
        Err(ServiceError::RequestBindingConflict)
    ));
    assert!(!service.recovery_required());
    assert_eq!(service.backend.load().map_err(map_backend_error)?, live);
    let prepared = service.prepare_restore(&backup)?;
    assert!(matches!(
        service.restore_prepared(prepared, false),
        Err(ServiceError::BackupRollbackRejected)
    ));
    assert!(!service.recovery_required());
    assert_eq!(service.backend.load().map_err(map_backend_error)?, live);
    let prepared = service.prepare_restore(&backup)?;
    assert_eq!(
        service
            .restore_prepared(prepared, true)?
            .restored_generation,
        1
    );
    Ok(())
}

#[test]
fn plans_cannot_cross_stores_or_reopen_even_with_identical_key_and_frontier()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("prepared-origin")?;
    let other = TestRoot::new("prepared-other")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    let mut destination = DurableService::create_new(&other.0, TestBarrier::new(), 16)?;
    let backup = service.export_backup()?;
    let plan = service.prepare_restore(&backup)?;
    let before = destination.backend.load().map_err(map_backend_error)?;
    assert!(matches!(
        destination.restore_prepared(plan, true),
        Err(ServiceError::RequestBindingConflict)
    ));
    assert_eq!(
        destination.backend.load().map_err(map_backend_error)?,
        before
    );
    let plan = service.prepare_restore(&backup)?;
    let before = service.backend.load().map_err(map_backend_error)?;
    drop(service);
    let mut reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
    assert!(matches!(
        reopened.restore_prepared(plan, true),
        Err(ServiceError::RequestBindingConflict)
    ));
    assert_eq!(reopened.backend.load().map_err(map_backend_error)?, before);
    assert!(!reopened.recovery_required());
    Ok(())
}

#[test]
fn successful_restore_invalidates_other_plans_even_after_generation_aba() -> Result<(), ServiceError>
{
    let _serial = serial_test();
    let root = TestRoot::new("prepared-aba")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    service.put(put_request("first", b"old")?)?;
    let old = service.export_backup()?;
    // Normalize the frontier so restoring the same backup has identical numbers.
    service.restore_backup(&old, false)?;
    let stale = service.prepare_restore(&old)?;
    service.put(put_request("second", b"new")?)?;
    service.restore_backup(&old, true)?;
    assert!(service.restore_frontier() == stale.frontier);
    let before = service.backend.load().map_err(map_backend_error)?;
    assert!(matches!(
        service.restore_prepared(stale, true),
        Err(ServiceError::RequestBindingConflict)
    ));
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    assert!(!service.recovery_required());
    Ok(())
}

#[test]
fn replay_retirement_and_changed_checkpoint_invalidate_but_same_frontier_compaction_is_allowed()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("prepared-maintenance")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    service.put(put_request("first", b"one")?)?;
    let backup = service.export_backup()?;
    let plan = service.prepare_restore(&backup)?;
    service.compact()?;
    assert!(matches!(
        service.restore_prepared(plan, true),
        Err(ServiceError::RequestBindingConflict)
    ));
    let plan = service.prepare_restore(&backup)?;
    service.compact()?;
    service.restore_prepared(plan, false)?;
    let plan = service.prepare_restore(&backup)?;
    service.retire_replay_epoch()?;
    let epoch = service.replay_epoch();
    assert!(matches!(
        service.restore_prepared(plan, true),
        Err(ServiceError::RequestBindingConflict)
    ));
    assert_eq!(service.replay_epoch(), epoch);
    let plan = service.prepare_restore(&backup)?;
    service.restore_prepared(plan, true)?;
    assert_eq!(service.replay_epoch(), 0);
    Ok(())
}

#[test]
fn tampered_ciphertext_and_declared_oversize_reject_without_any_write_or_fence()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("prepared-invalid")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    service.put(put_request("first", b"value")?)?;
    let backup = service.export_backup()?;
    let before = service.backend.load().map_err(map_backend_error)?;
    let mut invalid = backup.clone();
    // Forge both unkeyed frame/container checksums; AEAD must still reject.
    let snapshot_len = u32::from_le_bytes(
        invalid[16..20]
            .try_into()
            .map_err(|_| ServiceError::CorruptState)?,
    ) as usize;
    invalid[68] ^= 1;
    let snapshot_checksum = 20 + snapshot_len - 32;
    let digest = digest32(
        b"heptabao.durable-service.snapshot-frame.v2",
        &invalid[20..snapshot_checksum],
    );
    invalid[snapshot_checksum..snapshot_checksum + 32].copy_from_slice(&digest);
    let payload = invalid.len() - 32;
    let digest = digest32(b"heptabao.durable-service.backup.v1", &invalid[..payload]);
    invalid[payload..].copy_from_slice(&digest);
    assert!(service.prepare_restore(&invalid).is_err());
    let mut invalid = backup;
    // Snapshot component length begins after magic/version/reserved/generation.
    invalid[16..20].copy_from_slice(&((MAX_FILE_BYTES + 1) as u32).to_le_bytes());
    let payload = invalid.len() - 32;
    let digest = digest32(b"heptabao.durable-service.backup.v1", &invalid[..payload]);
    invalid[payload..].copy_from_slice(&digest);
    assert!(matches!(
        service.prepare_restore(&invalid),
        Err(ServiceError::CorruptState)
    ));
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    assert!(!service.recovery_required());
    service.put(put_request("after-invalid", b"still available")?)?;
    Ok(())
}

struct PublicationBackend {
    inner: FileBackend,
    lose_ack: Arc<AtomicBool>,
    lose_writer: Arc<AtomicBool>,
}

impl DurableBackend for PublicationBackend {
    fn verify(&self) -> Result<(), BackendError> {
        if self.lose_writer.load(Ordering::SeqCst) {
            return Err(BackendError::StaleWriter);
        }
        DurableBackend::verify(&self.inner)
    }
    fn load(&mut self) -> Result<BackendBundle, BackendError> {
        self.inner.load()
    }
    fn initialize_empty(&mut self, bundle: &BackendBundle) -> Result<(), BackendError> {
        self.inner.initialize_empty(bundle)
    }
    fn append_journal(&mut self, expected_len: usize, frame: &[u8]) -> Result<usize, BackendError> {
        self.inner.append_journal(expected_len, frame)
    }
    fn truncate_journal(
        &mut self,
        expected_len: usize,
        new_len: usize,
    ) -> Result<(), BackendError> {
        self.inner.truncate_journal(expected_len, new_len)
    }
    fn publish_checkpoint(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
    ) -> Result<(), BackendError> {
        self.inner.publish_checkpoint(expected, replacement)?;
        if self.lose_ack.swap(false, Ordering::SeqCst) {
            return Err(BackendError::OutcomeUnknown);
        }
        Ok(())
    }
    fn restore_profile(&self) -> Result<RestoreProfile, BackendError> {
        self.inner.restore_profile()
    }
    fn publish_restore(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
        intent: Option<&[u8]>,
    ) -> Result<(), BackendError> {
        self.inner.publish_restore(expected, replacement, intent)?;
        if self.lose_ack.swap(false, Ordering::SeqCst) {
            return Err(BackendError::OutcomeUnknown);
        }
        Ok(())
    }
    fn staged_restore_commitments(&self) -> Result<StagedRestoreCommitments, BackendError> {
        self.inner.staged_restore_commitments()
    }
    fn staged_restore_replacement(&self) -> Result<BackendBundle, BackendError> {
        self.inner.staged_restore_replacement()
    }
    fn finish_restore(
        &mut self,
        intent: &[u8],
        replacement: &BackendBundle,
    ) -> Result<(), BackendError> {
        self.inner.finish_restore(intent, replacement)
    }
    fn close(self) -> Result<(), BackendError> {
        self.inner.close()
    }
}

#[test]
fn writer_loss_prevents_publication_and_lost_commit_ack_keeps_recovery_fence()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("prepared-unknown")?;
    let lose_ack = Arc::new(AtomicBool::new(false));
    let lose_writer = Arc::new(AtomicBool::new(false));
    let backend = PublicationBackend {
        inner: FileBackend::create_new(&root.0).map_err(map_backend_error)?,
        lose_ack: Arc::clone(&lose_ack),
        lose_writer: Arc::clone(&lose_writer),
    };
    let mut service = DurableService::create_new_with_backend(backend, TestBarrier::new(), 16)?;
    service.put(put_request("one", b"old")?)?;
    let backup = service.export_backup()?;
    service.put(put_request("two", b"new")?)?;
    let plan = service.prepare_restore(&backup)?;
    let before = service.backend.load().map_err(map_backend_error)?;
    lose_writer.store(true, Ordering::SeqCst);
    assert!(matches!(
        service.restore_prepared(plan, true),
        Err(ServiceError::RecoveryRequired)
    ));
    assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
    lose_writer.store(false, Ordering::SeqCst);
    let plan = service.prepare_restore(&backup)?;
    lose_ack.store(true, Ordering::SeqCst);
    assert!(matches!(
        service.restore_prepared(plan, true),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(service.recovery_required());
    assert!(matches!(
        service.prepare_restore(&backup),
        Err(ServiceError::RecoveryRequired)
    ));
    drop(service);
    let reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
    assert_eq!(reopened.generation(), 1);
    assert_eq!(
        reopened
            .get("root/team-a", "secret/application")?
            .ok_or(ServiceError::CorruptState)?
            .expose(),
        b"old"
    );
    Ok(())
}
