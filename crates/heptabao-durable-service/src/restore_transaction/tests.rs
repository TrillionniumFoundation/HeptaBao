use super::*;
use crate::tests::{TestBarrier, TestRoot, put_request, serial_test};

fn service(root: &TestRoot) -> Result<DurableService<TestBarrier, FileBackend>, ServiceError> {
    DurableService::create_new_with_backend(
        FileBackend::create_new(&root.0).map_err(map_backend_error)?,
        TestBarrier::new(),
        16,
    )
}

fn value<B: Barrier, P: DurableBackend>(
    service: &DurableService<B, P>,
) -> Result<Vec<u8>, ServiceError> {
    Ok(service
        .get("root/team-a", "secret/application")?
        .ok_or(ServiceError::CorruptState)?
        .expose()
        .to_vec())
}

fn pending(root: &TestRoot, step: usize) -> Result<(), ServiceError> {
    let mut service = service(root)?;
    service.put(put_request("restore-original", b"restored")?)?;
    let backup = service.export_backup()?;
    service.retire_replay_epoch()?;
    service.put_in_replay_epoch(1, put_request("restore-current", b"current")?)?;
    let prepared = service.prepare_restore(&backup)?;
    service.backend.fail_restore_after(step);
    assert!(matches!(
        service.restore_prepared(prepared, true),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(service.recovery_required());
    assert!(matches!(
        service.put_in_replay_epoch(1, put_request("forbidden", b"no")?),
        Err(ServiceError::RecoveryRequired)
    ));
    Ok(())
}

#[test]
fn every_file_boundary_reopens_exact_old_or_authenticated_new_without_epoch_mix()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    for step in 1..=10 {
        let root = TestRoot::new("restore-crash-boundary")?;
        pending(&root, step)?;
        let snapshot = fs::read(root.0.join("state.hbs"))?;
        if (7..=9).contains(&step) {
            assert!(snapshot.starts_with(RESTORE_MAGIC));
            // This is the exact decoder the pre-intent version used. A pending
            // restore cannot be mistaken for an ordinary checkpoint snapshot.
            assert!(decode_snapshot_frame(&snapshot, &TestBarrier::new()).is_err());
        }
        let mut reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
        assert!(!reopened.recovery_required());
        if step < 7 {
            assert_eq!(value(&reopened)?, b"current");
            assert_eq!(reopened.replay_epoch(), 1);
        } else {
            assert_eq!(value(&reopened)?, b"restored");
            assert_eq!(reopened.replay_epoch(), 0);
        }
        let epoch = reopened.replay_epoch();
        reopened.put_in_replay_epoch(epoch, put_request("after-recovery", b"after")?)?;
        drop(reopened);
        let reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
        assert_eq!(value(&reopened)?, b"after");
    }
    Ok(())
}

#[test]
fn recovery_itself_can_crash_after_each_active_component_and_roll_forward_again()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    for step in 1..=3 {
        let root = TestRoot::new("restore-recovery-crash")?;
        pending(&root, 7)?;
        let mut backend = FileBackend::open(&root.0).map_err(map_backend_error)?;
        backend.fail_restore_after(step);
        assert!(matches!(
            DurableService::reopen_with_backend(backend, TestBarrier::new(), 16),
            Err(ServiceError::RecoveryRequired)
        ));
        let reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
        assert_eq!(value(&reopened)?, b"restored");
        assert_eq!(reopened.replay_epoch(), 0);
    }
    Ok(())
}

fn files(root: &TestRoot) -> Result<BTreeMap<String, Vec<u8>>, ServiceError> {
    let mut files = BTreeMap::new();
    for item in fs::read_dir(&root.0)? {
        let item = item?;
        if item.file_type()?.is_file() {
            files.insert(
                item.file_name().to_string_lossy().into_owned(),
                fs::read(item.path())?,
            );
        }
    }
    Ok(files)
}

#[test]
fn tampered_intent_retained_components_missing_files_and_unrelated_active_components_never_recover()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    for leaf in [
        "state.hbs",
        "restore-old-state.hbs",
        "restore-old-ledger.hbl",
        "restore-old-journal.hbj",
        "restore-new-state.hbs",
        "restore-new-ledger.hbl",
        "restore-new-journal.hbj",
        "ledger.hbl",
        "journal.hbj",
    ] {
        let root = TestRoot::new("restore-corrupt")?;
        pending(&root, 7)?;
        let path = root.0.join(leaf);
        let mut bytes = fs::read(&path)?;
        let index = bytes
            .len()
            .checked_sub(1)
            .ok_or(ServiceError::CorruptState)?;
        bytes[index] ^= 1;
        fs::write(path, bytes)?;
        let before = files(&root)?;
        assert!(DurableService::reopen(&root.0, TestBarrier::new(), 16).is_err());
        assert_eq!(files(&root)?, before);
    }
    let root = TestRoot::new("restore-missing")?;
    pending(&root, 7)?;
    fs::remove_file(root.0.join("restore-new-ledger.hbl"))?;
    let before = files(&root)?;
    assert!(DurableService::reopen(&root.0, TestBarrier::new(), 16).is_err());
    assert_eq!(files(&root)?, before);
    Ok(())
}

#[test]
fn valid_intent_copied_to_another_directory_is_not_authority_even_with_same_barrier()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let original = TestRoot::new("restore-original-directory")?;
    pending(&original, 7)?;
    let other = TestRoot::new("restore-other-directory")?;
    fs::create_dir(&other.0)?;
    for (name, bytes) in files(&original)? {
        fs::write(other.0.join(name), bytes)?;
    }
    let before = files(&other)?;
    assert!(matches!(
        DurableService::reopen(&other.0, TestBarrier::new(), 16),
        Err(ServiceError::RequestBindingConflict)
    ));
    assert_eq!(files(&other)?, before);
    let original = DurableService::reopen(&original.0, TestBarrier::new(), 16)?;
    assert_eq!(value(&original)?, b"restored");
    Ok(())
}

#[test]
fn authenticated_intent_cannot_publish_a_semantically_invalid_replacement()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("restore-invalid-new-epoch")?;
    pending(&root, 7)?;
    let mut backend = FileBackend::open(&root.0).map_err(map_backend_error)?;
    let active = backend.load().map_err(map_backend_error)?;
    let mut intent = open_intent(&TestBarrier::new(), &active.snapshot)?;
    intent.new_authority[1] += 1;
    let old = BackendBundle::new(
        fs::read(root.0.join("restore-old-state.hbs"))?,
        fs::read(root.0.join("restore-old-ledger.hbl"))?,
        fs::read(root.0.join("restore-old-journal.hbj"))?,
    )
    .map_err(map_backend_error)?;
    let new = backend
        .staged_restore_replacement()
        .map_err(map_backend_error)?;
    let forged = seal_intent(
        &TestBarrier::new(),
        intent.target,
        intent.old_authority,
        intent.new_authority,
        &old,
        &new,
    )?;
    drop(backend);
    fs::write(root.0.join("state.hbs"), forged)?;
    let before = files(&root)?;
    assert!(matches!(
        DurableService::reopen(&root.0, TestBarrier::new(), 16),
        Err(ServiceError::CorruptState)
    ));
    assert_eq!(files(&root)?, before);
    Ok(())
}

#[test]
fn ordinary_compaction_does_not_create_restore_intents_or_stages() -> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("restore-normal-compact")?;
    let mut service = service(&root)?;
    service.put(put_request("ordinary", b"ordinary")?)?;
    service.compact()?;
    assert!(
        !files(&root)?
            .keys()
            .any(|name| name.starts_with("restore-"))
    );
    assert!(!fs::read(root.0.join("state.hbs"))?.starts_with(RESTORE_MAGIC));
    drop(service);
    assert_eq!(
        value(&DurableService::reopen(&root.0, TestBarrier::new(), 16)?)?,
        b"ordinary"
    );
    Ok(())
}

// Deliberately implements only the pre-restore backend contract. The default
// must not reinterpret publish_checkpoint as an atomic restore capability.
struct CheckpointOnly(FileBackend);
impl DurableBackend for CheckpointOnly {
    fn verify(&self) -> Result<(), BackendError> {
        self.0.verify()
    }
    fn load(&mut self) -> Result<BackendBundle, BackendError> {
        self.0.load()
    }
    fn initialize_empty(&mut self, initial: &BackendBundle) -> Result<(), BackendError> {
        self.0.initialize_empty(initial)
    }
    fn append_journal(&mut self, length: usize, frame: &[u8]) -> Result<usize, BackendError> {
        self.0.append_journal(length, frame)
    }
    fn truncate_journal(&mut self, length: usize, new_length: usize) -> Result<(), BackendError> {
        self.0.truncate_journal(length, new_length)
    }
    fn publish_checkpoint(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
    ) -> Result<(), BackendError> {
        self.0.publish_checkpoint(expected, replacement)
    }
    fn close(self) -> Result<(), BackendError> {
        self.0.close()
    }
}

#[test]
fn checkpoint_only_backend_rejects_restore_without_publication_or_recovery_fence()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("restore-unsupported-backend")?;
    let backend = CheckpointOnly(FileBackend::create_new(&root.0).map_err(map_backend_error)?);
    let mut service = DurableService::create_new_with_backend(backend, TestBarrier::new(), 16)?;
    service.put(put_request("one", b"one")?)?;
    let backup = service.export_backup()?;
    let prepared = service.prepare_restore(&backup)?;
    let before = files(&root)?;
    assert!(matches!(
        service.restore_prepared(prepared, true),
        Err(ServiceError::UnsupportedProfile)
    ));
    assert_eq!(files(&root)?, before);
    assert!(!service.recovery_required());
    service.put(put_request("two", b"two")?)?;
    Ok(())
}

#[test]
fn declared_restore_bounds_and_oversized_retained_artifacts_fail_before_publication()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("restore-artifact-bound")?;
    pending(&root, 7)?;
    let path = root.0.join("restore-new-state.hbs");
    // Sparse fixture: check descriptor size before allocating a component.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_len(MAX_FILE_BYTES as u64 + 1)?;
    let marker = fs::read(root.0.join("state.hbs"))?;
    assert!(DurableService::reopen(&root.0, TestBarrier::new(), 16).is_err());
    assert_eq!(fs::read(root.0.join("state.hbs"))?, marker);
    assert_eq!(fs::metadata(path)?.len(), MAX_FILE_BYTES as u64 + 1);
    Ok(())
}
