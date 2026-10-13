use super::*;
use crate::{BackendBundle, DurableBackend};
use std::{
    fs,
    os::unix::fs::{MetadataExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let root = std::env::temp_dir().canonicalize()?.join(format!(
            "heptabao-immutable-backend-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        Ok(Self(root))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn locator(address: u8) -> Result<BlobLocator, BackendError> {
    BlobLocator::new([0x53; 16], [address; 32])
}
fn published(stage: ImmutableBlobStage) -> Result<ImmutableBlobReadPin, BackendError> {
    match stage {
        ImmutableBlobStage::Published(pin) => Ok(pin),
        ImmutableBlobStage::AlreadyExists(_) => Err(BackendError::Corrupt),
    }
}
fn initial() -> Result<BackendBundle, BackendError> {
    BackendBundle::new(
        b"sealed-snapshot".to_vec(),
        b"sealed-ledger".to_vec(),
        b"sealed-journal".to_vec(),
    )
}

#[test]
fn immutable_file_stage_and_real_reopen_preserve_legacy_bundle() -> TestResult {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let initial = initial()?;
    backend.initialize_empty(&initial)?;
    let profile = backend.immutable_blob_profile()?;
    assert_eq!(profile.max_ciphertext_bytes, 512 * 1024);
    let address = locator(1)?;
    // This is an opaque physical ciphertext fixture, not a typed root proof.
    let bytes = vec![0x43; 256 * 1024 + 57];
    let pin = published(backend.stage_immutable_ciphertext(address, &bytes)?)?;
    assert_eq!(pin.locator(), address);
    assert_eq!(pin.directory_identity(), profile.directory_identity);
    assert_eq!(pin.ciphertext_len(), bytes.len());
    assert_eq!(pin.read_ciphertext()?.as_slice(), bytes.as_slice());
    assert_eq!(backend.load()?, initial);
    assert!(!backend.directory.entry_exists(TEMPORARY_LEAF)?);
    drop(backend);
    assert!(matches!(
        pin.read_ciphertext(),
        Err(BackendError::Unavailable)
    ));
    let mut reopened = FileBackend::open(&root.0)?;
    assert_eq!(reopened.immutable_blob_profile()?, profile);
    let cold = reopened.pin_immutable_ciphertext(address, bytes.len())?;
    assert_eq!(cold.read_ciphertext()?.as_slice(), bytes.as_slice());
    assert_eq!(reopened.load()?, initial);
    Ok(())
}

#[test]
fn immutable_existing_ciphertext_is_preserved_without_address_authentication() -> TestResult {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let address = locator(2)?;
    let original = published(backend.stage_immutable_ciphertext(address, b"old-nonce")?)?;
    let ImmutableBlobStage::AlreadyExists(existing) =
        backend.stage_immutable_ciphertext(address, b"new-nonce")?
    else {
        return Err("existing ciphertext was replaced".into());
    };
    assert_eq!(existing.read_ciphertext()?.as_slice(), b"old-nonce");
    assert_eq!(original.0.identity, existing.0.identity);
    assert!(!backend.directory.entry_exists(TEMPORARY_LEAF)?);
    assert!(matches!(
        backend.stage_immutable_ciphertext(address, b"wrong-length"),
        Err(BackendError::Corrupt)
    ));
    assert_eq!(original.read_ciphertext()?.as_slice(), b"old-nonce");
    Ok(())
}

#[test]
fn immutable_physical_limit_rejects_before_creating_any_entry() -> TestResult {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let address = locator(3)?;
    for bytes in [Vec::new(), vec![0x43; MAX_IMMUTABLE_CIPHERTEXT_BYTES + 1]] {
        assert!(matches!(
            backend.stage_immutable_ciphertext(address, &bytes),
            Err(BackendError::Capacity)
        ));
        assert!(backend.directory.entries()?.next().is_none());
    }
    assert!(matches!(
        BlobLocator::new([0; 16], [0xff; 32]),
        Err(BackendError::InvalidRoot)
    ));
    let max = vec![0x43; MAX_IMMUTABLE_CIPHERTEXT_BYTES];
    let pin = published(backend.stage_immutable_ciphertext(address, &max)?)?;
    assert_eq!(pin.read_ciphertext()?.len(), MAX_IMMUTABLE_CIPHERTEXT_BYTES);
    assert!(matches!(
        backend.pin_immutable_ciphertext(address, 0),
        Err(BackendError::Capacity)
    ));
    Ok(())
}

#[test]
fn immutable_unsafe_existing_leaf_is_never_followed_or_overwritten() -> TestResult {
    for kind in ["symlink", "hardlink", "fifo", "directory"] {
        let root = Root::new()?;
        let mut backend = FileBackend::create_new(&root.0)?;
        let address = locator(4)?;
        let leaf = root.0.join(address.leaf());
        fs::write(root.0.join("sentinel"), b"unchanged")?;
        match kind {
            "symlink" => symlink(root.0.join("sentinel"), &leaf)?,
            "hardlink" => fs::hard_link(root.0.join("sentinel"), &leaf)?,
            "fifo" => assert!(
                std::process::Command::new("mkfifo")
                    .arg(&leaf)
                    .status()?
                    .success()
            ),
            "directory" => fs::create_dir(&leaf)?,
            _ => unreachable!(),
        }
        assert!(
            matches!(
                backend.pin_immutable_ciphertext(address, 9),
                Err(BackendError::Corrupt)
            ),
            "{kind}"
        );
        assert!(
            matches!(
                backend.stage_immutable_ciphertext(address, b"candidate"),
                Err(BackendError::Corrupt)
            ),
            "{kind}"
        );
        assert_eq!(fs::read(root.0.join("sentinel"))?, b"unchanged");
    }
    Ok(())
}

#[test]
fn immutable_foreign_descriptor_cannot_acquire_actual_owner_profile_or_lease() -> TestResult {
    let root = Root::new()?;
    let foreign_root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let mut foreign = FileBackend::create_new(&foreign_root.0)?;
    let address = locator(5)?;
    published(backend.stage_immutable_ciphertext(address, b"same-bytes")?)?;
    published(foreign.stage_immutable_ciphertext(address, b"same-bytes")?)?;
    let foreign_file = foreign
        .directory
        .open_file(address.leaf(), FileAccess::Read)?;
    assert!(matches!(
        backend.pin_checked_file(address, foreign_file, 10),
        Err(BackendError::Corrupt)
    ));
    assert_ne!(
        backend.immutable_blob_profile()?.directory_identity,
        foreign.immutable_blob_profile()?.directory_identity
    );
    Ok(())
}

#[test]
fn immutable_close_and_box_drop_revoke_pins_without_retaining_writer_lock() -> TestResult {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let address = locator(6)?;
    let pin = published(backend.stage_immutable_ciphertext(address, b"ciphertext")?)?;
    let retained = pin.clone();
    backend.close()?;
    assert!(matches!(
        pin.read_ciphertext(),
        Err(BackendError::Unavailable)
    ));
    let mut boxed: Box<dyn DurableBackend> = Box::new(FileBackend::open(&root.0)?);
    assert_eq!(
        boxed.immutable_blob_profile()?.max_ciphertext_bytes,
        MAX_IMMUTABLE_CIPHERTEXT_BYTES
    );
    let ImmutableBlobStage::AlreadyExists(boxed_pin) =
        boxed.stage_immutable_ciphertext(address, b"othernonce")?
    else {
        return Err("boxed existing leaf replaced".into());
    };
    assert_eq!(boxed_pin.read_ciphertext()?.as_slice(), b"ciphertext");
    assert_eq!(
        boxed
            .pin_immutable_ciphertext(address, 10)?
            .read_ciphertext()?
            .as_slice(),
        b"ciphertext"
    );
    drop(boxed);
    assert!(matches!(
        boxed_pin.read_ciphertext(),
        Err(BackendError::Unavailable)
    ));
    assert!(matches!(
        retained.read_ciphertext(),
        Err(BackendError::Unavailable)
    ));
    FileBackend::open(&root.0)?.verify()?;
    Ok(())
}

#[test]
fn immutable_reads_are_positioned_read_only_and_clone_safe() -> TestResult {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let bytes = vec![0x7a; 128 * 1024 + 57];
    let pin = published(backend.stage_immutable_ciphertext(locator(7)?, &bytes)?)?;
    assert!(pin.0.file.try_clone()?.write_all(b"overwrite").is_err());
    let mut readers = Vec::new();
    for _ in 0..4 {
        let reader = pin.clone();
        readers.push(std::thread::spawn(move || reader.read_ciphertext()));
    }
    for reader in readers {
        let result = reader
            .join()
            .map_err(|_| io::Error::other("physical reader panicked"))??;
        assert_eq!(result.as_slice(), bytes.as_slice());
    }
    assert_eq!(pin.read_ciphertext()?.as_slice(), bytes.as_slice());
    Ok(())
}

#[test]
fn immutable_ack_loss_after_actual_fsynced_publication_revokes_until_reopen() -> TestResult {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let initial = initial()?;
    backend.initialize_empty(&initial)?;
    let old_pin = published(backend.stage_immutable_ciphertext(locator(8)?, b"old-object")?)?;
    let address = locator(9)?;
    assert!(matches!(
        backend
            .stage_immutable_ciphertext_checked(address, b"new-object", || Err(BackendError::Io)),
        Err(BackendError::OutcomeUnknown)
    ));
    assert_eq!(fs::read(root.0.join(address.leaf()))?, b"new-object");
    assert_eq!(backend.load()?, initial);
    assert!(matches!(
        old_pin.read_ciphertext(),
        Err(BackendError::Unavailable)
    ));
    assert!(matches!(
        backend.immutable_blob_profile(),
        Err(BackendError::Unavailable)
    ));
    assert!(matches!(
        backend.pin_immutable_ciphertext(address, 10),
        Err(BackendError::Unavailable)
    ));
    assert!(matches!(
        backend.stage_immutable_ciphertext(locator(10)?, b"no-retry"),
        Err(BackendError::Unavailable)
    ));
    drop(backend);
    let mut reopened = FileBackend::open(&root.0)?;
    assert_eq!(
        reopened
            .pin_immutable_ciphertext(address, 10)?
            .read_ciphertext()?
            .as_slice(),
        b"new-object"
    );
    assert_eq!(reopened.load()?, initial);
    Ok(())
}

#[test]
fn immutable_real_link_crash_prefix_is_cleaned_before_backend_reopen_pin() -> TestResult {
    let root = Root::new()?;
    let backend = FileBackend::create_new(&root.0)?;
    let address = locator(11)?;
    let mut temporary = backend
        .directory
        .open_file(TEMPORARY_LEAF, FileAccess::CreateNewReadWrite)?;
    temporary.write_all(b"pending-object")?;
    temporary.sync_all()?;
    fs::hard_link(root.0.join(TEMPORARY_LEAF), root.0.join(address.leaf()))?;
    assert_eq!(temporary.metadata()?.nlink(), 2);
    assert!(matches!(
        backend.pin_immutable_ciphertext(address, 14),
        Err(BackendError::Corrupt)
    ));
    drop(temporary);
    drop(backend);
    let reopened = FileBackend::open(&root.0)?;
    assert!(!reopened.directory.entry_exists(TEMPORARY_LEAF)?);
    let pin = reopened.pin_immutable_ciphertext(address, 14)?;
    assert_eq!(pin.0.file.metadata()?.nlink(), 1);
    assert_eq!(pin.read_ciphertext()?.as_slice(), b"pending-object");
    Ok(())
}

#[test]
fn immutable_pinned_descriptor_shape_changes_are_rejected() -> TestResult {
    for change in ["truncate", "unlink", "hardlink"] {
        let root = Root::new()?;
        let mut backend = FileBackend::create_new(&root.0)?;
        let address = locator(12)?;
        let pin = published(backend.stage_immutable_ciphertext(address, b"original-data")?)?;
        match change {
            "truncate" => {
                backend
                    .directory
                    .open_file(address.leaf(), FileAccess::Write)?
                    .set_len(8)?;
            }
            "unlink" => {
                backend.directory.remove_file(address.leaf())?;
            }
            "hardlink" => {
                fs::hard_link(root.0.join(address.leaf()), root.0.join("foreign-link"))?;
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(pin.read_ciphertext(), Err(BackendError::Corrupt)),
            "{change}"
        );
    }
    Ok(())
}

#[test]
fn immutable_held_directory_does_not_follow_replaced_original_path() -> TestResult {
    let root = Root::new()?;
    let original = root.0.join("original");
    fs::create_dir(&original)?;
    let mut backend = FileBackend::create_new(&original)?;
    let profile = backend.immutable_blob_profile()?;
    let address = locator(13)?;
    let moved = root.0.join("moved");
    fs::rename(&original, &moved)?;
    fs::create_dir(&original)?;
    fs::write(original.join(address.leaf()), b"unrelated")?;
    let pin = published(backend.stage_immutable_ciphertext(address, b"old-owner")?)?;
    assert_eq!(pin.directory_identity(), profile.directory_identity);
    assert_eq!(pin.read_ciphertext()?.as_slice(), b"old-owner");
    assert_eq!(fs::read(moved.join(address.leaf()))?, b"old-owner");
    assert_eq!(fs::read(original.join(address.leaf()))?, b"unrelated");
    let replacement = FileBackend::open(&original)?;
    assert_ne!(
        replacement.immutable_blob_profile()?.directory_identity,
        profile.directory_identity
    );
    Ok(())
}

struct LegacyOnly(FileBackend);
impl DurableBackend for LegacyOnly {
    fn verify(&self) -> Result<(), BackendError> {
        self.0.verify()
    }
    fn load(&mut self) -> Result<BackendBundle, BackendError> {
        self.0.load()
    }
    fn initialize_empty(&mut self, initial: &BackendBundle) -> Result<(), BackendError> {
        self.0.initialize_empty(initial)
    }
    fn append_journal(&mut self, expected_len: usize, frame: &[u8]) -> Result<usize, BackendError> {
        self.0.append_journal(expected_len, frame)
    }
    fn truncate_journal(
        &mut self,
        expected_len: usize,
        new_len: usize,
    ) -> Result<(), BackendError> {
        self.0.truncate_journal(expected_len, new_len)
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
fn immutable_backend_default_is_unsupported_without_object_effects() -> TestResult {
    let root = Root::new()?;
    let mut backend: Box<dyn DurableBackend> =
        Box::new(LegacyOnly(FileBackend::create_new(&root.0)?));
    let address = locator(14)?;
    assert!(matches!(
        backend.immutable_blob_profile(),
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        backend.stage_immutable_ciphertext(address, b"ciphertext"),
        Err(BackendError::Unsupported)
    ));
    assert!(matches!(
        backend.pin_immutable_ciphertext(address, 10),
        Err(BackendError::Unsupported)
    ));
    assert!(!root.0.join(address.leaf()).exists());
    assert!(!root.0.join(TEMPORARY_LEAF).exists());
    Ok(())
}
