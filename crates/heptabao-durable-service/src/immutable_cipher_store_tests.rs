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
    let reopened_profile = reopened.immutable_blob_profile()?;
    assert_eq!(
        reopened_profile.directory_identity,
        profile.directory_identity
    );
    assert_ne!(reopened_profile, profile);
    assert!(!profile.is_live());
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
        backend.stage_immutable_ciphertext_with_ack_hook(
            address,
            b"new-object",
            &mut || Ok(()),
            || Err(BackendError::Io)
        ),
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

#[test]
fn immutable_owner_profile_is_private_lineage_and_does_not_extend_writer_lock() -> TestResult {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let address = locator(15)?;
    let pin = published(backend.stage_immutable_ciphertext(address, b"ciphertext")?)?;
    let original = backend.immutable_blob_profile()?;
    assert_eq!(backend.immutable_blob_profile()?, original);
    assert!(pin.matches_profile(&original));
    let retained = original.clone();
    backend.close()?;
    assert!(!retained.is_live());
    assert!(!pin.matches_profile(&retained));
    let reopened = FileBackend::open(&root.0)?;
    let current = reopened.immutable_blob_profile()?;
    assert_eq!(current.directory_identity, retained.directory_identity);
    assert_ne!(current, retained);
    let cold = reopened.pin_immutable_ciphertext(address, 10)?;
    assert!(cold.matches_profile(&current));
    assert!(!cold.matches_profile(&retained));
    assert!(!pin.matches_profile(&current));
    Ok(())
}

#[test]
fn immutable_original_deadline_after_actual_pread_prevents_delivery_and_retry() -> TestResult {
    use std::{
        os::unix::fs::FileExt,
        time::{Duration, Instant},
    };
    for interrupt in [false, true] {
        let root = Root::new()?;
        let mut backend = FileBackend::create_new(&root.0)?;
        let pin = published(backend.stage_immutable_ciphertext(locator(16)?, b"ciphertext")?)?;
        let original_deadline = Instant::now() + Duration::from_millis(500);
        let mut gate = || {
            if Instant::now() >= original_deadline {
                Err(io::Error::other("original deadline expired"))
            } else {
                Ok(())
            }
        };
        let mut actual_reads = 0;
        let result = pin.read_ciphertext_with_reader(&mut gate, |file, bytes, offset| {
            actual_reads += 1;
            let actual = file.read_at(bytes, offset)?;
            std::thread::sleep(Duration::from_millis(550));
            if interrupt {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                Ok(actual)
            }
        });
        assert_eq!(actual_reads, 1);
        assert!(matches!(result, Err(PinReadError::Gate(_))));
        assert_eq!(pin.read_ciphertext()?.as_slice(), b"ciphertext");
    }
    Ok(())
}

#[test]
fn immutable_stage_gate_before_and_after_link_never_becomes_canonical_unknown() -> TestResult {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let address = locator(17)?;
    let profile = backend.immutable_blob_profile()?;
    assert!(matches!(
        backend.stage_immutable_ciphertext_checked(address, b"ciphertext", &mut || Err(
            BackendError::Unavailable
        )),
        Err(BackendError::Unavailable)
    ));
    assert!(backend.directory.entries()?.next().is_none());
    let actual_leaf = root.0.join(address.leaf());
    let mut gate = || {
        if actual_leaf.exists() {
            Err(BackendError::Unavailable)
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        backend.stage_immutable_ciphertext_checked(address, b"ciphertext", &mut gate),
        Err(BackendError::Unavailable)
    ));
    assert!(actual_leaf.exists());
    assert_eq!(fs::metadata(&actual_leaf)?.nlink(), 2);
    assert!(profile.is_live());
    assert_eq!(backend.immutable_blob_profile()?, profile);
    // A new caller gate can clean the unadmitted temp link and authenticate the
    // existing object later; the rejected operation never returned a root grant.
    let ImmutableBlobStage::AlreadyExists(pin) =
        backend.stage_immutable_ciphertext(address, b"othernonce")?
    else {
        return Err("unadmitted object was overwritten".into());
    };
    assert!(pin.matches_profile(&profile));
    assert_eq!(pin.read_ciphertext()?.as_slice(), b"ciphertext");
    Ok(())
}

#[test]
fn immutable_checked_box_dispatch_retains_caller_gate_and_default_unsupported() -> TestResult {
    let root = Root::new()?;
    let mut backend: Box<dyn DurableBackend> = Box::new(FileBackend::create_new(&root.0)?);
    let address = locator(18)?;
    let mut checks = 0;
    let mut gate = || {
        checks += 1;
        Ok(())
    };
    let pin = published(backend.stage_immutable_ciphertext_checked(
        address,
        b"ciphertext",
        &mut gate,
    )?)?;
    assert!(checks > 1);
    assert!(pin.matches_profile(&backend.immutable_blob_profile()?));
    let other_root = Root::new()?;
    let mut unsupported: Box<dyn DurableBackend> =
        Box::new(LegacyOnly(FileBackend::create_new(&other_root.0)?));
    assert!(matches!(
        unsupported.stage_immutable_ciphertext_checked(address, b"ciphertext", &mut || Ok(())),
        Err(BackendError::Unsupported)
    ));
    assert!(!other_root.0.join(address.leaf()).exists());
    Ok(())
}

#[test]
fn bounded_io_gate_preserves_full_owner_and_fails_before_untrusted_link() -> TestResult {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let bytes = vec![0x51; 256 * 1024 + 3];
    let a = locator(0x91)?;
    let b = locator(0x92)?;
    let objects = [(a, bytes.as_slice()), (b, bytes.as_slice())];
    let mut owner_checks = 0;
    let mut bounded_checks = 0;
    let stages = backend.stage_immutable_ciphertext_batch_with_io_gate(
        &objects,
        &mut || {
            owner_checks += 1;
            Ok(())
        },
        &mut || {
            bounded_checks += 1;
            Ok(())
        },
    )?;
    assert_eq!(stages.len(), objects.len());
    assert!(owner_checks >= objects.len() * 3);
    assert!(bounded_checks >= objects.len() * 2);
    for stage in stages {
        let pin = published(stage)?;
        assert_eq!(pin.read_ciphertext()?.as_slice(), bytes.as_slice());
    }
    assert!(backend.immutable_blob_profile()?.is_live());

    let failure_root = Root::new()?;
    let mut failure_backend = FileBackend::create_new(&failure_root.0)?;
    let forbidden = locator(0x93)?;
    let input = [(forbidden, bytes.as_slice())];
    let mut bounded_calls = 0;
    let result = failure_backend.stage_immutable_ciphertext_batch_with_io_gate(
        &input,
        &mut || Ok(()),
        &mut || {
            bounded_calls += 1;
            if bounded_calls == 2 {
                Err(BackendError::Unavailable)
            } else {
                Ok(())
            }
        },
    );
    assert!(matches!(result, Err(BackendError::Unavailable)));
    assert_eq!(bounded_calls, 2);
    assert!(!failure_root.0.join(forbidden.leaf()).exists());
    assert!(failure_backend.immutable_blob_profile()?.is_live());
    Ok(())
}

#[test]
fn successful_batches_can_reuse_known_clean_temporary_names_after_cold_open() -> TestResult {
    let root = Root::new()?;
    let mut owner = FileBackend::create_new(&root.0)?;
    let initial = initial()?;
    owner.initialize_empty(&initial)?;
    assert!(owner.immutable_batch_temps_known_clean);
    let bytes = vec![0x5a; 64 * 1024];
    for cycle in 0..4 {
        let a = locator(0xb0 + cycle * 2)?;
        let b = locator(0xb1 + cycle * 2)?;
        let batch = [(a, bytes.as_slice()), (b, bytes.as_slice())];
        let mut live_checks = 0;
        let result = owner.stage_immutable_ciphertext_batch_checked(&batch, &mut || {
            live_checks += 1;
            Ok(())
        })?;
        assert_eq!(result.len(), 2);
        assert!(live_checks >= 4);
        assert!(owner.immutable_batch_temps_known_clean);
        for pinned in result {
            assert_eq!(
                published(pinned)?.read_ciphertext()?.as_slice(),
                bytes.as_slice()
            );
        }
        for name in BATCH_TEMPORARIES {
            assert!(!root.0.join(name).exists());
        }
        assert_eq!(owner.load()?, initial);
    }
    drop(owner);
    let mut reopened = FileBackend::open(&root.0)?;
    assert!(reopened.immutable_batch_temps_known_clean);
    assert_eq!(reopened.load()?, initial);
    Ok(())
}

#[test]
fn failed_known_clean_batch_recovers_stale_temp_before_next_batch() -> TestResult {
    let root = Root::new()?;
    let mut owner = FileBackend::create_new(&root.0)?;
    let bytes = vec![0x5b; 8192];
    let first = [(locator(0xd1)?, bytes.as_slice())];
    let previous = owner.stage_immutable_ciphertext_batch_checked(&first, &mut || Ok(()))?;
    assert_eq!(previous.len(), 1);
    assert!(owner.immutable_batch_temps_known_clean);
    let victim = root.0.join(BATCH_TEMPORARIES[0]);
    let failed = [(locator(0xd2)?, bytes.as_slice())];
    let refused = owner.stage_immutable_ciphertext_batch_checked(&failed, &mut || {
        if victim.exists() {
            Err(BackendError::Unavailable)
        } else {
            Ok(())
        }
    });
    assert!(matches!(refused, Err(BackendError::Unavailable)));
    assert!(!owner.immutable_batch_temps_known_clean);
    assert!(victim.exists());
    assert!(!root.0.join(failed[0].0.leaf()).exists());
    let restored = owner.stage_immutable_ciphertext_batch_checked(&failed, &mut || Ok(()))?;
    assert_eq!(restored.len(), 1);
    assert!(owner.immutable_batch_temps_known_clean);
    assert!(!victim.exists());
    assert_eq!(
        published(restored.into_iter().next().ok_or("missing staged object")?)?
            .read_ciphertext()?
            .as_slice(),
        bytes.as_slice()
    );
    Ok(())
}

#[test]
fn unexpected_external_temp_while_known_clean_refuses_without_following_symlink() -> TestResult {
    let root = Root::new()?;
    let mut owner = FileBackend::create_new(&root.0)?;
    let bytes = vec![0x51; 4096];
    let a = [(locator(0xe1)?, bytes.as_slice())];
    assert_eq!(
        owner
            .stage_immutable_ciphertext_batch_checked(&a, &mut || Ok(()))?
            .len(),
        1
    );
    assert!(owner.immutable_batch_temps_known_clean);
    let victim = root.0.join(BATCH_TEMPORARIES[0]);
    let protected = root.0.join("never-follow-external");
    fs::write(&protected, b"preserve")?;
    symlink("never-follow-external", &victim)?;
    let b = [(locator(0xe2)?, bytes.as_slice())];
    assert!(
        owner
            .stage_immutable_ciphertext_batch_checked(&b, &mut || Ok(()))
            .is_err()
    );
    assert!(!owner.immutable_batch_temps_known_clean);
    assert!(victim.is_symlink());
    assert_eq!(fs::read(&protected)?, b"preserve");
    assert!(!root.0.join(b[0].0.leaf()).exists());
    assert_eq!(
        owner
            .stage_immutable_ciphertext_batch_checked(&b, &mut || Ok(()))?
            .len(),
        1
    );
    assert!(!victim.exists());
    assert_eq!(fs::read(&protected)?, b"preserve");
    Ok(())
}
