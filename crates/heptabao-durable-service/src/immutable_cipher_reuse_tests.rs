//! Actual filesystem reuse tests. Opaque ciphertext here is not typed native
//! admission or cryptographic proof; that remains the durable caller's job.
use super::*;
use crate::tests::serial_test;
use std::{
    fs,
    os::{fd::AsRawFd, unix::fs::symlink},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().canonicalize()?.join(format!(
            "heptabao-immutable-reuse-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn locator(address: u8) -> Result<BlobLocator, BackendError> {
    BlobLocator::new([0x67; 16], [address; 32])
}
fn published(stage: ImmutableBlobStage) -> Result<ImmutableBlobReadPin, BackendError> {
    match stage {
        ImmutableBlobStage::Published(pin) => Ok(pin),
        ImmutableBlobStage::AlreadyExists(_) => Err(BackendError::Corrupt),
    }
}
fn names(root: &Root) -> io::Result<Vec<std::ffi::OsString>> {
    let mut names = fs::read_dir(&root.0)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}

#[test]
fn immutable_reuse_syncs_same_fd_and_directory_without_temporary_write() -> TestResult {
    let _serial = serial_test();
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let address = locator(1)?;
    let bytes = vec![0x43; 256 * 1024 + 57];
    let first = published(backend.stage_immutable_ciphertext(address, &bytes)?)?;
    let profile = backend.immutable_blob_profile()?;
    // Ordinary staging must fail on this reserved-name directory. A successful
    // reuse therefore cannot quietly create or clean the old temporary path.
    let blocked_temporary = root.0.join(TEMPORARY_LEAF);
    fs::create_dir(&blocked_temporary)?;
    fs::write(blocked_temporary.join("sentinel"), b"keep")?;
    let before_names = names(&root)?;
    let mut file_syncs = 0;
    let mut directory_syncs = 0;
    let mut synced_fd = None;
    let mut gate_calls = 0;
    let reused = backend
        .reuse_immutable_ciphertext_with_sync(
            address,
            bytes.len(),
            &mut || {
                gate_calls += 1;
                Ok(())
            },
            &mut |file| {
                assert_eq!(
                    object_identity(file, bytes.len()).map_err(io::Error::other)?,
                    first.0.identity
                );
                synced_fd = Some(file.as_raw_fd());
                file.sync_all()?;
                file_syncs += 1;
                Ok(())
            },
            &mut |directory| {
                let identity = directory.identity();
                assert_eq!(
                    identity.device().to_le_bytes(),
                    profile.directory_identity[..8]
                );
                assert_eq!(
                    identity.inode().to_le_bytes(),
                    profile.directory_identity[8..]
                );
                directory.sync_all().map_err(io::Error::other)?;
                directory_syncs += 1;
                Ok(())
            },
        )?
        .ok_or("existing file reported absent")?;
    assert_eq!(file_syncs, 1);
    assert_eq!(directory_syncs, 1);
    assert!(gate_calls >= 8);
    assert_eq!(synced_fd, Some(reused.0.file.as_raw_fd()));
    assert_eq!(reused.0.identity, first.0.identity);
    assert_eq!(reused.read_ciphertext()?.as_slice(), bytes);
    assert_eq!(names(&root)?, before_names);
    assert_eq!(fs::read(blocked_temporary.join("sentinel"))?, b"keep");
    Ok(())
}

#[test]
fn immutable_reuse_initial_absence_does_no_sync_and_keeps_every_gate() -> TestResult {
    let _serial = serial_test();
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let before_names = names(&root)?;
    let address = locator(2)?;
    let mut gate_count = 0;
    let mut syncs = 0;
    let missing = backend.reuse_immutable_ciphertext_with_sync(
        address,
        10,
        &mut || {
            gate_count += 1;
            Ok(())
        },
        &mut |file| {
            syncs += 1;
            file.sync_all()
        },
        &mut |directory| directory.sync_all().map_err(io::Error::other),
    )?;
    assert!(missing.is_none());
    assert_eq!(syncs, 0);
    assert_eq!(names(&root)?, before_names);
    // Also reject after the ENOENT observation, before it could become None.
    for reject_at in 1..=gate_count {
        let mut calls = 0;
        assert!(matches!(
            backend.reuse_immutable_ciphertext_checked(address, 10, &mut || {
                calls += 1;
                if calls == reject_at {
                    Err(BackendError::Unavailable)
                } else {
                    Ok(())
                }
            }),
            Err(BackendError::Unavailable)
        ));
        assert!(backend.immutable_blob_profile()?.is_live());
        assert_eq!(names(&root)?, before_names);
    }
    Ok(())
}

#[test]
fn immutable_reuse_original_gate_rejection_never_returns_or_revokes_a_pin() -> TestResult {
    let _serial = serial_test();
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let address = locator(3)?;
    let first = published(backend.stage_immutable_ciphertext(address, b"old-cipher")?)?;
    let mut gate_count = 0;
    backend
        .reuse_immutable_ciphertext_checked(address, 10, &mut || {
            gate_count += 1;
            Ok(())
        })?
        .ok_or("missing existing gate fixture")?;
    for reject_at in 1..=gate_count {
        let mut calls = 0;
        assert!(matches!(
            backend.reuse_immutable_ciphertext_checked(address, 10, &mut || {
                calls += 1;
                if calls == reject_at {
                    Err(BackendError::Unavailable)
                } else {
                    Ok(())
                }
            }),
            Err(BackendError::Unavailable)
        ));
        // Custody denial is not a fabricated uncertain physical write.
        assert!(backend.immutable_blob_profile()?.is_live());
        assert_eq!(first.read_ciphertext()?.as_slice(), b"old-cipher");
        assert!(!root.0.join(TEMPORARY_LEAF).exists());
    }
    Ok(())
}

#[test]
fn immutable_reuse_wrong_length_and_unsafe_leaf_never_sync_or_overwrite() -> TestResult {
    let _serial = serial_test();
    for kind in ["length", "symlink", "hardlink", "directory"] {
        let root = Root::new()?;
        let mut backend = FileBackend::create_new(&root.0)?;
        let address = locator(4)?;
        let leaf = root.0.join(address.leaf());
        let sentinel = root.0.join("sentinel");
        fs::write(&sentinel, b"unchanged")?;
        match kind {
            "length" => fs::write(&leaf, b"short")?,
            "symlink" => symlink(&sentinel, &leaf)?,
            "hardlink" => fs::hard_link(&sentinel, &leaf)?,
            "directory" => fs::create_dir(&leaf)?,
            _ => unreachable!(),
        }
        let before_names = names(&root)?;
        let mut file_syncs = 0;
        let result = backend.reuse_immutable_ciphertext_with_sync(
            address,
            9,
            &mut || Ok(()),
            &mut |file| {
                file_syncs += 1;
                file.sync_all()
            },
            &mut |directory| directory.sync_all().map_err(io::Error::other),
        );
        assert!(matches!(result, Err(BackendError::Corrupt)), "{kind}");
        assert_eq!(file_syncs, 0, "{kind}");
        assert_eq!(names(&root)?, before_names, "{kind}");
        assert_eq!(fs::read(&sentinel)?, b"unchanged", "{kind}");
        if kind == "length" {
            assert_eq!(fs::read(&leaf)?, b"short");
        }
    }
    Ok(())
}

#[test]
fn immutable_reuse_opened_leaf_loss_or_replacement_never_becomes_absence() -> TestResult {
    let _serial = serial_test();
    for phase in ["file", "directory"] {
        for replace in [false, true] {
            let root = Root::new()?;
            let mut backend = FileBackend::create_new(&root.0)?;
            let address = locator(5)?;
            let original = b"old-cipher";
            let replacement = b"new-cipher";
            let first = published(backend.stage_immutable_ciphertext(address, original)?)?;
            let leaf = root.0.join(address.leaf());
            let retained = root.0.join("retained-original");
            let change_name = || -> io::Result<()> {
                fs::rename(&leaf, &retained)?;
                if replace {
                    fs::write(&leaf, replacement)?;
                }
                Ok(())
            };
            let result = backend.reuse_immutable_ciphertext_with_sync(
                address,
                original.len(),
                &mut || Ok(()),
                &mut |file| {
                    file.sync_all()?;
                    if phase == "file" {
                        change_name()?;
                    }
                    Ok(())
                },
                &mut |directory| {
                    directory.sync_all().map_err(io::Error::other)?;
                    if phase == "directory" {
                        change_name()?;
                    }
                    Ok(())
                },
            );
            assert!(matches!(result, Err(BackendError::OutcomeUnknown)));
            assert!(matches!(first.read_ciphertext(), Err(BackendError::Unavailable)));
            assert_eq!(fs::read(&retained)?, original);
            if replace {
                assert_eq!(fs::read(&leaf)?, replacement);
            } else {
                assert!(!leaf.exists());
            }
            assert!(!root.0.join(TEMPORARY_LEAF).exists());
        }
    }
    Ok(())
}

#[test]
fn immutable_reuse_lost_sync_ack_fences_then_cold_reauthenticates_same_leaf() -> TestResult {
    let _serial = serial_test();
    for phase in ["file", "directory"] {
        let root = Root::new()?;
        let mut backend = FileBackend::create_new(&root.0)?;
        let address = locator(6)?;
        let first = published(backend.stage_immutable_ciphertext(address, b"old-cipher")?)?;
        let initial_identity = first.0.identity;
        let result = backend.reuse_immutable_ciphertext_with_sync(
            address,
            10,
            &mut || Ok(()),
            &mut |file| {
                file.sync_all()?;
                if phase == "file" {
                    Err(io::Error::other("injected lost completed file sync acknowledgement"))
                } else {
                    Ok(())
                }
            },
            &mut |directory| {
                directory.sync_all().map_err(io::Error::other)?;
                if phase == "directory" {
                    Err(io::Error::other("injected lost completed directory sync acknowledgement"))
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(result, Err(BackendError::OutcomeUnknown)));
        assert!(matches!(first.read_ciphertext(), Err(BackendError::Unavailable)));
        assert!(matches!(backend.immutable_blob_profile(), Err(BackendError::Unavailable)));
        assert_eq!(fs::read(root.0.join(address.leaf()))?, b"old-cipher");
        drop(backend);
        let mut cold = FileBackend::open(&root.0)?;
        let fresh = cold
            .reuse_immutable_ciphertext_checked(address, 10, &mut || Ok(()))?
            .ok_or("cold existing file reported absent")?;
        assert_eq!(fresh.0.identity, initial_identity);
        assert_eq!(fresh.read_ciphertext()?.as_slice(), b"old-cipher");
        assert!(matches!(first.read_ciphertext(), Err(BackendError::Unavailable)));
    }
    Ok(())
}

#[test]
fn immutable_reuse_same_inode_aba_across_real_sync_callbacks_is_rejected() -> TestResult {
    let _serial = serial_test();
    for phase in ["file", "directory", "between_syncs"] {
        let root = Root::new()?;
        let mut backend = FileBackend::create_new(&root.0)?;
        let address = locator(7)?;
        let original = b"old-cipher";
        let alternate = b"new-cipher";
        let first = published(backend.stage_immutable_ciphertext(address, original)?)?;
        let leaf = root.0.join(address.leaf());
        let before_names = names(&root)?;
        let before = object_metadata_witness(&first.0.file, original.len())?;
        let original_modified = first.0.file.metadata()?.modified()?;
        let restore_pending = Cell::new(false);
        let restored = Cell::new(false);
        let file_syncs = Cell::new(0);
        let directory_syncs = Cell::new(0);
        let rewrite = |bytes: &[u8]| -> io::Result<()> {
            // Actual writes to the existing inode, without truncate/rename.
            let mut writer = fs::OpenOptions::new().write(true).open(&leaf)?;
            writer.write_all(bytes)?;
            // Restore mtime too: ctime must remain part of the witness even
            // when both the final full read and visible mtime again match A.
            writer.set_modified(original_modified)?;
            Ok(())
        };
        let result = backend.reuse_immutable_ciphertext_with_sync(
            address,
            original.len(),
            &mut || {
                if restore_pending.replace(false) {
                    rewrite(original).map_err(|_| BackendError::Io)?;
                    restored.set(true);
                }
                Ok(())
            },
            &mut |file| {
                if phase == "file" || phase == "between_syncs" {
                    rewrite(alternate)?;
                    assert_eq!(fs::read(&leaf)?, alternate);
                }
                // The candidate's very same held descriptor really syncs B.
                file.sync_all()?;
                file_syncs.set(file_syncs.get() + 1);
                if phase == "file" {
                    rewrite(original)?;
                    restored.set(true);
                } else if phase == "between_syncs" {
                    // Restore in the original gate between the two sync
                    // callbacks. New code must refuse before entering dir sync.
                    restore_pending.set(true);
                }
                Ok(())
            },
            &mut |directory| {
                if phase == "directory" {
                    rewrite(alternate)?;
                    assert_eq!(fs::read(&leaf)?, alternate);
                }
                directory.sync_all().map_err(io::Error::other)?;
                directory_syncs.set(directory_syncs.get() + 1);
                if phase == "directory" {
                    rewrite(original)?;
                    restored.set(true);
                }
                Ok(())
            },
        );
        assert!(restored.get(), "the actual A -> B -> A callback must run: {phase}");
        assert!(matches!(result, Err(BackendError::OutcomeUnknown)), "{phase}");
        assert_eq!(file_syncs.get(), 1, "{phase}");
        assert_eq!(directory_syncs.get(), if phase == "directory" { 1 } else { 0 });
        let after = object_metadata_witness(&first.0.file, original.len())?;
        assert_eq!(before.identity, after.identity, "{phase}");
        assert_eq!(before.modified_seconds, after.modified_seconds, "{phase}");
        assert_eq!(before.modified_nanos, after.modified_nanos, "{phase}");
        assert_ne!(
            (before.changed_seconds, before.changed_nanos),
            (after.changed_seconds, after.changed_nanos),
            "actual filesystem must expose the ctime mutation: {phase}"
        );
        assert_eq!(fs::read(&leaf)?, original, "{phase}");
        assert_eq!(names(&root)?, before_names, "{phase}");
        assert!(matches!(first.read_ciphertext(), Err(BackendError::Unavailable)));
        assert!(!root.0.join(TEMPORARY_LEAF).exists());
    }
    Ok(())
}
