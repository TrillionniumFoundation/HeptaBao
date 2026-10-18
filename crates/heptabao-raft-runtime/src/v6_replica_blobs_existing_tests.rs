use super::*;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::io::Cursor;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "hb-v6-existing-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        private_directory(&root)?;
        Ok(Self(root))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn entries(path: &Path) -> io::Result<BTreeSet<std::ffi::OsString>> {
    fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect()
}

const EVENTS: [ExistingStageEvent; 4] = [
    ExistingStageEvent::Opened,
    ExistingStageEvent::Authenticated,
    ExistingStageEvent::FileSynced,
    ExistingStageEvent::DirectorySynced,
];

#[test]
fn checked_existing_exact_keeps_inode_and_real_syncs_without_temporary_write() -> TestResult {
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let ciphertext = vec![0x71; 256 * 1024];
    let mut missing_used_temporary = false;
    let first = store.stage_local_checked(&ciphertext, &mut || {
        missing_used_temporary |= entries(&root.0)?
            .iter()
            .any(|name| name.to_string_lossy().starts_with(".v6-tmp-"));
        Ok(())
    })?;
    assert!(missing_used_temporary, "missing objects keep the original write path");
    let destination = root.0.join(LocalV6BlobStage::leaf(first.reference())?);
    let file = File::open(&destination)?;
    let identity = ExistingIdentity::read(&file, first.reference())?;
    let before = entries(&root.0)?;
    let mut events = Vec::new();
    let duplicate = store.sync_existing_exact_with_hook(
        first.reference(),
        &ciphertext,
        &mut || {
            if entries(&root.0)? != before {
                return Err(LocalV6BlobError::CorruptOrChanged);
            }
            Ok(())
        },
        &mut |event| {
            events.push(event);
            Ok(())
        },
    )?;
    assert_eq!(duplicate.ok_or("existing receipt absent")?.reference(), first.reference());
    assert_eq!(events, EVENTS);
    assert_eq!(ExistingIdentity::read(&file, first.reference())?, identity);
    assert_eq!(entries(&root.0)?, before);
    assert_eq!(fs::read(&destination)?, ciphertext);
    // The actual public receiver enters the same fast branch and still grants
    // only a local ciphertext receipt, without changing its expected reference.
    assert_eq!(
        store
            .stage_received_replica_checked(first.reference(), &ciphertext, &mut || Ok(()))?
            .reference(),
        first.reference()
    );
    assert_eq!(ExistingIdentity::read(&file, first.reference())?, identity);
    Ok(())
}

#[test]
fn checked_existing_bad_or_truncated_leaf_is_rejected_without_rewrite() -> TestResult {
    for truncated in [false, true] {
        let root = Root::new()?;
        let store = LocalV6BlobStage::open_existing(&root.0)?;
        let ciphertext = vec![0x72; 196_608];
        let first = store.stage_local_checked(&ciphertext, &mut || Ok(()))?;
        let destination = root.0.join(LocalV6BlobStage::leaf(first.reference())?);
        let mut bad = ciphertext.clone();
        if truncated {
            bad.pop();
        } else {
            let middle = bad.len() / 2;
            bad[middle] ^= 1;
        }
        fs::write(&destination, &bad)?;
        let before = entries(&root.0)?;
        assert!(
            store
                .stage_received_replica_checked(first.reference(), &ciphertext, &mut || Ok(()))
                .is_err()
        );
        assert_eq!(fs::read(&destination)?, bad);
        assert_eq!(entries(&root.0)?, before);
    }
    Ok(())
}

#[test]
fn checked_existing_symlink_hardlink_and_directory_are_never_missing() -> TestResult {
    for shape in ["symlink", "hardlink", "directory"] {
        let root = Root::new()?;
        let store = LocalV6BlobStage::open_existing(&root.0)?;
        let ciphertext = vec![0x73; 131_072];
        let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.clone())?;
        let destination = root.0.join(LocalV6BlobStage::leaf(object.reference())?);
        let source = root.0.join("unselected.blob");
        fs::write(&source, &ciphertext)?;
        match shape {
            "symlink" => symlink(&source, &destination)?,
            "hardlink" => fs::hard_link(&source, &destination)?,
            _ => private_directory(&destination)?,
        }
        let before = entries(&root.0)?;
        assert!(
            store
                .stage_received_replica_checked(object.reference(), &ciphertext, &mut || Ok(()))
                .is_err()
        );
        assert_eq!(entries(&root.0)?, before);
        assert_eq!(fs::read(&source)?, ciphertext);
    }
    Ok(())
}

#[test]
fn checked_existing_cancellation_at_actual_boundaries_releases_no_receipt() -> TestResult {
    for stop_at in EVENTS {
        let root = Root::new()?;
        let store = LocalV6BlobStage::open_existing(&root.0)?;
        let ciphertext = vec![0x74; 196_608];
        let first = store.stage_local_checked(&ciphertext, &mut || Ok(()))?;
        let before = entries(&root.0)?;
        let cancelled = Cell::new(false);
        let result = store.sync_existing_exact_with_hook(
            first.reference(),
            &ciphertext,
            &mut || {
                if cancelled.get() {
                    Err(LocalV6BlobError::CorruptOrChanged)
                } else {
                    Ok(())
                }
            },
            &mut |event| {
                if event == stop_at {
                    cancelled.set(true);
                }
                Ok(())
            },
        );
        assert!(cancelled.get(), "the selected physical boundary was reached");
        assert!(result.is_err());
        assert_eq!(entries(&root.0)?, before);
        assert_eq!(store.read_local(first.reference())?, ciphertext);
    }
    Ok(())
}

#[test]
fn checked_existing_original_deadline_after_actual_file_sync_is_not_renewed() -> TestResult {
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let ciphertext = vec![0x75; 131_072];
    let first = store.stage_local_checked(&ciphertext, &mut || Ok(()))?;
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut file_synced = false;
    let result = store.sync_existing_exact_with_hook(
        first.reference(),
        &ciphertext,
        &mut || {
            if Instant::now() >= deadline {
                Err(LocalV6BlobError::CorruptOrChanged)
            } else {
                Ok(())
            }
        },
        &mut |event| {
            if event == ExistingStageEvent::FileSynced {
                file_synced = true;
                std::thread::sleep(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                );
            }
            Ok(())
        },
    );
    assert!(file_synced);
    assert!(Instant::now() >= deadline);
    assert!(result.is_err());
    assert_eq!(store.read_local(first.reference())?, ciphertext);
    Ok(())
}

#[test]
fn checked_existing_same_content_name_replacement_at_each_boundary_is_rejected() -> TestResult {
    for replace_at in EVENTS {
        let root = Root::new()?;
        let store = LocalV6BlobStage::open_existing(&root.0)?;
        let ciphertext = vec![0x76; 131_072];
        let first = store.stage_local_checked(&ciphertext, &mut || Ok(()))?;
        let destination = root.0.join(LocalV6BlobStage::leaf(first.reference())?);
        let retired = root.0.join("retired.blob");
        let original_inode = fs::metadata(&destination)?.ino();
        let mut replaced = false;
        let result = store.sync_existing_exact_with_hook(
            first.reference(),
            &ciphertext,
            &mut || Ok(()),
            &mut |event| {
                if event == replace_at {
                    fs::rename(&destination, &retired)?;
                    fs::write(&destination, &ciphertext)?;
                    replaced = true;
                }
                Ok(())
            },
        );
        assert!(replaced);
        assert!(result.is_err(), "equal bytes do not authorize another inode");
        assert_ne!(fs::metadata(&destination)?.ino(), original_inode);
        assert_eq!(fs::metadata(&retired)?.ino(), original_inode);
        assert_eq!(fs::read(&destination)?, ciphertext);
        assert_eq!(fs::read(&retired)?, ciphertext);
    }
    Ok(())
}

#[test]
fn checked_existing_same_inode_mutation_after_each_real_sync_is_rejected() -> TestResult {
    for mutate_at in [ExistingStageEvent::FileSynced, ExistingStageEvent::DirectorySynced] {
        let root = Root::new()?;
        let store = LocalV6BlobStage::open_existing(&root.0)?;
        let ciphertext = vec![0x77; 131_072];
        let first = store.stage_local_checked(&ciphertext, &mut || Ok(()))?;
        let destination = root.0.join(LocalV6BlobStage::leaf(first.reference())?);
        let original_inode = fs::metadata(&destination)?.ino();
        let mut mutated = false;
        let result = store.sync_existing_exact_with_hook(
            first.reference(),
            &ciphertext,
            &mut || Ok(()),
            &mut |event| {
                if event == mutate_at {
                    let mut file = fs::OpenOptions::new().write(true).open(&destination)?;
                    file.write_all(&[ciphertext[0] ^ 1])?;
                    mutated = true;
                }
                Ok(())
            },
        );
        assert!(mutated);
        assert!(result.is_err());
        assert_eq!(fs::metadata(&destination)?.ino(), original_inode);
        let mut expected = ciphertext;
        expected[0] ^= 1;
        assert_eq!(fs::read(&destination)?, expected, "bad existing bytes remain untouched");
    }
    Ok(())
}

#[test]
fn checked_existing_directory_path_replacement_keeps_the_held_directory() -> TestResult {
    let root = Root::new()?;
    let original = root.0.join("cipher");
    private_directory(&original)?;
    let store = LocalV6BlobStage::open_existing(&original)?;
    let ciphertext = vec![0x78; 131_072];
    let first = store.stage_local_checked(&ciphertext, &mut || Ok(()))?;
    let leaf = LocalV6BlobStage::leaf(first.reference())?;
    let held = root.0.join("held");
    fs::rename(&original, &held)?;
    private_directory(&original)?;
    let trap = vec![0x79; ciphertext.len()];
    fs::write(original.join(&leaf), &trap)?;
    let before = entries(&original)?;
    assert_eq!(
        store
            .stage_received_replica_checked(first.reference(), &ciphertext, &mut || Ok(()))?
            .reference(),
        first.reference()
    );
    assert_eq!(fs::read(held.join(&leaf))?, ciphertext);
    assert_eq!(fs::read(original.join(&leaf))?, trap);
    assert_eq!(entries(&original)?, before);
    Ok(())
}

struct ShortReader<'a> {
    inner: Cursor<Vec<u8>>,
    maximum_requested: usize,
    calls: usize,
    interrupt: bool,
    cancel_after_read: Option<&'a Cell<bool>>,
}
impl Read for ShortReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        self.maximum_requested = self.maximum_requested.max(buffer.len());
        if self.interrupt && self.calls == 1 {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let limit = buffer.len().min(7 * 1024);
        let count = self.inner.read(&mut buffer[..limit])?;
        if let Some(cancelled) = self.cancel_after_read {
            cancelled.set(true);
        }
        Ok(count)
    }
}
impl Seek for ShortReader<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

#[test]
fn checked_existing_short_reads_eintr_and_eof_keep_each_64k_gate() -> TestResult {
    let ciphertext = vec![0x7a; 256 * 1024];
    let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.clone())?;
    let mut reader = ShortReader {
        inner: Cursor::new(ciphertext.clone()),
        maximum_requested: 0,
        calls: 0,
        interrupt: true,
        cancel_after_read: None,
    };
    read_exact_existing(&mut reader, object.reference(), &ciphertext, &mut || Ok(()))?;
    assert!(reader.maximum_requested <= 64 * 1024);
    assert!(reader.calls > ciphertext.len() / (7 * 1024));

    let cancelled = Cell::new(false);
    reader.calls = 0;
    reader.interrupt = false;
    reader.cancel_after_read = Some(&cancelled);
    let result = read_exact_existing(&mut reader, object.reference(), &ciphertext, &mut || {
        if cancelled.get() {
            Err(LocalV6BlobError::CorruptOrChanged)
        } else {
            Ok(())
        }
    });
    assert!(result.is_err());
    assert_eq!(reader.calls, 1, "the post-read original gate stops the next read");
    Ok(())
}

#[test]
fn checked_existing_trailing_bytes_and_full_reference_mismatch_are_rejected() -> TestResult {
    let ciphertext = vec![0x7b; 131_072];
    let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.clone())?;
    let mut grown = ciphertext.clone();
    grown.push(0);
    assert!(
        read_exact_existing(&mut Cursor::new(grown), object.reference(), &ciphertext, &mut || Ok(()))
            .is_err()
    );
    let mut forged = object.reference().clone();
    forged.record_count = 1;
    assert!(
        read_exact_existing(&mut Cursor::new(ciphertext.clone()), &forged, &ciphertext, &mut || Ok(()))
            .is_err()
    );
    Ok(())
}

#[test]
fn checked_existing_interrupted_reads_have_a_finite_original_gate_bound() -> TestResult {
    struct Interrupted {
        calls: usize,
    }
    impl Read for Interrupted {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            Err(io::Error::from(io::ErrorKind::Interrupted))
        }
    }
    impl Seek for Interrupted {
        fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
            Ok(0)
        }
    }
    let ciphertext = vec![0x7c; 25];
    let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.clone())?;
    let mut file = Interrupted { calls: 0 };
    assert!(
        read_exact_existing(&mut file, object.reference(), &ciphertext, &mut || Ok(()))
            .is_err()
    );
    assert!(file.calls <= 65);
    Ok(())
}
