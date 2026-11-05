use super::*;
use crate::tests::serial_test;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    cell::Cell,
    fs,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().canonicalize()?.join(format!(
            "hb-existing-reuse-batch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
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
    BlobLocator::new([0x73; 16], [address; 32])
}
fn seed(
    backend: &mut FileBackend,
    address: u8,
    bytes: &[u8],
) -> Result<ImmutableBlobReadPin, BackendError> {
    match backend.stage_immutable_ciphertext(locator(address)?, bytes)? {
        ImmutableBlobStage::Published(pin) => Ok(pin),
        ImmutableBlobStage::AlreadyExists(_) => Err(BackendError::Corrupt),
    }
}
fn names(root: &Root) -> io::Result<Vec<std::ffi::OsString>> {
    let mut names = fs::read_dir(&root.0)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}
fn real_aba(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let modified = fs::metadata(path)?.modified()?;
    let mut alternate = bytes.to_vec();
    alternate[0] ^= 1;
    fs::write(path, alternate)?;
    fs::write(path, bytes)?;
    if fs::metadata(path)?.modified()? == modified {
        fs::OpenOptions::new()
            .write(true)
            .open(path)?
            .set_modified(modified + std::time::Duration::from_secs(1))?;
    }
    Ok(())
}

#[test]
fn bounded_existing_reuse_real_per_file_sync_shared_directory_and_cold_reopen() -> TestResult {
    let _serial = serial_test();
    let root = Root::new()?;
    let values = [vec![0x41; 32 * 1024], vec![0x42; 64 * 1024]];
    let mut backend = FileBackend::create_new(&root.0)?;
    let prior = [
        seed(&mut backend, 1, &values[0])?,
        seed(&mut backend, 2, &values[1])?,
    ];
    let identities = [prior[0].0.identity, prior[1].0.identity];
    drop(backend);
    assert!(prior.iter().all(|pin| pin.read_ciphertext().is_err()));
    let mut backend = FileBackend::open(&root.0)?;
    fs::create_dir(root.0.join(TEMPORARY_LEAF))?;
    fs::write(root.0.join(TEMPORARY_LEAF).join("keep"), b"unchanged")?;
    let before = names(&root)?;
    let input = [
        (locator(1)?, values[0].len()),
        (locator(9)?, 17),
        (locator(2)?, values[1].len()),
    ];
    let mut actual_fds = Vec::new();
    let mut directories = 0;
    let pins = backend.reuse_immutable_ciphertext_batch_with_sync(
        &input,
        &mut || Ok(()),
        &mut |file| {
            let identity =
                object_identity(file, file.metadata()?.len() as usize).map_err(io::Error::other)?;
            assert!(identities.contains(&identity));
            file.sync_all()?;
            actual_fds.push(file.as_raw_fd());
            Ok(())
        },
        &mut |directory| {
            directory.sync_all().map_err(io::Error::other)?;
            directories += 1;
            Ok(())
        },
    )?;
    assert_eq!(actual_fds.len(), 2);
    assert_eq!(directories, 1);
    assert!(pins[1].is_none());
    for ((pin, expected), actual_fd) in [pins[0].as_ref(), pins[2].as_ref()]
        .into_iter()
        .zip(&values)
        .zip(actual_fds)
    {
        let pin = pin.ok_or("existing ciphertext reported missing")?;
        assert_eq!(pin.0.file.as_raw_fd(), actual_fd);
        assert!(pin.has_synchronized_ciphertext());
        assert_eq!(pin.read_ciphertext()?.as_slice(), expected.as_slice());
    }
    assert_eq!(names(&root)?, before);
    assert!(!root.0.join(locator(9)?.leaf()).exists());
    Ok(())
}

#[test]
fn bounded_existing_reuse_capacity_and_unsafe_member_do_not_sync_or_write() -> TestResult {
    let _serial = serial_test();
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    seed(&mut backend, 1, b"existing")?;
    let before = names(&root)?;
    let count: Vec<_> = (1..=33)
        .map(|n| Ok((locator(n)?, 1)))
        .collect::<Result<_, BackendError>>()?;
    let bytes: Vec<_> = (1..=9)
        .map(|n| Ok((locator(n)?, MAX_IMMUTABLE_CIPHERTEXT_BYTES)))
        .collect::<Result<_, BackendError>>()?;
    let duplicate = [(locator(1)?, 8), (locator(1)?, 8)];
    let wrong_len = [(locator(1)?, 9)];
    for input in [
        &[][..],
        count.as_slice(),
        bytes.as_slice(),
        duplicate.as_slice(),
        wrong_len.as_slice(),
    ] {
        let files = Cell::new(0);
        let dirs = Cell::new(0);
        let result = backend.reuse_immutable_ciphertext_batch_with_sync(
            input,
            &mut || Ok(()),
            &mut |file| {
                files.set(files.get() + 1);
                file.sync_all()
            },
            &mut |directory| {
                dirs.set(dirs.get() + 1);
                directory.sync_all().map_err(io::Error::other)
            },
        );
        assert!(result.is_err());
        assert_eq!((files.get(), dirs.get()), (0, 0));
        assert_eq!(names(&root)?, before);
    }
    for unsafe_kind in ["symlink", "hardlink"] {
        let target = root.0.join(locator(2)?.leaf());
        let original = root.0.join(locator(1)?.leaf());
        if unsafe_kind == "symlink" {
            std::os::unix::fs::symlink(&original, &target)?;
        } else {
            fs::hard_link(&original, &target)?;
        }
        let files = Cell::new(0);
        assert!(
            backend
                .reuse_immutable_ciphertext_batch_with_sync(
                    &[(locator(2)?, 8)],
                    &mut || Ok(()),
                    &mut |file| {
                        files.set(files.get() + 1);
                        file.sync_all()
                    },
                    &mut |directory| directory.sync_all().map_err(io::Error::other),
                )
                .is_err()
        );
        assert_eq!(files.get(), 0);
        fs::remove_file(target)?;
    }
    assert_eq!(fs::read(root.0.join(locator(1)?.leaf()))?, b"existing");
    let maximum = vec![0x5a; MAX_IMMUTABLE_CIPHERTEXT_BYTES];
    let mut exact = Vec::new();
    for address in 20..28 {
        seed(&mut backend, address, &maximum)?;
        exact.push((locator(address)?, maximum.len()));
    }
    assert_eq!(
        exact.iter().map(|(_, length)| length).sum::<usize>(),
        MAX_REUSE_BATCH_BYTES
    );
    let mut files = 0;
    let mut directories = 0;
    let pins = backend.reuse_immutable_ciphertext_batch_with_sync(
        &exact,
        &mut || Ok(()),
        &mut |file| {
            file.sync_all()?;
            files += 1;
            Ok(())
        },
        &mut |directory| {
            directory.sync_all().map_err(io::Error::other)?;
            directories += 1;
            Ok(())
        },
    )?;
    assert_eq!((files, directories), (8, 1));
    for pin in pins {
        assert_eq!(
            pin.ok_or("exact boundary existing leaf absent")?
                .read_ciphertext()?
                .as_slice(),
            maximum.as_slice()
        );
    }
    Ok(())
}

#[test]
fn bounded_existing_reuse_later_member_and_final_gate_aba_reject_original_witness() -> TestResult {
    let _serial = serial_test();
    for phase in ["later_file", "directory", "terminal_gate"] {
        let root = Root::new()?;
        let mut backend = FileBackend::create_new(&root.0)?;
        let values = [
            b"first ciphertext".as_slice(),
            b"other ciphertext".as_slice(),
        ];
        let old = seed(&mut backend, 1, values[0])?;
        seed(&mut backend, 2, values[1])?;
        let input = [
            (locator(1)?, values[0].len()),
            (locator(2)?, values[1].len()),
        ];
        let path = root.0.join(locator(1)?.leaf());
        let mut total_gates = 0;
        backend.reuse_immutable_ciphertext_batch_checked(&input, &mut || {
            total_gates += 1;
            Ok(())
        })?;
        let changed = Cell::new(false);
        let gates = Cell::new(0);
        let files = Cell::new(0);
        let result = backend.reuse_immutable_ciphertext_batch_with_sync(
            &input,
            &mut || {
                gates.set(gates.get() + 1);
                if phase == "terminal_gate" && gates.get() == total_gates {
                    real_aba(&path, values[0]).map_err(|_| BackendError::Io)?;
                    changed.set(true);
                }
                Ok(())
            },
            &mut |file| {
                file.sync_all()?;
                files.set(files.get() + 1);
                if phase == "later_file" && files.get() == 2 {
                    real_aba(&path, values[0])?;
                    changed.set(true);
                }
                Ok(())
            },
            &mut |directory| {
                directory.sync_all().map_err(io::Error::other)?;
                if phase == "directory" {
                    real_aba(&path, values[0])?;
                    changed.set(true);
                }
                Ok(())
            },
        );
        assert!(changed.get(), "{phase}");
        assert!(
            matches!(result, Err(BackendError::OutcomeUnknown)),
            "{phase}"
        );
        assert!(matches!(
            old.read_ciphertext(),
            Err(BackendError::Unavailable)
        ));
        assert_eq!(fs::read(path)?, values[0]);
    }
    Ok(())
}

#[test]
fn bounded_existing_reuse_gate_and_lost_sync_return_no_batch_and_cold_recover() -> TestResult {
    let _serial = serial_test();
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let values = [
        b"first ciphertext".as_slice(),
        b"other ciphertext".as_slice(),
    ];
    seed(&mut backend, 1, values[0])?;
    seed(&mut backend, 2, values[1])?;
    let input = [
        (locator(1)?, values[0].len()),
        (locator(2)?, values[1].len()),
    ];
    let mut count = 0;
    backend.reuse_immutable_ciphertext_batch_checked(&input, &mut || {
        count += 1;
        Ok(())
    })?;
    for reject_at in 1..=count {
        let mut called = 0;
        assert!(matches!(
            backend.reuse_immutable_ciphertext_batch_checked(&input, &mut || {
                called += 1;
                if called == reject_at {
                    Err(BackendError::Unavailable)
                } else {
                    Ok(())
                }
            }),
            Err(BackendError::Unavailable)
        ));
        assert!(backend.immutable_blob_profile()?.is_live());
    }
    drop(backend);
    for phase in ["file", "directory"] {
        let mut backend = FileBackend::open(&root.0)?;
        let result = backend.reuse_immutable_ciphertext_batch_with_sync(
            &input,
            &mut || Ok(()),
            &mut |file| {
                file.sync_all()?;
                if phase == "file" {
                    Err(io::Error::other("lost real file sync acknowledgement"))
                } else {
                    Ok(())
                }
            },
            &mut |directory| {
                directory.sync_all().map_err(io::Error::other)?;
                Err(io::Error::other("lost real directory sync acknowledgement"))
            },
        );
        assert!(
            matches!(result, Err(BackendError::OutcomeUnknown)),
            "{phase}"
        );
        assert!(matches!(
            backend.immutable_blob_profile(),
            Err(BackendError::Unavailable)
        ));
        drop(backend);
        let mut cold = FileBackend::open(&root.0)?;
        let pins = cold.reuse_immutable_ciphertext_batch_checked(&input, &mut || Ok(()))?;
        for (pin, expected) in pins.into_iter().zip(values) {
            assert_eq!(
                pin.ok_or("cold existing file disappeared")?
                    .read_ciphertext()?
                    .as_slice(),
                expected
            );
        }
    }
    Ok(())
}
