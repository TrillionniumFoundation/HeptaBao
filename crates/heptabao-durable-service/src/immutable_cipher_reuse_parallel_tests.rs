use super::*;
use crate::tests::serial_test;
use std::{
    cell::Cell,
    fs,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::{
        Condvar, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().canonicalize()?.join(format!(
            "hb-existing-reuse-parallel-{}-{}",
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
type Fixture = (Root, FileBackend, Vec<(BlobLocator, usize)>, Vec<Vec<u8>>);
fn fixture(count: usize) -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let mut objects = Vec::new();
    let mut values = Vec::new();
    for index in 0..count {
        let bytes = vec![index as u8 + 0x31; 4096];
        let locator = BlobLocator::new([0x73; 16], [index as u8 + 1; 32])?;
        assert!(matches!(
            backend.stage_immutable_ciphertext(locator, &bytes)?,
            ImmutableBlobStage::Published(_)
        ));
        objects.push((locator, bytes.len()));
        values.push(bytes);
    }
    Ok((root, backend, objects, values))
}
fn together(arrived: &(Mutex<usize>, Condvar), expected: usize) -> io::Result<()> {
    let mut count = arrived
        .0
        .lock()
        .map_err(|_| io::Error::other("test rendezvous poisoned"))?;
    *count += 1;
    arrived.1.notify_all();
    let (_count, timeout) = arrived
        .1
        .wait_timeout_while(count, Duration::from_secs(3), |count| *count < expected)
        .map_err(|_| io::Error::other("test rendezvous poisoned"))?;
    if timeout.timed_out() {
        return Err(io::Error::other("test workers did not overlap"));
    }
    Ok(())
}
fn real_aba(path: &Path, original: &[u8]) -> io::Result<()> {
    let before = fs::metadata(path)?.modified()?;
    let mut changed = original.to_vec();
    changed[0] ^= 1;
    fs::write(path, changed)?;
    fs::write(path, original)?;
    if fs::metadata(path)?.modified()? == before {
        fs::OpenOptions::new()
            .write(true)
            .open(path)?
            .set_modified(before + Duration::from_secs(1))?;
    }
    Ok(())
}

#[test]
fn parallel_existing_reuse_real_four_fd_syncs_caller_gate_and_cold_reopen() -> TestResult {
    let _serial = serial_test();
    let (root, mut backend, objects, values) = fixture(9)?;
    let caller = std::thread::current().id();
    let gates = Cell::new(0usize);
    let mut widths = Vec::new();
    let mut directories = 0;
    let observed_fds = Mutex::new(Vec::new());
    let finished = AtomicUsize::new(0);
    let started = Instant::now();
    let pins = backend.reuse_immutable_ciphertext_batch_with_sync_chunks(
        &objects,
        &mut || {
            assert_eq!(std::thread::current().id(), caller);
            gates.set(gates.get() + 1);
            Ok(())
        },
        &mut |files| {
            widths.push(files.len());
            let before = gates.get();
            let arrived = (Mutex::new(0usize), Condvar::new());
            let results = parallel_existing_sync(files, &|file| {
                assert_ne!(std::thread::current().id(), caller);
                together(&arrived, files.len())?;
                file.sync_all()?;
                observed_fds
                    .lock()
                    .map_err(|_| io::Error::other("test fd list poisoned"))?
                    .push(file.as_raw_fd());
                finished.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })?;
            assert_eq!(
                gates.get(),
                before,
                "non-Send owner gate stays on caller thread"
            );
            Ok(results)
        },
        &mut |directory| {
            assert_eq!(finished.load(Ordering::SeqCst), 9);
            directory.sync_all().map_err(io::Error::other)?;
            directories += 1;
            Ok(())
        },
    )?;
    assert_eq!(widths, [4, 4, 1]);
    assert_eq!(directories, 1);
    assert_eq!(MAX_PARALLEL_EXISTING_FSYNC, 4);
    let mut actual = observed_fds
        .into_inner()
        .map_err(|_| "test fd list poisoned")?;
    let mut returned = Vec::new();
    for (pin, expected) in pins.into_iter().zip(&values) {
        let pin = pin.ok_or("existing ciphertext disappeared")?;
        assert!(pin.has_synchronized_ciphertext());
        returned.push(pin.0.file.as_raw_fd());
        assert_eq!(pin.read_ciphertext()?.as_slice(), expected.as_slice());
    }
    actual.sort_unstable();
    returned.sort_unstable();
    assert_eq!(actual, returned);
    println!(
        "HB-EXISTING-REUSE-PARALLEL objects=9 file_syncs=9 directory_syncs=1 elapsed_us={}",
        started.elapsed().as_micros()
    );
    drop(backend);
    let mut cold = FileBackend::open(&root.0)?;
    let pins = cold.reuse_immutable_ciphertext_batch_checked(&objects, &mut || Ok(()))?;
    for (pin, expected) in pins.into_iter().zip(values) {
        assert_eq!(
            pin.ok_or("cold reuse absent")?
                .read_ciphertext()?
                .as_slice(),
            expected.as_slice()
        );
    }
    Ok(())
}

#[test]
fn parallel_existing_reuse_fault_or_panic_joins_all_revokes_lease_and_cold_recovers() -> TestResult
{
    let _serial = serial_test();
    for panic_worker in [false, true] {
        let (root, mut backend, objects, values) = fixture(9)?;
        let mut chunks = 0;
        let mut directories = 0;
        let finished = AtomicUsize::new(0);
        let sequence = AtomicUsize::new(0);
        let result = backend.reuse_immutable_ciphertext_batch_with_sync_chunks(
            &objects,
            &mut || Ok(()),
            &mut |files| {
                chunks += 1;
                let arrived = (Mutex::new(0usize), Condvar::new());
                let results = parallel_existing_sync(files, &|file| {
                    let index = sequence.fetch_add(1, Ordering::SeqCst);
                    together(&arrived, files.len())?;
                    file.sync_all()?;
                    if index == 3 {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    finished.fetch_add(1, Ordering::SeqCst);
                    if index == 0 {
                        if panic_worker {
                            std::panic::resume_unwind(Box::new(
                                "injected existing fsync worker unwind",
                            ));
                        }
                        return Err(io::Error::other(
                            "lost original strong fsync acknowledgement",
                        ));
                    }
                    Ok(())
                })?;
                assert_eq!(
                    finished.load(Ordering::SeqCst),
                    4,
                    "no detached worker remains on error"
                );
                Ok(results)
            },
            &mut |directory| {
                directories += 1;
                directory.sync_all().map_err(io::Error::other)
            },
        );
        assert!(matches!(result, Err(BackendError::OutcomeUnknown)));
        assert_eq!(chunks, 1);
        assert_eq!(directories, 0);
        assert_eq!(finished.load(Ordering::SeqCst), 4);
        assert!(matches!(
            backend.immutable_blob_profile(),
            Err(BackendError::Unavailable)
        ));
        drop(backend);
        let mut cold = FileBackend::open(&root.0)?;
        let pins = cold.reuse_immutable_ciphertext_batch_checked(&objects, &mut || Ok(()))?;
        for (pin, expected) in pins.into_iter().zip(values) {
            assert_eq!(
                pin.ok_or("cold reuse absent")?
                    .read_ciphertext()?
                    .as_slice(),
                expected.as_slice()
            );
        }
    }
    Ok(())
}

#[test]
fn parallel_existing_reuse_original_witness_rejects_real_aba_after_all_file_syncs() -> TestResult {
    let _serial = serial_test();
    let (root, mut backend, objects, values) = fixture(4)?;
    let path = root.0.join(objects[0].0.leaf());
    let mut directories = 0;
    let changed = Cell::new(false);
    let result = backend.reuse_immutable_ciphertext_batch_with_sync_chunks(
        &objects,
        &mut || Ok(()),
        &mut |files| {
            let results = parallel_existing_sync(files, &File::sync_all)?;
            assert!(results.iter().all(Result::is_ok));
            real_aba(&path, &values[0])?;
            changed.set(true);
            Ok(results)
        },
        &mut |directory| {
            directories += 1;
            directory.sync_all().map_err(io::Error::other)
        },
    );
    assert!(changed.get());
    assert!(matches!(result, Err(BackendError::OutcomeUnknown)));
    assert_eq!(directories, 0);
    assert!(matches!(
        backend.immutable_blob_profile(),
        Err(BackendError::Unavailable)
    ));
    assert_eq!(fs::read(path)?, values[0]);
    Ok(())
}

#[test]
fn parallel_existing_reuse_later_pre_gate_aba_never_starts_any_sync() -> TestResult {
    let _serial = serial_test();
    let (root, mut backend, objects, values) = fixture(4)?;
    let path = root.0.join(objects[0].0.leaf());
    let count = Cell::new(0usize);
    let mut before_dispatch = 0;
    backend.reuse_immutable_ciphertext_batch_with_sync_chunks(
        &objects,
        &mut || {
            count.set(count.get() + 1);
            Ok(())
        },
        &mut |files| {
            before_dispatch = count.get();
            parallel_existing_sync(files, &File::sync_all)
        },
        &mut |directory| directory.sync_all().map_err(io::Error::other),
    )?;
    count.set(0);
    let changed = Cell::new(false);
    let syncs = Cell::new(0usize);
    let result = backend.reuse_immutable_ciphertext_batch_with_sync_chunks(
        &objects,
        &mut || {
            count.set(count.get() + 1);
            if count.get() == before_dispatch {
                real_aba(&path, &values[0]).map_err(|_| BackendError::Unavailable)?;
                changed.set(true);
            }
            Ok(())
        },
        &mut |files| {
            syncs.set(syncs.get() + 1);
            parallel_existing_sync(files, &File::sync_all)
        },
        &mut |directory| directory.sync_all().map_err(io::Error::other),
    );
    assert!(changed.get());
    assert!(matches!(result, Err(BackendError::OutcomeUnknown)));
    assert_eq!(syncs.get(), 0);
    assert!(matches!(
        backend.immutable_blob_profile(),
        Err(BackendError::Unavailable)
    ));
    Ok(())
}
