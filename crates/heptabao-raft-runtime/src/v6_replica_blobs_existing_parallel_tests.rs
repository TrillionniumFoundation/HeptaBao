use super::*;
use std::{
    cell::Cell,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::PathBuf,
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
            "hb-existing-replica-parallel-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

type Fixture = (Root, LocalV6BlobStage, Vec<RecordObjectRef>, Vec<Vec<u8>>);
fn fixture(count: usize) -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let values: Vec<_> = (0..count)
        .map(|index| vec![index as u8 + 0x31; 4096])
        .collect();
    let mut references = Vec::new();
    for value in &values {
        references.push(
            store
                .stage_local_checked(value, &mut || Ok(()))?
                .reference()
                .clone(),
        );
    }
    Ok((root, store, references, values))
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
fn parallel_existing_replica_real_four_fd_syncs_caller_gate_and_cold_reopen() -> TestResult {
    let (root, store, refs, values) = fixture(9)?;
    let ciphertexts: Vec<_> = values.iter().map(Vec::as_slice).collect();
    let caller = std::thread::current().id();
    let gates = Cell::new(0usize);
    let mut widths = Vec::new();
    let mut directories = 0;
    let observed_fds = Mutex::new(Vec::new());
    let finished = AtomicUsize::new(0);
    let started = Instant::now();
    let held = store.hold_existing_exact_batch_with_sync_chunks(
        &refs,
        &ciphertexts,
        &mut || {
            assert_eq!(std::thread::current().id(), caller);
            gates.set(gates.get() + 1);
            Ok(())
        },
        &mut |files| {
            widths.push(files.len());
            let before = gates.get();
            let arrived = (Mutex::new(0usize), Condvar::new());
            let result = parallel_existing_sync(files, &|file| {
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
            assert_eq!(gates.get(), before, "no non-Send gate enters a worker");
            Ok(result
                .into_iter()
                .map(|result| result.map_err(Into::into))
                .collect())
        },
        &mut |directory| {
            assert_eq!(finished.load(Ordering::SeqCst), 9);
            directory.sync_all()?;
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
    for (item, reference) in held.into_iter().zip(&refs) {
        let item = item.ok_or("existing replica disappeared")?;
        returned.push(item.file.as_raw_fd());
        item.check_without_callback(&store)?;
        assert_eq!(item.into_receipt().reference(), reference);
    }
    actual.sort_unstable();
    returned.sort_unstable();
    assert_eq!(actual, returned);
    println!(
        "HB-EXISTING-REPLICA-PARALLEL objects=9 file_syncs=9 directory_syncs=1 elapsed_us={}",
        started.elapsed().as_micros()
    );
    drop(store);
    let cold = LocalV6BlobStage::open_existing(&root.0)?;
    let inputs: Vec<_> = refs
        .iter()
        .zip(&values)
        .map(|(r, v)| (r, v.as_slice()))
        .collect();
    let receipts = cold.sync_existing_replicas_batch_checked(&inputs, &mut || Ok(()))?;
    for (receipt, value) in receipts.iter().zip(&values) {
        assert_eq!(
            cold.read_local(receipt.reference())?.as_slice(),
            value.as_slice()
        );
    }
    Ok(())
}

#[test]
fn parallel_existing_replica_fault_or_panic_joins_all_before_error_and_no_next_chunk() -> TestResult
{
    for panic_worker in [false, true] {
        let (_root, store, refs, values) = fixture(9)?;
        let ciphertexts: Vec<_> = values.iter().map(Vec::as_slice).collect();
        let mut chunks = 0;
        let mut directories = 0;
        let finished = AtomicUsize::new(0);
        let sequence = AtomicUsize::new(0);
        let result = store.hold_existing_exact_batch_with_sync_chunks(
            &refs,
            &ciphertexts,
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
                    "all workers joined before core sees failure"
                );
                Ok(results.into_iter().map(|r| r.map_err(Into::into)).collect())
            },
            &mut |directory| {
                directories += 1;
                directory.sync_all()?;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(chunks, 1);
        assert_eq!(directories, 0);
        assert_eq!(finished.load(Ordering::SeqCst), 4);
    }
    Ok(())
}

#[test]
fn parallel_existing_replica_retains_pre_sync_witness_after_real_aba() -> TestResult {
    let (root, store, refs, values) = fixture(4)?;
    let path = root.0.join(LocalV6BlobStage::leaf(&refs[0])?);
    let ciphertexts: Vec<_> = values.iter().map(Vec::as_slice).collect();
    let changed = Cell::new(false);
    let mut directories = 0;
    let result = store.hold_existing_exact_batch_with_sync_chunks(
        &refs,
        &ciphertexts,
        &mut || Ok(()),
        &mut |files| {
            let synced = parallel_existing_sync(files, &File::sync_all)?;
            for result in &synced {
                assert!(result.is_ok());
            }
            real_aba(&path, &values[0])?;
            changed.set(true);
            Ok(synced.into_iter().map(|r| r.map_err(Into::into)).collect())
        },
        &mut |directory| {
            directories += 1;
            directory.sync_all()?;
            Ok(())
        },
    );
    assert!(changed.get());
    assert!(result.is_err());
    assert_eq!(directories, 0);
    assert_eq!(fs::read(path)?, values[0]);
    Ok(())
}

#[test]
fn parallel_existing_replica_later_pre_gate_aba_never_starts_any_sync() -> TestResult {
    let (root, store, refs, values) = fixture(4)?;
    let path = root.0.join(LocalV6BlobStage::leaf(&refs[0])?);
    let ciphertexts: Vec<_> = values.iter().map(Vec::as_slice).collect();
    let count = Cell::new(0usize);
    let mut before_dispatch = 0;
    store.hold_existing_exact_batch_with_sync_chunks(
        &refs,
        &ciphertexts,
        &mut || {
            count.set(count.get() + 1);
            Ok(())
        },
        &mut |files| {
            before_dispatch = count.get();
            Ok(parallel_existing_sync(files, &File::sync_all)?
                .into_iter()
                .map(|r| r.map_err(Into::into))
                .collect())
        },
        &mut |directory| {
            directory.sync_all()?;
            Ok(())
        },
    )?;
    count.set(0);
    let changed = Cell::new(false);
    let syncs = Cell::new(0usize);
    let result = store.hold_existing_exact_batch_with_sync_chunks(
        &refs,
        &ciphertexts,
        &mut || {
            count.set(count.get() + 1);
            if count.get() == before_dispatch {
                real_aba(&path, &values[0])?;
                changed.set(true);
            }
            Ok(())
        },
        &mut |files| {
            syncs.set(syncs.get() + 1);
            Ok(parallel_existing_sync(files, &File::sync_all)?
                .into_iter()
                .map(|r| r.map_err(Into::into))
                .collect())
        },
        &mut |directory| {
            directory.sync_all()?;
            Ok(())
        },
    );
    assert!(changed.get());
    assert!(result.is_err());
    assert_eq!(syncs.get(), 0);
    Ok(())
}
