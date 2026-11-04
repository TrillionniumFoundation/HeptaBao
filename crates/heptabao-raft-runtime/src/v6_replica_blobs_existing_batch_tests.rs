use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    cell::Cell,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::PathBuf,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().canonicalize()?.join(format!(
            "hb-existing-replica-batch-{}-{}",
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
fn references(values: &[Vec<u8>]) -> Result<Vec<RecordObjectRef>, LocalV6BlobError> {
    values
        .iter()
        .map(|value| {
            SealedRecordObject::new_native_v6_ciphertext_chunk(value.clone())
                .map(|value| value.reference().clone())
                .map_err(|_| LocalV6BlobError::InvalidCiphertext)
        })
        .collect()
}
fn borrowed(values: &[Vec<u8>]) -> Vec<&[u8]> {
    values.iter().map(Vec::as_slice).collect()
}
fn names(root: &Root) -> io::Result<Vec<std::ffi::OsString>> {
    let mut result = fs::read_dir(&root.0)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    result.sort();
    Ok(result)
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
fn bounded_existing_replica_real_fd_barriers_shared_directory_and_cold_reopen() -> TestResult {
    let root = Root::new()?;
    let values = vec![vec![0x31; 32 * 1024], vec![0x32; 64 * 1024]];
    let references = references(&values)?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    for value in &values {
        store.stage_local_checked(value, &mut || Ok(()))?;
    }
    let before = names(&root)?;
    drop(store);
    let cold = LocalV6BlobStage::open_existing(&root.0)?;
    let mut fds = Vec::new();
    let mut directories = 0;
    let held = cold.hold_existing_exact_batch_with_sync(
        &references,
        &borrowed(&values),
        &mut || Ok(()),
        &mut |file| {
            file.sync_all()?;
            fds.push(file.as_raw_fd());
            Ok(())
        },
        &mut |directory| {
            directory.sync_all()?;
            directories += 1;
            Ok(())
        },
    )?;
    assert_eq!(fds.len(), 2);
    assert_eq!(directories, 1);
    for ((item, fd), reference) in held.into_iter().zip(fds).zip(&references) {
        let item = item.ok_or("cold existing ciphertext reported absent")?;
        assert_eq!(item.file.as_raw_fd(), fd);
        item.check_without_callback(&cold)?;
        assert_eq!(item.into_receipt().reference(), reference);
    }
    let inputs: Vec<_> = references
        .iter()
        .zip(&values)
        .map(|(r, v)| (r, v.as_slice()))
        .collect();
    let receipts = cold.sync_existing_replicas_batch_checked(&inputs, &mut || Ok(()))?;
    for (receipt, value) in receipts.iter().zip(&values) {
        assert_eq!(&cold.read_local(receipt.reference())?, value);
    }
    assert_eq!(names(&root)?, before);
    let missing = SealedRecordObject::new_native_v6_ciphertext_chunk(vec![0x33; 32])?;
    assert!(
        cold.sync_existing_replicas_batch_checked(
            &[(missing.reference(), missing.sealed())],
            &mut || Ok(()),
        )
        .is_err()
    );
    assert_eq!(
        names(&root)?,
        before,
        "existing-only API cannot create missing leaves"
    );
    Ok(())
}

#[test]
fn bounded_existing_replica_bounds_wrong_reference_and_mixed_absence_fail_closed() -> TestResult {
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let large: Vec<_> = (0..17).map(|n| vec![n; 256 * 1024]).collect();
    let large_refs = references(&large)?;
    let many: Vec<_> = (0..33).map(|n| vec![n; 32]).collect();
    let many_refs = references(&many)?;
    for (refs, values) in [
        (&[][..], &[][..]),
        (large_refs.as_slice(), large.as_slice()),
        (many_refs.as_slice(), many.as_slice()),
    ] {
        let files = Cell::new(0);
        let dirs = Cell::new(0);
        let result = store.hold_existing_exact_batch_with_sync(
            refs,
            &borrowed(values),
            &mut || Ok(()),
            &mut |file| {
                files.set(files.get() + 1);
                file.sync_all()?;
                Ok(())
            },
            &mut |directory| {
                dirs.set(dirs.get() + 1);
                directory.sync_all()?;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!((files.get(), dirs.get()), (0, 0));
    }
    let values = vec![vec![0x51; 32], vec![0x52; 32]];
    let refs = references(&values)?;
    store.stage_local_checked(&values[0], &mut || Ok(()))?;
    let before = names(&root)?;
    assert!(
        store
            .sync_existing_replicas_batch_checked(&[(&refs[0], &values[1])], &mut || Ok(()),)
            .is_err()
    );
    assert!(
        store
            .sync_existing_replicas_batch_checked(
                &[(&refs[0], &values[0]), (&refs[0], &values[0])],
                &mut || Ok(()),
            )
            .is_err()
    );
    assert!(
        store
            .sync_existing_replicas_batch_checked(
                &[(&refs[0], &values[0]), (&refs[1], &values[1])],
                &mut || Ok(()),
            )
            .is_err()
    );
    assert_eq!(names(&root)?, before);
    assert_eq!(store.read_local(&refs[0])?, values[0]);
    Ok(())
}

#[test]
fn bounded_existing_replica_later_member_and_final_gate_aba_reject_original_witness() -> TestResult
{
    for phase in ["later_file", "directory", "terminal_gate"] {
        let root = Root::new()?;
        let store = LocalV6BlobStage::open_existing(&root.0)?;
        let values = vec![vec![0x61; 4096], vec![0x62; 4096]];
        let refs = references(&values)?;
        for value in &values {
            store.stage_local_checked(value, &mut || Ok(()))?;
        }
        let path = root.0.join(LocalV6BlobStage::leaf(&refs[0])?);
        let mut total_gates = 0;
        store.hold_existing_exact_batch_checked(&refs, &borrowed(&values), &mut || {
            total_gates += 1;
            Ok(())
        })?;
        let changed = Cell::new(false);
        let gates = Cell::new(0);
        let files = Cell::new(0);
        let result = store.hold_existing_exact_batch_with_sync(
            &refs,
            &borrowed(&values),
            &mut || {
                gates.set(gates.get() + 1);
                if phase == "terminal_gate" && gates.get() == total_gates {
                    real_aba(&path, &values[0])?;
                    changed.set(true);
                }
                Ok(())
            },
            &mut |file| {
                file.sync_all()?;
                files.set(files.get() + 1);
                if phase == "later_file" && files.get() == 2 {
                    real_aba(&path, &values[0])?;
                    changed.set(true);
                }
                Ok(())
            },
            &mut |directory| {
                directory.sync_all()?;
                if phase == "directory" {
                    real_aba(&path, &values[0])?;
                    changed.set(true);
                }
                Ok(())
            },
        );
        assert!(changed.get(), "{phase}");
        assert!(result.is_err(), "{phase}");
        assert_eq!(fs::read(path)?, values[0]);
    }
    Ok(())
}

#[test]
fn bounded_existing_replica_gate_or_lost_barrier_never_returns_receipts() -> TestResult {
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let values = vec![vec![0x71; 32], vec![0x72; 32]];
    let refs = references(&values)?;
    for value in &values {
        store.stage_local_checked(value, &mut || Ok(()))?;
    }
    let mut total_gates = 0;
    store.hold_existing_exact_batch_checked(&refs, &borrowed(&values), &mut || {
        total_gates += 1;
        Ok(())
    })?;
    for reject_at in 1..=total_gates {
        let mut count = 0;
        assert!(
            store
                .hold_existing_exact_batch_checked(&refs, &borrowed(&values), &mut || {
                    count += 1;
                    if count == reject_at {
                        Err(LocalV6BlobError::CorruptOrChanged)
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
    }
    for phase in ["file", "directory"] {
        let result = store.hold_existing_exact_batch_with_sync(
            &refs,
            &borrowed(&values),
            &mut || Ok(()),
            &mut |file| {
                file.sync_all()?;
                if phase == "file" {
                    Err(io::Error::other("lost real file sync acknowledgement").into())
                } else {
                    Ok(())
                }
            },
            &mut |directory| {
                directory.sync_all()?;
                Err(io::Error::other("lost real directory sync acknowledgement").into())
            },
        );
        assert!(result.is_err(), "{phase}");
    }
    drop(store);
    let cold = LocalV6BlobStage::open_existing(&root.0)?;
    let input: Vec<_> = refs
        .iter()
        .zip(&values)
        .map(|(r, v)| (r, v.as_slice()))
        .collect();
    let receipts = cold.sync_existing_replicas_batch_checked(&input, &mut || Ok(()))?;
    for (receipt, value) in receipts.iter().zip(&values) {
        assert_eq!(&cold.read_local(receipt.reference())?, value);
    }
    Ok(())
}
