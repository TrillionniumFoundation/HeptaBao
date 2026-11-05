use super::*;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "hb-v6-prepare-batch-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self(root))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn payloads(count: usize, bytes: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|index| {
            let mut value = vec![0x61; bytes];
            value[..8].copy_from_slice(&(index as u64).to_be_bytes());
            value
        })
        .collect()
}
fn borrowed(values: &[Vec<u8>]) -> Vec<&[u8]> {
    values.iter().map(Vec::as_slice).collect()
}
fn destination(root: &Root, ciphertext: &[u8]) -> TestResult<PathBuf> {
    let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.to_vec())?;
    Ok(root.0.join(LocalV6BlobStage::leaf(object.reference())?))
}
fn names(root: &Root) -> io::Result<Vec<std::ffi::OsString>> {
    let mut result = fs::read_dir(&root.0)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    result.sort();
    Ok(result)
}
fn real_aba(path: &Path, original: &[u8]) -> Result<(), LocalV6BlobError> {
    let modified = fs::metadata(path)?.modified()?;
    let mut changed = original.to_vec();
    changed[0] ^= 1;
    fs::write(path, changed)?;
    fs::write(path, original)?;
    // Filesystem timestamp resolution must not make this witness-staleness
    // test probabilistic. This is an actual change to the same real file.
    if fs::metadata(path)?.modified()? == modified {
        fs::OpenOptions::new()
            .write(true)
            .open(path)?
            .set_modified(modified + std::time::Duration::from_secs(1))?;
    }
    Ok(())
}

#[test]
fn bounded_prepare_batch_new_and_cold_existing_exact_limits() -> TestResult {
    let root = Root::new()?;
    let values = payloads(32, 128 * 1024);
    let input = borrowed(&values);
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    store.stage_local_checked(&values[0], &mut || Ok(()))?;
    let existing = destination(&root, &values[0])?;
    let before = fs::metadata(&existing)?;
    let receipts = store.stage_local_batch_checked(&input, &mut || Ok(()))?;
    assert_eq!(receipts.len(), LocalV6BlobStage::MAX_CHECKED_BATCH_OBJECTS);
    assert_eq!(
        values.iter().map(Vec::len).sum::<usize>(),
        LocalV6BlobStage::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES
    );
    let after = fs::metadata(&existing)?;
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    for (receipt, expected) in receipts.iter().zip(&values) {
        assert_eq!(&store.read_local(receipt.reference())?, expected);
    }
    let actual_names = names(&root)?;
    drop(store);
    let cold = LocalV6BlobStage::open_existing(&root.0)?;
    let reopened = cold.stage_local_batch_checked(&input, &mut || Ok(()))?;
    assert_eq!(names(&root)?, actual_names);
    for ((receipt, prior), expected) in reopened.iter().zip(&receipts).zip(&values) {
        assert_eq!(receipt.reference(), prior.reference());
        assert_eq!(&cold.read_local(receipt.reference())?, expected);
    }
    Ok(())
}

#[test]
fn bounded_prepare_batch_rejects_empty_count_bytes_member_and_duplicates_before_write() -> TestResult
{
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let before = names(&root)?;
    assert!(
        store
            .stage_local_batch_checked(&[], &mut || Ok(()))
            .is_err()
    );
    let too_many = payloads(33, 25);
    assert!(
        store
            .stage_local_batch_checked(&borrowed(&too_many), &mut || Ok(()))
            .is_err()
    );
    let too_large = payloads(17, 256 * 1024);
    assert!(
        store
            .stage_local_batch_checked(&borrowed(&too_large), &mut || Ok(()))
            .is_err()
    );
    let one = vec![0x63; 256 * 1024 + 1];
    assert!(
        store
            .stage_local_batch_checked(&[&one], &mut || Ok(()))
            .is_err()
    );
    let same = vec![0x64; 25];
    assert!(
        store
            .stage_local_batch_checked(&[&same, &same], &mut || Ok(()))
            .is_err()
    );
    assert_eq!(names(&root)?, before);
    Ok(())
}

#[test]
fn bounded_prepare_batch_corrupt_existing_is_not_repaired_or_replaced() -> TestResult {
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let values = payloads(2, 4096);
    store.stage_local_checked(&values[0], &mut || Ok(()))?;
    let old = destination(&root, &values[0])?;
    let next = destination(&root, &values[1])?;
    let mut corrupt = values[0].clone();
    corrupt[17] ^= 1;
    fs::write(&old, &corrupt)?;
    let before = names(&root)?;
    assert!(
        store
            .stage_local_batch_checked(&borrowed(&values), &mut || Ok(()))
            .is_err()
    );
    assert_eq!(fs::read(&old)?, corrupt);
    assert!(!next.exists());
    assert_eq!(names(&root)?, before);
    Ok(())
}

#[test]
fn bounded_prepare_batch_original_gate_after_actual_link_returns_no_receipt() -> TestResult {
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let values = payloads(2, 65_536);
    let first = destination(&root, &values[0])?;
    let mut observed = false;
    let result = store.stage_local_batch_checked(&borrowed(&values), &mut || {
        if first.exists() {
            observed = true;
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        Ok(())
    });
    assert!(observed && first.exists());
    assert!(result.is_err());
    Ok(())
}

#[test]
fn bounded_prepare_batch_raced_existing_leaf_cannot_become_new_sync_receipt() -> TestResult {
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let values = payloads(2, 4096);
    let leaf = destination(&root, &values[0])?;
    let mut injected = false;
    let result = store.stage_local_batch_checked(&borrowed(&values), &mut || {
        if !injected
            && fs::read_dir(&root.0)?.any(|entry| {
                entry.is_ok_and(|entry| entry.file_name().to_string_lossy().starts_with(".v6-tmp-"))
            })
        {
            // The original initial-open miss has already happened. This is
            // a real independent equal-content file, deliberately not synced.
            let mut raced = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&leaf)?;
            raced.write_all(&values[0])?;
            injected = true;
        }
        Ok(())
    });
    assert!(injected);
    assert!(matches!(
        result,
        Err(LocalV6BlobError::Publication(
            ImmutablePublicationError::OutcomeUnknown(_)
        ))
    ));
    assert_eq!(fs::read(&leaf)?, values[0]);
    Ok(())
}

#[test]
fn bounded_prepare_batch_existing_aba_during_new_publication_rejects() -> TestResult {
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let values = payloads(2, 4096);
    store.stage_local_checked(&values[0], &mut || Ok(()))?;
    let old = destination(&root, &values[0])?;
    let new = destination(&root, &values[1])?;
    let mut changed = false;
    let result = store.stage_local_batch_checked(&borrowed(&values), &mut || {
        if !changed && new.exists() {
            real_aba(&old, &values[0])?;
            changed = true;
        }
        Ok(())
    });
    assert!(changed);
    assert!(matches!(result, Err(LocalV6BlobError::CorruptOrChanged)));
    assert_eq!(fs::read(&old)?, values[0]);
    Ok(())
}

#[test]
fn bounded_prepare_batch_existing_aba_at_last_gate_rejects() -> TestResult {
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let values = payloads(2, 4096);
    let input = borrowed(&values);
    store.stage_local_batch_checked(&input, &mut || Ok(()))?;
    let mut total = 0usize;
    store.stage_local_batch_checked(&input, &mut || {
        total += 1;
        Ok(())
    })?;
    assert!(total > 0);
    let leaf = destination(&root, &values[0])?;
    let mut calls = 0usize;
    let mut changed = false;
    let result = store.stage_local_batch_checked(&input, &mut || {
        calls += 1;
        if calls == total {
            real_aba(&leaf, &values[0])?;
            changed = true;
        }
        Ok(())
    });
    assert!(changed && calls == total);
    assert!(matches!(result, Err(LocalV6BlobError::CorruptOrChanged)));
    assert_eq!(fs::read(&leaf)?, values[0]);
    Ok(())
}

#[test]
fn bounded_prepare_batch_new_aba_at_last_gate_rejects() -> TestResult {
    let control = Root::new()?;
    let control_store = LocalV6BlobStage::open_existing(&control.0)?;
    let values = payloads(2, 4096);
    let input = borrowed(&values);
    let mut total = 0usize;
    control_store.stage_local_batch_checked(&input, &mut || {
        total += 1;
        Ok(())
    })?;
    assert!(total > 0);
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let leaf = destination(&root, &values[0])?;
    let mut calls = 0usize;
    let mut changed = false;
    let result = store.stage_local_batch_checked(&input, &mut || {
        calls += 1;
        if calls == total {
            real_aba(&leaf, &values[0])?;
            changed = true;
        }
        Ok(())
    });
    assert!(changed && calls == total);
    assert!(matches!(result, Err(LocalV6BlobError::CorruptOrChanged)));
    assert_eq!(fs::read(&leaf)?, values[0]);
    Ok(())
}

#[test]
fn bounded_prepare_batch_new_aba_at_inner_physical_last_gate_rejects() -> TestResult {
    use heptabao_filesystem_guard::ImmutableBatchEntry;
    let values = payloads(2, 4096);
    // Observe the exact physical API used by the SUT on a separate real
    // directory. Count only callbacks after both final names exist and all
    // temporary names have gone. This finds the INNER final callback without
    // a fixed global gate count or a fake sync hook.
    let control = Root::new()?;
    let control_store = LocalV6BlobStage::open_existing(&control.0)?;
    let temporary_names: Vec<_> = (0..values.len())
        .map(|index| format!(".v6-tmp-control-{index}"))
        .collect();
    let destinations = values
        .iter()
        .map(|value| {
            let object = SealedRecordObject::new_native_v6_ciphertext_chunk(value.clone())
                .map_err(|_| LocalV6BlobError::InvalidCiphertext)?;
            LocalV6BlobStage::leaf(object.reference())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut files = Vec::with_capacity(values.len());
    for (name, value) in temporary_names.iter().zip(&values) {
        let mut file = control_store
            .directory
            .open_file(name, FileAccess::CreateNewReadWrite)?;
        file.write_all(value)?;
        files.push(file);
    }
    let entries: Vec<_> = files
        .iter()
        .enumerate()
        .map(|(index, file)| ImmutableBatchEntry {
            temporary: &temporary_names[index],
            file,
            destination: &destinations[index],
            exact_len: values[index].len() as u64,
        })
        .collect();
    let all_final_names = |root: &Root| -> Result<bool, LocalV6BlobError> {
        if !destinations.iter().all(|leaf| root.0.join(leaf).exists()) {
            return Ok(false);
        }
        for entry in fs::read_dir(&root.0)? {
            if entry?.file_name().to_string_lossy().starts_with(".v6-tmp-") {
                return Ok(false);
            }
        }
        Ok(true)
    };
    let mut inner_gates = 0usize;
    control_store
        .directory
        .publish_new_files_noreplace_checked(&entries, &mut || {
            if all_final_names(&control)? {
                inner_gates += 1;
            }
            Ok::<(), LocalV6BlobError>(())
        })?;
    assert!(inner_gates > 0);

    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let leaf = root.0.join(&destinations[0]);
    let mut observed = 0usize;
    let mut changed = false;
    let result = store.stage_local_batch_checked(&borrowed(&values), &mut || {
        if all_final_names(&root)? {
            observed += 1;
            if observed == inner_gates {
                real_aba(&leaf, &values[0])?;
                changed = true;
            }
        }
        Ok(())
    });
    assert!(changed && observed == inner_gates);
    assert!(matches!(
        result,
        Err(LocalV6BlobError::Publication(
            ImmutablePublicationError::OutcomeUnknown(_)
        ))
    ));
    assert_eq!(fs::read(&leaf)?, values[0]);
    Ok(())
}

#[test]
fn retained_prepare_sync_witness_rejects_aba_between_physical_and_held_transfer() -> TestResult {
    use super::super::existing::HeldSynchronizedCiphertext;
    use heptabao_filesystem_guard::ImmutableBatchEntry;
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let bytes = payloads(1, 4096).pop().ok_or("missing ciphertext")?;
    let object = SealedRecordObject::new_native_v6_ciphertext_chunk(bytes.clone())?;
    let destination = LocalV6BlobStage::leaf(object.reference())?;
    let temporary = ".v6-tmp-original-sync-transfer";
    let mut file = store
        .directory
        .open_file(temporary, FileAccess::CreateNewReadWrite)?;
    file.write_all(&bytes)?;
    let entries = [ImmutableBatchEntry {
        temporary,
        file: &file,
        destination: &destination,
        exact_len: bytes.len() as u64,
    }];
    let mut publications = store
        .directory
        .publish_new_files_noreplace_with_witness_checked(&entries, &mut || {
            Ok::<(), LocalV6BlobError>(())
        })?
        .ok_or("unexpected existing destination")?;
    let publication = publications.pop().ok_or("missing synchronized file")?;
    // A separate real writer acts after the physical helper returned but
    // before the sender constructs its higher-level held descriptor.
    real_aba(&root.0.join(&destination), &bytes)?;
    assert!(matches!(
        HeldSynchronizedCiphertext::published(object.reference(), publication,),
        Err(LocalV6BlobError::CorruptOrChanged)
    ));
    assert_eq!(fs::read(root.0.join(destination))?, bytes);
    Ok(())
}
