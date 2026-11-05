//! Actual temporary-file and source-owner regressions for strict new pins.
//! These are additional protocol tests, outside every original fixed108 filter.
use super::*;
use crate::tests::{TestBarrier, TestRoot, put_request, serial_test};
use crate::{BackendBundle, Barrier, DurableBackend, DurableService, ServiceError};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let root = std::env::temp_dir().canonicalize()?.join(format!(
            "heptabao-synchronized-new-batch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
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
fn locator(address: u8) -> Result<BlobLocator, BackendError> {
    BlobLocator::new([0x53; 16], [address; 32])
}
fn values() -> Vec<Vec<u8>> {
    vec![vec![0x51; 4096], vec![0x72; 4096]]
}
fn inputs(values: &[Vec<u8>]) -> Result<Vec<(BlobLocator, &[u8])>, BackendError> {
    values
        .iter()
        .enumerate()
        .map(|(index, bytes)| Ok((locator((index + 1) as u8)?, bytes.as_slice())))
        .collect()
}
fn real_aba(path: &Path, original: &[u8]) -> io::Result<()> {
    let modified = fs::metadata(path)?.modified()?;
    let mut changed = original.to_vec();
    changed[0] ^= 1;
    fs::write(path, &changed)?;
    fs::write(path, original)?;
    // Keep this actual same-inode rewrite deterministic on coarse timestamps.
    if fs::metadata(path)?.modified()? == modified {
        fs::OpenOptions::new()
            .write(true)
            .open(path)?
            .set_modified(modified + std::time::Duration::from_secs(1))?;
    }
    Ok(())
}
fn all_linked(root: &Root, input: &[(BlobLocator, &[u8])]) -> bool {
    input
        .iter()
        .all(|(locator, _)| root.0.join(locator.leaf()).exists())
        && BATCH_TEMPORARIES[..input.len()]
            .iter()
            .all(|temporary| !root.0.join(temporary).exists())
}

#[test]
fn synchronized_new_batch_boxed_pins_cold_reuse_and_ordinary_semantics() -> TestResult {
    let root = Root::new()?;
    let mut backend: Box<dyn DurableBackend> = Box::new(FileBackend::create_new(&root.0)?);
    let profile = backend.immutable_blob_profile()?;
    let values = values();
    let input = inputs(&values)?;
    let pins = backend
        .stage_new_immutable_ciphertext_batch_checked(&input, &mut || Ok(()))?
        .ok_or("new files reported a collision")?;
    assert_eq!(pins.len(), input.len());
    for (pin, (locator, bytes)) in pins.iter().zip(&input) {
        assert!(pin.has_synchronized_ciphertext());
        assert!(pin.0.synchronized_publication_witness.is_some());
        assert!(pin.matches_profile(&profile));
        assert_eq!(pin.locator(), *locator);
        assert_eq!(pin.read_ciphertext()?.as_slice(), *bytes);
    }
    drop(backend);
    for pin in &pins {
        assert!(matches!(
            pin.read_ciphertext(),
            Err(BackendError::Unavailable)
        ));
    }
    let mut cold = FileBackend::open(&root.0)?;
    for (locator, bytes) in &input {
        let reused = cold
            .reuse_immutable_ciphertext_checked(*locator, bytes.len(), &mut || Ok(()))?
            .ok_or("cold leaf disappeared")?;
        assert!(reused.has_synchronized_ciphertext());
        assert!(reused.0.synchronized_publication_witness.is_none());
        assert_eq!(reused.read_ciphertext()?.as_slice(), *bytes);
    }
    // Ordinary APIs retain their prior weak-read-pin and EEXIST behavior.
    let ordinary = [(locator(3)?, b"old-nonce".as_slice())];
    let mut staged = cold.stage_immutable_ciphertext_batch_checked(&ordinary, &mut || Ok(()))?;
    let ImmutableBlobStage::Published(ordinary_pin) = staged.pop().ok_or("missing ordinary pin")?
    else {
        return Err("ordinary new leaf reported existing".into());
    };
    assert!(!ordinary_pin.has_synchronized_ciphertext());
    let mut staged = cold.stage_immutable_ciphertext_batch_checked(
        &[(locator(3)?, b"new-nonce".as_slice())],
        &mut || Ok(()),
    )?;
    let ImmutableBlobStage::AlreadyExists(existing) = staged.pop().ok_or("missing existing pin")?
    else {
        return Err("ordinary existing leaf was replaced".into());
    };
    assert!(!existing.has_synchronized_ciphertext());
    assert_eq!(existing.read_ciphertext()?.as_slice(), b"old-nonce");
    Ok(())
}

#[test]
fn synchronized_new_batch_original_physical_witness_survives_transfer() -> TestResult {
    let root = Root::new()?;
    let backend = FileBackend::create_new(&root.0)?;
    let profile = backend.immutable_blob_profile()?;
    let bytes = vec![0x51; 4096];
    let address = locator(1)?;
    let destination = address.leaf();
    let mut file = backend
        .directory
        .open_file(BATCH_TEMPORARIES[0], FileAccess::CreateNewReadWrite)?;
    file.write_all(&bytes)?;
    let entries = [ImmutableBatchEntry {
        temporary: BATCH_TEMPORARIES[0],
        file: &file,
        destination: &destination,
        exact_len: bytes.len() as u64,
    }];
    let mut published = backend
        .directory
        .publish_new_files_noreplace_with_witness_checked(&entries, &mut || {
            Ok::<(), BackendError>(())
        })?
        .ok_or("unexpected existing leaf")?;
    let publication = published.pop().ok_or("missing physical proof")?;
    // This is exactly the cross-layer window: physical publication succeeded,
    // but the durable pin has not been constructed or sampled metadata yet.
    real_aba(&root.0.join(&destination), &bytes)?;
    assert!(matches!(
        backend.pin_synchronized_new_file(address, publication, &bytes, &profile,),
        Err(BackendError::Corrupt)
    ));
    assert_eq!(fs::read(root.0.join(destination))?, bytes);
    Ok(())
}

#[test]
fn synchronized_new_batch_inner_last_gate_aba_returns_no_pin() -> TestResult {
    let values = values();
    let input = inputs(&values)?;
    let control = Root::new()?;
    let control_backend = FileBackend::create_new(&control.0)?;
    let destinations: Vec<_> = input.iter().map(|(locator, _)| locator.leaf()).collect();
    let mut files = Vec::new();
    for (index, (_, bytes)) in input.iter().enumerate() {
        let mut file = control_backend
            .directory
            .open_file(BATCH_TEMPORARIES[index], FileAccess::CreateNewReadWrite)?;
        file.write_all(bytes)?;
        files.push(file);
    }
    let entries: Vec<_> = files
        .iter()
        .enumerate()
        .map(|(index, file)| ImmutableBatchEntry {
            temporary: BATCH_TEMPORARIES[index],
            file,
            destination: &destinations[index],
            exact_len: input[index].1.len() as u64,
        })
        .collect();
    let mut inner_gates = 0usize;
    assert!(
        control_backend
            .directory
            .publish_new_files_noreplace_with_witness_checked(&entries, &mut || {
                if all_linked(&control, &input) {
                    inner_gates += 1;
                }
                Ok::<(), BackendError>(())
            },)?
            .is_some()
    );
    assert!(inner_gates > 0);
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let profile = backend.immutable_blob_profile()?;
    let mut observed = 0usize;
    let mut changed = false;
    let result = backend.stage_new_immutable_ciphertext_batch_checked(&input, &mut || {
        if all_linked(&root, &input) {
            observed += 1;
            if observed == inner_gates {
                real_aba(&root.0.join(&destinations[0]), &values[0])
                    .map_err(|_| BackendError::Io)?;
                changed = true;
            }
        }
        Ok(())
    });
    assert!(changed && observed == inner_gates);
    assert!(matches!(result, Err(BackendError::OutcomeUnknown)));
    assert!(!profile.is_live());
    assert_eq!(fs::read(root.0.join(&destinations[0]))?, values[0]);
    Ok(())
}

#[test]
fn synchronized_new_batch_outer_last_gate_rechecks_earlier_member() -> TestResult {
    let values = values();
    let input = inputs(&values)?;
    let control = Root::new()?;
    let mut control_backend = FileBackend::create_new(&control.0)?;
    let mut total = 0usize;
    assert!(
        control_backend
            .stage_new_immutable_ciphertext_batch_checked(&input, &mut || {
                total += 1;
                Ok(())
            },)?
            .is_some()
    );
    assert!(total > 0);
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let profile = backend.immutable_blob_profile()?;
    let mut calls = 0usize;
    let result = backend.stage_new_immutable_ciphertext_batch_checked(&input, &mut || {
        calls += 1;
        if calls == total {
            real_aba(&root.0.join(input[0].0.leaf()), &values[0]).map_err(|_| BackendError::Io)?;
        }
        Ok(())
    });
    assert_eq!(calls, total);
    assert!(matches!(result, Err(BackendError::OutcomeUnknown)));
    assert!(!profile.is_live());
    assert_eq!(fs::read(root.0.join(input[0].0.leaf()))?, values[0]);
    Ok(())
}

#[test]
fn synchronized_new_batch_actual_read_rejects_changed_temporary_ciphertext() -> TestResult {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let values = values();
    let input = inputs(&values)?;
    let mut changed = false;
    let result = backend.stage_new_immutable_ciphertext_batch_checked(&input, &mut || {
        let last = root.0.join(BATCH_TEMPORARIES[1]);
        if !changed && fs::metadata(&last).is_ok_and(|m| m.len() == values[1].len() as u64) {
            let mut corrupt = values[0].clone();
            corrupt[0] ^= 1;
            fs::write(root.0.join(BATCH_TEMPORARIES[0]), corrupt).map_err(|_| BackendError::Io)?;
            changed = true;
        }
        Ok(())
    });
    assert!(changed);
    // Even correctly synced, well-shaped bytes are not the caller's ciphertext.
    assert!(matches!(result, Err(BackendError::OutcomeUnknown)));
    assert_ne!(fs::read(root.0.join(input[0].0.leaf()))?, values[0]);
    Ok(())
}

#[test]
fn synchronized_new_batch_collision_returns_no_pins_or_rebased_existing_witness() -> TestResult {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let values = values();
    let input = inputs(&values)?;
    backend.stage_immutable_ciphertext(input[0].0, &values[0])?;
    let existing = backend
        .reuse_immutable_ciphertext_checked(input[0].0, values[0].len(), &mut || Ok(()))?
        .ok_or("missing existing")?;
    let profile = backend.immutable_blob_profile()?;
    real_aba(&root.0.join(input[0].0.leaf()), &values[0])?;
    assert!(!existing.matches_profile(&profile));
    let result = backend.stage_new_immutable_ciphertext_batch_checked(&input, &mut || Ok(()))?;
    assert!(result.is_none());
    assert!(profile.is_live());
    assert!(!existing.matches_profile(&profile));
    assert_eq!(fs::read(root.0.join(input[0].0.leaf()))?, values[0]);
    // A known collision is not proof that no other final names were linked.
    assert_eq!(fs::read(root.0.join(input[1].0.leaf()))?, values[1]);
    for temporary in &BATCH_TEMPORARIES[..input.len()] {
        assert!(!root.0.join(temporary).exists());
    }
    Ok(())
}

#[test]
fn synchronized_new_batch_invalid_inputs_reject_before_temporary_write() -> TestResult {
    let root = Root::new()?;
    let mut backend = FileBackend::create_new(&root.0)?;
    let large = vec![0x61; MAX_IMMUTABLE_CIPHERTEXT_BYTES];
    let oversized: Vec<_> = (1..=9)
        .map(|index| Ok((locator(index)?, large.as_slice())))
        .collect::<Result<_, BackendError>>()?;
    let small = b"bounded";
    let too_many: Vec<_> = (1..=33)
        .map(|index| Ok((locator(index)?, small.as_slice())))
        .collect::<Result<_, BackendError>>()?;
    for input in [&[][..], oversized.as_slice(), too_many.as_slice()] {
        assert!(matches!(
            backend.stage_new_immutable_ciphertext_batch_checked(input, &mut || Ok(()),),
            Err(BackendError::Capacity)
        ));
    }
    let duplicate = [
        (locator(1)?, small.as_slice()),
        (locator(1)?, small.as_slice()),
    ];
    assert!(matches!(
        backend.stage_new_immutable_ciphertext_batch_checked(&duplicate, &mut || Ok(()),),
        Err(BackendError::Corrupt)
    ));
    assert_eq!(fs::read_dir(&root.0)?.count(), 0);
    Ok(())
}

struct OrdinaryOnly {
    fallback_calls: Arc<AtomicU64>,
}
impl DurableBackend for OrdinaryOnly {
    fn verify(&self) -> Result<(), BackendError> {
        Ok(())
    }
    fn stage_immutable_ciphertext_checked(
        &mut self,
        _: BlobLocator,
        _: &[u8],
        _: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<ImmutableBlobStage, BackendError> {
        self.fallback_calls.fetch_add(1, Ordering::Relaxed);
        Err(BackendError::Unavailable)
    }
    fn load(&mut self) -> Result<BackendBundle, BackendError> {
        Err(BackendError::Unsupported)
    }
    fn initialize_empty(&mut self, _: &BackendBundle) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }
    fn append_journal(&mut self, _: usize, _: &[u8]) -> Result<usize, BackendError> {
        Err(BackendError::Unsupported)
    }
    fn truncate_journal(&mut self, _: usize, _: usize) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }
    fn publish_checkpoint(
        &mut self,
        _: &BackendBundle,
        _: &BackendBundle,
    ) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }
    fn close(self) -> Result<(), BackendError> {
        Ok(())
    }
}
#[test]
fn synchronized_new_batch_default_backend_is_unsupported_without_fallback() -> TestResult {
    let fallback_calls = Arc::new(AtomicU64::new(0));
    let mut backend: Box<dyn DurableBackend> = Box::new(OrdinaryOnly {
        fallback_calls: Arc::clone(&fallback_calls),
    });
    let mut gate_calls = 0usize;
    assert!(matches!(
        backend.stage_new_immutable_ciphertext_batch_checked(
            &[(locator(1)?, b"ciphertext".as_slice())],
            &mut || {
                gate_calls += 1;
                Ok(())
            },
        ),
        Err(BackendError::Unsupported)
    ));
    assert_eq!(gate_calls, 0);
    assert_eq!(
        fallback_calls.load(Ordering::Relaxed),
        0,
        "strict new publication must not fall back to ordinary staging"
    );
    Ok(())
}

#[test]
fn synchronized_new_batch_source_final_gate_rejects_new_leaf_aba() -> TestResult {
    let _serial = serial_test();
    let control = TestRoot::new("strict-new-source-control")?;
    let root = TestRoot::new("strict-new-source-final-gate")?;
    let source = b"typed-root-fixture";
    let context = b"typed-object-context-fixture";
    let payload = b"actual new plaintext";
    let barrier = TestBarrier::new();
    let exact_len = barrier.seal(context, payload)?.len();
    let input = [
        (
            locator(1)?,
            exact_len,
            context.as_slice(),
            payload.as_slice(),
        ),
        (
            locator(2)?,
            exact_len,
            context.as_slice(),
            payload.as_slice(),
        ),
    ];
    let mut control_owner = DurableService::create_new(&control.0, barrier.clone(), 16)?;
    control_owner.put(put_request("source", source)?)?;
    let control_session = control_owner.immutable_source_session(
        "root/team-a",
        "secret/application",
        source,
        [0x53; 16],
    )?;
    let mut total = 0usize;
    let pins = control_owner.stage_immutable_objects_reusing_existing_before_publish(
        &control_session,
        &input,
        &mut || {
            total += 1;
            Ok(())
        },
    )?;
    assert_eq!(pins.len(), 2);
    assert!(
        pins.iter()
            .all(ImmutableBlobReadPin::has_synchronized_ciphertext)
    );
    control_owner.close()?;
    assert!(total > 0);
    let mut owner = DurableService::create_new(&root.0, barrier, 16)?;
    owner.put(put_request("source", source)?)?;
    let generation = owner.generation();
    let session =
        owner.immutable_source_session("root/team-a", "secret/application", source, [0x53; 16])?;
    let mut calls = 0usize;
    let mut changed = false;
    let result = owner.stage_immutable_objects_reusing_existing_before_publish(
        &session,
        &input,
        &mut || {
            calls += 1;
            if calls == total {
                let path = root.0.join(input[0].0.leaf());
                let wire = fs::read(&path).map_err(|_| ServiceError::BarrierFailure)?;
                real_aba(&path, &wire).map_err(|_| ServiceError::BarrierFailure)?;
                changed = true;
            }
            Ok(())
        },
    );
    assert!(changed && calls == total);
    assert!(matches!(result, Err(ServiceError::CorruptState)));
    assert_eq!(owner.generation(), generation);
    assert_eq!(
        owner
            .get("root/team-a", "secret/application")?
            .ok_or("source disappeared")?
            .expose(),
        source
    );
    Ok(())
}
