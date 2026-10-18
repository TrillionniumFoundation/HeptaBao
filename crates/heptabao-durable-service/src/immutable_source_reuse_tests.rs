//! Real FileBackend tests with a deliberately nonproduction counting barrier.
//! They prove reuse, current physical/source custody and failure behavior;
//! the server's typed visitor and actual AeadBarrier remain separate gates.
use super::*;
use crate::tests::{TestBarrier, TestRoot, put_request, serial_test};
use std::{
    fs, io,
    io::Write,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Owner = DurableService<CountingBarrier, ObservedBackend>;
const SOURCE: &[u8] = b"exact-source-root";
const CONTEXT: &[u8] = b"exact-native-object-context";
const PAYLOAD: &[u8] = b"original";
const STORE: [u8; 16] = [0x71; 16];

#[derive(Clone)]
struct CountingBarrier {
    inner: TestBarrier,
    seals: Arc<AtomicU64>,
    opens: Arc<AtomicU64>,
    reject_seal: Arc<AtomicBool>,
    reject_open: Arc<AtomicBool>,
    revoke_after_open: Arc<AtomicBool>,
    revoked: Arc<AtomicBool>,
}
impl CountingBarrier {
    fn new() -> Self {
        Self {
            inner: TestBarrier::new(),
            seals: Arc::new(AtomicU64::new(0)),
            opens: Arc::new(AtomicU64::new(0)),
            reject_seal: Arc::new(AtomicBool::new(false)),
            reject_open: Arc::new(AtomicBool::new(false)),
            revoke_after_open: Arc::new(AtomicBool::new(false)),
            revoked: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl Barrier for CountingBarrier {
    fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BarrierError> {
        let nonce = self.seals.fetch_add(1, Ordering::SeqCst).to_le_bytes();
        if self.reject_seal.load(Ordering::SeqCst) {
            return Err(BarrierError);
        }
        let mut associated = context.to_vec();
        associated.extend_from_slice(&nonce);
        let mut ciphertext = nonce.to_vec();
        ciphertext.extend(self.inner.seal(&associated, plaintext)?);
        Ok(ciphertext)
    }
    fn open(&self, context: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, BarrierError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        if self.reject_open.load(Ordering::SeqCst) {
            return Err(BarrierError);
        }
        let (nonce, ciphertext) = ciphertext.split_at_checked(8).ok_or(BarrierError)?;
        let mut associated = context.to_vec();
        associated.extend_from_slice(nonce);
        let plaintext = self.inner.open(&associated, ciphertext)?;
        if self.revoke_after_open.load(Ordering::SeqCst) {
            self.revoked.store(true, Ordering::SeqCst);
        }
        Ok(plaintext)
    }
    fn sealed_len_bound(&self, plaintext_len: usize) -> Option<usize> {
        // Deliberately differs from server AeadBarrier's exact 32-byte overhead.
        plaintext_len.checked_add(40)
    }
}

#[derive(Clone, Default)]
struct BackendCounts {
    stages: Arc<AtomicU64>,
    reuses: Arc<AtomicU64>,
}
struct ObservedBackend {
    inner: FileBackend,
    counts: BackendCounts,
    support_reuse: bool,
    reject_stage: bool,
    error_after_reuse: Option<BackendError>,
    rewrite_after_reuse: Option<(PathBuf, Vec<u8>)>,
    aba_after_reuse: Option<(PathBuf, Vec<u8>, Vec<u8>)>,
    return_plain_read_pin: bool,
}
impl ObservedBackend {
    fn new(inner: FileBackend, counts: BackendCounts) -> Self {
        Self {
            inner,
            counts,
            support_reuse: true,
            reject_stage: false,
            error_after_reuse: None,
            rewrite_after_reuse: None,
            aba_after_reuse: None,
            return_plain_read_pin: false,
        }
    }
}
impl DurableBackend for ObservedBackend {
    fn verify(&self) -> Result<(), BackendError> {
        self.inner.verify()
    }
    fn load(&mut self) -> Result<BackendBundle, BackendError> {
        self.inner.load()
    }
    fn initialize_empty(&mut self, bundle: &BackendBundle) -> Result<(), BackendError> {
        self.inner.initialize_empty(bundle)
    }
    fn append_journal(&mut self, len: usize, frame: &[u8]) -> Result<usize, BackendError> {
        self.inner.append_journal(len, frame)
    }
    fn truncate_journal(&mut self, len: usize, new_len: usize) -> Result<(), BackendError> {
        self.inner.truncate_journal(len, new_len)
    }
    fn publish_checkpoint(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
    ) -> Result<(), BackendError> {
        self.inner.publish_checkpoint(expected, replacement)
    }
    fn immutable_blob_profile(&self) -> Result<ImmutableBlobProfile, BackendError> {
        self.inner.immutable_blob_profile()
    }
    fn pin_immutable_ciphertext(
        &self,
        locator: BlobLocator,
        len: usize,
    ) -> Result<ImmutableBlobReadPin, BackendError> {
        self.inner.pin_immutable_ciphertext(locator, len)
    }
    fn stage_immutable_ciphertext_checked(
        &mut self,
        locator: BlobLocator,
        bytes: &[u8],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<ImmutableBlobStage, BackendError> {
        self.counts.stages.fetch_add(1, Ordering::SeqCst);
        if self.reject_stage {
            return Err(BackendError::Io);
        }
        self.inner.stage_immutable_ciphertext_checked(locator, bytes, gate)
    }
    fn reuse_immutable_ciphertext_checked(
        &mut self,
        locator: BlobLocator,
        len: usize,
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Option<ImmutableBlobReadPin>, BackendError> {
        self.counts.reuses.fetch_add(1, Ordering::SeqCst);
        if !self.support_reuse {
            return Err(BackendError::Unsupported);
        }
        if self.return_plain_read_pin {
            return self.inner.pin_immutable_ciphertext(locator, len).map(Some);
        }
        let result = self.inner.reuse_immutable_ciphertext_checked(locator, len, gate)?;
        if let Some((leaf, ciphertext)) = self.rewrite_after_reuse.take() {
            fs::write(leaf, ciphertext).map_err(|_| BackendError::Io)?;
        }
        if let Some((leaf, alternate, original)) = self.aba_after_reuse.take() {
            rewrite_and_restore(&leaf, &alternate, &original)
                .map_err(|_| BackendError::Io)?;
        }
        // An upper backend failure after the actual existing descriptor was
        // synchronized must not be reclassified as first-open absence.
        if let Some(error) = self.error_after_reuse.take() {
            return Err(error);
        }
        Ok(result)
    }
    fn close(self) -> Result<(), BackendError> {
        self.inner.close()
    }
}

fn fixture(
    label: &str,
) -> Result<(TestRoot, Owner, CountingBarrier, BackendCounts), Box<dyn std::error::Error>> {
    let root = TestRoot::new(label)?;
    let barrier = CountingBarrier::new();
    let counts = BackendCounts::default();
    let backend = ObservedBackend::new(FileBackend::create_new(&root.0)?, counts.clone());
    let mut owner = DurableService::create_new_with_backend(backend, barrier.clone(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    Ok((root, owner, barrier, counts))
}
fn session<B: Barrier, P: DurableBackend>(
    owner: &mut DurableService<B, P>,
) -> Result<ImmutableSourceSession, ServiceError> {
    owner.immutable_source_session("root/team-a", "secret/application", SOURCE, STORE)
}
fn locator(address: u8) -> Result<BlobLocator, BackendError> {
    BlobLocator::new(STORE, [address; 32])
}
fn leaf_name(locator: BlobLocator) -> String {
    // Fixture addressing uses only public locator fields, not the physical
    // sibling module's private leaf() implementation.
    let store = locator.store_id().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let address = locator.address().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    format!("nv6.{store}.{address}.hbo")
}
fn no_gate() -> Result<(), ServiceError> {
    Ok(())
}
fn primary_files(root: &TestRoot) -> io::Result<[Vec<u8>; 3]> {
    Ok([
        fs::read(root.0.join("state.hbs"))?,
        fs::read(root.0.join("journal.hbj"))?,
        fs::read(root.0.join("ledger.hbl"))?,
    ])
}
fn rewrite_and_restore(leaf: &std::path::Path, alternate: &[u8], original: &[u8]) -> io::Result<()> {
    let mut writer = fs::OpenOptions::new().write(true).open(leaf)?;
    let modified = writer.metadata()?.modified()?;
    writer.write_all(alternate)?;
    writer.sync_all()?;
    // A separate descriptor starts at offset zero, preserving inode/length.
    let mut restore = fs::OpenOptions::new().write(true).open(leaf)?;
    restore.write_all(original)?;
    restore.set_modified(modified)?;
    Ok(())
}
fn first_object(
    owner: &mut Owner,
    session: &ImmutableSourceSession,
    address: BlobLocator,
) -> Result<ImmutableBlobReadPin, ServiceError> {
    owner.stage_immutable_object_before_publish(session, address, CONTEXT, PAYLOAD, &mut no_gate)
}
fn reuse(
    owner: &mut Owner,
    session: &ImmutableSourceSession,
    address: BlobLocator,
) -> Result<ImmutableBlobReadPin, ServiceError> {
    owner.stage_immutable_object_reusing_existing_before_publish(
        session, address, PAYLOAD.len() + 40, CONTEXT, PAYLOAD, &mut no_gate,
    )
}

#[test]
fn immutable_reuse_actual_source_blocks_reseal_and_new_stage_but_opens_fresh() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner, barrier, counts) = fixture("reuse-no-reseal")?;
    let session = session(&mut owner)?;
    let address = locator(1)?;
    let first = first_object(&mut owner, &session, address)?;
    let original = first.read_ciphertext()?;
    let generation = owner.generation();
    let primary = primary_files(&root)?;
    let seals = barrier.seals.load(Ordering::SeqCst);
    let opens = barrier.opens.load(Ordering::SeqCst);
    let stages = counts.stages.load(Ordering::SeqCst);
    let reuses = counts.reuses.load(Ordering::SeqCst);
    barrier.reject_seal.store(true, Ordering::SeqCst);
    owner.backend.reject_stage = true;
    let reserved = root.0.join("native-v6-object.tmp");
    fs::create_dir(&reserved)?;
    fs::write(reserved.join("sentinel"), b"keep")?;
    let reused = reuse(&mut owner, &session, address)?;
    assert_eq!(barrier.seals.load(Ordering::SeqCst), seals);
    assert_eq!(counts.stages.load(Ordering::SeqCst), stages);
    assert_eq!(counts.reuses.load(Ordering::SeqCst), reuses + 1);
    assert_eq!(barrier.opens.load(Ordering::SeqCst), opens + 1);
    assert_eq!(reused.read_ciphertext()?.as_slice(), original.as_slice());
    assert_eq!(owner.generation(), generation);
    assert_eq!(primary_files(&root)?, primary);
    assert_eq!(fs::read(reserved.join("sentinel"))?, b"keep");
    assert!(!owner.unresolved);
    Ok(())
}

#[test]
fn immutable_reuse_initial_missing_leaf_runs_original_stage_once() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner, barrier, counts) = fixture("reuse-missing")?;
    let session = session(&mut owner)?;
    let address = locator(2)?;
    let primary = primary_files(&root)?;
    let generation = owner.generation();
    let seals = barrier.seals.load(Ordering::SeqCst);
    let stages = counts.stages.load(Ordering::SeqCst);
    assert!(!root.0.join(leaf_name(address)).exists());
    let first = reuse(&mut owner, &session, address)?;
    assert_eq!(first.ciphertext_len(), PAYLOAD.len() + 40);
    assert_eq!(barrier.seals.load(Ordering::SeqCst), seals + 1);
    assert_eq!(counts.stages.load(Ordering::SeqCst), stages + 1);
    assert!(root.0.join(leaf_name(address)).is_file());
    barrier.reject_seal.store(true, Ordering::SeqCst);
    owner.backend.reject_stage = true;
    reuse(&mut owner, &session, address)?;
    assert_eq!(barrier.seals.load(Ordering::SeqCst), seals + 1);
    assert_eq!(counts.stages.load(Ordering::SeqCst), stages + 1);
    assert_eq!(owner.generation(), generation);
    assert_eq!(primary_files(&root)?, primary);
    Ok(())
}

#[test]
fn immutable_reuse_bad_local_cipher_or_context_or_plaintext_never_repairs() -> TestResult {
    let _serial = serial_test();
    for kind in ["plaintext", "context", "ciphertext", "length", "barrier"] {
        let (root, mut owner, barrier, counts) = fixture("reuse-bad-leaf")?;
        let session = session(&mut owner)?;
        let address = locator(3)?;
        first_object(&mut owner, &session, address)?;
        let leaf = root.0.join(leaf_name(address));
        if kind == "ciphertext" {
            let mut bytes = fs::read(&leaf)?;
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            fs::write(&leaf, bytes)?;
        } else if kind == "length" {
            let mut bytes = fs::read(&leaf)?;
            bytes.pop();
            fs::write(&leaf, bytes)?;
        } else if kind == "barrier" {
            barrier.reject_open.store(true, Ordering::SeqCst);
        }
        let existing = fs::read(&leaf)?;
        let primary = primary_files(&root)?;
        let generation = owner.generation();
        let seals = barrier.seals.load(Ordering::SeqCst);
        let stages = counts.stages.load(Ordering::SeqCst);
        barrier.reject_seal.store(true, Ordering::SeqCst);
        owner.backend.reject_stage = true;
        let context = if kind == "context" {
            b"foreign-context".as_slice()
        } else {
            CONTEXT
        };
        let expected = if kind == "plaintext" {
            b"altered!".as_slice()
        } else {
            PAYLOAD
        };
        let result = owner.stage_immutable_object_reusing_existing_before_publish(
            &session, address, PAYLOAD.len() + 40, context, expected, &mut no_gate,
        );
        match kind {
            "plaintext" => assert!(matches!(result, Err(ServiceError::RequestBindingConflict))),
            "length" => assert!(matches!(result, Err(ServiceError::CorruptState))),
            _ => assert!(matches!(result, Err(ServiceError::BarrierFailure))),
        }
        assert_eq!(barrier.seals.load(Ordering::SeqCst), seals, "{kind}");
        assert_eq!(counts.stages.load(Ordering::SeqCst), stages, "{kind}");
        assert_eq!(fs::read(&leaf)?, existing, "{kind}");
        assert_eq!(owner.generation(), generation, "{kind}");
        assert_eq!(primary_files(&root)?, primary, "{kind}");
        assert!(!root.0.join("native-v6-object.tmp").exists(), "{kind}");
    }
    Ok(())
}

#[test]
fn immutable_reuse_cold_orphan_requires_fresh_session_and_no_reseal() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner, barrier, counts) = fixture("reuse-cold-orphan")?;
    let old = session(&mut owner)?;
    let address = locator(4)?;
    let first = first_object(&mut owner, &old, address)?;
    let original = first.read_ciphertext()?;
    let generation = owner.generation();
    owner.close()?;
    let backend = ObservedBackend::new(FileBackend::open(&root.0)?, counts.clone());
    let mut cold = DurableService::reopen_with_backend(backend, barrier.clone(), 16)?;
    let primary = primary_files(&root)?;
    let seals = barrier.seals.load(Ordering::SeqCst);
    let stages = counts.stages.load(Ordering::SeqCst);
    barrier.reject_seal.store(true, Ordering::SeqCst);
    cold.backend.reject_stage = true;
    assert!(matches!(reuse(&mut cold, &old, address), Err(ServiceError::RecoveryRequired)));
    assert!(matches!(first.read_ciphertext(), Err(BackendError::Unavailable)));
    let fresh = session(&mut cold)?;
    let pin = reuse(&mut cold, &fresh, address)?;
    assert_eq!(pin.read_ciphertext()?.as_slice(), original.as_slice());
    assert_eq!(barrier.seals.load(Ordering::SeqCst), seals);
    assert_eq!(counts.stages.load(Ordering::SeqCst), stages);
    assert_eq!(cold.generation(), generation);
    assert_eq!(primary_files(&root)?, primary);
    Ok(())
}

#[test]
fn immutable_reuse_foreign_live_session_and_intervening_source_state_fail() -> TestResult {
    let _serial = serial_test();
    for kind in ["foreign", "generation", "epoch", "root"] {
        let (root, mut owner, barrier, counts) = fixture("reuse-stale-source")?;
        let (_foreign_root, mut foreign, _foreign_barrier, _foreign_counts) = fixture("reuse-foreign")?;
        let original = session(&mut owner)?;
        let foreign_session = session(&mut foreign)?;
        let address = locator(5)?;
        first_object(&mut owner, &original, address)?;
        match kind {
            "generation" => {
                owner.put(PutRequest::new(
                    "principal-a", "root/team-a", "other", "secret/other", [7; 32],
                    Secret::new(b"other".to_vec())?,
                )?)?;
            }
            "epoch" => {
                owner.retire_replay_epoch()?;
            }
            "root" => {
                owner.put(put_request("replace-root", b"new-root")?)?;
            }
            _ => {}
        }
        let source = if kind == "foreign" {
            &foreign_session
        } else {
            &original
        };
        let primary = primary_files(&root)?;
        let generation = owner.generation();
        let reuses = counts.reuses.load(Ordering::SeqCst);
        let stages = counts.stages.load(Ordering::SeqCst);
        let seals = barrier.seals.load(Ordering::SeqCst);
        let bytes = fs::read(root.0.join(leaf_name(address)))?;
        barrier.reject_seal.store(true, Ordering::SeqCst);
        owner.backend.reject_stage = true;
        assert!(matches!(reuse(&mut owner, source, address), Err(ServiceError::PublicationConditionConflict)), "{kind}");
        assert_eq!(counts.reuses.load(Ordering::SeqCst), reuses, "{kind}");
        assert_eq!(counts.stages.load(Ordering::SeqCst), stages, "{kind}");
        assert_eq!(barrier.seals.load(Ordering::SeqCst), seals, "{kind}");
        assert_eq!(owner.generation(), generation, "{kind}");
        assert_eq!(primary_files(&root)?, primary, "{kind}");
        assert_eq!(fs::read(root.0.join(leaf_name(address)))?, bytes, "{kind}");
    }
    Ok(())
}

#[test]
fn immutable_reuse_same_directory_reconnect_cannot_reuse_old_owner_session() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner, barrier, counts) = fixture("reuse-owner-lineage")?;
    let placeholder = TestRoot::new("reuse-owner-placeholder")?;
    let original = session(&mut owner)?;
    let address = locator(6)?;
    let first = first_object(&mut owner, &original, address)?;
    let primary = primary_files(&root)?;
    let generation = owner.generation();
    let prior = std::mem::replace(
        &mut owner.backend.inner,
        FileBackend::create_new(&placeholder.0)?,
    );
    prior.close()?;
    owner.backend.inner = FileBackend::open(&root.0)?;
    let seals = barrier.seals.load(Ordering::SeqCst);
    let stages = counts.stages.load(Ordering::SeqCst);
    barrier.reject_seal.store(true, Ordering::SeqCst);
    owner.backend.reject_stage = true;
    assert!(matches!(reuse(&mut owner, &original, address), Err(ServiceError::PublicationConditionConflict)));
    assert!(matches!(first.read_ciphertext(), Err(BackendError::Unavailable)));
    let fresh = session(&mut owner)?;
    reuse(&mut owner, &fresh, address)?;
    assert_eq!(barrier.seals.load(Ordering::SeqCst), seals);
    assert_eq!(counts.stages.load(Ordering::SeqCst), stages);
    assert_eq!(owner.generation(), generation);
    assert_eq!(primary_files(&root)?, primary);
    Ok(())
}

#[test]
fn immutable_reuse_original_gate_can_reject_before_io_and_after_actual_open() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner, barrier, counts) = fixture("reuse-original-gate")?;
    let session = session(&mut owner)?;
    let address = locator(7)?;
    first_object(&mut owner, &session, address)?;
    let primary = primary_files(&root)?;
    let seals = barrier.seals.load(Ordering::SeqCst);
    let opens = barrier.opens.load(Ordering::SeqCst);
    let stages = counts.stages.load(Ordering::SeqCst);
    let reuses = counts.reuses.load(Ordering::SeqCst);
    barrier.reject_seal.store(true, Ordering::SeqCst);
    owner.backend.reject_stage = true;
    assert!(matches!(
        owner.stage_immutable_object_reusing_existing_before_publish(
            &session, address, PAYLOAD.len() + 40, CONTEXT, PAYLOAD,
            &mut || Err(ServiceError::BarrierFailure),
        ),
        Err(ServiceError::BarrierFailure)
    ));
    assert_eq!(counts.reuses.load(Ordering::SeqCst), reuses);
    assert_eq!(barrier.opens.load(Ordering::SeqCst), opens);
    barrier.revoke_after_open.store(true, Ordering::SeqCst);
    assert!(matches!(
        owner.stage_immutable_object_reusing_existing_before_publish(
            &session, address, PAYLOAD.len() + 40, CONTEXT, PAYLOAD,
            &mut || {
                if barrier.revoked.load(Ordering::SeqCst) {
                    Err(ServiceError::BarrierFailure)
                } else {
                    Ok(())
                }
            },
        ),
        Err(ServiceError::BarrierFailure)
    ));
    assert!(barrier.revoked.load(Ordering::SeqCst));
    assert_eq!(barrier.opens.load(Ordering::SeqCst), opens + 1);
    assert_eq!(barrier.seals.load(Ordering::SeqCst), seals);
    assert_eq!(counts.stages.load(Ordering::SeqCst), stages);
    assert_eq!(primary_files(&root)?, primary);
    assert!(!owner.unresolved);
    Ok(())
}

#[test]
fn immutable_reuse_explicit_unsupported_backend_keeps_original_stage() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner, barrier, counts) = fixture("reuse-unsupported")?;
    let session = session(&mut owner)?;
    let address = locator(8)?;
    let first = first_object(&mut owner, &session, address)?;
    let original = first.read_ciphertext()?;
    let primary = primary_files(&root)?;
    let generation = owner.generation();
    owner.backend.support_reuse = false;
    let seals = barrier.seals.load(Ordering::SeqCst);
    let stages = counts.stages.load(Ordering::SeqCst);
    let reuses = counts.reuses.load(Ordering::SeqCst);
    let pin = reuse(&mut owner, &session, address)?;
    assert_eq!(counts.reuses.load(Ordering::SeqCst), reuses + 1);
    assert_eq!(barrier.seals.load(Ordering::SeqCst), seals + 1);
    assert_eq!(counts.stages.load(Ordering::SeqCst), stages + 1);
    assert_eq!(pin.read_ciphertext()?.as_slice(), original.as_slice());
    assert_eq!(owner.generation(), generation);
    assert_eq!(primary_files(&root)?, primary);
    Ok(())
}

#[test]
fn immutable_reuse_post_open_errors_never_fallback_and_unknown_fences() -> TestResult {
    let _serial = serial_test();
    for error in [
        BackendError::MissingArtifact,
        BackendError::OutcomeUnknown,
        BackendError::StaleWriter,
    ] {
        let (root, mut owner, barrier, counts) = fixture("reuse-after-open-error")?;
        let session = session(&mut owner)?;
        let address = locator(9)?;
        first_object(&mut owner, &session, address)?;
        let primary = primary_files(&root)?;
        let bytes = fs::read(root.0.join(leaf_name(address)))?;
        let generation = owner.generation();
        let seals = barrier.seals.load(Ordering::SeqCst);
        let stages = counts.stages.load(Ordering::SeqCst);
        let unknown = matches!(error, BackendError::OutcomeUnknown | BackendError::StaleWriter);
        owner.backend.error_after_reuse = Some(error);
        owner.backend.reject_stage = true;
        barrier.reject_seal.store(true, Ordering::SeqCst);
        let result = reuse(&mut owner, &session, address);
        if unknown {
            assert!(matches!(result, Err(ServiceError::RecoveryRequired)));
            assert!(owner.unresolved);
            assert!(matches!(owner.verify_live_ownership(), Err(ServiceError::RecoveryRequired)));
        } else {
            assert!(matches!(result, Err(ServiceError::CorruptState)));
            assert!(!owner.unresolved);
        }
        assert_eq!(barrier.seals.load(Ordering::SeqCst), seals);
        assert_eq!(counts.stages.load(Ordering::SeqCst), stages);
        assert_eq!(owner.generation(), generation);
        assert_eq!(primary_files(&root)?, primary);
        assert_eq!(fs::read(root.0.join(leaf_name(address)))?, bytes);
    }
    Ok(())
}

#[test]
fn immutable_reuse_rejects_same_inode_valid_nonce_change_after_sync() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner, barrier, counts) = fixture("reuse-same-inode-nonce")?;
    let session = session(&mut owner)?;
    let address = locator(10)?;
    first_object(&mut owner, &session, address)?;
    let leaf = root.0.join(leaf_name(address));
    let original = fs::read(&leaf)?;
    let replacement = barrier.seal(CONTEXT, PAYLOAD)?;
    assert_ne!(original, replacement);
    assert_eq!(original.len(), replacement.len());
    assert_eq!(barrier.open(CONTEXT, &replacement)?.as_slice(), PAYLOAD);
    let before = fs::metadata(&leaf)?;
    let primary = primary_files(&root)?;
    let generation = owner.generation();
    let seals = barrier.seals.load(Ordering::SeqCst);
    let opens = barrier.opens.load(Ordering::SeqCst);
    let stages = counts.stages.load(Ordering::SeqCst);
    // The replacement is valid under this same local barrier and opens to the
    // same fresh plaintext. Only binding the actual synchronized wire bytes
    // can reject borrowing the old fsync receipt for this new unsynced nonce.
    owner.backend.rewrite_after_reuse = Some((leaf.clone(), replacement.clone()));
    owner.backend.reject_stage = true;
    barrier.reject_seal.store(true, Ordering::SeqCst);
    assert!(matches!(
        reuse(&mut owner, &session, address),
        Err(ServiceError::CorruptState)
    ));
    let after = fs::metadata(&leaf)?;
    assert_eq!(before.dev(), after.dev());
    assert_eq!(before.ino(), after.ino());
    assert_eq!(before.len(), after.len());
    assert_eq!(fs::read(&leaf)?, replacement);
    assert_eq!(barrier.opens.load(Ordering::SeqCst), opens);
    assert_eq!(barrier.seals.load(Ordering::SeqCst), seals);
    assert_eq!(counts.stages.load(Ordering::SeqCst), stages);
    assert_eq!(owner.generation(), generation);
    assert_eq!(primary_files(&root)?, primary);
    Ok(())
}

#[test]
fn immutable_reuse_boxed_file_backend_forwards_supported_capability() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("reuse-boxed-file")?;
    let barrier = CountingBarrier::new();
    let mut owner = DurableService::create_new(&root.0, barrier.clone(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let session = session(&mut owner)?;
    let address = locator(11)?;
    let first = owner.stage_immutable_object_before_publish(
        &session, address, CONTEXT, PAYLOAD, &mut no_gate,
    )?;
    let original = first.read_ciphertext()?;
    let primary = primary_files(&root)?;
    let seals = barrier.seals.load(Ordering::SeqCst);
    barrier.reject_seal.store(true, Ordering::SeqCst);
    let pin = owner.stage_immutable_object_reusing_existing_before_publish(
        &session, address, PAYLOAD.len() + 40, CONTEXT, PAYLOAD, &mut no_gate,
    )?;
    assert_eq!(pin.read_ciphertext()?.as_slice(), original.as_slice());
    assert_eq!(barrier.seals.load(Ordering::SeqCst), seals);
    assert_eq!(primary_files(&root)?, primary);
    Ok(())
}

#[test]
fn immutable_reuse_plain_read_pin_is_not_a_synchronization_receipt() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner, barrier, counts) = fixture("reuse-ordinary-read-pin")?;
    let session = session(&mut owner)?;
    let address = locator(12)?;
    first_object(&mut owner, &session, address)?;
    let bytes = fs::read(root.0.join(leaf_name(address)))?;
    let primary = primary_files(&root)?;
    let seals = barrier.seals.load(Ordering::SeqCst);
    let opens = barrier.opens.load(Ordering::SeqCst);
    let stages = counts.stages.load(Ordering::SeqCst);
    owner.backend.return_plain_read_pin = true;
    owner.backend.reject_stage = true;
    barrier.reject_seal.store(true, Ordering::SeqCst);
    assert!(matches!(
        reuse(&mut owner, &session, address),
        Err(ServiceError::CorruptState)
    ));
    assert_eq!(barrier.seals.load(Ordering::SeqCst), seals);
    assert_eq!(barrier.opens.load(Ordering::SeqCst), opens);
    assert_eq!(counts.stages.load(Ordering::SeqCst), stages);
    assert_eq!(fs::read(root.0.join(leaf_name(address)))?, bytes);
    assert_eq!(primary_files(&root)?, primary);
    Ok(())
}

#[test]
fn immutable_reuse_sync_witness_survives_aba_after_backend_and_final_aead_gate() -> TestResult {
    let _serial = serial_test();
    for phase in ["after_backend", "after_aead", "final_gate"] {
        let (root, mut owner, barrier, counts) = fixture("reuse-source-aba")?;
        let session = session(&mut owner)?;
        let address = locator(13)?;
        first_object(&mut owner, &session, address)?;
        let leaf = root.0.join(leaf_name(address));
        let original = fs::read(&leaf)?;
        let alternate = barrier.seal(CONTEXT, PAYLOAD)?;
        assert_ne!(original, alternate);
        assert_eq!(original.len(), alternate.len());
        assert_eq!(barrier.open(CONTEXT, &alternate)?.as_slice(), PAYLOAD);
        let metadata = fs::metadata(&leaf)?;
        let primary = primary_files(&root)?;
        let generation = owner.generation();
        let seals = barrier.seals.load(Ordering::SeqCst);
        let opens = barrier.opens.load(Ordering::SeqCst);
        let stages = counts.stages.load(Ordering::SeqCst);
        owner.backend.reject_stage = true;
        barrier.reject_seal.store(true, Ordering::SeqCst);
        let mut changed_after_open = false;
        let mut gates_after_open = 0;
        if phase == "after_backend" {
            owner.backend.aba_after_reuse = Some((leaf.clone(), alternate.clone(), original.clone()));
        }
        let result = owner.stage_immutable_object_reusing_existing_before_publish(
            &session,
            address,
            PAYLOAD.len() + 40,
            CONTEXT,
            PAYLOAD,
            &mut || {
                if phase != "after_backend"
                    && barrier.opens.load(Ordering::SeqCst) == opens + 1
                {
                    gates_after_open += 1;
                    let target_gate = if phase == "final_gate" { 2 } else { 1 };
                    if !changed_after_open && gates_after_open == target_gate {
                        rewrite_and_restore(&leaf, &alternate, &original)
                            .map_err(|_| ServiceError::CorruptState)?;
                        changed_after_open = true;
                    }
                }
                Ok(())
            },
        );
        assert!(matches!(result, Err(ServiceError::CorruptState)), "{phase}");
        assert_eq!(changed_after_open, phase != "after_backend");
        assert_eq!(
            barrier.opens.load(Ordering::SeqCst),
            opens + if phase != "after_backend" { 1 } else { 0 },
            "{phase}"
        );
        let after = fs::metadata(&leaf)?;
        assert_eq!((metadata.dev(), metadata.ino(), metadata.len()), (after.dev(), after.ino(), after.len()));
        assert_eq!((metadata.mtime(), metadata.mtime_nsec()), (after.mtime(), after.mtime_nsec()));
        assert_ne!((metadata.ctime(), metadata.ctime_nsec()), (after.ctime(), after.ctime_nsec()));
        assert_eq!(fs::read(&leaf)?, original, "{phase}");
        assert_eq!(barrier.seals.load(Ordering::SeqCst), seals, "{phase}");
        assert_eq!(counts.stages.load(Ordering::SeqCst), stages, "{phase}");
        assert_eq!(owner.generation(), generation, "{phase}");
        assert_eq!(primary_files(&root)?, primary, "{phase}");
        assert!(!root.0.join("native-v6-object.tmp").exists(), "{phase}");
    }
    Ok(())
}
