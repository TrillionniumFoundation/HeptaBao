//! Real FileBackend protocol tests using a deliberately nonproduction test
//! barrier. These prove physical/source custody, not cryptographic or native
//! layout admission, a successful migration, or a 128 MiB HTTP qualification.
use super::*;
use crate::tests::{TestBarrier, TestRoot, put_request, serial_test};
use std::{
    fs,
    io::Write,
    sync::atomic::{AtomicU64, Ordering},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const SOURCE: &[u8] = b"typed-root-fixture";
const CONTEXT: &[u8] = b"typed-object-context-fixture";
const STORE_ID: [u8; 16] = [0x37; 16];

#[derive(Clone)]
struct NonceBarrier {
    inner: TestBarrier,
    seals: Arc<AtomicU64>,
}
impl NonceBarrier {
    fn new() -> Self {
        Self {
            inner: TestBarrier::new(),
            seals: Arc::new(AtomicU64::new(0)),
        }
    }
}
impl Barrier for NonceBarrier {
    fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BarrierError> {
        let nonce = self.seals.fetch_add(1, Ordering::Relaxed).to_le_bytes();
        let mut associated = context.to_vec();
        associated.extend_from_slice(&nonce);
        let mut protected = nonce.to_vec();
        protected.extend(self.inner.seal(&associated, plaintext)?);
        Ok(protected)
    }
    fn open(&self, context: &[u8], protected: &[u8]) -> Result<Vec<u8>, BarrierError> {
        let (nonce, ciphertext) = protected.split_at_checked(8).ok_or(BarrierError)?;
        let mut associated = context.to_vec();
        associated.extend_from_slice(nonce);
        self.inner.open(&associated, ciphertext)
    }
    fn sealed_len_bound(&self, plaintext_len: usize) -> Option<usize> {
        plaintext_len.checked_add(40)
    }
}
fn source_session<B: Barrier, P: DurableBackend>(
    service: &mut DurableService<B, P>,
) -> Result<ImmutableSourceSession, ServiceError> {
    service.immutable_source_session("root/team-a", "secret/application", SOURCE, STORE_ID)
}
fn locator(address: u8) -> Result<BlobLocator, BackendError> {
    BlobLocator::new(STORE_ID, [address; 32])
}
fn source_unchanged<B: Barrier, P: DurableBackend>(
    service: &DurableService<B, P>,
    generation: u64,
) -> TestResult {
    assert_eq!(service.generation(), generation);
    let actual = service
        .get("root/team-a", "secret/application")?
        .ok_or("missing source")?;
    assert_eq!(actual.expose(), SOURCE);
    Ok(())
}
fn no_gate() -> Result<(), ServiceError> {
    Ok(())
}
fn has_object(root: &std::path::Path) -> bool {
    fs::read_dir(root).is_ok_and(|entries| {
        entries.filter_map(Result::ok).any(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("nv6.") && name.ends_with(".hbo"))
        })
    })
}

#[test]
fn immutable_actual_source_stage_close_and_cold_pin_keep_primary_root() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-session-cold")?;
    let barrier = NonceBarrier::new();
    let mut service = DurableService::create_new(&root.0, barrier.clone(), 16)?;
    service.put(put_request("source", SOURCE)?)?;
    let generation = service.generation();
    let session = source_session(&mut service)?;
    let payload = vec![0x31; 256 * 1024];
    let pin = service.stage_immutable_object_before_publish(
        &session,
        locator(1)?,
        CONTEXT,
        &payload,
        &mut no_gate,
    )?;
    let ciphertext_len = pin.ciphertext_len();
    assert_eq!(
        service
            .read_immutable_object_before_delivery(&session, &pin, CONTEXT, &mut no_gate)?
            .as_slice(),
        payload
    );
    source_unchanged(&service, generation)?;
    service.close()?;
    assert!(matches!(
        pin.read_ciphertext(),
        Err(BackendError::Unavailable)
    ));
    let mut cold = DurableService::reopen(&root.0, barrier, 16)?;
    assert!(matches!(
        cold.pin_immutable_object_before_read(&session, locator(1)?, ciphertext_len, &mut no_gate),
        Err(ServiceError::RecoveryRequired)
    ));
    let fresh = source_session(&mut cold)?;
    let actual =
        cold.pin_immutable_object_before_read(&fresh, locator(1)?, ciphertext_len, &mut no_gate)?;
    assert_eq!(
        cold.read_immutable_object_before_delivery(&fresh, &actual, CONTEXT, &mut no_gate)?
            .as_slice(),
        payload
    );
    source_unchanged(&cold, generation)?;
    Ok(())
}

#[test]
fn immutable_actual_source_rejects_foreign_instance_and_directory_pin() -> TestResult {
    let _serial = serial_test();
    let first = TestRoot::new("immutable-session-first")?;
    let second = TestRoot::new("immutable-session-second")?;
    let barrier = NonceBarrier::new();
    let mut owner = DurableService::create_new(&first.0, barrier.clone(), 16)?;
    let mut foreign = DurableService::create_new(&second.0, barrier, 16)?;
    owner.put(put_request("owner-source", SOURCE)?)?;
    foreign.put(put_request("foreign-source", SOURCE)?)?;
    let owner_session = source_session(&mut owner)?;
    let foreign_session = source_session(&mut foreign)?;
    let pin = foreign.stage_immutable_object_before_publish(
        &foreign_session,
        locator(2)?,
        CONTEXT,
        b"same-shaped",
        &mut no_gate,
    )?;
    assert!(matches!(
        foreign.read_immutable_object_before_delivery(&owner_session, &pin, CONTEXT, &mut no_gate),
        Err(ServiceError::PublicationConditionConflict)
    ));
    assert!(matches!(
        owner.read_immutable_object_before_delivery(&owner_session, &pin, CONTEXT, &mut no_gate),
        Err(ServiceError::InvalidResource)
    ));
    assert!(matches!(
        owner.immutable_source_session(
            "root/team-a",
            "secret/application",
            b"wrong-root",
            STORE_ID
        ),
        Err(ServiceError::PublicationConditionConflict)
    ));
    assert!(!has_object(&first.0));
    Ok(())
}

#[test]
fn immutable_actual_source_rejects_intervening_generation_epoch_and_source_change() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-session-epoch")?;
    let mut owner = DurableService::create_new(&root.0, NonceBarrier::new(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation_session = source_session(&mut owner)?;
    owner.put(PutRequest::new(
        "principal-a",
        "root/team-a",
        "other",
        "secret/other",
        [7; 32],
        Secret::new(b"other".to_vec())?,
    )?)?;
    assert!(matches!(
        owner.stage_immutable_object_before_publish(
            &generation_session,
            locator(3)?,
            CONTEXT,
            b"blocked",
            &mut no_gate
        ),
        Err(ServiceError::PublicationConditionConflict)
    ));
    let epoch_session = source_session(&mut owner)?;
    owner.retire_replay_epoch()?;
    assert!(matches!(
        owner.stage_immutable_object_before_publish(
            &epoch_session,
            locator(3)?,
            CONTEXT,
            b"blocked",
            &mut no_gate
        ),
        Err(ServiceError::PublicationConditionConflict)
    ));
    let root_session = source_session(&mut owner)?;
    owner.put_in_replay_epoch(
        owner.replay_epoch(),
        put_request("replace-source", b"different-root")?,
    )?;
    assert!(matches!(
        owner.stage_immutable_object_before_publish(
            &root_session,
            locator(3)?,
            CONTEXT,
            b"blocked",
            &mut no_gate
        ),
        Err(ServiceError::PublicationConditionConflict)
    ));
    assert!(!has_object(&root.0));
    Ok(())
}

#[test]
fn immutable_original_gate_rejects_before_crypto_after_crypto_and_after_staging() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-session-gate")?;
    let barrier = NonceBarrier::new();
    let mut owner = DurableService::create_new(&root.0, barrier.clone(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    assert!(matches!(
        owner.stage_immutable_object_before_publish(
            &session,
            locator(4)?,
            CONTEXT,
            b"blocked",
            &mut || Err(ServiceError::ReplayEpochMismatch)
        ),
        Err(ServiceError::ReplayEpochMismatch)
    ));
    assert!(!has_object(&root.0));
    let before_seal = barrier.seals.load(Ordering::Relaxed);
    let mut gate = || {
        if barrier.seals.load(Ordering::Relaxed) > before_seal {
            Err(ServiceError::ReplayEpochMismatch)
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        owner.stage_immutable_object_before_publish(
            &session,
            locator(4)?,
            CONTEXT,
            b"blocked-after-crypto",
            &mut gate
        ),
        Err(ServiceError::ReplayEpochMismatch)
    ));
    assert!(!has_object(&root.0));
    let mut late_gate = || {
        if has_object(&root.0) {
            Err(ServiceError::ReplayEpochMismatch)
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        owner.stage_immutable_object_before_publish(
            &session,
            locator(4)?,
            CONTEXT,
            b"known-orphan",
            &mut late_gate
        ),
        Err(ServiceError::ReplayEpochMismatch)
    ));
    assert!(has_object(&root.0));
    // A known immutable orphan is not a root publication or an unknown apply.
    assert!(!owner.recovery_required());
    source_unchanged(&owner, generation)?;
    // A gate failure directly after no-replace link can leave the original
    // temporary hardlink. Only genuine cold cleanup may re-admit that file.
    owner.close()?;
    let mut cold = DurableService::reopen(&root.0, barrier, 16)?;
    source_unchanged(&cold, generation)?;
    let fresh = source_session(&mut cold)?;
    let actual = cold.pin_immutable_object_before_read(
        &fresh,
        locator(4)?,
        40 + b"known-orphan".len(),
        &mut no_gate,
    )?;
    assert_eq!(
        cold.read_immutable_object_before_delivery(&fresh, &actual, CONTEXT, &mut no_gate)?
            .as_slice(),
        b"known-orphan"
    );
    Ok(())
}

#[test]
fn immutable_existing_different_nonce_is_authenticated_and_never_overwritten() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-session-nonce")?;
    let mut owner = DurableService::create_new(&root.0, NonceBarrier::new(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    let first = owner.stage_immutable_object_before_publish(
        &session,
        locator(5)?,
        CONTEXT,
        b"original",
        &mut no_gate,
    )?;
    let first_wire = first.read_ciphertext()?;
    let second = owner.stage_immutable_object_before_publish(
        &session,
        locator(5)?,
        CONTEXT,
        b"original",
        &mut no_gate,
    )?;
    assert_eq!(second.read_ciphertext()?.as_slice(), first_wire.as_slice());
    assert!(matches!(
        owner.stage_immutable_object_before_publish(
            &session,
            locator(5)?,
            CONTEXT,
            b"altered!",
            &mut no_gate
        ),
        Err(ServiceError::RequestBindingConflict)
    ));
    assert_eq!(first.read_ciphertext()?.as_slice(), first_wire.as_slice());
    assert!(matches!(
        owner.read_immutable_object_before_delivery(
            &session,
            &first,
            b"foreign-domain",
            &mut no_gate
        ),
        Err(ServiceError::BarrierFailure)
    ));
    source_unchanged(&owner, generation)?;
    Ok(())
}

#[test]
fn immutable_actual_ciphertext_corruption_is_rejected_without_primary_write() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-session-corrupt")?;
    let mut owner = DurableService::create_new(&root.0, NonceBarrier::new(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    let pin = owner.stage_immutable_object_before_publish(
        &session,
        locator(6)?,
        CONTEXT,
        b"authenticated",
        &mut no_gate,
    )?;
    let leaf = fs::read_dir(&root.0)?
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("nv6."))
        })
        .ok_or("missing actual object file")?;
    let mut changed = pin.read_ciphertext()?.as_slice().to_vec();
    *changed.last_mut().ok_or("empty ciphertext")? ^= 0x80;
    let mut file = fs::OpenOptions::new().write(true).open(leaf.path())?;
    file.write_all(&changed)?;
    file.sync_all()?;
    assert!(matches!(
        owner.read_immutable_object_before_delivery(&session, &pin, CONTEXT, &mut no_gate),
        Err(ServiceError::BarrierFailure)
    ));
    source_unchanged(&owner, generation)?;
    Ok(())
}

#[test]
fn immutable_wrong_store_and_cipher_capacity_reject_without_stage() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-session-bounds")?;
    let mut owner = DurableService::create_new(&root.0, NonceBarrier::new(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let session = source_session(&mut owner)?;
    let foreign = BlobLocator::new([0x38; 16], [7; 32])?;
    assert!(matches!(
        owner.stage_immutable_object_before_publish(
            &session,
            foreign,
            CONTEXT,
            b"blocked",
            &mut no_gate
        ),
        Err(ServiceError::InvalidResource)
    ));
    assert!(matches!(
        owner.stage_immutable_object_before_publish(
            &session,
            locator(7)?,
            CONTEXT,
            &vec![0x31; MAX_IMMUTABLE_CIPHERTEXT_BYTES],
            &mut no_gate
        ),
        Err(ServiceError::RequestCapacityExhausted)
    ));
    assert!(!has_object(&root.0));
    Ok(())
}

struct FilesystemStageFault {
    inner: FileBackend,
    lose_once: bool,
    redirect: Option<BlobLocator>,
}
impl DurableBackend for FilesystemStageFault {
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
    fn stage_immutable_ciphertext(
        &mut self,
        locator: BlobLocator,
        bytes: &[u8],
    ) -> Result<ImmutableBlobStage, BackendError> {
        let stage = self
            .inner
            .stage_immutable_ciphertext(self.redirect.unwrap_or(locator), bytes)?;
        if std::mem::take(&mut self.lose_once) {
            Err(BackendError::OutcomeUnknown)
        } else {
            Ok(stage)
        }
    }
    fn stage_immutable_ciphertext_checked(
        &mut self,
        locator: BlobLocator,
        bytes: &[u8],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<ImmutableBlobStage, BackendError> {
        let stage = self.inner.stage_immutable_ciphertext_checked(
            self.redirect.unwrap_or(locator),
            bytes,
            gate,
        )?;
        if std::mem::take(&mut self.lose_once) {
            Err(BackendError::OutcomeUnknown)
        } else {
            Ok(stage)
        }
    }
    fn close(self) -> Result<(), BackendError> {
        self.inner.close()
    }
}

#[test]
fn immutable_lost_real_filesystem_stage_ack_fences_then_cold_authenticates_once() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-session-lost-ack")?;
    let barrier = NonceBarrier::new();
    let backend = FilesystemStageFault {
        inner: FileBackend::create_new(&root.0)?,
        lose_once: true,
        redirect: None,
    };
    let mut owner = DurableService::create_new_with_backend(backend, barrier.clone(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    assert!(matches!(
        owner.stage_immutable_object_before_publish(
            &session,
            locator(8)?,
            CONTEXT,
            b"lost-ack-object",
            &mut no_gate
        ),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(owner.recovery_required());
    assert!(has_object(&root.0));
    assert!(matches!(
        owner.pin_immutable_object_before_read(
            &session,
            locator(8)?,
            40 + b"lost-ack-object".len(),
            &mut no_gate
        ),
        Err(ServiceError::RecoveryRequired)
    ));
    owner.close()?;
    let mut cold = DurableService::reopen(&root.0, barrier, 16)?;
    source_unchanged(&cold, generation)?;
    let fresh = source_session(&mut cold)?;
    let actual = cold.pin_immutable_object_before_read(
        &fresh,
        locator(8)?,
        40 + b"lost-ack-object".len(),
        &mut no_gate,
    )?;
    assert_eq!(
        cold.read_immutable_object_before_delivery(&fresh, &actual, CONTEXT, &mut no_gate)?
            .as_slice(),
        b"lost-ack-object"
    );
    let count = fs::read_dir(&root.0)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("nv6.") && name.ends_with(".hbo"))
        })
        .count();
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn immutable_actual_stage_rejects_pin_for_different_typed_address() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-session-redirect")?;
    let backend = FilesystemStageFault {
        inner: FileBackend::create_new(&root.0)?,
        lose_once: false,
        redirect: Some(locator(10)?),
    };
    let mut owner = DurableService::create_new_with_backend(backend, NonceBarrier::new(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    assert!(matches!(
        owner.stage_immutable_object_before_publish(
            &session,
            locator(9)?,
            CONTEXT,
            b"wrong-file-address",
            &mut no_gate
        ),
        Err(ServiceError::CorruptState)
    ));
    source_unchanged(&owner, generation)?;
    assert!(has_object(&root.0));
    Ok(())
}

#[test]
fn immutable_same_directory_backend_reopen_changes_private_physical_lineage() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-session-reconnect")?;
    let placeholder = TestRoot::new("immutable-session-placeholder")?;
    let backend = FilesystemStageFault {
        inner: FileBackend::create_new(&root.0)?,
        lose_once: false,
        redirect: None,
    };
    let mut owner = DurableService::create_new_with_backend(backend, NonceBarrier::new(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let original = source_session(&mut owner)?;
    let pin = owner.stage_immutable_object_before_publish(
        &original,
        locator(11)?,
        CONTEXT,
        b"old-physical-owner",
        &mut no_gate,
    )?;
    let length = pin.ciphertext_len();
    // An intentionally misbehaving wrapper reconnects underneath unchanged
    // Service instance/generation/epoch/root. Actual lease identity must detect
    // this ABA even though the directory's dev/ino has not changed.
    let prior = std::mem::replace(
        &mut owner.backend.inner,
        FileBackend::create_new(&placeholder.0)?,
    );
    prior.close()?;
    owner.backend.inner = FileBackend::open(&root.0)?;
    source_unchanged(&owner, generation)?;
    assert!(matches!(
        owner.pin_immutable_object_before_read(&original, locator(11)?, length, &mut no_gate),
        Err(ServiceError::PublicationConditionConflict)
    ));
    assert!(matches!(
        pin.read_ciphertext(),
        Err(BackendError::Unavailable)
    ));
    let fresh = source_session(&mut owner)?;
    let actual =
        owner.pin_immutable_object_before_read(&fresh, locator(11)?, length, &mut no_gate)?;
    assert!(!pin.matches_profile(&fresh.profile));
    assert!(actual.matches_profile(&fresh.profile));
    assert_eq!(
        owner
            .read_immutable_object_before_delivery(&fresh, &actual, CONTEXT, &mut no_gate)?
            .as_slice(),
        b"old-physical-owner"
    );
    Ok(())
}

#[test]
fn immutable_read_observation_records_actual_open_but_never_bypasses_late_gate() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-observation-late-gate")?;
    let mut owner = DurableService::create_new(&root.0, NonceBarrier::new(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    let payload = b"owned observation fixture";
    let pin = owner.stage_immutable_object_before_publish(
        &session,
        locator(11)?,
        CONTEXT,
        payload,
        &mut no_gate,
    )?;
    let opened = std::cell::Cell::new(false);
    let mut observations = Vec::new();
    let mut gate = || {
        if opened.get() {
            Err(ServiceError::ReplayEpochMismatch)
        } else {
            Ok(())
        }
    };
    let rejected = owner.read_immutable_object_before_delivery_observed(
        &session,
        &pin,
        CONTEXT,
        &mut gate,
        &mut |event| {
            if matches!(
                event,
                ImmutableObjectReadObservation::PlaintextOpened { .. }
            ) {
                opened.set(true);
            }
            observations.push(event);
        },
    );
    assert!(matches!(rejected, Err(ServiceError::ReplayEpochMismatch)));
    assert_eq!(
        observations,
        vec![
            ImmutableObjectReadObservation::PositionedReadReturned {
                bytes: pin.ciphertext_len(),
                failed: false,
                interrupted: false,
            },
            ImmutableObjectReadObservation::CiphertextRead {
                bytes: pin.ciphertext_len()
            },
            ImmutableObjectReadObservation::PlaintextOpened {
                bytes: payload.len()
            },
        ]
    );
    source_unchanged(&owner, generation)?;
    Ok(())
}

#[test]
fn immutable_read_observation_separates_bad_aead_and_before_read_rejection() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-observation-bad-context")?;
    let mut owner = DurableService::create_new(&root.0, NonceBarrier::new(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    let pin = owner.stage_immutable_object_before_publish(
        &session,
        locator(12)?,
        CONTEXT,
        b"owned observer",
        &mut no_gate,
    )?;
    let mut observations = Vec::new();
    assert!(matches!(
        owner.read_immutable_object_before_delivery_observed(
            &session,
            &pin,
            b"foreign-domain",
            &mut no_gate,
            &mut |event| observations.push(event),
        ),
        Err(ServiceError::BarrierFailure)
    ));
    assert_eq!(
        observations,
        vec![
            ImmutableObjectReadObservation::PositionedReadReturned {
                bytes: pin.ciphertext_len(),
                failed: false,
                interrupted: false,
            },
            ImmutableObjectReadObservation::CiphertextRead {
                bytes: pin.ciphertext_len()
            },
        ]
    );
    observations.clear();
    assert!(matches!(
        owner.read_immutable_object_before_delivery_observed(
            &session,
            &pin,
            CONTEXT,
            &mut || Err(ServiceError::ReplayEpochMismatch),
            &mut |event| observations.push(event),
        ),
        Err(ServiceError::ReplayEpochMismatch)
    ));
    assert!(observations.is_empty());
    source_unchanged(&owner, generation)?;
    Ok(())
}

#[test]
fn immutable_positioned_read_observation_precedes_late_gate_without_aead_or_delivery() -> TestResult
{
    let _serial = serial_test();
    let root = TestRoot::new("immutable-observation-after-pread-before-gate")?;
    let mut owner = DurableService::create_new(&root.0, NonceBarrier::new(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    let pin = owner.stage_immutable_object_before_publish(
        &session,
        locator(13)?,
        CONTEXT,
        b"owned positioned-read observer",
        &mut no_gate,
    )?;
    let actual_read_returned = std::cell::Cell::new(false);
    let mut observations = Vec::new();
    let mut gate = || {
        if actual_read_returned.get() {
            Err(ServiceError::ReplayEpochMismatch)
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        owner.read_immutable_object_before_delivery_observed(
            &session,
            &pin,
            CONTEXT,
            &mut gate,
            &mut |event| {
                if matches!(
                    event,
                    ImmutableObjectReadObservation::PositionedReadReturned { .. }
                ) {
                    actual_read_returned.set(true);
                }
                observations.push(event);
            },
        ),
        Err(ServiceError::ReplayEpochMismatch)
    ));
    assert_eq!(
        observations,
        vec![ImmutableObjectReadObservation::PositionedReadReturned {
            bytes: pin.ciphertext_len(),
            failed: false,
            interrupted: false,
        }]
    );
    source_unchanged(&owner, generation)?;
    assert_eq!(
        pin.read_ciphertext()?.as_slice().len(),
        pin.ciphertext_len()
    );
    Ok(())
}
