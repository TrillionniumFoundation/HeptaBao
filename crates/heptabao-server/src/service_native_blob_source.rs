//! Explicit native object adapter over the actual descriptor-bound store.
//! The durable journal carries authenticated locator metadata, never the value.
//! This adapter grants neither a Principal nor typed graph/address authority.
use super::*;
use crate::state_record_root_v6::ObjectDomain;
use crate::state_records::{ObjectRef, RecordError, StagedObject};
use crate::v6_native_custody::OriginalDeadline;
use crate::v6_read_validation::ObjectSource;
use heptabao_durable_service::{
    BlobLocator, ImmutableObjectReadObservation, ImmutableSourceSession,
};
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

// One owned unit-test thread may pause its actual payload AEAD observation.
// This has no production CLI, HTTP route, environment knob or deadline change.
#[cfg(test)]
struct PayloadOpenPause {
    delay: std::time::Duration,
    fired: Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(test)]
thread_local! {
    static AFTER_PAYLOAD_OPEN_PAUSE: RefCell<Option<PayloadOpenPause>> = const { RefCell::new(None) };
}
#[cfg(test)]
pub(super) struct PayloadOpenPauseGuard {
    fired: Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(test)]
impl PayloadOpenPauseGuard {
    pub(super) fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}
#[cfg(test)]
impl Drop for PayloadOpenPauseGuard {
    fn drop(&mut self) {
        AFTER_PAYLOAD_OPEN_PAUSE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
#[cfg(test)]
pub(super) fn pause_after_payload_open_once(
    delay: std::time::Duration,
) -> Result<PayloadOpenPauseGuard, &'static str> {
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    AFTER_PAYLOAD_OPEN_PAUSE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err("owned payload-open pause is already armed");
        }
        *slot = Some(PayloadOpenPause {
            delay,
            fired: Arc::clone(&fired),
        });
        Ok(PayloadOpenPauseGuard { fired })
    })
}
#[cfg(test)]
fn observe_test_payload_open(event: &ImmutableObjectReadObservation) {
    if matches!(
        event,
        ImmutableObjectReadObservation::PlaintextOpened { .. }
    ) {
        let pause = AFTER_PAYLOAD_OPEN_PAUSE.with(|slot| slot.borrow_mut().take());
        if let Some(pause) = pause {
            pause.fired.store(true, Ordering::SeqCst);
            std::thread::sleep(pause.delay);
        }
    }
}

#[derive(Default)]
pub(super) struct PayloadObservations {
    pub(super) blocks_pinned: AtomicU64,
    pub(super) blocks_opened: AtomicU64,
    pub(super) ciphertext_bytes_read: AtomicU64,
    pub(super) plaintext_bytes_opened: AtomicU64,
    pub(super) positioned_read_calls: AtomicU64,
    pub(super) positioned_bytes_returned: AtomicU64,
    pub(super) positioned_read_failures: AtomicU64,
}
impl PayloadObservations {
    pub(super) fn snapshot(&self) -> [u64; 7] {
        [
            self.blocks_pinned.load(Ordering::Relaxed),
            self.blocks_opened.load(Ordering::Relaxed),
            self.ciphertext_bytes_read.load(Ordering::Relaxed),
            self.plaintext_bytes_opened.load(Ordering::Relaxed),
            self.positioned_read_calls.load(Ordering::Relaxed),
            self.positioned_bytes_returned.load(Ordering::Relaxed),
            self.positioned_read_failures.load(Ordering::Relaxed),
        ]
    }
    fn pinned(&self, bytes: usize) {
        self.blocks_pinned.fetch_add(1, Ordering::Relaxed);
        let _ = bytes;
    }
    fn observed(&self, event: ImmutableObjectReadObservation) {
        match event {
            ImmutableObjectReadObservation::PositionedReadReturned {
                bytes,
                failed,
                interrupted: _,
            } => {
                self.positioned_read_calls.fetch_add(1, Ordering::Relaxed);
                self.positioned_bytes_returned
                    .fetch_add(bytes as u64, Ordering::Relaxed);
                self.positioned_read_failures
                    .fetch_add(u64::from(failed), Ordering::Relaxed);
            }
            ImmutableObjectReadObservation::CiphertextRead { bytes } => {
                self.ciphertext_bytes_read
                    .fetch_add(bytes as u64, Ordering::Relaxed);
            }
            ImmutableObjectReadObservation::PlaintextOpened { bytes } => {
                self.blocks_opened.fetch_add(1, Ordering::Relaxed);
                self.plaintext_bytes_opened
                    .fetch_add(bytes as u64, Ordering::Relaxed);
            }
        }
    }
}

const MAGIC: &[u8; 16] = b"HBV6BLOBREF0001\0";
const SLOT_BYTES: usize = 16 + 16 + 32 + 4 + 4;

// These bytes are an authenticated journal entry, not a public capability.
// The enclosing typed ObjectRef and domain must still be authenticated by the
// actual graph reader. Exact widths keep untrusted length parsing bounded.
struct Slot {
    locator: BlobLocator,
    ciphertext_bytes: usize,
    plaintext_bytes: usize,
}
impl Slot {
    fn decode(bytes: &[u8], reference: &ObjectRef) -> Result<Self, RecordError> {
        if bytes.len() != SLOT_BYTES || &bytes[..16] != MAGIC {
            return Err(RecordError::Corrupt);
        }
        let store_id = bytes[16..32].try_into().map_err(|_| RecordError::Corrupt)?;
        let address = bytes[32..64].try_into().map_err(|_| RecordError::Corrupt)?;
        let ciphertext_bytes =
            u32::from_be_bytes(bytes[64..68].try_into().map_err(|_| RecordError::Corrupt)?)
                as usize;
        let plaintext_bytes =
            u32::from_be_bytes(bytes[68..72].try_into().map_err(|_| RecordError::Corrupt)?)
                as usize;
        if address != *reference.id.bytes()
            || plaintext_bytes != reference.encoded_bytes as usize
            || ciphertext_bytes == 0
            || ciphertext_bytes > heptabao_durable_service::MAX_IMMUTABLE_CIPHERTEXT_BYTES
        {
            return Err(RecordError::Corrupt);
        }
        Ok(Self {
            locator: BlobLocator::new(store_id, address).map_err(|_| RecordError::Corrupt)?,
            ciphertext_bytes,
            plaintext_bytes,
        })
    }
    fn encode(&self) -> Result<Secret, ServiceError> {
        let mut bytes = Vec::with_capacity(SLOT_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.locator.store_id());
        bytes.extend_from_slice(&self.locator.address());
        bytes.extend_from_slice(
            &u32::try_from(self.ciphertext_bytes)
                .map_err(|_| ServiceError::RequestCapacityExhausted)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.plaintext_bytes)
                .map_err(|_| ServiceError::RequestCapacityExhausted)?
                .to_be_bytes(),
        );
        Secret::new(bytes)
    }
}

fn store_id(root: &[u8]) -> Result<[u8; 16], ServiceError> {
    #[derive(Deserialize)]
    struct Cluster {
        cluster_id: String,
    }
    if root.len() > crate::state_record_root::MAX_ROOT_BYTES {
        return Err(ServiceError::CorruptState);
    }
    let cluster: Cluster = serde_json::from_slice(root).map_err(|_| ServiceError::CorruptState)?;
    if cluster.cluster_id.is_empty() || cluster.cluster_id.len() > 256 {
        return Err(ServiceError::CorruptState);
    }
    let mut scope = b"HeptaBao/native-v6/immutable-store/cluster\0".to_vec();
    scope.extend_from_slice(cluster.cluster_id.as_bytes());
    let digest = crypto::digest(&scope);
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] {
        return Err(ServiceError::CorruptState);
    }
    Ok(id)
}

fn context(domain: &ObjectDomain, reference: &ObjectRef) -> Vec<u8> {
    let mut aad = b"HeptaBao/native-v6/typed-object-file/v1\0".to_vec();
    aad.extend_from_slice(v6_records::native_resource(domain, reference).as_bytes());
    aad
}

pub(super) fn stage(
    durable: &mut DurableService<AeadBarrier>,
    session: &ImmutableSourceSession,
    domain: &ObjectDomain,
    object: &StagedObject,
    before: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<Secret, ServiceError> {
    before()?;
    let reference = object.reference();
    let locator = BlobLocator::new(session.store_id(), *reference.id.bytes())
        .map_err(|_| ServiceError::CorruptState)?;
    let aad = context(domain, reference);
    let pin = durable.stage_immutable_object_before_publish(
        session,
        locator,
        &aad,
        object.bytes(),
        before,
    )?;
    before()?;
    Slot {
        locator,
        ciphertext_bytes: pin.ciphertext_len(),
        plaintext_bytes: object.bytes().len(),
    }
    .encode()
}

pub(super) fn session(
    durable: &mut DurableService<AeadBarrier>,
    root: &[u8],
) -> Result<ImmutableSourceSession, ServiceError> {
    let id = store_id(root)?;
    durable.immutable_source_session("system", "state", root, id)
}

// The session fixes the actual root, generation, replay epoch and weak backend
// instance once. Per-object reads cannot recapture a different source or clock.
pub(super) struct NativeSource<'a> {
    durable: RefCell<&'a mut DurableService<AeadBarrier>>,
    session: ImmutableSourceSession,
    deadline: OriginalDeadline,
    allow_inline: bool,
    observations: Option<Arc<PayloadObservations>>,
    original_gate: RefCell<Box<dyn FnMut() -> Result<(), ServiceError> + 'a>>,
}
impl<'a> NativeSource<'a> {
    pub(super) fn with_observations(mut self, observations: Arc<PayloadObservations>) -> Self {
        self.observations = Some(observations);
        self
    }

    // Typed metadata names this exact ciphertext locator. Cold floor2 verifies
    // its actual descriptor/source/inode ownership with one bounded ciphertext
    // pin at a time; it does not decrypt or parse historical JSON. The selected
    // point reader still must authenticate AEAD and the typed plaintext address.
    pub(super) fn pin_payload_location(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<(), RecordError> {
        if !matches!(domain, ObjectDomain::Kv2(_))
            || reference.kind != crate::state_records::ObjectKind::Block
        {
            return Err(RecordError::Invalid);
        }
        let mut gate = self
            .original_gate
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?;
        let mut before = || {
            self.deadline
                .check()
                .map_err(|_| ServiceError::BarrierFailure)?;
            gate()?;
            self.deadline
                .check()
                .map_err(|_| ServiceError::BarrierFailure)
        };
        before().map_err(|_| RecordError::Invalid)?;
        let mut durable = self
            .durable
            .try_borrow_mut()
            .map_err(|_| RecordError::Corrupt)?;
        let stored = durable
            .get("system", &v6_records::native_resource(domain, reference))
            .map_err(|_| RecordError::Corrupt)?
            .ok_or(RecordError::Missing)?;
        before().map_err(|_| RecordError::Invalid)?;
        let slot = Slot::decode(stored.expose(), reference)?;
        if slot.locator.store_id() != self.session.store_id() {
            return Err(RecordError::Corrupt);
        }
        let pin = durable
            .pin_immutable_object_before_read(
                &self.session,
                slot.locator,
                slot.ciphertext_bytes,
                &mut before,
            )
            .map_err(|_| RecordError::Corrupt)?;
        if let Some(observations) = &self.observations {
            observations.pinned(pin.ciphertext_len());
        }
        drop(pin);
        before().map_err(|_| RecordError::Invalid)
    }

    pub(super) fn new_checked(
        durable: &'a mut DurableService<AeadBarrier>,
        deadline: OriginalDeadline,
        mut original_gate: impl FnMut() -> Result<(), ServiceError> + 'a,
    ) -> Result<Self, RecordError> {
        original_gate().map_err(|_| RecordError::Invalid)?;
        deadline.check().map_err(|_| RecordError::Invalid)?;
        durable
            .verify_live_ownership()
            .map_err(|_| RecordError::Corrupt)?;
        let root = durable
            .get("system", "state")
            .map_err(|_| RecordError::Corrupt)?
            .ok_or(RecordError::Missing)?;
        #[derive(Deserialize)]
        struct Frontier {
            #[serde(default)]
            reader_floor: Option<crate::state_record_root_v6::ReaderFloor>,
        }
        let frontier: Frontier =
            serde_json::from_slice(root.expose()).map_err(|_| RecordError::Corrupt)?;
        let allow_inline = frontier
            .reader_floor
            .is_none_or(|floor| floor.native_kv2_format == 1);
        let session = session(durable, root.expose()).map_err(|_| RecordError::Corrupt)?;
        deadline.check().map_err(|_| RecordError::Invalid)?;
        original_gate().map_err(|_| RecordError::Invalid)?;
        Ok(Self {
            durable: RefCell::new(durable),
            session,
            deadline,
            allow_inline,
            observations: None,
            original_gate: RefCell::new(Box::new(original_gate)),
        })
    }
}
impl NativeSource<'_> {
    // Only a descriptor's actual typed payload reader may request payload
    // observations. KV1 metadata indexes also have Block objects and never
    // count as historical payload reads merely because their kind is Block.
    pub(super) fn read_paged_payload(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        if !matches!(domain, ObjectDomain::Kv2(_))
            || reference.kind != crate::state_records::ObjectKind::Block
        {
            return Err(RecordError::Invalid);
        }
        self.read_checked(domain, reference, true)
    }

    fn read_checked(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
        observe_payload: bool,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let mut original_gate = self
            .original_gate
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?;
        original_gate().map_err(|_| RecordError::Invalid)?;
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        let mut durable = self
            .durable
            .try_borrow_mut()
            .map_err(|_| RecordError::Corrupt)?;
        let stored = durable
            .get("system", &v6_records::native_resource(domain, reference))
            .map_err(|_| RecordError::Corrupt)?
            .ok_or(RecordError::Missing)?;
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        if !stored.expose().starts_with(MAGIC) {
            if !self.allow_inline || stored.expose().len() != reference.encoded_bytes as usize {
                return Err(RecordError::Corrupt);
            }
            original_gate().map_err(|_| RecordError::Invalid)?;
            return Ok(Zeroizing::new(stored.expose().to_vec()));
        }
        let slot = Slot::decode(stored.expose(), reference)?;
        if slot.locator.store_id() != self.session.store_id() {
            return Err(RecordError::Corrupt);
        }
        let mut before = || {
            self.deadline
                .check()
                .map_err(|_| ServiceError::BarrierFailure)?;
            original_gate()?;
            self.deadline
                .check()
                .map_err(|_| ServiceError::BarrierFailure)
        };
        let pin = durable
            .pin_immutable_object_before_read(
                &self.session,
                slot.locator,
                slot.ciphertext_bytes,
                &mut before,
            )
            .map_err(|_| RecordError::Corrupt)?;
        if observe_payload && let Some(observations) = &self.observations {
            observations.pinned(pin.ciphertext_len());
        }
        let plaintext = durable
            .read_immutable_object_before_delivery_observed(
                &self.session,
                &pin,
                &context(domain, reference),
                &mut before,
                &mut |event| {
                    #[cfg(test)]
                    if observe_payload {
                        observe_test_payload_open(&event);
                    }
                    if observe_payload && let Some(observations) = &self.observations {
                        observations.observed(event);
                    }
                },
            )
            .map_err(|_| RecordError::Corrupt)?;

        if plaintext.len() != slot.plaintext_bytes {
            return Err(RecordError::Corrupt);
        }
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        Ok(plaintext)
    }
}

impl ObjectSource for NativeSource<'_> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        self.read_checked(domain, reference, false)
    }
}
