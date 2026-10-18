//! Actual durable-owner sessions for an independent sealed immutable store.
//! A session is a physical source binding, never an Actor, NativeProof, typed
//! address-MAC witness, resource write grant or successful migration receipt.
use super::*;
use std::sync::{Arc, Weak};

#[path = "immutable_source_reuse.rs"]
mod reuse;

const MAX_SESSION_ROOT_BYTES: usize = 1024 * 1024;
const MAX_OBJECT_CONTEXT_BYTES: usize = 4096;

/// Minted by the actual live service from an exact current source resource.
/// No constructor, Clone, serde or plaintext/address-key observation is public.
pub struct ImmutableSourceSession {
    instance: Weak<()>,
    generation: u64,
    replay_epoch: u64,
    namespace: String,
    resource: String,
    root: Secret,
    store_id: [u8; 16],
    profile: ImmutableBlobProfile,
}
impl fmt::Debug for ImmutableSourceSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImmutableSourceSession")
            .field("generation", &self.generation)
            .field("replay_epoch", &self.replay_epoch)
            .finish_non_exhaustive()
    }
}
impl ImmutableSourceSession {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn replay_epoch(&self) -> u64 {
        self.replay_epoch
    }
    pub fn store_id(&self) -> [u8; 16] {
        self.store_id
    }
}

/// Size observations grant no Actor, delivery or publication authority.
/// Later gates and typed address/grammar checks still may reject plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImmutableObjectReadObservation {
    PositionedReadReturned {
        bytes: usize,
        failed: bool,
        interrupted: bool,
    },
    CiphertextRead {
        bytes: usize,
    },
    PlaintextOpened {
        bytes: usize,
    },
}

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    /// Establish only an actual current physical source binding. The server must
    /// separately prove its authenticated typed root, layout, Actor and original
    /// Clock/deadline before using this source for native publication.
    pub fn immutable_source_session(
        &mut self,
        namespace: &str,
        resource: &str,
        expected_root: &[u8],
        store_id: [u8; 16],
    ) -> Result<ImmutableSourceSession, ServiceError> {
        self.verify_live_ownership()?;
        validate_namespace(namespace)?;
        validate_resource(resource)?;
        if expected_root.is_empty()
            || expected_root.len() > MAX_SESSION_ROOT_BYTES
            || store_id == [0; 16]
        {
            return Err(ServiceError::InvalidResource);
        }
        let profile = self
            .backend
            .immutable_blob_profile()
            .map_err(map_backend_error)?;
        if !profile.is_live() {
            return Err(ServiceError::RecoveryRequired);
        }
        let root = self
            .snapshot
            .entries
            .get(&(namespace.to_owned(), resource.to_owned()))
            .ok_or(ServiceError::CorruptState)?;
        if root.expose() != expected_root {
            return Err(ServiceError::PublicationConditionConflict);
        }
        let session = ImmutableSourceSession {
            instance: Arc::downgrade(&self.restore_instance),
            generation: self.snapshot.generation,
            replay_epoch: self.replay_epoch,
            namespace: namespace.to_owned(),
            resource: resource.to_owned(),
            root: root.clone(),
            store_id,
            profile,
        };
        self.check_immutable_source_session(&session)?;
        Ok(session)
    }

    pub(super) fn check_immutable_source_session(
        &mut self,
        session: &ImmutableSourceSession,
    ) -> Result<(), ServiceError> {
        self.verify_live_ownership()?;
        let instance = session
            .instance
            .upgrade()
            .ok_or(ServiceError::RecoveryRequired)?;
        if !session.profile.is_live()
            || !Arc::ptr_eq(&instance, &self.restore_instance)
            || session.generation != self.snapshot.generation
            || session.replay_epoch != self.replay_epoch
            || self
                .backend
                .immutable_blob_profile()
                .map_err(map_backend_error)?
                != session.profile
            || self
                .snapshot
                .entries
                .get(&(session.namespace.clone(), session.resource.clone()))
                .is_none_or(|root| root.expose() != session.root.expose())
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        self.verify_live_ownership()
    }

    /// Seal/stage one bounded object under this actual owner. Every local crypto
    /// and physical step retains the caller's same original custody check. No
    /// canonical root, cursor or replay envelope is written by this method.
    pub fn stage_immutable_object_before_publish(
        &mut self,
        session: &ImmutableSourceSession,
        locator: BlobLocator,
        context: &[u8],
        plaintext: &[u8],
        before: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<ImmutableBlobReadPin, ServiceError> {
        before()?;
        self.check_immutable_source_session(session)?;
        if locator.store_id() != session.store_id
            || context.is_empty()
            || context.len() > MAX_OBJECT_CONTEXT_BYTES
            || plaintext.is_empty()
            || plaintext.len() > session.profile.max_ciphertext_bytes
        {
            return Err(ServiceError::InvalidResource);
        }
        before()?;
        let protected = Zeroizing::new(
            self.barrier
                .seal(context, plaintext)
                .map_err(|_| ServiceError::BarrierFailure)?,
        );
        before()?;
        self.check_immutable_source_session(session)?;
        if protected.is_empty() || protected.len() > session.profile.max_ciphertext_bytes {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let mut gate_error = None;
        let mut physical_gate = || match before() {
            Ok(()) => Ok(()),
            Err(error) => {
                gate_error = Some(error);
                Err(BackendError::Unavailable)
            }
        };
        let staged = self.backend.stage_immutable_ciphertext_checked(
            locator,
            &protected,
            &mut physical_gate,
        );
        if matches!(
            staged,
            Err(BackendError::OutcomeUnknown | BackendError::StaleWriter)
        ) {
            self.unresolved = true;
        }
        if let Some(error) = gate_error {
            return Err(error);
        }
        let pin = match staged.map_err(map_backend_error)? {
            ImmutableBlobStage::Published(pin) | ImmutableBlobStage::AlreadyExists(pin) => pin,
        };
        before()?;
        self.check_immutable_source_session(session)?;
        if pin.locator() != locator || !pin.matches_profile(&session.profile) {
            return Err(ServiceError::CorruptState);
        }
        let observed =
            self.read_immutable_object_before_delivery(session, &pin, context, before)?;
        if observed.as_slice() != plaintext {
            return Err(ServiceError::RequestBindingConflict);
        }
        before()?;
        self.check_immutable_source_session(session)?;
        Ok(pin)
    }

    /// Open one exact bounded ciphertext from the actual admitted backend.
    /// Caller-supplied syntax never substitutes for the source instance or the
    /// kernel's authenticated typed layout and address checks.
    pub fn pin_immutable_object_before_read(
        &mut self,
        session: &ImmutableSourceSession,
        locator: BlobLocator,
        exact_len: usize,
        before: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<ImmutableBlobReadPin, ServiceError> {
        before()?;
        self.check_immutable_source_session(session)?;
        if locator.store_id() != session.store_id
            || exact_len == 0
            || exact_len > session.profile.max_ciphertext_bytes
        {
            return Err(ServiceError::InvalidResource);
        }
        before()?;
        let pin = self
            .backend
            .pin_immutable_ciphertext(locator, exact_len)
            .map_err(map_backend_error)?;
        before()?;
        self.check_immutable_source_session(session)?;
        if pin.locator() != locator
            || !pin.matches_profile(&session.profile)
            || pin.ciphertext_len() != exact_len
        {
            return Err(ServiceError::CorruptState);
        }
        Ok(pin)
    }

    /// Barrier-authenticate the actual sealed file under an exact current source
    /// session. The kernel still MUST verify domain, ObjectRef kind/length/address
    /// MAC and canonical grammar before accepting these bytes as a native object.
    pub fn read_immutable_object_before_delivery(
        &mut self,
        session: &ImmutableSourceSession,
        pin: &ImmutableBlobReadPin,
        context: &[u8],
        before: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
        self.read_immutable_object_before_delivery_observed(
            session,
            pin,
            context,
            before,
            &mut |_| {},
        )
    }

    pub fn read_immutable_object_before_delivery_observed(
        &mut self,
        session: &ImmutableSourceSession,
        pin: &ImmutableBlobReadPin,
        context: &[u8],
        before: &mut impl FnMut() -> Result<(), ServiceError>,
        observe: &mut impl FnMut(ImmutableObjectReadObservation),
    ) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
        before()?;
        self.check_immutable_source_session(session)?;
        if pin.locator().store_id() != session.store_id
            || !pin.matches_profile(&session.profile)
            || context.is_empty()
            || context.len() > MAX_OBJECT_CONTEXT_BYTES
            || pin.ciphertext_len() > session.profile.max_ciphertext_bytes
        {
            return Err(ServiceError::InvalidResource);
        }
        before()?;
        let mut physical_gate = || {
            before()?;
            self.check_immutable_source_session(session)
        };
        let mut physical_observer = |result: Result<usize, std::io::ErrorKind>| {
            let (bytes, failed, interrupted) = match result {
                Ok(bytes) => (bytes, false, false),
                Err(kind) => (0, true, kind == std::io::ErrorKind::Interrupted),
            };
            observe(ImmutableObjectReadObservation::PositionedReadReturned {
                bytes,
                failed,
                interrupted,
            });
        };
        let protected = pin
            .read_ciphertext_checked_observed(&mut physical_gate, &mut physical_observer)
            .map_err(|error| match error {
                PinReadError::Backend(error) => map_backend_error(error),
                PinReadError::Gate(error) => error,
            })?;
        observe(ImmutableObjectReadObservation::CiphertextRead {
            bytes: protected.len(),
        });
        before()?;
        self.check_immutable_source_session(session)?;
        let plaintext = Zeroizing::new(
            self.barrier
                .open(context, protected.as_slice())
                .map_err(|_| ServiceError::BarrierFailure)?,
        );
        observe(ImmutableObjectReadObservation::PlaintextOpened {
            bytes: plaintext.len(),
        });
        before()?;
        self.check_immutable_source_session(session)?;
        if plaintext.is_empty() || plaintext.len() > session.profile.max_ciphertext_bytes {
            return Err(ServiceError::CorruptState);
        }
        Ok(plaintext)
    }
}

#[cfg(all(test, unix))]
#[path = "immutable_source_session_tests.rs"]
mod tests;
