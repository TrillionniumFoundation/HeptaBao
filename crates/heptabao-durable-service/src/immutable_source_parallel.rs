//! A borrowed, FileBackend-only immutable reader for scoped read workers.
//! This is not a new source session or an Actor/publication capability. The
//! original service stays exclusively borrowed until every worker has joined.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// No Clone, public fields, caller-created instance or serializable authority.
/// The real FileBackend and every logical source field remain borrowed from
/// the same DurableService. Rust requires B and FileBackend to be Sync before
/// callers may share this view between scoped workers.
pub struct FileImmutableSourceReader<'a, B: Barrier> {
    backend: &'a FileBackend,
    barrier: &'a B,
    snapshot: &'a Snapshot,
    replay_epoch: &'a u64,
    instance: &'a std::sync::Arc<()>,
    unresolved: std::sync::Mutex<&'a mut bool>,
    ownership_failed: AtomicBool,
}
impl<B: Barrier> fmt::Debug for FileImmutableSourceReader<'_, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileImmutableSourceReader")
            .finish_non_exhaustive()
    }
}
impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    /// Eligibility only. This does not validate any session or permit a read.
    pub fn has_file_immutable_reader(&self) -> bool {
        self.backend.immutable_file_read_backend().is_some()
    }

    /// Lend only the original physical file owner. Backends with sessionful
    /// ownership checks (including remote database backends) keep their
    /// existing mutable, serial read API.
    pub fn borrow_file_immutable_reader(
        &mut self,
    ) -> Result<FileImmutableSourceReader<'_, B>, ServiceError> {
        self.verify_live_ownership()?;
        let backend = self
            .backend
            .immutable_file_read_backend()
            .ok_or(ServiceError::UnsupportedProfile)?;
        let reader = FileImmutableSourceReader {
            backend,
            barrier: &self.barrier,
            snapshot: &self.snapshot,
            replay_epoch: &self.replay_epoch,
            instance: &self.restore_instance,
            unresolved: std::sync::Mutex::new(&mut self.unresolved),
            ownership_failed: AtomicBool::new(false),
        };
        reader.verify_live_ownership()?;
        Ok(reader)
    }
}
impl<B: Barrier> FileImmutableSourceReader<'_, B> {
    // This lock covers only the original one-bit failure state, never I/O.
    // It writes the original service immediately; safety does not rely on Drop.
    fn latch_ownership_failure(&self) {
        self.ownership_failed.store(true, Ordering::Release);
        let mut unresolved = match self.unresolved.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        **unresolved = true;
    }

    fn available(&self) -> Result<(), ServiceError> {
        if self.ownership_failed.load(Ordering::Acquire) {
            return Err(ServiceError::RecoveryRequired);
        }
        match self.unresolved.lock() {
            Ok(unresolved) => {
                if **unresolved || self.ownership_failed.load(Ordering::Acquire) {
                    Err(ServiceError::RecoveryRequired)
                } else {
                    Ok(())
                }
            }
            Err(poisoned) => {
                **poisoned.into_inner() = true;
                self.ownership_failed.store(true, Ordering::Release);
                Err(ServiceError::RecoveryRequired)
            }
        }
    }

    fn verify_live_ownership(&self) -> Result<(), ServiceError> {
        self.available()?;
        if let Err(error) = self.backend.verify() {
            self.latch_ownership_failure();
            return Err(map_backend_error(error));
        }
        // Another worker may have observed a loss while this one verified.
        self.available()
    }

    pub fn get(&self, namespace: &str, resource: &str) -> Result<Option<Secret>, ServiceError> {
        validate_namespace(namespace)?;
        validate_resource(resource)?;
        self.available()?;
        let key = (namespace.to_owned(), resource.to_owned());
        let value = self.snapshot.entries.get(&key).cloned();
        self.available()?;
        Ok(value)
    }

    pub fn verify_immutable_source_session(
        &self,
        session: &ImmutableSourceSession,
    ) -> Result<(), ServiceError> {
        self.check_session(session)
    }

    fn check_session(&self, session: &ImmutableSourceSession) -> Result<(), ServiceError> {
        self.verify_live_ownership()?;
        let instance = session
            .instance
            .upgrade()
            .ok_or(ServiceError::RecoveryRequired)?;
        if !session.profile.is_live()
            || !std::sync::Arc::ptr_eq(&instance, self.instance)
            || session.generation != self.snapshot.generation
            || session.replay_epoch != *self.replay_epoch
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

    /// Open one exact bounded ciphertext from the actual admitted backend.
    /// Caller-supplied syntax never substitutes for the source instance or the
    /// kernel's authenticated typed layout and address checks.
    pub fn pin_immutable_object_before_read(
        &self,
        session: &ImmutableSourceSession,
        locator: BlobLocator,
        exact_len: usize,
        before: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<ImmutableBlobReadPin, ServiceError> {
        before()?;
        self.check_session(session)?;
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
        self.check_session(session)?;
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
        &self,
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
        &self,
        session: &ImmutableSourceSession,
        pin: &ImmutableBlobReadPin,
        context: &[u8],
        before: &mut impl FnMut() -> Result<(), ServiceError>,
        observe: &mut impl FnMut(ImmutableObjectReadObservation),
    ) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
        before()?;
        self.check_session(session)?;
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
            self.check_session(session)
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
        self.check_session(session)?;
        let plaintext = Zeroizing::new(
            self.barrier
                .open(context, protected.as_slice())
                .map_err(|_| ServiceError::BarrierFailure)?,
        );
        observe(ImmutableObjectReadObservation::PlaintextOpened {
            bytes: plaintext.len(),
        });
        before()?;
        self.check_session(session)?;
        if plaintext.is_empty() || plaintext.len() > session.profile.max_ciphertext_bytes {
            return Err(ServiceError::CorruptState);
        }
        Ok(plaintext)
    }
}

#[cfg(all(test, unix))]
#[path = "immutable_source_parallel_tests.rs"]
mod tests;
