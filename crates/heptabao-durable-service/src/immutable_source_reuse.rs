//! Reuse only an actual synchronized local ciphertext under a current source
//! session. A physical pin is not typed authority: the caller must retain its
//! fresh verified object borrow, Actor/Auth and original absolute deadline.
use super::*;

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    /// Avoid sealing/writing an existing leaf only after physical re-admission
    /// and fresh local barrier authentication with exact plaintext equality.
    /// `exact_ciphertext_len` is an exact format length supplied by the concrete
    /// barrier owner, not the generic Barrier::sealed_len_bound upper bound.
    ///
    /// Initial ENOENT and explicit Unsupported are distinct branches that keep
    /// the ordinary staging path. Every error from an already opened leaf is
    /// final for this attempt. No root, locator journal or cursor is published.
    pub fn stage_immutable_object_reusing_existing_before_publish(
        &mut self,
        session: &ImmutableSourceSession,
        locator: BlobLocator,
        exact_ciphertext_len: usize,
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
        if exact_ciphertext_len == 0
            || exact_ciphertext_len > session.profile.max_ciphertext_bytes
        {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        before()?;
        let mut gate_error = None;
        let mut physical_gate = || match before() {
            Ok(()) => Ok(()),
            Err(error) => {
                gate_error = Some(error);
                Err(BackendError::Unavailable)
            }
        };
        let reused = self.backend.reuse_immutable_ciphertext_checked(
            locator,
            exact_ciphertext_len,
            &mut physical_gate,
        );
        if matches!(
            reused,
            Err(BackendError::OutcomeUnknown | BackendError::StaleWriter)
        ) {
            self.unresolved = true;
        }
        if let Some(error) = gate_error {
            return Err(error);
        }
        let pin = match reused {
            Ok(Some(pin)) => pin,
            Ok(None) => {
                // Only the first guarded open's actual ENOENT reaches here.
                before()?;
                self.check_immutable_source_session(session)?;
                return self.stage_immutable_object_before_publish(
                    session, locator, context, plaintext, before,
                );
            }
            Err(BackendError::Unsupported) => {
                // Compatibility is an explicit capability result, not a
                // fabricated absence or a claimed durability receipt.
                before()?;
                self.check_immutable_source_session(session)?;
                return self.stage_immutable_object_before_publish(
                    session, locator, context, plaintext, before,
                );
            }
            Err(error) => return Err(map_backend_error(error)),
        };
        before()?;
        self.check_immutable_source_session(session)?;
        if pin.locator() != locator
            || pin.ciphertext_len() != exact_ciphertext_len
            || !pin.matches_profile(&session.profile)
            || !pin.has_synchronized_ciphertext()
        {
            return Err(ServiceError::CorruptState);
        }
        let actual =
            self.read_immutable_object_before_delivery(session, &pin, context, before)?;
        if actual.as_slice() != plaintext {
            return Err(ServiceError::RequestBindingConflict);
        }
        before()?;
        self.check_immutable_source_session(session)?;
        // The final local open and original caller gate may run arbitrary
        // code. A -> B -> A after the checked wire read must not return an old
        // synchronization receipt even though AEAD and plaintext still match.
        if !pin.matches_profile(&session.profile) || !pin.has_synchronized_ciphertext() {
            return Err(ServiceError::CorruptState);
        }
        Ok(pin)
    }
}

#[cfg(all(test, unix))]
#[path = "immutable_source_reuse_tests.rs"]
mod tests;
