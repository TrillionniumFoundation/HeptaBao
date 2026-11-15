//! Bounded new-object publication under one actual durable source owner.
//! Existing leaves keep their original strong per-file reuse protocol and
//! share one bounded real directory barrier. No canonical
//! root, locator journal, cursor or delivery receipt is published here.
use super::*;
use heptabao_filesystem_guard::MAX_IMMUTABLE_BATCH_OBJECTS;
use std::collections::BTreeSet;

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    /// Stage at most thirty-two bounded objects with at most four MiB of actual
    /// ciphertext in total, including independently reused existing leaves.
    /// Each input is
    /// `(locator, exact_ciphertext_len, context, plaintext)` under this same
    /// actual source session. The exact length belongs to the concrete barrier
    /// owner, not to its generic sealed_len_bound estimate.
    ///
    /// Existing ciphertext is read, synced on its actual fd and directory,
    /// reopened with the local barrier and compared after bounded existing
    /// reuse. Only initially absent leaves enter the new-object batch. No pin
    /// escapes before its full durability barrier and all readbacks complete.
    /// The original backend trait dispatch reaches FileBackend's physical
    /// strict new-only batch through boxed production owners. Other backends
    /// must implement this synchronization proof explicitly; Unsupported has
    /// no ordinary per-object fallback and cannot mint a physical pin.
    /// An EEXIST race in that new batch fails closed; it is never accepted as a
    /// synchronized existing-leaf receipt or repaired by overwriting bytes.
    pub fn stage_immutable_objects_reusing_existing_before_publish(
        &mut self,
        session: &ImmutableSourceSession,
        objects: &[(BlobLocator, usize, &[u8], &[u8])],
        before: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<Vec<ImmutableBlobReadPin>, ServiceError> {
        before()?;
        self.check_immutable_source_session(session)?;
        if objects.is_empty() || objects.len() > MAX_IMMUTABLE_BATCH_OBJECTS {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let mut addresses = BTreeSet::new();
        let mut total_ciphertext_bytes = 0usize;
        for (locator, exact_len, context, plaintext) in objects {
            self.ensure_immutable_locator_not_retiring(*locator)?;
            if locator.store_id() != session.store_id
                || !addresses.insert((locator.store_id(), locator.address()))
                || context.is_empty()
                || context.len() > MAX_OBJECT_CONTEXT_BYTES
                || plaintext.is_empty()
                || plaintext.len() > session.profile.max_ciphertext_bytes
            {
                return Err(ServiceError::InvalidResource);
            }
            if *exact_len == 0 || *exact_len > session.profile.max_ciphertext_bytes {
                return Err(ServiceError::RequestCapacityExhausted);
            }
            total_ciphertext_bytes = total_ciphertext_bytes
                .checked_add(*exact_len)
                .filter(|total| *total <= ImmutableSourceSession::MAX_BATCH_CIPHERTEXT_BYTES)
                .ok_or(ServiceError::RequestCapacityExhausted)?;
        }

        let mut pins =
            self.reuse_existing_immutable_objects_before_publish(session, objects, before)?;
        let mut pending = Vec::with_capacity(objects.len());
        for (index, (_locator, exact_len, context, plaintext)) in objects.iter().enumerate() {
            if pins[index].is_some() {
                continue;
            }
            before()?;
            self.check_immutable_source_session(session)?;
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
            if protected.len() != *exact_len {
                return Err(ServiceError::RequestBindingConflict);
            }
            pending.push((index, protected));
        }

        if !pending.is_empty() {
            before()?;
            self.check_immutable_source_session(session)?;
            let ciphertext: Vec<_> = pending
                .iter()
                .map(|(index, bytes)| (objects[*index].0, bytes.as_slice()))
                .collect();
            let mut gate_error = None;
            let mut physical_gate = || match before() {
                Ok(()) => Ok(()),
                Err(error) => {
                    gate_error = Some(error);
                    Err(BackendError::Unavailable)
                }
            };
            // This retains the full original gate at each object, every write
            // syscall, each link and the final file/device+directory barrier.
            let staged = self
                .backend
                .stage_new_immutable_ciphertext_batch_checked(&ciphertext, &mut physical_gate);
            if matches!(
                staged,
                Err(BackendError::OutcomeUnknown | BackendError::StaleWriter)
            ) {
                self.unresolved = true;
            }
            if let Some(error) = gate_error {
                return Err(error);
            }
            let Some(staged) = staged.map_err(map_backend_error)? else {
                // The strict physical path classified a raced destination.
                // It returns no pins, including for any newly linked members.
                // Preserve the original explicit conflict without retrying or
                // passing an existing fd through a fresh-new sync boundary.
                return Err(ServiceError::RequestBindingConflict);
            };
            if staged.len() != pending.len() {
                return Err(ServiceError::CorruptState);
            }
            for ((index, _), pin) in pending.iter().zip(staged) {
                before()?;
                self.check_immutable_source_session(session)?;
                let (locator, exact_len, context, plaintext) = objects[*index];
                if pin.locator() != locator
                    || pin.ciphertext_len() != exact_len
                    || !pin.has_synchronized_ciphertext()
                    || !pin.matches_profile(&session.profile)
                {
                    return Err(ServiceError::CorruptState);
                }
                let observed =
                    self.read_immutable_object_before_delivery(session, &pin, context, before)?;
                if observed.as_slice() != plaintext {
                    return Err(ServiceError::RequestBindingConflict);
                }
                before()?;
                self.check_immutable_source_session(session)?;
                pins[*index] = Some(pin);
            }
        }
        before()?;
        self.check_immutable_source_session(session)?;
        let mut result = Vec::with_capacity(objects.len());
        for (pin, (locator, exact_len, _, _)) in pins.into_iter().zip(objects) {
            before()?;
            self.check_immutable_source_session(session)?;
            let pin = pin.ok_or(ServiceError::CorruptState)?;
            if pin.locator() != *locator
                || pin.ciphertext_len() != *exact_len
                || !pin.has_synchronized_ciphertext()
                || !pin.matches_profile(&session.profile)
            {
                return Err(ServiceError::CorruptState);
            }
            result.push(pin);
        }
        before()?;
        self.check_immutable_source_session(session)?;
        // No user callback may run after these actual-fd checks. A later
        // member's gate, including the terminal gate above, could have changed
        // an earlier leaf since its per-member check. Both cold-reuse and new
        // pins retain their original synchronization witness, so A -> B -> A
        // must fail here without reading or syncing the ciphertext again.
        for pin in &result {
            if !pin.has_synchronized_ciphertext() || !pin.matches_profile(&session.profile) {
                return Err(ServiceError::CorruptState);
            }
        }
        Ok(result)
    }

    /// Keep every member's original source gates and fresh local AEAD read.
    /// Only the physical directory barriers are coalesced. This method holds
    /// the exclusive Service borrow throughout; mutable filesystem ownership
    /// is rechecked by the physical operation and by each original source
    /// check. No result escapes this helper until all those checks complete.
    fn reuse_existing_immutable_objects_before_publish(
        &mut self,
        session: &ImmutableSourceSession,
        objects: &[(BlobLocator, usize, &[u8], &[u8])],
        before: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<Vec<Option<ImmutableBlobReadPin>>, ServiceError> {
        let mut physical = Vec::with_capacity(objects.len());
        for (locator, exact_len, _, _) in objects {
            // All syntax/length predicates were checked before this helper;
            // the original member's live entry gates still run individually.
            before()?;
            self.check_immutable_source_session(session)?;
            before()?;
            physical.push((*locator, *exact_len));
        }
        let mut gate_error = None;
        let mut physical_gate = || match before() {
            Ok(()) => Ok(()),
            Err(error) => {
                gate_error = Some(error);
                Err(BackendError::Unavailable)
            }
        };
        let reused = self
            .backend
            .reuse_immutable_ciphertext_batch_checked(&physical, &mut physical_gate);
        if matches!(
            reused,
            Err(BackendError::OutcomeUnknown | BackendError::StaleWriter)
        ) {
            self.unresolved = true;
        }
        if let Some(error) = gate_error {
            return Err(error);
        }
        let reused = match reused {
            Ok(reused) => reused,
            Err(BackendError::Unsupported) => {
                // Explicit old capability compatibility, never fabricated
                // absence or an ordinary fallback for strict-new publication.
                return objects
                    .iter()
                    .map(|(locator, length, context, plaintext)| {
                        self.reuse_existing_immutable_object_before_publish(
                            session, *locator, *length, context, plaintext, before,
                        )
                    })
                    .collect();
            }
            Err(error) => return Err(map_backend_error(error)),
        };
        if reused.len() != objects.len() {
            return Err(ServiceError::CorruptState);
        }
        let mut result = Vec::with_capacity(objects.len());
        for (pin, (locator, exact_len, context, plaintext)) in reused.into_iter().zip(objects) {
            let Some(pin) = pin else {
                before()?;
                self.check_immutable_source_session(session)?;
                result.push(None);
                continue;
            };
            before()?;
            self.check_immutable_source_session(session)?;
            if pin.locator() != *locator
                || pin.ciphertext_len() != *exact_len
                || !pin.matches_profile(&session.profile)
                || !pin.has_synchronized_ciphertext()
            {
                return Err(ServiceError::CorruptState);
            }
            let actual =
                self.read_immutable_object_before_delivery(session, &pin, context, before)?;
            if actual.as_slice() != *plaintext {
                return Err(ServiceError::RequestBindingConflict);
            }
            before()?;
            self.check_immutable_source_session(session)?;
            if !pin.matches_profile(&session.profile) || !pin.has_synchronized_ciphertext() {
                return Err(ServiceError::CorruptState);
            }
            result.push(Some(pin));
        }
        before()?;
        self.check_immutable_source_session(session)?;
        for pin in result.iter().flatten() {
            if !pin.matches_profile(&session.profile) || !pin.has_synchronized_ciphertext() {
                return Err(ServiceError::CorruptState);
            }
        }
        Ok(result)
    }
}
