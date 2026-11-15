//! New-only physical batch pins retain the original synchronization witness.
//! Ordinary batch and independently synchronized existing-leaf reuse keep
//! their original entry points and behavior; neither is a fallback here.
use super::*;
use heptabao_filesystem_guard::SynchronizedImmutablePublication;
use std::collections::BTreeSet;

const MAX_NEW_BATCH_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;

impl FileBackend {
    /// Publish at most 32 new objects / 4 MiB of actual ciphertext. Each new
    /// descriptor crosses the strict real per-file, device and directory
    /// barriers and keeps that SAME original identity through every read and
    /// caller gate. No canonical locator, root or application receipt is written.
    /// None means only a classified raced destination, without any returned
    /// pins. It does not imply absence of unadmitted newly linked objects.
    pub fn stage_new_immutable_ciphertext_batch_checked(
        &mut self,
        objects: &[(BlobLocator, &[u8])],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Option<Vec<ImmutableBlobReadPin>>, BackendError> {
        let cleanup_needed = !self.immutable_batch_temps_known_clean;
        self.immutable_batch_temps_known_clean = false;
        let gate_rejected = Cell::new(false);
        let result = {
            let mut checked_gate = || {
                let result = gate();
                if result.is_err() {
                    gate_rejected.set(true);
                }
                result
            };
            (|| {
                checked_gate()?;
                if objects.is_empty() || objects.len() > MAX_IMMUTABLE_BATCH_OBJECTS {
                    return Err(BackendError::Capacity);
                }
                let mut addresses = BTreeSet::new();
                let mut total = 0usize;
                for (locator, bytes) in objects {
                    length_check(bytes.len())?;
                    if !addresses.insert((locator.store_id(), locator.address())) {
                        return Err(BackendError::Corrupt);
                    }
                    total = total
                        .checked_add(bytes.len())
                        .filter(|total| *total <= MAX_NEW_BATCH_CIPHERTEXT_BYTES)
                        .ok_or(BackendError::Capacity)?;
                }
                let profile = self.immutable_blob_profile()?;
                if cleanup_needed {
                    cleanup_temporary(&self.directory)?;
                }
                let mut files = Vec::with_capacity(objects.len());
                let mut destinations = Vec::with_capacity(objects.len());
                for (index, (locator, bytes)) in objects.iter().enumerate() {
                    checked_gate()?;
                    let mut file = self
                        .directory
                        .open_file(BATCH_TEMPORARIES[index], FileAccess::CreateNewReadWrite)
                        .map_err(|_| BackendError::Io)?;
                    let mut offset = 0;
                    let mut interrupts = 0;
                    while offset < bytes.len() {
                        checked_gate()?;
                        let written = file.write(&bytes[offset..]);
                        checked_gate()?;
                        match written {
                            Ok(n) if n > 0 && n <= bytes.len() - offset => {
                                offset += n;
                                interrupts = 0;
                            }
                            Err(error)
                                if error.kind() == io::ErrorKind::Interrupted
                                    && interrupts < 64 =>
                            {
                                interrupts += 1;
                            }
                            _ => return Err(BackendError::Io),
                        }
                    }
                    checked_gate()?;
                    files.push(file);
                    destinations.push(locator.leaf());
                }
                let entries: Vec<_> = files
                    .iter()
                    .enumerate()
                    .map(|(index, file)| ImmutableBatchEntry {
                        temporary: BATCH_TEMPORARIES[index],
                        file,
                        destination: &destinations[index],
                        exact_len: objects[index].1.len() as u64,
                    })
                    .collect();
                let published = self
                    .directory
                    .publish_new_files_noreplace_with_witness_checked(&entries, &mut checked_gate)
                    .map_err(|error| match error {
                        ImmutablePublicationCheckedError::Publication(error) => {
                            publication_error(error)
                        }
                        ImmutablePublicationCheckedError::GateBeforeLink(error)
                        | ImmutablePublicationCheckedError::GateAfterLink(error) => error,
                    })?;
                let Some(published) = published else {
                    // Only the physical helper's private typed collision
                    // marker can reach this branch. No existing fd was synced
                    // as new, and no pin from any member escapes the batch.
                    return Ok(None);
                };
                if published.len() != objects.len() {
                    return Err(BackendError::OutcomeUnknown);
                }
                let mut pins = Vec::with_capacity(objects.len());
                // Transfer every ORIGINAL lower-layer witness and descriptor
                // before any new user callback. Even an intervening external
                // A->B->A cannot be relabelled by the local metadata sample.
                for (publication, (locator, bytes)) in published.into_iter().zip(objects) {
                    pins.push(
                        self.pin_synchronized_new_file(*locator, publication, bytes, &profile)
                            .map_err(|_| BackendError::OutcomeUnknown)?,
                    );
                }
                for (pin, (_, bytes)) in pins.iter().zip(objects) {
                    checked_gate()?;
                    let observed = pin.read_ciphertext_checked(&mut checked_gate).map_err(
                        |error| match error {
                            PinReadError::Backend(_) => BackendError::OutcomeUnknown,
                            PinReadError::Gate(error) => error,
                        },
                    )?;
                    if observed.as_slice() != *bytes {
                        return Err(BackendError::OutcomeUnknown);
                    }
                    self.check_synchronized_new_pin_current(pin, &profile)
                        .map_err(|_| BackendError::OutcomeUnknown)?;
                }
                checked_gate()?;
                // No callback follows this WHOLE collection recheck. A later
                // member or terminal gate cannot leave an earlier stale pin.
                for pin in &pins {
                    self.check_synchronized_new_pin_current(pin, &profile)
                        .map_err(|_| BackendError::OutcomeUnknown)?;
                }
                Ok(Some(pins))
            })()
        };
        if result.is_ok() {
            // Both all-new success and the explicit collision classification
            // consumed every temporary. None still returns no durability pin.
            self.immutable_batch_temps_known_clean = true;
        }
        if !gate_rejected.get() && matches!(&result, Err(BackendError::OutcomeUnknown)) {
            self.immutable_lease.revoke();
        }
        result
    }

    fn pin_synchronized_new_file(
        &self,
        locator: BlobLocator,
        publication: SynchronizedImmutablePublication,
        ciphertext: &[u8],
        profile: &ImmutableBlobProfile,
    ) -> Result<ImmutableBlobReadPin, BackendError> {
        length_check(ciphertext.len())?;
        let (file, original_sync_witness) = publication.into_parts();
        original_sync_witness
            .verify_file(&file)
            .map_err(|_| BackendError::Corrupt)?;
        let metadata = object_metadata_witness(&file, ciphertext.len())?;
        let pin = ImmutableBlobReadPin(Arc::new(PinnedObject {
            file,
            locator,
            identity: metadata.identity,
            directory_identity: profile.directory_identity,
            lease: Arc::downgrade(&self.immutable_lease),
            synchronized_ciphertext_digest: Some(crate::digest32(
                b"heptabao.immutable-reuse-ciphertext.v1",
                ciphertext,
            )),
            synchronized_metadata: Some(metadata),
            reuse_mutation_witness: None,
            synchronized_publication_witness: Some(original_sync_witness),
        }));
        self.check_synchronized_new_pin_current(&pin, profile)?;
        Ok(pin)
    }

    fn check_synchronized_new_pin_current(
        &self,
        pin: &ImmutableBlobReadPin,
        profile: &ImmutableBlobProfile,
    ) -> Result<(), BackendError> {
        if self.immutable_blob_profile()? != *profile
            || !pin.has_synchronized_ciphertext()
            || !pin.matches_profile(profile)
        {
            return Err(BackendError::Corrupt);
        }
        let witness = pin
            .0
            .synchronized_publication_witness
            .as_ref()
            .ok_or(BackendError::Corrupt)?;
        let named = self
            .directory
            .open_file(pin.locator().leaf(), FileAccess::Read)
            .map_err(|_| BackendError::Corrupt)?;
        witness
            .verify_file(&named)
            .map_err(|_| BackendError::Corrupt)?;
        pin.check()?;
        self.verify()?;
        self.immutable_lease.check()
    }
}

#[cfg(all(test, unix))]
#[path = "immutable_cipher_new_batch_tests.rs"]
mod tests;
