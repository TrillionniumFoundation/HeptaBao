//! Re-admit an actual existing immutable ciphertext without a temporary write.
//! This is only a physical receipt. The caller must still authenticate the
//! same descriptor with its actual local barrier and compare fresh plaintext.
use super::*;

impl FileBackend {
    /// An existing leaf is neither a cache hit nor evidence of an earlier
    /// successful fsync. Sync its actual descriptor and the actual directory
    /// again, retaining the same owner lease and original caller gate.
    pub fn reuse_immutable_ciphertext_checked(
        &mut self,
        locator: BlobLocator,
        exact_len: usize,
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Option<ImmutableBlobReadPin>, BackendError> {
        self.reuse_immutable_ciphertext_with_sync(
            locator,
            exact_len,
            gate,
            &mut |file| file.sync_all(),
            &mut |directory| directory.sync_all().map_err(io::Error::other),
        )
    }

    // Keep the strong File::sync_all semantics used by ordinary existing-leaf
    // publication. In particular this must not substitute buffered/raw fsync
    // for the existing platform's final file/device and directory barriers.
    fn reuse_immutable_ciphertext_with_sync(
        &mut self,
        locator: BlobLocator,
        exact_len: usize,
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
        sync_file: &mut impl FnMut(&File) -> io::Result<()>,
        sync_directory: &mut impl FnMut(&ExclusiveDirectory) -> io::Result<()>,
    ) -> Result<Option<ImmutableBlobReadPin>, BackendError> {
        let mut rejected_by_gate = false;
        let result = {
            let mut checked_gate = || {
                let result = gate();
                if result.is_err() {
                    rejected_by_gate = true;
                }
                result
            };
            (|| {
                checked_gate()?;
                length_check(exact_len)?;
                let profile = self.immutable_blob_profile()?;
                checked_gate()?;
                let existing = match self.directory.open_file(locator.leaf(), FileAccess::Read) {
                    Ok(file) => file,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        // This is the only absence result. No descriptor has
                        // been admitted and no synchronization has been tried.
                        checked_gate()?;
                        if self.immutable_blob_profile()? != profile {
                            return Err(BackendError::Corrupt);
                        }
                        checked_gate()?;
                        return Ok(None);
                    }
                    Err(_) => return Err(BackendError::Corrupt),
                };
                checked_gate()?;
                let witness = object_metadata_witness(&existing, exact_len)?;
                let identity = witness.identity;
                self.check_reused_file_current(locator, &existing, witness, &profile)?;
                checked_gate()?;

                let mut pin = ImmutableBlobReadPin(Arc::new(PinnedObject {
                    file: existing,
                    locator,
                    identity,
                    directory_identity: profile.directory_identity,
                    lease: Arc::downgrade(&self.immutable_lease),
                    synchronized_ciphertext_digest: None,
                    synchronized_metadata: Some(witness),
                }));
                // Read the actual bounded descriptor before synchronization.
                // The final local AEAD read must read this descriptor again
                // and match this exact wire commitment, including its nonce.
                // Metadata equality alone cannot prove these bytes stayed put.
                let protected = pin
                    .read_ciphertext_checked(&mut checked_gate)
                    .map_err(|error| match error {
                        PinReadError::Backend(error) | PinReadError::Gate(error) => error,
                    })?;
                let synchronized_ciphertext_digest = crate::digest32(
                    b"heptabao.immutable-reuse-ciphertext.v1",
                    protected.as_slice(),
                );
                drop(protected);
                checked_gate()?;
                self.check_reused_file_current(locator, &pin.0.file, witness, &profile)?;
                checked_gate()?;
                self.check_reused_file_current(locator, &pin.0.file, witness, &profile)?;

                sync_file(&pin.0.file).map_err(|_| BackendError::OutcomeUnknown)?;
                checked_gate()?;
                self.check_reused_file_current(locator, &pin.0.file, witness, &profile)
                    .map_err(|_| BackendError::OutcomeUnknown)?;
                checked_gate()?;
                self.check_reused_file_current(locator, &pin.0.file, witness, &profile)
                    .map_err(|_| BackendError::OutcomeUnknown)?;

                sync_directory(&self.directory).map_err(|_| BackendError::OutcomeUnknown)?;
                checked_gate()?;
                self.check_reused_file_current(locator, &pin.0.file, witness, &profile)
                    .map_err(|_| BackendError::OutcomeUnknown)?;
                checked_gate()?;
                // Recheck after the final caller gate as well. A gate may
                // revoke custody or provoke a name change; neither can turn
                // the originally opened object into a freshly missing leaf.
                self.check_reused_file_current(locator, &pin.0.file, witness, &profile)
                    .map_err(|_| BackendError::OutcomeUnknown)?;
                Arc::get_mut(&mut pin.0)
                    .ok_or(BackendError::Corrupt)?
                    .synchronized_ciphertext_digest = Some(synchronized_ciphertext_digest);
                Ok(Some(pin))
            })()
        };
        if !rejected_by_gate && matches!(&result, Err(BackendError::OutcomeUnknown)) {
            // A real failed synchronization cannot leave a reusable receipt
            // under this owner. Cold recovery must establish a new lease.
            self.immutable_lease.revoke();
        }
        result
    }

    fn check_reused_file_current(
        &self,
        locator: BlobLocator,
        existing: &File,
        witness: ObjectMetadataWitness,
        profile: &ImmutableBlobProfile,
    ) -> Result<(), BackendError> {
        if self.immutable_blob_profile()? != *profile
            || object_metadata_witness(existing, witness.identity.length)? != witness
        {
            return Err(BackendError::Corrupt);
        }
        // This is a recheck of an already opened object. Even ENOENT is a
        // changed binding now, never the initial-absence optimization result.
        let named = self
            .directory
            .open_file(locator.leaf(), FileAccess::Read)
            .map_err(|_| BackendError::Corrupt)?;
        if object_metadata_witness(&named, witness.identity.length)? != witness
            || object_metadata_witness(existing, witness.identity.length)? != witness
        {
            return Err(BackendError::Corrupt);
        }
        self.verify()?;
        self.immutable_lease.check()
    }
}

#[cfg(all(test, unix))]
#[path = "immutable_cipher_reuse_tests.rs"]
mod tests;
