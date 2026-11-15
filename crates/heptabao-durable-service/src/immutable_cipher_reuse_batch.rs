//! Existing-only physical re-admission with a shared directory barrier.
//! Every held file still receives its own strong File::sync_all. No new leaf,
//! replacement, provisional pin or initial-absence observation is published.
use super::*;

const MAX_REUSE_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_PARALLEL_EXISTING_FSYNC: usize = 4;

// Only held read-only descriptors enter workers. The original non-Send
// owner/gate and all mutable backend state stay on the caller thread.
fn parallel_existing_sync(
    files: &[&File],
    sync_one: &(impl Fn(&File) -> io::Result<()> + Sync),
) -> io::Result<Vec<io::Result<()>>> {
    if files.is_empty() || files.len() > MAX_PARALLEL_EXISTING_FSYNC {
        return Err(io::Error::other("invalid existing fsync worker count"));
    }
    std::thread::scope(|scope| {
        let mut jobs = Vec::with_capacity(files.len());
        let mut spawn_error = None;
        for file in files {
            match std::thread::Builder::new().spawn_scoped(scope, move || sync_one(file)) {
                Ok(job) => jobs.push(job),
                Err(error) => {
                    spawn_error = Some(error);
                    break;
                }
            }
        }
        // Join ALL started workers even after a failed spawn, failed fsync or
        // panic. No unfinished I/O may coexist with a returned pin, directory
        // barrier, cleanup, next chunk or caller return.
        let results = jobs
            .into_iter()
            .map(|job| {
                job.join()
                    .unwrap_or_else(|_| Err(io::Error::other("existing fsync worker panicked")))
            })
            .collect();
        match spawn_error {
            Some(error) => Err(error),
            None => Ok(results),
        }
    })
}

struct PendingReuse {
    pin: ImmutableBlobReadPin,
    witness: ObjectMetadataWitness,
    digest: [u8; 32],
}

impl FileBackend {
    /// Return Some only for the originally opened, authenticated and actually
    /// synchronized fd. None remains the first guarded open's ENOENT only.
    /// This does not call, generalize or fall back through new publication.
    pub fn reuse_immutable_ciphertext_batch_checked(
        &mut self,
        objects: &[(BlobLocator, usize)],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Vec<Option<ImmutableBlobReadPin>>, BackendError> {
        self.reuse_immutable_ciphertext_batch_with_sync_chunks(
            objects,
            gate,
            &mut |files| parallel_existing_sync(files, &File::sync_all),
            &mut |directory| directory.sync_all().map_err(io::Error::other),
        )
    }

    // The original per-file injection API exercises this same core. Only the
    // test callback is serial; production uses the bounded scoped join above.
    #[cfg(test)]
    fn reuse_immutable_ciphertext_batch_with_sync(
        &mut self,
        objects: &[(BlobLocator, usize)],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
        sync_file: &mut impl FnMut(&File) -> io::Result<()>,
        sync_directory: &mut impl FnMut(&ExclusiveDirectory) -> io::Result<()>,
    ) -> Result<Vec<Option<ImmutableBlobReadPin>>, BackendError> {
        self.reuse_immutable_ciphertext_batch_with_sync_chunks(
            objects,
            gate,
            &mut |files| Ok(files.iter().map(|file| sync_file(file)).collect()),
            sync_directory,
        )
    }

    fn reuse_immutable_ciphertext_batch_with_sync_chunks(
        &mut self,
        objects: &[(BlobLocator, usize)],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
        sync_files: &mut impl FnMut(&[&File]) -> io::Result<Vec<io::Result<()>>>,
        sync_directory: &mut impl FnMut(&ExclusiveDirectory) -> io::Result<()>,
    ) -> Result<Vec<Option<ImmutableBlobReadPin>>, BackendError> {
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
                if objects.is_empty() || objects.len() > MAX_IMMUTABLE_BATCH_OBJECTS {
                    return Err(BackendError::Capacity);
                }
                let mut unique = std::collections::BTreeSet::new();
                let mut total_bytes = 0usize;
                for (locator, exact_len) in objects {
                    length_check(*exact_len)?;
                    if !unique.insert((locator.store_id(), locator.address())) {
                        return Err(BackendError::Corrupt);
                    }
                    total_bytes = total_bytes
                        .checked_add(*exact_len)
                        .filter(|total| *total <= MAX_REUSE_BATCH_BYTES)
                        .ok_or(BackendError::Capacity)?;
                }
                let profile = self.immutable_blob_profile()?;
                let mut pending = Vec::with_capacity(objects.len());
                for objects_chunk in objects.chunks(MAX_PARALLEL_EXISTING_FSYNC) {
                    let start = pending.len();
                    for (locator, exact_len) in objects_chunk {
                        // The original single-object prefix, including both
                        // checks adjacent to the real file barrier, is retained.
                        checked_gate()?;
                        length_check(*exact_len)?;
                        if self.immutable_blob_profile()? != profile {
                            return Err(BackendError::Corrupt);
                        }
                        checked_gate()?;
                        let existing =
                            match self.directory.open_file(locator.leaf(), FileAccess::Read) {
                                Ok(file) => file,
                                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                                    checked_gate()?;
                                    if self.immutable_blob_profile()? != profile {
                                        return Err(BackendError::Corrupt);
                                    }
                                    checked_gate()?;
                                    pending.push(None);
                                    continue;
                                }
                                Err(_) => return Err(BackendError::Corrupt),
                            };
                        checked_gate()?;
                        let mutations = self
                            .directory
                            .watch_file_mutations(&existing)
                            .map_err(|_| BackendError::Corrupt)?;
                        let witness = object_metadata_witness(&existing, *exact_len)?;
                        self.check_reused_file_current(
                            *locator, &existing, witness, &profile, &mutations,
                        )?;
                        checked_gate()?;
                        // The digest is intentionally absent on this private pin
                        // until the shared directory barrier has also completed.
                        let pin = ImmutableBlobReadPin(Arc::new(PinnedObject {
                            file: existing,
                            locator: *locator,
                            identity: witness.identity,
                            directory_identity: profile.directory_identity,
                            lease: Arc::downgrade(&self.immutable_lease),
                            synchronized_ciphertext_digest: None,
                            synchronized_metadata: Some(witness),
                            reuse_mutation_witness: Some(mutations),
                            synchronized_publication_witness: None,
                        }));
                        let protected =
                            pin.read_ciphertext_checked(&mut checked_gate)
                                .map_err(|error| match error {
                                    PinReadError::Backend(error) | PinReadError::Gate(error) => {
                                        error
                                    }
                                })?;
                        let digest = crate::digest32(
                            b"heptabao.immutable-reuse-ciphertext.v1",
                            protected.as_slice(),
                        );
                        drop(protected);
                        checked_gate()?;
                        self.check_reused_file_current(
                            *locator,
                            &pin.0.file,
                            witness,
                            &profile,
                            pin.reuse_mutations()?,
                        )?;
                        checked_gate()?;
                        self.check_reused_file_current(
                            *locator,
                            &pin.0.file,
                            witness,
                            &profile,
                            pin.reuse_mutations()?,
                        )?;
                        pending.push(Some(PendingReuse {
                            pin,
                            witness,
                            digest,
                        }));
                    }
                    let chunk = &pending[start..];
                    if chunk.iter().any(Option::is_some) {
                        // Keep every original prefix and pre-sync gate, then add
                        // fresh owner-thread gates and callback-free checks of the
                        // ORIGINAL witnesses after later members' preparation.
                        for item in chunk.iter().flatten() {
                            checked_gate()?;
                            self.check_reused_file_current(
                                item.pin.locator(),
                                &item.pin.0.file,
                                item.witness,
                                &profile,
                                item.pin.reuse_mutations()?,
                            )
                            .map_err(|_| BackendError::OutcomeUnknown)?;
                        }
                        for item in chunk.iter().flatten() {
                            self.check_reused_file_current(
                                item.pin.locator(),
                                &item.pin.0.file,
                                item.witness,
                                &profile,
                                item.pin.reuse_mutations()?,
                            )
                            .map_err(|_| BackendError::OutcomeUnknown)?;
                        }
                        let files: Vec<_> = chunk
                            .iter()
                            .flatten()
                            .map(|item| &item.pin.0.file)
                            .collect();
                        let synced =
                            sync_files(&files).map_err(|_| BackendError::OutcomeUnknown)?;
                        if synced.len() != files.len() {
                            return Err(BackendError::OutcomeUnknown);
                        }
                        for (item, result) in chunk.iter().flatten().zip(synced) {
                            result.map_err(|_| BackendError::OutcomeUnknown)?;
                            checked_gate()?;
                            self.check_reused_file_current(
                                item.pin.locator(),
                                &item.pin.0.file,
                                item.witness,
                                &profile,
                                item.pin.reuse_mutations()?,
                            )
                            .map_err(|_| BackendError::OutcomeUnknown)?;
                            checked_gate()?;
                            self.check_reused_file_current(
                                item.pin.locator(),
                                &item.pin.0.file,
                                item.witness,
                                &profile,
                                item.pin.reuse_mutations()?,
                            )
                            .map_err(|_| BackendError::OutcomeUnknown)?;
                        }
                    }
                }

                if pending.iter().any(Option::is_some) {
                    // Later members' callbacks cannot silently change an
                    // earlier file before the common directory boundary.
                    checked_gate()?;
                    for item in pending.iter().flatten() {
                        self.check_reused_file_current(
                            item.pin.locator(),
                            &item.pin.0.file,
                            item.witness,
                            &profile,
                            item.pin.reuse_mutations()?,
                        )
                        .map_err(|_| BackendError::OutcomeUnknown)?;
                    }
                    sync_directory(&self.directory).map_err(|_| BackendError::OutcomeUnknown)?;
                }

                // Every original post-directory callback/check remains. The
                // same pre-file-sync witness is carried through this pass;
                // neither a final read nor a fresh fstat may replace it.
                for item in pending.iter().flatten() {
                    checked_gate()?;
                    self.check_reused_file_current(
                        item.pin.locator(),
                        &item.pin.0.file,
                        item.witness,
                        &profile,
                        item.pin.reuse_mutations()?,
                    )
                    .map_err(|_| BackendError::OutcomeUnknown)?;
                    checked_gate()?;
                    self.check_reused_file_current(
                        item.pin.locator(),
                        &item.pin.0.file,
                        item.witness,
                        &profile,
                        item.pin.reuse_mutations()?,
                    )
                    .map_err(|_| BackendError::OutcomeUnknown)?;
                }
                checked_gate()?;
                if self.immutable_blob_profile()? != profile {
                    return Err(BackendError::Corrupt);
                }
                // No callback after this whole-set check. This also covers
                // A -> B -> A of an early member by the final member's gate.
                for item in pending.iter().flatten() {
                    self.check_reused_file_current(
                        item.pin.locator(),
                        &item.pin.0.file,
                        item.witness,
                        &profile,
                        item.pin.reuse_mutations()?,
                    )
                    .map_err(|_| BackendError::OutcomeUnknown)?;
                }
                pending
                    .into_iter()
                    .map(|item| {
                        let Some(mut item) = item else {
                            return Ok(None);
                        };
                        Arc::get_mut(&mut item.pin.0)
                            .ok_or(BackendError::Corrupt)?
                            .synchronized_ciphertext_digest = Some(item.digest);
                        Ok(Some(item.pin))
                    })
                    .collect()
            })()
        };
        if !rejected_by_gate && matches!(&result, Err(BackendError::OutcomeUnknown)) {
            self.immutable_lease.revoke();
        }
        result
    }
}

#[cfg(all(test, unix))]
#[path = "immutable_cipher_reuse_batch_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "immutable_cipher_reuse_parallel_tests.rs"]
mod parallel_tests;
