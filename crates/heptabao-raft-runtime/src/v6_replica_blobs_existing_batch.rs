//! Existing-only bounded synchronization. The captured pre-sync descriptor,
//! exact ciphertext and full metadata are never replaced by a later sample.
use super::*;

// This changes only scheduling within the existing 32-object/four-MiB unit.
// Every retained descriptor still crosses its own strong File::sync_all.
const MAX_PARALLEL_EXISTING_FSYNC: usize = 4;

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
        // Neither a failed spawn, a failed fsync nor a panic permits an
        // unfinished worker to outlive these borrowed descriptors or escape
        // into the directory barrier, cleanup, next chunk or caller return.
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

struct PendingExistingCiphertext {
    reference: RecordObjectRef,
    destination: String,
    file: File,
    identity: ExistingIdentity,
    mutations: heptabao_filesystem_guard::FileMutationWitness,
}

impl PendingExistingCiphertext {
    fn check_without_callback(&self, store: &LocalV6BlobStage) -> Result<(), LocalV6BlobError> {
        self.mutations
            .verify_file(&self.file)
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        store.directory.verify()?;
        let current = store
            .directory
            .open_file(&self.destination, FileAccess::Read)?;
        if ExistingIdentity::read(&self.file, &self.reference)? != self.identity
            || ExistingIdentity::read(&current, &self.reference)? != self.identity
        {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        store.directory.verify()?;
        self.mutations
            .verify_file(&self.file)
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        Ok(())
    }
}

impl LocalV6BlobStage {
    pub(in super::super) fn hold_existing_exact_batch_checked(
        &self,
        references: &[RecordObjectRef],
        ciphertexts: &[&[u8]],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<Vec<Option<HeldSynchronizedCiphertext>>, LocalV6BlobError> {
        self.hold_existing_exact_batch_with_sync_chunks(
            references,
            ciphertexts,
            gate,
            &mut |files| {
                Ok(parallel_existing_sync(files, &File::sync_all)?
                    .into_iter()
                    .map(|result| result.map_err(Into::into))
                    .collect())
            },
            &mut |directory| directory.sync_all().map_err(Into::into),
        )
    }

    // Preserve the original per-file fault-injection interface. It drives the
    // SAME chunk/gate/identity core, with serial injected I/O only in tests.
    #[cfg(test)]
    fn hold_existing_exact_batch_with_sync(
        &self,
        references: &[RecordObjectRef],
        ciphertexts: &[&[u8]],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
        sync_file: &mut impl FnMut(&File) -> Result<(), LocalV6BlobError>,
        sync_directory: &mut impl FnMut(&ExclusiveDirectory) -> Result<(), LocalV6BlobError>,
    ) -> Result<Vec<Option<HeldSynchronizedCiphertext>>, LocalV6BlobError> {
        self.hold_existing_exact_batch_with_sync_chunks(
            references,
            ciphertexts,
            gate,
            &mut |files| Ok(files.iter().map(|file| sync_file(file)).collect()),
            sync_directory,
        )
    }

    fn hold_existing_exact_batch_with_sync_chunks(
        &self,
        references: &[RecordObjectRef],
        ciphertexts: &[&[u8]],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
        sync_files: &mut impl FnMut(
            &[&File],
        )
            -> Result<Vec<Result<(), LocalV6BlobError>>, LocalV6BlobError>,
        sync_directory: &mut impl FnMut(&ExclusiveDirectory) -> Result<(), LocalV6BlobError>,
    ) -> Result<Vec<Option<HeldSynchronizedCiphertext>>, LocalV6BlobError> {
        gate()?;
        if references.is_empty()
            || references.len() != ciphertexts.len()
            || references.len() > Self::MAX_CHECKED_BATCH_OBJECTS
        {
            return Err(LocalV6BlobError::InvalidClosure);
        }
        let mut unique = std::collections::BTreeSet::new();
        let mut total = 0usize;
        for (reference, ciphertext) in references.iter().zip(ciphertexts) {
            Self::leaf(reference)?;
            if !(25..=256 * 1024).contains(&ciphertext.len())
                || u64::try_from(ciphertext.len()).ok() != Some(reference.payload_bytes)
                || !unique.insert(reference.id)
            {
                return Err(LocalV6BlobError::InvalidClosure);
            }
            total = total
                .checked_add(ciphertext.len())
                .filter(|total| *total <= Self::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES)
                .ok_or(LocalV6BlobError::InvalidClosure)?;
        }
        let mut pending = Vec::with_capacity(references.len());
        for (reference_chunk, ciphertext_chunk) in references
            .chunks(MAX_PARALLEL_EXISTING_FSYNC)
            .zip(ciphertexts.chunks(MAX_PARALLEL_EXISTING_FSYNC))
        {
            let start = pending.len();
            for (reference, ciphertext) in reference_chunk.iter().zip(ciphertext_chunk) {
                // This is the original existing-leaf prefix. Every gate around
                // the actual read and strong per-file sync remains in place.
                gate()?;
                let destination = Self::leaf(reference)?;
                gate()?;
                let opened = self.directory.open_file(&destination, FileAccess::Read);
                gate()?;
                let mut file = match opened {
                    Ok(file) => file,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        self.directory.verify()?;
                        gate()?;
                        pending.push(None);
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let mutations = self.directory.watch_file_mutations(&file)?;
                let identity = ExistingIdentity::read(&file, reference);
                gate()?;
                let identity = identity?;
                self.verify_existing_binding(
                    &file,
                    reference,
                    &destination,
                    identity,
                    gate,
                    &mutations,
                )?;
                read_exact_existing(&mut file, reference, ciphertext, gate)?;
                self.verify_existing_binding(
                    &file,
                    reference,
                    &destination,
                    identity,
                    gate,
                    &mutations,
                )?;
                gate()?;
                pending.push(Some(PendingExistingCiphertext {
                    reference: reference.clone(),
                    destination,
                    file,
                    identity,
                    mutations,
                }));
            }
            let chunk = &pending[start..];
            if chunk.iter().any(Option::is_some) {
                // Each original prefix and pre-sync gate above is retained. Add
                // fresh owner-thread gates and verify every ORIGINAL witness after
                // the later members' callbacks, before dispatching any fsync.
                for item in chunk.iter().flatten() {
                    gate()?;
                    item.check_without_callback(self)?;
                }
                for item in chunk.iter().flatten() {
                    item.check_without_callback(self)?;
                }
                let files: Vec<_> = chunk.iter().flatten().map(|item| &item.file).collect();
                let synced = sync_files(&files);
                // Worker/spawn failure still crosses an original post-sync gate.
                let synced = match synced {
                    Ok(results) => results,
                    Err(error) => {
                        gate()?;
                        return Err(error);
                    }
                };
                if synced.len() != files.len() {
                    return Err(LocalV6BlobError::CorruptOrChanged);
                }
                for (item, result) in chunk.iter().flatten().zip(synced) {
                    gate()?;
                    result?;
                    self.verify_existing_binding(
                        &item.file,
                        &item.reference,
                        &item.destination,
                        item.identity,
                        gate,
                        &item.mutations,
                    )?;
                }
            }
        }
        if pending.iter().any(Option::is_some) {
            for item in pending.iter().flatten() {
                // Retain each original pre-directory gate, then check the
                // earlier held fd against mutations by later members' gates.
                gate()?;
                item.check_without_callback(self)?;
            }
            // No callback between this complete set check and the one actual
            // directory barrier. Every file above already crossed its own
            // original strong sync_all; this does not use raw/buffered fsync.
            for item in pending.iter().flatten() {
                item.check_without_callback(self)?;
            }
            let synced = sync_directory(&self.directory);
            gate()?;
            synced?;
        }
        let mut held = Vec::with_capacity(pending.len());
        for (item, ciphertext) in pending.into_iter().zip(ciphertexts) {
            let Some(mut item) = item else {
                held.push(None);
                continue;
            };
            // The original post-directory gate, original full readback and
            // original binding checks are retained for every actual member.
            gate()?;
            self.verify_existing_binding(
                &item.file,
                &item.reference,
                &item.destination,
                item.identity,
                gate,
                &item.mutations,
            )?;
            read_exact_existing(&mut item.file, &item.reference, ciphertext, gate)?;
            self.verify_existing_binding(
                &item.file,
                &item.reference,
                &item.destination,
                item.identity,
                gate,
                &item.mutations,
            )?;
            held.push(Some(HeldSynchronizedCiphertext {
                reference: item.reference,
                destination: item.destination,
                file: item.file,
                identity: item.identity,
                reuse_mutation_witness: Some(item.mutations),
                original_new_sync_witness: None,
            }));
        }
        gate()?;
        self.directory.verify()?;
        // This terminal pass runs no arbitrary caller code. A later member
        // or the final gate cannot rebase an earlier member's sync witness.
        for item in held.iter().flatten() {
            item.check_without_callback(self)?;
        }
        Ok(held)
    }
}

#[cfg(test)]
#[path = "v6_replica_blobs_existing_batch_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "v6_replica_blobs_existing_parallel_tests.rs"]
mod parallel_tests;
