//! Bounded physical publication for privately prepared shared-key ciphertext.
//! Every receipt is LOCAL only. The wire protocol, quorum, and root authority
//! remain unchanged. Existing leaves retain independent strong real-fd sync
//! and share one bounded directory barrier before any receipt is returned.
use super::*;

impl LocalV6BlobStage {
    pub const MAX_CHECKED_BATCH_OBJECTS: usize =
        heptabao_filesystem_guard::MAX_IMMUTABLE_BATCH_OBJECTS;
    pub const MAX_CHECKED_BATCH_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;

    /// Re-admit only existing exact replicas. Every reference is checked
    /// against the real supplied ciphertext before physical I/O. If any leaf
    /// is absent or changes, no member receipt escapes and no leaf is created.
    /// This grants local custody only, never a quorum or application receipt.
    pub fn sync_existing_replicas_batch_checked(
        &self,
        objects: &[(&RecordObjectRef, &[u8])],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<Vec<LocalV6BlobReceipt>, LocalV6BlobError> {
        let _operation = self.begin_native_operation()?;
        gate()?;
        if objects.is_empty() || objects.len() > Self::MAX_CHECKED_BATCH_OBJECTS {
            return Err(LocalV6BlobError::InvalidClosure);
        }
        let mut bytes = 0usize;
        let mut references = Vec::with_capacity(objects.len());
        let mut ciphertexts = Vec::with_capacity(objects.len());
        let mut unique = std::collections::BTreeSet::new();
        for (expected, ciphertext) in objects {
            gate()?;
            Self::leaf(expected)?;
            if !(25..=256 * 1024).contains(&ciphertext.len())
                || u64::try_from(ciphertext.len()).ok() != Some(expected.payload_bytes)
                || !unique.insert(expected.id)
            {
                return Err(LocalV6BlobError::CorruptOrChanged);
            }
            bytes = bytes
                .checked_add(ciphertext.len())
                .filter(|total| *total <= Self::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES)
                .ok_or(LocalV6BlobError::InvalidClosure)?;
            let checked = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.to_vec())
                .map_err(|_| LocalV6BlobError::InvalidCiphertext)?;
            if checked.reference() != *expected {
                return Err(LocalV6BlobError::CorruptOrChanged);
            }
            gate()?;
            // Keep the original stage_local_checked entry gate as well as
            // both stage_received_replica_checked reference-binding gates.
            gate()?;
            references.push((**expected).clone());
            ciphertexts.push(*ciphertext);
        }
        #[cfg(not(unix))]
        {
            let _ = (references, ciphertexts);
            Err(LocalV6BlobError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "checked existing V6 batch requires guarded Unix descriptors",
            )))
        }
        #[cfg(unix)]
        {
            self.hold_existing_exact_batch_checked(&references, &ciphertexts, gate)?
                .into_iter()
                .map(|item| {
                    Ok(item
                        .ok_or(LocalV6BlobError::CorruptOrChanged)?
                        .into_receipt())
                })
                .collect()
        }
    }

    /// Publish at most 32 exact ciphertext chunks and at most 4 MiB together.
    /// No local receipt escapes until the complete physical batch has crossed
    /// the original gates, real file/device and directory barriers, readback,
    /// and a final callback-free check of every held descriptor and leaf name.
    /// A failure may leave orphan leaves and never permits an automatic retry.
    pub fn stage_local_batch_checked(
        &self,
        ciphertexts: &[&[u8]],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<Vec<LocalV6BlobReceipt>, LocalV6BlobError> {
        let _operation = self.begin_native_operation()?;
        gate()?;
        if ciphertexts.is_empty() || ciphertexts.len() > Self::MAX_CHECKED_BATCH_OBJECTS {
            return Err(LocalV6BlobError::InvalidClosure);
        }
        let mut total_bytes = 0usize;
        let mut references = Vec::with_capacity(ciphertexts.len());
        let mut unique = std::collections::BTreeSet::new();
        for ciphertext in ciphertexts {
            gate()?;
            if !(25..=256 * 1024).contains(&ciphertext.len()) {
                return Err(LocalV6BlobError::InvalidCiphertext);
            }
            total_bytes = total_bytes
                .checked_add(ciphertext.len())
                .filter(|total| *total <= Self::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES)
                .ok_or(LocalV6BlobError::InvalidClosure)?;
            let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.to_vec())
                .map_err(|_| LocalV6BlobError::InvalidCiphertext)?;
            let reference = object.reference().clone();
            Self::leaf(&reference)?;
            if !unique.insert(reference.id) {
                return Err(LocalV6BlobError::InvalidClosure);
            }
            references.push(reference);
        }
        gate()?;
        #[cfg(not(unix))]
        {
            let _ = references;
            Err(LocalV6BlobError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "checked V6 physical batch requires guarded Unix publication",
            )))
        }
        #[cfg(unix)]
        {
            use super::existing::HeldSynchronizedCiphertext;
            use heptabao_filesystem_guard::ImmutableBatchEntry;
            struct Temporary {
                index: usize,
                name: String,
                destination: String,
                file: File,
            }
            let mut held: Vec<Option<HeldSynchronizedCiphertext>> =
                self.hold_existing_exact_batch_checked(&references, ciphertexts, gate)?;
            let mut temporary = Vec::with_capacity(ciphertexts.len());
            for (index, (reference, ciphertext)) in references.iter().zip(ciphertexts).enumerate() {
                gate()?;
                if held[index].is_some() {
                    continue;
                }
                let name = format!(
                    ".v6-tmp-{}-{}",
                    std::process::id(),
                    NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed),
                );
                gate()?;
                let mut file = self
                    .directory
                    .open_file(&name, FileAccess::CreateNewReadWrite)?;
                gate()?;
                for part in ciphertext.chunks(64 * 1024) {
                    gate()?;
                    file.write_all(part)?;
                    gate()?;
                }
                temporary.push(Temporary {
                    index,
                    name,
                    destination: Self::leaf(reference)?,
                    file,
                });
            }
            if !temporary.is_empty() {
                let entries: Vec<_> = temporary
                    .iter()
                    .map(|item| ImmutableBatchEntry {
                        temporary: &item.name,
                        file: &item.file,
                        destination: &item.destination,
                        exact_len: references[item.index].payload_bytes,
                    })
                    .collect();
                let published = self
                    .directory
                    .publish_new_files_noreplace_with_witness_checked(&entries, gate)
                    .map_err(|error| match error {
                        ImmutablePublicationCheckedError::Publication(error) => {
                            LocalV6BlobError::Publication(error)
                        }
                        ImmutablePublicationCheckedError::GateBeforeLink(error)
                        | ImmutablePublicationCheckedError::GateAfterLink(error) => error,
                    })?
                    .ok_or_else(|| {
                        LocalV6BlobError::Publication(ImmutablePublicationError::OutcomeUnknown(
                            io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                "V6 batch leaf appeared after the initial absent observation",
                            ),
                        ))
                    })?;
                if published.len() != temporary.len() {
                    return Err(LocalV6BlobError::CorruptOrChanged);
                }
                // A raced EEXIST was not synchronized through the existing
                // descriptor path. Equal bytes cannot turn it into a receipt.
                // No output (including earlier successful new members) escapes.
                for (item, publication) in temporary.iter().zip(published) {
                    held[item.index] = Some(HeldSynchronizedCiphertext::published(
                        &references[item.index],
                        publication,
                    )?);
                }
                // The strict physical helper captured every new fd BEFORE
                // its post-link fsync and checked that entire witness set
                // after its last callback. The owned original witness travels
                // with the descriptor; no later fstat can rebase it. Existing
                // witnesses retain their independently synchronized fd.
                for item in &temporary {
                    gate()?;
                    held[item.index]
                        .as_mut()
                        .ok_or(LocalV6BlobError::CorruptOrChanged)?
                        .authenticate(ciphertexts[item.index], gate)?;
                    gate()?;
                }
            }
            gate()?;
            self.directory.verify()?;
            // Last gate above, then no callbacks: a later member's read or
            // final gate cannot hide A->B->A on an earlier synchronized file.
            for member in &held {
                member
                    .as_ref()
                    .ok_or(LocalV6BlobError::CorruptOrChanged)?
                    .check_without_callback(self)?;
            }
            held.into_iter()
                .map(|member| {
                    Ok(member
                        .ok_or(LocalV6BlobError::CorruptOrChanged)?
                        .into_receipt())
                })
                .collect()
        }
    }
}

#[cfg(all(test, unix))]
#[path = "v6_replica_blobs_batch_tests.rs"]
mod tests;
