//! Original caller gate at actual bounded write, fsync, link and directory
//! barriers. These remain LOCAL ciphertext receipts, never quorum authority.
use super::*;
use heptabao_filesystem_guard::ImmutablePublicationCheckedError;

#[cfg(unix)]
#[path = "v6_replica_blobs_existing.rs"]
mod existing;

impl LocalV6BlobStage {
    pub fn stage_local_checked(
        &self,
        ciphertext: &[u8],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<LocalV6BlobReceipt, LocalV6BlobError> {
        gate()?;
        let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.to_vec())
            .map_err(|_| LocalV6BlobError::InvalidCiphertext)?;
        let reference = object.reference().clone();
        let destination = Self::leaf(&reference)?;
        #[cfg(unix)]
        if let Some(receipt) = self.sync_existing_exact_checked(&reference, ciphertext, gate)? {
            return Ok(receipt);
        }
        let temporary = format!(
            ".v6-tmp-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        );
        gate()?;
        let mut opened = self
            .directory
            .open_file(&temporary, FileAccess::CreateNewReadWrite)?;
        for part in ciphertext.chunks(64 * 1024) {
            gate()?;
            opened.write_all(part)?;
            gate()?;
        }
        let published = self
            .directory
            .publish_file_noreplace_checked(
                &temporary,
                &opened,
                &destination,
                reference.payload_bytes,
                gate,
            )
            .map_err(|error| match error {
                ImmutablePublicationCheckedError::Publication(error) => {
                    LocalV6BlobError::Publication(error)
                }
                ImmutablePublicationCheckedError::GateBeforeLink(error)
                | ImmutablePublicationCheckedError::GateAfterLink(error) => error,
            })?;
        let mut file = match published {
            ImmutablePublication::Published(file) | ImmutablePublication::AlreadyExists(file) => {
                file
            }
        };
        gate()?;
        if Self::read_checked(&mut file, &reference)?.as_slice() != ciphertext {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        gate()?;
        Ok(LocalV6BlobReceipt { reference })
    }

    pub fn stage_received_replica_checked(
        &self,
        expected: &RecordObjectRef,
        ciphertext: &[u8],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<LocalV6BlobReceipt, LocalV6BlobError> {
        gate()?;
        Self::leaf(expected)?;
        if u64::try_from(ciphertext.len()).ok() != Some(expected.payload_bytes) {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        let checked = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.to_vec())
            .map_err(|_| LocalV6BlobError::InvalidCiphertext)?;
        if checked.reference() != expected {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        gate()?;
        self.stage_local_checked(ciphertext, gate)
    }
}

#[cfg(all(test, unix))]
#[path = "v6_replica_blobs_checked_tests.rs"]
mod tests;
