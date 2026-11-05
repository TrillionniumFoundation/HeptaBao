//! A fresh descriptor admission for one explicit reconciliation request.
//! Old serialized intent metadata never reconstructs a physical deletion ticket.
use super::*;

pub struct PreparedImmutableReconciliation {
    owner: Weak<()>,
    all: Vec<BlobLocator>,
    present_indices: Vec<usize>,
    present: Option<PreparedImmutableRetirement>,
    present_mask: u32,
    descriptor_digest: [u8; 32],
}
impl fmt::Debug for PreparedImmutableReconciliation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedImmutableReconciliation")
            .field("selected_objects", &self.all.len())
            .field("present_objects", &self.present_indices.len())
            .finish_non_exhaustive()
    }
}
impl PreparedImmutableReconciliation {
    pub fn present_mask(&self) -> u32 {
        self.present_mask
    }
    pub fn descriptor_digest(&self) -> [u8; 32] {
        self.descriptor_digest
    }
}

#[cfg(unix)]
fn append_descriptor(material: &mut Vec<u8>, file: &File) -> Result<(), BackendError> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata().map_err(|_| BackendError::Io)?;
    // The original ticket independently verifies all of these facts and its
    // live kernel mutation witness. This commitment is evidence, not a ticket.
    for n in [m.dev(), m.ino(), m.len(), m.nlink()] {
        material.extend_from_slice(&n.to_be_bytes());
    }
    for n in [m.uid(), m.gid(), m.mode()] {
        material.extend_from_slice(&n.to_be_bytes());
    }
    for n in [m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()] {
        material.extend_from_slice(&n.to_be_bytes());
    }
    Ok(())
}
#[cfg(not(unix))]
fn append_descriptor(_: &mut Vec<u8>, _: &File) -> Result<(), BackendError> {
    Err(BackendError::Unsupported)
}

impl FileBackend {
    pub fn prepare_immutable_reconciliation(
        &mut self,
        objects: &[(BlobLocator, usize, [u8; 32])],
        authenticate: crate::ImmutableCiphertextAuthenticator<'_>,
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<PreparedImmutableReconciliation, BackendError> {
        gate()?;
        self.retirement_quiescent()?;
        if objects.is_empty() || objects.len() > MAX_IMMUTABLE_RETIREMENT_FILES {
            return Err(BackendError::Capacity);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut all = Vec::with_capacity(objects.len());
        let mut entries = Vec::new();
        let mut present_indices = Vec::new();
        let mut present_mask = 0_u32;
        let mut material = Vec::new();
        for (index, &(locator, length, expected)) in objects.iter().enumerate() {
            gate()?;
            length_check(length)?;
            if !seen.insert((locator.store_id(), locator.address())) {
                return Err(BackendError::Corrupt);
            }
            all.push(locator);
            material.extend_from_slice(&(index as u32).to_be_bytes());
            material.extend_from_slice(&locator.store_id());
            material.extend_from_slice(&locator.address());
            material.extend_from_slice(&(length as u64).to_be_bytes());
            material.extend_from_slice(&expected);
            if !self
                .directory
                .entry_exists(locator.leaf())
                .map_err(|_| BackendError::Io)?
            {
                material.push(0);
                continue;
            }
            let file = self
                .directory
                .prepare_file_retirement(locator.leaf(), length)
                .map_err(|_| BackendError::Corrupt)?;
            let bytes = read(file.file(), length, gate)?;
            self.directory
                .verify_file_retirement(&file)
                .map_err(|_| BackendError::Corrupt)?;
            if digest(&bytes) != expected {
                return Err(BackendError::Corrupt);
            }
            gate()?;
            authenticate(index, &bytes)?;
            gate()?;
            material.push(1);
            append_descriptor(&mut material, file.file())?;
            self.directory
                .verify_file_retirement(&file)
                .map_err(|_| BackendError::Corrupt)?;
            present_mask |= 1_u32 << index;
            present_indices.push(index);
            entries.push(Entry {
                locator,
                length,
                file,
                ciphertext_digest: expected,
            });
        }
        // No absent member may silently reappear during this preparation.
        for (index, locator) in all.iter().enumerate() {
            gate()?;
            if present_mask & (1_u32 << index) == 0
                && self
                    .directory
                    .entry_exists(locator.leaf())
                    .map_err(|_| BackendError::Io)?
            {
                return Err(BackendError::Corrupt);
            }
        }
        for entry in &entries {
            self.directory
                .verify_file_retirement(&entry.file)
                .map_err(|_| BackendError::Corrupt)?;
            gate()?;
        }
        self.retirement_quiescent()?;
        gate()?;
        let present = if entries.is_empty() {
            None
        } else {
            Some(PreparedImmutableRetirement {
                owner: Arc::downgrade(&self.retirement_instance),
                entries,
            })
        };
        Ok(PreparedImmutableReconciliation {
            owner: Arc::downgrade(&self.retirement_instance),
            all,
            present_indices,
            present,
            present_mask,
            descriptor_digest: crate::digest32(
                b"heptabao.immutable-fresh-reconciliation-descriptors.v1",
                &material,
            ),
        })
    }

    /// The caller must have committed THIS fresh reconciliation intent. The
    /// old intent or an observed file name never authorizes this invocation.
    pub fn finish_prepared_immutable_reconciliation(
        &mut self,
        prepared: PreparedImmutableReconciliation,
        authenticate: crate::ImmutableCiphertextAuthenticator<'_>,
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        gate()?;
        let owner = prepared.owner.upgrade().ok_or(BackendError::Unavailable)?;
        if !Arc::ptr_eq(&owner, &self.retirement_instance) {
            return Err(BackendError::Unavailable);
        }
        drop(owner);
        self.retirement_quiescent()?;
        if prepared.all.is_empty()
            || prepared.all.len() > MAX_IMMUTABLE_RETIREMENT_FILES
            || prepared.present_indices.len() != prepared.present_mask.count_ones() as usize
            || prepared.present.is_none() != prepared.present_indices.is_empty()
        {
            return Err(BackendError::Corrupt);
        }
        for (index, locator) in prepared.all.iter().enumerate() {
            gate()?;
            if prepared.present_mask & (1_u32 << index) == 0
                && self
                    .directory
                    .entry_exists(locator.leaf())
                    .map_err(|_| BackendError::Io)?
            {
                return Err(BackendError::Corrupt);
            }
        }
        if let Some(present) = prepared.present {
            let indices = prepared.present_indices;
            let mut original_auth = |index: usize, bytes: &[u8]| {
                authenticate(*indices.get(index).ok_or(BackendError::Corrupt)?, bytes)
            };
            self.retire_prepared_immutable_ciphertexts(present, &mut original_auth, gate)?;
        }
        // Includes the previously absent partition, not just this invocation's
        // deleted files. A new barrier cannot relabel the old unknown outcome.
        self.confirm_immutable_retirement_absent(&prepared.all, gate)
    }
}
