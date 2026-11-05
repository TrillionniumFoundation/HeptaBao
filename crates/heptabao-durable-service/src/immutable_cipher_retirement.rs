//! Quiescent, original-fd physical retirement. No graph or Actor is inferred
//! from a locator. The durable layer owns the authenticated retirement Apply.
use super::*;
use heptabao_filesystem_guard::{
    FileRetirementError, MAX_IMMUTABLE_RETIREMENT_FILES, PreparedFileRetirement,
};

#[path = "immutable_cipher_reconcile.rs"]
mod reconciliation;
pub use reconciliation::PreparedImmutableReconciliation;

struct Entry {
    locator: BlobLocator,
    length: usize,
    file: PreparedFileRetirement,
    ciphertext_digest: [u8; 32],
}

/// The same original descriptors observed before the retirement metadata
/// transaction. Its separate weak instance token is not a read pin and cannot
/// keep a backend alive or be mistaken for a quiescence observation.
pub struct PreparedImmutableRetirement {
    owner: Weak<()>,
    entries: Vec<Entry>,
}
impl fmt::Debug for PreparedImmutableRetirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedImmutableRetirement")
            .field("objects", &self.entries.len())
            .finish_non_exhaustive()
    }
}
impl PreparedImmutableRetirement {
    pub fn ciphertext_digest(&self, index: usize) -> Result<[u8; 32], BackendError> {
        self.entries
            .get(index)
            .map(|entry| entry.ciphertext_digest)
            .ok_or(BackendError::Corrupt)
    }
}

fn read(
    file: &File,
    exact_len: usize,
    gate: &mut dyn FnMut() -> Result<(), BackendError>,
) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    gate()?;
    length_check(exact_len)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        let mut bytes = Zeroizing::new(vec![0; exact_len]);
        let mut offset = 0;
        let mut interrupts = 0;
        while offset < exact_len {
            gate()?;
            let end = exact_len.min(offset.saturating_add(256 * 1024));
            let result = file.read_at(&mut bytes[offset..end], offset as u64);
            gate()?;
            match result {
                Ok(0) => return Err(BackendError::Corrupt),
                Ok(n) if n <= end - offset => {
                    offset += n;
                    interrupts = 0;
                }
                Ok(_) => return Err(BackendError::Corrupt),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    interrupts += 1;
                    if interrupts >= 64 {
                        return Err(BackendError::Io);
                    }
                }
                Err(_) => return Err(BackendError::Io),
            }
        }
        gate()?;
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(BackendError::Unsupported)
    }
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    crate::digest32(b"heptabao.immutable-retirement-ciphertext.v1", bytes)
}

impl FileBackend {
    fn retirement_quiescent(&mut self) -> Result<(), BackendError> {
        self.verify()?;
        // get_mut is one atomic strong AND weak uniqueness observation, not
        // two racing counter snapshots. &mut self prevents a new local pin.
        Arc::get_mut(&mut self.immutable_lease)
            .ok_or(BackendError::Unavailable)?
            .check()?;
        self.verify()
    }

    pub fn prepare_immutable_retirement(
        &mut self,
        objects: &[(BlobLocator, usize)],
        authenticate: crate::ImmutableCiphertextAuthenticator<'_>,
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<PreparedImmutableRetirement, BackendError> {
        gate()?;
        self.retirement_quiescent()?;
        #[cfg(test)]
        eprintln!("HBGC-PHYSICAL stage=quiescent selected={}", objects.len());
        if objects.is_empty() || objects.len() > MAX_IMMUTABLE_RETIREMENT_FILES {
            return Err(BackendError::Capacity);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut entries = Vec::with_capacity(objects.len());
        for (index, &(locator, length)) in objects.iter().enumerate() {
            gate()?;
            length_check(length)?;
            if !seen.insert((locator.store_id(), locator.address())) {
                return Err(BackendError::Corrupt);
            }
            let observation = self
                .directory
                .prepare_file_retirement(locator.leaf(), length);
            #[cfg(test)]
            eprintln!(
                "HBGC-PHYSICAL stage=descriptor-preparation index={index} admitted={} error_kind={:?}",
                observation.is_ok(),
                observation.as_ref().err().map(std::io::Error::kind)
            );
            let file = observation.map_err(|_| BackendError::Corrupt)?;
            let bytes = read(file.file(), length, gate)?;
            #[cfg(test)]
            eprintln!(
                "HBGC-PHYSICAL stage=ciphertext-read index={index} bytes={}",
                bytes.len()
            );
            self.directory
                .verify_file_retirement(&file)
                .map_err(|_| BackendError::Corrupt)?;
            gate()?;
            #[cfg(test)]
            eprintln!("HBGC-PHYSICAL stage=first-fd-recheck index={index}");
            let authenticated = authenticate(index, &bytes);
            #[cfg(test)]
            eprintln!(
                "HBGC-PHYSICAL stage=authentication-returned index={index} accepted={} error={:?}",
                authenticated.is_ok(),
                authenticated.as_ref().err()
            );
            authenticated?;
            gate()?;
            self.directory
                .verify_file_retirement(&file)
                .map_err(|_| BackendError::Corrupt)?;
            #[cfg(test)]
            eprintln!("HBGC-PHYSICAL stage=second-fd-recheck index={index}");
            entries.push(Entry {
                locator,
                length,
                file,
                ciphertext_digest: digest(&bytes),
            });
        }
        gate()?;
        self.retirement_quiescent()?;
        Ok(PreparedImmutableRetirement {
            owner: Arc::downgrade(&self.retirement_instance),
            entries,
        })
    }

    pub fn retire_prepared_immutable_ciphertexts(
        &mut self,
        prepared: PreparedImmutableRetirement,
        authenticate: crate::ImmutableCiphertextAuthenticator<'_>,
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        use std::cell::RefCell;
        gate()?;
        let actual = prepared.owner.upgrade().ok_or(BackendError::Unavailable)?;
        if !Arc::ptr_eq(&actual, &self.retirement_instance) {
            return Err(BackendError::Unavailable);
        }
        drop(actual);
        self.retirement_quiescent()?;
        let identities = prepared
            .entries
            .iter()
            .map(|entry| (entry.locator, entry.length, entry.ciphertext_digest))
            .collect::<Vec<_>>();
        let files = prepared
            .entries
            .into_iter()
            .map(|entry| entry.file)
            .collect();
        let original = RefCell::new(gate);
        let mut before = |index: usize, file: &File| -> io::Result<()> {
            let mut gate = original
                .try_borrow_mut()
                .map_err(|_| io::Error::other("retirement gate unavailable"))?;
            let (_, length, expected) = *identities
                .get(index)
                .ok_or_else(|| io::Error::other("retirement object missing"))?;
            let bytes = read(file, length, &mut **gate).map_err(io::Error::other)?;
            if digest(&bytes) != expected {
                return Err(io::Error::other("retirement ciphertext changed"));
            }
            gate().map_err(io::Error::other)?;
            authenticate(index, &bytes).map_err(io::Error::other)?;
            gate().map_err(io::Error::other)
        };
        let mut check = || {
            let mut gate = original
                .try_borrow_mut()
                .map_err(|_| io::Error::other("retirement gate unavailable"))?;
            gate().map_err(io::Error::other)
        };
        let result = self
            .directory
            .retire_files_checked(files, &mut before, &mut check);
        match result {
            Ok(()) => {
                self.retirement_quiescent()?;
                Ok(())
            }
            Err(FileRetirementError::BeforeUnlink(_)) => Err(BackendError::Corrupt),
            Err(FileRetirementError::OutcomeUnknown(_)) => {
                self.immutable_lease.revoke();
                Err(BackendError::OutcomeUnknown)
            }
        }
    }

    /// Explicit absence reconciliation with a directory durability barrier.
    /// No descriptor is unlinked here and an existing name, including a
    /// replacement or symlink, is never adopted. A current ENOENT observation
    /// alone cannot acknowledge a historically unknown unlink directory sync.
    pub fn confirm_immutable_retirement_absent(
        &mut self,
        objects: &[BlobLocator],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        gate()?;
        self.retirement_quiescent()?;
        if objects.len() > MAX_IMMUTABLE_RETIREMENT_FILES {
            return Err(BackendError::Capacity);
        }
        if objects.is_empty() {
            // The zero-object operation asks only for owner uniqueness.
            return gate();
        }
        for locator in objects {
            gate()?;
            if self
                .directory
                .entry_exists(locator.leaf())
                .map_err(|_| BackendError::Io)?
            {
                return Err(BackendError::Unavailable);
            }
            gate()?;
        }
        gate()?;
        self.directory.sync_all().map_err(|_| BackendError::Io)?;
        gate()?;
        for locator in objects {
            gate()?;
            if self
                .directory
                .entry_exists(locator.leaf())
                .map_err(|_| BackendError::Io)?
            {
                return Err(BackendError::Unavailable);
            }
            gate()?;
        }
        self.retirement_quiescent()?;
        gate()
    }
}
