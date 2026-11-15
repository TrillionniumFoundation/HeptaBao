//! Existing exact ciphertext still receives real file and directory barriers.
//! No existence probe, retained receipt or cache can substitute for those I/O
//! operations. Only a missing leaf enters the unchanged temporary-write path.
use super::*;
use std::os::unix::fs::MetadataExt;

#[path = "v6_replica_blobs_existing_batch.rs"]
mod bounded_batch;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExistingIdentity {
    device: u64,
    inode: u64,
    length: u64,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
}

impl ExistingIdentity {
    fn read(file: &File, expected: &RecordObjectRef) -> Result<Self, LocalV6BlobError> {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != expected.payload_bytes
        {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            links: metadata.nlink(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            modified_seconds: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
        })
    }
}

/// A private held descriptor, never a wire receipt. A physical batch retains
/// the exact descriptor and its observed metadata until every later callback
/// has completed. It must not reopen an equal-content replacement and call it
/// the file that was synchronized.
pub(super) struct HeldSynchronizedCiphertext {
    reference: RecordObjectRef,
    destination: String,
    file: File,
    identity: ExistingIdentity,
    reuse_mutation_witness: Option<heptabao_filesystem_guard::FileMutationWitness>,
    original_new_sync_witness: Option<heptabao_filesystem_guard::ImmutableFileSyncWitness>,
}

impl HeldSynchronizedCiphertext {
    pub(super) fn published(
        reference: &RecordObjectRef,
        publication: heptabao_filesystem_guard::SynchronizedImmutablePublication,
    ) -> Result<Self, LocalV6BlobError> {
        let (file, original_new_sync_witness) = publication.into_parts();
        original_new_sync_witness
            .verify_file(&file)
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        let identity = ExistingIdentity::read(&file, reference)?;
        original_new_sync_witness
            .verify_file(&file)
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        Ok(Self {
            reference: reference.clone(),
            destination: LocalV6BlobStage::leaf(reference)?,
            file,
            identity,
            reuse_mutation_witness: None,
            original_new_sync_witness: Some(original_new_sync_witness),
        })
    }

    pub(super) fn authenticate(
        &mut self,
        ciphertext: &[u8],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<(), LocalV6BlobError> {
        self.verify_mutations(&self.file)?;
        read_exact_existing(&mut self.file, &self.reference, ciphertext, gate)?;
        self.verify_mutations(&self.file)
    }

    fn verify_mutations(&self, file: &File) -> Result<(), LocalV6BlobError> {
        if let Some(witness) = &self.reuse_mutation_witness {
            witness
                .verify_file(file)
                .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        }
        if let Some(witness) = &self.original_new_sync_witness {
            witness
                .verify_file(file)
                .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        }
        Ok(())
    }

    /// No caller callback is allowed after the complete batch's final pass.
    /// This checks the original descriptor and the actual current leaf name;
    /// the same kernel watch and metadata span synchronization and callbacks.
    pub(super) fn check_without_callback(
        &self,
        store: &LocalV6BlobStage,
    ) -> Result<(), LocalV6BlobError> {
        store.directory.verify()?;
        let current = store
            .directory
            .open_file(&self.destination, FileAccess::Read)?;
        self.verify_mutations(&self.file)?;
        self.verify_mutations(&current)?;
        if ExistingIdentity::read(&self.file, &self.reference)? != self.identity
            || ExistingIdentity::read(&current, &self.reference)? != self.identity
        {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        store.directory.verify()?;
        self.verify_mutations(&self.file)?;
        Ok(())
    }

    pub(super) fn into_receipt(self) -> LocalV6BlobReceipt {
        LocalV6BlobReceipt {
            reference: self.reference,
        }
    }
}

// Private observation hooks follow actual operations. Production uses no-op
// hooks; tests may cancel the original gate or mutate a real owned file here.
// They cannot skip an I/O barrier, mint a receipt or supply another deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingStageEvent {
    Opened,
    Authenticated,
    FileSynced,
    DirectorySynced,
}

fn read_exact_existing(
    file: &mut (impl Read + Seek),
    reference: &RecordObjectRef,
    ciphertext: &[u8],
    gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
) -> Result<(), LocalV6BlobError> {
    gate()?;
    let position = file.seek(SeekFrom::Start(0));
    gate()?;
    if position? != 0 {
        return Err(LocalV6BlobError::CorruptOrChanged);
    }
    let expected = reference.encoded_bytes as usize;
    let mut bytes = Vec::with_capacity(expected);
    let mut scratch = [0u8; 64 * 1024];
    let mut interrupts = 0;
    loop {
        let limit = scratch.len().min(expected - bytes.len() + 1);
        gate()?;
        let observed = file.read(&mut scratch[..limit]);
        gate()?;
        let count = match observed {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupts < 64 => {
                interrupts += 1;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if count == 0 {
            break;
        }
        if count > limit || count > expected - bytes.len() {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        bytes.extend_from_slice(&scratch[..count]);
    }
    if bytes.len() != expected || bytes.as_slice() != ciphertext {
        return Err(LocalV6BlobError::CorruptOrChanged);
    }
    gate()?;
    let verified = SealedRecordObject::new(reference.clone(), Vec::new(), bytes)
        .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
    gate()?;
    if verified.reference() != reference
        || verified.reference().kind != RecordObjectKind::NativeV6CiphertextChunk
    {
        return Err(LocalV6BlobError::CorruptOrChanged);
    }
    Ok(())
}

impl LocalV6BlobStage {
    pub(super) fn sync_existing_exact_checked(
        &self,
        reference: &RecordObjectRef,
        ciphertext: &[u8],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<Option<LocalV6BlobReceipt>, LocalV6BlobError> {
        self.sync_existing_exact_with_hook(reference, ciphertext, gate, &mut |_| Ok(()))
    }

    fn verify_existing_binding(
        &self,
        file: &File,
        reference: &RecordObjectRef,
        destination: &str,
        identity: ExistingIdentity,
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
        mutations: &heptabao_filesystem_guard::FileMutationWitness,
    ) -> Result<(), LocalV6BlobError> {
        gate()?;
        mutations
            .verify_file(file)
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        self.directory.verify()?;
        gate()?;
        let held = ExistingIdentity::read(file, reference);
        gate()?;
        if held? != identity {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        let reopened = self.directory.open_file(destination, FileAccess::Read);
        gate()?;
        let reopened = reopened?;
        let named = ExistingIdentity::read(&reopened, reference);
        gate()?;
        if named? != identity {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        // A gate or rename during the named observation must not discharge an
        // old descriptor. Reopen the name after the gate, as the original
        // no-replace guard does at its acknowledgement boundary.
        self.directory.verify()?;
        let current = self.directory.open_file(destination, FileAccess::Read)?;
        let identities_match = ExistingIdentity::read(&current, reference)? == identity
            && ExistingIdentity::read(file, reference)? == identity
            && ExistingIdentity::read(&reopened, reference)? == identity;
        gate()?;
        if !identities_match
            || ExistingIdentity::read(&current, reference)? != identity
            || ExistingIdentity::read(file, reference)? != identity
            || ExistingIdentity::read(&reopened, reference)? != identity
        {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        gate()?;
        mutations
            .verify_file(file)
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        Ok(())
    }

    fn sync_existing_exact_with_hook(
        &self,
        reference: &RecordObjectRef,
        ciphertext: &[u8],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
        hook: &mut impl FnMut(ExistingStageEvent) -> Result<(), LocalV6BlobError>,
    ) -> Result<Option<LocalV6BlobReceipt>, LocalV6BlobError> {
        Ok(self
            .hold_existing_exact_with_hook(reference, ciphertext, gate, hook)?
            .map(HeldSynchronizedCiphertext::into_receipt))
    }

    fn hold_existing_exact_with_hook(
        &self,
        reference: &RecordObjectRef,
        ciphertext: &[u8],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
        hook: &mut impl FnMut(ExistingStageEvent) -> Result<(), LocalV6BlobError>,
    ) -> Result<Option<HeldSynchronizedCiphertext>, LocalV6BlobError> {
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
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let mutations = self.directory.watch_file_mutations(&file)?;
        let identity = ExistingIdentity::read(&file, reference);
        gate()?;
        let identity = identity?;
        hook(ExistingStageEvent::Opened)?;
        self.verify_existing_binding(&file, reference, &destination, identity, gate, &mutations)?;
        read_exact_existing(&mut file, reference, ciphertext, gate)?;
        hook(ExistingStageEvent::Authenticated)?;
        self.verify_existing_binding(&file, reference, &destination, identity, gate, &mutations)?;

        // The original descriptor, not a newly opened equal-content leaf, is
        // strongly synced. Every rejection keeps the exact existing bytes and
        // returns no local durability receipt. No write, link or unlink occurs.
        gate()?;
        let synced = file.sync_all();
        gate()?;
        synced?;
        hook(ExistingStageEvent::FileSynced)?;
        self.verify_existing_binding(&file, reference, &destination, identity, gate, &mutations)?;
        gate()?;
        let synced = self.directory.sync_all();
        gate()?;
        synced?;
        hook(ExistingStageEvent::DirectorySynced)?;
        self.verify_existing_binding(&file, reference, &destination, identity, gate, &mutations)?;

        // Reauthenticate the same held descriptor after both real barriers.
        // The retained event watch and metadata never replace this final full
        // ciphertext/ref verification or the caller's original live gate.
        read_exact_existing(&mut file, reference, ciphertext, gate)?;
        self.verify_existing_binding(&file, reference, &destination, identity, gate, &mutations)?;
        Ok(Some(HeldSynchronizedCiphertext {
            reference: reference.clone(),
            destination,
            file,
            identity,
            reuse_mutation_witness: Some(mutations),
            original_new_sync_witness: None,
        }))
    }
}

#[cfg(test)]
#[path = "v6_replica_blobs_existing_tests.rs"]
mod tests;
