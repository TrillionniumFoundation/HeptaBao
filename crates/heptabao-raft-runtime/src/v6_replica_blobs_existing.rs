//! Existing exact ciphertext still receives real file and directory barriers.
//! No existence probe, retained receipt or cache can substitute for those I/O
//! operations. Only a missing leaf enters the unchanged temporary-write path.
use super::*;
use std::os::unix::fs::MetadataExt;

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
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.len() != expected.payload_bytes
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
    let verified = SealedRecordObject::new_native_v6_ciphertext_chunk(bytes)
        .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
    gate()?;
    if verified.reference() != reference {
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
    ) -> Result<(), LocalV6BlobError> {
        gate()?;
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
        Ok(())
    }

    fn sync_existing_exact_with_hook(
        &self,
        reference: &RecordObjectRef,
        ciphertext: &[u8],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
        hook: &mut impl FnMut(ExistingStageEvent) -> Result<(), LocalV6BlobError>,
    ) -> Result<Option<LocalV6BlobReceipt>, LocalV6BlobError> {
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
        let identity = ExistingIdentity::read(&file, reference);
        gate()?;
        let identity = identity?;
        hook(ExistingStageEvent::Opened)?;
        self.verify_existing_binding(&file, reference, &destination, identity, gate)?;
        read_exact_existing(&mut file, reference, ciphertext, gate)?;
        hook(ExistingStageEvent::Authenticated)?;
        self.verify_existing_binding(&file, reference, &destination, identity, gate)?;

        // The original descriptor, not a newly opened equal-content leaf, is
        // strongly synced. Every rejection keeps the exact existing bytes and
        // returns no local durability receipt. No write, link or unlink occurs.
        gate()?;
        let synced = file.sync_all();
        gate()?;
        synced?;
        hook(ExistingStageEvent::FileSynced)?;
        self.verify_existing_binding(&file, reference, &destination, identity, gate)?;
        gate()?;
        let synced = self.directory.sync_all();
        gate()?;
        synced?;
        hook(ExistingStageEvent::DirectorySynced)?;
        self.verify_existing_binding(&file, reference, &destination, identity, gate)?;

        // Reauthenticate the same held descriptor after both real barriers.
        // Timestamps bind mutation windows; they never replace this final full
        // ciphertext/ref verification or the caller's original live gate.
        read_exact_existing(&mut file, reference, ciphertext, gate)?;
        self.verify_existing_binding(&file, reference, &destination, identity, gate)?;
        Ok(Some(LocalV6BlobReceipt {
            reference: reference.clone(),
        }))
    }
}

#[cfg(test)]
#[path = "v6_replica_blobs_existing_tests.rs"]
mod tests;
