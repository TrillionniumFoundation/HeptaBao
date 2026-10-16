//! Local durable V6 ciphertext staging, explicitly not a Raft root or quorum proof.
//!
//! Never place 139 MiB of encrypted V6 history into the 47 MiB JSON state
//! snapshot.  This owner-only, descriptor-anchored staging primitive stores one
//! bounded opaque ciphertext per immutable file using the existing filesystem
//! guard's fsync/no-replace publication.  Replication, authorization, epoch,
//! committed index, genesis, garbage collection and V6 publication are NOT
//! implemented here.  The only returned proof is of a local authenticated
//! ciphertext copy. It is not suitable for acknowledging a client mutation.

use crate::records::{RecordObjectKind, RecordObjectRef, SealedRecordObject};
use heptabao_filesystem_guard::{
    DirectoryGuardError, ExclusiveDirectory, FileAccess, ImmutablePublication,
    ImmutablePublicationError,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum LocalV6BlobError {
    InvalidCiphertext,
    InvalidClosure,
    InvalidRoot,
    CorruptOrChanged,
    Guard(DirectoryGuardError),
    Io(io::Error),
    Publication(ImmutablePublicationError),
}
impl fmt::Display for LocalV6BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidCiphertext => "invalid or unbounded V6 ciphertext",
            Self::InvalidClosure => "empty, duplicate or oversized local V6 closure",
            Self::InvalidRoot => "V6 staging requires an existing private real directory",
            Self::CorruptOrChanged => "V6 ciphertext bytes or identity do not match",
            Self::Guard(_) => "V6 staging directory identity/owner fence unavailable",
            Self::Io(_) => "V6 staging file I/O failed",
            Self::Publication(_) => "V6 staging publication failed or outcome unknown",
        };
        f.write_str(message)
    }
}
impl std::error::Error for LocalV6BlobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Guard(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Publication(e) => Some(e),
            _ => None,
        }
    }
}
impl From<DirectoryGuardError> for LocalV6BlobError {
    fn from(e: DirectoryGuardError) -> Self {
        Self::Guard(e)
    }
}
impl From<io::Error> for LocalV6BlobError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<ImmutablePublicationError> for LocalV6BlobError {
    fn from(e: ImmutablePublicationError) -> Self {
        Self::Publication(e)
    }
}

/// A file verified and fsynced on THIS host only, not an authenticated Raft
/// command, replication witness, read permission, or published V6 root.
#[derive(Debug)]
pub struct LocalV6BlobReceipt {
    reference: RecordObjectRef,
}
impl LocalV6BlobReceipt {
    pub fn reference(&self) -> &RecordObjectRef {
        &self.reference
    }
}

/// A point-in-time authenticated observation of **local** staged ciphertext.
/// The digest binds a canonical set of exact ciphertext object references.
/// It is NOT a Raft quorum certificate, a root publication or read permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalV6ClosureReceipt {
    object_count: usize,
    ciphertext_bytes: u64,
    manifest_sha256: [u8; 32],
}
impl LocalV6ClosureReceipt {
    pub fn object_count(&self) -> usize {
        self.object_count
    }
    pub fn ciphertext_bytes(&self) -> u64 {
        self.ciphertext_bytes
    }
    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }
}

/// Exclusive owner of a pre-existing local ciphertext-stage directory.
///
/// No path from untrusted input is opened: the only names are domain-separated
/// ciphertext digest leaves and independently generated temporary leaves.
#[derive(Debug)]
pub struct LocalV6BlobStage {
    directory: ExclusiveDirectory,
}
impl LocalV6BlobStage {
    pub fn open_existing(root: &Path) -> Result<Self, LocalV6BlobError> {
        let meta = fs::symlink_metadata(root)?;
        if !meta.file_type().is_dir() || !root.is_absolute() {
            return Err(LocalV6BlobError::InvalidRoot);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(LocalV6BlobError::InvalidRoot);
            }
        }
        Ok(Self {
            directory: ExclusiveDirectory::open(root)?,
        })
    }

    fn leaf(reference: &RecordObjectRef) -> Result<String, LocalV6BlobError> {
        if reference.kind != RecordObjectKind::NativeV6CiphertextChunk
            || reference.record_count != 0
            || reference.payload_bytes != u64::from(reference.encoded_bytes)
            || !(25..=256 * 1024).contains(&reference.encoded_bytes)
        {
            return Err(LocalV6BlobError::InvalidCiphertext);
        }
        let mut name = String::from("v6-");
        crate::append_hex(&mut name, &reference.id);
        name.push_str(".blob");
        Ok(name)
    }

    fn read_checked(
        file: &mut File,
        reference: &RecordObjectRef,
    ) -> Result<Vec<u8>, LocalV6BlobError> {
        if file.metadata()?.len() != reference.payload_bytes {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(reference.encoded_bytes as usize);
        let mut bounded = file.take(reference.payload_bytes + 1);
        bounded.read_to_end(&mut bytes)?;
        if bytes.len() != reference.encoded_bytes as usize {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        // Authenticate both the exact bytes and all immutable reference fields
        // by reconstructing the domain-separated record object.
        let verified = SealedRecordObject::new_native_v6_ciphertext_chunk(bytes.clone())
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        if verified.reference() != reference {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        Ok(bytes)
    }

    /// Stage a local copy. A late I/O or fsync failure is NEVER interpreted as
    /// an uncommitted/no-effect result and must not automatically be retried.
    /// This function never touches Raft or native V6 root publication.
    pub fn stage_local(&self, ciphertext: &[u8]) -> Result<LocalV6BlobReceipt, LocalV6BlobError> {
        let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.to_vec())
            .map_err(|_| LocalV6BlobError::InvalidCiphertext)?;
        let reference = object.reference().clone();
        let destination = Self::leaf(&reference)?;
        let temporary = format!(
            ".v6-tmp-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed),
        );
        let mut opened = self
            .directory
            .open_file(&temporary, FileAccess::CreateNewReadWrite)?;
        opened.write_all(ciphertext)?;
        let published = self.directory.publish_file_noreplace(
            &temporary,
            &opened,
            &destination,
            reference.payload_bytes,
        )?;
        let mut file = match published {
            ImmutablePublication::Published(file) | ImmutablePublication::AlreadyExists(file) => {
                file
            }
        };
        // "AlreadyExists" is NOT a successful duplicate by filename alone.
        // Authenticate the existing file and require exact original ciphertext.
        if Self::read_checked(&mut file, &reference)?.as_slice() != ciphertext {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        Ok(LocalV6BlobReceipt { reference })
    }

    /// Receive a V6 ciphertext leaf whose identity was specified by a peer.
    ///
    /// This method is only an untrusted-byte, local durability primitive.
    /// The caller MUST separately authenticate peer identity, cluster, epoch,
    /// operation, Raft membership, the complete closure, and original deadline.
    /// Never interpret its local receipt as a majority acknowledgement or
    /// permission to publish/serve a V6 root.
    ///
    /// Reject a mismatched reference BEFORE creating any temporary file.
    /// Repeated, identical deliveries still use the guarded no-replace/fsync
    /// path; a preexisting leaf is physically reopened and reauthenticated.
    pub fn stage_received_replica(
        &self,
        expected: &RecordObjectRef,
        ciphertext: &[u8],
    ) -> Result<LocalV6BlobReceipt, LocalV6BlobError> {
        Self::leaf(expected)?;
        if u64::try_from(ciphertext.len()).ok() != Some(expected.payload_bytes) {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        let checked = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.to_vec())
            .map_err(|_| LocalV6BlobError::InvalidCiphertext)?;
        if checked.reference() != expected {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        self.stage_local(ciphertext)
    }

    /// Physically reopen and authenticate a local ciphertext copy; no read
    /// authority or verified Raft root is implied by this staging operation.
    pub fn read_local(&self, reference: &RecordObjectRef) -> Result<Vec<u8>, LocalV6BlobError> {
        let destination = Self::leaf(reference)?;
        let mut file = self.directory.open_file(&destination, FileAccess::Read)?;
        Self::read_checked(&mut file, reference)
    }

    /// Observe an entire exact set of local ciphertext objects without
    /// materializing their combined plaintext/ciphertext or using the Raft
    /// JSON state. Every leaf is physically reopened and SHA256 checked.
    /// Sorting IDs makes the manifest deterministic across process/host
    /// enumeration order. Duplicate IDs (even with altered length metadata)
    /// and missing/tampered leaves fail closed.
    ///
    /// This receipt has no cluster/epoch/Actor, index or majority authority.
    /// An authenticated future Raft publisher MUST recheck closure durability
    /// under its own commit fence; this snapshot is not a durable lease.
    pub fn observe_local_closure(
        &self,
        references: &[RecordObjectRef],
    ) -> Result<LocalV6ClosureReceipt, LocalV6BlobError> {
        if references.is_empty() {
            return Err(LocalV6BlobError::InvalidClosure);
        }
        let count =
            u64::try_from(references.len()).map_err(|_| LocalV6BlobError::InvalidClosure)?;
        let mut ordered: Vec<&RecordObjectRef> = references.iter().collect();
        ordered.sort_unstable_by_key(|reference| reference.id);
        if ordered.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(LocalV6BlobError::InvalidClosure);
        }
        let mut digest = Sha256::new();
        digest.update(b"heptabao.v6.local-ciphertext-closure.v1\0");
        digest.update(count.to_be_bytes());
        let mut ciphertext_bytes = 0_u64;
        for reference in ordered {
            ciphertext_bytes = ciphertext_bytes
                .checked_add(reference.payload_bytes)
                .ok_or(LocalV6BlobError::InvalidClosure)?;
            // read_local validates the kind, expected exact length and
            // ciphertext digest before the manifest can contain this entry.
            drop(self.read_local(reference)?);
            digest.update(reference.id);
            digest.update(reference.payload_bytes.to_be_bytes());
        }
        Ok(LocalV6ClosureReceipt {
            object_count: references.len(),
            ciphertext_bytes,
            manifest_sha256: digest.finalize().into(),
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    static TEMP_ROOT: AtomicU64 = AtomicU64::new(1);

    fn new_root() -> io::Result<PathBuf> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-v6-local-blob-{}-{}",
            std::process::id(),
            TEMP_ROOT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(path)
    }

    #[test]
    fn ciphertext_reopen_tamper_and_duplicate_reject() -> Result<(), Box<dyn std::error::Error>> {
        let root = new_root()?;
        let ciphertext = vec![0x93_u8; 131_072];
        let store = LocalV6BlobStage::open_existing(&root)?;
        let receipt = store.stage_local(&ciphertext)?;
        assert_eq!(store.read_local(receipt.reference())?, ciphertext);
        assert_eq!(
            store.stage_local(&ciphertext)?.reference(),
            receipt.reference(),
            "identical content must reuse one checked immutable destination",
        );
        let reference = receipt.reference().clone();
        drop(store);
        let store = LocalV6BlobStage::open_existing(&root)?;
        assert_eq!(store.read_local(&reference)?, ciphertext);
        drop(store);
        let filename = LocalV6BlobStage::leaf(&reference)?;
        fs::write(root.join(filename), vec![0x92_u8; ciphertext.len()])?;
        let store = LocalV6BlobStage::open_existing(&root)?;
        assert!(matches!(
            store.read_local(&reference),
            Err(LocalV6BlobError::CorruptOrChanged),
        ));
        // A duplicate digest name cannot launder a tampered existing file
        // into a verified local staging receipt.
        assert!(matches!(
            store.stage_local(&ciphertext),
            Err(LocalV6BlobError::CorruptOrChanged),
        ));
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn refuses_unbounded_ciphertext_and_public_root() -> Result<(), Box<dyn std::error::Error>> {
        let root = new_root()?;
        let store = LocalV6BlobStage::open_existing(&root)?;
        assert!(matches!(
            store.stage_local(&[4_u8; 24]),
            Err(LocalV6BlobError::InvalidCiphertext),
        ));
        assert!(matches!(
            store.stage_local(&vec![5_u8; 256 * 1024 + 1]),
            Err(LocalV6BlobError::InvalidCiphertext),
        ));
        drop(store);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
        assert!(matches!(
            LocalV6BlobStage::open_existing(&root),
            Err(LocalV6BlobError::InvalidRoot),
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn closure_observation_requires_all_local_bytes_and_unique_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = new_root()?;
        let store = LocalV6BlobStage::open_existing(&root)?;
        let first = store.stage_local(&[0x41_u8; 4096])?.reference().clone();
        let second = store.stage_local(&[0x42_u8; 1024])?.reference().clone();
        let ordered = vec![first.clone(), second.clone()];
        let before = store.observe_local_closure(&ordered)?;
        assert_eq!(before.object_count(), 2);
        assert_eq!(before.ciphertext_bytes(), 5120);
        assert_ne!(before.manifest_sha256(), [0; 32]);
        assert_eq!(
            before,
            store.observe_local_closure(&[second.clone(), first.clone()])?
        );
        assert!(matches!(
            store.observe_local_closure(&[]),
            Err(LocalV6BlobError::InvalidClosure),
        ));
        assert!(matches!(
            store.observe_local_closure(&[first.clone(), first.clone()]),
            Err(LocalV6BlobError::InvalidClosure),
        ));
        let absent = SealedRecordObject::new_native_v6_ciphertext_chunk(vec![0x43; 4096])?;
        assert!(
            store
                .observe_local_closure(&[first.clone(), absent.reference().clone()])
                .is_err()
        );
        drop(store);
        let store = LocalV6BlobStage::open_existing(&root)?;
        assert_eq!(before, store.observe_local_closure(&ordered)?);
        drop(store);
        fs::write(root.join(LocalV6BlobStage::leaf(&second)?), [0x44_u8; 1024])?;
        let store = LocalV6BlobStage::open_existing(&root)?;
        assert!(matches!(
            store.observe_local_closure(&ordered),
            Err(LocalV6BlobError::CorruptOrChanged),
        ));
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn remote_replica_import_requires_exact_reference_before_disk_and_recovers_lost_ack()
    -> Result<(), Box<dyn std::error::Error>> {
        // Two physically independent private directories, not an in-memory
        // mock object table.  No peer identity, quorum or root is asserted.
        let sender_root = new_root()?;
        let receiver_root = new_root()?;
        let sender = LocalV6BlobStage::open_existing(&sender_root)?;
        let receiver = LocalV6BlobStage::open_existing(&receiver_root)?;
        let ciphertext = vec![0x67_u8; 256 * 1024];
        let wrong_ciphertext = vec![0x68_u8; 256 * 1024];
        let claimed = sender.stage_local(&ciphertext)?.reference().clone();
        let wrong = sender.stage_local(&wrong_ciphertext)?.reference().clone();

        // Wrong digest, wrong length, and wrong record kind cannot create
        // a file.  A transport-controlled ID must not become an alias.
        assert!(matches!(
            receiver.stage_received_replica(&wrong, &ciphertext),
            Err(LocalV6BlobError::CorruptOrChanged),
        ));
        let mut bad_length = claimed.clone();
        bad_length.payload_bytes += 1;
        assert!(matches!(
            receiver.stage_received_replica(&bad_length, &ciphertext),
            Err(LocalV6BlobError::InvalidCiphertext),
        ));
        let mut bad_kind = claimed.clone();
        bad_kind.kind = RecordObjectKind::Block;
        assert!(matches!(
            receiver.stage_received_replica(&bad_kind, &ciphertext),
            Err(LocalV6BlobError::InvalidCiphertext),
        ));
        assert!(matches!(
            receiver.stage_received_replica(&claimed, &ciphertext[..ciphertext.len() - 1]),
            Err(LocalV6BlobError::CorruptOrChanged),
        ));
        assert_eq!(fs::read_dir(&receiver_root)?.count(), 0);

        let delivered = receiver.stage_received_replica(&claimed, &ciphertext)?;
        assert_eq!(delivered.reference(), &claimed);
        // Simulate losing the delivery acknowledgement.  A fresh process
        // must be able to reconcile the exact already-durable bytes.
        drop(receiver);
        let receiver = LocalV6BlobStage::open_existing(&receiver_root)?;
        assert_eq!(receiver.read_local(&claimed)?, ciphertext);
        assert_eq!(
            receiver
                .stage_received_replica(&claimed, &ciphertext)?
                .reference(),
            &claimed,
            "idempotent byte-identical resend must not publish a new object",
        );
        assert_eq!(
            sender.observe_local_closure(std::slice::from_ref(&claimed))?,
            receiver.observe_local_closure(std::slice::from_ref(&claimed))?,
        );
        drop(receiver);

        // A changed existing object must never be repaired by blind replay
        // or admitted into a closure after local tampering.
        fs::write(
            receiver_root.join(LocalV6BlobStage::leaf(&claimed)?),
            &wrong_ciphertext,
        )?;
        let receiver = LocalV6BlobStage::open_existing(&receiver_root)?;
        assert!(matches!(
            receiver.stage_received_replica(&claimed, &ciphertext),
            Err(LocalV6BlobError::CorruptOrChanged),
        ));
        assert!(receiver.observe_local_closure(&[claimed]).is_err());
        drop(receiver);
        drop(sender);
        fs::remove_dir_all(sender_root)?;
        fs::remove_dir_all(receiver_root)?;
        Ok(())
    }

    #[test]
    #[ignore = "explicit 139 MiB local disk trial; no quorum or root publication"]
    fn stages_unique_139_mib_without_raft_json() -> Result<(), Box<dyn std::error::Error>> {
        let root = new_root()?;
        let store = LocalV6BlobStage::open_existing(&root)?;
        let mut references = Vec::new();
        // Exactly 139 MiB of unique ciphertext in 556 independent 256-KiB
        // immutable objects, with zero modifications to the Raft JSON state.
        for i in 0..556_u64 {
            let mut ciphertext = vec![0x6a_u8; 256 * 1024];
            ciphertext[..8].copy_from_slice(&i.to_be_bytes());
            references.push(store.stage_local(&ciphertext)?.reference().clone());
        }
        let before = store.observe_local_closure(&references)?;
        assert_eq!(before.object_count(), 556);
        assert_eq!(before.ciphertext_bytes(), 139_u64 * 1024 * 1024);
        drop(store);
        let store = LocalV6BlobStage::open_existing(&root)?;
        assert_eq!(references.len(), 556);
        assert_eq!(store.observe_local_closure(&references)?, before);
        for (index, reference) in references.iter().enumerate() {
            let result = store.read_local(reference)?;
            assert_eq!(&result[..8], &(index as u64).to_be_bytes());
            assert_eq!(result.len(), 256 * 1024);
        }
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
