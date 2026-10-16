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
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum LocalV6BlobError {
    InvalidCiphertext,
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
    pub fn stage_local(
        &self,
        ciphertext: &[u8],
    ) -> Result<LocalV6BlobReceipt, LocalV6BlobError> {
        let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.to_vec())
            .map_err(|_| LocalV6BlobError::InvalidCiphertext)?;
        let reference = object.reference().clone();
        let destination = Self::leaf(&reference)?;
        let temporary = format!(
            ".v6-tmp-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed),
        );
        let mut opened = self.directory.open_file(&temporary, FileAccess::CreateNewReadWrite)?;
        opened.write_all(ciphertext)?;
        let published = self.directory.publish_file_noreplace(
            &temporary, &opened, &destination, reference.payload_bytes,
        )?;
        let mut file = match published {
            ImmutablePublication::Published(file)
            | ImmutablePublication::AlreadyExists(file) => file,
        };
        // "AlreadyExists" is NOT a successful duplicate by filename alone.
        // Authenticate the existing file and require exact original ciphertext.
        if Self::read_checked(&mut file, &reference)?.as_slice() != ciphertext {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        Ok(LocalV6BlobReceipt { reference })
    }

    /// Physically reopen and authenticate a local ciphertext copy; no read
    /// authority or verified Raft root is implied by this staging operation.
    pub fn read_local(
        &self,
        reference: &RecordObjectRef,
    ) -> Result<Vec<u8>, LocalV6BlobError> {
        let destination = Self::leaf(reference)?;
        let mut file = self.directory.open_file(&destination, FileAccess::Read)?;
        Self::read_checked(&mut file, reference)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::os::unix::fs::PermissionsExt;

    static TEMP_ROOT: AtomicU64 = AtomicU64::new(1);

    fn new_root() -> io::Result<PathBuf> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-v6-local-blob-{}-{}",
            std::process::id(), TEMP_ROOT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(path)
    }

    #[test]
    fn immutable_local_ciphertext_reopen_replay_and_tamper_rejection()
    -> Result<(), Box<dyn std::error::Error>> {
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
    fn refuses_unbounded_ciphertext_and_public_directory()
    -> Result<(), Box<dyn std::error::Error>> {
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
    #[ignore = "explicit 139 MiB local disk trial; no quorum or root publication"]
    fn distinct_139_mib_ciphertext_chunks_do_not_enter_json_state()
    -> Result<(), Box<dyn std::error::Error>> {
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
        drop(store);
        let store = LocalV6BlobStage::open_existing(&root)?;
        assert_eq!(references.len(), 556);
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
