//! Physical immutable ciphertext storage on the existing FileBackend owner.
//!
//! A locator, profile, stage acknowledgement or read pin is not application
//! authority. This module never owns a barrier, address key or principal and
//! does not authenticate the bytes supplied to or read from the backend.
use super::{BackendError, FileBackend};
use heptabao_filesystem_guard::{
    ExclusiveDirectory, FileAccess, ImmutablePublication as FilePublication,
    ImmutablePublicationError,
};
use std::{
    fmt,
    fs::File,
    io::{self, Write},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;

/// A per-object physical bound. Existing snapshot/journal limits are unchanged.
pub const MAX_IMMUTABLE_CIPHERTEXT_BYTES: usize = 512 * 1024;
const TEMPORARY_LEAF: &str = "native-v6-object.tmp";

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct BlobLocator {
    store_id: [u8; 16],
    address: [u8; 32],
}
impl BlobLocator {
    /// Construct a fixed-width physical address. This performs syntax checks
    /// only; a nonzero store identifier does not grant a native Service owner.
    pub fn new(store_id: [u8; 16], address: [u8; 32]) -> Result<Self, BackendError> {
        if store_id == [0; 16] {
            return Err(BackendError::InvalidRoot);
        }
        Ok(Self { store_id, address })
    }
    pub const fn store_id(&self) -> [u8; 16] {
        self.store_id
    }
    pub const fn address(&self) -> [u8; 32] {
        self.address
    }
    fn leaf(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut leaf = String::with_capacity(105);
        leaf.push_str("nv6.");
        for byte in self.store_id {
            leaf.push(char::from(DIGITS[usize::from(byte >> 4)]));
            leaf.push(char::from(DIGITS[usize::from(byte & 15)]));
        }
        leaf.push('.');
        for byte in self.address {
            leaf.push(char::from(DIGITS[usize::from(byte >> 4)]));
            leaf.push(char::from(DIGITS[usize::from(byte & 15)]));
        }
        leaf.push_str(".hbo");
        leaf
    }
}
impl fmt::Debug for BlobLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlobLocator([FIXED_WIDTH_ADDRESS])")
    }
}

/// Observed physical facts only, not a native layout or root admission.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ImmutableBlobProfile {
    pub directory_identity: [u8; 16],
    pub max_ciphertext_bytes: usize,
}
impl fmt::Debug for ImmutableBlobProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImmutableBlobProfile")
            .field("directory_identity", &"[DESCRIPTOR_BOUND]")
            .field("max_ciphertext_bytes", &self.max_ciphertext_bytes)
            .finish()
    }
}

pub enum ImmutableBlobStage {
    Published(ImmutableBlobReadPin),
    /// The existing descriptor is safe to read. Its ciphertext and plaintext
    /// have not been compared with the candidate or address-authenticated.
    AlreadyExists(ImmutableBlobReadPin),
}
impl fmt::Debug for ImmutableBlobStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Published(_) => "ImmutableBlobStage::Published([CIPHERTEXT_PIN])",
            Self::AlreadyExists(_) => "ImmutableBlobStage::AlreadyExists([CIPHERTEXT_PIN])",
        })
    }
}

pub(super) struct ImmutableLease(AtomicBool);
impl ImmutableLease {
    pub(super) fn new() -> Self {
        Self(AtomicBool::new(true))
    }
    pub(super) fn revoke(&self) {
        self.0.store(false, Ordering::Release);
    }
    fn check(&self) -> Result<(), BackendError> {
        if self.0.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(BackendError::Unavailable)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
    length: usize,
}
#[cfg(unix)]
fn object_identity(file: &File, exact_len: usize) -> Result<ObjectIdentity, BackendError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().map_err(|_| BackendError::Io)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != exact_len as u64 {
        return Err(BackendError::Corrupt);
    }
    Ok(ObjectIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: exact_len,
    })
}
#[cfg(not(unix))]
fn object_identity(_file: &File, _exact_len: usize) -> Result<ObjectIdentity, BackendError> {
    Err(BackendError::Unsupported)
}

struct PinnedObject {
    file: File,
    locator: BlobLocator,
    identity: ObjectIdentity,
    directory_identity: [u8; 16],
    lease: Weak<ImmutableLease>,
}

/// An owned read-only physical ciphertext pin. It keeps the object descriptor
/// alive but holds neither the directory descriptor nor its writer lock. A
/// backend close, drop or uncertain staging result revokes all of its pins.
#[derive(Clone)]
pub struct ImmutableBlobReadPin(Arc<PinnedObject>);
impl fmt::Debug for ImmutableBlobReadPin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImmutableBlobReadPin")
            .field("ciphertext_bytes", &self.0.identity.length)
            .field("descriptor", &"READ_ONLY")
            .finish()
    }
}
impl ImmutableBlobReadPin {
    pub fn locator(&self) -> BlobLocator {
        self.0.locator
    }
    pub fn ciphertext_len(&self) -> usize {
        self.0.identity.length
    }
    pub fn directory_identity(&self) -> [u8; 16] {
        self.0.directory_identity
    }
    fn check(&self) -> Result<Arc<ImmutableLease>, BackendError> {
        let lease = self.0.lease.upgrade().ok_or(BackendError::Unavailable)?;
        lease.check()?;
        if object_identity(&self.0.file, self.0.identity.length)? != self.0.identity {
            return Err(BackendError::Corrupt);
        }
        lease.check()?;
        Ok(lease)
    }
    /// Read exactly this pinned descriptor using independent positioned reads.
    /// The caller must bind its actual instance/generation/epoch and original
    /// deadline, then decrypt and verify the typed object address separately.
    pub fn read_ciphertext(&self) -> Result<Arc<Zeroizing<Vec<u8>>>, BackendError> {
        let lease = self.check()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            let mut bytes = Zeroizing::new(vec![0; self.0.identity.length]);
            let mut offset = 0;
            while offset < bytes.len() {
                lease.check()?;
                let read = match self.0.file.read_at(&mut bytes[offset..], offset as u64) {
                    Ok(read) => read,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(BackendError::Io),
                };
                if read == 0 {
                    return Err(BackendError::Corrupt);
                }
                offset += read;
            }
            self.check()?;
            lease.check()?;
            Ok(Arc::new(bytes))
        }
        #[cfg(not(unix))]
        {
            let _ = lease;
            Err(BackendError::Unsupported)
        }
    }
}

fn length_check(length: usize) -> Result<(), BackendError> {
    if length == 0 || length > MAX_IMMUTABLE_CIPHERTEXT_BYTES {
        Err(BackendError::Capacity)
    } else {
        Ok(())
    }
}
fn read_error(error: io::Error) -> BackendError {
    if error.kind() == io::ErrorKind::NotFound {
        BackendError::MissingArtifact
    } else {
        BackendError::Corrupt
    }
}
fn publication_error(error: ImmutablePublicationError) -> BackendError {
    match error {
        ImmutablePublicationError::BeforePublication(_) => BackendError::Corrupt,
        ImmutablePublicationError::OutcomeUnknown(_) => BackendError::OutcomeUnknown,
    }
}
pub(super) fn cleanup_temporary(directory: &ExclusiveDirectory) -> Result<(), BackendError> {
    directory
        .cleanup_immutable_temporary(TEMPORARY_LEAF)
        .map(|_| ())
        .map_err(publication_error)
}

impl FileBackend {
    pub fn immutable_blob_profile(&self) -> Result<ImmutableBlobProfile, BackendError> {
        self.verify()?;
        self.immutable_lease.check()?;
        let identity = self.directory.identity();
        let mut directory_identity = [0; 16];
        directory_identity[..8].copy_from_slice(&identity.device().to_le_bytes());
        directory_identity[8..].copy_from_slice(&identity.inode().to_le_bytes());
        self.verify()?;
        self.immutable_lease.check()?;
        Ok(ImmutableBlobProfile {
            directory_identity,
            max_ciphertext_bytes: MAX_IMMUTABLE_CIPHERTEXT_BYTES,
        })
    }

    fn pin_checked_file(
        &self,
        locator: BlobLocator,
        file: File,
        exact_len: usize,
    ) -> Result<ImmutableBlobReadPin, BackendError> {
        length_check(exact_len)?;
        let profile = self.immutable_blob_profile()?;
        let identity = object_identity(&file, exact_len)?;
        // A same-shaped descriptor supplied from another directory must not
        // acquire this backend's observed provenance or live lease.
        let named = self
            .directory
            .open_file(locator.leaf(), FileAccess::Read)
            .map_err(read_error)?;
        if object_identity(&named, exact_len)? != identity {
            return Err(BackendError::Corrupt);
        }
        self.verify()?;
        self.immutable_lease.check()?;
        Ok(ImmutableBlobReadPin(Arc::new(PinnedObject {
            file: named,
            locator,
            identity,
            directory_identity: profile.directory_identity,
            lease: Arc::downgrade(&self.immutable_lease),
        })))
    }

    pub fn pin_immutable_ciphertext(
        &self,
        locator: BlobLocator,
        exact_len: usize,
    ) -> Result<ImmutableBlobReadPin, BackendError> {
        length_check(exact_len)?;
        self.immutable_blob_profile()?;
        let file = self
            .directory
            .open_file(locator.leaf(), FileAccess::Read)
            .map_err(read_error)?;
        self.pin_checked_file(locator, file, exact_len)
    }

    /// Persist one bounded opaque ciphertext object, without replacing any
    /// existing leaf. This neither mutates the authenticated snapshot/root nor
    /// verifies the ciphertext's application domain or object address.
    pub fn stage_immutable_ciphertext(
        &mut self,
        locator: BlobLocator,
        ciphertext: &[u8],
    ) -> Result<ImmutableBlobStage, BackendError> {
        self.stage_immutable_ciphertext_checked(locator, ciphertext, || Ok(()))
    }

    // The public method's callback is always a no-op. Tests lose an actual
    // durable file publication acknowledgement here, rather than forging a
    // root, snapshot or in-memory recovery flag.
    fn stage_immutable_ciphertext_checked(
        &mut self,
        locator: BlobLocator,
        ciphertext: &[u8],
        after_publication: impl FnOnce() -> Result<(), BackendError>,
    ) -> Result<ImmutableBlobStage, BackendError> {
        length_check(ciphertext.len())?;
        self.immutable_blob_profile()?;
        let result = (|| {
            cleanup_temporary(&self.directory)?;
            let mut temporary = self
                .directory
                .open_file(TEMPORARY_LEAF, FileAccess::CreateNewReadWrite)
                .map_err(|_| BackendError::Io)?;
            if temporary.write_all(ciphertext).is_err() {
                cleanup_temporary(&self.directory)?;
                return Err(BackendError::Io);
            }
            let publication = self
                .directory
                .publish_file_noreplace(
                    TEMPORARY_LEAF,
                    &temporary,
                    locator.leaf(),
                    ciphertext.len() as u64,
                )
                .map_err(publication_error)?;
            after_publication().map_err(|_| BackendError::OutcomeUnknown)?;
            match publication {
                FilePublication::Published(file) => self
                    .pin_checked_file(locator, file, ciphertext.len())
                    .map(ImmutableBlobStage::Published)
                    .map_err(|_| BackendError::OutcomeUnknown),
                FilePublication::AlreadyExists(file) => self
                    .pin_checked_file(locator, file, ciphertext.len())
                    .map(ImmutableBlobStage::AlreadyExists)
                    .map_err(|_| BackendError::OutcomeUnknown),
            }
        })();
        if matches!(&result, Err(BackendError::OutcomeUnknown)) {
            self.immutable_lease.revoke();
        }
        result
    }
}

impl Drop for FileBackend {
    fn drop(&mut self) {
        self.immutable_lease.revoke();
    }
}

#[cfg(all(test, unix))]
#[path = "immutable_cipher_store_tests.rs"]
mod tests;
