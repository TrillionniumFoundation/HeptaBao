//! Physical immutable ciphertext storage on the existing FileBackend owner.
//!
//! A locator, profile, stage acknowledgement or read pin is not application
//! authority. This module never owns a barrier, address key or principal and
//! does not authenticate the bytes supplied to or read from the backend.
use super::{BackendError, FileBackend};
use heptabao_filesystem_guard::{
    ExclusiveDirectory, FileAccess, ImmutableBatchEntry, ImmutablePublication as FilePublication,
    ImmutablePublicationCheckedError, ImmutablePublicationError, MAX_IMMUTABLE_BATCH_OBJECTS,
};
use std::cell::Cell;
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

#[path = "immutable_cipher_reuse.rs"]
mod reuse;

/// A per-object physical bound. Existing snapshot/journal limits are unchanged.
pub const MAX_IMMUTABLE_CIPHERTEXT_BYTES: usize = 512 * 1024;
const TEMPORARY_LEAF: &str = "native-v6-object.tmp";
const BATCH_TEMPORARIES: [&str; MAX_IMMUTABLE_BATCH_OBJECTS] = [
    "native-v6-batch-0.tmp",
    "native-v6-batch-1.tmp",
    "native-v6-batch-2.tmp",
    "native-v6-batch-3.tmp",
    "native-v6-batch-4.tmp",
    "native-v6-batch-5.tmp",
    "native-v6-batch-6.tmp",
    "native-v6-batch-7.tmp",
    "native-v6-batch-8.tmp",
    "native-v6-batch-9.tmp",
    "native-v6-batch-10.tmp",
    "native-v6-batch-11.tmp",
    "native-v6-batch-12.tmp",
    "native-v6-batch-13.tmp",
    "native-v6-batch-14.tmp",
    "native-v6-batch-15.tmp",
    "native-v6-batch-16.tmp",
    "native-v6-batch-17.tmp",
    "native-v6-batch-18.tmp",
    "native-v6-batch-19.tmp",
    "native-v6-batch-20.tmp",
    "native-v6-batch-21.tmp",
    "native-v6-batch-22.tmp",
    "native-v6-batch-23.tmp",
    "native-v6-batch-24.tmp",
    "native-v6-batch-25.tmp",
    "native-v6-batch-26.tmp",
    "native-v6-batch-27.tmp",
    "native-v6-batch-28.tmp",
    "native-v6-batch-29.tmp",
    "native-v6-batch-30.tmp",
    "native-v6-batch-31.tmp",
];

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

/// Actual physical owner lineage, not a native layout or root admission.
/// Its private weak token can only be minted by the held FileBackend owner.
/// Keeping a profile alive does not retain its directory or writer lock.
#[derive(Clone)]
pub struct ImmutableBlobProfile {
    pub directory_identity: [u8; 16],
    pub max_ciphertext_bytes: usize,
    owner: Weak<ImmutableLease>,
}
impl ImmutableBlobProfile {
    pub fn is_live(&self) -> bool {
        self.owner
            .upgrade()
            .is_some_and(|owner| owner.check().is_ok())
    }
}
impl PartialEq for ImmutableBlobProfile {
    fn eq(&self, other: &Self) -> bool {
        self.directory_identity == other.directory_identity
            && self.max_ciphertext_bytes == other.max_ciphertext_bytes
            && Weak::ptr_eq(&self.owner, &other.owner)
    }
}
impl Eq for ImmutableBlobProfile {}
impl fmt::Debug for ImmutableBlobProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImmutableBlobProfile")
            .field("directory_identity", &"[DESCRIPTOR_BOUND]")
            .field("owner_instance", &"[PRIVATE_WEAK_OWNER]")
            .field("max_ciphertext_bytes", &self.max_ciphertext_bytes)
            .finish()
    }
}

/// Custody rejection is preserved separately from physical read failure.
pub enum PinReadError<E> {
    Backend(BackendError),
    Gate(E),
}
impl<E> fmt::Debug for PinReadError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Backend(_) => "PinReadError::Backend",
            Self::Gate(_) => "PinReadError::Gate",
        })
    }
}
impl<E> fmt::Display for PinReadError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Backend(_) => "immutable physical read failed",
            Self::Gate(_) => "immutable physical read custody rejected",
        })
    }
}
impl<E: std::error::Error + 'static> std::error::Error for PinReadError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Backend(error) => error,
            Self::Gate(error) => error,
        })
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

// A wire digest alone misses A -> B -> A rewrites spanning synchronization.
// This actual fstat witness is additional to, never a substitute for, both
// full descriptor reads and the caller's final AEAD/plaintext authentication.
// Do not include atime: the required real reads may legitimately change it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectMetadataWitness {
    identity: ObjectIdentity,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
}
#[cfg(unix)]
fn object_metadata_witness(
    file: &File,
    exact_len: usize,
) -> Result<ObjectMetadataWitness, BackendError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().map_err(|_| BackendError::Io)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != exact_len as u64 {
        return Err(BackendError::Corrupt);
    }
    Ok(ObjectMetadataWitness {
        identity: ObjectIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: exact_len,
        },
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
#[cfg(not(unix))]
fn object_metadata_witness(
    _file: &File,
    _exact_len: usize,
) -> Result<ObjectMetadataWitness, BackendError> {
    Err(BackendError::Unsupported)
}

struct PinnedObject {
    file: File,
    locator: BlobLocator,
    identity: ObjectIdentity,
    directory_identity: [u8; 16],
    lease: Weak<ImmutableLease>,
    // Only existing-leaf reuse pins carry this pre-sync wire commitment. A
    // dev/ino/length check cannot detect same-inode, same-length rewriting.
    // Actual checked reads must still read every byte and match this digest.
    synchronized_ciphertext_digest: Option<[u8; 32]>,
    // Reuse only: retained from before its first full read through both real
    // synchronization boundaries and the final checked read/AEAD gate.
    // Ordinary pins keep None and retain their original read semantics.
    synchronized_metadata: Option<ObjectMetadataWitness>,
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
    pub(crate) fn has_synchronized_ciphertext(&self) -> bool {
        self.0.synchronized_ciphertext_digest.is_some()
            && self.0.synchronized_metadata.is_some()
    }
    fn check(&self) -> Result<Arc<ImmutableLease>, BackendError> {
        let lease = self.0.lease.upgrade().ok_or(BackendError::Unavailable)?;
        lease.check()?;
        if object_identity(&self.0.file, self.0.identity.length)? != self.0.identity {
            return Err(BackendError::Corrupt);
        }
        if let Some(expected) = self.0.synchronized_metadata {
            if object_metadata_witness(&self.0.file, self.0.identity.length)? != expected {
                return Err(BackendError::Corrupt);
            }
        }
        lease.check()?;
        Ok(lease)
    }
    pub fn matches_profile(&self, profile: &ImmutableBlobProfile) -> bool {
        self.0.directory_identity == profile.directory_identity
            && self.0.identity.length <= profile.max_ciphertext_bytes
            && Weak::ptr_eq(&self.0.lease, &profile.owner)
            && profile.is_live()
            && self.check().is_ok()
    }
    /// Read exactly this pinned descriptor without selecting a Clock/Actor.
    /// The no-gate compatibility path still bounds consecutive EINTR retries.
    pub fn read_ciphertext(&self) -> Result<Arc<Zeroizing<Vec<u8>>>, BackendError> {
        let mut gate = || Ok::<(), std::convert::Infallible>(());
        self.read_ciphertext_checked(&mut gate)
            .map_err(|error| match error {
                PinReadError::Backend(error) => error,
                PinReadError::Gate(never) => match never {},
            })
    }
    /// Retain the caller's same original gate before and after every positioned
    /// read, including EINTR. No gate error exposes the partially filled buffer.
    pub fn read_ciphertext_checked<E, G>(
        &self,
        gate: &mut G,
    ) -> Result<Arc<Zeroizing<Vec<u8>>>, PinReadError<E>>
    where
        G: FnMut() -> Result<(), E> + ?Sized,
    {
        self.read_ciphertext_checked_observed(gate, &mut |_| {})
    }
    /// Observe the result of each actual positioned system read immediately
    /// after it returns, before a later original-gate or lease rejection.
    /// Byte counts and error kinds grant no custody or plaintext delivery.
    pub fn read_ciphertext_checked_observed<E, G, O>(
        &self,
        gate: &mut G,
        observe: &mut O,
    ) -> Result<Arc<Zeroizing<Vec<u8>>>, PinReadError<E>>
    where
        G: FnMut() -> Result<(), E> + ?Sized,
        O: FnMut(Result<usize, io::ErrorKind>) + ?Sized,
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.read_ciphertext_with_reader(gate, |file, bytes, offset| {
                let result = file.read_at(bytes, offset);
                observe(result.as_ref().copied().map_err(io::Error::kind));
                result
            })
        }
        #[cfg(not(unix))]
        {
            let _ = observe;
            gate().map_err(PinReadError::Gate)?;
            Err(PinReadError::Backend(BackendError::Unsupported))
        }
    }
    #[cfg(unix)]
    fn read_ciphertext_with_reader<E, G>(
        &self,
        gate: &mut G,
        mut read_at: impl FnMut(&File, &mut [u8], u64) -> io::Result<usize>,
    ) -> Result<Arc<Zeroizing<Vec<u8>>>, PinReadError<E>>
    where
        G: FnMut() -> Result<(), E> + ?Sized,
    {
        const MAX_INTERRUPTS: usize = 64;
        gate().map_err(PinReadError::Gate)?;
        let lease = self.check().map_err(PinReadError::Backend)?;
        gate().map_err(PinReadError::Gate)?;
        let mut bytes = Zeroizing::new(vec![0; self.0.identity.length]);
        let mut offset = 0;
        let mut interrupts = 0;
        while offset < bytes.len() {
            gate().map_err(PinReadError::Gate)?;
            lease.check().map_err(PinReadError::Backend)?;
            let read = read_at(&self.0.file, &mut bytes[offset..], offset as u64);
            gate().map_err(PinReadError::Gate)?;
            lease.check().map_err(PinReadError::Backend)?;
            match read {
                Ok(0) => return Err(PinReadError::Backend(BackendError::Corrupt)),
                Ok(read) if read <= bytes.len() - offset => {
                    offset += read;
                    interrupts = 0;
                }
                Ok(_) => return Err(PinReadError::Backend(BackendError::Corrupt)),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    interrupts += 1;
                    if interrupts >= MAX_INTERRUPTS {
                        return Err(PinReadError::Backend(BackendError::Io));
                    }
                }
                Err(_) => return Err(PinReadError::Backend(BackendError::Io)),
            }
        }
        gate().map_err(PinReadError::Gate)?;
        self.check().map_err(PinReadError::Backend)?;
        lease.check().map_err(PinReadError::Backend)?;
        if self.0.synchronized_ciphertext_digest.is_some_and(|expected| {
            crate::digest32(b"heptabao.immutable-reuse-ciphertext.v1", bytes.as_slice())
                != expected
        }) {
            return Err(PinReadError::Backend(BackendError::Corrupt));
        }
        gate().map_err(PinReadError::Gate)?;
        if self.0.synchronized_metadata.is_some() {
            // The final arbitrary caller gate may itself rewrite and restore
            // bytes. Keep the synchronization witness after that gate too.
            self.check().map_err(PinReadError::Backend)?;
        }
        Ok(Arc::new(bytes))
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
    for name in std::iter::once(TEMPORARY_LEAF).chain(BATCH_TEMPORARIES) {
        directory
            .cleanup_immutable_temporary(name)
            .map_err(publication_error)?;
    }
    Ok(())
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
            owner: Arc::downgrade(&self.immutable_lease),
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
            synchronized_ciphertext_digest: None,
            synchronized_metadata: None,
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

    /// No staged pin escapes until the thirty-two-or-fewer objects have completed
    /// the filesystem guard's strong durability barrier. This method does not
    /// publish an application root or authorize an imported archive.
    pub fn stage_immutable_ciphertext_batch_checked(
        &mut self,
        objects: &[(BlobLocator, &[u8])],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Vec<ImmutableBlobStage>, BackendError> {
        self.stage_immutable_ciphertext_batch_gate_impl(objects, gate, None)
    }

    /// Full owner checks at each object and publication boundary, with a
    /// separate bounded-I/O cancellation check around each write syscall.
    pub fn stage_immutable_ciphertext_batch_with_io_gate(
        &mut self,
        objects: &[(BlobLocator, &[u8])],
        full_gate: &mut dyn FnMut() -> Result<(), BackendError>,
        io_gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Vec<ImmutableBlobStage>, BackendError> {
        self.stage_immutable_ciphertext_batch_gate_impl(objects, full_gate, Some(io_gate))
    }

    fn stage_immutable_ciphertext_batch_gate_impl(
        &mut self,
        objects: &[(BlobLocator, &[u8])],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
        mut io_gate: Option<&mut dyn FnMut() -> Result<(), BackendError>>,
    ) -> Result<Vec<ImmutableBlobStage>, BackendError> {
        // Opening this backend already recovered EVERY reserved temporary.
        // Successful prior batches unlink them all. Avoid redoing 33 guarded
        // negative unlinkat checks for every 32-object batch. Failed or
        // interrupted batches ALWAYS require full recovery before reuse.
        let cleanup_needed = !self.immutable_batch_temps_known_clean;
        self.immutable_batch_temps_known_clean = false;
        let gate_rejected = Cell::new(false);
        let result = {
            let mut checked_gate = || {
                let result = gate();
                if result.is_err() {
                    gate_rejected.set(true);
                }
                result
            };
            (|| {
                checked_gate()?;
                if objects.is_empty() || objects.len() > MAX_IMMUTABLE_BATCH_OBJECTS {
                    return Err(BackendError::Capacity);
                }
                for (_, bytes) in objects {
                    length_check(bytes.len())?;
                }
                self.immutable_blob_profile()?;
                if cleanup_needed {
                    cleanup_temporary(&self.directory)?;
                }
                let mut files = Vec::with_capacity(objects.len());
                let mut destinations = Vec::with_capacity(objects.len());
                for (index, (locator, bytes)) in objects.iter().enumerate() {
                    checked_gate()?;
                    let mut file = self
                        .directory
                        .open_file(BATCH_TEMPORARIES[index], FileAccess::CreateNewReadWrite)
                        .map_err(|_| BackendError::Io)?;
                    let mut offset = 0;
                    let mut interrupts = 0;
                    {
                        let mut bounded_gate = || match io_gate.as_mut() {
                            Some(io) => {
                                let result = io();
                                if result.is_err() {
                                    gate_rejected.set(true);
                                }
                                result
                            }
                            None => checked_gate(),
                        };
                        while offset < bytes.len() {
                            bounded_gate()?;
                            let result = file.write(&bytes[offset..]);
                            bounded_gate()?;
                            match result {
                                Ok(n) if n > 0 && n <= bytes.len() - offset => {
                                    offset += n;
                                    interrupts = 0;
                                }
                                Err(e)
                                    if e.kind() == io::ErrorKind::Interrupted
                                        && interrupts < 64 =>
                                {
                                    interrupts += 1;
                                }
                                _ => return Err(BackendError::Io),
                            }
                        }
                    }
                    // A complete live full-owner check AFTER this object's
                    // actual write; no subsequent link on a stale Actor/seal.
                    checked_gate()?;
                    files.push(file);
                    destinations.push(locator.leaf());
                }
                let entries: Vec<_> = files
                    .iter()
                    .enumerate()
                    .map(|(index, file)| ImmutableBatchEntry {
                        temporary: BATCH_TEMPORARIES[index],
                        file,
                        destination: &destinations[index],
                        exact_len: objects[index].1.len() as u64,
                    })
                    .collect();
                let published = self
                    .directory
                    .publish_files_noreplace_checked(&entries, &mut checked_gate)
                    .map_err(|error| match error {
                        ImmutablePublicationCheckedError::Publication(error) => {
                            publication_error(error)
                        }
                        ImmutablePublicationCheckedError::GateBeforeLink(error)
                        | ImmutablePublicationCheckedError::GateAfterLink(error) => error,
                    })?;
                if published.len() != objects.len() {
                    return Err(BackendError::OutcomeUnknown);
                }
                let mut pins = Vec::with_capacity(objects.len());
                for (value, (locator, bytes)) in published.into_iter().zip(objects) {
                    checked_gate()?;
                    let pin = match value {
                        FilePublication::Published(file) => ImmutableBlobStage::Published(
                            self.pin_checked_file(*locator, file, bytes.len())
                                .map_err(|_| BackendError::OutcomeUnknown)?,
                        ),
                        FilePublication::AlreadyExists(file) => ImmutableBlobStage::AlreadyExists(
                            self.pin_checked_file(*locator, file, bytes.len())
                                .map_err(|_| BackendError::OutcomeUnknown)?,
                        ),
                    };
                    pins.push(pin);
                }
                checked_gate()?;
                Ok(pins)
            })()
        };
        if result.is_ok() {
            // The full publication barrier, every returned pin, and terminal
            // gate succeeded; every reserved temporary name was consumed.
            self.immutable_batch_temps_known_clean = true;
        }
        if !gate_rejected.get() && matches!(result, Err(BackendError::OutcomeUnknown)) {
            self.immutable_lease.revoke();
        }
        result
    }

    /// Persist one bounded opaque ciphertext object without replacing a leaf.
    /// This never writes or acknowledges an authenticated application root.
    pub fn stage_immutable_ciphertext(
        &mut self,
        locator: BlobLocator,
        ciphertext: &[u8],
    ) -> Result<ImmutableBlobStage, BackendError> {
        self.stage_immutable_ciphertext_checked(locator, ciphertext, &mut || Ok(()))
    }

    /// Retain the supplied gate throughout writes and final-link publication.
    /// Gate rejection after linking leaves an unadmitted object and does not
    /// become an uncertain canonical publication or revoke a healthy owner.
    pub fn stage_immutable_ciphertext_checked(
        &mut self,
        locator: BlobLocator,
        ciphertext: &[u8],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<ImmutableBlobStage, BackendError> {
        self.stage_immutable_ciphertext_with_ack_hook(locator, ciphertext, gate, || Ok(()))
    }

    fn stage_immutable_ciphertext_with_ack_hook(
        &mut self,
        locator: BlobLocator,
        ciphertext: &[u8],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
        after_publication: impl FnOnce() -> Result<(), BackendError>,
    ) -> Result<ImmutableBlobStage, BackendError> {
        // Ordinary staging shares the reserved single-file temporary; force
        // the next multi-object batch to recover all names conservatively.
        self.immutable_batch_temps_known_clean = false;
        let mut rejected_by_gate = false;
        let result = {
            let mut checked_gate = || {
                let result = gate();
                if result.is_err() {
                    rejected_by_gate = true;
                }
                result
            };
            (|| {
                checked_gate()?;
                length_check(ciphertext.len())?;
                self.immutable_blob_profile()?;
                checked_gate()?;
                cleanup_temporary(&self.directory)?;
                checked_gate()?;
                let mut temporary = self
                    .directory
                    .open_file(TEMPORARY_LEAF, FileAccess::CreateNewReadWrite)
                    .map_err(|_| BackendError::Io)?;
                checked_gate()?;
                let mut offset = 0;
                let mut interrupts = 0;
                while offset < ciphertext.len() {
                    checked_gate()?;
                    let written = temporary.write(&ciphertext[offset..]);
                    checked_gate()?;
                    match written {
                        Ok(0) => return Err(BackendError::Io),
                        Ok(written) if written <= ciphertext.len() - offset => {
                            offset += written;
                            interrupts = 0;
                        }
                        Ok(_) => return Err(BackendError::Io),
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                            interrupts += 1;
                            if interrupts >= 64 {
                                return Err(BackendError::Io);
                            }
                        }
                        Err(_) => return Err(BackendError::Io),
                    }
                }
                checked_gate()?;
                let publication = self
                    .directory
                    .publish_file_noreplace_checked(
                        TEMPORARY_LEAF,
                        &temporary,
                        locator.leaf(),
                        ciphertext.len() as u64,
                        &mut checked_gate,
                    )
                    .map_err(|error| match error {
                        ImmutablePublicationCheckedError::Publication(error) => {
                            publication_error(error)
                        }
                        ImmutablePublicationCheckedError::GateBeforeLink(error)
                        | ImmutablePublicationCheckedError::GateAfterLink(error) => error,
                    })?;
                after_publication().map_err(|_| BackendError::OutcomeUnknown)?;
                checked_gate()?;
                let staged = match publication {
                    FilePublication::Published(file) => self
                        .pin_checked_file(locator, file, ciphertext.len())
                        .map(ImmutableBlobStage::Published)
                        .map_err(|_| BackendError::OutcomeUnknown),
                    FilePublication::AlreadyExists(file) => self
                        .pin_checked_file(locator, file, ciphertext.len())
                        .map(ImmutableBlobStage::AlreadyExists)
                        .map_err(|_| BackendError::OutcomeUnknown),
                }?;
                checked_gate()?;
                Ok(staged)
            })()
        };
        if !rejected_by_gate && matches!(&result, Err(BackendError::OutcomeUnknown)) {
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
