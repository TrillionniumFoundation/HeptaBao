//! Durable no-replace publication on the existing directory descriptor.
//!
//! These operations prove physical identity and durability only. The caller
//! must authenticate the returned file's contents before publishing a root.
use super::ExclusiveDirectory;
#[cfg(unix)]
use super::FileAccess;
use std::{fmt, fs::File, io, path::Path};

/// One bounded physical strong-sync unit holds at most thirty-two objects.
/// Every file is independently fsynced and no pin escapes before the final
/// device barrier; the original caller gate remains live at each mutation.
pub const MAX_IMMUTABLE_BATCH_OBJECTS: usize = 32;

/// The actual read-only descriptor observed at the immutable destination.
pub enum ImmutablePublication {
    Published(File),
    /// Contents were not compared with the temporary file or authenticated.
    AlreadyExists(File),
}
impl fmt::Debug for ImmutablePublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Published(_) => "ImmutablePublication::Published([READ_ONLY_FD])",
            Self::AlreadyExists(_) => "ImmutablePublication::AlreadyExists([READ_ONLY_FD])",
        })
    }
}

/// Opaque identity captured BEFORE a real synchronization of one new file.
/// Retaining this value across layers avoids sampling a new baseline after
/// the physical barrier. It proves no plaintext, authority or root admission.
#[derive(Clone)]
pub struct ImmutableFileSyncWitness {
    #[cfg(unix)]
    identity: PublishedContentIdentity,
    mutations: super::FileMutationWitness,
    _private: (),
}
impl fmt::Debug for ImmutableFileSyncWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImmutableFileSyncWitness([ORIGINAL_SYNCHRONIZED_IDENTITY])")
    }
}
impl ImmutableFileSyncWitness {
    /// Compare the supplied actual descriptor with the original pre-sync
    /// identity. This never refreshes the witness or synchronizes a new fd.
    pub fn verify_file(&self, file: &File) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.mutations.verify_file(file)?;
            if PublishedContentIdentity::read(file, self.identity.identity.length)? != self.identity
            {
                return Err(io::Error::other("immutable synchronized identity changed"));
            }
            self.mutations.verify_file(file)
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            Err(io::Error::other(
                super::DirectoryGuardError::UnsupportedPlatform,
            ))
        }
    }
}

/// One newly published read-only descriptor together with the SAME opaque
/// witness that crossed its actual per-fd, device and directory barriers.
/// Only this module can create the pair; consumers must keep the witness.
pub struct SynchronizedImmutablePublication {
    file: File,
    witness: ImmutableFileSyncWitness,
}
impl fmt::Debug for SynchronizedImmutablePublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SynchronizedImmutablePublication([READ_ONLY_FD_WITH_SYNC_WITNESS])")
    }
}
impl SynchronizedImmutablePublication {
    pub fn into_parts(self) -> (File, ImmutableFileSyncWitness) {
        (self.file, self.witness)
    }
}

// Only the completed new-batch classification below creates this marker.
// An arbitrary I/O error whose kind happens to be AlreadyExists must remain
// OutcomeUnknown; neither error strings nor generic errno authorize a retry.
#[derive(Debug)]
struct NewBatchDestinationCollision;
impl fmt::Display for NewBatchDestinationCollision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("new immutable batch destination appeared during publication")
    }
}
impl std::error::Error for NewBatchDestinationCollision {}

/// A final-link or durability acknowledgement failure must not be retried as
/// if no destination could have been published.
#[derive(Debug)]
pub enum ImmutablePublicationError {
    BeforePublication(io::Error),
    OutcomeUnknown(io::Error),
}
impl fmt::Display for ImmutablePublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BeforePublication(_) => "immutable file publication rejected before final link",
            Self::OutcomeUnknown(_) => "immutable file publication outcome is unknown",
        })
    }
}
impl std::error::Error for ImmutablePublicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::BeforePublication(error) | Self::OutcomeUnknown(error) => error,
        })
    }
}

/// Gate rejection before a new final link leaves no new publication. A
/// rejection after that link leaves an unadmitted immutable object, not an
/// acknowledgement of an application root or an uncertain I/O result.
pub enum ImmutablePublicationCheckedError<E> {
    Publication(ImmutablePublicationError),
    GateBeforeLink(E),
    GateAfterLink(E),
}
impl<E> fmt::Debug for ImmutablePublicationCheckedError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Publication(_) => "ImmutablePublicationCheckedError::Publication",
            Self::GateBeforeLink(_) => "ImmutablePublicationCheckedError::GateBeforeLink",
            Self::GateAfterLink(_) => "ImmutablePublicationCheckedError::GateAfterLink",
        })
    }
}
impl<E> fmt::Display for ImmutablePublicationCheckedError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Publication(_) => "immutable publication I/O failed",
            Self::GateBeforeLink(_) => "immutable publication gate rejected before final link",
            Self::GateAfterLink(_) => "immutable publication gate rejected after final link",
        })
    }
}
impl<E: std::error::Error + 'static> std::error::Error for ImmutablePublicationCheckedError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Publication(error) => error,
            Self::GateBeforeLink(error) | Self::GateAfterLink(error) => error,
        })
    }
}

fn validated_leaf(path: &Path) -> io::Result<&str> {
    let name = path
        .to_str()
        .ok_or_else(|| io::Error::other("non-UTF-8 immutable leaf"))?;
    super::validate_leaf(name).map_err(io::Error::other)?;
    Ok(name)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
}
#[cfg(unix)]
fn checked_identity(file: &File, expected_len: u64, links: u64) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != links || metadata.len() != expected_len {
        return Err(io::Error::other("immutable file descriptor shape changed"));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
    })
}
#[cfg(unix)]
fn same_identity(file: &File, expected: FileIdentity, links: u64) -> io::Result<()> {
    if checked_identity(file, expected.length, links)? != expected {
        return Err(io::Error::other(
            "immutable file descriptor identity changed",
        ));
    }
    Ok(())
}

/// A new publication's content witness is captured only after all of our
/// link/unlink operations, and BEFORE a fresh sync of every published fd.
/// No later operation may legitimately change these fields. In particular,
/// equal bytes after A->B->A do not preserve this synchronization witness.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublishedContentIdentity {
    identity: FileIdentity,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
}

#[cfg(unix)]
impl PublishedContentIdentity {
    fn read(file: &File, expected_len: u64) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != expected_len {
            return Err(io::Error::other("new immutable publication shape changed"));
        }
        Ok(Self {
            identity: FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
            },
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

/// One borrowed temporary descriptor. A batch entry is not a durability receipt.
pub struct ImmutableBatchEntry<'a> {
    pub temporary: &'a str,
    pub file: &'a File,
    pub destination: &'a str,
    pub exact_len: u64,
}

impl fmt::Debug for ImmutableBatchEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImmutableBatchEntry([BOUNDED_BORROWED_DESCRIPTOR])")
    }
}

#[cfg(unix)]
struct PublicationHooks<B, A> {
    before: B,
    after: A,
    buffered: bool,
}

#[cfg(unix)]
fn sync_file(file: &File, buffered: bool) -> io::Result<()> {
    if buffered {
        rustix::fs::fsync(file).map_err(io::Error::from)
    } else {
        file.sync_all()
    }
}

#[cfg(target_os = "macos")]
fn verify_strict_new_batch_device(
    directory: super::DirectoryIdentity,
    witnesses: &[ImmutableFileSyncWitness],
    expected_count: usize,
) -> io::Result<()> {
    // These are the ORIGINAL actual-fd captures made before the linked-file
    // fsyncs, not new metadata samples or caller-asserted device identities.
    if expected_count == 0
        || expected_count > MAX_IMMUTABLE_BATCH_OBJECTS
        || witnesses.len() != expected_count
        || witnesses
            .iter()
            .any(|witness| witness.identity.identity.device != directory.device())
    {
        return Err(io::Error::other(
            "strict new batch does not share the held directory device",
        ));
    }
    Ok(())
}

/// Only the opaque temporary file descriptors are used in worker threads.
/// No authorization closure or mutable directory state ever crosses threads.
/// All workers MUST join before any final name is linked; a panic or I/O error
/// is a before-publication refusal, not a partially committed application root.
#[cfg(unix)]
const MAX_PARALLEL_TEMP_FSYNC: usize = 4;

#[cfg(unix)]
fn preflush_batch_temporaries<E, G, F>(
    entries: &[ImmutableBatchEntry<'_>],
    gate: &mut G,
    sync_one: &F,
) -> Result<(), ImmutablePublicationCheckedError<E>>
where
    G: FnMut() -> Result<(), E> + ?Sized,
    F: Fn(&File) -> io::Result<()> + Sync,
{
    for chunk in entries.chunks(MAX_PARALLEL_TEMP_FSYNC) {
        for _ in chunk {
            gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
        }
        let results: Vec<io::Result<()>> = std::thread::scope(|scope| {
            let jobs: Vec<_> = chunk
                .iter()
                .map(|entry| scope.spawn(move || sync_one(entry.file)))
                .collect();
            // Join EVERY worker, even if an earlier worker failed. Never let an
            // unfinished fsync coexist with a final-link action or cleanup.
            jobs.into_iter()
                .map(|job| {
                    job.join().unwrap_or_else(|_| {
                        Err(io::Error::other("immutable fsync worker panicked"))
                    })
                })
                .collect()
        });
        for result in results {
            result.map_err(|error| {
                ImmutablePublicationCheckedError::Publication(
                    ImmutablePublicationError::BeforePublication(error),
                )
            })?;
            gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
        }
    }
    Ok(())
}

/// Strict new-file publication obtains a fresh proof after the last link and
/// unlink. The earlier temporary fsyncs are retained, but their identity
/// cannot safely be reconstructed after link-count changes and caller gates.
/// Existing destinations never enter this path: a raced EEXIST is unknown.
#[cfg(unix)]
fn sync_new_publications<E, G>(
    directory: &ExclusiveDirectory,
    entries: &[ImmutableBatchEntry<'_>],
    published: &[ImmutablePublication],
    gate: &mut G,
) -> Result<Vec<ImmutableFileSyncWitness>, ImmutablePublicationCheckedError<E>>
where
    G: FnMut() -> Result<(), E> + ?Sized,
{
    let unknown = |error| {
        ImmutablePublicationCheckedError::Publication(ImmutablePublicationError::OutcomeUnknown(
            error,
        ))
    };
    if entries.len() != published.len() {
        return Err(unknown(io::Error::other(
            "new publication batch length changed",
        )));
    }
    // Complete this classification and capture before the next caller gate.
    // None of the fds below can be a pre-existing or raced destination.
    let files: Vec<&File> = published
        .iter()
        .map(|publication| match publication {
            ImmutablePublication::Published(file) => Ok(file),
            ImmutablePublication::AlreadyExists(_) => Err(unknown(io::Error::new(
                io::ErrorKind::AlreadyExists,
                NewBatchDestinationCollision,
            ))),
        })
        .collect::<Result<_, _>>()?;
    let identities = files
        .iter()
        .zip(entries)
        .map(|(file, entry)| {
            // All our own links/unlinks and initialization writes are finished.
            // Register before the ORIGINAL identity capture and real syncs.
            let mutations = directory.watch_file_mutations(file).map_err(unknown)?;
            let identity =
                PublishedContentIdentity::read(file, entry.exact_len).map_err(unknown)?;
            mutations.verify_file(file).map_err(unknown)?;
            Ok(ImmutableFileSyncWitness {
                identity,
                mutations,
                _private: (),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    for chunk in files.chunks(MAX_PARALLEL_TEMP_FSYNC) {
        for _ in chunk {
            gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
        }
        let results: Vec<io::Result<()>> = std::thread::scope(|scope| {
            let jobs: Vec<_> = chunk
                .iter()
                .map(|file| scope.spawn(move || sync_file(file, true)))
                .collect();
            // Join every real fsync before inspecting any result or gate.
            jobs.into_iter()
                .map(|job| {
                    job.join().unwrap_or_else(|_| {
                        Err(io::Error::other("new immutable fsync worker panicked"))
                    })
                })
                .collect()
        });
        for result in results {
            result.map_err(unknown)?;
            gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
        }
    }
    Ok(identities)
}

impl ExclusiveDirectory {
    /// Sync the caller's exact temporary descriptor, publish its leaf without
    /// replacing any destination, unlink the temporary name and sync the held
    /// directory. Both names must be different validated single leaves.
    ///
    /// Success returns a read-only descriptor, after device/inode/length and
    /// link-count checks against the descriptor that was actually synced.
    /// AlreadyExists preserves the destination and returns its descriptor;
    /// the caller must separately authenticate it. Neither variant authenticates
    /// ciphertext or grants authority to publish an application root.
    pub fn publish_file_noreplace(
        &self,
        temporary: impl AsRef<Path>,
        opened_temporary: &File,
        destination: impl AsRef<Path>,
        exact_len: u64,
    ) -> Result<ImmutablePublication, ImmutablePublicationError> {
        let mut gate = || Ok::<(), std::convert::Infallible>(());
        self.publish_file_noreplace_checked(
            temporary,
            opened_temporary,
            destination,
            exact_len,
            &mut gate,
        )
        .map_err(|error| match error {
            ImmutablePublicationCheckedError::Publication(error) => error,
            ImmutablePublicationCheckedError::GateBeforeLink(never)
            | ImmutablePublicationCheckedError::GateAfterLink(never) => match never {},
        })
    }

    /// Retain the caller's same gate before and after each sync, final link and
    /// unlink. This method does not create, select or extend any Clock/Actor.
    pub fn publish_file_noreplace_checked<E, G>(
        &self,
        temporary: impl AsRef<Path>,
        opened_temporary: &File,
        destination: impl AsRef<Path>,
        exact_len: u64,
        gate: &mut G,
    ) -> Result<ImmutablePublication, ImmutablePublicationCheckedError<E>>
    where
        G: FnMut() -> Result<(), E> + ?Sized,
    {
        let before = |error| {
            ImmutablePublicationCheckedError::Publication(
                ImmutablePublicationError::BeforePublication(error),
            )
        };
        gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
        let temporary = validated_leaf(temporary.as_ref()).map_err(before)?;
        let destination = validated_leaf(destination.as_ref()).map_err(before)?;
        if temporary == destination {
            return Err(before(io::Error::other(
                "immutable temporary and destination must differ",
            )));
        }
        #[cfg(unix)]
        {
            self.publish_file_noreplace_with_hooks(
                temporary,
                opened_temporary,
                destination,
                exact_len,
                gate,
                (|| Ok(()), || Ok(())),
            )
        }
        #[cfg(not(unix))]
        {
            let _ = (temporary, opened_temporary, destination, exact_len, gate);
            Err(before(io::Error::other(
                super::DirectoryGuardError::UnsupportedPlatform,
            )))
        }
    }

    #[cfg(unix)]
    fn immutable_leaf_with_links(
        &self,
        name: &str,
        exact_len: u64,
        links: u64,
    ) -> io::Result<File> {
        use rustix::fs::{Mode, OFlags, openat};
        self.verify().map_err(io::Error::other)?;
        let file = File::from(openat(
            &self.handle,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?);
        checked_identity(&file, exact_len, links)?;
        self.verify().map_err(io::Error::other)?;
        Ok(file)
    }

    // Hooks make actual filesystem mutation windows observable in tests. The
    // public entry points use no-op hooks; the real caller gate is separate.
    #[cfg(unix)]
    fn publish_file_noreplace_with_hooks<E, G>(
        &self,
        temporary: &str,
        opened_temporary: &File,
        destination: &str,
        exact_len: u64,
        gate: &mut G,
        hooks: (
            impl FnOnce() -> io::Result<()>,
            impl FnOnce() -> io::Result<()>,
        ),
    ) -> Result<ImmutablePublication, ImmutablePublicationCheckedError<E>>
    where
        G: FnMut() -> Result<(), E> + ?Sized,
    {
        self.publish_file_noreplace_with_hooks_and_sync(
            temporary,
            opened_temporary,
            destination,
            exact_len,
            gate,
            PublicationHooks {
                before: hooks.0,
                after: hooks.1,
                buffered: false,
            },
        )
    }

    #[cfg(unix)]
    fn publish_file_noreplace_with_hooks_and_sync<E, G>(
        &self,
        temporary: &str,
        opened_temporary: &File,
        destination: &str,
        exact_len: u64,
        gate: &mut G,
        hooks: PublicationHooks<impl FnOnce() -> io::Result<()>, impl FnOnce() -> io::Result<()>>,
    ) -> Result<ImmutablePublication, ImmutablePublicationCheckedError<E>>
    where
        G: FnMut() -> Result<(), E> + ?Sized,
    {
        use rustix::fs::{AtFlags, linkat};
        let before = |error| {
            ImmutablePublicationCheckedError::Publication(
                ImmutablePublicationError::BeforePublication(error),
            )
        };
        let unknown = |error| {
            ImmutablePublicationCheckedError::Publication(
                ImmutablePublicationError::OutcomeUnknown(error),
            )
        };
        let PublicationHooks {
            before: before_link,
            after: after_link,
            buffered,
        } = hooks;
        gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
        self.verify().map_err(io::Error::other).map_err(before)?;
        let identity = checked_identity(opened_temporary, exact_len, 1).map_err(before)?;
        // The guarded batch caller already proved the exact temporary name
        // and descriptor match BEFORE preflush, and joined every completed
        // fsync before calling this method. Repeating this first reopen and
        // its full authorization read adds no further admission boundary:
        // the final reopen, identity check and live gate immediately before
        // linkat BELOW are retained. Ordinary single-file publication keeps
        // its original first reopen and pre/post sync authorization checks.
        if !buffered {
            let named = self
                .open_file(temporary, FileAccess::Read)
                .map_err(before)?;
            same_identity(&named, identity, 1).map_err(before)?;
            gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
            sync_file(opened_temporary, false).map_err(before)?;
        }
        gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
        same_identity(opened_temporary, identity, 1).map_err(before)?;
        let named = self
            .open_file(temporary, FileAccess::Read)
            .map_err(before)?;
        same_identity(&named, identity, 1).map_err(before)?;
        before_link().map_err(before)?;
        // A temp sync can take longer than the original deadline. Recheck the
        // same caller gate at the actual final-link boundary, not a new clock.
        gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
        match linkat(
            &self.handle,
            temporary,
            &self.handle,
            destination,
            AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::EXIST => {
                gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
                let existing = self
                    .open_file(destination, FileAccess::Read)
                    .map_err(before)?;
                let existing_identity =
                    checked_identity(&existing, exact_len, 1).map_err(before)?;
                let named = self
                    .open_file(temporary, FileAccess::Read)
                    .map_err(before)?;
                same_identity(&named, identity, 1).map_err(before)?;
                gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
                self.remove_file(temporary).map_err(unknown)?;
                gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
                same_identity(opened_temporary, identity, 0).map_err(unknown)?;
                gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
                // A buffered batch never acknowledges any pin before its
                // final strong file/device and directory barriers. Each
                // member was already fsynced before linkat; defer the
                // post-link metadata fsync to that one final directory sync.
                // Ordinary single-file publication retains both syncs.
                if !buffered {
                    sync_file(&existing, false).map_err(unknown)?;
                    gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
                    gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
                    self.sync_batch_directory(false).map_err(unknown)?;
                }
                gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
                let current = self
                    .open_file(destination, FileAccess::Read)
                    .map_err(unknown)?;
                same_identity(&current, existing_identity, 1).map_err(unknown)?;
                same_identity(&existing, existing_identity, 1).map_err(unknown)?;
                return Ok(ImmutablePublication::AlreadyExists(existing));
            }
            Err(error) => return Err(unknown(error.into())),
        }
        after_link().map_err(unknown)?;
        gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
        same_identity(opened_temporary, identity, 2).map_err(unknown)?;
        let published = self
            .immutable_leaf_with_links(destination, exact_len, 2)
            .map_err(unknown)?;
        same_identity(&published, identity, 2).map_err(unknown)?;
        let named = self
            .immutable_leaf_with_links(temporary, exact_len, 2)
            .map_err(unknown)?;
        same_identity(&named, identity, 2).map_err(unknown)?;
        gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
        self.remove_file(temporary).map_err(unknown)?;
        gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
        same_identity(opened_temporary, identity, 1).map_err(unknown)?;
        same_identity(&published, identity, 1).map_err(unknown)?;
        gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
        // The buffered caller holds all returned descriptors privately until
        // its final strong barrier and directory fsync complete. Retain all
        // live gate and post-link identity checks without issuing redundant
        // per-object post-link fsyncs. Failure remains OutcomeUnknown and
        // no application root or public acknowledgement may be published.
        if !buffered {
            sync_file(&published, false).map_err(unknown)?;
            gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
            gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
            self.sync_batch_directory(false).map_err(unknown)?;
        }
        gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
        let current = self
            .open_file(destination, FileAccess::Read)
            .map_err(unknown)?;
        same_identity(&current, identity, 1).map_err(unknown)?;
        same_identity(&published, identity, 1).map_err(unknown)?;
        Ok(ImmutablePublication::Published(published))
    }

    #[cfg(unix)]
    fn sync_batch_directory(&self, buffered: bool) -> io::Result<()> {
        self.verify().map_err(io::Error::other)?;
        sync_file(&self.handle, buffered)?;
        self.verify().map_err(io::Error::other)
    }

    /// Publish at most thirty-two 512KiB files as one physical durability unit.
    /// No descriptor or success receipt escapes until all file data/metadata
    /// and directory changes have been synced and a final strong device flush
    /// completes. On Apple, raw fsync moves data to the device; File::sync_all
    /// then requests F_FULLFSYNC for all previously fsynced data on that device.
    /// On other Unix platforms the earlier fsync calls already retain their
    /// native strength. Ordinary single-file publication remains unchanged.
    /// A failed batch can leave unreferenced leaves, never an application root.
    pub fn publish_files_noreplace_checked<E, G>(
        &self,
        entries: &[ImmutableBatchEntry<'_>],
        gate: &mut G,
    ) -> Result<Vec<ImmutablePublication>, ImmutablePublicationCheckedError<E>>
    where
        G: FnMut() -> Result<(), E> + ?Sized,
    {
        self.publish_files_noreplace_with_final_sync(entries, gate, &mut |file| file.sync_all())
    }

    /// Publish only NEW files and retain an exact content-identity witness
    /// across every callback after their final per-fd synchronization. This
    /// strict path keeps the ordinary batch's temporary preflush, adds a
    /// bounded parallel real fsync of each newly linked descriptor, and keeps
    /// its strong device and directory barriers. All callbacks finish before
    /// the final held-fd/current-name metadata check. A raced existing leaf
    /// returns OutcomeUnknown without entering that fresh per-fd sync path.
    /// The caller must still authenticate every returned file's contents.
    pub fn publish_new_files_noreplace_checked<E, G>(
        &self,
        entries: &[ImmutableBatchEntry<'_>],
        gate: &mut G,
    ) -> Result<Vec<ImmutablePublication>, ImmutablePublicationCheckedError<E>>
    where
        G: FnMut() -> Result<(), E> + ?Sized,
    {
        self.publish_files_noreplace_with_sync_mode(
            entries,
            gate,
            &mut |file| file.sync_all(),
            true,
            None,
        )
    }

    /// Strict new-only publication with the original synchronization witness
    /// transferred to the caller alongside each actual read-only descriptor.
    /// Some means every new descriptor completed the full strict protocol.
    /// None is only the explicit, completed classification of a raced
    /// destination: all temporary names were consumed, but no pin or success
    /// receipt is returned and unadmitted new leaves may remain. It is NOT a
    /// claim that nothing was linked and must not trigger an automatic retry.
    pub fn publish_new_files_noreplace_with_witness_checked<E, G>(
        &self,
        entries: &[ImmutableBatchEntry<'_>],
        gate: &mut G,
    ) -> Result<Option<Vec<SynchronizedImmutablePublication>>, ImmutablePublicationCheckedError<E>>
    where
        G: FnMut() -> Result<(), E> + ?Sized,
    {
        let mut witnesses = Vec::new();
        let published = match self.publish_files_noreplace_with_sync_mode(
            entries,
            gate,
            &mut |file| file.sync_all(),
            true,
            Some(&mut witnesses),
        ) {
            Ok(published) => published,
            Err(ImmutablePublicationCheckedError::Publication(
                ImmutablePublicationError::OutcomeUnknown(error),
            )) if error.get_ref().is_some_and(|source| {
                source
                    .downcast_ref::<NewBatchDestinationCollision>()
                    .is_some()
            }) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let unknown = || {
            ImmutablePublicationCheckedError::Publication(
                ImmutablePublicationError::OutcomeUnknown(io::Error::other(
                    "new publication synchronization proof changed shape",
                )),
            )
        };
        if published.len() != entries.len() || witnesses.len() != entries.len() {
            return Err(unknown());
        }
        published
            .into_iter()
            .zip(witnesses)
            .map(|(publication, witness)| match publication {
                ImmutablePublication::Published(file) => {
                    Ok(SynchronizedImmutablePublication { file, witness })
                }
                ImmutablePublication::AlreadyExists(_) => Err(unknown()),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    fn publish_files_noreplace_with_final_sync<E, G, S>(
        &self,
        entries: &[ImmutableBatchEntry<'_>],
        gate: &mut G,
        strong_sync: &mut S,
    ) -> Result<Vec<ImmutablePublication>, ImmutablePublicationCheckedError<E>>
    where
        G: FnMut() -> Result<(), E> + ?Sized,
        S: FnMut(&File) -> io::Result<()>,
    {
        self.publish_files_noreplace_with_sync_mode(entries, gate, strong_sync, false, None)
    }

    fn publish_files_noreplace_with_sync_mode<E, G, S>(
        &self,
        entries: &[ImmutableBatchEntry<'_>],
        gate: &mut G,
        strong_sync: &mut S,
        require_new_content_witness: bool,
        retained_witnesses: Option<&mut Vec<ImmutableFileSyncWitness>>,
    ) -> Result<Vec<ImmutablePublication>, ImmutablePublicationCheckedError<E>>
    where
        G: FnMut() -> Result<(), E> + ?Sized,
        S: FnMut(&File) -> io::Result<()>,
    {
        let before = |e| {
            ImmutablePublicationCheckedError::Publication(
                ImmutablePublicationError::BeforePublication(e),
            )
        };
        #[cfg(not(unix))]
        {
            let _ = (
                entries,
                gate,
                strong_sync,
                require_new_content_witness,
                retained_witnesses,
            );
            Err(before(io::Error::other("unsupported batch platform")))
        }
        #[cfg(unix)]
        {
            gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
            if entries.is_empty() || entries.len() > MAX_IMMUTABLE_BATCH_OBJECTS {
                return Err(before(io::Error::other("invalid bounded batch length")));
            }
            self.verify().map_err(io::Error::other).map_err(before)?;
            let mut names = std::collections::BTreeSet::new();
            for e in entries {
                for name in [e.temporary, e.destination] {
                    validated_leaf(Path::new(name)).map_err(before)?;
                    if !names.insert(name) {
                        return Err(before(io::Error::other("aliased batch leaves")));
                    }
                }
                if e.exact_len == 0 || e.exact_len > 512 * 1024 {
                    return Err(before(io::Error::other("batch member exceeds bound")));
                }
                let expected = checked_identity(e.file, e.exact_len, 1).map_err(before)?;
                let named = self
                    .open_file(e.temporary, FileAccess::Read)
                    .map_err(before)?;
                same_identity(&named, expected, 1).map_err(before)?;
            }
            // All temporary bytes must reach stable storage before any
            // name gains a final link. The original non-Send owner/ACL/seal
            // gate runs on the caller thread before and after each batch.
            preflush_batch_temporaries(entries, gate, &|file| sync_file(file, true))?;
            gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
            let unknown = |e| {
                ImmutablePublicationCheckedError::Publication(
                    ImmutablePublicationError::OutcomeUnknown(e),
                )
            };
            let mut published = Vec::with_capacity(entries.len());
            for e in entries {
                let result = self.publish_file_noreplace_with_hooks_and_sync(
                    e.temporary,
                    e.file,
                    e.destination,
                    e.exact_len,
                    gate,
                    PublicationHooks {
                        before: || Ok(()),
                        after: || Ok(()),
                        buffered: true,
                    },
                );
                let result = result.map_err(|error| {
                    if published.is_empty() {
                        return error;
                    }
                    match error {
                        ImmutablePublicationCheckedError::GateBeforeLink(e) => {
                            ImmutablePublicationCheckedError::GateAfterLink(e)
                        }
                        ImmutablePublicationCheckedError::Publication(
                            ImmutablePublicationError::BeforePublication(e),
                        ) => unknown(e),
                        e => e,
                    }
                })?;
                published.push(result);
            }
            let content_identities = if require_new_content_witness {
                Some(sync_new_publications(self, entries, &published, gate)?)
            } else {
                None
            };
            // The first regular file belongs to the same held directory/device.
            // Flush previously fsynced members and names before exposing any pin.
            gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
            let first = match &published[0] {
                ImmutablePublication::Published(f) | ImmutablePublication::AlreadyExists(f) => f,
            };
            #[cfg(target_os = "macos")]
            {
                if require_new_content_witness {
                    let witnesses = content_identities.as_deref().ok_or_else(|| {
                        unknown(io::Error::other("strict new batch has no sync witnesses"))
                    })?;
                    verify_strict_new_batch_device(self.identity(), witnesses, published.len())
                        .map_err(unknown)?;
                    // Every actual file has already crossed its original raw
                    // pre/post-link fsyncs. Flush this SAME held directory with
                    // raw fsync before the final same-device F_FULLFSYNC.
                    // No pin escapes until the unchanged post-callback fd,
                    // current-name and original mutation-witness checks below.
                    // Any failure remains terminal; no weaker sync is retried.
                    self.sync_batch_directory(true).map_err(unknown)?;
                    gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
                    strong_sync(first).map_err(unknown)?;
                } else {
                    // Existing/non-strict batches retain their old protocol.
                    strong_sync(first).map_err(unknown)?;
                    gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
                    self.sync_all().map_err(io::Error::other).map_err(unknown)?;
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                strong_sync(first).map_err(unknown)?;
                gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
                self.sync_all().map_err(io::Error::other).map_err(unknown)?;
            }
            gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
            for (e, result) in entries.iter().zip(&published) {
                let file = match result {
                    ImmutablePublication::Published(f) | ImmutablePublication::AlreadyExists(f) => {
                        f
                    }
                };
                let expected = checked_identity(file, e.exact_len, 1).map_err(unknown)?;
                let named = self
                    .open_file(e.destination, FileAccess::Read)
                    .map_err(unknown)?;
                same_identity(&named, expected, 1).map_err(unknown)?;
                gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
            }
            if let Some(identities) = content_identities {
                // No caller callback occurs during or after this whole pass.
                // Read the original fd AND the actual current leaf name so a
                // late same-inode ABA or equal-content replacement cannot be
                // relabelled as the descriptor that crossed the real syncs.
                self.verify().map_err(io::Error::other).map_err(unknown)?;
                for ((entry, publication), expected) in
                    entries.iter().zip(&published).zip(&identities)
                {
                    let ImmutablePublication::Published(file) = publication else {
                        return Err(unknown(io::Error::other("new publication changed kind")));
                    };
                    let named = self
                        .open_file(entry.destination, FileAccess::Read)
                        .map_err(unknown)?;
                    expected.verify_file(file).map_err(unknown)?;
                    expected.verify_file(&named).map_err(unknown)?;
                }
                self.verify().map_err(io::Error::other).map_err(unknown)?;
                if let Some(output) = retained_witnesses {
                    // Transfer the ORIGINAL capture, never a post-barrier
                    // fstat sample. There is no callback or new sync here.
                    *output = identities;
                }
            }
            Ok(published)
        }
    }

    /// Unlink only a known, validated temporary leaf and sync the held
    /// directory. A symlink is unlinked without following it. This recovers a
    /// crash after linkat: removing the temporary name leaves a singly-linked
    /// destination, which still requires normal guarded read/authentication.
    /// The caller chooses its fixed reserved temporary name, not an inventory
    /// entry or a name supplied by an external request.
    pub fn cleanup_immutable_temporary(
        &self,
        temporary: impl AsRef<Path>,
    ) -> Result<bool, ImmutablePublicationError> {
        let name = validated_leaf(temporary.as_ref())
            .map_err(ImmutablePublicationError::BeforePublication)?;
        self.verify()
            .map_err(io::Error::other)
            .map_err(ImmutablePublicationError::BeforePublication)?;
        #[cfg(unix)]
        {
            match rustix::fs::unlinkat(&self.handle, name, rustix::fs::AtFlags::empty()) {
                Ok(()) => {
                    self.sync_all()
                        .map_err(io::Error::other)
                        .map_err(ImmutablePublicationError::OutcomeUnknown)?;
                    Ok(true)
                }
                Err(error) if error == rustix::io::Errno::NOENT => {
                    self.verify()
                        .map_err(io::Error::other)
                        .map_err(ImmutablePublicationError::BeforePublication)?;
                    Ok(false)
                }
                Err(error) => Err(ImmutablePublicationError::OutcomeUnknown(error.into())),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            Err(ImmutablePublicationError::BeforePublication(
                io::Error::other(super::DirectoryGuardError::UnsupportedPlatform),
            ))
        }
    }
}

#[cfg(all(test, unix))]
#[path = "immutable_tests.rs"]
mod tests;
