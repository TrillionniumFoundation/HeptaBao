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
        let named = self
            .open_file(temporary, FileAccess::Read)
            .map_err(before)?;
        same_identity(&named, identity, 1).map_err(before)?;
        gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
        // The batch path has already fsynced all temporary descriptors in
        // bounded concurrent groups and joined their workers BEFORE the first
        // link. Ordinary single-file publication keeps its original fsync.
        if !buffered {
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
        let before = |e| {
            ImmutablePublicationCheckedError::Publication(
                ImmutablePublicationError::BeforePublication(e),
            )
        };
        #[cfg(not(unix))]
        {
            let _ = (entries, gate, strong_sync);
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
            // The first regular file belongs to the same held directory/device.
            // Flush previously fsynced members and names before exposing any pin.
            gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
            let first = match &published[0] {
                ImmutablePublication::Published(f) | ImmutablePublication::AlreadyExists(f) => f,
            };
            strong_sync(first).map_err(unknown)?;
            gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
            self.sync_all().map_err(io::Error::other).map_err(unknown)?;
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
