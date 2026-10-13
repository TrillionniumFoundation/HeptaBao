//! Durable no-replace publication on the existing directory descriptor.
//!
//! These operations prove physical identity and durability only. The caller
//! must authenticate the returned file's contents before publishing a root.
use super::ExclusiveDirectory;
#[cfg(unix)]
use super::FileAccess;
use std::{fmt, fs::File, io, path::Path};

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
        let (before_link, after_link) = hooks;
        gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
        self.verify().map_err(io::Error::other).map_err(before)?;
        let identity = checked_identity(opened_temporary, exact_len, 1).map_err(before)?;
        let named = self
            .open_file(temporary, FileAccess::Read)
            .map_err(before)?;
        same_identity(&named, identity, 1).map_err(before)?;
        gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
        opened_temporary.sync_all().map_err(before)?;
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
                existing.sync_all().map_err(unknown)?;
                gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
                gate().map_err(ImmutablePublicationCheckedError::GateBeforeLink)?;
                self.sync_all().map_err(io::Error::other).map_err(unknown)?;
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
        published.sync_all().map_err(unknown)?;
        gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
        gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
        self.sync_all().map_err(io::Error::other).map_err(unknown)?;
        gate().map_err(ImmutablePublicationCheckedError::GateAfterLink)?;
        let current = self
            .open_file(destination, FileAccess::Read)
            .map_err(unknown)?;
        same_identity(&current, identity, 1).map_err(unknown)?;
        same_identity(&published, identity, 1).map_err(unknown)?;
        Ok(ImmutablePublication::Published(published))
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
