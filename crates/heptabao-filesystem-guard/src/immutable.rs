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
        let temporary = validated_leaf(temporary.as_ref())
            .map_err(ImmutablePublicationError::BeforePublication)?;
        let destination = validated_leaf(destination.as_ref())
            .map_err(ImmutablePublicationError::BeforePublication)?;
        if temporary == destination {
            return Err(ImmutablePublicationError::BeforePublication(
                io::Error::other("immutable temporary and destination must differ"),
            ));
        }
        #[cfg(unix)]
        {
            self.publish_file_noreplace_checked(
                temporary,
                opened_temporary,
                destination,
                exact_len,
                || Ok(()),
                || Ok(()),
            )
        }
        #[cfg(not(unix))]
        {
            let _ = (temporary, opened_temporary, destination, exact_len);
            Err(ImmutablePublicationError::BeforePublication(
                io::Error::other(super::DirectoryGuardError::UnsupportedPlatform),
            ))
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

    // The callbacks exist only to make filesystem mutation windows observable
    // in this module's real-FS tests. The public entry point always supplies
    // no-op callbacks and performs every identity check itself.
    #[cfg(unix)]
    fn publish_file_noreplace_checked(
        &self,
        temporary: &str,
        opened_temporary: &File,
        destination: &str,
        exact_len: u64,
        before_link: impl FnOnce() -> io::Result<()>,
        after_link: impl FnOnce() -> io::Result<()>,
    ) -> Result<ImmutablePublication, ImmutablePublicationError> {
        use rustix::fs::{AtFlags, linkat};
        let before = ImmutablePublicationError::BeforePublication;
        let unknown = ImmutablePublicationError::OutcomeUnknown;
        self.verify().map_err(io::Error::other).map_err(before)?;
        let identity = checked_identity(opened_temporary, exact_len, 1).map_err(before)?;
        let named = self
            .open_file(temporary, FileAccess::Read)
            .map_err(before)?;
        same_identity(&named, identity, 1).map_err(before)?;
        opened_temporary.sync_all().map_err(before)?;
        same_identity(opened_temporary, identity, 1).map_err(before)?;
        let named = self
            .open_file(temporary, FileAccess::Read)
            .map_err(before)?;
        same_identity(&named, identity, 1).map_err(before)?;
        before_link().map_err(before)?;

        match linkat(
            &self.handle,
            temporary,
            &self.handle,
            destination,
            AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::EXIST => {
                // An existing symlink, FIFO, multiply-linked file or wrong
                // length is rejected before any destination mutation. An
                // arbitrary existing entry must never be followed or replaced.
                let existing = self
                    .open_file(destination, FileAccess::Read)
                    .map_err(before)?;
                let existing_identity =
                    checked_identity(&existing, exact_len, 1).map_err(before)?;
                let named = self
                    .open_file(temporary, FileAccess::Read)
                    .map_err(before)?;
                same_identity(&named, identity, 1).map_err(before)?;
                self.remove_file(temporary).map_err(unknown)?;
                same_identity(opened_temporary, identity, 0).map_err(unknown)?;
                existing.sync_all().map_err(unknown)?;
                self.sync_all().map_err(io::Error::other).map_err(unknown)?;
                let current = self
                    .open_file(destination, FileAccess::Read)
                    .map_err(unknown)?;
                same_identity(&current, existing_identity, 1).map_err(unknown)?;
                same_identity(&existing, existing_identity, 1).map_err(unknown)?;
                return Ok(ImmutablePublication::AlreadyExists(existing));
            }
            Err(error) => return Err(unknown(error.into())),
        }

        // From this point on a final leaf exists. Never turn a lost sync,
        // acknowledgement or identity mismatch into an ordinary pre-write
        // failure, and never delete a destination to hide an uncertain result.
        after_link().map_err(unknown)?;
        same_identity(opened_temporary, identity, 2).map_err(unknown)?;
        let published = self
            .immutable_leaf_with_links(destination, exact_len, 2)
            .map_err(unknown)?;
        same_identity(&published, identity, 2).map_err(unknown)?;
        let named = self
            .immutable_leaf_with_links(temporary, exact_len, 2)
            .map_err(unknown)?;
        same_identity(&named, identity, 2).map_err(unknown)?;
        self.remove_file(temporary).map_err(unknown)?;
        same_identity(opened_temporary, identity, 1).map_err(unknown)?;
        same_identity(&published, identity, 1).map_err(unknown)?;
        published.sync_all().map_err(unknown)?;
        self.sync_all().map_err(io::Error::other).map_err(unknown)?;
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
