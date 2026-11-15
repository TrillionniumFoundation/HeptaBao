//! Exact-fd retirement under the existing exclusive directory owner.
//!
//! A ticket proves only a physical observation. The caller must first commit
//! its authenticated retirement record and retain its own root/reader gates.
//! POSIX unlink is not an inode compare-and-swap: this protocol assumes the
//! same private, cooperatively exclusive custody as immutable publication.
use super::{DirectoryIdentity, ExclusiveDirectory, FileAccess, FileMutationWitness};
use std::{collections::BTreeSet, fmt, fs::File, io, path::Path};

pub const MAX_IMMUTABLE_RETIREMENT_FILES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContentIdentity {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
}
fn refused() -> io::Error {
    io::Error::other("immutable retirement identity or custody changed")
}
impl ContentIdentity {
    #[cfg(unix)]
    fn read(file: &File, exact_len: usize, owner_uid: u32) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        if !m.is_file()
            || m.nlink() != 1
            || m.len() != exact_len as u64
            || m.uid() != owner_uid
            || m.mode() & 0o077 != 0
        {
            return Err(refused());
        }
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
            length: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            modified_seconds: m.mtime(),
            modified_nanos: m.mtime_nsec(),
            changed_seconds: m.ctime(),
            changed_nanos: m.ctime_nsec(),
        })
    }
    #[cfg(not(unix))]
    fn read(_file: &File, _exact_len: usize, _owner_uid: u32) -> io::Result<Self> {
        Err(refused())
    }
    #[cfg(unix)]
    fn check_unlinked(self, file: &File) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        // unlink itself may change ctime. It must not change the original
        // fd, contents metadata, owner, or mode, and its link count must be 0.
        if !m.is_file()
            || m.nlink() != 0
            || m.dev() != self.device
            || m.ino() != self.inode
            || m.len() != self.length
            || m.uid() != self.uid
            || m.gid() != self.gid
            || m.mode() != self.mode
            || m.mtime() != self.modified_seconds
            || m.mtime_nsec() != self.modified_nanos
        {
            return Err(refused());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    fn check_unlinked(self, _file: &File) -> io::Result<()> {
        Err(refused())
    }
}

/// Affine original fd/metadata/event observation; no path or name constructor
/// exists outside the actual held directory owner.
pub struct PreparedFileRetirement {
    directory: DirectoryIdentity,
    leaf: String,
    file: File,
    identity: ContentIdentity,
    mutations: FileMutationWitness,
}
impl fmt::Debug for PreparedFileRetirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedFileRetirement([ORIGINAL_READ_ONLY_FD])")
    }
}
impl PreparedFileRetirement {
    /// The caller may authenticate bounded bytes on this same read-only fd.
    /// This observation does not authorize deletion or publish a root.
    pub fn file(&self) -> &File {
        &self.file
    }
}

#[derive(Debug)]
pub enum FileRetirementError {
    BeforeUnlink(io::Error),
    OutcomeUnknown(io::Error),
}
impl fmt::Display for FileRetirementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BeforeUnlink(_) => "immutable retirement rejected before unlink",
            Self::OutcomeUnknown(_) => "immutable retirement outcome is unknown",
        })
    }
}
impl std::error::Error for FileRetirementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::BeforeUnlink(e) | Self::OutcomeUnknown(e) => e,
        })
    }
}

impl ExclusiveDirectory {
    pub fn prepare_file_retirement(
        &self,
        leaf: impl AsRef<Path>,
        exact_len: usize,
    ) -> io::Result<PreparedFileRetirement> {
        let leaf = leaf.as_ref().to_str().ok_or_else(refused)?;
        super::validate_leaf(leaf).map_err(io::Error::other)?;
        self.verify().map_err(io::Error::other)?;
        #[cfg(unix)]
        let uid = {
            use std::os::unix::fs::MetadataExt;
            let owner = self.handle.metadata()?;
            if owner.mode() & 0o077 != 0 {
                return Err(refused());
            }
            owner.uid()
        };
        #[cfg(not(unix))]
        let uid = 0;
        let file = self.open_file(leaf, FileAccess::Read)?;
        let identity = ContentIdentity::read(&file, exact_len, uid)?;
        // Retain the kernel witness before the first caller ciphertext read.
        let mutations = self.watch_file_mutations(&file)?;
        let prepared = PreparedFileRetirement {
            directory: self.identity(),
            leaf: leaf.to_owned(),
            file,
            identity,
            mutations,
        };
        self.verify_file_retirement(&prepared)?;
        Ok(prepared)
    }

    pub fn verify_file_retirement(&self, prepared: &PreparedFileRetirement) -> io::Result<()> {
        self.verify().map_err(io::Error::other)?;
        if self.identity() != prepared.directory {
            return Err(refused());
        }
        prepared.mutations.verify_file(&prepared.file)?;
        let original = prepared.identity;
        if ContentIdentity::read(&prepared.file, original.length as usize, original.uid)?
            != original
        {
            return Err(refused());
        }
        let named = self.open_file(&prepared.leaf, FileAccess::Read)?;
        if ContentIdentity::read(&named, original.length as usize, original.uid)? != original {
            return Err(refused());
        }
        prepared.mutations.verify_file(&prepared.file)?;
        self.verify().map_err(io::Error::other)
    }

    /// Consume a bounded batch after the caller's durable retirement Apply.
    /// Its callback authenticates each SAME fd immediately before its unlink.
    /// Any error once an unlink syscall is attempted is conservatively unknown;
    /// there is no fallback, retry, or interpretation of ENOENT as success.
    pub fn retire_files_checked(
        &self,
        prepared: Vec<PreparedFileRetirement>,
        before_unlink: &mut dyn FnMut(usize, &File) -> io::Result<()>,
        gate: &mut dyn FnMut() -> io::Result<()>,
    ) -> Result<(), FileRetirementError> {
        self.retire_files_with_sync(prepared, before_unlink, gate, &mut || {
            self.sync_all().map_err(io::Error::other)
        })
    }

    fn retire_files_with_sync(
        &self,
        prepared: Vec<PreparedFileRetirement>,
        before_unlink: &mut dyn FnMut(usize, &File) -> io::Result<()>,
        gate: &mut dyn FnMut() -> io::Result<()>,
        sync: &mut dyn FnMut() -> io::Result<()>,
    ) -> Result<(), FileRetirementError> {
        let mut attempted = false;
        let result = (|| -> io::Result<()> {
            if prepared.is_empty() || prepared.len() > MAX_IMMUTABLE_RETIREMENT_FILES {
                return Err(refused());
            }
            let mut names = BTreeSet::new();
            let mut inodes = BTreeSet::new();
            gate()?;
            for entry in &prepared {
                if !names.insert(&entry.leaf)
                    || !inodes.insert((entry.identity.device, entry.identity.inode))
                {
                    return Err(refused());
                }
                self.verify_file_retirement(entry)?;
                gate()?;
            }
            for (index, entry) in prepared.iter().enumerate() {
                gate()?;
                self.verify_file_retirement(entry)?;
                before_unlink(index, entry.file())?;
                gate()?;
                self.verify_file_retirement(entry)?;
                #[cfg(unix)]
                {
                    attempted = true;
                    rustix::fs::unlinkat(
                        &self.handle,
                        entry.leaf.as_str(),
                        rustix::fs::AtFlags::empty(),
                    )?;
                }
                #[cfg(not(unix))]
                return Err(refused());
            }
            gate()?;
            sync()?;
            gate()?;
            for entry in &prepared {
                entry.identity.check_unlinked(entry.file())?;
                if self.entry_exists(&entry.leaf)? {
                    return Err(refused());
                }
                gate()?;
            }
            self.verify().map_err(io::Error::other)?;
            gate()
        })();
        result.map_err(|error| {
            if attempted {
                FileRetirementError::OutcomeUnknown(error)
            } else {
                FileRetirementError::BeforeUnlink(error)
            }
        })
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[path = "retirement_tests.rs"]
mod tests;
