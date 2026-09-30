//! Leaf operations on the existing exclusive directory owner, never its path.
#[cfg(not(unix))]
use super::DirectoryGuardError;
use super::{ExclusiveDirectory, validate_leaf};
use std::{ffi::OsString, fs::File, io, path::Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileAccess {
    Read,
    Write,
    Append,
    CreateNew,
    CreateNewReadWrite,
}

fn leaf(path: &Path) -> io::Result<&str> {
    let name = path
        .to_str()
        .ok_or_else(|| io::Error::other("non-UTF-8 guarded leaf"))?;
    validate_leaf(name).map_err(io::Error::other)?;
    Ok(name)
}

impl ExclusiveDirectory {
    pub fn open_file(&self, path: impl AsRef<Path>, access: FileAccess) -> io::Result<File> {
        let name = leaf(path.as_ref())?;
        self.verify().map_err(io::Error::other)?;
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};
            use std::os::unix::fs::MetadataExt;
            let flags = match access {
                FileAccess::Read => OFlags::RDONLY,
                FileAccess::Write => OFlags::WRONLY,
                FileAccess::Append => OFlags::WRONLY | OFlags::APPEND,
                FileAccess::CreateNew => OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                FileAccess::CreateNewReadWrite => OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            };
            let file = File::from(openat(
                &self.handle,
                name,
                flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            )?);
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(io::Error::other(
                    "guarded leaf is not a singly-linked regular file",
                ));
            }
            self.verify().map_err(io::Error::other)?;
            Ok(file)
        }
        #[cfg(not(unix))]
        {
            let _ = (name, access);
            Err(io::Error::other(DirectoryGuardError::UnsupportedPlatform))
        }
    }

    pub fn entry_exists(&self, path: impl AsRef<Path>) -> io::Result<bool> {
        let name = leaf(path.as_ref())?;
        self.verify().map_err(io::Error::other)?;
        #[cfg(unix)]
        {
            match rustix::fs::statat(&self.handle, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => Ok(true),
                Err(rustix::io::Errno::NOENT) => Ok(false),
                Err(error) => Err(error.into()),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            Err(io::Error::other(DirectoryGuardError::UnsupportedPlatform))
        }
    }

    pub fn remove_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let name = leaf(path.as_ref())?;
        self.verify().map_err(io::Error::other)?;
        #[cfg(unix)]
        {
            rustix::fs::unlinkat(&self.handle, name, rustix::fs::AtFlags::empty())?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            Err(io::Error::other(DirectoryGuardError::UnsupportedPlatform))
        }
    }

    pub fn rename(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
        let from = leaf(from.as_ref())?;
        let to = leaf(to.as_ref())?;
        self.verify().map_err(io::Error::other)?;
        #[cfg(unix)]
        {
            rustix::fs::renameat(&self.handle, from, &self.handle, to)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (from, to);
            Err(io::Error::other(DirectoryGuardError::UnsupportedPlatform))
        }
    }

    /// Each call starts an independent stream; do not allocate an entire inventory.
    pub fn entries(&self) -> io::Result<impl Iterator<Item = io::Result<OsString>>> {
        self.verify().map_err(io::Error::other)?;
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            Ok(
                rustix::fs::Dir::read_from(&self.handle)?.filter_map(|entry| {
                    let entry = match entry {
                        Ok(e) => e,
                        Err(e) => return Some(Err(e.into())),
                    };
                    let name = entry.file_name().to_bytes();
                    if name == b"." || name == b".." {
                        None
                    } else {
                        Some(Ok(OsString::from_vec(name.to_vec())))
                    }
                }),
            )
        }
        #[cfg(not(unix))]
        {
            Err::<std::iter::Empty<io::Result<OsString>>, _>(io::Error::other(
                DirectoryGuardError::UnsupportedPlatform,
            ))
        }
    }
}
