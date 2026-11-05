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

#[cfg(unix)]
fn open_directory_at(parent: &File, name: &str) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, openat};
    Ok(File::from(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}

#[cfg(unix)]
fn remove_directory_contents(directory: &File) -> io::Result<()> {
    use rustix::fs::{AtFlags, Dir, Mode, OFlags, openat, unlinkat};
    use std::ffi::CString;

    let mut names = Vec::<CString>::new();
    for entry in Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_owned());
        }
    }

    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    for name in names {
        match openat(directory, name.as_c_str(), directory_flags, Mode::empty()) {
            Ok(child) => {
                let child = File::from(child);
                remove_directory_contents(&child)?;
                drop(child);
                unlinkat(directory, name.as_c_str(), AtFlags::REMOVEDIR)?;
            }
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(error)
                if error == rustix::io::Errno::NOTDIR || error == rustix::io::Errno::LOOP =>
            {
                unlinkat(directory, name.as_c_str(), AtFlags::empty())?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    directory.sync_all()
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

    /// Remove one ordinary entry from a descriptor-anchored child directory.
    pub fn remove_file_in_directory(
        &self,
        directory: impl AsRef<Path>,
        path: impl AsRef<Path>,
    ) -> io::Result<()> {
        let directory_name = leaf(directory.as_ref())?;
        let name = leaf(path.as_ref())?;
        self.verify().map_err(io::Error::other)?;
        #[cfg(unix)]
        {
            let directory = open_directory_at(&self.handle, directory_name)?;
            rustix::fs::unlinkat(&directory, name, rustix::fs::AtFlags::empty())?;
            directory.sync_all()?;
            self.verify().map_err(io::Error::other)
        }
        #[cfg(not(unix))]
        {
            let _ = (directory_name, name);
            Err(io::Error::other(DirectoryGuardError::UnsupportedPlatform))
        }
    }

    /// Recursively remove a descriptor-anchored child directory without
    /// following symlinks or falling back to the original root pathname.
    pub fn remove_directory_all(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let name = leaf(path.as_ref())?;
        self.verify().map_err(io::Error::other)?;
        #[cfg(unix)]
        {
            let directory = open_directory_at(&self.handle, name)?;
            remove_directory_contents(&directory)?;
            drop(directory);
            rustix::fs::unlinkat(&self.handle, name, rustix::fs::AtFlags::REMOVEDIR)?;
            self.handle.sync_all()?;
            self.verify().map_err(io::Error::other)
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
